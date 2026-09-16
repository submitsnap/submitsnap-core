use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::modules::auth::error::AuthError;

/// Distinguishes access tokens from any other JWT this service might issue in the future, so
/// one kind can never be replayed as another.
const TOKEN_TYPE: &str = "access";

/// Tolerated clock skew between the issuer and the verifier, in seconds.
const LEEWAY_SECONDS: u64 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    /// Account identifier.
    pub sub: String,
    /// Session identifier, checked against `sessions` so logout is immediate.
    pub sid: String,
    /// Unique token identifier.
    pub jti: String,
    pub iss: String,
    pub aud: String,
    /// Token kind; see [`TOKEN_TYPE`].
    pub typ: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
}

#[derive(Clone)]
pub struct AccessTokens {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
    issuer: String,
    audience: String,
    ttl_seconds: i64,
}

impl AccessTokens {
    pub fn new(secret: &SecretString, issuer: String, audience: String, ttl_seconds: u64) -> Self {
        let bytes = secret.expose_secret().as_bytes();

        // `Validation::new` pins the accepted algorithm to HS256, which rules out algorithm
        // confusion attacks where a token is re-signed with a different family.
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[issuer.as_str()]);
        validation.set_audience(&[audience.as_str()]);
        validation.leeway = LEEWAY_SECONDS;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.required_spec_claims = ["exp", "nbf", "iss", "aud", "sub"]
            .into_iter()
            .map(str::to_owned)
            .collect();

        Self {
            encoding: EncodingKey::from_secret(bytes),
            decoding: DecodingKey::from_secret(bytes),
            validation,
            issuer,
            audience,
            ttl_seconds: i64::try_from(ttl_seconds).unwrap_or(i64::MAX),
        }
    }

    /// Returns the encoded token and its lifetime in seconds.
    pub fn issue(&self, user_id: Uuid, session_id: Uuid) -> Result<(String, i64), AuthError> {
        let now = Utc::now().timestamp();
        let claims = AccessClaims {
            sub: user_id.to_string(),
            sid: session_id.to_string(),
            jti: Uuid::new_v4().to_string(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            typ: TOKEN_TYPE.to_owned(),
            iat: now,
            nbf: now,
            exp: now.saturating_add(self.ttl_seconds),
        };

        let token = encode(&Header::default(), &claims, &self.encoding)
            .map_err(|error| AuthError::Internal(error.into()))?;

        Ok((token, self.ttl_seconds))
    }

    /// Verifies signature, algorithm, issuer, audience, lifetime, and token kind.
    pub fn verify(&self, token: &str) -> Result<AccessClaims, AuthError> {
        let claims = decode::<AccessClaims>(token, &self.decoding, &self.validation)
            .map_err(|_| AuthError::InvalidToken)?
            .claims;

        if claims.typ != TOKEN_TYPE {
            return Err(AuthError::InvalidToken);
        }

        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "a-test-secret-that-is-long-enough";

    fn tokens(secret: &str, ttl_seconds: u64) -> AccessTokens {
        AccessTokens::new(
            &SecretString::from(secret.to_owned()),
            "submitsnap".into(),
            "submitsnap-api".into(),
            ttl_seconds,
        )
    }

    fn claims_at(exp: i64, token_type: &str) -> AccessClaims {
        AccessClaims {
            sub: Uuid::new_v4().to_string(),
            sid: Uuid::new_v4().to_string(),
            jti: Uuid::new_v4().to_string(),
            iss: "submitsnap".into(),
            aud: "submitsnap-api".into(),
            typ: token_type.to_owned(),
            iat: exp - 900,
            nbf: exp - 900,
            exp,
        }
    }

    fn encode_with_secret(claims: &AccessClaims, secret: &str) -> String {
        encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn issued_tokens_verify_and_carry_both_identifiers() {
        let service = tokens(SECRET, 900);
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        let (token, expires_in) = service.issue(user_id, session_id).unwrap();
        let claims = service.verify(&token).unwrap();

        assert_eq!(expires_in, 900);
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.sid, session_id.to_string());
        assert_eq!(claims.typ, "access");
        assert_eq!(claims.exp - claims.iat, 900);
    }

    #[test]
    fn tokens_signed_with_another_secret_are_rejected() {
        let other = tokens("a-different-secret-that-is-long-enough", 900);
        let token = encode_with_secret(&claims_at(Utc::now().timestamp() + 900, "access"), SECRET);

        assert!(other.verify(&token).is_err());
    }

    #[test]
    fn tokens_from_another_audience_are_rejected() {
        let other_audience = AccessTokens::new(
            &SecretString::from(SECRET.to_owned()),
            "submitsnap".into(),
            "another-api".into(),
            900,
        );
        let token = encode_with_secret(&claims_at(Utc::now().timestamp() + 900, "access"), SECRET);

        assert!(other_audience.verify(&token).is_err());
    }

    #[test]
    fn expired_tokens_are_rejected() {
        let service = tokens(SECRET, 900);
        let token = encode_with_secret(&claims_at(Utc::now().timestamp() - 3600, "access"), SECRET);

        assert!(service.verify(&token).is_err());
    }

    #[test]
    fn tokens_of_another_kind_are_rejected() {
        let service = tokens(SECRET, 900);
        let token = encode_with_secret(&claims_at(Utc::now().timestamp() + 900, "refresh"), SECRET);

        assert!(service.verify(&token).is_err());
    }

    #[test]
    fn tokens_signed_with_an_unexpected_algorithm_are_rejected() {
        // A "none"-style token must not be accepted even though its claims look valid.
        let header = Header::new(Algorithm::HS384);
        let token = encode(
            &header,
            &claims_at(Utc::now().timestamp() + 900, "access"),
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap();

        assert!(tokens(SECRET, 900).verify(&token).is_err());
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        let service = tokens(SECRET, 900);

        assert!(service.verify("not-a-jwt").is_err());
        assert!(service.verify("").is_err());
    }
}
