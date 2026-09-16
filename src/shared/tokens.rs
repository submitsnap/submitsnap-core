use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

/// Entropy behind every opaque secret this service hands out (refresh tokens and the
/// single-use links for email verification and password reset).
const TOKEN_BYTES: usize = 32;

/// Returns a fresh, URL-safe opaque token. The value is only ever known to the client that
/// receives it; the server keeps nothing but its hash.
pub fn generate_secret_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Hashes a token for storage. Deterministic and one-way, so a database disclosure does not
/// yield usable tokens.
pub fn hash_secret_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_unique_and_url_safe() {
        let first = generate_secret_token();
        let second = generate_secret_token();

        assert_ne!(first, second);
        assert_eq!(first.len(), 43);
        assert!(
            first
                .chars()
                .all(|character| character.is_ascii_alphanumeric()
                    || character == '-'
                    || character == '_')
        );
    }

    #[test]
    fn hashing_is_deterministic_and_fixed_width() {
        let token = generate_secret_token();

        assert_eq!(hash_secret_token(&token), hash_secret_token(&token));
        assert_eq!(hash_secret_token(&token).len(), 32);
        assert_ne!(hash_secret_token(&token), token.as_bytes());
    }
}
