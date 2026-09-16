use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{
        PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString, rand_core::OsRng,
    },
};
use secrecy::{ExposeSecret, SecretString, zeroize::Zeroizing};

/// Argon2id with the OWASP-recommended profile for interactive logins:
/// 19 MiB of memory, 2 iterations, one lane.
const MEMORY_COST_KIB: u32 = 19 * 1024;
const TIME_COST: u32 = 2;
const PARALLELISM: u32 = 1;
const ALGORITHM_ID: &str = "argon2id";

/// A fixed secret hashed once at startup. Verifying against it costs the same as a real
/// verification, which keeps login timing independent of whether an account exists.
const CANARY_PASSWORD: &str = "submitsnap-timing-canary";

#[derive(Clone)]
pub struct PasswordHasher {
    argon2: Argon2<'static>,
    pepper: Option<SecretString>,
    canary_hash: String,
    params_encoding: String,
}

impl PasswordHasher {
    pub fn new(pepper: Option<SecretString>) -> anyhow::Result<Self> {
        let params = Params::new(MEMORY_COST_KIB, TIME_COST, PARALLELISM, None)
            .map_err(|error| anyhow::anyhow!("invalid Argon2 parameters: {error}"))?;

        let mut hasher = Self {
            argon2: Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
            pepper,
            canary_hash: String::new(),
            params_encoding: String::new(),
        };

        let canary = hasher.hash(CANARY_PASSWORD)?;
        // Derive the expected parameter encoding from our own output so a future parameter
        // change cannot leave `needs_rehash` comparing against a stale literal.
        hasher.params_encoding = PasswordHash::new(&canary)
            .map(|parsed| parsed.params.as_str().to_owned())
            .unwrap_or_default();
        hasher.canary_hash = canary;

        Ok(hasher)
    }

    pub fn hash(&self, password: &str) -> anyhow::Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let material = self.material(password);
        self.argon2
            .hash_password(material.as_slice(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|error| anyhow::anyhow!("failed to hash password: {error}"))
    }

    pub fn verify(&self, password: &str, password_hash: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(password_hash) else {
            return false;
        };
        let material = self.material(password);
        self.argon2
            .verify_password(material.as_slice(), &parsed)
            .is_ok()
    }

    /// Burns the same CPU time as [`Self::verify`] for callers that found no account.
    pub fn verify_canary(&self, password: &str) {
        let verdict = self.verify(password, &self.canary_hash);
        std::hint::black_box(verdict);
    }

    pub fn needs_rehash(&self, password_hash: &str) -> bool {
        match PasswordHash::new(password_hash) {
            Ok(parsed) => {
                parsed.algorithm.as_str() != ALGORITHM_ID
                    || parsed.params.as_str() != self.params_encoding
            }
            Err(_) => true,
        }
    }

    /// Appends the optional pepper to the password. The intermediate buffer is zeroized on
    /// drop so the plaintext does not linger in memory.
    fn material(&self, password: &str) -> Zeroizing<Vec<u8>> {
        let mut material = Zeroizing::new(Vec::with_capacity(password.len() + 64));
        material.extend_from_slice(password.as_bytes());
        if let Some(pepper) = &self.pepper {
            material.extend_from_slice(pepper.expose_secret().as_bytes());
        }
        material
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hasher(pepper: Option<&str>) -> PasswordHasher {
        PasswordHasher::new(pepper.map(|value| SecretString::from(value.to_owned()))).unwrap()
    }

    #[test]
    fn passwords_round_trip_without_being_stored_in_clear() {
        let hasher = hasher(None);
        let hash = hasher.hash("a sufficiently long password").unwrap();

        assert!(!hash.contains("a sufficiently long password"));
        assert!(hash.starts_with("$argon2id$"));
        assert!(hasher.verify("a sufficiently long password", &hash));
        assert!(!hasher.verify("wrong password", &hash));
    }

    #[test]
    fn salts_make_identical_passwords_hash_differently() {
        let hasher = hasher(None);

        assert_ne!(
            hasher.hash("a sufficiently long password").unwrap(),
            hasher.hash("a sufficiently long password").unwrap()
        );
    }

    #[test]
    fn pepper_is_required_to_verify() {
        let peppered = hasher(Some("server-side-pepper"));
        let unpeppered = hasher(None);
        let hash = peppered.hash("a sufficiently long password").unwrap();

        assert!(peppered.verify("a sufficiently long password", &hash));
        assert!(!unpeppered.verify("a sufficiently long password", &hash));
    }

    #[test]
    fn current_hashes_do_not_need_a_rehash() {
        let hasher = hasher(None);
        let hash = hasher.hash("a sufficiently long password").unwrap();

        assert!(!hasher.needs_rehash(&hash));
        assert!(hasher.needs_rehash("not-a-password-hash"));
    }

    #[test]
    fn malformed_hashes_never_verify() {
        let hasher = hasher(None);

        assert!(!hasher.verify("a sufficiently long password", "not-a-password-hash"));
        assert!(!hasher.verify("a sufficiently long password", ""));
    }
}
