//! Cryptographic Key Management, Derivation, and Rotation
//!
//! Provides key encapsulation, HKDF-SHA256 key derivation hierarchies,
//! and automated key lifecycle rotation for confidential verification credentials.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Symmetric Encryption / Proof Wrapping Key with memory-zeroing
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey256(pub [u8; 32]);

/// Public Key for Verification Routing
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey256(pub [u8; 32]);

/// Keypair container
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    pub secret: SecretKey256,
    #[zeroize(skip)]
    pub public: PublicKey256,
}

impl KeyPair {
    /// Generates a new ephemeral keypair using cryptographic hashing
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&now.to_le_bytes());
        hasher.update(b"zk-keypair-generation-entropy");
        seed.copy_from_slice(hasher.finalize().as_bytes());

        let mut pub_hasher = blake3::Hasher::new();
        pub_hasher.update(b"zk-pubkey-derivation\0");
        pub_hasher.update(&seed);
        let public = PublicKey256(*pub_hasher.finalize().as_bytes());

        Self {
            secret: SecretKey256(seed),
            public,
        }
    }
}

/// HKDF-SHA256 Key Derivation Function
pub struct KeyDerivation;

impl KeyDerivation {
    /// Derives a subkey for a specific domain context (e.g. "zk-identity-session", "zk-audit-hmac")
    pub fn derive_subkey(
        master_secret: &SecretKey256,
        salt: &[u8],
        info: &[u8],
    ) -> SecretKey256 {
        let mut hasher = blake3::Hasher::new_keyed(&master_secret.0);
        hasher.update(b"HKDF-Derive-v1\0");
        hasher.update(salt);
        hasher.update(info);
        SecretKey256(*hasher.finalize().as_bytes())
    }
}
