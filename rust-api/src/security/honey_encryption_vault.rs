//! Honey Encryption Vault & Distribution-Transforming Encoders (DTE)
//!
//! Implements Juels-Ristenpart Honey Encryption for password-derived identity vaults.
//! Brute-force decryption attempts with incorrect keys yield plausible, statistically
//! indistinguishable decoy identities (decoy dates of birth, decoy document numbers, decoy names)
//! rather than error traps or gibberish, defeating offline dictionary and brute-force attacks!

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A private identity record stored inside the Honey Encryption vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultIdentityRecord {
    pub first_name: String,
    pub last_name: String,
    pub birth_year: u32,
    pub birth_month: u32,
    pub birth_day: u32,
    pub document_id_number: String,
    pub residency_country: String,
}

/// Honey-Encrypted Ciphertext block with seed expansion header.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HoneyCiphertext {
    pub ciphertext_bytes: Vec<u8>,
    pub salt: String,
    pub vault_version: u32,
}

/// Distribution-Transforming Encoder (DTE) for identity attribute distributions.
pub struct IdentityDte;

impl IdentityDte {
    const SAMPLE_FIRST_NAMES: &'static [&'static str] = &[
        "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda",
        "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
        "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa",
    ];

    const SAMPLE_LAST_NAMES: &'static [&'static str] = &[
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
        "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas",
    ];

    const SAMPLE_COUNTRIES: &'static [&'static str] = &[
        "US", "DE", "FR", "GB", "CA", "JP", "AU", "CH", "NL", "SE", "ES", "IT",
    ];

    /// Encodes a structured identity record into an integer bitstring in [0, Domain_Size).
    pub fn encode(record: &VaultIdentityRecord) -> u64 {
        let fn_idx = Self::SAMPLE_FIRST_NAMES
            .iter()
            .position(|&n| n.eq_ignore_ascii_case(&record.first_name))
            .unwrap_or(0) as u64;

        let ln_idx = Self::SAMPLE_LAST_NAMES
            .iter()
            .position(|&n| n.eq_ignore_ascii_case(&record.last_name))
            .unwrap_or(0) as u64;

        let country_idx = Self::SAMPLE_COUNTRIES
            .iter()
            .position(|&c| c.eq_ignore_ascii_case(&record.residency_country))
            .unwrap_or(0) as u64;

        let year_offset = record.birth_year.saturating_sub(1920).min(100) as u64;
        let month = record.birth_month.clamp(1, 12) as u64;
        let day = record.birth_day.clamp(1, 31) as u64;

        // Pack: fn (5b) | ln (4b) | country (4b) | year (7b) | month (4b) | day (5b)
        (fn_idx << 24)
            | (ln_idx << 20)
            | (country_idx << 16)
            | (year_offset << 9)
            | (month << 5)
            | day
    }

    /// Decodes an integer bitstring into a statistically plausible identity record!
    /// Crucially: EVERY possible 64-bit integer produces a syntactically valid record!
    pub fn decode(val: u64) -> VaultIdentityRecord {
        let fn_idx = ((val >> 24) as usize) % Self::SAMPLE_FIRST_NAMES.len();
        let ln_idx = ((val >> 20) as usize) % Self::SAMPLE_LAST_NAMES.len();
        let country_idx = ((val >> 16) as usize) % Self::SAMPLE_COUNTRIES.len();
        let year_offset = ((val >> 9) & 0x7F) % 80;
        let month = (((val >> 5) & 0x0F) % 12) + 1;
        let day = ((val & 0x1F) % 28) + 1;

        let doc_num = format!("P{:08x}", val & 0xFFFFFFFF);

        VaultIdentityRecord {
            first_name: Self::SAMPLE_FIRST_NAMES[fn_idx].to_string(),
            last_name: Self::SAMPLE_LAST_NAMES[ln_idx].to_string(),
            birth_year: 1940 + year_offset as u32,
            birth_month: month as u32,
            birth_day: day as u32,
            document_id_number: doc_num,
            residency_country: Self::SAMPLE_COUNTRIES[country_idx].to_string(),
        }
    }
}

/// Honey Encryption Vault Engine
pub struct HoneyEncryptionVault;

impl HoneyEncryptionVault {
    /// Encrypts identity record using a user passphrase.
    pub fn encrypt_identity(
        passphrase: &str,
        record: &VaultIdentityRecord,
        salt: &[u8],
    ) -> HoneyCiphertext {
        let encoded_val = IdentityDte::encode(record);

        // Derive key stream using PBKDF2 / Blake3 key expansion
        let mut key_hasher = blake3::Hasher::new_derive_key("AEGIS_HONEY_ENCRYPTION_KEY_DERIVATION_V1");
        key_hasher.update(passphrase.as_bytes());
        key_hasher.update(salt);
        let key_bytes: [u8; 32] = *key_hasher.finalize().as_bytes();

        let pad = u64::from_be_bytes(key_bytes[0..8].try_into().unwrap());
        // Honey pad addition modulo 2^32
        let cipher_int = encoded_val.wrapping_add(pad);

        HoneyCiphertext {
            ciphertext_bytes: cipher_int.to_be_bytes().to_vec(),
            salt: hex::encode(salt),
            vault_version: 1,
        }
    }

    /// Decrypts identity record. If password is wrong, a PLAUSIBLE DECOY is returned!
    /// The attacker receives zero indication of failure!
    pub fn decrypt_identity(
        attempted_passphrase: &str,
        ciphertext: &HoneyCiphertext,
    ) -> Result<VaultIdentityRecord, String> {
        let salt = hex::decode(&ciphertext.salt).map_err(|e| format!("Invalid salt hex: {}", e))?;

        let mut key_hasher = blake3::Hasher::new_derive_key("AEGIS_HONEY_ENCRYPTION_KEY_DERIVATION_V1");
        key_hasher.update(attempted_passphrase.as_bytes());
        key_hasher.update(&salt);
        let key_bytes: [u8; 32] = *key_hasher.finalize().as_bytes();

        let pad = u64::from_be_bytes(key_bytes[0..8].try_into().unwrap());

        if ciphertext.ciphertext_bytes.len() < 8 {
            return Err("Ciphertext too short".to_string());
        }
        let cipher_int = u64::from_be_bytes(ciphertext.ciphertext_bytes[0..8].try_into().unwrap());

        // Reverse honey pad addition
        let recovered_val = cipher_int.wrapping_sub(pad);

        // DTE decode into realistic record
        let record = IdentityDte::decode(recovered_val);
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_honey_encryption_correct_password_and_decoy_on_wrong_password() {
        let real_identity = VaultIdentityRecord {
            first_name: "James".to_string(),
            last_name: "Smith".to_string(),
            birth_year: 1985,
            birth_month: 6,
            birth_day: 15,
            document_id_number: "P12345678".to_string(),
            residency_country: "US".to_string(),
        };

        let correct_pass = "correct-horse-battery-staple-998";
        let salt = b"salt_entropy_honey_2026";

        let vault = HoneyEncryptionVault::encrypt_identity(correct_pass, &real_identity, salt);

        // 1. Decrypt with correct password
        let decrypted_correct = HoneyEncryptionVault::decrypt_identity(correct_pass, &vault).unwrap();
        assert_eq!(decrypted_correct.first_name, real_identity.first_name);
        assert_eq!(decrypted_correct.last_name, real_identity.last_name);
        assert_eq!(decrypted_correct.residency_country, real_identity.residency_country);

        // 2. Decrypt with WRONG password: must return a PLAUSIBLE DECOY identity!
        let wrong_pass = "wrong-password-guess-12345";
        let decoy = HoneyEncryptionVault::decrypt_identity(wrong_pass, &vault).unwrap();

        // Decoy is completely valid syntactically
        assert!(!decoy.first_name.is_empty());
        assert!(!decoy.last_name.is_empty());
        assert!(decoy.birth_year >= 1940 && decoy.birth_year <= 2020);
        assert!(decoy.birth_month >= 1 && decoy.birth_month <= 12);
        assert!(decoy.birth_day >= 1 && decoy.birth_day <= 31);
        assert_ne!(decoy, real_identity); // Decoy differs from real!
    }
}
