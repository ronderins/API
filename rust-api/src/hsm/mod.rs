//! Hardware Security Module (HSM) & Secure Enclave Suite
//!
//! Submodules:
//! - `enclave`: AWS Nitro / Intel SGX attestation quote verification.
//! - `pkcs11`: PKCS#11 hardware token integration and blinded hardware signing.

pub mod enclave;
pub mod pkcs11;

pub use enclave::{EnclaveAttestationQuote, EnclaveAttestationVerifier};
pub use pkcs11::{HsmCryptoToken, HsmSession};
