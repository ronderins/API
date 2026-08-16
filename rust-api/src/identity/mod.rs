//! Decentralized Identity (DID) & Anonymous Credentials Suite
//!
//! Submodules:
//! - `did`: W3C DID document resolver and verification method extractor.
//! - `revocation`: Cryptographic dynamic accumulator revocation registry.
//! - `anon_creds`: Anonymous credentials and zero-knowledge presentation tokens.
//! - `w3c_vc`: W3C Verifiable Credentials Data Model v2.0 & SD-JWT parser.

pub mod anon_creds;
pub mod did;
pub mod revocation;
pub mod w3c_vc;

pub use anon_creds::{AnonCredentialPresentation, AnonCredentialSignature, AnonCredsVerifier};
pub use did::{DidDocument, DidResolver, VerificationMethod};
pub use revocation::RevocationAccumulator;
pub use w3c_vc::{SdJwtToken, W3cProofBlock, W3cVerifiableCredential, W3cVcEngine};
