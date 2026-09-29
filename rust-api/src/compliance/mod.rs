//! Regulatory Compliance and Identity Standards Suite
//!
//! Submodules:
//! - `eidas`: eIDAS 2.0 and W3C Verifiable Credentials selective disclosure.
//! - `iso_18013_5`: ISO/IEC 18013-5 Mobile Driving License (mDL) zero-knowledge verifier.

pub mod eidas;
pub mod eidas_vectors;
pub mod gdpr_article32_encryption;
pub mod iso_18013_5;
pub mod iso18013_mdl;
pub mod iso_29115_assurance;

pub use eidas_vectors::{EidasComplianceSuite, EidasQeaaCredential};
pub use gdpr_article32_encryption::{GdprArticle32Report, GdprComplianceAuditor};
pub use iso18013_mdl::{IssuerSignedItem, MdlZkVerifier, MobileSecurityObject};
pub use iso_29115_assurance::{AuthenticationEvidence, Iso29115AssertionToken, Iso29115AssuranceEngine, LevelOfAssurance};
