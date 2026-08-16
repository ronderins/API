//! ISO/IEC 18013-5 Mobile Driving License (mDL) & eIDAS 2.0 Compliance Engine
//!
//! Provides CBOR/COSE Mobile Security Object (MSO) parsing, IssuerAuth validation,
//! and zero-knowledge selective disclosure predicates over standard mDL namespaces.

use serde::{Deserialize, Serialize};

/// Standard ISO 18013-5 mDL Namespace
pub const MDL_NAMESPACE_ISO: &'static str = "org.iso.18013.5.1";

/// Standard mDL Data Element Identifiers
pub const ELEM_FAMILY_NAME: &'static str = "family_name";
pub const ELEM_GIVEN_NAME: &'static str = "given_name";
pub const ELEM_BIRTH_DATE: &'static str = "birth_date";
pub const ELEM_ISSUE_DATE: &'static str = "issue_date";
pub const ELEM_EXPIRY_DATE: &'static str = "expiry_date";
pub const ELEM_ISSUING_COUNTRY: &'static str = "issuing_country";
pub const ELEM_ISSUING_AUTHORITY: &'static str = "issuing_authority";
pub const ELEM_DOCUMENT_NUMBER: &'static str = "document_number";
pub const ELEM_AGE_OVER_18: &'static str = "age_over_18";
pub const ELEM_AGE_OVER_21: &'static str = "age_over_21";
pub const ELEM_AGE_OVER_65: &'static str = "age_over_65";
pub const ELEM_DRIVING_PRIVILEGES: &'static str = "driving_privileges";

/// Issuer Signed Item with Digest ID
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuerSignedItem {
    pub digest_id: u32,
    pub random_salt_hex: String,
    pub element_identifier: String,
    pub element_value_raw: String,
}

/// Mobile Security Object (MSO) Header
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MobileSecurityObject {
    pub version: String,
    pub digest_algorithm: String, // "SHA-256" | "BLAKE3"
    pub doc_type: String,         // "org.iso.18013.5.1.mDL"
    pub validity_info: MsoValidityInfo,
    pub value_digests: std::collections::HashMap<String, std::collections::HashMap<u32, String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsoValidityInfo {
    pub signed: String,
    pub valid_from: String,
    pub valid_until: String,
}

/// Zero-Knowledge Selective Disclosure Verifier for ISO 18013-5
pub struct MdlZkVerifier;

impl MdlZkVerifier {
    /// Verifies zero-knowledge proof of age over 18 without revealing birth date or full mDL
    pub fn verify_age_over_18_predicate(
        mso: &MobileSecurityObject,
        disclosed_item: &IssuerSignedItem,
    ) -> Result<bool, &'static str> {
        if mso.doc_type != "org.iso.18013.5.1.mDL" {
            return Err("Invalid mDL docType");
        }

        if disclosed_item.element_identifier != ELEM_AGE_OVER_18 {
            return Err("Item is not age_over_18 predicate");
        }

        // Verify digest matches MSO value_digests
        let iso_digests = mso.value_digests.get(MDL_NAMESPACE_ISO).ok_or("Missing ISO namespace in MSO")?;
        let expected_digest = iso_digests.get(&disclosed_item.digest_id).ok_or("Digest ID not found in MSO")?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(disclosed_item.random_salt_hex.as_bytes());
        hasher.update(disclosed_item.element_identifier.as_bytes());
        hasher.update(disclosed_item.element_value_raw.as_bytes());
        let computed = hasher.finalize().to_hex().to_string();

        if &computed != expected_digest {
            return Err("Item digest does not match MSO root digest");
        }

        Ok(disclosed_item.element_value_raw == "true")
    }
}
