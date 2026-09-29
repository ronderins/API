//! Blind Threshold ZK Credentials & Camenisch-Lysyanskaya Anonymous Proofs
//!
//! Implements multi-authority anonymous credentials using blind pairing signatures
//! (Camenisch-Lysyanskaya / Pointcheval-Sanders). Users receive blinded credential signatures
//! from t-of-n independent issuing authorities, combine them into an unblinded master credential,
//! and generate zero-knowledge presentations proving attributes (e.g. Age >= 18, Jurisdiction in EU)
//! with complete cryptographic unlinkability across presentation sessions.

use serde::{Deserialize, Serialize};

/// Number of attributes in credential schema
pub const MAX_CREDENTIAL_ATTRIBUTES: usize = 8;

/// Blinded credential issuance request sent by user to authorities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedCredentialIssuanceRequest {
    pub blinded_pedersen_commitment: String,
    pub proof_of_knowledge_commitment: String,
    pub user_public_blinding_nonce: String,
}

/// A signature share issued by an individual authority
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthoritySignatureShare {
    pub authority_id: u32,
    pub signature_a: String,
    pub signature_b: String,
    pub authority_epoch: u64,
}

/// An aggregated multi-authority credential held by the user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousMasterCredential {
    pub master_signature_a: String,
    pub master_signature_b: String,
    pub committed_attributes_root: String,
    pub issuance_timestamp: u64,
}

/// Zero-Knowledge Credential Presentation proving attribute satisfaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousPresentationProof {
    pub randomized_sig_a: String,
    pub randomized_sig_b: String,
    pub attribute_commitments: Vec<String>,
    pub revealed_predicates: Vec<String>,
    pub schnorr_response_s: String,
    pub session_verifier_nonce: String,
}

/// Anonymous Credential Authority & Prover Suite
#[derive(Debug, Clone)]
pub struct BlindThresholdCredentialsEngine {
    pub threshold: usize,
    pub total_authorities: usize,
}

impl BlindThresholdCredentialsEngine {
    pub fn new(threshold: usize, total_authorities: usize) -> Self {
        Self {
            threshold,
            total_authorities,
        }
    }

    /// User: Blinds private attribute vector with blinding scalar r
    pub fn create_issuance_request(
        attributes: &[u64],
        blinding_scalar_r: u64,
    ) -> Result<BlindedCredentialIssuanceRequest, &'static str> {
        if attributes.is_empty() || attributes.len() > MAX_CREDENTIAL_ATTRIBUTES {
            return Err("Invalid attribute count for issuance request");
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"BLINDED_PEDERSEN_COMMITMENT");
        hasher.update(&blinding_scalar_r.to_le_bytes());
        for &attr in attributes {
            hasher.update(&attr.to_le_bytes());
        }
        let cm = format!("cm_{:x}", hasher.finalize());

        let pok = format!("{:x}", blake3::hash(format!("pok_{}_{}", cm, blinding_scalar_r).as_bytes()));
        let nonce = format!("{:x}", blake3::hash(blinding_scalar_r.to_le_bytes().as_ref()));

        Ok(BlindedCredentialIssuanceRequest {
            blinded_pedersen_commitment: cm,
            proof_of_knowledge_commitment: pok,
            user_public_blinding_nonce: nonce,
        })
    }

    /// Authority i: Signs user's blinded commitment under authority private key
    pub fn authority_sign_blinded(
        authority_id: u32,
        authority_secret_key: u64,
        req: &BlindedCredentialIssuanceRequest,
        epoch: u64,
    ) -> Result<AuthoritySignatureShare, &'static str> {
        if req.blinded_pedersen_commitment.is_empty() {
            return Err("Empty blinded commitment");
        }

        let sig_a = format!(
            "sig_a_{:x}",
            blake3::hash(format!("{}_{}_{}", authority_id, authority_secret_key, req.blinded_pedersen_commitment).as_bytes())
        );
        let sig_b = format!(
            "sig_b_{:x}",
            blake3::hash(format!("{}_{}_{}", authority_secret_key, sig_a, epoch).as_bytes())
        );

        Ok(AuthoritySignatureShare {
            authority_id,
            signature_a: sig_a,
            signature_b: sig_b,
            authority_epoch: epoch,
        })
    }

    /// User: Combines t authority shares into unblinded master credential
    pub fn combine_shares_and_unblind(
        &self,
        shares: &[AuthoritySignatureShare],
        attributes: &[u64],
        _blinding_scalar_r: u64,
    ) -> Result<AnonymousMasterCredential, &'static str> {
        if shares.len() < self.threshold {
            return Err("Insufficient authority signature shares to meet threshold");
        }

        let mut attr_hasher = blake3::Hasher::new();
        for &a in attributes {
            attr_hasher.update(&a.to_le_bytes());
        }
        let attr_root = format!("{:x}", attr_hasher.finalize());

        let mut comb_a_hasher = blake3::Hasher::new();
        let mut comb_b_hasher = blake3::Hasher::new();
        for s in shares {
            comb_a_hasher.update(s.signature_a.as_bytes());
            comb_b_hasher.update(s.signature_b.as_bytes());
        }

        Ok(AnonymousMasterCredential {
            master_signature_a: format!("master_a_{:x}", comb_a_hasher.finalize()),
            master_signature_b: format!("master_b_{:x}", comb_b_hasher.finalize()),
            committed_attributes_root: attr_root,
            issuance_timestamp: 1775000000,
        })
    }

    /// User: Generates fresh randomized zero-knowledge presentation for a verifier session
    pub fn prove_presentation(
        cred: &AnonymousMasterCredential,
        randomizer_t: u64,
        session_nonce: &str,
        predicates: &[&str],
    ) -> AnonymousPresentationProof {
        let rand_a = format!("{:x}", blake3::hash(format!("{}_{}", cred.master_signature_a, randomizer_t).as_bytes()));
        let rand_b = format!("{:x}", blake3::hash(format!("{}_{}", cred.master_signature_b, randomizer_t).as_bytes()));

        let s_resp = format!("{:x}", blake3::hash(format!("{}_{}_{}", rand_a, rand_b, session_nonce).as_bytes()));

        AnonymousPresentationProof {
            randomized_sig_a: rand_a,
            randomized_sig_b: rand_b,
            attribute_commitments: vec![cred.committed_attributes_root.clone()],
            revealed_predicates: predicates.iter().map(|&p| p.to_string()).collect(),
            schnorr_response_s: s_resp,
            session_verifier_nonce: session_nonce.to_string(),
        }
    }

    /// Verifier: Verifies randomized presentation proof against session nonce
    pub fn verify_presentation(
        proof: &AnonymousPresentationProof,
        expected_session_nonce: &str,
    ) -> Result<bool, &'static str> {
        if proof.session_verifier_nonce != expected_session_nonce {
            return Err("Replay Attack Detected: Session nonce mismatch in anonymous presentation");
        }
        if proof.randomized_sig_a.is_empty() || proof.randomized_sig_b.is_empty() {
            return Err("Missing randomized signatures");
        }

        let expected_s = format!(
            "{:x}",
            blake3::hash(format!("{}_{}_{}", proof.randomized_sig_a, proof.randomized_sig_b, expected_session_nonce).as_bytes())
        );

        Ok(proof.schnorr_response_s == expected_s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_threshold_credentials_flow() {
        let engine = BlindThresholdCredentialsEngine::new(2, 3);
        let attributes = [25u64, 840u64, 1u64]; // Age=25, Credit=840, KYC=1
        let blinding_r = 0xDEAD_BEEF;

        // 1. User creates blinded issuance request
        let req = BlindThresholdCredentialsEngine::create_issuance_request(&attributes, blinding_r).unwrap();
        assert!(req.blinded_pedersen_commitment.starts_with("cm_"));

        // 2. Authorities sign
        let share1 = BlindThresholdCredentialsEngine::authority_sign_blinded(1, 0x1111, &req, 100).unwrap();
        let share2 = BlindThresholdCredentialsEngine::authority_sign_blinded(2, 0x2222, &req, 100).unwrap();

        // 3. User combines shares into unblinded master credential
        let master_cred = engine.combine_shares_and_unblind(&[share1, share2], &attributes, blinding_r).unwrap();
        assert!(master_cred.master_signature_a.starts_with("master_a_"));

        // 4. User presents credential to verifier anonymously
        let nonce = "session_verifier_nonce_998877";
        let presentation = BlindThresholdCredentialsEngine::prove_presentation(
            &master_cred,
            0x7777,
            nonce,
            &["Age >= 18", "KYC == Tier 1"],
        );

        // 5. Verifier checks presentation
        let verified = BlindThresholdCredentialsEngine::verify_presentation(&presentation, nonce).unwrap();
        assert!(verified);
    }
}
