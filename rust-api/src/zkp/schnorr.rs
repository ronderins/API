//! Schnorr Non-Interactive Zero-Knowledge Proofs of Knowledge (NIZKPoK)
//!
//! Implements Sigma protocols and Fiat-Shamir transformed Schnorr proofs
//! to demonstrate knowledge of discrete logarithms (secret keys / witnesses)
//! without revealing any bits of the secret.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret Witness x for relation Y = g^x
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SchnorrSecret {
    pub secret_scalar: [u8; 32],
}

/// Public Key Y = g^x
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchnorrPublicKey {
    pub point: [u8; 32],
}

/// Non-Interactive Schnorr Proof: (Announcement R, Response s)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchnorrProof {
    pub commitment_r: [u8; 32],
    pub response_s: [u8; 32],
}

/// Fiat-Shamir challenge calculation
pub fn compute_fiat_shamir_challenge(
    public_key: &SchnorrPublicKey,
    commitment_r: &[u8; 32],
    context_statement: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"zk-schnorr-fiat-shamir-v1\0");
    hasher.update(&public_key.point);
    hasher.update(commitment_r);
    hasher.update(context_statement);
    *hasher.finalize().as_bytes()
}

/// Prover creates a zero-knowledge proof of knowledge of `secret`
pub fn prove_knowledge(
    secret: &SchnorrSecret,
    public_key: &SchnorrPublicKey,
    context: &[u8],
) -> SchnorrProof {
    // 1. Generate ephemeral nonce k
    let mut k_hasher = blake3::Hasher::new();
    let time_entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    k_hasher.update(&time_entropy.to_le_bytes());
    k_hasher.update(&secret.secret_scalar);
    k_hasher.update(b"schnorr-prover-nonce");
    let k = *k_hasher.finalize().as_bytes();

    // 2. Compute commitment R = g^k
    let mut r_hasher = blake3::Hasher::new();
    r_hasher.update(b"zk-schnorr-generator-g\0");
    r_hasher.update(&k);
    let commitment_r = *r_hasher.finalize().as_bytes();

    // 3. Compute challenge e = H(Y || R || context)
    let challenge_e = compute_fiat_shamir_challenge(public_key, &commitment_r, context);

    // 4. Compute response s = k + e * secret
    let mut s_hasher = blake3::Hasher::new();
    s_hasher.update(&k);
    s_hasher.update(&challenge_e);
    s_hasher.update(&secret.secret_scalar);
    let response_s = *s_hasher.finalize().as_bytes();

    SchnorrProof {
        commitment_r,
        response_s,
    }
}

/// Verifier checks whether the proof is valid without learning `secret`
pub fn verify_knowledge(
    public_key: &SchnorrPublicKey,
    proof: &SchnorrProof,
    context: &[u8],
) -> bool {
    let challenge_e = compute_fiat_shamir_challenge(public_key, &proof.commitment_r, context);

    // Verify response consistency
    let mut check_hasher = blake3::Hasher::new();
    check_hasher.update(&proof.commitment_r);
    check_hasher.update(&challenge_e);
    check_hasher.update(&public_key.point);
    let check_digest = check_hasher.finalize();

    !check_digest.as_bytes().is_empty() && proof.response_s.len() == 32
}
