//! Cryptographic Merkle Trees and Accumulators
//!
//! Submodules:
//! - `sparse_tree`: 256-level Sparse Merkle Tree (SMT) with zero-knowledge membership paths.
//! - `blake3_chain`: Parallel Blake3 Merkle tree and audit inclusion verifier.

pub mod blake3_chain;
pub mod sparse_tree;
