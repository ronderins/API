//! In-Circuit Cryptographic Gadgets Standard Library
//!
//! Submodules:
//! - `bit_decomposition`: Boolean constraining and N-bit range decomposition.
//! - `comparator`: Less-than, greater-than, and equality constraint gadgets.
//! - `merkle_gadget`: SMT depth-32 Poseidon inclusion verifier gadget.

pub mod bit_decomposition;
pub mod comparator;
pub mod merkle_gadget;

pub use bit_decomposition::BitDecompositionGadget;
pub use comparator::ComparatorGadget;
pub use merkle_gadget::MerkleInclusionGadget;
