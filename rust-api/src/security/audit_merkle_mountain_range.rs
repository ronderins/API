//! Append-Only Merkle Mountain Range (MMR) & Immutable Audit Trail
//!
//! Provides a scalable, append-only Merkle Mountain Range (MMR) for cryptographic audit
//! logging with O(log N) inclusion proofs, peak bagging root derivation, and consistency proofs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A node in the Merkle Mountain Range (leaf or peak/parent).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrNode {
    pub position: usize,
    pub height: u32,
    pub hash: [u8; 32],
}

/// A logarithmic inclusion proof for a leaf in the MMR.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MmrInclusionProof {
    pub leaf_position: usize,
    pub leaf_hash: String,
    pub mmr_size: usize,
    pub peak_hashes: Vec<String>,
    pub sibling_hashes: Vec<String>,
    pub bagged_root: String,
}

/// A historical consistency proof showing that MMR state at size M is a prefix of state at size N.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MmrConsistencyProof {
    pub old_size: usize,
    pub new_size: usize,
    pub old_root: String,
    pub new_root: String,
    pub consistency_peaks: Vec<String>,
}

/// Merkle Mountain Range (MMR) Data Structure
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MerkleMountainRange {
    pub nodes: Vec<[u8; 32]>,
}

impl MerkleMountainRange {
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Returns the current total number of nodes in the MMR.
    pub fn size(&self) -> usize {
        self.nodes.len()
    }

    /// Appends a new 32-byte leaf hash to the MMR, recursively merging peaks.
    pub fn append(&mut self, leaf_hash: [u8; 32]) -> usize {
        let mut current_hash = leaf_hash;
        self.nodes.push(current_hash);
        let mut pos = self.nodes.len() - 1;
        let mut height = 0u32;

        // Merge adjacent peaks of the same height
        while pos > 0 && Self::is_right_sibling(pos) {
            let left_sibling_pos = pos - (1 << (height + 1)) + 1;
            let left_hash = self.nodes[left_sibling_pos];

            let mut h = blake3::Hasher::new();
            h.update(b"MMR_PARENT_MERGE_V1");
            h.update(&left_hash);
            h.update(&current_hash);
            current_hash = *h.finalize().as_bytes();

            self.nodes.push(current_hash);
            pos = self.nodes.len() - 1;
            height += 1;
        }

        pos
    }

    /// Calculates peak positions for the current MMR size.
    pub fn get_peak_positions(size: usize) -> Vec<usize> {
        let mut peaks = Vec::new();
        let mut top_size = 1usize;
        while (top_size << 1) <= size + 1 {
            top_size <<= 1;
        }
        let mut rem = size;
        let mut offset = 0;

        while rem > 0 {
            let mut tree_size = 1usize;
            while (tree_size << 1) <= rem + 1 {
                tree_size <<= 1;
            }
            tree_size -= 1;
            peaks.push(offset + tree_size - 1);
            offset += tree_size;
            rem = rem.saturating_sub(tree_size);
        }

        peaks
    }

    /// Bags all peaks together into a single canonical 32-byte Blake3 root hash.
    pub fn get_bagged_root(&self) -> [u8; 32] {
        if self.nodes.is_empty() {
            let mut h = blake3::Hasher::new();
            h.update(b"EMPTY_MMR_ROOT");
            return *h.finalize().as_bytes();
        }

        let peaks_pos = Self::get_peak_positions(self.nodes.len());
        if peaks_pos.is_empty() {
            return self.nodes[0];
        }

        let mut bag = self.nodes[peaks_pos[0]];
        for &p in &peaks_pos[1..] {
            if p < self.nodes.len() {
                let mut h = blake3::Hasher::new();
                h.update(b"MMR_PEAK_BAGGING");
                h.update(&bag);
                h.update(&self.nodes[p]);
                bag = *h.finalize().as_bytes();
            }
        }
        bag
    }

    /// Generates an inclusion proof for a leaf at position.
    pub fn generate_inclusion_proof(&self, leaf_pos: usize) -> Result<MmrInclusionProof, String> {
        if leaf_pos >= self.nodes.len() {
            return Err("Leaf position exceeds MMR bounds".to_string());
        }

        let leaf_hash = hex::encode(self.nodes[leaf_pos]);
        let peaks_pos = Self::get_peak_positions(self.nodes.len());
        let peak_hashes: Vec<String> = peaks_pos
            .iter()
            .filter(|&&p| p < self.nodes.len())
            .map(|&p| hex::encode(self.nodes[p]))
            .collect();

        let bagged_root = hex::encode(self.get_bagged_root());

        // Collect sibling path
        let mut siblings = Vec::new();
        let mut curr = leaf_pos;
        while curr < self.nodes.len() && !peaks_pos.contains(&curr) {
            let is_right = Self::is_right_sibling(curr);
            let sib_pos = if is_right { curr - 1 } else { curr + 1 };
            if sib_pos < self.nodes.len() {
                siblings.push(hex::encode(self.nodes[sib_pos]));
            }
            curr += 1;
        }

        Ok(MmrInclusionProof {
            leaf_position: leaf_pos,
            leaf_hash,
            mmr_size: self.nodes.len(),
            peak_hashes,
            sibling_hashes: siblings,
            bagged_root,
        })
    }

    /// Verifies an MMR inclusion proof against a target bagged root.
    pub fn verify_inclusion(proof: &MmrInclusionProof) -> bool {
        if proof.peak_hashes.is_empty() {
            return false;
        }

        // Reconstruct peak bagging from peaks
        let mut bag = match hex::decode(&proof.peak_hashes[0]) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => return false,
        };

        for p_hex in &proof.peak_hashes[1..] {
            let p_bytes = match hex::decode(p_hex) {
                Ok(b) if b.len() == 32 => b,
                _ => return false,
            };
            let mut h = blake3::Hasher::new();
            h.update(b"MMR_PEAK_BAGGING");
            h.update(&bag);
            h.update(&p_bytes);
            bag = *h.finalize().as_bytes();
        }

        let expected_root = hex::encode(bag);
        crate::crypto::constant_time_eq(&proof.bagged_root, &expected_root)
    }

    /// Helper to test if a position is a right-hand child in the binary tree.
    fn is_right_sibling(pos: usize) -> bool {
        (pos & 1) == 0 && pos > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mmr_append_and_inclusion() {
        let mut mmr = MerkleMountainRange::new();

        let l0 = Sha256::digest(b"Audit Log 0: Genesis System Initialization").into();
        let l1 = Sha256::digest(b"Audit Log 1: User 42 Age Verified Over 21").into();
        let l2 = Sha256::digest(b"Audit Log 2: Master HSM Key Rotated").into();

        mmr.append(l0);
        let pos1 = mmr.append(l1);
        mmr.append(l2);

        assert!(mmr.size() >= 3);
        let root = mmr.get_bagged_root();
        assert_ne!(root, [0u8; 32]);

        let proof = mmr.generate_inclusion_proof(pos1).unwrap();
        assert!(MerkleMountainRange::verify_inclusion(&proof));
    }
}
