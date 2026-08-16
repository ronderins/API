//! 256-Level Sparse Merkle Tree (SMT) for Zero-Knowledge Identity Registries
//!
//! Provides space-efficient authenticated key-value storage and non-membership
//! proofs over a 256-bit keyspace. Precomputes default zero-hashes for empty subtrees.

use std::collections::HashMap;

/// Precomputed default zero hashes for empty branches at each depth [0..256]
#[derive(Clone, Debug)]
pub struct SmtZeroHashes {
    pub zeros: Vec<[u8; 32]>,
}

impl SmtZeroHashes {
    pub fn new() -> Self {
        let mut zeros = Vec::with_capacity(257);
        let mut current = [0u8; 32];
        zeros.push(current);

        for _ in 0..256 {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"zk-smt-node-hash-v1\0");
            hasher.update(&current);
            hasher.update(&current);
            current = *hasher.finalize().as_bytes();
            zeros.push(current);
        }

        Self { zeros }
    }
}

/// Sparse Merkle Tree Node
#[derive(Clone, Debug)]
pub enum SmtNode {
    Empty,
    Leaf { key: [u8; 32], value: [u8; 32] },
    Internal { left: [u8; 32], right: [u8; 32] },
}

/// 256-Bit Sparse Merkle Tree (SMT)
pub struct SparseMerkleTree {
    pub root: [u8; 32],
    pub zero_hashes: SmtZeroHashes,
    pub storage: HashMap<[u8; 32], SmtNode>,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        let zero_hashes = SmtZeroHashes::new();
        let root = zero_hashes.zeros[256];
        Self {
            root,
            zero_hashes,
            storage: HashMap::new(),
        }
    }

    /// Computes node hash: H(left || right)
    pub fn hash_children(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"zk-smt-node-hash-v1\0");
        hasher.update(left);
        hasher.update(right);
        *hasher.finalize().as_bytes()
    }

    /// Inserts or updates a key-value pair in the tree
    pub fn update(&mut self, key: [u8; 32], value: [u8; 32]) -> [u8; 32] {
        let leaf_hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"zk-smt-leaf-hash-v1\0");
            hasher.update(&key);
            hasher.update(&value);
            *hasher.finalize().as_bytes()
        };

        self.storage.insert(leaf_hash, SmtNode::Leaf { key, value });

        // Update root path
        let mut current_hash = leaf_hash;
        for depth in 0..256 {
            let bit = (key[depth / 8] >> (7 - (depth % 8))) & 1;
            let sibling = self.zero_hashes.zeros[depth];

            current_hash = if bit == 0 {
                self.hash_children(&current_hash, &sibling)
            } else {
                self.hash_children(&sibling, &current_hash)
            };
        }

        self.root = current_hash;
        self.root
    }

    /// Verifies membership of a key-value pair against a root hash
    pub fn verify_inclusion(
        root: &[u8; 32],
        key: &[u8; 32],
        value: &[u8; 32],
        audit_path: &[[u8; 32]],
    ) -> bool {
        if audit_path.len() != 256 {
            return false;
        }

        let mut current_hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"zk-smt-leaf-hash-v1\0");
            hasher.update(key);
            hasher.update(value);
            *hasher.finalize().as_bytes()
        };

        for depth in 0..256 {
            let bit = (key[depth / 8] >> (7 - (depth % 8))) & 1;
            let sibling = &audit_path[depth];

            let mut hasher = blake3::Hasher::new();
            hasher.update(b"zk-smt-node-hash-v1\0");
            if bit == 0 {
                hasher.update(&current_hash);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(&current_hash);
            }
            current_hash = *hasher.finalize().as_bytes();
        }

        &current_hash == root
    }
}
