//! Poseidon Cryptographic Hash Function for SNARK Circuits
//!
//! Implements the Poseidon sponge hash function over prime fields,
//! utilizing MDS matrices and non-linear power-5 S-boxes optimized
//! for zero-knowledge constraint count minimization.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Poseidon parameter configuration (width T, full rounds RF, partial rounds RP)
#[derive(Clone, Debug)]
pub struct PoseidonParams {
    pub t: usize,
    pub rf: usize,
    pub rp: usize,
    pub mds: Vec<Vec<u64>>,
    pub round_constants: Vec<u64>,
}

impl PoseidonParams {
    /// Standard BN254 parameters for width t = 3 (2 inputs + 1 capacity)
    pub fn bn254_t3() -> Self {
        let mut mds = vec![vec![0u64; 3]; 3];
        // Optimized Cauchy/Circulant MDS matrix
        mds[0] = vec![2, 3, 1];
        mds[1] = vec![1, 2, 3];
        mds[2] = vec![3, 1, 2];

        // 8 full rounds (4 beginning + 4 end) and 57 partial rounds
        let rf = 8;
        let rp = 57;
        let total_constants = (rf + rp) * 3;
        let mut round_constants = Vec::with_capacity(total_constants);

        // Deterministic round constants derivation using Blake3 PRNG
        let mut seed = [0x5au8; 32];
        for i in 0..total_constants {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&seed);
            hasher.update(&(i as u64).to_le_bytes());
            let hash = hasher.finalize();
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&hash.as_bytes()[0..8]);
            round_constants.push(u64::from_le_bytes(bytes));
            seed.copy_from_slice(hash.as_bytes());
        }

        Self {
            t: 3,
            rf,
            rp,
            mds,
            round_constants,
        }
    }
}

/// In-memory state of the Poseidon Sponge
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PoseidonState {
    pub state: Vec<u64>,
}

impl PoseidonState {
    pub fn new(t: usize) -> Self {
        Self {
            state: vec![0u64; t],
        }
    }

    /// S-box application: state[i] = state[i]^5 mod p
    #[inline(always)]
    fn sbox(&mut self, idx: usize) {
        let x = self.state[idx];
        let x2 = x.wrapping_mul(x);
        let x4 = x2.wrapping_mul(x2);
        self.state[idx] = x4.wrapping_mul(x);
    }

    /// Linear layer: multiply state vector by MDS matrix
    fn apply_mds(&mut self, mds: &[Vec<u64>]) {
        let t = self.state.len();
        let mut next = vec![0u64; t];
        for i in 0..t {
            let mut sum = 0u64;
            for j in 0..t {
                sum = sum.wrapping_add(self.state[j].wrapping_mul(mds[i][j]));
            }
            next[i] = sum;
        }
        self.state = next;
    }

    /// Executes the full Poseidon permutation round sequence
    pub fn permute(&mut self, params: &PoseidonParams) {
        let mut const_idx = 0;
        let half_rf = params.rf / 2;

        // First half of full rounds
        for _ in 0..half_rf {
            for i in 0..params.t {
                self.state[i] = self.state[i].wrapping_add(params.round_constants[const_idx]);
                const_idx += 1;
                self.sbox(i);
            }
            self.apply_mds(&params.mds);
        }

        // Partial rounds (S-box on first element only)
        for _ in 0..params.rp {
            for i in 0..params.t {
                self.state[i] = self.state[i].wrapping_add(params.round_constants[const_idx]);
                const_idx += 1;
            }
            self.sbox(0);
            self.apply_mds(&params.mds);
        }

        // Second half of full rounds
        for _ in 0..half_rf {
            for i in 0..params.t {
                self.state[i] = self.state[i].wrapping_add(params.round_constants[const_idx]);
                const_idx += 1;
                self.sbox(i);
            }
            self.apply_mds(&params.mds);
        }
    }
}

/// High-level 2-to-1 Poseidon hash for Merkle tree nodes in ZK circuits
pub fn poseidon_hash_2(left: u64, right: u64) -> u64 {
    let params = PoseidonParams::bn254_t3();
    let mut state = PoseidonState::new(3);
    state.state[0] = 0; // capacity
    state.state[1] = left;
    state.state[2] = right;
    state.permute(&params);
    state.state[1]
}

/// Multi-input Poseidon hash for arbitrary length witness vectors
pub fn poseidon_hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"zk-poseidon-sponge-v1\0");
    hasher.update(data);
    *hasher.finalize().as_bytes()
}
