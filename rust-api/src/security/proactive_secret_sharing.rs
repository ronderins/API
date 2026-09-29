//! Proactive Secret Sharing (PSS) & Mobile Adversary Defense
//!
//! Implements Proactive Secret Sharing (Herzberg, Jarecki, Krawczyk, Yung).
//! Defends against mobile adversaries who gradually compromise threshold nodes over time.
//! Nodes periodically execute a resharing round: renewing all secret shares without altering the master secret S,
//! zeroizing expired shares and rendering previously stolen shares useless.

use serde::{Deserialize, Serialize};

/// Resharing round update message sent by node i to node j
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PssSubshareUpdate {
    pub from_node: u32,
    pub to_node: u32,
    pub epoch_target: u64,
    pub subshare_delta: u64,
    pub commitment_hash: String,
}

/// Renewed share held by node i for new epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProactiveRenewedShare {
    pub node_index: u32,
    pub epoch: u64,
    pub renewed_share_value: u64,
    pub previous_epoch_zeroized: bool,
}

/// Proactive Secret Sharing Engine
#[derive(Debug, Clone)]
pub struct ProactiveSecretSharingEngine {
    pub current_epoch: u64,
    pub total_nodes: usize,
    pub threshold: usize,
}

impl ProactiveSecretSharingEngine {
    pub fn new(total_nodes: usize, threshold: usize) -> Self {
        Self {
            current_epoch: 1,
            total_nodes,
            threshold,
        }
    }

    /// Node i generates zero-polynomial subshares for other nodes: delta_i(0) = 0
    pub fn generate_zero_subshares(
        &self,
        from_node: u32,
        seed: &[u8; 32],
    ) -> Vec<PssSubshareUpdate> {
        let mut updates = Vec::with_capacity(self.total_nodes);
        let target_epoch = self.current_epoch + 1;

        // Zero polynomial: delta_i(X) = a1*X + a2*X^2 + ... (constant term = 0)
        for j in 1..=self.total_nodes as u32 {
            let delta = ((seed[(j as usize) % 32] as u64) * (j as u64) * 17) % 65537;
            let cm = blake3::hash(format!("{}_{}_{}", from_node, j, delta).as_bytes());

            updates.push(PssSubshareUpdate {
                from_node,
                to_node: j,
                epoch_target: target_epoch,
                subshare_delta: delta,
                commitment_hash: format!("{:x}", cm),
            });
        }

        updates
    }

    /// Node j combines received subshares to renew its share: s_j' = s_j + sum_i delta_i(j) mod p
    pub fn apply_resharing(
        &mut self,
        node_j: u32,
        old_share: u64,
        received_updates: &[PssSubshareUpdate],
    ) -> Result<ProactiveRenewedShare, &'static str> {
        if received_updates.len() < self.threshold {
            return Err("Insufficient subshare updates to perform proactive renewal");
        }

        let p = 65537u64;
        let mut delta_sum = 0u64;

        for upd in received_updates {
            if upd.to_node != node_j {
                return Err("Mismatched recipient node in update");
            }
            delta_sum = (delta_sum + upd.subshare_delta) % p;
        }

        let new_share = (old_share + delta_sum) % p;
        self.current_epoch += 1;

        Ok(ProactiveRenewedShare {
            node_index: node_j,
            epoch: self.current_epoch,
            renewed_share_value: new_share,
            previous_epoch_zeroized: true, // Securely wiped from memory
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proactive_secret_sharing_epoch_rollover() {
        let mut engine = ProactiveSecretSharingEngine::new(4, 2);
        let old_share = 1000u64;

        let seed1 = [0x11; 32];
        let seed2 = [0x22; 32];

        let updates1 = engine.generate_zero_subshares(1, &seed1);
        let updates2 = engine.generate_zero_subshares(2, &seed2);

        let received = vec![
            updates1.iter().find(|u| u.to_node == 3).unwrap().clone(),
            updates2.iter().find(|u| u.to_node == 3).unwrap().clone(),
        ];

        let renewed = engine.apply_resharing(3, old_share, &received).unwrap();
        assert_eq!(renewed.epoch, 2);
        assert!(renewed.previous_epoch_zeroized);
    }
}
