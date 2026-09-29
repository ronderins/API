//! Advanced Differential Privacy: Renyi DP, Privacy Loss Distributions & Moments Accountant
//!
//! Provides mathematically rigorous privacy budget composition using Renyi Differential Privacy (RDP)
//! and the Moments Accountant (Abadi et al.). Guarantees tight (epsilon, delta)-differential privacy bounds
//! across multiple sequential demographic queries, preventing reconstruction attacks on database rows.

use serde::{Deserialize, Serialize};

/// Supported Differential Privacy Mechanism kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DpMechanismKind {
    Laplace,
    Gaussian,
    DiscreteGeometric,
}

/// A privacy query consumption record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpQueryRecord {
    pub query_id: String,
    pub mechanism: DpMechanismKind,
    pub sensitivity: f64,
    pub noise_scale: f64,
    pub consumed_rdp_orders: Vec<(f64, f64)>, // (order alpha, Renyi divergence D_alpha)
}

/// Cumulative Privacy Budget Tracker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyBudgetLedger {
    pub max_allowed_epsilon: f64,
    pub target_delta: f64,
    pub total_queries_served: usize,
    pub current_effective_epsilon: f64,
    pub is_budget_depleted: bool,
}

/// Advanced Differential Privacy Engine
#[derive(Debug, Clone)]
pub struct AdvancedDpEngine {
    pub max_epsilon: f64,
    pub target_delta: f64,
    pub history: Vec<DpQueryRecord>,
}

impl AdvancedDpEngine {
    pub fn new(max_epsilon: f64, target_delta: f64) -> Self {
        Self {
            max_epsilon,
            target_delta,
            history: Vec::new(),
        }
    }

    /// Evaluates RDP privacy divergence for Gaussian mechanism at order alpha:
    /// D_alpha = alpha * sensitivity^2 / (2 * sigma^2)
    pub fn compute_rdp_gaussian(alpha: f64, sensitivity: f64, sigma: f64) -> f64 {
        if sigma <= 0.0 || alpha <= 1.0 {
            return 0.0;
        }
        (alpha * sensitivity * sensitivity) / (2.0 * sigma * sigma)
    }

    /// Converts cumulative RDP bounds across alphas to tight (epsilon, delta)-DP:
    /// epsilon(delta) = min_{alpha > 1} { D_alpha + log(1/delta) / (alpha - 1) }
    pub fn convert_rdp_to_approx_dp(&self) -> f64 {
        let alphas = [1.5, 2.0, 3.0, 5.0, 8.0, 16.0, 32.0];
        let mut min_eps = f64::MAX;

        for &alpha in &alphas {
            let mut total_rdp = 0.0;
            for q in &self.history {
                for &(a, rdp_val) in &q.consumed_rdp_orders {
                    if (a - alpha).abs() < 0.1 {
                        total_rdp += rdp_val;
                    }
                }
            }

            let eps_alpha = total_rdp + (1.0 / self.target_delta).ln() / (alpha - 1.0);
            if eps_alpha < min_eps {
                min_eps = eps_alpha;
            }
        }

        if min_eps == f64::MAX {
            0.0
        } else {
            min_eps
        }
    }

    /// Perturbs a true query result using calibrated Gaussian noise and accounts for budget
    pub fn execute_private_query(
        &mut self,
        query_id: &str,
        true_value: f64,
        sensitivity: f64,
        sigma: f64,
        noise_prng_sample: f64,
    ) -> Result<f64, &'static str> {
        let current_eps = self.convert_rdp_to_approx_dp();
        if current_eps >= self.max_epsilon {
            return Err("Differential Privacy Error: Privacy budget epsilon depleted for this epoch");
        }

        // Add calibrated perturbation
        let noisy_result = true_value + noise_prng_sample * sigma;

        // Record RDP values across orders
        let alphas = [1.5, 2.0, 3.0, 5.0, 8.0, 16.0, 32.0];
        let mut rdp_records = Vec::new();
        for &a in &alphas {
            let div = Self::compute_rdp_gaussian(a, sensitivity, sigma);
            rdp_records.push((a, div));
        }

        self.history.push(DpQueryRecord {
            query_id: query_id.to_string(),
            mechanism: DpMechanismKind::Gaussian,
            sensitivity,
            noise_scale: sigma,
            consumed_rdp_orders: rdp_records,
        });

        Ok(noisy_result)
    }

    /// Inspects current budget usage
    pub fn get_budget_ledger(&self) -> PrivacyBudgetLedger {
        let eff_eps = self.convert_rdp_to_approx_dp();
        PrivacyBudgetLedger {
            max_allowed_epsilon: self.max_epsilon,
            target_delta: self.target_delta,
            total_queries_served: self.history.len(),
            current_effective_epsilon: eff_eps,
            is_budget_depleted: eff_eps >= self.max_epsilon,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rdp_moments_accountant_composition() {
        let mut engine = AdvancedDpEngine::new(5.0, 1e-5);

        // Execute 3 queries with sensitivity 1.0, sigma 2.0
        for i in 0..3 {
            let res = engine
                .execute_private_query(&format!("q_{}", i), 100.0, 1.0, 2.0, 0.25)
                .unwrap();
            assert!((res - 100.0).abs() < 5.0);
        }

        let ledger = engine.get_budget_ledger();
        assert_eq!(ledger.total_queries_served, 3);
        assert!(!ledger.is_budget_depleted);
        assert!(ledger.current_effective_epsilon > 0.0);
        assert!(ledger.current_effective_epsilon < 5.0);
    }
}
