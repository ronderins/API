//! Multi-Party Computation (MPC) Trusted Setup Suite
//!
//! Submodules:
//! - `ceremony`: Powers-of-Tau ceremony coordinator and contribution pipeline.
//! - `transcript`: Cryptographically chained verifiable contribution transcript.
//! - `lagrange`: Lagrange basis polynomial evaluator for QAP synthesis.

pub mod ceremony;
pub mod lagrange;
pub mod transcript;

pub use ceremony::{ContributorSecret, MpcContribution, MpcCoordinator};
pub use lagrange::LagrangeBasis;
pub use transcript::CeremonyTranscript;
