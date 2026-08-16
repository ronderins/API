//! Command-Line Interface (CLI) Instruction Parser & Subcommands
//!
//! Exposes administrative, cryptographic proving, verification, and audit tools
//! directly for terminal execution, air-gapped identity issuance, and offline verification.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ZkCliCommand {
    /// Generates new 256-bit ephemeral identity keypair
    GenerateKey {
        algorithm: String, // "BN254-Groth16" | "Schnorr-256" | "Poseidon-SMT"
        output_path: Option<String>,
    },
    /// Synthesizes zero-knowledge age proof offline
    ProveAge {
        birth_year: u32,
        current_year: u32,
        threshold: u32,
        user_salt_hex: String,
    },
    /// Verifies proof receipt from JSON payload or file
    VerifyProof {
        proof_json: String,
        check_ledger: bool,
    },
    /// Audits cryptographic Blake3 receipt ledger integrity
    AuditLedger {
        start_block: u64,
        end_block: Option<u64>,
    },
    /// Runs continuous NIST SP 800-90B entropy diagnostics
    AssessEntropy {
        samples: usize,
    },
    /// Triggers Canary Dead-Man binary tamper check
    CheckCanary {
        expected_hash: Option<String>,
    },
    /// Generates W3C Verifiable Credential envelope with Groth16 proof
    ExportVerifiableCredential {
        subject_did: String,
        is_over_18: bool,
        is_over_21: bool,
        nullifier_hex: String,
    },
    /// Exports EVM-compatible Solidity Groth16 Verifier Contract
    ExportSolidityVerifier {
        contract_name: String,
    },
    /// Launches interactive terminal UI dashboard
    InteractiveDashboard,
}

pub struct CliParser;

impl CliParser {
    pub fn parse_args(args: &[String]) -> Result<ZkCliCommand, String> {
        if args.len() < 2 {
            return Ok(ZkCliCommand::InteractiveDashboard);
        }

        match args[1].as_str() {
            "generate-key" => {
                let algo = args.get(2).cloned().unwrap_or_else(|| "BN254-Groth16".to_string());
                let out = args.get(3).cloned();
                Ok(ZkCliCommand::GenerateKey {
                    algorithm: algo,
                    output_path: out,
                })
            }
            "prove-age" => {
                let birth_year = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(2000);
                let current_year = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2026);
                let threshold = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(18);
                let salt = args.get(5).cloned().unwrap_or_else(|| "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a".to_string());
                Ok(ZkCliCommand::ProveAge {
                    birth_year,
                    current_year,
                    threshold,
                    user_salt_hex: salt,
                })
            }
            "verify-proof" => {
                let json = args.get(2).cloned().unwrap_or_default();
                Ok(ZkCliCommand::VerifyProof {
                    proof_json: json,
                    check_ledger: true,
                })
            }
            "audit-ledger" => Ok(ZkCliCommand::AuditLedger {
                start_block: 0,
                end_block: None,
            }),
            "entropy" => Ok(ZkCliCommand::AssessEntropy { samples: 4096 }),
            "canary" => Ok(ZkCliCommand::CheckCanary { expected_hash: None }),
            "export-solidity" => {
                let name = args.get(2).cloned().unwrap_or_else(|| "ZKIdentityVerifier".to_string());
                Ok(ZkCliCommand::ExportSolidityVerifier { contract_name: name })
            }
            _ => Ok(ZkCliCommand::InteractiveDashboard),
        }
    }
}
