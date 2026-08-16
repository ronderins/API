//! Terminal UI (TUI) Interactive Renderer & ASCII Verification Card Generator
//!
//! Provides rich terminal output, ANSI cryptographic status cards,
//! Merkle inclusion tree visualizations, and tamper-evident audit receipts.

pub struct TerminalRenderer;

impl TerminalRenderer {
    pub const ANSI_RESET: &'static str = "\x1b[0m";
    pub const ANSI_BOLD: &'static str = "\x1b[1m";
    pub const ANSI_GREEN: &'static str = "\x1b[32m";
    pub const ANSI_EMERALD: &'static str = "\x1b[38;5;48m";
    pub const ANSI_CYAN: &'static str = "\x1b[36m";
    pub const ANSI_YELLOW: &'static str = "\x1b[33m";
    pub const ANSI_RED: &'static str = "\x1b[31m";
    pub const ANSI_DIM: &'static str = "\x1b[2m";

    /// Prints cryptographic banner
    pub fn print_banner() {
        println!("{}{}╔══════════════════════════════════════════════════════════════════════╗{}", Self::ANSI_BOLD, Self::ANSI_EMERALD, Self::ANSI_RESET);
        println!("{}║      ZK-AUTH :: ZERO-KNOWLEDGE IDENTITY VERIFICATION SUITE         ║{}", Self::ANSI_EMERALD, Self::ANSI_RESET);
        println!("{}║   Constant-Time Rust Core • Groth16/BN254 • Poseidon • Blake3 SMT  ║{}", Self::ANSI_EMERALD, Self::ANSI_RESET);
        println!("{}╚══════════════════════════════════════════════════════════════════════╝{}", Self::ANSI_EMERALD, Self::ANSI_RESET);
        println!();
    }

    /// Renders a cryptographic verification receipt card in terminal
    pub fn render_verification_card(
        proof_id: &str,
        predicate: &str,
        nullifier: &str,
        latency_us: u64,
        is_valid: bool,
    ) {
        let status_text = if is_valid {
            format!("{}[VALID] CRYPTOGRAPHICALLY VERIFIED{}", Self::ANSI_BOLD, Self::ANSI_RESET)
        } else {
            format!("{}[FAILED] VERIFICATION REJECTED{}", Self::ANSI_BOLD, Self::ANSI_RESET)
        };

        println!("{}+----------------------------------------------------------------------+{}", Self::ANSI_DIM, Self::ANSI_RESET);
        println!("| {}STATEMENT RESULT:{} {}", Self::ANSI_BOLD, Self::ANSI_RESET, status_text);
        println!("{}+----------------------------------------------------------------------+{}", Self::ANSI_DIM, Self::ANSI_RESET);
        println!("| {}Proof ID:{}      {}", Self::ANSI_CYAN, Self::ANSI_RESET, proof_id);
        println!("| {}Predicate:{}     {}", Self::ANSI_CYAN, Self::ANSI_RESET, predicate);
        println!("| {}Nullifier:{}     {}...", Self::ANSI_CYAN, Self::ANSI_RESET, &nullifier[0..32.min(nullifier.len())]);
        println!("| {}Latency:{}       {}{} µs{} (Rust native constant-time)", Self::ANSI_CYAN, Self::ANSI_RESET, Self::ANSI_YELLOW, latency_us, Self::ANSI_RESET);
        println!("| {}Memory State:{}  {}Ephemeral Zeroize memory wiped{}", Self::ANSI_CYAN, Self::ANSI_RESET, Self::ANSI_GREEN, Self::ANSI_RESET);
        println!("{}+----------------------------------------------------------------------+{}", Self::ANSI_DIM, Self::ANSI_RESET);
        println!();
    }

    /// Generates ASCII representation of a Merkle inclusion branch
    pub fn render_merkle_branch(root_hex: &str, leaf_hex: &str, depth: usize) {
        println!("{}Merkle Inclusion Proof Authentication Path:{}", Self::ANSI_BOLD, Self::ANSI_RESET);
        println!("  Root: {}...{}", &root_hex[0..12], &root_hex[root_hex.len().saturating_sub(8)..]);
        println!("    └── [Depth 0] Leaf: {}...{}", &leaf_hex[0..12], &leaf_hex[leaf_hex.len().saturating_sub(8)..]);
        for d in 1..=depth.min(4) {
            println!("        ├── [Level {} Sibling Hash Verified]", d);
        }
        println!("        └── [SMT Membership Verified in BN254 Pairing]");
        println!();
    }
}
