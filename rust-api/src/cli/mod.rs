//! Command-Line Interface & Interactive Terminal Module
//!
//! Submodules:
//! - `commands`: Command-line subcommands and argument dispatcher.
//! - `interactive`: Rich ANSI terminal card formatter and Merkle tree renderer.

pub mod commands;
pub mod interactive;

pub use commands::{CliParser, ZkCliCommand};
pub use interactive::TerminalRenderer;
