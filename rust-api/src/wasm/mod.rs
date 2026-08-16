//! WebAssembly (WASM) Client-Side Prover Suite
//!
//! Submodules:
//! - `browser_prover`: Local in-browser R1CS witness synthesizer and proof generator.
//! - `webgpu_prover`: WebGPU compute shader hardware acceleration bridge.

pub mod browser_prover;
pub mod webgpu_prover;

pub use browser_prover::{BrowserProverEngine, WasmProverRequest, WasmProverResponse};
pub use webgpu_prover::{GpuAccelerationBenchmark, WebGpuPipelineConfig, WebGpuProver};
