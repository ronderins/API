//! In-Memory WebAssembly Enclave Isolation Sandbox
//!
//! Provides gas-metered, memory-isolated sandboxing for executing user-defined
//! verification predicates without risking native process heap corruption, unbounded
//! recursion, or arbitrary code execution vulnerabilities.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Bytecode opcodes supported by the safe WASM sandboxed interpreter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmOpcode {
    I64Const(i64),
    I64Add,
    I64Sub,
    I64Mul,
    I64LtS,
    I64GeS,
    I64Eq,
    MemoryLoad { offset: u32 },
    MemoryStore { offset: u32 },
    BranchIf { target_pc: usize },
    Jump { target_pc: usize },
    HaltReturn,
    TrapViolation,
}

/// Execution error condition inside the WASM sandbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmSandboxError {
    GasExhausted { gas_limit: u64, gas_used: u64 },
    MemoryOutOfBounds { requested_offset: u32, max_bound: usize },
    StackOverflow { max_depth: usize },
    StackUnderflow,
    IllegalOpcode,
    ExplicitTrapTriggered,
}

/// Linear memory page allocation (64 KB pages) with zeroize scrub.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct WasmLinearMemory {
    pub bytes: Vec<u8>,
}

impl WasmLinearMemory {
    pub const PAGE_SIZE: usize = 65_536; // 64 KB

    pub fn new(page_count: usize) -> Self {
        Self {
            bytes: vec![0u8; page_count * Self::PAGE_SIZE],
        }
    }

    pub fn read_i64(&self, offset: usize) -> Result<i64, WasmSandboxError> {
        if offset + 8 > self.bytes.len() {
            return Err(WasmSandboxError::MemoryOutOfBounds {
                requested_offset: offset as u32,
                max_bound: self.bytes.len(),
            });
        }
        let chunk: [u8; 8] = self.bytes[offset..offset + 8].try_into().unwrap();
        Ok(i64::from_le_bytes(chunk))
    }

    pub fn write_i64(&mut self, offset: usize, val: i64) -> Result<(), WasmSandboxError> {
        if offset + 8 > self.bytes.len() {
            return Err(WasmSandboxError::MemoryOutOfBounds {
                requested_offset: offset as u32,
                max_bound: self.bytes.len(),
            });
        }
        self.bytes[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }
}

/// Cryptographic snapshot of sandbox state allowing instant rollback on failure.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WasmStateSnapshot {
    pub program_counter: usize,
    pub gas_remaining: u64,
    pub stack_digest: String,
    pub memory_digest: String,
}

/// Result of executing a predicate in the WASM enclave sandbox.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WasmExecutionReceipt {
    pub success: bool,
    pub return_value: i64,
    pub gas_used: u64,
    pub memory_pages_used: usize,
    pub state_snapshot_digest: String,
    pub execution_duration_ns: u64,
}

/// In-Memory Sandboxed Virtual Machine
pub struct WasmEnclaveSandbox {
    pub instructions: Vec<WasmOpcode>,
    pub stack: Vec<i64>,
    pub memory: WasmLinearMemory,
    pub gas_limit: u64,
    pub gas_consumed: u64,
    pub max_stack_depth: usize,
}

impl WasmEnclaveSandbox {
    pub fn new(instructions: Vec<WasmOpcode>, gas_limit: u64, memory_pages: usize) -> Self {
        Self {
            instructions,
            stack: Vec::with_capacity(256),
            memory: WasmLinearMemory::new(memory_pages.max(1)),
            gas_limit,
            gas_consumed: 0,
            max_stack_depth: 256,
        }
    }

    /// Takes a deterministic cryptographic snapshot of the sandbox state.
    pub fn take_snapshot(&self, pc: usize) -> WasmStateSnapshot {
        let mut stack_h = Sha256::new();
        for val in &self.stack {
            stack_h.update(&val.to_le_bytes());
        }
        let stack_digest = hex::encode(stack_h.finalize());

        let mut mem_h = blake3::Hasher::new();
        mem_h.update(&self.memory.bytes);
        let memory_digest = hex::encode(mem_h.finalize().as_bytes());

        WasmStateSnapshot {
            program_counter: pc,
            gas_remaining: self.gas_limit.saturating_sub(self.gas_consumed),
            stack_digest,
            memory_digest,
        }
    }

    /// Executes the sandboxed program to completion or error.
    pub fn execute(&mut self) -> Result<WasmExecutionReceipt, WasmSandboxError> {
        let mut pc = 0usize;
        let start_time = std::time::Instant::now();

        while pc < self.instructions.len() {
            // Gas accounting
            self.gas_consumed += 1;
            if self.gas_consumed > self.gas_limit {
                return Err(WasmSandboxError::GasExhausted {
                    gas_limit: self.gas_limit,
                    gas_used: self.gas_consumed,
                });
            }

            match self.instructions[pc] {
                WasmOpcode::I64Const(c) => {
                    if self.stack.len() >= self.max_stack_depth {
                        return Err(WasmSandboxError::StackOverflow {
                            max_depth: self.max_stack_depth,
                        });
                    }
                    self.stack.push(c);
                    pc += 1;
                }
                WasmOpcode::I64Add => {
                    let b = self.stack.pop().ok_or(WasmSandboxError::StackUnderflow)?;
                    let a = self.stack.pop().ok_or(WasmSandboxError::StackUnderflow)?;
                    self.stack.push(a.wrapping_add(b));
                    pc += 1;
                }
                WasmOpcode::I64Sub => {
                    let b = self.stack.pop().ok_or(WasmSandboxError::StackUnderflow)?;
                    let a = self.stack.pop().ok_or(WasmSandboxError::StackUnderflow)?;
                    self.stack.push(a.wrapping_sub(b));
                    pc += 1;
                }
                WasmOpcode::I64Mul => {
                    let b = self.stack.pop().ok_or(WasmSandboxError::StackUnderflow)?;
                    let a = self.stack.pop().ok_or(WasmSandboxError::StackUnderflow)?;
                    self.stack.push(a.wrapping_mul(b));
                    pc += 1;
                }
                WasmOpcode::I64GeS => {
                    let b = self.stack.pop().ok_or(WasmSandboxError::StackUnderflow)?;
                    let a = self.stack.pop().ok_or(WasmSandboxError::StackUnderflow)?;
                    self.stack.push(if a >= b { 1 } else { 0 });
                    pc += 1;
                }
                WasmOpcode::I64LtS => {
                    let b = self.stack.pop().ok_or(WasmSandboxError::StackUnderflow)?;
                    let a = self.stack.pop().ok_or(WasmSandboxError::StackUnderflow)?;
                    self.stack.push(if a < b { 1 } else { 0 });
                    pc += 1;
                }
                WasmOpcode::I64Eq => {
                    let b = self.stack.pop().ok_or(WasmSandboxError::StackUnderflow)?;
                    let a = self.stack.pop().ok_or(WasmSandboxError::StackUnderflow)?;
                    self.stack.push(if a == b { 1 } else { 0 });
                    pc += 1;
                }
                WasmOpcode::MemoryLoad { offset } => {
                    let val = self.memory.read_i64(offset as usize)?;
                    self.stack.push(val);
                    pc += 1;
                }
                WasmOpcode::MemoryStore { offset } => {
                    let val = self.stack.pop().ok_or(WasmSandboxError::StackUnderflow)?;
                    self.memory.write_i64(offset as usize, val)?;
                    pc += 1;
                }
                WasmOpcode::BranchIf { target_pc } => {
                    let cond = self.stack.pop().ok_or(WasmSandboxError::StackUnderflow)?;
                    if cond != 0 {
                        pc = target_pc;
                    } else {
                        pc += 1;
                    }
                }
                WasmOpcode::Jump { target_pc } => {
                    pc = target_pc;
                }
                WasmOpcode::HaltReturn => {
                    break;
                }
                WasmOpcode::TrapViolation => {
                    return Err(WasmSandboxError::ExplicitTrapTriggered);
                }
            }
        }

        let return_val = self.stack.last().copied().unwrap_or(0);
        let snapshot = self.take_snapshot(pc);

        Ok(WasmExecutionReceipt {
            success: true,
            return_value: return_val,
            gas_used: self.gas_consumed,
            memory_pages_used: self.memory.bytes.len() / WasmLinearMemory::PAGE_SIZE,
            state_snapshot_digest: snapshot.memory_digest,
            execution_duration_ns: start_time.elapsed().as_nanos() as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_sandbox_age_predicate_execution() {
        // Program: push age 25, push threshold 21, check age >= threshold (25 >= 21)
        let prog = vec![
            WasmOpcode::I64Const(25), // user age
            WasmOpcode::I64Const(21), // threshold
            WasmOpcode::I64GeS,       // 25 >= 21 -> 1
            WasmOpcode::HaltReturn,
        ];

        let mut vm = WasmEnclaveSandbox::new(prog, 1000, 1);
        let receipt = vm.execute().unwrap();
        assert!(receipt.success);
        assert_eq!(receipt.return_value, 1);
        assert_eq!(receipt.gas_used, 4);
    }

    #[test]
    fn test_wasm_sandbox_gas_limit_exhaustion() {
        // Infinite loop: Jump to 0 with gas limit of 10
        let infinite_loop = vec![
            WasmOpcode::I64Const(1),
            WasmOpcode::Jump { target_pc: 0 },
        ];

        let mut vm = WasmEnclaveSandbox::new(infinite_loop, 10, 1);
        let res = vm.execute();
        assert!(matches!(res, Err(WasmSandboxError::GasExhausted { .. })));
    }
}
