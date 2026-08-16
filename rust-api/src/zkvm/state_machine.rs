//! zkVM Cycle State Machine & Execution Trace Generator
//!
//! Executes zkVM bytecode, manages isolated register files and virtual memory,
//! and outputs an algebraic execution trace matrix for STARK/SNARK proving.

use crate::zkp::poseidon::poseidon_hash_2;
use crate::zkvm::opcodes::{Instruction, Opcode, Register};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Execution Trace Row capturing machine state at cycle `t`
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceRow {
    pub cycle: u64,
    pub pc: u64,
    pub instruction: u64,
    pub registers: [u64; 8],
    pub memory_addr: u64,
    pub memory_val: u64,
    pub auxiliary_hash: u64,
    pub is_halted: bool,
}

/// Execution Trace Table representing entire computational history
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExecutionTrace {
    pub rows: Vec<TraceRow>,
    pub final_registers: [u64; 8],
    pub total_cycles: usize,
    pub trace_root: [u8; 32],
}

/// Zero-Knowledge Virtual Machine Runtime Engine
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ZkVirtualMachine {
    pub pc: usize,
    pub registers: [u64; 8],
    #[zeroize(skip)]
    pub memory: Vec<u64>,
    #[zeroize(skip)]
    pub stack: Vec<u64>,
    #[zeroize(skip)]
    pub program: Vec<Instruction>,
    pub cycle_count: usize,
    pub is_halted: bool,
}

impl ZkVirtualMachine {
    pub const MAX_CYCLES: usize = 100_000;
    pub const MEMORY_SIZE: usize = 65_536;

    pub fn new(program: Vec<Instruction>) -> Self {
        Self {
            pc: 0,
            registers: [0u64; 8],
            memory: vec![0u64; Self::MEMORY_SIZE],
            stack: Vec::with_capacity(1024),
            program,
            cycle_count: 0,
            is_halted: false,
        }
    }

    /// Sets initial witness inputs into registers R1, R2, etc.
    pub fn set_inputs(&mut self, inputs: &[u64]) {
        for (i, &val) in inputs.iter().enumerate().take(7) {
            self.registers[i + 1] = val;
        }
    }

    /// Executes program and captures complete cryptographic execution trace
    pub fn run_with_trace(&mut self) -> Result<ExecutionTrace, &'static str> {
        let mut rows = Vec::with_capacity(self.program.len().max(16));

        while !self.is_halted && self.cycle_count < Self::MAX_CYCLES {
            if self.pc >= self.program.len() {
                self.is_halted = true;
                break;
            }

            let inst = self.program[self.pc].clone();
            let mut row = TraceRow {
                cycle: self.cycle_count as u64,
                pc: self.pc as u64,
                instruction: inst.encode(),
                registers: self.registers,
                memory_addr: 0,
                memory_val: 0,
                auxiliary_hash: 0,
                is_halted: false,
            };

            self.step(&inst, &mut row)?;
            rows.push(row);
            self.cycle_count += 1;
        }

        let mut trace_hasher = blake3::Hasher::new();
        trace_hasher.update(b"zkvm-execution-trace-commitment-v1\0");
        for r in &rows {
            trace_hasher.update(&r.cycle.to_le_bytes());
            trace_hasher.update(&r.pc.to_le_bytes());
            trace_hasher.update(&r.instruction.to_le_bytes());
            for reg in &r.registers {
                trace_hasher.update(&reg.to_le_bytes());
            }
        }
        let trace_root = *trace_hasher.finalize().as_bytes();

        Ok(ExecutionTrace {
            rows,
            final_registers: self.registers,
            total_cycles: self.cycle_count,
            trace_root,
        })
    }

    /// Single execution step
    fn step(&mut self, inst: &Instruction, row: &mut TraceRow) -> Result<(), &'static str> {
        let dst_idx = inst.dst as usize;
        let s1_idx = inst.src1 as usize;
        let s2_idx = inst.src2 as usize;

        let v1 = self.registers[s1_idx];
        let v2 = self.registers[s2_idx];

        match inst.opcode {
            Opcode::Noop => {
                self.pc += 1;
            }
            Opcode::Add => {
                self.registers[dst_idx] = v1.wrapping_add(v2);
                self.pc += 1;
            }
            Opcode::Sub => {
                self.registers[dst_idx] = v1.wrapping_sub(v2);
                self.pc += 1;
            }
            Opcode::Mul => {
                self.registers[dst_idx] = v1.wrapping_mul(v2);
                self.pc += 1;
            }
            Opcode::Div => {
                if v2 == 0 {
                    return Err("Division by zero in zkVM");
                }
                self.registers[dst_idx] = v1 / v2;
                self.pc += 1;
            }
            Opcode::Mod => {
                if v2 == 0 {
                    return Err("Modulo by zero in zkVM");
                }
                self.registers[dst_idx] = v1 % v2;
                self.pc += 1;
            }
            Opcode::And => {
                self.registers[dst_idx] = v1 & v2;
                self.pc += 1;
            }
            Opcode::Or => {
                self.registers[dst_idx] = v1 | v2;
                self.pc += 1;
            }
            Opcode::Xor => {
                self.registers[dst_idx] = v1 ^ v2;
                self.pc += 1;
            }
            Opcode::Not => {
                self.registers[dst_idx] = !v1;
                self.pc += 1;
            }
            Opcode::Shl => {
                self.registers[dst_idx] = v1.wrapping_shl((v2 & 63) as u32);
                self.pc += 1;
            }
            Opcode::Shr => {
                self.registers[dst_idx] = v1.wrapping_shr((v2 & 63) as u32);
                self.pc += 1;
            }
            Opcode::LoadImm => {
                self.registers[dst_idx] = inst.immediate;
                self.pc += 1;
            }
            Opcode::AddImm => {
                self.registers[dst_idx] = v1.wrapping_add(inst.immediate);
                self.pc += 1;
            }
            Opcode::MulImm => {
                self.registers[dst_idx] = v1.wrapping_mul(inst.immediate);
                self.pc += 1;
            }
            Opcode::LoadMem => {
                let addr = (v1 as usize) % Self::MEMORY_SIZE;
                let val = self.memory[addr];
                self.registers[dst_idx] = val;
                row.memory_addr = addr as u64;
                row.memory_val = val;
                self.pc += 1;
            }
            Opcode::StoreMem => {
                let addr = (v1 as usize) % Self::MEMORY_SIZE;
                self.memory[addr] = v2;
                row.memory_addr = addr as u64;
                row.memory_val = v2;
                self.pc += 1;
            }
            Opcode::Push => {
                self.stack.push(v1);
                self.pc += 1;
            }
            Opcode::Pop => {
                self.registers[dst_idx] = self.stack.pop().unwrap_or(0);
                self.pc += 1;
            }
            Opcode::Jmp => {
                self.pc = inst.immediate as usize;
            }
            Opcode::JmpEq => {
                if v1 == v2 {
                    self.pc = inst.immediate as usize;
                } else {
                    self.pc += 1;
                }
            }
            Opcode::JmpNeq => {
                if v1 != v2 {
                    self.pc = inst.immediate as usize;
                } else {
                    self.pc += 1;
                }
            }
            Opcode::JmpGt => {
                if v1 > v2 {
                    self.pc = inst.immediate as usize;
                } else {
                    self.pc += 1;
                }
            }
            Opcode::JmpLt => {
                if v1 < v2 {
                    self.pc = inst.immediate as usize;
                } else {
                    self.pc += 1;
                }
            }
            Opcode::Call => {
                self.stack.push((self.pc + 1) as u64);
                self.pc = inst.immediate as usize;
            }
            Opcode::Ret => {
                self.pc = self.stack.pop().unwrap_or(self.program.len()) as usize;
            }
            Opcode::PoseidonSponge => {
                let hash = poseidon_hash_2(v1, v2);
                self.registers[dst_idx] = hash;
                row.auxiliary_hash = hash;
                self.pc += 1;
            }
            Opcode::Blake3Compress => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&v1.to_le_bytes());
                hasher.update(&v2.to_le_bytes());
                let bytes = hasher.finalize();
                let mut u64_bytes = [0u8; 8];
                u64_bytes.copy_from_slice(&bytes.as_bytes()[0..8]);
                let val = u64::from_le_bytes(u64_bytes);
                self.registers[dst_idx] = val;
                row.auxiliary_hash = val;
                self.pc += 1;
            }
            Opcode::PedersenCommit => {
                let val = v1.wrapping_mul(0x517cc1b727220a95).wrapping_add(v2);
                self.registers[dst_idx] = val;
                self.pc += 1;
            }
            Opcode::MerkleAuthPath => {
                let parent = poseidon_hash_2(v1, v2);
                self.registers[dst_idx] = parent;
                self.pc += 1;
            }
            Opcode::RangeCheck64 => {
                let is_valid = v1 <= inst.immediate;
                self.registers[dst_idx] = if is_valid { 1 } else { 0 };
                self.pc += 1;
            }
            Opcode::AssertEq => {
                if v1 != v2 {
                    return Err("Assertion failed in zkVM execution");
                }
                self.pc += 1;
            }
            Opcode::NullifierGen => {
                let nullifier = poseidon_hash_2(v1 ^ 0x6e756c6c69666965, v2);
                self.registers[dst_idx] = nullifier;
                self.pc += 1;
            }
            Opcode::Halt => {
                self.is_halted = true;
                row.is_halted = true;
            }
        }

        Ok(())
    }
}
