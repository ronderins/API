//! Zero-Knowledge Virtual Machine (zkVM) Instruction Set Architecture
//!
//! Defines 64-bit zkVM opcodes, instruction encoding, operand decoding,
//! and algebraic constraint expressions for general-purpose identity predicates.

use serde::{Deserialize, Serialize};

/// 64-bit zkVM Register Identifier
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Register {
    R0 = 0, // General Purpose / Return Value
    R1 = 1, // Parameter 1 / Accumulator
    R2 = 2, // Parameter 2 / Operand B
    R3 = 3, // Parameter 3 / Hash Digest 0
    R4 = 4, // Parameter 4 / Hash Digest 1
    R5 = 5, // Scratch Register A
    R6 = 6, // Scratch Register B
    R7 = 7, // Frame Pointer / Stack Offset
}

impl Register {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Register::R0),
            1 => Some(Register::R1),
            2 => Some(Register::R2),
            3 => Some(Register::R3),
            4 => Some(Register::R4),
            5 => Some(Register::R5),
            6 => Some(Register::R6),
            7 => Some(Register::R7),
            _ => None,
        }
    }
}

/// Zero-Knowledge Virtual Machine Opcode Set
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Opcode {
    // Arithmetic & Bitwise
    Noop = 0x00,
    Add = 0x01,
    Sub = 0x02,
    Mul = 0x03,
    Div = 0x04,
    Mod = 0x05,
    And = 0x06,
    Or = 0x07,
    Xor = 0x08,
    Not = 0x09,
    Shl = 0x0A,
    Shr = 0x0B,

    // Immediate Operations
    LoadImm = 0x10,
    AddImm = 0x11,
    MulImm = 0x12,

    // Memory & Stack Operations
    LoadMem = 0x20,
    StoreMem = 0x21,
    Push = 0x22,
    Pop = 0x23,

    // Control Flow & Branching
    Jmp = 0x30,
    JmpEq = 0x31,
    JmpNeq = 0x32,
    JmpGt = 0x33,
    JmpLt = 0x34,
    Call = 0x35,
    Ret = 0x36,

    // Cryptographic & Identity SNARK Primitives
    PoseidonSponge = 0x40,
    Blake3Compress = 0x41,
    PedersenCommit = 0x42,
    MerkleAuthPath = 0x43,
    RangeCheck64 = 0x44,
    AssertEq = 0x45,
    NullifierGen = 0x46,

    // Termination
    Halt = 0xFF,
}

/// Decoded zkVM Instruction
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub opcode: Opcode,
    pub dst: Register,
    pub src1: Register,
    pub src2: Register,
    pub immediate: u64,
}

impl Instruction {
    pub fn new(opcode: Opcode, dst: Register, src1: Register, src2: Register, immediate: u64) -> Self {
        Self {
            opcode,
            dst,
            src1,
            src2,
            immediate,
        }
    }

    /// Encodes instruction to 64-bit binary representation
    pub fn encode(&self) -> u64 {
        let op = self.opcode as u64;
        let dst = (self.dst as u64) & 0x07;
        let s1 = (self.src1 as u64) & 0x07;
        let s2 = (self.src2 as u64) & 0x07;
        let imm_low = self.immediate & 0x0000_FFFF_FFFF;

        (op << 56) | (dst << 53) | (s1 << 50) | (s2 << 47) | imm_low
    }

    /// Decodes 64-bit binary representation into instruction
    pub fn decode(raw: u64) -> Result<Self, &'static str> {
        let op_byte = ((raw >> 56) & 0xFF) as u8;
        let dst_u8 = ((raw >> 53) & 0x07) as u8;
        let s1_u8 = ((raw >> 50) & 0x07) as u8;
        let s2_u8 = ((raw >> 47) & 0x07) as u8;
        let immediate = raw & 0x0000_FFFF_FFFF;

        let dst = Register::from_u8(dst_u8).ok_or("Invalid dst register")?;
        let src1 = Register::from_u8(s1_u8).ok_or("Invalid src1 register")?;
        let src2 = Register::from_u8(s2_u8).ok_or("Invalid src2 register")?;

        let opcode = match op_byte {
            0x00 => Opcode::Noop,
            0x01 => Opcode::Add,
            0x02 => Opcode::Sub,
            0x03 => Opcode::Mul,
            0x04 => Opcode::Div,
            0x05 => Opcode::Mod,
            0x06 => Opcode::And,
            0x07 => Opcode::Or,
            0x08 => Opcode::Xor,
            0x09 => Opcode::Not,
            0x0A => Opcode::Shl,
            0x0B => Opcode::Shr,
            0x10 => Opcode::LoadImm,
            0x11 => Opcode::AddImm,
            0x12 => Opcode::MulImm,
            0x20 => Opcode::LoadMem,
            0x21 => Opcode::StoreMem,
            0x22 => Opcode::Push,
            0x23 => Opcode::Pop,
            0x30 => Opcode::Jmp,
            0x31 => Opcode::JmpEq,
            0x32 => Opcode::JmpNeq,
            0x33 => Opcode::JmpGt,
            0x34 => Opcode::JmpLt,
            0x35 => Opcode::Call,
            0x36 => Opcode::Ret,
            0x40 => Opcode::PoseidonSponge,
            0x41 => Opcode::Blake3Compress,
            0x42 => Opcode::PedersenCommit,
            0x43 => Opcode::MerkleAuthPath,
            0x44 => Opcode::RangeCheck64,
            0x45 => Opcode::AssertEq,
            0x46 => Opcode::NullifierGen,
            0xFF => Opcode::Halt,
            _ => return Err("Unknown opcode byte"),
        };

        Ok(Self {
            opcode,
            dst,
            src1,
            src2,
            immediate,
        })
    }
}
