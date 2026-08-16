#![no_std]
#![forbid(unsafe_code)]

//! Bytecode execution engine for MoonBlokz chain-configuration parameters.
//!
//! A chain-configurable parameter may be a plain literal or a small program that
//! *computes* its value — a registration price that grows with the size of the
//! network, for example. This crate executes those programs. It carries no
//! MoonBlokz domain concepts at all: it receives a program, its arguments, a fuel
//! budget and a host handle, and returns a typed outcome. What a parameter *is*,
//! what the fuel limit should be, and what to do when a program fails all stay in
//! `moonblokz-configuration`.
//!
//! That separation is what makes the crate verifiable on its own terms, and it is
//! also why the post-MVP smart-contract runtime can build on the same engine
//! without inheriting the configuration registry.
//!
//! # Determinism is the correctness property
//!
//! Every value computed here feeds a consensus decision, so two nodes running the
//! same program over the same arguments must reach the same answer or they will
//! disagree about whether a block is valid. Three consequences run through the
//! whole implementation:
//!
//! - **Initial state is fully defined.** Local slots are zero-initialised and no
//!   instruction can read machine state that was never written.
//! - **Every arithmetic instruction is total.** Division and modulo by zero yield
//!   `0`, shifts of 64 or more yield `0`, subtraction saturates at `0`, and
//!   addition and multiplication saturate at [`u64::MAX`]. No operand combination
//!   traps, so what remains able to fail is structural — fuel, stack depth,
//!   nesting — never arithmetic.
//! - **Nothing node-local is reachable.** There is no clock, no randomness, and no
//!   instruction that reads the remaining fuel. A value that differs between nodes
//!   cannot be a value the network agrees on.
//!
//! # There is no verifier
//!
//! Every way a program can fail is a runtime condition, checked as it happens.
//! A load-time pass could catch undefined opcodes, truncated immediates and
//! out-of-range jump destinations, but it could not catch fuel exhaustion, stack
//! depth or nesting depth — none of which are decidable ahead of a run once the
//! instruction set has backward jumps. The runtime therefore has to be total
//! regardless, and a verifier would merely duplicate a subset of the same checks
//! in a second code path on a device where code size is budgeted. Structural
//! diagnostics belong in `vm-asm`, where they cost no device code size and can
//! name the offending line.
//!
//! # Example
//!
//! ```
//! use moonblokz_vm::{Fuel, Vm, VmOutcome};
//! # struct NoHost;
//! # impl moonblokz_vm::VmHost for NoHost {
//! #     fn call(&self, _: u16, _: &[u64], _: &mut Fuel) -> Option<u64> { None }
//! # }
//! // registration_price(n) = min(1000 + 5 * n, 50000)
//! let program = [
//!     0x32, 0x00,             // ARG 0
//!     0x10, 0x05,             // PUSH_U8 5
//!     0x42,                   // MUL
//!     0x11, 0xE8, 0x03,       // PUSH_U16 1000
//!     0x40,                   // ADD
//!     0x11, 0x50, 0xC3,       // PUSH_U16 50000
//!     0x45,                   // MIN
//!     0x01,                   // RET
//! ];
//! let mut fuel = Fuel::new(1000);
//! let outcome = Vm::<16, 8, 4>::execute(&program, &[200], &mut fuel, &NoHost);
//! // `Debug` is a test-only derive, so match rather than compare.
//! assert!(matches!(outcome, VmOutcome::Completed(2000)));
//! ```

// ---------------------------------------------------------------------------
// Opcodes
// ---------------------------------------------------------------------------

/// The opcode byte of every instruction.
///
/// Bytecode is permanent: once a chain exists, a program's bytes cannot be
/// reinterpreted. The space is therefore partitioned up front in aligned 16-byte
/// groups, with the room current instructions do not need left explicitly
/// reserved, so that later additions extend the encoding rather than filling in
/// whatever bytes happened to be free.
///
/// | Range | Group |
/// |---|---|
/// | `0x00` | permanently unallocated |
/// | `0x01`–`0x0F` | control and return |
/// | `0x10`–`0x1F` | constants |
/// | `0x20`–`0x2F` | stack |
/// | `0x30`–`0x3F` | locals and arguments |
/// | `0x40`–`0x4F` | arithmetic |
/// | `0x50`–`0x5F` | bitwise |
/// | `0x60`–`0x6F` | comparison |
/// | `0x70`–`0x7F` | host calls |
/// | `0x80`–`0xBF` | reserved for future groups |
/// | `0xC0`–`0xFF` | reserved, unassigned |
///
/// `0x00` is permanently unallocated on purpose. Zero is what a truncated,
/// padded or zero-initialised buffer is made of, and the most likely accidental
/// "program" is a run of zero bytes; keeping `0x00` undefined means such a buffer
/// traps on its first instruction instead of executing something.
pub mod opcode {
    // Control and return.
    /// Ends execution; the top of the stack is the program's result.
    pub const RET: u8 = 0x01;
    /// Unconditional branch.
    pub const JMP: u8 = 0x02;
    /// Branch if the top of the stack is zero.
    pub const JMPZ: u8 = 0x03;
    /// Branch if the top of the stack is non-zero.
    pub const JMPNZ: u8 = 0x04;

    // Constants.
    /// Push a `u8` immediate, zero-extended.
    pub const PUSH_U8: u8 = 0x10;
    /// Push a `u16` immediate, zero-extended.
    pub const PUSH_U16: u8 = 0x11;
    /// Push a `u32` immediate, zero-extended.
    pub const PUSH_U32: u8 = 0x12;
    /// Push a `u64` immediate.
    pub const PUSH_U64: u8 = 0x13;

    // Stack.
    /// Discard the top of the stack.
    pub const POP: u8 = 0x20;
    /// Duplicate the top of the stack.
    pub const DUP: u8 = 0x21;
    /// Exchange the top two operands.
    pub const SWAP: u8 = 0x22;

    // Locals and arguments.
    /// Push a local slot.
    pub const LOAD: u8 = 0x30;
    /// Pop into a local slot.
    pub const STORE: u8 = 0x31;
    /// Push an argument of the invocation.
    pub const ARG: u8 = 0x32;

    // Arithmetic.
    /// Saturating addition.
    pub const ADD: u8 = 0x40;
    /// Saturating subtraction, floored at zero.
    pub const SUB: u8 = 0x41;
    /// Saturating multiplication.
    pub const MUL: u8 = 0x42;
    /// Division; zero when the divisor is zero.
    pub const DIV: u8 = 0x43;
    /// Remainder; zero when the divisor is zero.
    pub const MOD: u8 = 0x44;
    /// The smaller of two operands.
    pub const MIN: u8 = 0x45;
    /// The larger of two operands.
    pub const MAX: u8 = 0x46;

    // Bitwise.
    /// Bitwise conjunction.
    pub const AND: u8 = 0x50;
    /// Bitwise disjunction.
    pub const OR: u8 = 0x51;
    /// Bitwise exclusive disjunction.
    pub const XOR: u8 = 0x52;
    /// Bitwise complement.
    pub const NOT: u8 = 0x53;
    /// Left shift; zero when the shift is 64 or more.
    pub const SHL: u8 = 0x54;
    /// Right shift; zero when the shift is 64 or more.
    pub const SHR: u8 = 0x55;

    // Comparison.
    /// Equality.
    pub const EQ: u8 = 0x60;
    /// Inequality.
    pub const NE: u8 = 0x61;
    /// Less than.
    pub const LT: u8 = 0x62;
    /// Less than or equal.
    pub const LTE: u8 = 0x63;
    /// Greater than.
    pub const GT: u8 = 0x64;
    /// Greater than or equal.
    pub const GTE: u8 = 0x65;

    // Host calls.
    /// Resolve another configuration parameter through the host, consuming the
    /// number of operands the instruction itself declares.
    pub const GETPARAM: u8 = 0x70;
}

/// The immediate operand an opcode carries, if any.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum Imm {
    /// No immediate; the instruction is one byte.
    None,
    /// An unsigned 8-bit immediate.
    U8,
    /// Two unsigned 8-bit immediates, in the order written.
    U8Pair,
    /// An unsigned 16-bit immediate, little-endian.
    U16,
    /// An unsigned 32-bit immediate, little-endian.
    U32,
    /// An unsigned 64-bit immediate, little-endian.
    U64,
    /// A jump displacement: two's-complement `i16`, little-endian, relative to
    /// the address of the *following* instruction.
    Rel16,
}

impl Imm {
    /// Width of the immediate in bytes.
    pub const fn size(self) -> usize {
        match self {
            Imm::None => 0,
            Imm::U8 => 1,
            Imm::U8Pair | Imm::U16 | Imm::Rel16 => 2,
            Imm::U32 => 4,
            Imm::U64 => 8,
        }
    }
}

/// The static description of one instruction.
///
/// This is the single source of truth for the instruction set: the runtime cost
/// table is derived from it, and `vm-asm` and `vm-dis` read it rather than
/// restating opcode meanings. Two places that must agree on what `0x43` means is
/// exactly the arrangement this avoids.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub struct InstructionInfo {
    /// The opcode byte.
    pub opcode: u8,
    /// The canonical mnemonic, uppercase.
    pub mnemonic: &'static str,
    /// The immediate this opcode carries.
    pub imm: Imm,
    /// Fuel charged for executing this instruction.
    pub cost: u8,
}

const fn insn(opcode: u8, mnemonic: &'static str, imm: Imm) -> InstructionInfo {
    InstructionInfo { opcode, mnemonic, imm, cost: 1 }
}

/// Every allocated instruction, ordered by opcode.
pub const INSTRUCTIONS: [InstructionInfo; 34] = {
    use crate::opcode as op;
    [
        insn(op::RET, "RET", Imm::None),
        insn(op::JMP, "JMP", Imm::Rel16),
        insn(op::JMPZ, "JMPZ", Imm::Rel16),
        insn(op::JMPNZ, "JMPNZ", Imm::Rel16),
        insn(op::PUSH_U8, "PUSH_U8", Imm::U8),
        insn(op::PUSH_U16, "PUSH_U16", Imm::U16),
        insn(op::PUSH_U32, "PUSH_U32", Imm::U32),
        insn(op::PUSH_U64, "PUSH_U64", Imm::U64),
        insn(op::POP, "POP", Imm::None),
        insn(op::DUP, "DUP", Imm::None),
        insn(op::SWAP, "SWAP", Imm::None),
        insn(op::LOAD, "LOAD", Imm::U8),
        insn(op::STORE, "STORE", Imm::U8),
        insn(op::ARG, "ARG", Imm::U8),
        insn(op::ADD, "ADD", Imm::None),
        insn(op::SUB, "SUB", Imm::None),
        insn(op::MUL, "MUL", Imm::None),
        insn(op::DIV, "DIV", Imm::None),
        insn(op::MOD, "MOD", Imm::None),
        insn(op::MIN, "MIN", Imm::None),
        insn(op::MAX, "MAX", Imm::None),
        insn(op::AND, "AND", Imm::None),
        insn(op::OR, "OR", Imm::None),
        insn(op::XOR, "XOR", Imm::None),
        insn(op::NOT, "NOT", Imm::None),
        insn(op::SHL, "SHL", Imm::None),
        insn(op::SHR, "SHR", Imm::None),
        insn(op::EQ, "EQ", Imm::None),
        insn(op::NE, "NE", Imm::None),
        insn(op::LT, "LT", Imm::None),
        insn(op::LTE, "LTE", Imm::None),
        insn(op::GT, "GT", Imm::None),
        insn(op::GTE, "GTE", Imm::None),
        insn(op::GETPARAM, "GETPARAM", Imm::U8Pair),
    ]
};

/// The static description of `opcode`, or `None` if it is unallocated.
pub fn instruction(opcode: u8) -> Option<InstructionInfo> {
    let mut i = 0;
    while i < INSTRUCTIONS.len() {
        if INSTRUCTIONS[i].opcode == opcode {
            return Some(INSTRUCTIONS[i]);
        }
        i += 1;
    }
    None
}

/// Fuel charged per opcode, indexed by the opcode byte.
///
/// A cost of `0` marks an unallocated opcode and is what the interpreter tests
/// to reject one, so this table is also the runtime's definition of which bytes
/// are instructions at all.
///
/// The table is derived rather than hand-written, but it is a table on purpose
/// even though every entry is `1` today. It is consensus-critical and effectively
/// permanent: a cost change changes which programs exhaust their budget and
/// therefore changes returned values. Introducing the indirection later — when
/// the first instruction whose real cost is not one unit appears — would be a
/// retroactive change to every chain's results.
const COST: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < INSTRUCTIONS.len() {
        table[INSTRUCTIONS[i].opcode as usize] = INSTRUCTIONS[i].cost;
        i += 1;
    }
    table
};

// ---------------------------------------------------------------------------
// Fuel
// ---------------------------------------------------------------------------

/// The execution budget of one accessor invocation.
///
/// Fuel is **one budget per invocation, shared across nesting**: a [`GETPARAM`]
/// sub-evaluation draws from the same budget as its caller, and exhaustion aborts
/// the whole invocation rather than just the sub-evaluation. Per-sub-evaluation
/// budgets would let a program compose arbitrarily many sub-evaluations, each
/// individually under the limit, and evade the bound entirely.
///
/// The nesting depth travels here for the same reason the fuel does — it is the
/// other quantity that must be shared across a nested evaluation, and the host
/// seam threads exactly one value through the call.
///
/// The limit is supplied by the caller. This crate never learns where it comes
/// from, which is what keeps it independent of the configuration registry.
///
/// [`GETPARAM`]: opcode::GETPARAM
#[cfg_attr(test, derive(Debug))]
pub struct Fuel {
    remaining: u32,
    depth: u16,
}

impl Fuel {
    /// A budget of `limit` fuel units at nesting depth zero.
    pub fn new(limit: u32) -> Self {
        Self { remaining: limit, depth: 0 }
    }

    /// Deducts `cost`, reporting whether the budget covered it.
    fn charge(&mut self, cost: u8) -> bool {
        match self.remaining.checked_sub(cost as u32) {
            Some(rest) => {
                self.remaining = rest;
                true
            }
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Host seam
// ---------------------------------------------------------------------------

/// The `func_id` of parameter resolution: `args[0]` is the parameter identifier
/// and `args[1..]` are its arguments.
pub const HOST_RESOLVE_PARAMETER: u16 = 0;

/// The whole of this crate's coupling to MoonBlokz: an identifier it does not
/// interpret, and a callback it does not implement.
///
/// The entry point is general rather than parameter-specific so that later host
/// capabilities are new `func_id` values rather than new trait methods — an added
/// method is a breaking change for every implementor, an added identifier is not.
///
/// # The host validates the argument count
///
/// [`GETPARAM`] declares how many operands it passes, so `args.len() - 1` is what
/// the *program* claims the parameter's arity to be, not what the registry says
/// it is. The host owns the registry and is therefore the only party that can
/// tell the two apart: a program declaring the wrong count should be declined,
/// which reaches the program as [`HostCallUnresolved`] and falls to the next
/// resolution tier like any other failure. The VM neither knows nor checks.
///
/// [`GETPARAM`]: opcode::GETPARAM
/// [`HostCallUnresolved`]: TrapReason::HostCallUnresolved
pub trait VmHost {
    /// Invokes `func_id` over `args`, drawing from the caller's remaining budget.
    ///
    /// `None` propagates as a failed evaluation of the calling program.
    fn call(&self, func_id: u16, args: &[u64], fuel: &mut Fuel) -> Option<u64>;
}

// ---------------------------------------------------------------------------
// Outcome
// ---------------------------------------------------------------------------

/// Why a program terminated without producing a result.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum TrapReason {
    /// The operand stack exceeded its maximum depth.
    StackOverflow,
    /// An instruction consumed an absent operand.
    StackUnderflow,
    /// `GETPARAM` recursion passed the fixed maximum.
    NestingDepthExceeded,
    /// A reserved or unassigned opcode byte was decoded.
    UndefinedOpcode,
    /// An immediate, or the opcode itself, extended past the end of the program.
    TruncatedInstruction,
    /// A jump destination fell outside the program's byte range.
    ControlFlowOutOfRange,
    /// An `ARG` index at or above the invocation's arity, or a `LOAD` / `STORE`
    /// slot outside the local-slot array.
    OperandIndexOutOfRange,
    /// The host declined a parameter named by `GETPARAM`.
    HostCallUnresolved,
}

/// What an execution produced.
///
/// The VM reports; it does not decide. Mapping a non-[`Completed`] outcome onto a
/// fallback is the caller's policy — the configuration module sends both onto the
/// next resolution tier, but a different caller may need a different policy for
/// the same outcomes, and a VM that folded the policy in could not serve one.
///
/// [`Completed`]: VmOutcome::Completed
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum VmOutcome {
    /// The program reached `RET`; this is its result.
    Completed(u64),
    /// The program hit one of the structural failure conditions.
    Trapped(TrapReason),
    /// The budget ran out.
    OutOfFuel,
}

// ---------------------------------------------------------------------------
// Machine
// ---------------------------------------------------------------------------

/// A stack machine over `u64`, sized by its const generics.
///
/// The three bounds are deliberately the caller's: the operand stack and the
/// local-slot array are the crate's only allocations, and their sizes follow from
/// the memory budget of whoever hosts the VM rather than from anything this crate
/// knows. `moonblokz-configuration` picks them.
///
/// - `STACK_DEPTH` — maximum operand-stack depth.
/// - `LOCAL_SLOTS` — number of local slots, zero-initialised before execution.
/// - `MAX_NESTING` — maximum depth of `GETPARAM` recursion. A cyclic reference
///   between parameters is caught here, and failing that by fuel.
pub struct Vm<const STACK_DEPTH: usize, const LOCAL_SLOTS: usize, const MAX_NESTING: usize>;

impl<const STACK_DEPTH: usize, const LOCAL_SLOTS: usize, const MAX_NESTING: usize>
    Vm<STACK_DEPTH, LOCAL_SLOTS, MAX_NESTING>
{
    /// Runs `program` over `args`, charging `fuel` and resolving host calls
    /// through `host`.
    ///
    /// Execution starts at offset 0 and ends at `RET`. Nothing requires `RET` to
    /// be the final byte and nothing scans ahead for it: a program whose control
    /// flow leaves the byte range simply traps.
    ///
    /// # Failure taxonomy
    ///
    /// Two of the eight conditions are worth distinguishing precisely, because
    /// they describe adjacent situations. Falling off the end of the program
    /// sequentially is [`TruncatedInstruction`] — the opcode itself extends past
    /// the end. A *jump* computing a destination outside the byte range is
    /// [`ControlFlowOutOfRange`], checked where the jump is taken. Since the
    /// program counter only ever moves by sequential advance or by a jump, every
    /// way of leaving the program is covered by exactly one of the two.
    ///
    /// [`TruncatedInstruction`]: TrapReason::TruncatedInstruction
    /// [`ControlFlowOutOfRange`]: TrapReason::ControlFlowOutOfRange
    pub fn execute<H: VmHost + ?Sized>(program: &[u8], args: &[u64], fuel: &mut Fuel, host: &H) -> VmOutcome {
        let mut stack = [0u64; STACK_DEPTH];
        let mut locals = [0u64; LOCAL_SLOTS];
        let mut sp: usize = 0;
        let mut pc: usize = 0;

        macro_rules! pop {
            () => {{
                if sp == 0 {
                    return VmOutcome::Trapped(TrapReason::StackUnderflow);
                }
                sp -= 1;
                stack[sp]
            }};
        }

        macro_rules! push {
            ($value:expr) => {{
                if sp == STACK_DEPTH {
                    return VmOutcome::Trapped(TrapReason::StackOverflow);
                }
                stack[sp] = $value;
                sp += 1;
            }};
        }

        macro_rules! binary {
            ($f:expr) => {{
                let b = pop!();
                let a = pop!();
                push!(($f)(a, b));
            }};
        }

        // Reads an immediate of `$len` bytes at `pc + 1`, trapping if it runs
        // past the end of the program.
        macro_rules! imm {
            ($len:expr) => {{
                match program.get(pc + 1..pc + 1 + $len) {
                    Some(bytes) => bytes,
                    None => return VmOutcome::Trapped(TrapReason::TruncatedInstruction),
                }
            }};
        }

        loop {
            let opcode = match program.get(pc) {
                Some(&byte) => byte,
                None => return VmOutcome::Trapped(TrapReason::TruncatedInstruction),
            };

            // A cost of zero marks an unallocated opcode. Charging only defined
            // instructions keeps the order fixed: an undefined byte traps before
            // it can exhaust the budget.
            let cost = COST[opcode as usize];
            if cost == 0 {
                return VmOutcome::Trapped(TrapReason::UndefinedOpcode);
            }
            if !fuel.charge(cost) {
                return VmOutcome::OutOfFuel;
            }

            use crate::opcode as op;
            match opcode {
                op::RET => return VmOutcome::Completed(pop!()),

                op::JMP | op::JMPZ | op::JMPNZ => {
                    let bytes = imm!(2);
                    let displacement = i16::from_le_bytes([bytes[0], bytes[1]]);
                    let next_pc = pc + 3;

                    let take = match opcode {
                        op::JMP => true,
                        op::JMPZ => pop!() == 0,
                        _ => pop!() != 0,
                    };

                    if take {
                        // Displacements are relative to the address of the
                        // following instruction, so a displacement of zero falls
                        // through and a negative one loops backwards.
                        let target = next_pc as i64 + displacement as i64;
                        if target < 0 || target as usize >= program.len() {
                            return VmOutcome::Trapped(TrapReason::ControlFlowOutOfRange);
                        }
                        // A destination inside the program is always meaningful,
                        // including one landing mid-instruction: decoding simply
                        // resumes there. Every node decodes the same bytes the
                        // same way, so the result stays deterministic, which is
                        // the only property that matters.
                        pc = target as usize;
                    } else {
                        pc = next_pc;
                    }
                }

                op::PUSH_U8 => {
                    let bytes = imm!(1);
                    push!(bytes[0] as u64);
                    pc += 2;
                }
                op::PUSH_U16 => {
                    let bytes = imm!(2);
                    push!(u16::from_le_bytes([bytes[0], bytes[1]]) as u64);
                    pc += 3;
                }
                op::PUSH_U32 => {
                    let bytes = imm!(4);
                    push!(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64);
                    pc += 5;
                }
                op::PUSH_U64 => {
                    let b = imm!(8);
                    push!(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]));
                    pc += 9;
                }

                op::POP => {
                    pop!();
                    pc += 1;
                }
                op::DUP => {
                    if sp == 0 {
                        return VmOutcome::Trapped(TrapReason::StackUnderflow);
                    }
                    push!(stack[sp - 1]);
                    pc += 1;
                }
                op::SWAP => {
                    if sp < 2 {
                        return VmOutcome::Trapped(TrapReason::StackUnderflow);
                    }
                    stack.swap(sp - 1, sp - 2);
                    pc += 1;
                }

                op::LOAD => {
                    let slot = imm!(1)[0] as usize;
                    if slot >= LOCAL_SLOTS {
                        return VmOutcome::Trapped(TrapReason::OperandIndexOutOfRange);
                    }
                    push!(locals[slot]);
                    pc += 2;
                }
                op::STORE => {
                    let slot = imm!(1)[0] as usize;
                    if slot >= LOCAL_SLOTS {
                        return VmOutcome::Trapped(TrapReason::OperandIndexOutOfRange);
                    }
                    locals[slot] = pop!();
                    pc += 2;
                }
                op::ARG => {
                    let index = imm!(1)[0] as usize;
                    match args.get(index) {
                        Some(&value) => push!(value),
                        None => return VmOutcome::Trapped(TrapReason::OperandIndexOutOfRange),
                    }
                    pc += 2;
                }

                op::ADD => {
                    binary!(u64::saturating_add);
                    pc += 1;
                }
                op::SUB => {
                    binary!(u64::saturating_sub);
                    pc += 1;
                }
                op::MUL => {
                    binary!(u64::saturating_mul);
                    pc += 1;
                }
                op::DIV => {
                    binary!(|a, b| if b == 0 { 0 } else { a / b });
                    pc += 1;
                }
                op::MOD => {
                    binary!(|a, b| if b == 0 { 0 } else { a % b });
                    pc += 1;
                }
                op::MIN => {
                    binary!(core::cmp::min);
                    pc += 1;
                }
                op::MAX => {
                    binary!(core::cmp::max);
                    pc += 1;
                }

                op::AND => {
                    binary!(|a, b| a & b);
                    pc += 1;
                }
                op::OR => {
                    binary!(|a, b| a | b);
                    pc += 1;
                }
                op::XOR => {
                    binary!(|a, b| a ^ b);
                    pc += 1;
                }
                op::NOT => {
                    let a = pop!();
                    push!(!a);
                    pc += 1;
                }
                op::SHL => {
                    binary!(|a, b| if b >= 64 { 0 } else { a << b });
                    pc += 1;
                }
                op::SHR => {
                    binary!(|a, b| if b >= 64 { 0 } else { a >> b });
                    pc += 1;
                }

                op::EQ => {
                    binary!(|a, b| u64::from(a == b));
                    pc += 1;
                }
                op::NE => {
                    binary!(|a, b| u64::from(a != b));
                    pc += 1;
                }
                op::LT => {
                    binary!(|a, b| u64::from(a < b));
                    pc += 1;
                }
                op::LTE => {
                    binary!(|a, b| u64::from(a <= b));
                    pc += 1;
                }
                op::GT => {
                    binary!(|a, b| u64::from(a > b));
                    pc += 1;
                }
                op::GTE => {
                    binary!(|a, b| u64::from(a >= b));
                    pc += 1;
                }

                op::GETPARAM => {
                    // The instruction is self-describing: it carries both the
                    // parameter it resolves and the number of operands it passes.
                    // Nothing here consults a registry, so the VM still learns
                    // only a count — and the host, which owns the registry, is
                    // where a count that disagrees with it is caught.
                    let operands = imm!(2);
                    let key = operands[0];
                    let argc = operands[1] as usize;

                    if argc > sp {
                        return VmOutcome::Trapped(TrapReason::StackUnderflow);
                    }
                    if fuel.depth as usize >= MAX_NESTING {
                        return VmOutcome::Trapped(TrapReason::NestingDepthExceeded);
                    }

                    // The host wants `[key, arg0, .., argN-1]` contiguously, and
                    // the arguments are already contiguous on the operand stack
                    // with argument 0 deepest. Shifting them up by one slot makes
                    // room for the key beneath them, which turns the stack itself
                    // into the argument buffer — no second array, and the depth
                    // check that guards the shift is the stack bound the machine
                    // already owes.
                    if sp == STACK_DEPTH {
                        return VmOutcome::Trapped(TrapReason::StackOverflow);
                    }
                    let base = sp - argc;
                    stack.copy_within(base..sp, base + 1);
                    stack[base] = key as u64;

                    fuel.depth += 1;
                    let resolved = host.call(HOST_RESOLVE_PARAMETER, &stack[base..sp + 1], fuel);
                    fuel.depth -= 1;

                    sp = base;
                    match resolved {
                        Some(value) => push!(value),
                        None => return VmOutcome::Trapped(TrapReason::HostCallUnresolved),
                    }
                    pc += 3;
                }

                _ => return VmOutcome::Trapped(TrapReason::UndefinedOpcode),
            }
        }
    }
}

#[cfg(test)]
mod tests;
