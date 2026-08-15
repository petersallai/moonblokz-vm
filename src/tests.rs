//! Conformance tests for the execution engine.
//!
//! The suite aims to be close to exhaustive, which this component allows: 34
//! instructions, eight trap conditions, three totality rules and a fixed opcode
//! space are all small enough to cover completely rather than by sampling.

use super::*;

/// The machine shape used throughout the suite. The values are test fixtures,
/// not defaults — the real ones are picked by `moonblokz-configuration` once the
/// measurements of specification §12 exist.
type TestVm = Vm<16, 8, 4>;

const STACK_DEPTH: usize = 16;

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

/// What a test host knows about one parameter.
enum Param {
    /// Resolves to a fixed value, arity zero.
    Constant(u64),
    /// Resolves by running a program of the given arity.
    Program(&'static [u8], u8),
}

/// A host backed by a small parameter table, which runs bytecode parameters on
/// the same shared budget as their caller.
struct TableHost {
    params: &'static [(u8, Param)],
    calls: core::cell::Cell<u32>,
}

impl TableHost {
    fn new(params: &'static [(u8, Param)]) -> Self {
        Self { params, calls: core::cell::Cell::new(0) }
    }

    fn lookup(&self, key: u8) -> Option<&Param> {
        self.params.iter().find(|(k, _)| *k == key).map(|(_, p)| p)
    }
}

impl VmHost for TableHost {
    fn arity(&self, func_id: u16, selector: u8) -> Option<u8> {
        if func_id != HOST_RESOLVE_PARAMETER {
            return None;
        }
        match self.lookup(selector)? {
            Param::Constant(_) => Some(0),
            Param::Program(_, arity) => Some(*arity),
        }
    }

    fn call(&self, func_id: u16, args: &[u64], fuel: &mut Fuel) -> Option<u64> {
        if func_id != HOST_RESOLVE_PARAMETER {
            return None;
        }
        self.calls.set(self.calls.get() + 1);
        match self.lookup(args[0] as u8)? {
            Param::Constant(value) => Some(*value),
            Param::Program(program, _) => match TestVm::execute(program, &args[1..], fuel, self) {
                VmOutcome::Completed(value) => Some(value),
                _ => None,
            },
        }
    }
}

/// A host that resolves nothing.
struct DecliningHost;

impl VmHost for DecliningHost {
    fn arity(&self, _func_id: u16, _selector: u8) -> Option<u8> {
        None
    }
    fn call(&self, _func_id: u16, _args: &[u64], _fuel: &mut Fuel) -> Option<u64> {
        None
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Runs `program` with a budget generous enough not to interfere.
fn run(program: &[u8], args: &[u64]) -> VmOutcome {
    let mut fuel = Fuel::new(10_000);
    TestVm::execute(program, args, &mut fuel, &DecliningHost)
}

/// Runs a program consisting of two `PUSH_U64` operands followed by `op` and
/// `RET`, which is the shape every binary instruction test needs.
fn binary(op: u8, a: u64, b: u64) -> VmOutcome {
    let mut program = [0u8; 20];
    program[0] = opcode::PUSH_U64;
    program[1..9].copy_from_slice(&a.to_le_bytes());
    program[9] = opcode::PUSH_U64;
    program[10..18].copy_from_slice(&b.to_le_bytes());
    program[18] = op;
    program[19] = opcode::RET;
    run(&program, &[])
}

fn completed(outcome: VmOutcome) -> u64 {
    match outcome {
        VmOutcome::Completed(value) => value,
        other => panic!("expected completion, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Opcode space
// ---------------------------------------------------------------------------

#[test]
fn instruction_table_is_consistent() {
    // Opcodes are unique, and the cost table agrees with the instruction list on
    // exactly which bytes are instructions.
    for (i, a) in INSTRUCTIONS.iter().enumerate() {
        for b in &INSTRUCTIONS[i + 1..] {
            assert_ne!(a.opcode, b.opcode, "duplicate opcode {:#04x}", a.opcode);
        }
        assert_ne!(a.cost, 0, "{} must carry a non-zero cost", a.mnemonic);
        assert_eq!(COST[a.opcode as usize], a.cost);
    }
    assert_eq!(COST.iter().filter(|c| **c != 0).count(), INSTRUCTIONS.len());
}

#[test]
fn opcode_groups_match_the_specified_partition() {
    let allocated_in = |lo: u8, hi: u8| INSTRUCTIONS.iter().filter(|i| i.opcode >= lo && i.opcode <= hi).count();
    assert_eq!(allocated_in(0x01, 0x0F), 4, "control and return");
    assert_eq!(allocated_in(0x10, 0x1F), 4, "constants");
    assert_eq!(allocated_in(0x20, 0x2F), 3, "stack");
    assert_eq!(allocated_in(0x30, 0x3F), 3, "locals and arguments");
    assert_eq!(allocated_in(0x40, 0x4F), 7, "arithmetic");
    assert_eq!(allocated_in(0x50, 0x5F), 6, "bitwise");
    assert_eq!(allocated_in(0x60, 0x6F), 6, "comparison");
    assert_eq!(allocated_in(0x70, 0x7F), 1, "host calls");
    assert_eq!(allocated_in(0x80, 0xFF), 0, "reserved for future groups");
}

#[test]
fn every_unallocated_opcode_traps() {
    // The strongest available form of the prohibition in specification 7.5:
    // there is no hidden instruction, so nothing can read the fuel counter or
    // reach a node-local quantity.
    for byte in 0..=u8::MAX {
        if instruction(byte).is_some() {
            continue;
        }
        assert_eq!(
            run(&[byte], &[]),
            VmOutcome::Trapped(TrapReason::UndefinedOpcode),
            "opcode {byte:#04x} should be undefined"
        );
    }
}

#[test]
fn zero_filled_buffer_traps_at_offset_zero() {
    // The most likely accidental "program" is a run of zero bytes, and 0x00 is
    // permanently unallocated so that such a buffer cannot execute.
    assert_eq!(run(&[0u8; 32], &[]), VmOutcome::Trapped(TrapReason::UndefinedOpcode));
}

// ---------------------------------------------------------------------------
// Instruction semantics
// ---------------------------------------------------------------------------

#[test]
fn control_and_return() {
    use opcode::*;

    // RET yields the top of the stack.
    assert_eq!(completed(run(&[PUSH_U8, 7, RET], &[])), 7);

    // JMP with a zero displacement falls through to the following instruction.
    assert_eq!(completed(run(&[JMP, 0, 0, PUSH_U8, 9, RET], &[])), 9);

    // JMP skips over the intervening PUSH.
    assert_eq!(completed(run(&[JMP, 2, 0, PUSH_U8, 1, PUSH_U8, 2, RET], &[])), 2);

    // JMPZ branches on zero and falls through otherwise. The two paths return
    // different values, so the test distinguishes taken from not-taken.
    let jmpz_taken = [PUSH_U8, 0, JMPZ, 3, 0, PUSH_U8, 7, RET, PUSH_U8, 9, RET];
    assert_eq!(completed(run(&jmpz_taken, &[])), 9);
    let jmpz_not_taken = [PUSH_U8, 1, JMPZ, 3, 0, PUSH_U8, 7, RET, PUSH_U8, 9, RET];
    assert_eq!(completed(run(&jmpz_not_taken, &[])), 7);

    // JMPNZ is its mirror image.
    let jmpnz_taken = [PUSH_U8, 1, JMPNZ, 3, 0, PUSH_U8, 7, RET, PUSH_U8, 9, RET];
    assert_eq!(completed(run(&jmpnz_taken, &[])), 9);
    let jmpnz_not_taken = [PUSH_U8, 0, JMPNZ, 3, 0, PUSH_U8, 7, RET, PUSH_U8, 9, RET];
    assert_eq!(completed(run(&jmpnz_not_taken, &[])), 7);
}

#[test]
fn ret_need_not_be_the_final_byte() {
    // Nothing scans ahead for RET; execution simply ends where it is reached.
    let program = [opcode::PUSH_U8, 3, opcode::RET, 0xFF, 0xFF];
    assert_eq!(completed(run(&program, &[])), 3);
}

#[test]
fn constants_are_zero_extended_little_endian() {
    use opcode::*;
    assert_eq!(completed(run(&[PUSH_U8, 0xFF, RET], &[])), 0xFF);
    assert_eq!(completed(run(&[PUSH_U16, 0xE8, 0x03, RET], &[])), 1000);
    assert_eq!(completed(run(&[PUSH_U32, 0x01, 0x02, 0x03, 0x04, RET], &[])), 0x0403_0201);
    let push64 = [PUSH_U64, 1, 2, 3, 4, 5, 6, 7, 8, RET];
    assert_eq!(completed(run(&push64, &[])), 0x0807_0605_0403_0201);
}

#[test]
fn stack_instructions() {
    use opcode::*;
    // POP discards the top, leaving the one beneath it as the result.
    assert_eq!(completed(run(&[PUSH_U8, 1, PUSH_U8, 2, POP, RET], &[])), 1);
    // DUP copies the top.
    assert_eq!(completed(run(&[PUSH_U8, 4, DUP, ADD, RET], &[])), 8);
    // SWAP exchanges the top two, which SUB then makes visible.
    assert_eq!(completed(run(&[PUSH_U8, 10, PUSH_U8, 3, SWAP, SUB, RET], &[])), 0);
    assert_eq!(completed(run(&[PUSH_U8, 10, PUSH_U8, 3, SUB, RET], &[])), 7);
}

#[test]
fn locals_are_zero_initialised() {
    use opcode::*;
    // No instruction can read machine state that was never written: an untouched
    // slot reads as zero rather than as whatever the frame happened to hold.
    for slot in 0..8u8 {
        assert_eq!(completed(run(&[LOAD, slot, RET], &[])), 0);
    }
}

#[test]
fn locals_round_trip() {
    use opcode::*;
    let program = [PUSH_U16, 0x34, 0x12, STORE, 5, PUSH_U8, 0, POP, LOAD, 5, RET];
    assert_eq!(completed(run(&program, &[])), 0x1234);
}

#[test]
fn arguments_are_read_by_index() {
    use opcode::*;
    assert_eq!(completed(run(&[ARG, 0, RET], &[11, 22, 33])), 11);
    assert_eq!(completed(run(&[ARG, 2, RET], &[11, 22, 33])), 33);
}

#[test]
fn arithmetic() {
    use opcode::*;
    assert_eq!(binary(ADD, 2, 3), VmOutcome::Completed(5));
    assert_eq!(binary(SUB, 9, 4), VmOutcome::Completed(5));
    assert_eq!(binary(MUL, 6, 7), VmOutcome::Completed(42));
    assert_eq!(binary(DIV, 22, 7), VmOutcome::Completed(3));
    assert_eq!(binary(MOD, 22, 7), VmOutcome::Completed(1));
    assert_eq!(binary(MIN, 4, 9), VmOutcome::Completed(4));
    assert_eq!(binary(MAX, 4, 9), VmOutcome::Completed(9));
}

#[test]
fn bitwise() {
    use opcode::*;
    assert_eq!(binary(AND, 0b1100, 0b1010), VmOutcome::Completed(0b1000));
    assert_eq!(binary(OR, 0b1100, 0b1010), VmOutcome::Completed(0b1110));
    assert_eq!(binary(XOR, 0b1100, 0b1010), VmOutcome::Completed(0b0110));
    assert_eq!(binary(SHL, 1, 4), VmOutcome::Completed(16));
    assert_eq!(binary(SHR, 32, 4), VmOutcome::Completed(2));

    let not = [opcode::PUSH_U8, 0, opcode::NOT, opcode::RET];
    assert_eq!(completed(run(&not, &[])), u64::MAX);
}

#[test]
fn comparison_pushes_one_or_zero() {
    use opcode::*;
    assert_eq!(binary(EQ, 5, 5), VmOutcome::Completed(1));
    assert_eq!(binary(EQ, 5, 6), VmOutcome::Completed(0));
    assert_eq!(binary(NE, 5, 6), VmOutcome::Completed(1));
    assert_eq!(binary(NE, 5, 5), VmOutcome::Completed(0));
    assert_eq!(binary(LT, 4, 5), VmOutcome::Completed(1));
    assert_eq!(binary(LT, 5, 5), VmOutcome::Completed(0));
    assert_eq!(binary(LTE, 5, 5), VmOutcome::Completed(1));
    assert_eq!(binary(LTE, 6, 5), VmOutcome::Completed(0));
    assert_eq!(binary(GT, 6, 5), VmOutcome::Completed(1));
    assert_eq!(binary(GT, 5, 5), VmOutcome::Completed(0));
    assert_eq!(binary(GTE, 5, 5), VmOutcome::Completed(1));
    assert_eq!(binary(GTE, 4, 5), VmOutcome::Completed(0));
}

// ---------------------------------------------------------------------------
// Totality
// ---------------------------------------------------------------------------

#[test]
fn division_and_modulo_by_zero_yield_zero() {
    use opcode::*;
    assert_eq!(binary(DIV, 7, 0), VmOutcome::Completed(0));
    assert_eq!(binary(MOD, 7, 0), VmOutcome::Completed(0));
    assert_eq!(binary(DIV, 0, 0), VmOutcome::Completed(0));
    assert_eq!(binary(MOD, 0, 0), VmOutcome::Completed(0));
}

#[test]
fn shifts_of_sixty_four_or_more_yield_zero() {
    use opcode::*;
    assert_eq!(binary(SHL, 1, 63), VmOutcome::Completed(1 << 63));
    assert_eq!(binary(SHL, 1, 64), VmOutcome::Completed(0));
    assert_eq!(binary(SHL, 1, 65), VmOutcome::Completed(0));
    assert_eq!(binary(SHL, 1, u64::MAX), VmOutcome::Completed(0));

    assert_eq!(binary(SHR, 1 << 63, 63), VmOutcome::Completed(1));
    assert_eq!(binary(SHR, u64::MAX, 64), VmOutcome::Completed(0));
    assert_eq!(binary(SHR, u64::MAX, 65), VmOutcome::Completed(0));
}

#[test]
fn addition_subtraction_and_multiplication_saturate() {
    use opcode::*;
    assert_eq!(binary(SUB, 0, 1), VmOutcome::Completed(0));
    assert_eq!(binary(SUB, 5, u64::MAX), VmOutcome::Completed(0));
    assert_eq!(binary(ADD, u64::MAX, 1), VmOutcome::Completed(u64::MAX));
    assert_eq!(binary(MUL, u64::MAX, 2), VmOutcome::Completed(u64::MAX));
    assert_eq!(binary(MUL, u64::MAX, 0), VmOutcome::Completed(0));
}

#[test]
fn no_operand_combination_traps_an_arithmetic_instruction() {
    use opcode::*;
    let ops = [ADD, SUB, MUL, DIV, MOD, MIN, MAX, AND, OR, XOR, SHL, SHR];
    let operands = [0, 1, 2, 63, 64, 65, u64::MAX / 2, u64::MAX - 1, u64::MAX];
    for op in ops {
        for a in operands {
            for b in operands {
                assert!(
                    matches!(binary(op, a, b), VmOutcome::Completed(_)),
                    "{op:#04x} trapped on ({a}, {b})"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Trap conditions, each in isolation
// ---------------------------------------------------------------------------

#[test]
fn trap_stack_overflow() {
    use opcode::*;
    let mut program = [0u8; STACK_DEPTH * 2 + 3];
    for slot in 0..=STACK_DEPTH {
        program[slot * 2] = PUSH_U8;
        program[slot * 2 + 1] = 1;
    }
    program[STACK_DEPTH * 2 + 2] = RET;
    assert_eq!(run(&program, &[]), VmOutcome::Trapped(TrapReason::StackOverflow));
}

#[test]
fn trap_stack_underflow() {
    use opcode::*;
    assert_eq!(run(&[RET], &[]), VmOutcome::Trapped(TrapReason::StackUnderflow));
    assert_eq!(run(&[POP, RET], &[]), VmOutcome::Trapped(TrapReason::StackUnderflow));
    assert_eq!(run(&[DUP, RET], &[]), VmOutcome::Trapped(TrapReason::StackUnderflow));
    assert_eq!(run(&[ADD, RET], &[]), VmOutcome::Trapped(TrapReason::StackUnderflow));
    // SWAP needs two operands, so one is not enough.
    assert_eq!(run(&[PUSH_U8, 1, SWAP, RET], &[]), VmOutcome::Trapped(TrapReason::StackUnderflow));
}

#[test]
fn trap_undefined_opcode() {
    // 0x05 is reserved inside the allocated control group, 0xC0 is unassigned.
    assert_eq!(run(&[0x05], &[]), VmOutcome::Trapped(TrapReason::UndefinedOpcode));
    assert_eq!(run(&[0xC0], &[]), VmOutcome::Trapped(TrapReason::UndefinedOpcode));
}

#[test]
fn trap_truncated_instruction() {
    use opcode::*;
    // An immediate that runs past the end.
    assert_eq!(run(&[PUSH_U8], &[]), VmOutcome::Trapped(TrapReason::TruncatedInstruction));
    assert_eq!(run(&[PUSH_U16, 0x01], &[]), VmOutcome::Trapped(TrapReason::TruncatedInstruction));
    assert_eq!(run(&[JMP, 0x01], &[]), VmOutcome::Trapped(TrapReason::TruncatedInstruction));
    // The opcode itself past the end: falling off the tail of the program.
    assert_eq!(run(&[PUSH_U8, 1], &[]), VmOutcome::Trapped(TrapReason::TruncatedInstruction));
}

#[test]
fn trap_control_flow_out_of_range() {
    use opcode::*;
    // Forward past the end.
    assert_eq!(run(&[JMP, 0x64, 0x00, RET], &[]), VmOutcome::Trapped(TrapReason::ControlFlowOutOfRange));
    // Backwards before the start.
    let back = [JMP, 0xF0, 0xFF, RET];
    assert_eq!(run(&back, &[]), VmOutcome::Trapped(TrapReason::ControlFlowOutOfRange));
    // A destination exactly at the end is outside the byte range.
    assert_eq!(run(&[JMP, 0x01, 0x00, RET], &[]), VmOutcome::Trapped(TrapReason::ControlFlowOutOfRange));
}

#[test]
fn trap_operand_index_out_of_range() {
    use opcode::*;
    // ARG at or above the invocation's arity.
    assert_eq!(run(&[ARG, 0, RET], &[]), VmOutcome::Trapped(TrapReason::OperandIndexOutOfRange));
    assert_eq!(run(&[ARG, 1, RET], &[7]), VmOutcome::Trapped(TrapReason::OperandIndexOutOfRange));
    // LOAD and STORE outside the local-slot array.
    assert_eq!(run(&[LOAD, 8, RET], &[]), VmOutcome::Trapped(TrapReason::OperandIndexOutOfRange));
    let store = [PUSH_U8, 1, STORE, 8, RET];
    assert_eq!(run(&store, &[]), VmOutcome::Trapped(TrapReason::OperandIndexOutOfRange));
}

#[test]
fn trap_host_call_unresolved() {
    use opcode::*;
    let mut fuel = Fuel::new(1000);
    let outcome = TestVm::execute(&[GETPARAM, 1, RET], &[], &mut fuel, &DecliningHost);
    assert_eq!(outcome, VmOutcome::Trapped(TrapReason::HostCallUnresolved));
}

#[test]
fn trap_nesting_depth_exceeded() {
    use opcode::*;
    // Checked directly at the boundary: an invocation already at the maximum
    // depth cannot make a further host call.
    static PARAMS: &[(u8, Param)] = &[(1, Param::Constant(5))];
    let host = TableHost::new(PARAMS);
    let mut fuel = Fuel::new(1000);
    fuel.depth = 4;
    let outcome = TestVm::execute(&[GETPARAM, 1, RET], &[], &mut fuel, &host);
    assert_eq!(outcome, VmOutcome::Trapped(TrapReason::NestingDepthExceeded));
}

#[test]
fn a_cycle_between_parameters_terminates() {
    use opcode::*;
    // Parameter 5 resolves by asking for parameter 5. Nothing detects the cycle
    // statically; the nesting limit stops it, and the host maps the failed
    // sub-evaluation onto a declined resolution for its caller.
    static SELF_REFERENCE: &[u8] = &[GETPARAM, 5, RET];
    static PARAMS: &[(u8, Param)] = &[(5, Param::Program(SELF_REFERENCE, 0))];
    let host = TableHost::new(PARAMS);
    let mut fuel = Fuel::new(10_000);
    let outcome = TestVm::execute(&[GETPARAM, 5, RET], &[], &mut fuel, &host);
    assert_eq!(outcome, VmOutcome::Trapped(TrapReason::HostCallUnresolved));
    // Four levels of nesting were entered before the limit refused the fifth.
    assert_eq!(host.calls.get(), 4);
    // Fuel remains: the nesting limit caught the cycle, not exhaustion.
    assert!(fuel.remaining > 0);
}

// ---------------------------------------------------------------------------
// Fuel
// ---------------------------------------------------------------------------

#[test]
fn fuel_is_charged_once_per_instruction() {
    use opcode::*;
    let mut fuel = Fuel::new(100);
    let outcome = TestVm::execute(&[PUSH_U8, 1, PUSH_U8, 2, ADD, RET], &[], &mut fuel, &DecliningHost);
    assert_eq!(outcome, VmOutcome::Completed(3));
    assert_eq!(fuel.remaining, 96);
}

#[test]
fn fuel_exhaustion_at_the_exact_boundary() {
    use opcode::*;
    let program = [PUSH_U8, 1, PUSH_U8, 2, ADD, RET];

    // Exactly enough for all four instructions.
    let mut fuel = Fuel::new(4);
    assert_eq!(TestVm::execute(&program, &[], &mut fuel, &DecliningHost), VmOutcome::Completed(3));
    assert_eq!(fuel.remaining, 0);

    // One short: the final RET cannot be charged.
    let mut fuel = Fuel::new(3);
    assert_eq!(TestVm::execute(&program, &[], &mut fuel, &DecliningHost), VmOutcome::OutOfFuel);

    // Nothing at all: the first instruction cannot be charged.
    let mut fuel = Fuel::new(0);
    assert_eq!(TestVm::execute(&program, &[], &mut fuel, &DecliningHost), VmOutcome::OutOfFuel);
}

#[test]
fn fuel_exhausted_mid_program_by_a_loop() {
    use opcode::*;
    // An unconditional backward jump: only fuel can stop it.
    let program = [JMP, 0xFD, 0xFF, RET];
    let mut fuel = Fuel::new(500);
    assert_eq!(TestVm::execute(&program, &[], &mut fuel, &DecliningHost), VmOutcome::OutOfFuel);
    assert_eq!(fuel.remaining, 0);
}

#[test]
fn nested_evaluation_draws_from_the_callers_budget() {
    use opcode::*;
    // Parameter 1 is itself a two-instruction program.
    static INTER_BLOCK: &[u8] = &[PUSH_U16, 0x60, 0xEA, RET];
    static PARAMS: &[(u8, Param)] = &[(1, Param::Program(INTER_BLOCK, 0))];
    let host = TableHost::new(PARAMS);

    // Four instructions in the caller, two in the callee.
    let program = [GETPARAM, 1, PUSH_U8, 2, DIV, RET];
    let mut fuel = Fuel::new(1000);
    assert_eq!(TestVm::execute(&program, &[], &mut fuel, &host), VmOutcome::Completed(30_000));
    assert_eq!(fuel.remaining, 1000 - 6, "the callee spends from the same budget");

    // Six units is exactly enough; five is not, which is only true because the
    // budget is shared rather than replenished per nesting level.
    let mut fuel = Fuel::new(6);
    assert_eq!(TestVm::execute(&program, &[], &mut fuel, &host), VmOutcome::Completed(30_000));
    let mut fuel = Fuel::new(5);
    assert_eq!(TestVm::execute(&program, &[], &mut fuel, &host), VmOutcome::OutOfFuel);
}

// ---------------------------------------------------------------------------
// Host calls
// ---------------------------------------------------------------------------

#[test]
fn getparam_consumes_exactly_the_declared_arity() {
    use opcode::*;
    // registration_price(registered_nodes) = min(1000 + 5 * n, 50000)
    static PRICE: &[u8] = &[ARG, 0, PUSH_U8, 5, MUL, PUSH_U16, 0xE8, 0x03, ADD, PUSH_U16, 0x50, 0xC3, MIN, RET];
    static PARAMS: &[(u8, Param)] = &[(24, Param::Program(PRICE, 1))];
    let host = TableHost::new(PARAMS);

    // A sentinel beneath the argument must survive the call untouched: dropping
    // the result leaves the sentinel, which only holds if exactly one operand
    // was consumed.
    let program = [PUSH_U8, 99, PUSH_U8, 200, GETPARAM, 24, POP, RET];
    let mut fuel = Fuel::new(1000);
    assert_eq!(TestVm::execute(&program, &[], &mut fuel, &host), VmOutcome::Completed(99));

    // And the value itself is the computed price.
    let program = [PUSH_U8, 200, GETPARAM, 24, RET];
    let mut fuel = Fuel::new(1000);
    assert_eq!(TestVm::execute(&program, &[], &mut fuel, &host), VmOutcome::Completed(2000));
}

#[test]
fn getparam_arguments_are_passed_deepest_first() {
    use opcode::*;
    // A two-argument parameter returning arg0 * 100 + arg1 makes the order
    // visible: argument 0 is the one pushed first.
    static ORDER: &[u8] = &[ARG, 0, PUSH_U8, 100, MUL, ARG, 1, ADD, RET];
    static PARAMS: &[(u8, Param)] = &[(7, Param::Program(ORDER, 2))];
    let host = TableHost::new(PARAMS);

    let program = [PUSH_U8, 3, PUSH_U8, 4, GETPARAM, 7, RET];
    let mut fuel = Fuel::new(1000);
    assert_eq!(TestVm::execute(&program, &[], &mut fuel, &host), VmOutcome::Completed(304));
}

#[test]
fn getparam_underflows_when_the_stack_lacks_the_arity() {
    use opcode::*;
    static PRICE: &[u8] = &[ARG, 0, RET];
    static PARAMS: &[(u8, Param)] = &[(24, Param::Program(PRICE, 1))];
    let host = TableHost::new(PARAMS);
    let mut fuel = Fuel::new(1000);
    let outcome = TestVm::execute(&[GETPARAM, 24, RET], &[], &mut fuel, &host);
    assert_eq!(outcome, VmOutcome::Trapped(TrapReason::StackUnderflow));
}

#[test]
fn getparam_overflows_when_the_stack_is_full() {
    use opcode::*;
    // The key is written beneath the arguments, so a full stack has no room for
    // it even when the call would consume operands.
    static PARAMS: &[(u8, Param)] = &[(1, Param::Constant(5))];
    let host = TableHost::new(PARAMS);

    let mut program = [0u8; STACK_DEPTH * 2 + 3];
    for slot in 0..STACK_DEPTH {
        program[slot * 2] = PUSH_U8;
        program[slot * 2 + 1] = 1;
    }
    program[STACK_DEPTH * 2] = GETPARAM;
    program[STACK_DEPTH * 2 + 1] = 1;
    program[STACK_DEPTH * 2 + 2] = RET;

    let mut fuel = Fuel::new(1000);
    assert_eq!(TestVm::execute(&program, &[], &mut fuel, &host), VmOutcome::Trapped(TrapReason::StackOverflow));
}

#[test]
fn a_host_that_declines_one_key_still_serves_another() {
    use opcode::*;
    static PARAMS: &[(u8, Param)] = &[(1, Param::Constant(42))];
    let host = TableHost::new(PARAMS);

    let mut fuel = Fuel::new(1000);
    assert_eq!(TestVm::execute(&[GETPARAM, 1, RET], &[], &mut fuel, &host), VmOutcome::Completed(42));

    let mut fuel = Fuel::new(1000);
    let outcome = TestVm::execute(&[GETPARAM, 2, RET], &[], &mut fuel, &host);
    assert_eq!(outcome, VmOutcome::Trapped(TrapReason::HostCallUnresolved));
}

// ---------------------------------------------------------------------------
// Decoding behaviour that is deliberate rather than incidental
// ---------------------------------------------------------------------------

#[test]
fn a_jump_into_the_middle_of_an_instruction_decodes_deterministically() {
    use opcode::*;
    // Offset 3 was authored as PUSH_U16 0x0510. Jumping to offset 4 lands on its
    // first immediate byte, 0x10, which is PUSH_U8 — so decoding resumes there
    // and pushes 5. There is no instruction-boundary concept at runtime, and
    // every node decodes these bytes identically.
    let program = [JMP, 0x01, 0x00, PUSH_U16, 0x10, 0x05, RET];
    assert_eq!(completed(run(&program, &[])), 5);

    // Repeating the run is the point: the behaviour is defined, not incidental.
    assert_eq!(completed(run(&program, &[])), 5);
}

// ---------------------------------------------------------------------------
// The worked examples of specification 7.2.4
// ---------------------------------------------------------------------------

#[test]
fn specification_example_derived_parameter() {
    // GETPARAM 1 / PUSH 2 / DIV / RET, stated as six bytes: 70 01 10 02 43 01.
    let program = [0x70, 0x01, 0x10, 0x02, 0x43, 0x01];
    assert_eq!(program.len(), 6);

    static PARAMS: &[(u8, Param)] = &[(1, Param::Constant(60_000))];
    let host = TableHost::new(PARAMS);
    let mut fuel = Fuel::new(1000);
    assert_eq!(TestVm::execute(&program, &[], &mut fuel, &host), VmOutcome::Completed(30_000));
}

#[test]
fn specification_example_argument_taking_parameter() {
    // The hexdump given in the specification, verbatim.
    let program = [
        0x32, 0x00, // ARG 0
        0x10, 0x05, // PUSH_U8 5
        0x42, // MUL
        0x11, 0xE8, 0x03, // PUSH_U16 1000
        0x40, // ADD
        0x11, 0x50, 0xC3, // PUSH_U16 50000
        0x45, // MIN
        0x01, // RET
    ];
    assert_eq!(program.len(), 14, "the specification states fourteen bytes");

    assert_eq!(completed(run(&program, &[0])), 1000);
    assert_eq!(completed(run(&program, &[200])), 2000);
    // The clamp binds well before the saturation point.
    assert_eq!(completed(run(&program, &[100_000])), 50_000);
    assert_eq!(completed(run(&program, &[u64::MAX])), 50_000);
}

#[test]
fn specification_example_loop() {
    use opcode::*;
    // Compounding growth, one step per hundred registered nodes.
    let program = [
        PUSH_U16, 0xE8, 0x03, // 0:  PUSH 1000
        ARG, 0x00,   // 3:  ARG 0
        PUSH_U8, 0x64,   // 5:  PUSH 100
        DIV,    // 7:  DIV
        DUP,    // 8:  loop: DUP
        JMPZ, 0x0D, 0x00, // 9:  JMPZ done  (+13)
        PUSH_U8, 0x01, // 12: PUSH 1
        SUB,    // 14: SUB
        SWAP,   // 15: SWAP
        DUP,    // 16: DUP
        PUSH_U8, 0x0A, // 17: PUSH 10
        DIV,    // 19: DIV
        ADD,    // 20: ADD
        SWAP,   // 21: SWAP
        JMP, 0xEF, 0xFF, // 22: JMP loop  (-17)
        POP,    // 25: done: POP
        RET,    // 26: RET
    ];
    assert_eq!(program.len(), 27, "the specification states twenty-seven bytes");

    // Ten iterations of price += price / 10, starting from 1000.
    let mut fuel = Fuel::new(1000);
    let outcome = TestVm::execute(&program, &[1000], &mut fuel, &DecliningHost);
    assert_eq!(outcome, VmOutcome::Completed(2591));

    // Four in the prologue, eleven per iteration, two to fall out, two to
    // finish: 118 units at a thousand registered nodes.
    assert_eq!(1000 - fuel.remaining, 118, "the specification states 118 fuel units");

    // Below a hundred nodes the loop body never runs.
    assert_eq!(completed(run(&program, &[0])), 1000);
    assert_eq!(completed(run(&program, &[99])), 1000);
}
