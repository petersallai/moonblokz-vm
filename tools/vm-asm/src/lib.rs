//! Assembler for MoonBlokz configuration bytecode.
//!
//! This is the only place where structural mistakes in a program are diagnosed.
//! The runtime carries no verifier, so an out-of-range jump or an oversized
//! immediate merely traps and falls back on-device — correct behaviour, but a
//! poor diagnostic. Static checking belongs here, where it costs no device code
//! size and can produce a message that names the offending line.
//!
//! The crate is a library as well as a binary because `config-encoder` assembles
//! the bytecode entries of a configuration payload itself, rather than forcing
//! the author through a two-step pipeline by hand.

use std::fmt;

use moonblokz_vm::{INSTRUCTIONS, Imm, opcode};

/// The 255-byte ceiling on a program, imposed by the one-byte `value_length` of
/// the configuration payload's framing rather than by the machine.
pub const MAX_PROGRAM_LEN: usize = 255;

/// A diagnostic naming the line that could not be assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsmError {
    /// One-based line number, or zero for a whole-program diagnostic.
    pub line: usize,
    /// What went wrong.
    pub message: String,
}

impl fmt::Display for AsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(f, "{}", self.message)
        } else {
            write!(f, "line {}: {}", self.line, self.message)
        }
    }
}

impl std::error::Error for AsmError {}

fn err(line: usize, message: impl Into<String>) -> AsmError {
    AsmError { line, message: message.into() }
}

/// How a jump's destination was written.
enum Target {
    /// A label name, resolved in the second pass.
    Label(String),
    /// An explicit displacement, already relative to the following instruction.
    Displacement(i16),
}

/// One parsed instruction, with its resolved offset and pending operand.
struct Parsed {
    line: usize,
    offset: usize,
    opcode: u8,
    imm: Imm,
    /// The immediate for everything except jumps; the first of the two for a
    /// paired immediate.
    value: u64,
    /// The second immediate of a paired immediate.
    second: u64,
    /// The destination for jumps.
    target: Option<Target>,
}

impl Parsed {
    fn size(&self) -> usize {
        1 + self.imm.size()
    }
}

/// Looks up a mnemonic, case-insensitively.
fn lookup(mnemonic: &str) -> Option<(u8, Imm)> {
    INSTRUCTIONS
        .iter()
        .find(|i| i.mnemonic.eq_ignore_ascii_case(mnemonic))
        .map(|i| (i.opcode, i.imm))
}

/// Parses a decimal or `0x`-prefixed hexadecimal unsigned operand.
fn parse_unsigned(token: &str) -> Option<u64> {
    match token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => token.parse::<u64>().ok(),
    }
}

/// Parses a signed jump displacement, decimal or `0x`-prefixed.
fn parse_signed(token: &str) -> Option<i64> {
    if let Some(rest) = token.strip_prefix('-') {
        parse_unsigned(rest).and_then(|v| i64::try_from(v).ok()).map(|v| -v)
    } else {
        parse_unsigned(token).and_then(|v| i64::try_from(v).ok())
    }
}

fn is_label_name(token: &str) -> bool {
    let mut chars = token.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The narrowest `PUSH_*` encoding that holds `value`.
///
/// Programs live in a 255-byte budget, and an author who reaches for `PUSH_U64`
/// out of habit spends nine bytes where two would do. The rule is deterministic,
/// so the alias never makes a program's encoding a matter of taste.
fn narrowest_push(value: u64) -> (u8, Imm) {
    if value <= u8::MAX as u64 {
        (opcode::PUSH_U8, Imm::U8)
    } else if value <= u16::MAX as u64 {
        (opcode::PUSH_U16, Imm::U16)
    } else if value <= u32::MAX as u64 {
        (opcode::PUSH_U32, Imm::U32)
    } else {
        (opcode::PUSH_U64, Imm::U64)
    }
}

/// Translates assembly source into bytecode.
pub fn assemble(source: &str) -> Result<Vec<u8>, AsmError> {
    let mut parsed: Vec<Parsed> = Vec::new();
    let mut labels: Vec<(String, usize)> = Vec::new();
    let mut offset: usize = 0;

    for (index, raw) in source.lines().enumerate() {
        let line = index + 1;

        // Everything from a `;` to the end of the line is a comment.
        let mut text = match raw.find(';') {
            Some(at) => &raw[..at],
            None => raw,
        }
        .trim();

        // A label is `name:`, either alone or preceding an instruction.
        if let Some(at) = text.find(':') {
            let name = text[..at].trim();
            if !is_label_name(name) {
                return Err(err(line, format!("`{name}` is not a valid label name")));
            }
            if labels.iter().any(|(existing, _)| existing == name) {
                return Err(err(line, format!("label `{name}` is defined more than once")));
            }
            labels.push((name.to_string(), offset));
            text = text[at + 1..].trim();
        }

        if text.is_empty() {
            continue;
        }

        // Operands are separated by a comma, whitespace, or both; normalising the
        // comma away keeps the lexer a single whitespace split.
        let normalised = text.replace(',', " ");
        let mut tokens = normalised.split_whitespace();
        let mnemonic = tokens.next().expect("non-empty text has a first token");
        let operand = tokens.next();
        let operand2 = tokens.next();
        if let Some(extra) = tokens.next() {
            return Err(err(line, format!("unexpected operand `{extra}`")));
        }

        // `PUSH` without a width is an alias for the narrowest encoding.
        let (op, imm) = if mnemonic.eq_ignore_ascii_case("PUSH") {
            let token = operand.ok_or_else(|| err(line, "PUSH needs an operand"))?;
            let value = parse_unsigned(token).ok_or_else(|| err(line, format!("`{token}` is not an unsigned integer")))?;
            narrowest_push(value)
        } else {
            lookup(mnemonic).ok_or_else(|| err(line, format!("unknown instruction `{mnemonic}`")))?
        };

        let mut value = 0u64;
        let mut second = 0u64;
        let mut target = None;

        if imm != Imm::U8Pair && let Some(extra) = operand2 {
            return Err(err(line, format!("{mnemonic} takes one operand, found `{extra}`")));
        }

        match imm {
            Imm::None => {
                if let Some(extra) = operand {
                    return Err(err(line, format!("{mnemonic} takes no operand, found `{extra}`")));
                }
            }
            Imm::U8Pair => {
                let key = operand.ok_or_else(|| err(line, format!("{mnemonic} needs a key and an argument count")))?;
                let count = operand2.ok_or_else(|| err(line, format!("{mnemonic} needs an argument count after the key")))?;
                value = parse_unsigned(key).ok_or_else(|| err(line, format!("`{key}` is not an unsigned integer")))?;
                second = parse_unsigned(count).ok_or_else(|| err(line, format!("`{count}` is not an unsigned integer")))?;
                if value > u8::MAX as u64 {
                    return Err(err(line, format!("key {value} does not fit in 8 bits")));
                }
                if second > u8::MAX as u64 {
                    return Err(err(line, format!("argument count {second} does not fit in 8 bits")));
                }
            }
            Imm::Rel16 => {
                let token = operand.ok_or_else(|| err(line, format!("{mnemonic} needs a label or displacement")))?;
                target = Some(if is_label_name(token) {
                    Target::Label(token.to_string())
                } else {
                    let displacement =
                        parse_signed(token).ok_or_else(|| err(line, format!("`{token}` is neither a label nor a displacement")))?;
                    Target::Displacement(
                        i16::try_from(displacement).map_err(|_| err(line, format!("displacement {displacement} does not fit in i16")))?,
                    )
                });
            }
            width => {
                let token = operand.ok_or_else(|| err(line, format!("{mnemonic} needs an operand")))?;
                value = parse_unsigned(token).ok_or_else(|| err(line, format!("`{token}` is not an unsigned integer")))?;
                let bits = width.size() * 8;
                if bits < 64 && value >= (1u64 << bits) {
                    return Err(err(line, format!("operand {value} does not fit in {bits} bits")));
                }
            }
        }

        parsed.push(Parsed { line, offset, opcode: op, imm, value, second, target });
        offset += parsed.last().expect("just pushed").size();

        if offset > MAX_PROGRAM_LEN {
            return Err(err(
                line,
                format!("program exceeds the {MAX_PROGRAM_LEN}-byte limit imposed by the configuration framing"),
            ));
        }
    }

    let total = offset;
    let mut bytes = Vec::with_capacity(total);

    for insn in &parsed {
        bytes.push(insn.opcode);
        match insn.imm {
            Imm::None => {}
            Imm::U8 => bytes.push(insn.value as u8),
            Imm::U8Pair => {
                bytes.push(insn.value as u8);
                bytes.push(insn.second as u8);
            }
            Imm::U16 => bytes.extend_from_slice(&(insn.value as u16).to_le_bytes()),
            Imm::U32 => bytes.extend_from_slice(&(insn.value as u32).to_le_bytes()),
            Imm::U64 => bytes.extend_from_slice(&insn.value.to_le_bytes()),
            Imm::Rel16 => {
                // Displacements are relative to the address of the following
                // instruction, so the base is this instruction's offset plus its
                // own three bytes.
                let next_pc = (insn.offset + 3) as i64;
                let displacement = match insn.target.as_ref().expect("a jump carries a target") {
                    Target::Displacement(d) => *d as i64,
                    Target::Label(name) => {
                        let target = labels
                            .iter()
                            .find(|(existing, _)| existing == name)
                            .map(|(_, at)| *at as i64)
                            .ok_or_else(|| err(insn.line, format!("undefined label `{name}`")))?;
                        target - next_pc
                    }
                };

                let destination = next_pc + displacement;
                if destination < 0 || destination >= total as i64 {
                    return Err(err(
                        insn.line,
                        format!("jump destination {destination} falls outside the {total}-byte program"),
                    ));
                }
                let displacement = i16::try_from(displacement)
                    .map_err(|_| err(insn.line, format!("displacement {displacement} does not fit in i16")))?;
                bytes.extend_from_slice(&displacement.to_le_bytes());
            }
        }
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specification_example_derived_parameter() {
        let source = "GETPARAM 1, 0        ; inter_block_interval_ms\nPUSH 2\nDIV\nRET\n";
        assert_eq!(assemble(source).unwrap(), vec![0x70, 0x01, 0x00, 0x10, 0x02, 0x43, 0x01]);
    }

    #[test]
    fn getparam_declares_its_argument_count() {
        // The comma is optional, and the count is a second immediate byte.
        assert_eq!(assemble("GETPARAM 24, 1\nRET\n").unwrap(), vec![0x70, 0x18, 0x01, 0x01]);
        assert_eq!(assemble("GETPARAM 24 1\nRET\n").unwrap(), vec![0x70, 0x18, 0x01, 0x01]);
        assert_eq!(assemble("getparam 0x18,0x01\nret\n").unwrap(), vec![0x70, 0x18, 0x01, 0x01]);

        let missing = assemble("GETPARAM 24\n").unwrap_err();
        assert!(missing.message.contains("argument count"), "{}", missing.message);

        let too_wide = assemble("GETPARAM 24, 256\n").unwrap_err();
        assert!(too_wide.message.contains("argument count"), "{}", too_wide.message);

        // An instruction with a single immediate still refuses a second operand.
        let spurious = assemble("PUSH_U8 1, 2\n").unwrap_err();
        assert!(spurious.message.contains("one operand"), "{}", spurious.message);
    }

    #[test]
    fn specification_example_argument_taking_parameter() {
        let source = "\
; registration_price(registered_nodes) = min(1000 + 5 * n, 50000)
ARG 0
PUSH 5
MUL
PUSH 1000
ADD
PUSH 50000
MIN
RET
";
        let expected = vec![
            0x32, 0x00, // ARG 0
            0x10, 0x05, // PUSH_U8 5
            0x42, // MUL
            0x11, 0xE8, 0x03, // PUSH_U16 1000
            0x40, // ADD
            0x11, 0x50, 0xC3, // PUSH_U16 50000
            0x45, // MIN
            0x01, // RET
        ];
        assert_eq!(assemble(source).unwrap(), expected);
    }

    #[test]
    fn specification_example_loop() {
        let source = "\
        PUSH 1000          ; price
        ARG 0
        PUSH 100
        DIV                ; [price tiers]
loop:   DUP
        JMPZ done
        PUSH 1
        SUB                ; tiers -= 1
        SWAP               ; [tiers price]
        DUP
        PUSH 10
        DIV
        ADD                ; price += price / 10
        SWAP               ; [price tiers]
        JMP loop
done:   POP
        RET
";
        let bytes = assemble(source).unwrap();
        assert_eq!(bytes.len(), 27, "the specification states twenty-seven bytes");
        // JMPZ at offset 9 reaches `done` at 25 from a following instruction at 12.
        assert_eq!(&bytes[9..12], &[0x03, 0x0D, 0x00]);
        // JMP at offset 22 reaches `loop` at 8 from a following instruction at 25.
        assert_eq!(&bytes[22..25], &[0x02, 0xEF, 0xFF]);
    }

    #[test]
    fn push_selects_the_narrowest_encoding() {
        assert_eq!(assemble("PUSH 255\nRET\n").unwrap(), vec![0x10, 0xFF, 0x01]);
        assert_eq!(assemble("PUSH 256\nRET\n").unwrap(), vec![0x11, 0x00, 0x01, 0x01]);
        assert_eq!(assemble("PUSH 65536\nRET\n").unwrap(), vec![0x12, 0x00, 0x00, 0x01, 0x00, 0x01]);
        let wide = assemble("PUSH 4294967296\nRET\n").unwrap();
        assert_eq!(wide[0], 0x13);
        assert_eq!(wide.len(), 10);
    }

    #[test]
    fn explicit_widths_are_never_narrowed() {
        assert_eq!(assemble("PUSH_U64 1\nRET\n").unwrap().len(), 10);
        assert_eq!(assemble("PUSH_U16 1\nRET\n").unwrap(), vec![0x11, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn mnemonics_are_case_insensitive_and_hex_operands_are_accepted() {
        assert_eq!(assemble("push_u8 0x0A\nret\n").unwrap(), vec![0x10, 0x0A, 0x01]);
        assert_eq!(assemble("Push 0xFF\nRet\n").unwrap(), vec![0x10, 0xFF, 0x01]);
    }

    #[test]
    fn comments_blank_lines_and_lone_labels_are_ignored() {
        let source = "\n; a comment\n\nstart:\n   RET   ; trailing\n";
        assert_eq!(assemble(source).unwrap(), vec![0x01]);
    }

    #[test]
    fn an_explicit_displacement_is_accepted() {
        // JMP +0 falls through to the RET that follows it.
        assert_eq!(assemble("JMP 0\nRET\n").unwrap(), vec![0x02, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn diagnostics_name_the_offending_line() {
        let unknown = assemble("RET\nFROBNICATE\n").unwrap_err();
        assert_eq!(unknown.line, 2);
        assert!(unknown.message.contains("FROBNICATE"), "{}", unknown.message);

        let undefined = assemble("JMP nowhere\nRET\n").unwrap_err();
        assert_eq!(undefined.line, 1);
        assert!(undefined.message.contains("nowhere"), "{}", undefined.message);

        let too_wide = assemble("PUSH_U8 256\nRET\n").unwrap_err();
        assert_eq!(too_wide.line, 1);
        assert!(too_wide.message.contains("8 bits"), "{}", too_wide.message);

        let spurious = assemble("ADD 1\n").unwrap_err();
        assert_eq!(spurious.line, 1);

        let missing = assemble("PUSH_U8\n").unwrap_err();
        assert_eq!(missing.line, 1);

        let duplicate = assemble("a:\nRET\na:\nRET\n").unwrap_err();
        assert_eq!(duplicate.line, 3);
    }

    #[test]
    fn a_jump_outside_the_program_is_refused() {
        let out_of_range = assemble("JMP 100\nRET\n").unwrap_err();
        assert!(out_of_range.message.contains("outside"), "{}", out_of_range.message);

        let backwards = assemble("JMP -100\nRET\n").unwrap_err();
        assert!(backwards.message.contains("outside"), "{}", backwards.message);
    }

    #[test]
    fn the_program_length_limit_is_enforced() {
        // Each RET is one byte, so 256 of them is one past the ceiling.
        let source = "RET\n".repeat(256);
        let too_long = assemble(&source).unwrap_err();
        assert!(too_long.message.contains("255-byte"), "{}", too_long.message);

        assert!(assemble(&"RET\n".repeat(255)).is_ok());
    }

    #[test]
    fn every_instruction_assembles() {
        for info in INSTRUCTIONS {
            let source = match info.imm {
                Imm::None => format!("{}\n", info.mnemonic),
                // A jump needs somewhere to land, so give it a following RET.
                Imm::Rel16 => format!("{} 0\nRET\n", info.mnemonic),
                Imm::U8Pair => format!("{} 1, 0\n", info.mnemonic),
                _ => format!("{} 1\n", info.mnemonic),
            };
            let bytes = assemble(&source).unwrap_or_else(|e| panic!("{} failed: {e}", info.mnemonic));
            assert_eq!(bytes[0], info.opcode, "{}", info.mnemonic);
        }
    }
}
