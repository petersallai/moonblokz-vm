//! Disassembler for MoonBlokz configuration bytecode.
//!
//! Renders bytecode back to the canonical textual form: for tests, for reviewing
//! a proposed genesis configuration before it is signed, and for diagnosing a
//! chain whose configuration is known only as bytes.
//!
//! It is also the counterpart the assembler is tested against. A round trip
//! through both is the conformance test for the instruction set, and it is
//! meaningful only because the canonical text is specified rather than left to
//! whatever the two tools happen to agree on.

use std::fmt;

use moonblokz_vm::{INSTRUCTIONS, Imm, instruction};

/// A diagnostic naming the offset that could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisError {
    /// Byte offset within the program.
    pub offset: usize,
    /// What went wrong.
    pub message: String,
}

impl fmt::Display for DisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "offset {}: {}", self.offset, self.message)
    }
}

impl std::error::Error for DisError {}

/// One decoded instruction.
struct Decoded {
    offset: usize,
    opcode: u8,
    imm: Imm,
    /// The immediate, for everything except jumps; the first of the two for a
    /// paired immediate.
    value: u64,
    /// The second immediate of a paired immediate.
    second: u64,
    /// The destination, for jumps. `None` when it falls outside the program.
    destination: Option<usize>,
    /// The raw displacement, for jumps.
    displacement: i16,
}

/// Decodes a program linearly from offset zero.
///
/// Linear decoding is what the canonical text describes; it is not what the
/// machine does at runtime, where a jump may land mid-instruction and decoding
/// simply resumes there. A program relying on that is still disassembled here as
/// the byte sequence it is, which is what keeps the round trip exact.
fn decode(bytes: &[u8]) -> Result<Vec<Decoded>, DisError> {
    let mut decoded = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        let byte = bytes[offset];
        let info = instruction(byte).ok_or(DisError {
            offset,
            message: format!("{byte:#04x} is not an allocated opcode"),
        })?;

        let width = info.imm.size();
        let immediate = bytes.get(offset + 1..offset + 1 + width).ok_or(DisError {
            offset,
            message: format!("{} needs a {width}-byte immediate, but the program ends", info.mnemonic),
        })?;

        let mut value = 0u64;
        let mut second = 0u64;
        let mut displacement = 0i16;
        let mut destination = None;

        match info.imm {
            Imm::None => {}
            Imm::U8 => value = immediate[0] as u64,
            Imm::U8Pair => {
                value = immediate[0] as u64;
                second = immediate[1] as u64;
            }
            Imm::U16 => value = u16::from_le_bytes([immediate[0], immediate[1]]) as u64,
            Imm::U32 => value = u32::from_le_bytes([immediate[0], immediate[1], immediate[2], immediate[3]]) as u64,
            Imm::U64 => {
                value = u64::from_le_bytes([
                    immediate[0],
                    immediate[1],
                    immediate[2],
                    immediate[3],
                    immediate[4],
                    immediate[5],
                    immediate[6],
                    immediate[7],
                ]);
            }
            Imm::Rel16 => {
                displacement = i16::from_le_bytes([immediate[0], immediate[1]]);
                let next_pc = (offset + 3) as i64;
                let target = next_pc + displacement as i64;
                if target >= 0 && (target as usize) < bytes.len() {
                    destination = Some(target as usize);
                }
            }
        }

        decoded.push(Decoded { offset, opcode: byte, imm: info.imm, value, second, destination, displacement });
        offset += 1 + width;
    }

    Ok(decoded)
}

/// Renders bytecode as the canonical textual form.
///
/// The canonical rendering is uppercase mnemonics, one instruction per line, a
/// single space before an operand, decimal immediates, explicit `PUSH_*` widths,
/// no comments, labels named `L0`, `L1`, … numbered by ascending target offset
/// and placed on their own lines, a comma and a space between the two operands
/// of a paired immediate, and LF line endings.
///
/// A jump whose destination does not coincide with a linearly decoded
/// instruction — one landing mid-instruction, or outside the program — is
/// rendered as an explicit signed displacement instead of a label. There is no
/// line to attach a label to in those cases, and emitting the displacement is
/// what keeps `assemble(disassemble(bytes)) == bytes` exact.
pub fn disassemble(bytes: &[u8]) -> Result<String, DisError> {
    let decoded = decode(bytes)?;

    // A destination earns a label only if it starts a decoded instruction.
    let mut destinations: Vec<usize> = decoded
        .iter()
        .filter_map(|d| d.destination)
        .filter(|target| decoded.iter().any(|d| d.offset == *target))
        .collect();
    destinations.sort_unstable();
    destinations.dedup();

    let label_of = |offset: usize| destinations.iter().position(|d| *d == offset).map(|index| format!("L{index}"));

    let mut out = String::new();
    for insn in &decoded {
        if let Some(name) = label_of(insn.offset) {
            out.push_str(&name);
            out.push_str(":\n");
        }

        let mnemonic = INSTRUCTIONS
            .iter()
            .find(|i| i.opcode == insn.opcode)
            .expect("decode only yields allocated opcodes")
            .mnemonic;
        out.push_str(mnemonic);

        match insn.imm {
            Imm::None => {}
            Imm::U8Pair => {
                out.push(' ');
                out.push_str(&insn.value.to_string());
                out.push_str(", ");
                out.push_str(&insn.second.to_string());
            }
            Imm::Rel16 => {
                let operand = insn
                    .destination
                    .and_then(label_of)
                    .unwrap_or_else(|| insn.displacement.to_string());
                out.push(' ');
                out.push_str(&operand);
            }
            _ => {
                out.push(' ');
                out.push_str(&insn.value.to_string());
            }
        }
        out.push('\n');
    }

    Ok(out)
}

/// Renders a program as a space-separated uppercase hexdump.
pub fn hexdump(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

/// Parses a hexadecimal string, ignoring whitespace.
pub fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let digits: String = text.split_whitespace().collect();
    if !digits.len().is_multiple_of(2) {
        return Err("a hexadecimal program needs an even number of digits".to_string());
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).map_err(|_| format!("`{}` is not a hexadecimal byte", &digits[i..i + 2])))
        .collect()
}

/// The canonical mnemonic of an opcode, or `None` if it is unallocated.
pub fn mnemonic(opcode: u8) -> Option<&'static str> {
    instruction(opcode).map(|i| i.mnemonic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use moonblokz_vm::opcode;
    use moonblokz_vm_asm::assemble;

    /// The property that makes the round trip a conformance test for the ISA.
    fn round_trips(bytes: &[u8]) {
        let text = disassemble(bytes).unwrap_or_else(|e| panic!("disassembly failed: {e}"));
        let reassembled = assemble(&text).unwrap_or_else(|e| panic!("reassembly of\n{text}\nfailed: {e}"));
        assert_eq!(reassembled, bytes, "round trip differs for {}\n{text}", hexdump(bytes));
    }

    #[test]
    fn canonical_form_of_the_derived_parameter_example() {
        let text = disassemble(&[0x70, 0x01, 0x00, 0x10, 0x02, 0x43, 0x01]).unwrap();
        assert_eq!(text, "GETPARAM 1, 0\nPUSH_U8 2\nDIV\nRET\n");
    }

    #[test]
    fn canonical_form_uses_explicit_push_widths_and_decimal_immediates() {
        let text = disassemble(&[0x11, 0xE8, 0x03, 0x01]).unwrap();
        assert_eq!(text, "PUSH_U16 1000\nRET\n");
    }

    #[test]
    fn labels_are_numbered_by_ascending_target_offset() {
        // Two backward jumps, the later one reaching the earlier target, so the
        // numbering cannot come from the order the jumps appear in.
        let source = "\
first:  RET
second: RET
        JMP second
        JMP first
";
        let bytes = assemble(source).unwrap();
        let text = disassemble(&bytes).unwrap();
        assert_eq!(text, "L0:\nRET\nL1:\nRET\nJMP L1\nJMP L0\n");
    }

    #[test]
    fn a_destination_inside_an_instruction_is_rendered_as_a_displacement() {
        // Offset 3 is PUSH_U16; the jump lands on its first immediate byte, so
        // there is no line to label and the displacement is emitted instead.
        let bytes = [0x02, 0x01, 0x00, 0x11, 0x10, 0x05, 0x01];
        let text = disassemble(&bytes).unwrap();
        assert_eq!(text, "JMP 1\nPUSH_U16 1296\nRET\n");
        round_trips(&bytes);
    }

    #[test]
    fn the_specification_examples_round_trip() {
        round_trips(&[0x70, 0x01, 0x00, 0x10, 0x02, 0x43, 0x01]);
        round_trips(&[
            0x32, 0x00, 0x10, 0x05, 0x42, 0x11, 0xE8, 0x03, 0x40, 0x11, 0x50, 0xC3, 0x45, 0x01,
        ]);
        round_trips(&[
            0x11, 0xE8, 0x03, 0x32, 0x00, 0x10, 0x64, 0x43, 0x21, 0x03, 0x0D, 0x00, 0x10, 0x01, 0x41, 0x22, 0x21, 0x10, 0x0A, 0x43,
            0x40, 0x22, 0x02, 0xEF, 0xFF, 0x20, 0x01,
        ]);
    }

    #[test]
    fn every_opcode_round_trips() {
        // A corpus covering each instruction at least once. Jumps get a trailing
        // RET so their destination stays inside the program.
        for info in INSTRUCTIONS {
            let mut bytes = vec![info.opcode];
            match info.imm {
                Imm::None => {}
                Imm::Rel16 => bytes.extend_from_slice(&0i16.to_le_bytes()),
                width => bytes.extend(std::iter::repeat_n(0x7Au8, width.size())),
            }
            if info.imm == Imm::Rel16 {
                bytes.push(opcode::RET);
            }
            round_trips(&bytes);
        }
    }

    #[test]
    fn immediates_round_trip_at_their_boundaries() {
        for (op, width) in [
            (opcode::PUSH_U8, 1usize),
            (opcode::PUSH_U16, 2),
            (opcode::PUSH_U32, 4),
            (opcode::PUSH_U64, 8),
        ] {
            for fill in [0x00u8, 0x01, 0xFF] {
                let mut bytes = vec![op];
                bytes.extend(std::iter::repeat_n(fill, width));
                bytes.push(opcode::RET);
                round_trips(&bytes);
            }
        }
    }

    #[test]
    fn displacements_round_trip_in_both_directions() {
        // Forward, zero, and backward, each landing on an instruction boundary.
        round_trips(&assemble("JMP 0\nRET\n").unwrap());
        round_trips(&assemble("a:\nRET\nJMP a\n").unwrap());
        round_trips(&assemble("JMPZ 1\nRET\nRET\n").unwrap());
        round_trips(&assemble("JMPNZ 1\nRET\nRET\n").unwrap());
    }

    #[test]
    fn an_unallocated_opcode_is_refused() {
        let error = disassemble(&[0x00]).unwrap_err();
        assert_eq!(error.offset, 0);
        assert!(error.message.contains("0x00"), "{}", error.message);

        let later = disassemble(&[opcode::RET, 0xC0]).unwrap_err();
        assert_eq!(later.offset, 1);
    }

    #[test]
    fn a_truncated_immediate_is_refused() {
        let error = disassemble(&[opcode::PUSH_U16, 0x01]).unwrap_err();
        assert_eq!(error.offset, 0);
        assert!(error.message.contains("immediate"), "{}", error.message);
    }

    #[test]
    fn hex_helpers_round_trip() {
        let bytes = [0x70u8, 0x01, 0x10, 0x02, 0x43, 0x01];
        assert_eq!(hexdump(&bytes), "70 01 10 02 43 01");
        assert_eq!(parse_hex("70 01 10 02 43 01").unwrap(), bytes);
        assert_eq!(parse_hex("700110024301").unwrap(), bytes);
        assert!(parse_hex("70 0").is_err());
        assert!(parse_hex("ZZ").is_err());
    }

    #[test]
    fn mnemonic_lookup_matches_the_instruction_table() {
        assert_eq!(mnemonic(opcode::DIV), Some("DIV"));
        assert_eq!(mnemonic(0x00), None);
    }
}
