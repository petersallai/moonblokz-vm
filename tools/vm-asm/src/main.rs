//! `vm-asm` — assembles MoonBlokz configuration bytecode.
//!
//! ```text
//! vm-asm [INPUT.asm] [-o OUTPUT.bin]
//! ```
//!
//! Reads assembly source from `INPUT.asm`, or from standard input when no path
//! is given. Writes raw bytes to `OUTPUT.bin` when `-o` is given, and otherwise
//! prints a hexdump on standard output, which is the form a program appears in
//! when it is reviewed, quoted in a bug report, or pasted into a test fixture.

use std::io::{Read, Write};
use std::process::ExitCode;

use moonblokz_vm_asm::assemble;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("vm-asm: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-o" | "--output" => {
                output = Some(args.next().ok_or("-o needs a path")?);
            }
            "-h" | "--help" => {
                println!("usage: vm-asm [INPUT.asm] [-o OUTPUT.bin]");
                return Ok(());
            }
            other if other.starts_with('-') => return Err(format!("unknown option `{other}`")),
            path => {
                if input.replace(path.to_string()).is_some() {
                    return Err("only one input path is accepted".to_string());
                }
            }
        }
    }

    let source = match &input {
        Some(path) => std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?,
        None => {
            let mut buffer = String::new();
            std::io::stdin().read_to_string(&mut buffer).map_err(|e| format!("cannot read standard input: {e}"))?;
            buffer
        }
    };

    let bytes = assemble(&source).map_err(|e| match &input {
        Some(path) => format!("{path}:{e}"),
        None => e.to_string(),
    })?;

    match output {
        Some(path) => std::fs::write(&path, &bytes).map_err(|e| format!("cannot write {path}: {e}"))?,
        None => {
            let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
            let mut stdout = std::io::stdout();
            writeln!(stdout, "{}", hex.join(" ")).map_err(|e| e.to_string())?;
        }
    }

    eprintln!("vm-asm: {} bytes", bytes.len());
    Ok(())
}
