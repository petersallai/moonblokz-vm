//! `vm-dis` — disassembles MoonBlokz configuration bytecode.
//!
//! ```text
//! vm-dis [INPUT.bin]
//! vm-dis --hex "70 01 10 02 43 01"
//! ```
//!
//! Reads raw bytes from `INPUT.bin`, or from standard input when no path is
//! given. `--hex` takes the program as a hexadecimal string instead, which is
//! how a chain's configuration usually arrives when it is known only as bytes.

use std::io::Read;
use std::process::ExitCode;

use moonblokz_vm_dis::{disassemble, parse_hex};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("vm-dis: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut input: Option<String> = None;
    let mut hex: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--hex" => hex = Some(args.next().ok_or("--hex needs a program")?),
            "-h" | "--help" => {
                println!("usage: vm-dis [INPUT.bin]\n       vm-dis --hex \"70 01 10 02 43 01\"");
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

    let bytes = match (hex, &input) {
        (Some(text), _) => parse_hex(&text)?,
        (None, Some(path)) => std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?,
        (None, None) => {
            let mut buffer = Vec::new();
            std::io::stdin().read_to_end(&mut buffer).map_err(|e| format!("cannot read standard input: {e}"))?;
            buffer
        }
    };

    print!("{}", disassemble(&bytes).map_err(|e| e.to_string())?);
    Ok(())
}
