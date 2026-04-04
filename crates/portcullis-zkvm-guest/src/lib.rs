//! WASM parser execution logic for the zkVM guest program (#1116).
//!
//! This module is the core of the guest program — it executes a WASM parser
//! on input bytes and returns the output, following the same ABI contract as
//! the wasmtime-based [`portcullis_core::wasm_sandbox`]:
//!
//! - **`alloc(len: i32) -> i32`** — allocate `len` bytes in guest memory.
//! - **`parse(ptr: i32, len: i32) -> i64`** — parse input; return packed `(out_ptr << 32) | out_len`.
//! - **`memory`** — exported linear memory.
//!
//! Unlike the wasmtime sandbox (which runs in the host process), this code
//! runs inside the RISC Zero zkVM guest. The zkVM proves its execution,
//! producing a receipt that can be verified by any third party.
//!
//! ## Portability
//!
//! The lib is compiled twice:
//! 1. For the host (x86_64/aarch64): run via `cargo test`.
//! 2. For the RISC-V guest: compiled by `risc0-build` and embedded as an ELF.
//!
//! Using `wasmi` (not `wasmtime`) because wasmi is portable across targets
//! and has no JIT/signal-handler dependencies that would fail in the zkVM.

use sha2::{Digest, Sha256};
use wasmi::{Engine, Error as WasmiError, Linker, Module, Store};
use wasmi::errors::MemoryError;

/// Error from WASM parser execution inside the guest.
#[derive(Debug)]
pub enum GuestError {
    /// Failed to parse or validate the WASM module.
    WasmParse(String),
    /// Failed to instantiate the module (missing exports, link error).
    Instantiate(String),
    /// Runtime trap during execution.
    Trap(String),
    /// Guest memory read/write failed.
    Memory(String),
    /// Parser returned an output size that overflows.
    OutputOverflow,
}

impl core::fmt::Display for GuestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WasmParse(s) => write!(f, "WASM parse error: {s}"),
            Self::Instantiate(s) => write!(f, "instantiation error: {s}"),
            Self::Trap(s) => write!(f, "runtime trap: {s}"),
            Self::Memory(s) => write!(f, "memory error: {s}"),
            Self::OutputOverflow => write!(f, "output size overflows address space"),
        }
    }
}

impl std::error::Error for GuestError {}

/// Execute a WASM parser on `input` bytes and return the output bytes.
///
/// The WASM module must export:
/// - `alloc(len: i32) -> i32` — allocate guest memory
/// - `parse(ptr: i32, len: i32) -> i64` — run the parser
/// - `memory` — the linear memory
///
/// This function is deterministic: for fixed `wasm_bytes` and `input`, the
/// output is always the same. The zkVM receipt proves this determinism
/// cryptographically.
pub fn execute_wasm_parser(wasm_bytes: &[u8], input: &[u8]) -> Result<Vec<u8>, GuestError> {
    let engine = Engine::default();
    let module =
        Module::new(&engine, wasm_bytes).map_err(|e| GuestError::WasmParse(e.to_string()))?;

    let mut store = Store::new(&engine, ());
    let linker: Linker<()> = Linker::new(&engine);

    // Instantiate and run start function (wasmi 1.0 combined API).
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|e: WasmiError| GuestError::Instantiate(e.to_string()))?;

    // Resolve the required exports.
    let alloc_fn = instance
        .get_typed_func::<i32, i32>(&store, "alloc")
        .map_err(|e: WasmiError| GuestError::Instantiate(format!("missing `alloc` export: {e}")))?;

    let parse_fn = instance
        .get_typed_func::<(i32, i32), i64>(&store, "parse")
        .map_err(|e: WasmiError| GuestError::Instantiate(format!("missing `parse` export: {e}")))?;

    let memory = instance
        .get_memory(&store, "memory")
        .ok_or_else(|| GuestError::Instantiate("missing `memory` export".into()))?;

    // Allocate input buffer in guest memory.
    let input_len = input.len() as i32;
    let input_ptr = alloc_fn
        .call(&mut store, input_len)
        .map_err(|e: WasmiError| GuestError::Trap(e.to_string()))?;

    // Copy input into guest memory.
    memory
        .write(&mut store, input_ptr as usize, input)
        .map_err(|e: MemoryError| GuestError::Memory(e.to_string()))?;

    // Invoke the parser — returns packed `(out_ptr << 32) | out_len`.
    let packed = parse_fn
        .call(&mut store, (input_ptr, input_len))
        .map_err(|e: WasmiError| GuestError::Trap(e.to_string()))?;

    let out_ptr = ((packed >> 32) & 0xFFFF_FFFF) as usize;
    let out_len = (packed & 0xFFFF_FFFF) as usize;

    // Read the output from guest memory.
    let mut output = vec![0u8; out_len];
    memory
        .read(&store, out_ptr, &mut output)
        .map_err(|e: MemoryError| GuestError::Memory(e.to_string()))?;

    Ok(output)
}

// ── Hash utilities ─────────────────────────────────────────────────────────

/// Compute the SHA-256 hash of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// The journal payload committed by the guest to prove parser execution.
///
/// All three hashes are SHA-256 digests. Verifiers check that:
/// 1. `parser_hash` matches the registered parser's `build_hash`.
/// 2. `input_hash` matches the input they supplied to the prover.
/// 3. `output_hash` matches the output they received from the prover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserJournal {
    /// SHA-256 of the WASM parser binary.
    pub parser_hash: [u8; 32],
    /// SHA-256 of the raw input bytes.
    pub input_hash: [u8; 32],
    /// SHA-256 of the raw output bytes.
    pub output_hash: [u8; 32],
}

/// Run the full guest computation: execute parser, hash inputs/outputs.
///
/// This is called from `main.rs` with I/O sourced from the zkVM journal.
/// It is also directly called in host-side tests.
pub fn run_guest(wasm_bytes: &[u8], input: &[u8]) -> Result<(Vec<u8>, ParserJournal), GuestError> {
    let output = execute_wasm_parser(wasm_bytes, input)?;
    let journal = ParserJournal {
        parser_hash: sha256(wasm_bytes),
        input_hash: sha256(input),
        output_hash: sha256(&output),
    };
    Ok((output, journal))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Identity parser WAT: copies input to output unchanged.
    fn identity_wat() -> &'static str {
        r#"
        (module
            (memory (export "memory") 1)
            (global $bump (mut i32) (i32.const 1024))
            (func (export "alloc") (param $len i32) (result i32)
                (local $ptr i32)
                (local.set $ptr (global.get $bump))
                (global.set $bump (i32.add (global.get $bump) (local.get $len)))
                (local.get $ptr))
            (func (export "parse") (param $ptr i32) (param $len i32) (result i64)
                (local $out i32)
                (local.set $out (global.get $bump))
                (global.set $bump (i32.add (global.get $bump) (local.get $len)))
                (memory.copy (local.get $out) (local.get $ptr) (local.get $len))
                (i64.or
                    (i64.shl (i64.extend_i32_u (local.get $out)) (i64.const 32))
                    (i64.extend_i32_u (local.get $len))))
        )
        "#
    }

    #[test]
    fn identity_parser_returns_input_unchanged() {
        let wasm = wat::parse_str(identity_wat()).unwrap();
        let input = b"hello zkVM world";
        let output = execute_wasm_parser(&wasm, input).unwrap();
        assert_eq!(output, input);
    }

    #[test]
    fn identity_parser_empty_input() {
        let wasm = wat::parse_str(identity_wat()).unwrap();
        let output = execute_wasm_parser(&wasm, b"").unwrap();
        assert_eq!(output, b"");
    }

    #[test]
    fn identity_parser_large_input() {
        let wasm = wat::parse_str(identity_wat()).unwrap();
        let input: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let output = execute_wasm_parser(&wasm, &input).unwrap();
        assert_eq!(output, input.as_slice());
    }

    #[test]
    fn run_guest_produces_correct_hashes() {
        let wasm = wat::parse_str(identity_wat()).unwrap();
        let input = b"parser execution proof";

        let (output, journal) = run_guest(&wasm, input).unwrap();

        // Identity parser: output == input
        assert_eq!(output.as_slice(), input);
        // Hashes are consistent
        assert_eq!(journal.parser_hash, sha256(&wasm));
        assert_eq!(journal.input_hash, sha256(input));
        assert_eq!(journal.output_hash, sha256(&output));
        // Since identity: input_hash == output_hash
        assert_eq!(journal.input_hash, journal.output_hash);
    }

    #[test]
    fn run_guest_deterministic() {
        let wasm = wat::parse_str(identity_wat()).unwrap();
        let input = b"determinism test";

        let (_, j1) = run_guest(&wasm, input).unwrap();
        let (_, j2) = run_guest(&wasm, input).unwrap();

        assert_eq!(j1, j2, "same input must produce same journal");
    }

    #[test]
    fn run_guest_different_inputs_produce_different_hashes() {
        let wasm = wat::parse_str(identity_wat()).unwrap();
        let (_, j1) = run_guest(&wasm, b"input A").unwrap();
        let (_, j2) = run_guest(&wasm, b"input B").unwrap();
        assert_ne!(j1.input_hash, j2.input_hash);
        assert_ne!(j1.output_hash, j2.output_hash);
    }

    #[test]
    fn error_on_invalid_wasm() {
        let result = execute_wasm_parser(b"not valid wasm", b"input");
        assert!(result.is_err(), "invalid WASM must return an error");
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("WASM parse error"));
    }

    #[test]
    fn sha256_known_value() {
        // SHA-256 of the empty string is well-known
        let hash = sha256(b"");
        let expected = hex::decode(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
        assert_eq!(&hash, expected.as_slice());
    }
}
