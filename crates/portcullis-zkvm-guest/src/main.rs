//! RISC-V zkVM guest entrypoint — `nucleus-audit verify-provenance` (#1116).
//!
//! This binary is compiled to a RISC-V ELF by `risc0-build` and embedded
//! in `portcullis-core` (behind the `zkvm` feature flag). The host invokes
//! the prover with this ELF and receives a `risc0_zkvm::Receipt` that proves:
//!
//! > "Parser with hash H, when executed on input I, produced output O."
//!
//! ## Journal layout (committed to the proof)
//!
//! The guest commits exactly 96 bytes to the journal in this order:
//! ```text
//! [0..32]  parser_hash  — SHA-256 of the WASM parser binary
//! [32..64] input_hash   — SHA-256 of the raw input bytes
//! [64..96] output_hash  — SHA-256 of the parser's output bytes
//! ```
//!
//! ## Host usage
//!
//! ```rust,ignore
//! use risc0_zkvm::{default_prover, ExecutorEnv};
//!
//! let env = ExecutorEnv::builder()
//!     .write(&parser_wasm)?
//!     .write(&input_bytes)?
//!     .build()?;
//! let receipt = default_prover().prove(env, PORTCULLIS_PARSER_EXEC_ELF)?;
//! let journal: [u8; 96] = receipt.journal.decode()?;
//! // journal[0..32]  = parser_hash
//! // journal[32..64] = input_hash
//! // journal[64..96] = output_hash
//! ```

// When compiling for the RISC-V zkVM target, disable the default entrypoint.
#![cfg_attr(target_arch = "riscv32", no_main)]

// Suppress dead_code in the binary target when not on RISC-V.
#![allow(dead_code)]

use portcullis_zkvm_guest::run_guest;

// Register the guest entrypoint with the risc0 runtime.
// On non-RISC-V targets (host tests), this expands to nothing.
risc0_zkvm::guest::entry!(main);

pub fn main() {
    // Read the WASM parser binary from the host.
    let parser_wasm: Vec<u8> = risc0_zkvm::guest::env::read();

    // Read the input bytes from the host.
    let input: Vec<u8> = risc0_zkvm::guest::env::read();

    // Execute the parser and compute hashes.
    let (_, journal) = run_guest(&parser_wasm, &input)
        .expect("parser execution failed");

    // Commit the 96-byte journal to the proof.
    // Verifiers check these hashes against the expected values.
    risc0_zkvm::guest::env::commit_slice(&journal.parser_hash);
    risc0_zkvm::guest::env::commit_slice(&journal.input_hash);
    risc0_zkvm::guest::env::commit_slice(&journal.output_hash);
}
