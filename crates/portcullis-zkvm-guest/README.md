# portcullis-zkvm-guest

RISC-V zkVM guest program for proof-carrying WASM parser execution.

This binary is compiled to a RISC-V ELF by `risc0-build` and embedded in
[`portcullis-core`](../portcullis-core) (behind the `zkvm` feature). The host
invokes the prover with this ELF and receives a `risc0_zkvm::Receipt` proving:

> "Parser with hash H, when executed on input I, produced output O."

## Journal layout

The guest commits exactly **96 bytes** to the proof journal:

| Bytes | Field | Meaning |
|---|---|---|
| `0..32` | `parser_hash` | SHA-256 of the WASM parser binary |
| `32..64` | `input_hash` | SHA-256 of the raw input bytes |
| `64..96` | `output_hash` | SHA-256 of the parser's output bytes |

A verifier that trusts the receipt therefore learns the parser/input/output
binding without re-executing the parser.

## Host usage

```rust,ignore
use risc0_zkvm::{default_prover, ExecutorEnv};

let env = ExecutorEnv::builder()
    .write(&parser_wasm)?
    .write(&input_bytes)?
    .build()?;
let receipt = default_prover().prove(env, PORTCULLIS_PARSER_EXEC_ELF)?;
let journal: [u8; 96] = receipt.journal.decode()?;
// journal[0..32] = parser_hash, [32..64] = input_hash, [64..96] = output_hash
```

## Building & testing

This crate declares its **own `[workspace]`** so it can be compiled
independently with the RISC-V target — it is intentionally **not** a member of
the main nucleus workspace.

- The `wasmi`-based execution logic lives in the **library** and is host-testable:

  ```bash
  cargo test --lib   # from this crate's directory
  ```

- The **binary** target links only for the zkVM target (it uses the risc0
  `guest::entry!` macro); building the bin on the host is expected to fail at
  link time. It is produced via `risc0-build` during a `zkvm`-feature build of
  `portcullis-core`.

## License

MIT
