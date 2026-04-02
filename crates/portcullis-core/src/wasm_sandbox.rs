//! Wasmtime-based parser sandbox runtime.
//!
//! Executes deterministic parser plugins in complete isolation: no WASI
//! capabilities (filesystem, network, clocks, random), deterministic
//! instruction metering via fuel, and canonical NaN / SIMD behaviour.
//!
//! ## Plugin ABI
//!
//! A parser WASM module must export:
//!
//! - `alloc(len: i32) -> i32` -- allocate `len` bytes in guest memory,
//!   returning a pointer to the start of the allocation.
//! - `parse(ptr: i32, len: i32) -> i64` -- parse the input bytes at
//!   `[ptr..ptr+len]` and return a packed `i64` where the high 32 bits
//!   are the output pointer and the low 32 bits are the output length.
//!
//! If the module exports `parse` returning `i32` instead, it must also
//! export `output_len() -> i32` so the host can determine the output size.
//!
//! Because we grant zero WASI capabilities the module cannot perform I/O,
//! read the clock, or access randomness -- any attempt traps immediately.
//!
//! ## Content addressing
//!
//! Every compiled module carries the SHA-256 digest of its original WASM
//! bytes, tying it to [`crate::parser_registry::ParserDeclaration::build_hash`].

use sha2::{Digest, Sha256};
use std::fmt;
use wasmtime::{Config, Engine, Instance, Linker, Memory, Module, Store};

// ═══════════════════════════════════════════════════════════════════════════
// Error types
// ═══════════════════════════════════════════════════════════════════════════

/// Errors produced by the WASM parser sandbox.
#[derive(Debug)]
pub enum SandboxError {
    /// The WASM module failed to compile.
    CompileError(String),
    /// Execution trapped or returned an error.
    ExecutionError(String),
    /// The fuel budget was exhausted before execution completed.
    FuelExhausted,
    /// The module does not export a `parse` function.
    NoParseExport,
    /// The module does not export an `alloc` function.
    NoAllocExport,
    /// Reading or writing guest memory failed.
    MemoryError(String),
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompileError(msg) => write!(f, "wasm compile error: {msg}"),
            Self::ExecutionError(msg) => write!(f, "wasm execution error: {msg}"),
            Self::FuelExhausted => write!(f, "wasm fuel exhausted"),
            Self::NoParseExport => write!(f, "wasm module missing `parse` export"),
            Self::NoAllocExport => write!(f, "wasm module missing `alloc` export"),
            Self::MemoryError(msg) => write!(f, "wasm memory error: {msg}"),
        }
    }
}

impl std::error::Error for SandboxError {}

// ═══════════════════════════════════════════════════════════════════════════
// ParserSandbox
// ═══════════════════════════════════════════════════════════════════════════

/// A Wasmtime engine configured for deterministic, zero-capability execution.
///
/// Create one per process and reuse it to compile and execute many modules.
pub struct ParserSandbox {
    engine: Engine,
}

impl ParserSandbox {
    /// Create a new sandbox with determinism knobs enabled.
    ///
    /// The engine is configured with:
    /// - `consume_fuel(true)` -- deterministic instruction metering
    /// - `cranelift_nan_canonicalization(true)` -- canonical NaN values
    /// - `relaxed_simd_deterministic(true)` -- deterministic SIMD lowering
    /// - No WASI -- zero host capabilities
    pub fn new() -> Self {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.cranelift_nan_canonicalization(true);
        config.relaxed_simd_deterministic(true);

        let engine = Engine::new(&config).expect("failed to create wasmtime engine");
        Self { engine }
    }

    /// Compile a WASM module from raw bytes and compute its content hash.
    ///
    /// The returned [`CompiledParser`] carries the SHA-256 digest of
    /// `wasm_bytes`, which should match the `build_hash` in the
    /// corresponding [`crate::parser_registry::ParserDeclaration`].
    pub fn compile(&self, wasm_bytes: &[u8]) -> Result<CompiledParser, SandboxError> {
        let content_hash = {
            let mut hasher = Sha256::new();
            hasher.update(wasm_bytes);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        };

        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| SandboxError::CompileError(e.to_string()))?;

        Ok(CompiledParser {
            module,
            content_hash,
        })
    }

    /// Execute a compiled parser module on the given input bytes.
    ///
    /// The execution is bounded by `fuel_limit` fuel units.  Most WASM
    /// instructions consume 1 unit of fuel; if the budget is exhausted
    /// before `parse` returns, [`SandboxError::FuelExhausted`] is returned.
    ///
    /// Returns the raw output bytes produced by the parser.
    pub fn execute(
        &self,
        parser: &CompiledParser,
        input: &[u8],
        fuel_limit: u64,
    ) -> Result<Vec<u8>, SandboxError> {
        // Each invocation gets a fresh Store -- full per-call isolation.
        let mut store = Store::new(&self.engine, ());
        store
            .set_fuel(fuel_limit)
            .map_err(|e| SandboxError::ExecutionError(e.to_string()))?;

        // No WASI, no host functions -- empty linker.
        let linker = Linker::new(&self.engine);
        let instance = linker
            .instantiate(&mut store, &parser.module)
            .map_err(|e| SandboxError::ExecutionError(e.to_string()))?;

        // Resolve exports.
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| SandboxError::MemoryError("no `memory` export".into()))?;

        let alloc_fn = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|_| SandboxError::NoAllocExport)?;

        // Try i64 return first (packed ptr|len), fall back to i32.
        let parse_result = self.call_parse(&mut store, &instance, &memory, &alloc_fn, input)?;

        Ok(parse_result)
    }

    /// Write input into guest memory via `alloc`, call `parse`, read output.
    fn call_parse(
        &self,
        store: &mut Store<()>,
        instance: &Instance,
        memory: &Memory,
        alloc_fn: &wasmtime::TypedFunc<i32, i32>,
        input: &[u8],
    ) -> Result<Vec<u8>, SandboxError> {
        let input_len = input.len() as i32;

        // Allocate space in guest memory for the input.
        let input_ptr = alloc_fn
            .call(&mut *store, input_len)
            .map_err(classify_trap)?;

        // Write input bytes into guest memory.
        memory
            .write(&mut *store, input_ptr as usize, input)
            .map_err(|e| SandboxError::MemoryError(e.to_string()))?;

        // Call parse -- try i64 signature first, then i32.
        let (out_ptr, out_len) = if let Ok(parse_i64) =
            instance.get_typed_func::<(i32, i32), i64>(&mut *store, "parse")
        {
            let packed = parse_i64
                .call(&mut *store, (input_ptr, input_len))
                .map_err(classify_trap)?;
            let ptr = (packed >> 32) as i32;
            let len = (packed & 0xFFFF_FFFF) as i32;
            (ptr, len)
        } else if let Ok(parse_i32) =
            instance.get_typed_func::<(i32, i32), i32>(&mut *store, "parse")
        {
            let result = parse_i32
                .call(&mut *store, (input_ptr, input_len))
                .map_err(classify_trap)?;
            // Convention: result is a packed i32 with ptr in upper 16 bits
            // and len in lower 16 bits.  But for simplicity and to support
            // larger outputs we treat the i32 return as an output pointer
            // and require a separate `output_len` export.
            let out_len_fn = instance
                .get_typed_func::<(), i32>(&mut *store, "output_len")
                .map_err(|_| {
                    SandboxError::ExecutionError(
                        "parse returns i32 but module has no `output_len` export".into(),
                    )
                })?;
            let len = out_len_fn.call(&mut *store, ()).map_err(classify_trap)?;
            (result, len)
        } else {
            return Err(SandboxError::NoParseExport);
        };

        if out_len < 0 {
            return Err(SandboxError::ExecutionError(format!(
                "parse returned negative length: {out_len}"
            )));
        }

        // Read output from guest memory.
        let mut output = vec![0u8; out_len as usize];
        memory
            .read(&*store, out_ptr as usize, &mut output)
            .map_err(|e| SandboxError::MemoryError(e.to_string()))?;

        Ok(output)
    }
}

impl Default for ParserSandbox {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CompiledParser
// ═══════════════════════════════════════════════════════════════════════════

/// A compiled WASM parser module with its content-address hash.
pub struct CompiledParser {
    module: Module,
    content_hash: [u8; 32],
}

impl fmt::Debug for CompiledParser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledParser")
            .field("content_hash", &self.content_hash)
            .finish_non_exhaustive()
    }
}

impl CompiledParser {
    /// The SHA-256 digest of the original WASM bytes.
    pub fn content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Classify a wasmtime trap/error into the appropriate `SandboxError`.
fn classify_trap(err: wasmtime::Error) -> SandboxError {
    if let Some(trap) = err.downcast_ref::<wasmtime::Trap>()
        && matches!(trap, wasmtime::Trap::OutOfFuel)
    {
        return SandboxError::FuelExhausted;
    }
    SandboxError::ExecutionError(err.to_string())
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a trivial WAT module that implements the parser ABI.
    ///
    /// This module has 1 page of linear memory.  `alloc` bumps a global
    /// pointer.  `parse` copies input bytes to a new location and returns
    /// the (ptr, len) packed as i64.
    fn identity_parser_wat() -> &'static str {
        r#"
        (module
            (memory (export "memory") 1)

            ;; bump allocator pointer (starts at offset 1024)
            (global $bump (mut i32) (i32.const 1024))

            (func (export "alloc") (param $len i32) (result i32)
                (local $ptr i32)
                (local.set $ptr (global.get $bump))
                (global.set $bump
                    (i32.add (global.get $bump) (local.get $len)))
                (local.get $ptr)
            )

            ;; parse: copy input to a new allocation, return packed i64
            (func (export "parse") (param $ptr i32) (param $len i32) (result i64)
                (local $out_ptr i32)

                ;; allocate output
                (local.set $out_ptr (global.get $bump))
                (global.set $bump
                    (i32.add (global.get $bump) (local.get $len)))

                ;; memory.copy src=input_ptr dst=out_ptr len=len
                (memory.copy
                    (local.get $out_ptr)
                    (local.get $ptr)
                    (local.get $len))

                ;; return packed: (out_ptr << 32) | len
                (i64.or
                    (i64.shl
                        (i64.extend_i32_u (local.get $out_ptr))
                        (i64.const 32))
                    (i64.extend_i32_u (local.get $len)))
            )
        )
        "#
    }

    /// A module whose `parse` loops forever, exhausting fuel.
    fn infinite_loop_wat() -> &'static str {
        r#"
        (module
            (memory (export "memory") 1)
            (global $bump (mut i32) (i32.const 1024))

            (func (export "alloc") (param $len i32) (result i32)
                (local $ptr i32)
                (local.set $ptr (global.get $bump))
                (global.set $bump
                    (i32.add (global.get $bump) (local.get $len)))
                (local.get $ptr)
            )

            (func (export "parse") (param $ptr i32) (param $len i32) (result i64)
                (loop $inf
                    (br $inf))
                (unreachable)
            )
        )
        "#
    }

    #[test]
    fn compile_and_execute_identity_parser() {
        let wasm = wat::parse_str(identity_parser_wat()).expect("WAT parse failed");
        let sandbox = ParserSandbox::new();
        let compiled = sandbox.compile(&wasm).unwrap();

        let input = b"hello, portcullis!";
        let output = sandbox.execute(&compiled, input, 100_000).unwrap();
        assert_eq!(output, input);
    }

    #[test]
    fn content_hash_is_sha256_of_bytes() {
        let wasm = wat::parse_str(identity_parser_wat()).expect("WAT parse failed");
        let sandbox = ParserSandbox::new();
        let compiled = sandbox.compile(&wasm).unwrap();

        let expected = {
            let mut hasher = Sha256::new();
            hasher.update(&wasm);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        };

        assert_eq!(compiled.content_hash(), &expected);
    }

    #[test]
    fn determinism_same_input_same_output() {
        let wasm = wat::parse_str(identity_parser_wat()).expect("WAT parse failed");
        let sandbox = ParserSandbox::new();
        let compiled = sandbox.compile(&wasm).unwrap();

        let input = b"determinism test";
        let out1 = sandbox.execute(&compiled, input, 100_000).unwrap();
        let out2 = sandbox.execute(&compiled, input, 100_000).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn fuel_exhaustion_returns_error() {
        let wasm = wat::parse_str(infinite_loop_wat()).expect("WAT parse failed");
        let sandbox = ParserSandbox::new();
        let compiled = sandbox.compile(&wasm).unwrap();

        let result = sandbox.execute(&compiled, b"test", 1_000);
        assert!(result.is_err());
        match result.unwrap_err() {
            SandboxError::FuelExhausted => {} // expected
            other => panic!("expected FuelExhausted, got: {other}"),
        }
    }

    #[test]
    fn invalid_wasm_returns_compile_error() {
        let sandbox = ParserSandbox::new();
        let result = sandbox.compile(b"not valid wasm");
        assert!(result.is_err());
        match result.unwrap_err() {
            SandboxError::CompileError(_) => {} // expected
            other => panic!("expected CompileError, got: {other}"),
        }
    }

    #[test]
    fn module_without_parse_export_returns_error() {
        let wat = r#"
        (module
            (memory (export "memory") 1)
            (global $bump (mut i32) (i32.const 1024))
            (func (export "alloc") (param $len i32) (result i32)
                (local $ptr i32)
                (local.set $ptr (global.get $bump))
                (global.set $bump
                    (i32.add (global.get $bump) (local.get $len)))
                (local.get $ptr)
            )
        )
        "#;
        let wasm = wat::parse_str(wat).expect("WAT parse failed");
        let sandbox = ParserSandbox::new();
        let compiled = sandbox.compile(&wasm).unwrap();

        let result = sandbox.execute(&compiled, b"test", 100_000);
        assert!(result.is_err());
        match result.unwrap_err() {
            SandboxError::NoParseExport => {} // expected
            other => panic!("expected NoParseExport, got: {other}"),
        }
    }

    #[test]
    fn empty_input_works() {
        let wasm = wat::parse_str(identity_parser_wat()).expect("WAT parse failed");
        let sandbox = ParserSandbox::new();
        let compiled = sandbox.compile(&wasm).unwrap();

        let output = sandbox.execute(&compiled, b"", 100_000).unwrap();
        assert!(output.is_empty());
    }
}
