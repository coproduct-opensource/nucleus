//! Refuse to compile unless the embedded wasm artifacts match their pins.
//!
//! `src/routes.rs` embeds `sdks/verifier-js/pkg/*` with `include_bytes!` and
//! `include_str!`. That directory is gitignored — it is a wasm-pack build
//! product — so those bytes are invisible to git, and therefore to any read-set
//! built from tracked files. `nucleus-action-key`'s closure refuses to key this
//! crate for that reason: the artifact could change with nothing in the tree
//! noticing, and this crate is the relying-party verifier.
//!
//! `embedded-wasm.pins` records their digests. This checks them. A tracked
//! digest that nothing verifies is a lie that reads like a promise, so the pin
//! and this file only make sense together.
//!
//! This adds no failure mode that did not already exist **when the artifacts are
//! actually embedded**: `include_bytes!` of a missing file is already a compile
//! error. That qualifier was missing, and the check was unconditional, so it did
//! add one — see below.
//!
//! # Why this is gated on `embedded-wasm`
//!
//! The embed is behind the `embedded-wasm` feature, which is OFF by default.
//! #2730 made it optional for a specific reason, recorded in `Cargo.toml`: an
//! unconditional embed "made a clean checkout fail to compile this crate — and
//! one crate failing takes every other crate's test targets down with it".
//!
//! This build script then re-introduced exactly that failure. With the default
//! feature set the `include_bytes!` in `routes.rs` is `#[cfg]`'d out and nothing
//! reads the artifacts, but the script demanded them anyway, so a clean checkout
//! could not build this crate — the script was the sole cause, which is why the
//! header's reasoning from `include_bytes!` did not catch it. Measured
//! 2026-09-15 on a tree with no `sdks/verifier-js/pkg/`: `cargo build -p
//! nucleus-verifier-service` panicked in this script; gated, the crate builds
//! and its 97 tests pass.
//!
//! Pins guard what is embedded. With nothing embedded there is nothing to
//! guard, and a gate that fires where its subject is absent is not a stricter
//! gate — it is a broken one.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn main() {
    let crate_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let repo_root = crate_dir
        .parent()
        .and_then(Path::parent)
        .expect("crates/<name> sits two levels below the repository root")
        .to_path_buf();

    // Nothing is embedded without the feature, so there is nothing to pin-check.
    // Cargo sets CARGO_FEATURE_<NAME> (uppercased, `-` → `_`) for each enabled
    // feature; its absence is the feature being off.
    if std::env::var_os("CARGO_FEATURE_EMBEDDED_WASM").is_none() {
        return;
    }

    let pins_path = crate_dir.join("embedded-wasm.pins");
    println!("cargo:rerun-if-changed={}", pins_path.display());
    let pins = std::fs::read_to_string(&pins_path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", pins_path.display()));

    let mut checked = 0usize;
    // path -> every digest accepted for it. wasm-pack output is not
    // reproducible across platforms (measured: macOS aarch64 and Linux x86_64
    // differ for one source and one wasm-pack), so a single-digest pin would
    // break whichever platform did not mint it. Listing the artifacts actually
    // accepted keeps the gate meaningful -- an unknown blob still fails -- while
    // admitting that "the" artifact is a set of one per builder.
    let mut accepted: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for (number, line) in pins.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (expected, relative) = line.split_once("  ").unwrap_or_else(|| {
            panic!(
                "{}:{}: expected `<sha256>  <path>` as shasum -a 256 emits, got {line:?}",
                pins_path.display(),
                number + 1
            )
        });
        accepted
            .entry(relative.to_string())
            .or_default()
            .push(expected.to_string());
        checked = checked.saturating_add(1);
    }

    let mut mismatches: Vec<String> = Vec::new();
    for (relative, expected) in &accepted {
        let target = repo_root.join(relative);
        println!("cargo:rerun-if-changed={}", target.display());

        let bytes = std::fs::read(&target).unwrap_or_else(|e| {
            panic!(
                "{}: {e}\n\nThis crate embeds wasm-pack output that is not checked in. Build it \
                 first:\n    wasm-pack build sdks/verifier-js --target web --release",
                target.display()
            )
        });
        let actual = hex(&Sha256::digest(&bytes));
        if !expected.contains(&actual) {
            // Collected rather than asserted one at a time: a build that stops
            // at the first mismatch makes updating a multi-artifact pin take one
            // CI round trip per file.
            mismatches.push(format!(
                "  {relative}\n    accepted: {}\n    actual:   {actual}",
                expected.join("\n              ")
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "{} embedded artifact(s) do not match their pins:\n{}\n\nIf the SDK changed on purpose, \
         rebuild and update crates/nucleus-verifier-service/embedded-wasm.pins:\n    wasm-pack \
         build sdks/verifier-js --target web --release\n    shasum -a 256 \
         sdks/verifier-js/pkg/nucleus_verifier_wasm_bg.wasm \
         sdks/verifier-js/pkg/nucleus_verifier_wasm.js\n\nNote that wasm-pack output is NOT \
         reproducible across platforms -- measured, macOS aarch64 and Linux x86_64 differ for the \
         same source and the same wasm-pack. The pins track the canonical builder, which is CI.",
        mismatches.len(),
        mismatches.join("\n")
    );

    assert!(
        checked > 0,
        "{} pinned nothing. An empty pin file passes every check it is supposed to make, which \
         is worse than having none.",
        pins_path.display()
    );
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}
