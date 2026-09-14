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
//! This adds no failure mode that did not already exist: `include_bytes!` of a
//! missing file is already a compile error, so this crate already could not
//! build without wasm-pack having run. What changes is that building against
//! the *wrong* artifact stops being silent.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn main() {
    let crate_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"),
    );
    let repo_root = crate_dir
        .parent()
        .and_then(Path::parent)
        .expect("crates/<name> sits two levels below the repository root")
        .to_path_buf();

    let pins_path = crate_dir.join("embedded-wasm.pins");
    println!("cargo:rerun-if-changed={}", pins_path.display());
    let pins = std::fs::read_to_string(&pins_path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", pins_path.display()));

    let mut checked = 0usize;
    let mut mismatches: Vec<String> = Vec::new();
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
        if actual != expected {
            // Collected rather than asserted one at a time: a build that stops
            // at the first mismatch makes updating a multi-artifact pin take one
            // CI round trip per file.
            mismatches.push(format!("  {relative}\n    pinned: {expected}\n    actual: {actual}"));
        }
        checked = checked.saturating_add(1);
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
