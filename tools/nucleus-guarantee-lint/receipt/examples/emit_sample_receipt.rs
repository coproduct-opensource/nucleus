//! Emit a sample guarantee receipt + detached signature + the witness PUBLIC key, for a
//! CLI smoke test of `verify-guarantee-receipt`.
//!
//! HONESTY: the signing key here is GENERATED FRESH at runtime and written to the OUTPUT
//! dir only. No real/private key is read or committed. This is example/test plumbing.
//!
//! Usage: cargo run --example emit_sample_receipt -- <out_dir>
//!
//! Writes into <out_dir>:
//!   <anchor_hash>.json   — canonical receipt
//!   <anchor_hash>.sig    — hex ed25519 signature
//!   witness.pub          — hex 32-byte verifying key (PUBLIC)
//!   anchor_hash.txt      — the anchor hash (convenience)

use nucleus_guarantee_receipt::{PROFILE_ID, Receipt};
use rand_core::OsRng;

fn main() {
    let out = std::env::args().nth(1).unwrap_or_else(|| "testdata/sample".to_string());
    std::fs::create_dir_all(&out).unwrap();

    let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let pubkey = key.verifying_key();

    let source = "fn clean_add(a: u64, b: u64) -> u64 {\n    a + b\n}";
    let receipt = Receipt::build(
        "crate::clean_add".into(),
        "fn".into(),
        source,
        "nightly-2026-04-16",
        PROFILE_ID,
        &[],   // clean
        vec![],
    );
    let (json, sig) = receipt.sign(&key).unwrap();

    let base = std::path::Path::new(&out).join(&receipt.anchor_hash);
    std::fs::write(base.with_extension("json"), &json).unwrap();
    std::fs::write(base.with_extension("sig"), hex::encode(sig.to_bytes())).unwrap();
    std::fs::write(std::path::Path::new(&out).join("witness.pub"), hex::encode(pubkey.to_bytes())).unwrap();
    std::fs::write(std::path::Path::new(&out).join("anchor_hash.txt"), &receipt.anchor_hash).unwrap();

    println!("anchor_hash={}", receipt.anchor_hash);
    println!("wrote receipt + sig + witness.pub to {out}");
}
