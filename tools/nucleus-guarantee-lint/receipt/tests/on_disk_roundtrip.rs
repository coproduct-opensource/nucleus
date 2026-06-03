//! On-disk roundtrip: mirror exactly what the lint's `flush_receipts` writes
//! (`<anchor_hash>.json` canonical bytes + `<anchor_hash>.sig` as lowercase HEX) and
//! verify it back with the witness PUBLIC key — the same path the
//! `verify-guarantee-receipt` bin takes. No rustc / dylint needed.
//!
//! HONESTY: the signing key is generated FRESH in-test and never leaves the temp dir.
//! No real/private key is read or committed.

use nucleus_guarantee_receipt::{PROFILE_ID, Receipt, load_verifying_key, verify_receipt};
use rand_core::OsRng;

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!(
        "nucleus-guarantee-receipt-test-{tag}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn writes_json_plus_hex_sig_and_verifies_back() {
    let dir = tmp_dir("roundtrip");

    let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let pubkey_hex = hex::encode(key.verifying_key().to_bytes());

    let receipt = Receipt::build(
        "crate::clean_add".into(),
        "fn".into(),
        "fn clean_add(a: u64, b: u64) -> u64 { a + b }",
        "nightly-2026-04-16",
        PROFILE_ID,
        &[],
        vec![],
    );
    let (json, sig) = receipt.sign(&key).unwrap();

    // Exactly the lint's on-disk format.
    let json_path = dir.join(format!("{}.json", receipt.anchor_hash));
    let sig_path = dir.join(format!("{}.sig", receipt.anchor_hash));
    std::fs::write(&json_path, &json).unwrap();
    std::fs::write(&sig_path, hex::encode(sig.to_bytes())).unwrap();

    // Holder side: read back, decode the hex sig + hex pubkey, verify.
    let json_back = std::fs::read(&json_path).unwrap();
    let sig_hex = std::fs::read_to_string(&sig_path).unwrap();
    let sig_bytes = hex::decode(sig_hex.trim()).unwrap();
    let pubkey = load_verifying_key(pubkey_hex.as_bytes()).unwrap();

    assert!(verify_receipt(&json_back, &sig_bytes, &pubkey).unwrap());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn ineligible_receipt_on_disk_records_failed_rule() {
    let dir = tmp_dir("ineligible");
    let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let pubkey = key.verifying_key();

    let receipt = Receipt::build(
        "crate::ineligible_unsafe".into(),
        "fn".into(),
        "unsafe fn ineligible_unsafe() -> u64 { 0 }",
        "nightly-2026-04-16",
        PROFILE_ID,
        &["no_unsafe"],
        vec!["an `unsafe` function signature".into()],
    );
    let (json, sig) = receipt.sign(&key).unwrap();
    let json_path = dir.join(format!("{}.json", receipt.anchor_hash));
    std::fs::write(&json_path, &json).unwrap();

    let parsed: Receipt = serde_json::from_slice(&std::fs::read(&json_path).unwrap()).unwrap();
    assert_eq!(parsed.result, nucleus_guarantee_receipt::ScreenResult::Ineligible);
    assert_eq!(
        parsed.guarantees["no_unsafe"],
        nucleus_guarantee_receipt::Guarantee::Fail
    );
    assert!(verify_receipt(&json, &sig.to_bytes(), &pubkey).unwrap());

    std::fs::remove_dir_all(&dir).ok();
}
