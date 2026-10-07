//! `nucleus-audit verify`, driven as a binary, against the log a keyless
//! party can write (#3293).
//!
//! Before #3293 the tool-proxy keyed its audit MAC with the auth secret, and
//! on vsock and on the peer-verified socket that secret is EMPTY. So anyone
//! could write a log, or append to one, that `nucleus-audit verify --secret ""`
//! (or the empty `NUCLEUS_TOOL_PROXY_AUTH_SECRET` such a pod carries) reported
//! as verified. The fixture is built by hand from the legacy preimage, with no
//! crate API, so this test means the same thing on the tree before the fix: it
//! is red there.

use std::process::Command;

use hmac::{Hmac, Mac, digest::KeyInit};
use sha2::{Digest, Sha256};

/// One legacy record, as the pre-#3293 writer made it, under `key`.
fn legacy_line(key: &[u8], ts: u64, event: &str, prev: &str) -> (String, String) {
    let message = format!("{ts}|forger|{event}|anything|ok|{prev}");
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
    mac.update(message.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    let hash = hex::encode(Sha256::digest(format!("{message}|{signature}").as_bytes()));
    let line = serde_json::json!({
        "timestamp_unix": ts,
        "actor": "forger",
        "event": event,
        "subject": "anything",
        "result": "ok",
        "prev_hash": prev,
        "hash": hash,
        "signature": signature,
    })
    .to_string();
    (line, hash)
}

#[test]
fn a_log_forged_with_no_key_is_not_reported_verified() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.log");
    let (boot, h) = legacy_line(b"", 100, "boot", "");
    let (forged, _) = legacy_line(b"", 101, "approve", &h);
    std::fs::write(&path, format!("{boot}\n{forged}\n")).expect("write");

    let out = Command::new(env!("CARGO_BIN_EXE_nucleus-audit"))
        .args(["verify", "--log"])
        .arg(&path)
        .args(["--secret", ""])
        .env_remove("NUCLEUS_TOOL_PROXY_AUTH_SECRET")
        .env_remove("NUCLEUS_TOOL_PROXY_AUDIT_SECRET")
        .output()
        .expect("run nucleus-audit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a log any keyless party can write was reported verified: {stdout}"
    );
    assert!(
        stderr.contains("LegacyMacUnkeyed"),
        "the refusal must name the legacy keyless MAC: {stderr}"
    );
}
