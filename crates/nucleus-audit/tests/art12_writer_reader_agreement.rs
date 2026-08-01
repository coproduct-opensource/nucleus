//! The writer and the verifier must agree on the SAME log.
//!
//! Every test in `verify_art12`'s own module authors its fixtures with the
//! verifier's idea of the preimage. That proves the verifier is
//! self-consistent, which is not the property anyone cares about: if the writer
//! in `nucleus-tool-proxy` folded a field differently, both sides would still be
//! green and every real log would fail in the field.
//!
//! This drives the REAL writer — `portcullis::art12_record::Art12Record` as the
//! tool-proxy builds and signs it — and hands the result to the verifier. It is
//! the same discipline as `nucleus-flow-replay`'s kernel-vs-mirror corpus.

use std::collections::BTreeMap;
use std::io::Write;

use portcullis::art12_record::{Actor, Art12Record, DenyInfo, ART12_SCHEMA_VERSION};

/// Mirrors `Art12Log::append_inner`: assign chain fields, sign the canonical
/// preimage, then hash it. Kept deliberately close to the writer so a divergence
/// shows up here rather than in production.
fn append_like_the_writer(
    draft: &mut Art12Record,
    secret: &[u8],
    seq: u64,
    prev_hash: &str,
) -> String {
    draft.schema_version = ART12_SCHEMA_VERSION;
    draft.seq = seq;
    draft.prev_hash = prev_hash.to_string();
    let preimage = draft.canonical_preimage();
    draft.signature = {
        use hmac::{digest::KeyInit, Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac accepts any key length");
        mac.update(preimage.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    };
    draft.hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(preimage.as_bytes());
        hex::encode(h.finalize())
    };
    draft.hash.clone()
}

fn draft(operation: &str, verdict: &str, deny: Option<DenyInfo>) -> Art12Record {
    let mut extensions = BTreeMap::new();
    // The flow cross-check (#2144) rides in extensions and IS signed; a writer
    // that stopped folding extensions into the preimage would let it be edited.
    extensions.insert("flow_cross_check".to_string(), "confirmed".to_string());
    Art12Record {
        schema_version: 0,
        seq: 0,
        timestamp_unix: 1_700_000_000,
        session_id: "e2e".into(),
        transport: "http".into(),
        actor: Actor {
            kind: "stdio_guest".into(),
            spiffe_id: None,
        },
        operation: operation.into(),
        subject: "subject".into(),
        verdict: verdict.into(),
        gate_class: "hard".into(),
        deny_reason: deny,
        policy_checksum: "checksum".into(),
        policy_rule: None,
        dlc_admission: "unprovisioned".into(),
        lockdown_active: false,
        decision_sequence: Some(1),
        extensions,
        prev_hash: String::new(),
        hash: String::new(),
        signature: String::new(),
    }
}

/// A log produced the way the runtime produces it must verify. If the writer and
/// verifier ever disagree on the preimage, this REDs — and the unit tests on
/// either side would not.
#[test]
fn a_writer_produced_log_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a12.jsonl");
    let secret = b"shared-secret";
    let mut f = std::fs::File::create(&path).unwrap();

    let mut prev = "art12-genesis:e2e".to_string();
    let mut allow = draft("read_files", "allow", None);
    prev = append_like_the_writer(&mut allow, secret, 1, &prev);
    writeln!(f, "{}", serde_json::to_string(&allow).unwrap()).unwrap();

    let mut deny = draft(
        "run_bash",
        "deny",
        Some(DenyInfo {
            code: "command_blocked".into(),
            detail: Some("blocked by the command lattice".into()),
        }),
    );
    append_like_the_writer(&mut deny, secret, 2, &prev);
    writeln!(f, "{}", serde_json::to_string(&deny).unwrap()).unwrap();
    drop(f);

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_nucleus-audit"))
        .args(["verify-art12", "--log"])
        .arg(&path)
        .args(["--secret", "shared-secret", "--json"])
        .output()
        .expect("run nucleus-audit");

    assert!(
        out.status.success(),
        "verification failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json report");
    assert_eq!(report["records"], 2);
    assert_eq!(report["signatures_checked"], true);
    assert_eq!(report["verdicts"]["deny"], 1);
}

/// **The limitations must reach the operator, not just the struct.** A report
/// rendered without them invites reading "verified" as more than it is, and the
/// text surface is what a human actually sees.
#[test]
fn the_text_output_prints_what_was_not_established() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.jsonl");
    std::fs::write(&path, "").unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_nucleus-audit"))
        .args(["verify-art12", "--log"])
        .arg(&path)
        .output()
        .expect("run nucleus-audit");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("This run did NOT establish"),
        "the caveats must be printed, got:\n{stdout}"
    );
    assert!(
        stdout.contains("holder of the secret"),
        "the secret-holder caveat is the load-bearing one; got:\n{stdout}"
    );
}
