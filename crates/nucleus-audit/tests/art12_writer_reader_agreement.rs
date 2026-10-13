//! The writer and the verifier must agree on the SAME log.
//!
//! Every test in `verify_art12`'s own module authors its fixtures with the
//! verifier's idea of the preimage. That proves the verifier is
//! self-consistent, which is not the property anyone cares about: if the writer
//! in `nucleus-tool-proxy` folded a field differently, both sides would still be
//! green and every real log would fail in the field.
//!
//! This seals records with the calls the REAL writer makes
//! (`AuditSigner::seal_art12`: `to_be_signed_by`, `signed_bytes`, an Ed25519
//! signature, `with_signature`) and hands the result to the verifier, driven as
//! a binary. It is the same discipline as `nucleus-flow-replay`'s
//! kernel-vs-mirror corpus.

use std::collections::BTreeMap;
use std::io::Write;

use ed25519_dalek::{Signer as _, SigningKey};
use portcullis::art12_record::{ART12_SCHEMA_VERSION, Art12Record, DenyInfo};

/// The audit signer's stand-in. In the proxy it is generated from the OS RNG.
fn signer() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn signer_hex() -> String {
    hex::encode(signer().verifying_key().to_bytes())
}

/// Mirrors `Art12Log::append_inner` and `AuditSigner::seal_art12`: assign the
/// chain fields, name the signer, sign the signed bytes, then hash. Returns the
/// sealed record.
fn append_like_the_writer(mut draft: Art12Record, seq: u64, prev_hash: &str) -> Art12Record {
    draft.schema_version = ART12_SCHEMA_VERSION;
    draft.seq = seq;
    draft.prev_hash = prev_hash.to_string();
    let unsigned = draft.to_be_signed_by(signer_hex());
    let bytes = unsigned.signed_bytes().expect("signed form");
    unsigned
        .with_signature(hex::encode(signer().sign(&bytes).to_bytes()))
        .expect("signed form")
}

/// A draft built from JSON, naming no field the pre-#3309 record lacked, so
/// the legacy fixtures below mean the same thing on the tree before the fix.
fn draft(operation: &str, verdict: &str, deny: Option<DenyInfo>) -> Art12Record {
    let mut extensions = BTreeMap::new();
    // The flow cross-check (#2144) rides in extensions and IS signed; a writer
    // that stopped folding extensions into the preimage would let it be edited.
    extensions.insert("flow_cross_check".to_string(), "confirmed".to_string());
    serde_json::from_value(serde_json::json!({
        "schema_version": 0,
        "seq": 0,
        "timestamp_unix": 1_700_000_000_u64,
        "session_id": "e2e",
        "transport": "http",
        "actor": { "kind": "stdio_guest" },
        "operation": operation,
        "subject": "subject",
        "verdict": verdict,
        "gate_class": "hard",
        "deny_reason": deny.map(|d| serde_json::json!({ "code": d.code, "detail": d.detail })),
        "policy_checksum": "checksum",
        "dlc_admission": "unprovisioned",
        "lockdown_active": false,
        "decision_sequence": 1,
        "extensions": extensions,
        "prev_hash": "",
        "hash": "",
        "signature": "",
    }))
    .expect("a draft")
}

fn write_log(path: &std::path::Path, records: &[Art12Record]) {
    let mut f = std::fs::File::create(path).unwrap();
    for r in records {
        writeln!(f, "{}", serde_json::to_string(r).unwrap()).unwrap();
    }
}

fn verify(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_nucleus-audit"))
        .arg("verify-art12")
        .args(args)
        .env_remove("NUCLEUS_ART12_SECRET")
        .output()
        .expect("run nucleus-audit")
}

/// A log produced the way the runtime produces it must verify. If the writer and
/// verifier ever disagree on the preimage, this REDs — and the unit tests on
/// either side would not.
#[test]
fn a_writer_produced_log_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a12.jsonl");

    let allow = append_like_the_writer(draft("read_files", "allow", None), 1, "art12-genesis:e2e");
    let deny = append_like_the_writer(
        draft(
            "run_bash",
            "deny",
            Some(DenyInfo {
                code: "command_blocked".into(),
                detail: Some("blocked by the command lattice".into()),
            }),
        ),
        2,
        &allow.hash,
    );
    write_log(&path, &[allow, deny]);

    let out = verify(&[
        "--log",
        path.to_str().unwrap(),
        "--signer-pubkey",
        &signer_hex(),
        "--json",
    ]);
    assert!(
        out.status.success(),
        "verification failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json report");
    assert_eq!(report["records"], 2);
    assert_eq!(report["signatures_checked"], true);
    assert_eq!(report["signed"], 2);
    assert_eq!(report["signers"][0], signer_hex());
    assert_eq!(report["verdicts"]["deny"], 1);
}

/// #3309, A-19, through the binary: a log any keyless party can write is not
/// reported verified. Before #3376 a pod with no operator key MAC'd its log
/// under `art12:<session id>`, and the session id is public; an empty key is
/// computable by anyone. Under the MAC scheme `verify-art12` with no secret
/// checked only the hash chain and passed, and with `--secret ""` it checked
/// the empty-key MAC and passed. The fixture is built from the legacy
/// preimage with no API this change added, so this test is red on the tree
/// before it.
#[test]
fn a_log_forged_with_no_key_is_not_reported_verified() {
    use hmac::{Hmac, Mac, digest::KeyInit};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("forged.jsonl");
    let forge = |mut rec: Art12Record, key: &[u8], seq: u64, prev: &str| {
        rec.schema_version = ART12_SCHEMA_VERSION;
        rec.seq = seq;
        rec.prev_hash = prev.to_string();
        let preimage = rec.canonical_preimage();
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
        mac.update(preimage.as_bytes());
        rec.signature = hex::encode(mac.finalize().into_bytes());
        rec.hash = {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(preimage.as_bytes()))
        };
        rec
    };
    for key in [&b"art12:e2e"[..], b""] {
        // The refusal the operator saw is now an allow.
        let a = forge(
            draft("run_bash", "allow", None),
            key,
            1,
            "art12-genesis:e2e",
        );
        let b = forge(draft("read_files", "allow", None), key, 2, &a.hash);
        write_log(&path, &[a, b]);
        for secret in [None, Some("")] {
            let mut args = vec!["--log", path.to_str().unwrap(), "--json"];
            if let Some(s) = secret {
                args.extend(["--secret", s]);
            }
            let out = verify(&args);
            assert!(
                !out.status.success(),
                "a log a keyless party wrote was reported verified (key {key:?}, secret \
                 {secret:?}): {}",
                String::from_utf8_lossy(&out.stdout)
            );
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains("LegacyMacUnkeyed"),
                "the refusal must name the legacy keyless MAC: {stderr}"
            );
        }
    }
}

/// **The limitations must reach the operator, not just the struct.** A report
/// rendered without them invites reading "verified" as more than it is, and the
/// text surface is what a human actually sees.
#[test]
fn the_text_output_prints_what_was_not_established() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.jsonl");
    std::fs::write(&path, "").unwrap();

    let out = verify(&["--log", path.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("This run did NOT establish"),
        "the caveats must be printed, got:\n{stdout}"
    );
    assert!(
        stdout.contains("the key's holder"),
        "the key-holder caveat is the load-bearing one; got:\n{stdout}"
    );
}

/// **The whole export loop, through the CLI.** Writer produces a log; the host
/// signs its head with a key the pod never holds; the verifier checks that
/// signature, pins the head (and with it the record signer) by it, and
/// recomputes the head from the file.
///
/// The signer (`nucleus-node::attest_art12`) and this verifier share ONE
/// preimage function in `portcullis::art12_record`, so they cannot disagree
/// about what is signed — but the CLI plumbing between them can still be wrong,
/// and that is what this exercises.
#[test]
fn the_signed_head_round_trips_through_the_cli() {
    use portcullis::art12_record::{
        ART12_ATTESTATION_KIND, Art12Attestation, art12_attestation_preimage,
    };

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("a12.jsonl");

    let rec = append_like_the_writer(draft("read_files", "allow", None), 1, "art12-genesis:e2e");
    let head = rec.hash.clone();
    write_log(&log_path, std::slice::from_ref(&rec));

    // The host signs the head it was told, with the executor key.
    let key = SigningKey::from_bytes(&[11u8; 32]);
    let preimage = art12_attestation_preimage("e2e", &head, 1, 0, "exec-1");
    let att = Art12Attestation {
        kind: ART12_ATTESTATION_KIND.to_string(),
        session_id: "e2e".into(),
        chain_head: head.clone(),
        records: 1,
        dropped: 0,
        executor_id: "exec-1".into(),
        pod_reported_head: None,
        pod_records: None,
        signature: hex::encode(key.sign(preimage.as_bytes()).to_bytes()),
    };
    let att_path = dir.path().join("att.json");
    std::fs::write(&att_path, serde_json::to_string(&att).unwrap()).unwrap();
    let pubkey = hex::encode(key.verifying_key().to_bytes());

    // No --signer-pubkey: the attested head is the only pin.
    let run = || {
        verify(&[
            "--log",
            log_path.to_str().unwrap(),
            "--json",
            "--attestation",
            att_path.to_str().unwrap(),
            "--executor-pubkey",
            &pubkey,
        ])
    };

    let out = run();
    assert!(
        out.status.success(),
        "attested verification failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["attestation_checked"], true);
    // With the head bound by a key the pod never held, the key-holder caveat
    // no longer applies and must be gone — a report that keeps it would be
    // understating what was established.
    let limits = report["limitations"].as_array().unwrap();
    assert!(
        !limits
            .iter()
            .any(|l| l.as_str().unwrap().contains("the key's holder")),
        "the key-holder limitation should be lifted once the head is attested"
    );
    assert!(
        limits
            .iter()
            .any(|l| l.as_str().unwrap().contains("HEAD, not its content")),
        "and replaced by the one that still applies"
    );

    // A rewritten log fails: the recomputed head no longer matches.
    let extra = append_like_the_writer(draft("run_bash", "allow", None), 2, &head);
    write_log(&log_path, &[rec, extra]);
    let out = run();
    assert!(
        !out.status.success(),
        "a log extended after attestation must not verify"
    );
}
