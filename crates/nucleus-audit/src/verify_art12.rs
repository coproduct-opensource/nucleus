//! Independent verification of an EU AI Act Article 12 record-keeping log.
//!
//! # What the log is
//!
//! `nucleus-tool-proxy --art12-log` appends one hash-chained, HMAC-signed
//! [`Art12Record`] per kernel decision — allows, refusals and deferrals alike.
//! This reads that file back and checks it, using the SAME
//! `canonical_preimage()` the writer used, reconstructed from each record's own
//! fields rather than by re-serialising (JSON key order and escaping are not
//! stable across serde versions, and a verifier that re-serialises to check a
//! hash is checking its own serialiser).
//!
//! # What verification proves, and what it does not
//!
//! Article 12 is enforced from August 2026 and requires automatic recording over
//! the system's lifetime, identification of the persons involved, and retention.
//! A verifier that answered only "valid / invalid" would let a reader infer far
//! more than was checked, so the report carries its limitations as data and the
//! CLI prints them. Specifically:
//!
//! * A passing chain shows **no party lacking the secret** altered the file. It
//!   does not show a holder of the secret did not rewrite history. Only a
//!   signature over the chain head by a key the pod does not possess can do
//!   that.
//! * If the pod derived its own signing secret (no operator `--audit-secret`),
//!   the pod can re-sign any history it likes, and the log is not evidence
//!   against the pod at all. The log cannot reveal which case it is in — the
//!   operator knows — so the limitation is reported unconditionally.
//! * Completeness is not verifiable from the artifact. A chain proves the
//!   records present are consecutive and unaltered; it cannot prove the process
//!   was running, or that it recorded every decision it made. `dropped` on the
//!   writer and the runtime's own degraded-refusal are what bound that, and they
//!   live outside this file.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use portcullis::art12_record::{Art12Attestation, Art12Record, ART12_SCHEMA_VERSION};
use serde::Serialize;

use crate::AuditError;

/// What a verification run established.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Art12Report {
    /// Records read and checked.
    pub records: u64,
    /// Chain head after the last record.
    pub chain_head: String,
    /// Earliest and latest `timestamp_unix` seen, if any.
    pub first_timestamp: Option<u64>,
    pub last_timestamp: Option<u64>,
    /// How many records name an authenticated actor. Article 12 asks for
    /// identification of the persons involved; a log of anonymous decisions
    /// satisfies the chain but not the requirement, and the difference should be
    /// visible rather than inferred from a green tick.
    pub identified_actors: u64,
    /// Count per verdict (`allow`, `deny`, `requires_approval`, `error`).
    pub verdicts: BTreeMap<String, u64>,
    /// Whether signatures were checked at all.
    pub signatures_checked: bool,
    /// Whether an executor attestation was checked against the computed head.
    pub attestation_checked: bool,
    /// What this run did NOT establish. Never empty.
    pub limitations: Vec<String>,
}

/// Check an executor attestation against the head this verifier computed.
///
/// # What this closes
///
/// Without it, a passing chain means "no party lacking the HMAC secret altered
/// this file" — which says nothing about a pod that holds its own secret. The
/// executor key lives on the node and the pod never sees it, so a pod that
/// rewrites its log produces a different head and cannot forge a signature over
/// the new one.
///
/// The signature is checked over the attestation's OWN preimage, then the head
/// it names is compared to the head computed from the log. Both halves are
/// required: a valid signature over a head that is not this log's proves only
/// that some other log was attested.
///
/// # Errors
/// If the signature does not verify, or the attested head is not the computed one.
pub fn check_attestation(
    att: &Art12Attestation,
    computed_head: &str,
    executor_pubkey: &VerifyingKey,
) -> Result<(), AuditError> {
    if att.kind != portcullis::art12_record::ART12_ATTESTATION_KIND {
        return Err(AuditError::Invalid {
            line: 0,
            message: format!(
                "unknown attestation kind {:?}; refusing rather than checking fields that may \
                 have moved",
                att.kind
            ),
        });
    }

    let bytes: [u8; 64] = hex::decode(&att.signature)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| AuditError::Invalid {
            line: 0,
            message: "attestation signature is not 64 hex-encoded bytes".to_string(),
        })?;
    // STRICT, not `verify`. Audit finding M-3: the cofactored equation accepts
    // small-order and non-canonical points, so one crafted signature can verify
    // under several identities. This attestation exists to bind a log to ONE
    // executor, so a weak signature-to-identity binding would defeat its whole
    // purpose. `check-verify-strict.sh` caught this before it landed.
    executor_pubkey
        .verify_strict(att.preimage().as_bytes(), &Signature::from_bytes(&bytes))
        .map_err(|_| AuditError::Invalid {
            line: 0,
            message: "attestation signature does not verify under the executor public key"
                .to_string(),
        })?;

    if att.chain_head != computed_head {
        return Err(AuditError::Invalid {
            line: 0,
            message: format!(
                "the executor attested chain head {} but this log computes {computed_head} -- \
                 the log was rewritten after it was attested",
                att.chain_head
            ),
        });
    }
    Ok(())
}

/// The limitations that hold for every run, stated as data so a consumer cannot
/// render a report without them.
fn base_limitations(signatures_checked: bool) -> Vec<String> {
    let mut v = vec![
        "A valid chain shows no party WITHOUT the signing secret altered this file. It does not \
         show that a holder of the secret did not rewrite history. Supply --attestation and \
         --executor-pubkey to close that: the executor key is one the pod never holds."
            .to_string(),
        "If the pod derived its own signing secret (no operator-supplied --audit-secret), the pod \
         could re-sign any history; the log is then not evidence against the pod UNLESS an \
         executor attestation was checked. This file alone cannot reveal which case applies."
            .to_string(),
        "Completeness is not verifiable from this artifact: the chain shows the records present \
         are consecutive and unaltered, not that every decision made was recorded."
            .to_string(),
    ];
    if !signatures_checked {
        v.push(
            "No secret was supplied, so signatures were NOT checked. Only the hash chain was \
             verified, which detects accidental corruption but not deliberate rewriting."
                .to_string(),
        );
    }
    v
}

/// Verify a JSONL Article 12 log.
///
/// `secret` absent means hashes and chaining are checked but signatures are not,
/// and the report says so.
///
/// # Errors
/// The first record that fails to parse, chain, or verify, naming its line.
pub fn verify_art12_log(path: &Path, secret: Option<&[u8]>) -> Result<Art12Report, AuditError> {
    let reader = BufReader::new(File::open(path)?);

    let mut prev_hash: Option<String> = None;
    let mut expected_seq: u64 = 1;
    let mut report = Art12Report {
        records: 0,
        chain_head: String::new(),
        first_timestamp: None,
        last_timestamp: None,
        identified_actors: 0,
        verdicts: BTreeMap::new(),
        signatures_checked: secret.is_some(),
        attestation_checked: false,
        limitations: base_limitations(secret.is_some()),
    };

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let line_no = idx + 1;
        let rec: Art12Record = serde_json::from_str(line).map_err(|source| AuditError::Json {
            line: line_no,
            source,
        })?;

        if rec.schema_version != ART12_SCHEMA_VERSION {
            return Err(AuditError::Invalid {
                line: line_no,
                message: format!(
                    "schema version {} but this verifier understands {ART12_SCHEMA_VERSION}; \
                     refusing rather than checking fields that may have moved",
                    rec.schema_version
                ),
            });
        }

        if rec.seq != expected_seq {
            return Err(AuditError::Invalid {
                line: line_no,
                message: format!(
                    "sequence gap: expected {expected_seq}, got {}. A gap means records are \
                     missing or reordered, which is the failure an Article 12 log exists to make \
                     visible",
                    rec.seq
                ),
            });
        }

        // The first record chains from the writer's genesis anchor, which this
        // verifier does not know; from the second on, the chain is checked.
        if let Some(prev) = &prev_hash {
            if &rec.prev_hash != prev {
                return Err(AuditError::Invalid {
                    line: line_no,
                    message: format!(
                        "prev_hash mismatch (expected {prev}, got {}) -- the chain is broken here",
                        rec.prev_hash
                    ),
                });
            }
        }

        // Recompute from the record's OWN fields. Any tampered field changes the
        // preimage and so the hash.
        let preimage = rec.canonical_preimage();
        let computed = crate::sha256_hex(&preimage);
        if computed != rec.hash {
            return Err(AuditError::Invalid {
                line: line_no,
                message: "hash does not match the record's fields -- this record was modified"
                    .to_string(),
            });
        }

        if let Some(secret) = secret {
            let sig = crate::sign_message(secret, preimage.as_bytes());
            if sig != rec.signature {
                return Err(AuditError::Invalid {
                    line: line_no,
                    message: "signature mismatch under the supplied secret".to_string(),
                });
            }
        }

        report.records += 1;
        report.first_timestamp.get_or_insert(rec.timestamp_unix);
        report.last_timestamp = Some(rec.timestamp_unix);
        if rec.actor.spiffe_id.as_ref().is_some_and(|s| !s.is_empty()) {
            report.identified_actors += 1;
        }
        *report.verdicts.entry(rec.verdict.clone()).or_insert(0) += 1;

        prev_hash = Some(rec.hash.clone());
        expected_seq += 1;
    }

    report.chain_head = prev_hash.unwrap_or_default();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis::art12_record::{Actor, DenyInfo};
    use std::io::Write;

    const SECRET: &[u8] = b"operator-held-secret";

    fn record(seq: u64, prev_hash: &str, verdict: &str) -> Art12Record {
        let mut rec = Art12Record {
            schema_version: ART12_SCHEMA_VERSION,
            seq,
            timestamp_unix: 1_700_000_000 + seq,
            session_id: "sess".into(),
            transport: "http".into(),
            actor: Actor {
                kind: "authenticated".into(),
                spiffe_id: Some("spiffe://nucleus/agent".into()),
            },
            operation: "run_bash".into(),
            subject: "ls".into(),
            verdict: verdict.into(),
            gate_class: "hard".into(),
            deny_reason: if verdict == "deny" {
                Some(DenyInfo {
                    code: "command_blocked".into(),
                    detail: Some("blocked by the command lattice".into()),
                })
            } else {
                None
            },
            policy_checksum: "ck".into(),
            policy_rule: None,
            dlc_admission: "unprovisioned".into(),
            lockdown_active: false,
            decision_sequence: Some(seq),
            extensions: BTreeMap::new(),
            prev_hash: prev_hash.to_string(),
            hash: String::new(),
            signature: String::new(),
        };
        // Sign exactly as the writer does.
        let preimage = rec.canonical_preimage();
        rec.signature = crate::sign_message(SECRET, preimage.as_bytes());
        rec.hash = crate::sha256_hex(&preimage);
        rec
    }

    /// Write a valid two-record log and return its path.
    fn valid_log(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let r1 = record(1, "art12-genesis:sess", "allow");
        let r2 = record(2, &r1.hash, "deny");
        write_log(dir, &[r1, r2])
    }

    fn write_log(dir: &tempfile::TempDir, records: &[Art12Record]) -> std::path::PathBuf {
        let path = dir.path().join("a12.jsonl");
        let mut f = File::create(&path).unwrap();
        for r in records {
            writeln!(f, "{}", serde_json::to_string(r).unwrap()).unwrap();
        }
        path
    }

    #[test]
    fn a_well_formed_log_verifies_and_reports_what_it_saw() {
        let dir = tempfile::tempdir().unwrap();
        let report = verify_art12_log(&valid_log(&dir), Some(SECRET)).expect("should verify");
        assert_eq!(report.records, 2);
        assert!(report.signatures_checked);
        assert_eq!(report.identified_actors, 2);
        assert_eq!(report.verdicts.get("allow"), Some(&1));
        assert_eq!(report.verdicts.get("deny"), Some(&1));
        assert_eq!(report.first_timestamp, Some(1_700_000_001));
        assert_eq!(report.last_timestamp, Some(1_700_000_002));
    }

    /// **The report can never claim more than it checked.** A consumer that
    /// renders "verified" without the caveats is the failure mode; making the
    /// caveats data rather than prose in a doc comment is what prevents it.
    #[test]
    fn a_passing_report_still_carries_its_limitations() {
        let dir = tempfile::tempdir().unwrap();
        let report = verify_art12_log(&valid_log(&dir), Some(SECRET)).unwrap();
        assert!(
            !report.limitations.is_empty(),
            "a passing verification must still say what it did not establish"
        );
        assert!(
            report
                .limitations
                .iter()
                .any(|l| l.contains("holder of the secret")),
            "the secret-holder limitation is the one that matters most; it must be present"
        );
        assert!(
            report
                .limitations
                .iter()
                .any(|l| l.contains("Completeness")),
            "a chain does not prove the log is complete, and the report must say so"
        );
    }

    /// Without a secret, hashes still chain but signatures are unchecked — and
    /// the report must not let that pass as the same thing.
    #[test]
    fn verifying_without_a_secret_says_signatures_were_not_checked() {
        let dir = tempfile::tempdir().unwrap();
        let report = verify_art12_log(&valid_log(&dir), None).expect("hash chain should verify");
        assert!(!report.signatures_checked);
        assert!(
            report
                .limitations
                .iter()
                .any(|l| l.contains("signatures were NOT checked")),
            "an unsigned verification must say so in the artifact, not only in the exit code"
        );
    }

    /// **The tamper sweep.** Every field folded into the canonical preimage must
    /// break verification when changed. A field that does not appear here is one
    /// an attacker can rewrite for free.
    /// A named single-field edit to a record.
    type Tamper = (&'static str, fn(&mut Art12Record));

    #[test]
    fn every_preimage_field_is_tamper_evident() {
        let mutations: Vec<Tamper> = vec![
            ("timestamp_unix", |r| r.timestamp_unix += 1),
            ("session_id", |r| r.session_id = "other".into()),
            ("transport", |r| r.transport = "mcp".into()),
            ("actor.kind", |r| r.actor.kind = "unknown".into()),
            ("actor.spiffe_id", |r| {
                r.actor.spiffe_id = Some("spiffe://elsewhere".into())
            }),
            ("operation", |r| r.operation = "read_files".into()),
            ("subject", |r| r.subject = "rm -rf /".into()),
            ("verdict", |r| r.verdict = "allow".into()),
            ("gate_class", |r| r.gate_class = "none".into()),
            ("deny_reason", |r| r.deny_reason = None),
            ("policy_checksum", |r| r.policy_checksum = "other".into()),
            ("policy_rule", |r| r.policy_rule = Some("rule".into())),
            ("dlc_admission", |r| r.dlc_admission = "admitted".into()),
            ("lockdown_active", |r| r.lockdown_active = true),
            ("decision_sequence", |r| r.decision_sequence = Some(99)),
            ("extensions", |r| {
                r.extensions.insert("k".into(), "v".into());
            }),
        ];

        for (field, mutate) in mutations {
            let dir = tempfile::tempdir().unwrap();
            let mut r1 = record(1, "art12-genesis:sess", "deny");
            mutate(&mut r1);
            // Hash and signature deliberately NOT recomputed: this is tampering,
            // not authoring.
            let path = write_log(&dir, &[r1]);
            let err = verify_art12_log(&path, Some(SECRET));
            assert!(
                err.is_err(),
                "tampering with `{field}` was not detected -- it is outside the signed preimage"
            );
        }
    }

    /// The control for the sweep above: the same record UNTAMPERED verifies, so
    /// the sweep is detecting the mutation rather than a broken fixture.
    #[test]
    fn the_untampered_fixture_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let r1 = record(1, "art12-genesis:sess", "deny");
        let path = write_log(&dir, &[r1]);
        assert!(verify_art12_log(&path, Some(SECRET)).is_ok());
    }

    /// A removed record is the attack an Article 12 log exists to make visible:
    /// deleting the refusal that embarrasses you.
    #[test]
    fn a_deleted_record_is_caught_as_a_sequence_gap() {
        let dir = tempfile::tempdir().unwrap();
        let r1 = record(1, "art12-genesis:sess", "allow");
        let r2 = record(2, &r1.hash, "deny");
        let r3 = record(3, &r2.hash, "allow");
        // Drop r2 — the refusal.
        let path = write_log(&dir, &[r1, r3]);
        let err = verify_art12_log(&path, Some(SECRET)).unwrap_err();
        assert!(
            format!("{err}").contains("sequence gap"),
            "a removed record must be reported as a gap, got: {err}"
        );
    }

    /// Re-chaining after a deletion still fails, because the surviving records'
    /// `prev_hash` cannot be repaired without re-signing them.
    #[test]
    fn a_rechained_deletion_still_fails_without_the_secret() {
        let dir = tempfile::tempdir().unwrap();
        let r1 = record(1, "art12-genesis:sess", "allow");
        let r2 = record(2, &r1.hash, "deny");
        let mut r3 = record(3, &r2.hash, "allow");
        // Attacker renumbers r3 to seq 2 and points it at r1, but cannot re-sign.
        r3.seq = 2;
        r3.prev_hash = r1.hash.clone();
        let path = write_log(&dir, &[r1, r3]);
        assert!(verify_art12_log(&path, Some(SECRET)).is_err());
    }

    /// A schema the verifier does not understand is refused rather than checked
    /// against fields that may have moved.
    #[test]
    fn an_unknown_schema_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut r1 = record(1, "art12-genesis:sess", "allow");
        r1.schema_version = ART12_SCHEMA_VERSION + 1;
        let path = write_log(&dir, &[r1]);
        let err = verify_art12_log(&path, Some(SECRET)).unwrap_err();
        assert!(format!("{err}").contains("schema version"), "got: {err}");
    }

    /// An empty log verifies vacuously — and the report must make that legible
    /// rather than looking like a clean session.
    #[test]
    fn an_empty_log_reports_zero_rather_than_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_log(&dir, &[]);
        let report = verify_art12_log(&path, Some(SECRET)).unwrap();
        assert_eq!(report.records, 0);
        assert!(report.chain_head.is_empty());
    }

    // ── executor attestation ────────────────────────────────────────────────

    use ed25519_dalek::{Signer as _, SigningKey};
    use portcullis::art12_record::{art12_attestation_preimage, ART12_ATTESTATION_KIND};

    fn attest(chain_head: &str, key: &SigningKey) -> Art12Attestation {
        let preimage = art12_attestation_preimage("sess", chain_head, 2, 0, "exec-1");
        Art12Attestation {
            kind: ART12_ATTESTATION_KIND.to_string(),
            session_id: "sess".into(),
            chain_head: chain_head.to_string(),
            records: 2,
            dropped: 0,
            executor_id: "exec-1".into(),
            pod_reported_head: None,
            pod_records: None,
            signature: hex::encode(key.sign(preimage.as_bytes()).to_bytes()),
        }
    }

    /// The happy path: the executor attested the head this log actually computes.
    #[test]
    fn an_attestation_over_the_computed_head_checks_out() {
        let dir = tempfile::tempdir().unwrap();
        let report = verify_art12_log(&valid_log(&dir), Some(SECRET)).unwrap();
        let key = SigningKey::from_bytes(&[3u8; 32]);
        assert!(check_attestation(
            &attest(&report.chain_head, &key),
            &report.chain_head,
            &key.verifying_key()
        )
        .is_ok());
    }

    /// **The property the export exists for.** A pod that rewrites its log after
    /// being attested produces a different head, and cannot re-sign.
    #[test]
    fn a_log_rewritten_after_attestation_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[3u8; 32]);
        // Attested when the log ended at some earlier head.
        let att = attest("the-head-that-was-attested", &key);

        let report = verify_art12_log(&valid_log(&dir), Some(SECRET)).unwrap();
        let err = check_attestation(&att, &report.chain_head, &key.verifying_key()).unwrap_err();
        assert!(
            format!("{err}").contains("rewritten after it was attested"),
            "got: {err}"
        );
    }

    /// A signature from the wrong key must not pass — otherwise the attestation
    /// proves only that SOMEONE signed, which is what the pod can already do.
    #[test]
    fn an_attestation_from_another_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let report = verify_art12_log(&valid_log(&dir), Some(SECRET)).unwrap();
        let real = SigningKey::from_bytes(&[3u8; 32]);
        let impostor = SigningKey::from_bytes(&[4u8; 32]);
        let err = check_attestation(
            &attest(&report.chain_head, &impostor),
            &report.chain_head,
            &real.verifying_key(),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("does not verify"), "got: {err}");
    }

    /// Both halves are required. A signature valid over ANOTHER log's head must
    /// not pass for this one — that is the substitution attack.
    #[test]
    fn a_valid_signature_over_a_different_log_does_not_pass() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let att = attest("head-of-some-other-session", &key);
        // The signature itself is perfectly valid...
        assert!(
            check_attestation(&att, "head-of-some-other-session", &key.verifying_key()).is_ok()
        );
        // ...but not for this log.
        assert!(check_attestation(&att, "this-logs-head", &key.verifying_key()).is_err());
    }

    /// An unknown attestation kind is refused rather than field-guessed.
    #[test]
    fn an_unknown_attestation_kind_is_refused() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let mut att = attest("h", &key);
        att.kind = "something-else-v9".into();
        let err = check_attestation(&att, "h", &key.verifying_key()).unwrap_err();
        assert!(
            format!("{err}").contains("unknown attestation kind"),
            "got: {err}"
        );
    }
}
