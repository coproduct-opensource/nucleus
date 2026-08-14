//! Independent verification + scoreboard for signed [`MediationReceipt`]s.
//!
//! # What the file is
//!
//! `nucleus-tool-proxy`, when a mediator signing key is provisioned, emits one
//! signed [`MediationReceipt`] per kernel decision — a portable proof binding
//! *who mediated*, *what it decided*, and the SHA-256 hash of the Article 12
//! record that recorded it. This reads that JSONL back, verifies each signature
//! (strict) under a supplied mediator public key, and renders a scoreboard.
//!
//! Verification uses the receipt's OWN `preimage()` (reconstructed from its
//! fields, never re-serialized JSON) via [`MediationReceipt::verify`] — the same
//! discipline `verify_art12` uses, so this is not a checker checking its own
//! serializer.
//!
//! # What a verified receipt proves, and what it does NOT
//!
//! A receipt that verifies is **the mediator-key-holder's own word** about a
//! crossing — nothing more. The scoreboard therefore carries its limitations as
//! data (never empty), the same guard `verify_art12` uses so a reader cannot
//! infer more than was checked:
//!
//!  * It does **not** show the mediator is genuine. A valid signature over
//!    `signer_assurance = 2` proves only the key-holder *wrote* `2`. That the
//!    key's SVID is attested (C9 EK/DevID) AND that the self-claimed
//!    assurance/backend EQUAL the independently-derived attestation is a separate
//!    cross-check — the one that catches an inflated self-claim.
//!  * It does **not** show the crossing is in a tamper-evident, witnessed log.
//!    Each receipt names an `art12_record_hash`; showing that hash is included in
//!    the witnessed Article 12 lineage is a separate step.
//!  * It does **not** show completeness. A receipt file proves the receipts
//!    present verify, not that every crossing produced one — a silent mediator
//!    leaves no receipt to miss here.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use ed25519_dalek::VerifyingKey;
use portcullis::mediation_receipt::MediationReceipt;
use serde::Serialize;

use crate::AuditError;

/// A receipt that was present but did not verify under the supplied key — the
/// alarm a tamper scoreboard exists to raise, carried per-line rather than
/// aborting the whole run so the rest of the picture is still legible.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ReceiptFailure {
    pub line: usize,
    pub reason: String,
}

/// What a scoreboard run established.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ReceiptReport {
    /// Receipts parsed.
    pub receipts: u64,
    /// Receipts whose signature verified (strict) under the supplied key. Zero
    /// when no key was supplied.
    pub verified: u64,
    /// Receipts that failed to verify, with why. Non-empty ⇒ the CLI exits
    /// non-zero: a receipt file with a bad signature is the tamper case.
    pub failures: Vec<ReceiptFailure>,
    /// Count per verdict (`allow`, `deny`, `requires_approval`, `error`).
    pub verdicts: BTreeMap<String, u64>,
    /// Count per mediator SPIFFE id. More than one means receipts from several
    /// mediators are mixed in this file — legible rather than silently merged.
    pub mediators: BTreeMap<String, u64>,
    /// Count per session id.
    pub sessions: BTreeMap<String, u64>,
    /// Distinct `art12_record_hash` values — the number of unique recorded
    /// decisions these receipts vouch for.
    pub distinct_record_hashes: u64,
    /// Whether signatures were checked at all (a key was supplied).
    pub signatures_checked: bool,
    /// What this run did NOT establish. Never empty.
    pub limitations: Vec<String>,
}

/// The limitations that hold for every run, stated as data so a consumer cannot
/// render a scoreboard without them. Mirrors `verify_art12::base_limitations`.
fn base_limitations(signatures_checked: bool) -> Vec<String> {
    let mut v = vec![
        "A verified receipt is only the MEDIATOR-KEY-HOLDER'S OWN WORD about a crossing. It does \
         NOT establish the mediator is genuine: you must independently verify that key's SVID is \
         attested (C9 EK/DevID) AND that each receipt's signer_assurance/signer_backend EQUAL that \
         attestation. An inflated self-claim is caught only by that cross-check, never by this \
         signature."
            .to_string(),
        "This scoreboard does NOT show the crossings it counts are recorded in a tamper-evident, \
         witnessed log. Each receipt names an art12_record_hash; showing that hash is included in \
         the witnessed Article 12 lineage (signed-tree-head / witness federation) is a separate \
         check."
            .to_string(),
        "Completeness is not verifiable from this artifact: a receipt file proves the receipts \
         PRESENT verify, not that every mediated crossing produced one — a mediator that stayed \
         silent leaves no receipt to miss here."
            .to_string(),
    ];
    if !signatures_checked {
        v.push(
            "No mediator public key was supplied, so signatures were NOT checked — receipts were \
             only parsed and tallied. A tally without verification is not evidence of anything."
                .to_string(),
        );
    }
    v
}

/// Verify a JSONL MediationReceipt log and tally a scoreboard.
///
/// `mediator_pubkey` absent means receipts are parsed and counted but signatures
/// are NOT checked, and the report says so. A malformed line aborts (the file we
/// wrote should be well-formed; a parse failure is corruption). A signature that
/// does not verify is collected into `failures` rather than aborting, so a single
/// forged receipt among many does not hide the rest.
///
/// # Errors
/// The first line that fails to parse, naming its line number.
pub fn verify_receipt_log(
    path: &Path,
    mediator_pubkey: Option<&VerifyingKey>,
) -> Result<ReceiptReport, AuditError> {
    let reader = BufReader::new(File::open(path)?);
    let mut report = ReceiptReport {
        receipts: 0,
        verified: 0,
        failures: Vec::new(),
        verdicts: BTreeMap::new(),
        mediators: BTreeMap::new(),
        sessions: BTreeMap::new(),
        distinct_record_hashes: 0,
        signatures_checked: mediator_pubkey.is_some(),
        limitations: base_limitations(mediator_pubkey.is_some()),
    };
    let mut hashes: BTreeSet<String> = BTreeSet::new();

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let line_no = idx + 1;
        let rec: MediationReceipt =
            serde_json::from_str(line).map_err(|source| AuditError::Json {
                line: line_no,
                source,
            })?;

        report.receipts += 1;
        *report.verdicts.entry(rec.verdict.clone()).or_insert(0) += 1;
        *report
            .mediators
            .entry(rec.mediator_spiffe_id.clone())
            .or_insert(0) += 1;
        *report.sessions.entry(rec.session_id.clone()).or_insert(0) += 1;
        hashes.insert(rec.art12_record_hash.clone());

        if let Some(pk) = mediator_pubkey {
            match rec.verify(pk) {
                Ok(()) => report.verified += 1,
                Err(e) => report.failures.push(ReceiptFailure {
                    line: line_no,
                    reason: e.to_string(),
                }),
            }
        }
    }

    report.distinct_record_hashes = hashes.len() as u64;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use portcullis::art12_record::{Actor, Art12Record};
    use std::collections::BTreeMap as Map;
    use std::io::Write;

    fn art12_record(session: &str, op: &str, verdict: &str, hash: &str) -> Art12Record {
        Art12Record {
            schema_version: 1,
            seq: 1,
            timestamp_unix: 1_700_000_000,
            session_id: session.into(),
            transport: "http".into(),
            actor: Actor {
                kind: "authenticated".into(),
                spiffe_id: Some("spiffe://demo/ns/default/sa/agent".into()),
            },
            operation: op.into(),
            subject: "ls".into(),
            verdict: verdict.into(),
            gate_class: "hard".into(),
            deny_reason: None,
            policy_checksum: "ck".into(),
            policy_rule: None,
            dlc_admission: "unprovisioned".into(),
            lockdown_active: false,
            decision_sequence: Some(1),
            extensions: Map::new(),
            prev_hash: "prev".into(),
            // The receipt binds this; give each a distinct value so the distinct
            // count is meaningful.
            hash: hash.into(),
            signature: String::new(),
        }
    }

    fn receipt(
        key: &SigningKey,
        session: &str,
        op: &str,
        verdict: &str,
        hash: &str,
    ) -> MediationReceipt {
        MediationReceipt::issue(
            &art12_record(session, op, verdict, hash),
            "spiffe://demo/mediator/pod-1",
            0,
            "software",
            key,
        )
    }

    fn write_log(dir: &tempfile::TempDir, receipts: &[MediationReceipt]) -> std::path::PathBuf {
        let path = dir.path().join("receipts.jsonl");
        let mut f = File::create(&path).unwrap();
        for r in receipts {
            writeln!(f, "{}", serde_json::to_string(r).unwrap()).unwrap();
        }
        path
    }

    #[test]
    fn a_well_formed_log_verifies_and_tallies_what_it_saw() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let log = write_log(
            &dir,
            &[
                receipt(&key, "s1", "run_bash", "allow", "h1"),
                receipt(&key, "s1", "run_bash", "deny", "h2"),
            ],
        );
        let report = verify_receipt_log(&log, Some(&key.verifying_key())).unwrap();
        assert_eq!(report.receipts, 2);
        assert_eq!(report.verified, 2);
        assert!(report.failures.is_empty());
        assert!(report.signatures_checked);
        assert_eq!(report.verdicts.get("allow"), Some(&1));
        assert_eq!(report.verdicts.get("deny"), Some(&1));
        assert_eq!(report.distinct_record_hashes, 2);
        assert_eq!(report.sessions.get("s1"), Some(&2));
        assert_eq!(
            report.mediators.get("spiffe://demo/mediator/pod-1"),
            Some(&2)
        );
    }

    /// **The tamper case.** A receipt whose bound fields were altered after
    /// signing must fail to verify — this is the whole reason the receipt is
    /// signed. Editing the verdict changes the preimage; the signature no longer
    /// covers it.
    #[test]
    fn a_forged_receipt_is_reported_as_a_failure_not_silently_counted() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut r = receipt(&key, "s1", "run_bash", "deny", "h1");
        // Flip the verdict a relying party would read, WITHOUT re-signing.
        r.verdict = "allow".into();
        let log = write_log(&dir, &[r]);
        let report = verify_receipt_log(&log, Some(&key.verifying_key())).unwrap();
        assert_eq!(report.receipts, 1);
        assert_eq!(report.verified, 0);
        assert_eq!(
            report.failures.len(),
            1,
            "the forged receipt must be flagged"
        );
        assert_eq!(report.failures[0].line, 1);
    }

    /// A receipt signed by another key must not pass under the mediator we asked
    /// about — otherwise "verified" would mean only "someone signed", which the
    /// pod can already do for itself.
    #[test]
    fn a_receipt_from_another_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let real = SigningKey::from_bytes(&[7u8; 32]);
        let impostor = SigningKey::from_bytes(&[9u8; 32]);
        let log = write_log(&dir, &[receipt(&impostor, "s1", "run_bash", "allow", "h1")]);
        let report = verify_receipt_log(&log, Some(&real.verifying_key())).unwrap();
        assert_eq!(report.verified, 0);
        assert_eq!(report.failures.len(), 1);
    }

    /// Without a key, receipts are tallied but signatures are unchecked — and the
    /// report must not let that pass as the same thing as verification.
    #[test]
    fn without_a_key_signatures_are_not_checked_and_the_report_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let log = write_log(&dir, &[receipt(&key, "s1", "run_bash", "allow", "h1")]);
        let report = verify_receipt_log(&log, None).unwrap();
        assert_eq!(report.receipts, 1);
        assert_eq!(report.verified, 0);
        assert!(
            report.failures.is_empty(),
            "unchecked is not the same as failed"
        );
        assert!(!report.signatures_checked);
        assert!(
            report
                .limitations
                .iter()
                .any(|l| l.contains("signatures were NOT checked")),
            "an unverified tally must say so in the artifact, not only in the exit code"
        );
    }

    /// **The scoreboard can never claim more than it checked.** The self-vouching
    /// limitation is the one that matters most here (a receipt is the mediator's
    /// own word); it must be present on every run, passing or not.
    #[test]
    fn a_passing_report_still_carries_the_self_vouching_limitation() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let log = write_log(&dir, &[receipt(&key, "s1", "run_bash", "allow", "h1")]);
        let report = verify_receipt_log(&log, Some(&key.verifying_key())).unwrap();
        assert!(report.failures.is_empty());
        assert!(
            report.limitations.iter().any(|l| l.contains("OWN WORD")),
            "the self-vouching caveat must be present even on a clean run"
        );
        assert!(
            report.limitations.iter().any(|l| l.contains("witnessed")),
            "the lineage-inclusion caveat must be present"
        );
    }

    /// An empty file verifies vacuously — the report must make that legible rather
    /// than reading like a clean, active session.
    #[test]
    fn an_empty_log_reports_zero_rather_than_success() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let log = write_log(&dir, &[]);
        let report = verify_receipt_log(&log, Some(&key.verifying_key())).unwrap();
        assert_eq!(report.receipts, 0);
        assert_eq!(report.verified, 0);
        assert_eq!(report.distinct_record_hashes, 0);
    }

    /// Distinct record hashes are counted, not double-counted: two receipts over
    /// the SAME record hash are two receipts but one recorded decision.
    #[test]
    fn distinct_record_hashes_dedupe_repeated_receipts() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let log = write_log(
            &dir,
            &[
                receipt(&key, "s1", "run_bash", "allow", "same"),
                receipt(&key, "s1", "run_bash", "allow", "same"),
            ],
        );
        let report = verify_receipt_log(&log, Some(&key.verifying_key())).unwrap();
        assert_eq!(report.receipts, 2);
        assert_eq!(report.distinct_record_hashes, 1);
    }

    /// A malformed line is corruption of a file we wrote, and aborts with its line
    /// number rather than being silently skipped.
    #[test]
    fn a_malformed_line_aborts_with_its_line_number() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipts.jsonl");
        let mut f = File::create(&path).unwrap();
        writeln!(f, "{{not valid json").unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let err = verify_receipt_log(&path, Some(&key.verifying_key())).unwrap_err();
        assert!(
            matches!(err, AuditError::Json { line: 1, .. }),
            "got: {err}"
        );
    }
}
