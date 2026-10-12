//! Independent verification of an EU AI Act Article 12 record-keeping log.
//!
//! # What the log is
//!
//! `nucleus-tool-proxy --art12-log` appends one hash-chained [`Art12Record`]
//! per kernel decision — allows, refusals and deferrals alike — each signed with
//! Ed25519 by the tool-proxy's audit signer, the key that signs its audit log
//! (#3309). This reads that file back and checks it through the same
//! declaration the writer used (`portcullis::art12_record`), reconstructing each
//! preimage from the record's own fields rather than by re-serialising (JSON key
//! order and escaping are not stable across serde versions, and a verifier that
//! re-serialises to check a hash is checking its own serialiser).
//!
//! # What a pass means
//!
//! The per-record check is [`crate::signed_chain`]'s, the one `verify` uses for
//! the audit log (ADR 0007 G-1):
//!
//! - A **signed** record passes only under a signer the caller pinned:
//!   `--signer-pubkey` (the `NUCLEUS-AUDIT-SIGNER` key the proxy printed at
//!   boot), or an executor attestation (`--attestation` with
//!   `--executor-pubkey`), whose signed chain head commits to every record's
//!   signer. A record signed by a key nothing pins is refused.
//! - A **legacy** record (an HMAC, written before #3309) passes only against a
//!   non-empty `--secret`, and is counted as legacy. With no secret, or an empty
//!   one, it is refused by name (`LegacyMacUnkeyed`): before #3376 a pod with no
//!   operator key MAC'd its log under a key derived from the public session id,
//!   which anyone can compute. A legacy record after a signed one is a
//!   downgrade and is refused.
//!
//! # What verification does not prove
//!
//! A verifier that answered only "valid / invalid" would let a reader infer far
//! more than was checked, so the report carries its limitations as data and the
//! CLI prints them. Specifically:
//!
//! * A passing chain shows **no party lacking the signing key** altered the
//!   file. The key is the tool-proxy's own, generated in the pod, so it does not
//!   show the key's holder did not rewrite history. Only a signature over the
//!   chain head by a key the pod does not possess (the executor attestation)
//!   can do that.
//! * Completeness is not verifiable from the artifact. A chain proves the
//!   records present are consecutive and unaltered; it cannot prove the process
//!   was running, or that it recorded every decision it made. `dropped` on the
//!   writer and the runtime's own degraded-refusal are what bound that, and they
//!   live outside this file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use portcullis::art12_record::{ART12_SCHEMA_VERSION, Art12Attestation, Art12Record};
use serde::Serialize;

use crate::AuditError;
use crate::signed_chain::{Pins, Tally};

#[derive(clap::Subcommand, Debug)]
pub(crate) enum Command {
    /// Verify an EU AI Act Article 12 record-keeping log.
    ///
    /// Checks sequence continuity, hash chaining, and each record's Ed25519
    /// signature under a pinned signer (#3309); legacy HMAC records verify only
    /// against a non-empty secret. Prints what was established AND what was not
    /// — a chain proves no party lacking the signing key altered the file, not
    /// that the log is complete or that the key's holder did not rewrite it.
    #[command(mut_args = |a| a.hide_env_values(true))]
    VerifyArt12 {
        /// Path to the JSONL Article 12 log.
        #[arg(long)]
        log: PathBuf,
        /// A key the log may be signed by (64 hex characters): what the proxy
        /// printed as `NUCLEUS-AUDIT-SIGNER` at boot. Repeat it for a log that a
        /// restarted proxy continued under a new key.
        #[arg(long = "signer-pubkey")]
        signer_pubkeys: Vec<String>,
        /// Secret for LEGACY records only (written before #3309), which carry
        /// an HMAC. An empty secret is refused: it authenticates nothing.
        #[arg(long, env = "NUCLEUS_ART12_SECRET")]
        secret: Option<String>,
        /// Emit the report as JSON instead of text.
        #[arg(long)]
        json: bool,
        /// Executor attestation JSON, as sent with the session-complete receipt.
        ///
        /// Supplying it (with --executor-pubkey) pins the chain head, and with
        /// it every record's signer, under a key the pod never holds: that is
        /// what turns "no third party altered this file" into evidence about
        /// the pod.
        #[arg(long, requires = "executor_pubkey")]
        attestation: Option<PathBuf>,
        /// The executor's Ed25519 public key, hex-encoded (32 bytes).
        #[arg(long, requires = "attestation")]
        executor_pubkey: Option<String>,
        /// Require every record to be decided under this certificate fingerprint
        /// (hex): the pod's `fingerprint` in the node's `authority.json` (#2437).
        #[arg(long)]
        authority_fingerprint: Option<String>,
    },
}

/// The flags that pin this log's signer, named when none was given.
const HOW_TO_PIN: &str = "--signer-pubkey (the NUCLEUS-AUDIT-SIGNER key the proxy printed at \
                          boot) or --attestation with --executor-pubkey (the node's signature \
                          over the chain head)";

/// The limitation an executor attestation lifts. One constant, so the report
/// that states it and the CLI that lifts it name the same text.
pub(crate) const KEY_HOLDER_LIMITATION: &str = "A valid chain shows no party WITHOUT the signing key altered this file. The key is the \
     tool-proxy's own, generated in the pod, so it does not show that the key's holder (the \
     proxy, or root in its pod) did not rewrite history. Supply --attestation and \
     --executor-pubkey to close that: the executor key is one the pod never holds.";

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
    /// Whether any signature was checked. Every record's is, or the run fails,
    /// so this is false only for an empty log.
    pub signatures_checked: bool,
    /// Records Ed25519-signed under a pinned signer.
    pub signed: u64,
    /// Legacy HMAC records, checked against the given secret.
    pub legacy: u64,
    /// The distinct signers named, in first-seen order.
    pub signers: Vec<String>,
    /// Whether an executor attestation was checked against the computed head.
    pub attestation_checked: bool,
    /// How many records name the certificate they were decided under
    /// (`authority.fingerprint`, #2437). A pod created since the certificate
    /// convergence binds every record; a shortfall is listed as a limitation.
    pub authority_bound: u64,
    /// The distinct certificate fingerprints named, in first-seen order. One
    /// per session is the expected shape: a pod holds one certificate.
    pub authority_fingerprints: Vec<String>,
    /// What this run did NOT establish. Never empty.
    pub limitations: Vec<String>,
}

/// What the caller trusts for this log: signer keys, the head an executor
/// attestation vouched for (already checked by [`attested_head`]), and a
/// secret for legacy records.
///
/// # Errors
/// A signer that is not a 32-byte hex Ed25519 key.
pub(crate) fn pins(
    signers: &[String],
    attested_head: Option<String>,
    legacy_secret: Option<String>,
) -> Result<Pins, AuditError> {
    Pins::parse(signers, attested_head, legacy_secret, HOW_TO_PIN)
}

/// Check an executor attestation's own signature, and return the chain head it
/// vouches for, to pin with [`pins`].
///
/// # What this closes
///
/// A passing chain means "no party lacking the signing key altered this file",
/// which says nothing about the pod that holds the key. The executor key lives
/// on the node and the pod never sees it, so a pod that rewrites its log
/// produces a different head and cannot forge a signature over the new one. The
/// head this returns is compared to the head computed from the log by
/// [`verify_art12_log`]: a valid signature over a head that is not this log's
/// proves only that some other log was attested.
///
/// # Errors
/// An unknown attestation kind, or a signature that does not verify.
pub fn attested_head(
    att: &Art12Attestation,
    executor_pubkey: &VerifyingKey,
) -> Result<String, AuditError> {
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
    Ok(att.chain_head.clone())
}

/// The limitations that hold for every run, stated as data so a consumer cannot
/// render a report without them.
fn base_limitations() -> Vec<String> {
    vec![
        KEY_HOLDER_LIMITATION.to_string(),
        "Completeness is not verifiable from this artifact: the chain shows the records present \
         are consecutive and unaltered, not that every decision made was recorded."
            .to_string(),
    ]
}

/// Verify a JSONL Article 12 log against `pins`.
///
/// # Errors
/// The first record that fails to parse, chain, or verify, naming its line;
/// and a log that does not end at the head `pins` names.
pub(crate) fn verify_art12_log(path: &Path, pins: &Pins) -> Result<Art12Report, AuditError> {
    let mut lines = crate::record_lines::open(path)?;

    let mut prev_hash: Option<String> = None;
    let mut tally = Tally::default();
    let mut report = Art12Report {
        records: 0,
        chain_head: String::new(),
        first_timestamp: None,
        last_timestamp: None,
        identified_actors: 0,
        verdicts: BTreeMap::new(),
        signatures_checked: false,
        signed: 0,
        legacy: 0,
        signers: Vec::new(),
        attestation_checked: false,
        authority_bound: 0,
        authority_fingerprints: Vec::new(),
        limitations: base_limitations(),
    };

    // The sequence number each record must carry, counted from 1.
    for (expected_seq, item) in (1_u64..).zip(&mut lines) {
        let (line_no, line) = item?;
        let rec: Art12Record = crate::record_lines::parse(line_no, &line)?;
        let invalid = |message: String| AuditError::Invalid {
            line: line_no,
            message,
        };

        if rec.schema_version != ART12_SCHEMA_VERSION {
            return Err(invalid(format!(
                "schema version {} but this verifier understands {ART12_SCHEMA_VERSION}; \
                 refusing rather than checking fields that may have moved",
                rec.schema_version
            )));
        }

        if rec.seq != expected_seq {
            return Err(invalid(format!(
                "sequence gap: expected {expected_seq}, got {}. A gap means records are \
                 missing or reordered, which is the failure an Article 12 log exists to make \
                 visible",
                rec.seq
            )));
        }

        // The first record chains from the writer's genesis anchor, which this
        // verifier does not know (it is inside the first record's signed bytes);
        // from the second on, the chain is checked.
        if let Some(prev) = &prev_hash
            && &rec.prev_hash != prev
        {
            return Err(invalid(format!(
                "prev_hash mismatch (expected {prev}, got {}) -- the chain is broken here",
                rec.prev_hash
            )));
        }

        // Recompute from the record's OWN fields. Any tampered field changes the
        // preimage and so the hash.
        let form = rec.form().map_err(|e| invalid(e.to_string()))?;
        let computed = rec.chain_hash().map_err(|e| invalid(e.to_string()))?;
        if computed != rec.hash {
            return Err(invalid(
                "hash does not match the record's fields -- this record was modified".to_string(),
            ));
        }
        let bytes = rec.signed_bytes().map_err(|e| invalid(e.to_string()))?;
        pins.check(line_no, form, &bytes, &rec.signature, &mut tally)?;

        report.records += 1;
        if let Some(fp) = rec.authority_fingerprint() {
            report.authority_bound += 1;
            if !report.authority_fingerprints.iter().any(|f| f == fp) {
                report.authority_fingerprints.push(fp.to_string());
            }
        }
        report.first_timestamp.get_or_insert(rec.timestamp_unix);
        report.last_timestamp = Some(rec.timestamp_unix);
        if rec.actor.spiffe_id.as_ref().is_some_and(|s| !s.is_empty()) {
            report.identified_actors += 1;
        }
        *report.verdicts.entry(rec.verdict.clone()).or_insert(0) += 1;

        prev_hash = Some(rec.hash.clone());
    }
    lines.finish(usize::try_from(report.records).unwrap_or(usize::MAX))?;

    report.chain_head = prev_hash.unwrap_or_default();
    pins.check_head(&report.chain_head, "the executor attestation")?;
    report.signatures_checked = report.records > 0;
    report.signed = u64::try_from(tally.signed).unwrap_or(u64::MAX);
    report.legacy = u64::try_from(tally.legacy).unwrap_or(u64::MAX);
    report.signers = tally.signers;
    if report.legacy > 0 {
        report.limitations.push(format!(
            "{} of {} records are legacy HMAC records (written before #3309). A MAC shows only \
             that no party WITHOUT that secret altered them, and a pod that derived its own \
             secret, or held one the workload could read, could have written them.",
            report.legacy, report.records
        ));
    }
    if report.authority_bound < report.records {
        report.limitations.push(format!(
            "{} of {} records name no authority (no `authority.fingerprint`): they cannot be tied \
             to the certificate — and so the root key — that authorized the deciding kernel. \
             Expected only for pods created before the node issued certificates.",
            report.records - report.authority_bound,
            report.records
        ));
    }
    Ok(report)
}

/// Require every record to have been decided under exactly `expected_hex` —
/// the fingerprint of the certificate the node issued this pod (from its
/// `pods/<id>/authority.json`). This is what ties a log to the root public
/// key with no side channel: the node verified that chain against its root
/// when it issued it, and every record here names it inside the signed
/// preimage.
///
/// # Errors
/// If any record names no authority, or any names a different one.
pub fn require_authority(report: &Art12Report, expected_hex: &str) -> Result<(), AuditError> {
    if report.authority_bound != report.records {
        return Err(AuditError::Invalid {
            line: 0,
            message: format!(
                "{} of {} records name no authority; --authority-fingerprint requires every record \
                 to be bound",
                report.records - report.authority_bound,
                report.records
            ),
        });
    }
    let expected = expected_hex.trim().to_ascii_lowercase();
    if let Some(other) = report
        .authority_fingerprints
        .iter()
        .find(|fp| fp.to_ascii_lowercase() != expected)
    {
        return Err(AuditError::Invalid {
            line: 0,
            message: format!(
                "a record names authority {other}, not the expected {expected} -- it was decided \
                 under a certificate this node did not issue to this pod"
            ),
        });
    }
    Ok(())
}

/// Parse `--executor-pubkey` (32 hex-encoded bytes) into a verifying key.
///
/// # Errors
/// If the hex is not 32 bytes or is not a valid Ed25519 point.
pub fn executor_pubkey_from_hex(
    pubkey_hex: &str,
) -> Result<ed25519_dalek::VerifyingKey, AuditError> {
    let key_bytes: [u8; 32] = hex::decode(pubkey_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| AuditError::Invalid {
            line: 0,
            message: "--executor-pubkey must be 32 hex-encoded bytes".to_string(),
        })?;
    ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|_| AuditError::Invalid {
        line: 0,
        message: "--executor-pubkey is not a valid Ed25519 public key".to_string(),
    })
}

/// Apply `--authority-fingerprint`, when given: every record must be bound to
/// it ([`require_authority`]), after which the "name no authority" limitation
/// no longer applies.
///
/// # Errors
/// Those of [`require_authority`].
pub fn apply_authority_requirement(
    report: &mut Art12Report,
    expected_hex: Option<&str>,
) -> Result<(), AuditError> {
    let Some(expected) = expected_hex else {
        return Ok(());
    };
    require_authority(report, expected)?;
    report
        .limitations
        .retain(|l| !l.contains("name no authority"));
    Ok(())
}

impl Command {
    pub(crate) fn run(self) -> Result<(), AuditError> {
        let Self::VerifyArt12 {
            log,
            signer_pubkeys,
            secret,
            json,
            attestation,
            executor_pubkey,
            authority_fingerprint,
        } = self;
        // The attestation's own signature first: the head it vouches for is a
        // pin only once a key the pod never held is known to have signed it.
        let attested = match (attestation, executor_pubkey) {
            (Some(att_path), Some(pubkey_hex)) => {
                let att: Art12Attestation =
                    serde_json::from_str(&std::fs::read_to_string(&att_path)?)
                        .map_err(|e| AuditError::Json { line: 0, source: e })?;
                Some(attested_head(
                    &att,
                    &executor_pubkey_from_hex(&pubkey_hex)?,
                )?)
            }
            _ => None,
        };
        let attestation_checked = attested.is_some();
        let pins = pins(&signer_pubkeys, attested, secret)?;
        let mut report = verify_art12_log(&log, &pins)?;
        apply_authority_requirement(&mut report, authority_fingerprint.as_deref())?;
        if attestation_checked {
            report.attestation_checked = true;
            report.limitations.retain(|l| l != KEY_HOLDER_LIMITATION);
            report.limitations.push(
                "The executor attestation binds this log's HEAD, not its content: a pod that \
                 recorded nothing would export a validly signed empty log."
                    .to_string(),
            );
        }
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .map_err(|e| AuditError::Json { line: 0, source: e })?
            );
            return Ok(());
        }
        let yes_no = |b: bool| if b { "yes" } else { "NO" };
        println!("Article 12 log: {}", log.display());
        println!("  records:            {}", report.records);
        println!("  chain head:         {}", report.chain_head);
        println!(
            "  signatures checked: {} ({} signed, {} legacy)",
            yes_no(report.signatures_checked),
            report.signed,
            report.legacy
        );
        for s in &report.signers {
            println!("  signer:             {s}");
        }
        println!(
            "  identified actors:  {} of {}",
            report.identified_actors, report.records
        );
        println!(
            "  executor attested:  {}",
            yes_no(report.attestation_checked)
        );
        for (verdict, n) in &report.verdicts {
            println!("  verdict {verdict:<18} {n}");
        }
        // Printed, not appended as a footnote a reader may skip: the point of
        // the list is that "verified" is narrower than it sounds.
        println!("\n  This run did NOT establish:");
        for l in &report.limitations {
            println!("    - {l}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use hmac::{Hmac, Mac, digest::KeyInit};
    use portcullis::art12_record::{
        ART12_ATTESTATION_KIND, Actor, DenyInfo, art12_attestation_preimage,
    };
    use std::fs::File;
    use std::io::Write;

    const SECRET: &[u8] = b"operator-held-secret";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[1; 32])
    }

    fn hex_key(k: &SigningKey) -> String {
        hex::encode(k.verifying_key().to_bytes())
    }

    fn draft(seq: u64, prev_hash: &str, verdict: &str) -> Art12Record {
        Art12Record {
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
            sig_alg: None,
            signer: None,
        }
    }

    /// A record signed by `k` exactly as the writer seals one.
    fn signed_by(k: &SigningKey, seq: u64, prev_hash: &str, verdict: &str) -> Art12Record {
        let unsigned = draft(seq, prev_hash, verdict).to_be_signed_by(hex_key(k));
        let sig = hex::encode(k.sign(&unsigned.signed_bytes().unwrap()).to_bytes());
        unsigned.with_signature(sig).unwrap()
    }

    fn record(seq: u64, prev_hash: &str, verdict: &str) -> Art12Record {
        signed_by(&key(), seq, prev_hash, verdict)
    }

    /// A legacy record exactly as the pre-#3309 writer made it: HMAC over the
    /// canonical preimage under `secret`, hash over the preimage.
    fn legacy(secret: &[u8], seq: u64, prev_hash: &str, verdict: &str) -> Art12Record {
        let rec = draft(seq, prev_hash, verdict);
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret).unwrap();
        mac.update(rec.canonical_preimage().as_bytes());
        rec.with_signature(hex::encode(mac.finalize().into_bytes()))
            .unwrap()
    }

    fn pinned() -> Pins {
        pins(&[hex_key(&key())], None, None).unwrap()
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

    /// A crash mid-append leaves the last record without its newline: the records
    /// before it verify and the tear is a torn tail. The same bytes followed by a
    /// newline, mid-log, are an altered line.
    #[test]
    fn a_torn_tail_and_an_altered_line_are_different_failures() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a12.jsonl");
        let r1 = record(1, "art12-genesis:sess", "allow");
        let r2 = record(2, &r1.hash, "deny");
        let (l1, l2) = (
            serde_json::to_string(&r1).unwrap(),
            serde_json::to_string(&r2).unwrap(),
        );
        let torn = &l2[..l2.len() / 2];
        std::fs::write(&path, format!("{l1}\n{torn}")).unwrap();
        let err = verify_art12_log(&path, &pinned()).unwrap_err();
        assert!(
            matches!(
                err,
                AuditError::TornTail {
                    line: 2,
                    verified: 1
                }
            ),
            "got: {err}"
        );
        std::fs::write(&path, format!("{l1}\n{torn}\n{l2}\n")).unwrap();
        let err = verify_art12_log(&path, &pinned()).unwrap_err();
        assert!(
            matches!(err, AuditError::NotARecord { line: 2, .. }),
            "got: {err}"
        );
    }

    #[test]
    fn a_well_formed_log_verifies_and_reports_what_it_saw() {
        let dir = tempfile::tempdir().unwrap();
        let report = verify_art12_log(&valid_log(&dir), &pinned()).expect("should verify");
        assert_eq!(report.records, 2);
        assert!(report.signatures_checked);
        assert_eq!((report.signed, report.legacy), (2, 0));
        assert_eq!(report.signers, vec![hex_key(&key())]);
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
        let report = verify_art12_log(&valid_log(&dir), &pinned()).unwrap();
        assert!(
            report
                .limitations
                .iter()
                .any(|l| l == KEY_HOLDER_LIMITATION),
            "the key-holder limitation is the one that matters most; it must be present"
        );
        assert!(
            report
                .limitations
                .iter()
                .any(|l| l.contains("Completeness")),
            "a chain does not prove the log is complete, and the report must say so"
        );
    }

    /// #3309, A-19: a record forged by a party holding NO key is rejected in
    /// every shape it can take. Under the MAC scheme each of these verified:
    /// the forger computed the MAC under the key it could derive (the public
    /// session id before #3376) or the empty key, and a verifier given that key
    /// — or no key at all, which checked only the hash chain — reported the log
    /// verified.
    #[test]
    fn a_record_forged_without_the_key_is_rejected() {
        let forger = SigningKey::from_bytes(&[66; 32]);
        let dir = tempfile::tempdir().unwrap();
        let first = record(1, "art12-genesis:sess", "deny");

        // A whole log MAC'd under a key anyone can compute, with no secret
        // given (the old hash-chain-only mode), or the empty one.
        let a = legacy(b"art12:sess", 1, "art12-genesis:sess", "allow");
        let b = legacy(b"art12:sess", 2, &a.hash, "allow");
        let path = write_log(&dir, &[a, b]);
        for secret in [None, Some(""), Some("  ")] {
            let err =
                verify_art12_log(&path, &pins(&[], None, secret.map(str::to_string)).unwrap())
                    .unwrap_err();
            assert!(
                matches!(err, AuditError::LegacyMacUnkeyed { line: 1, .. }),
                "{err}"
            );
        }

        // A legacy record appended after a signed one: a downgrade, refused
        // even when the verifier holds the legacy secret the forger used.
        let downgrade = legacy(SECRET, 2, &first.hash, "allow");
        let path = write_log(&dir, &[first.clone(), downgrade]);
        let s = String::from_utf8(SECRET.to_vec()).unwrap();
        let err =
            verify_art12_log(&path, &pins(&[hex_key(&key())], None, Some(s)).unwrap()).unwrap_err();
        assert!(err.to_string().contains("downgrade"), "{err}");

        // A record claiming the pinned signer, signed by the forger.
        let claims_key = {
            let mut rec = signed_by(&forger, 2, &first.hash, "allow");
            rec.signer = first.signer.clone();
            let forged = std::mem::take(&mut rec.signature);
            rec.with_signature(forged).unwrap()
        };
        let path = write_log(&dir, &[first.clone(), claims_key]);
        let err = verify_art12_log(&path, &pinned()).unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");

        // A record signed under the forger's own key, named honestly.
        let own_key = signed_by(&forger, 2, &first.hash, "allow");
        let path = write_log(&dir, &[first.clone(), own_key]);
        let err = verify_art12_log(&path, &pinned()).unwrap_err();
        assert!(err.to_string().contains("not a pinned"), "{err}");
        // Pinned by the executor-attested head instead: the forged record moved it.
        let by_head = pins(&[], Some(first.hash.clone()), None).unwrap();
        let err = verify_art12_log(&path, &by_head).unwrap_err();
        assert!(err.to_string().contains("rewritten after"), "{err}");
        // And with nothing pinned, the forger's own key is not trusted.
        let err = verify_art12_log(&path, &pins(&[], None, None).unwrap()).unwrap_err();
        assert!(
            matches!(err, AuditError::UnpinnedSigner { line: 1, .. }),
            "{err}"
        );

        let path = write_log(&dir, &[first]);
        assert_eq!(verify_art12_log(&path, &pinned()).unwrap().signed, 1);
    }

    /// A legacy log with a real secret still verifies, counted as legacy and
    /// with the limitation that says what a MAC does not show; a signed segment
    /// may follow it.
    #[test]
    fn a_legacy_log_with_its_secret_verifies_as_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let a = legacy(SECRET, 1, "art12-genesis:sess", "allow");
        let b = legacy(SECRET, 2, &a.hash, "deny");
        let c = record(3, &b.hash, "allow");
        let path = write_log(&dir, &[a, b, c]);
        let s = String::from_utf8(SECRET.to_vec()).unwrap();
        let report =
            verify_art12_log(&path, &pins(&[hex_key(&key())], None, Some(s)).unwrap()).unwrap();
        assert_eq!((report.legacy, report.signed), (2, 1));
        assert!(
            report.limitations.iter().any(|l| l.contains("legacy HMAC")),
            "{:?}",
            report.limitations
        );
    }

    /// **The tamper sweep.** Every field must break verification when changed.
    /// A field that does not appear here is one an attacker can rewrite for free.
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
            ("prev_hash", |r| r.prev_hash = "elsewhere".into()),
            ("signer", |r| r.signer = Some("cd".repeat(32))),
        ];

        for (field, mutate) in mutations {
            let dir = tempfile::tempdir().unwrap();
            let mut r1 = record(1, "art12-genesis:sess", "deny");
            mutate(&mut r1);
            // Hash and signature deliberately NOT recomputed: this is tampering,
            // not authoring.
            let path = write_log(&dir, &[r1.clone()]);
            assert!(
                verify_art12_log(&path, &pinned()).is_err(),
                "tampering with `{field}` was not detected"
            );
            // Nor when the tamperer recomputes the hash: only the signature,
            // which they cannot make, stops it.
            let rehashed = r1.clone().with_signature(r1.signature.clone()).unwrap();
            let path = write_log(&dir, &[rehashed]);
            assert!(
                verify_art12_log(&path, &pinned()).is_err(),
                "tampering with `{field}` and re-hashing was not detected -- it is unsigned"
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
        assert!(verify_art12_log(&path, &pinned()).is_ok());
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
        let err = verify_art12_log(&path, &pinned()).unwrap_err();
        assert!(
            format!("{err}").contains("sequence gap"),
            "a removed record must be reported as a gap, got: {err}"
        );
    }

    /// Re-chaining after a deletion still fails, because the surviving records'
    /// `seq` and `prev_hash` cannot be repaired without re-signing them.
    #[test]
    fn a_rechained_deletion_still_fails_without_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let r1 = record(1, "art12-genesis:sess", "allow");
        let r2 = record(2, &r1.hash, "deny");
        let mut r3 = record(3, &r2.hash, "allow");
        // Attacker renumbers r3 to seq 2, points it at r1 and re-hashes, but
        // cannot re-sign.
        r3.seq = 2;
        r3.prev_hash = r1.hash.clone();
        let r3 = r3.clone().with_signature(r3.signature.clone()).unwrap();
        let path = write_log(&dir, &[r1, r3]);
        assert!(verify_art12_log(&path, &pinned()).is_err());
    }

    /// A schema the verifier does not understand is refused rather than checked
    /// against fields that may have moved.
    #[test]
    fn an_unknown_schema_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut r1 = record(1, "art12-genesis:sess", "allow");
        r1.schema_version = ART12_SCHEMA_VERSION + 1;
        let path = write_log(&dir, &[r1]);
        let err = verify_art12_log(&path, &pinned()).unwrap_err();
        assert!(format!("{err}").contains("schema version"), "got: {err}");
    }

    /// An empty log verifies vacuously — and the report must make that legible
    /// rather than looking like a clean session.
    #[test]
    fn an_empty_log_reports_zero_rather_than_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_log(&dir, &[]);
        let report = verify_art12_log(&path, &pinned()).unwrap();
        assert_eq!(report.records, 0);
        assert!(!report.signatures_checked);
        assert!(report.chain_head.is_empty());
    }

    // ── executor attestation ────────────────────────────────────────────────

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

    /// The happy path: the executor attested the head this log actually
    /// computes, and that alone pins the signer.
    #[test]
    fn an_attestation_over_the_computed_head_pins_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = valid_log(&dir);
        let head = verify_art12_log(&path, &pinned()).unwrap().chain_head;
        let exec = SigningKey::from_bytes(&[3u8; 32]);
        let attested = attested_head(&attest(&head, &exec), &exec.verifying_key()).unwrap();
        let report = verify_art12_log(&path, &pins(&[], Some(attested), None).unwrap()).unwrap();
        assert_eq!(report.signed, 2);
    }

    /// **The property the export exists for.** A pod that rewrites its log after
    /// being attested produces a different head, and cannot re-sign.
    #[test]
    fn a_log_rewritten_after_attestation_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        let exec = SigningKey::from_bytes(&[3u8; 32]);
        // Attested when the log ended at some earlier head.
        let attested = attested_head(
            &attest("the-head-that-was-attested", &exec),
            &exec.verifying_key(),
        )
        .unwrap();
        let err = verify_art12_log(&valid_log(&dir), &pins(&[], Some(attested), None).unwrap())
            .unwrap_err();
        assert!(format!("{err}").contains("rewritten after"), "got: {err}");
    }

    /// A signature from the wrong key must not pass — otherwise the attestation
    /// proves only that SOMEONE signed, which is what the pod can already do.
    #[test]
    fn an_attestation_from_another_key_is_rejected() {
        let real = SigningKey::from_bytes(&[3u8; 32]);
        let impostor = SigningKey::from_bytes(&[4u8; 32]);
        let err = attested_head(&attest("h", &impostor), &real.verifying_key()).unwrap_err();
        assert!(format!("{err}").contains("does not verify"), "got: {err}");
    }

    /// Both halves are required. A signature valid over ANOTHER log's head must
    /// not pass for this one — that is the substitution attack.
    #[test]
    fn a_valid_signature_over_a_different_log_does_not_pass() {
        let dir = tempfile::tempdir().unwrap();
        let exec = SigningKey::from_bytes(&[3u8; 32]);
        let other = record(1, "art12-genesis:other", "allow");
        // The signature itself is perfectly valid...
        let attested = attested_head(&attest(&other.hash, &exec), &exec.verifying_key()).unwrap();
        // ...but not for this log.
        assert!(
            verify_art12_log(&valid_log(&dir), &pins(&[], Some(attested), None).unwrap()).is_err()
        );
    }

    /// An unknown attestation kind is refused rather than field-guessed.
    #[test]
    fn an_unknown_attestation_kind_is_refused() {
        let exec = SigningKey::from_bytes(&[3u8; 32]);
        let mut att = attest("h", &exec);
        att.kind = "something-else-v9".into();
        let err = attested_head(&att, &exec.verifying_key()).unwrap_err();
        assert!(
            format!("{err}").contains("unknown attestation kind"),
            "got: {err}"
        );
    }

    fn report_with(records: u64, bound: u64, fingerprints: &[&str]) -> Art12Report {
        Art12Report {
            records,
            chain_head: String::new(),
            first_timestamp: None,
            last_timestamp: None,
            identified_actors: 0,
            verdicts: BTreeMap::new(),
            signatures_checked: false,
            signed: 0,
            legacy: 0,
            signers: Vec::new(),
            attestation_checked: false,
            authority_bound: bound,
            authority_fingerprints: fingerprints.iter().map(|s| s.to_string()).collect(),
            limitations: vec!["N of M records name no authority".to_string()],
        }
    }

    /// #2437: `--authority-fingerprint` passes only when EVERY record names
    /// exactly that certificate; a partial binding or a foreign fingerprint
    /// fails, and a pass discharges the "name no authority" limitation.
    #[test]
    fn the_authority_requirement_is_all_or_nothing() {
        let mut ok = report_with(3, 3, &["ab"]);
        apply_authority_requirement(&mut ok, Some("AB")).unwrap();
        assert!(ok.limitations.is_empty(), "the limitation is discharged");

        let mut partial = report_with(3, 2, &["ab"]);
        assert!(apply_authority_requirement(&mut partial, Some("ab")).is_err());

        let mut foreign = report_with(3, 3, &["ab", "cd"]);
        assert!(apply_authority_requirement(&mut foreign, Some("ab")).is_err());

        let mut unasked = report_with(3, 0, &[]);
        apply_authority_requirement(&mut unasked, None).unwrap();
        assert_eq!(unasked.limitations.len(), 1, "no flag, no requirement");
    }
}
