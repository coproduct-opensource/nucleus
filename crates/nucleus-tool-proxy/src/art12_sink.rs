//! The Article 12 record-keeping log, on the live decision path.
//!
//! `art12.rs` was landed deliberately unwired — its own module docs say so, and
//! name the removal condition for its `allow(dead_code)`. This is that
//! increment: a [`VerdictSink`] that projects each verdict into an
//! [`Art12Record`] and appends it to the chained log.
//!
//! # Why a sink wrapper
//!
//! The record must exist for **every** decision the runtime makes, including
//! refusals. Putting the projection at a call site would reintroduce the defect
//! #2127 fixed: a refusal returns through `?` before any later step runs. A sink
//! in the chain sees exactly what the chain sees, and there is no path around
//! it — the sink is built by `build_monitored_sink`, which is the only
//! constructor callers can reach.
//!
//! # It fails CLOSED, and that is the point of wiring it
//!
//! `Art12Log` latches `degraded` when a write fails and counts what it dropped.
//! Consulting that in [`preflight`](Art12Sink::preflight) means the NEXT
//! operation is denied before it executes: evidence loss is bounded to the
//! records already lost, rather than continuing silently. An Article 12 log that
//! keeps going after it stops recording is worse than no log, because the gap is
//! invisible in the artifact.
//!
//! Calls whose effect has already happened are not failed retroactively — the
//! latch is read at preflight, not at record.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use portcullis::art12_record::{Actor, Art12Record, DenyInfo};
use portcullis::mediation_receipt::MediationReceipt;
use portcullis::verdict_sink::{
    ActorIdentity, SinkError, VerdictContext, VerdictOutcome, VerdictSink,
};
use portcullis::Operation;

use crate::art12::Art12Log;

/// Opt-in signer that issues a signed [`MediationReceipt`] for each recorded
/// verdict, binding the receipt's `art12_record_hash` to the record's chained
/// hash. Absent ⇒ no receipts are issued (behavior unchanged). Activated only by
/// configuring a mediator signing key; the key VALUE is never logged.
///
/// `signer_assurance` is L0 (self-claimed) by design: the receipt proves only
/// that the mediator key-holder witnessed this record — a relying party still
/// cross-checks that key's SVID is attested (`verify_attested_receipt`).
pub(crate) struct ReceiptSigner {
    mediator_spiffe_id: String,
    signer_assurance: u8,
    signer_backend: String,
    key: SigningKey,
    /// Receipts emitted so far — durable via telemetry and readable in-process.
    pub(crate) emitted: Arc<Mutex<Vec<MediationReceipt>>>,
}

impl ReceiptSigner {
    /// Build from the environment, opt-in and fail-closed:
    /// `NUCLEUS_MEDIATION_SIGNING_KEY` (64 hex chars = a 32-byte ed25519 seed) and
    /// `NUCLEUS_MEDIATION_SPIFFE_ID`. Returns `None` when unset or malformed — a
    /// malformed key is a warn, never the key value.
    pub(crate) fn from_env() -> Option<Self> {
        let key_hex = std::env::var("NUCLEUS_MEDIATION_SIGNING_KEY").ok()?;
        let mediator_spiffe_id = std::env::var("NUCLEUS_MEDIATION_SPIFFE_ID").ok()?;
        let seed = match hex::decode(key_hex.trim()) {
            Ok(b) if b.len() == 32 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(&b);
                s
            }
            _ => {
                tracing::warn!(
                    "NUCLEUS_MEDIATION_SIGNING_KEY is not 32 hex-encoded bytes — \
                     mediation receipts disabled"
                );
                return None;
            }
        };
        Some(Self {
            mediator_spiffe_id,
            signer_assurance: 0,
            signer_backend: "software".to_string(),
            key: SigningKey::from_bytes(&seed),
            emitted: Arc::new(Mutex::new(Vec::new())),
        })
    }
}

/// Why a log path was refused.
#[derive(Debug)]
pub(crate) enum Art12PathError {
    /// The path is inside the agent's workspace.
    InsideWorkspace { path: PathBuf, work_dir: PathBuf },
}

impl std::fmt::Display for Art12PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsideWorkspace { path, work_dir } => write!(
                f,
                "the Article 12 log path {} is inside the agent workspace {} -- the log is the \
                 runtime's record ABOUT this session and must not be in the session's own read \
                 surface (see #2145); choose a host-private path",
                path.display(),
                work_dir.display()
            ),
        }
    }
}

/// Refuse a log path that lands inside the agent's workspace.
///
/// Learned from #2145: `.nucleus-exit-report.json` was written into `work_dir`
/// and the agent's path lattice permitted reading it. The Article 12 log is a
/// strictly richer record of the same kind — every decision, with gate class and
/// deny code — so it must not repeat that. This is checked at startup and
/// refuses to boot rather than warning, because a misconfigured evidence path is
/// not something to discover from an artifact later.
///
/// # Normalising a path that does not exist yet
///
/// The log file has not been created when this runs, so `canonicalize` on it
/// fails — and falling back to the raw path compares an unresolved path against
/// a resolved one. On macOS that alone defeats the check, because the workspace
/// canonicalises `/var/...` to `/private/var/...` and the prefix test then never
/// matches. The first version of this function had exactly that bug and its test
/// caught it; a guard that silently never fires is worse than no guard.
///
/// So: canonicalise the deepest ancestor that DOES exist, then re-attach the
/// remaining components. Both sides end up resolved through the same symlinks.
///
/// This is a guard against misconfiguration, not a defence against a hostile
/// operator — the operator supplies both paths.
pub(crate) fn reject_workspace_path(path: &Path, work_dir: &Path) -> Result<(), Art12PathError> {
    /// Canonicalise as much of `p` as exists, keeping the rest verbatim.
    fn resolve(p: &Path) -> PathBuf {
        if let Ok(c) = p.canonicalize() {
            return c;
        }
        let mut suffix: Vec<std::ffi::OsString> = Vec::new();
        let mut cur = p;
        while let Some(parent) = cur.parent() {
            if let Some(name) = cur.file_name() {
                suffix.push(name.to_os_string());
            }
            if let Ok(c) = parent.canonicalize() {
                let mut out = c;
                for part in suffix.iter().rev() {
                    out.push(part);
                }
                return out;
            }
            cur = parent;
        }
        p.to_path_buf()
    }
    let (p, w) = (resolve(path), resolve(work_dir));
    if p.starts_with(&w) {
        return Err(Art12PathError::InsideWorkspace {
            path: p,
            work_dir: w,
        });
    }
    Ok(())
}

/// Open the Article 12 log for a session, refusing a workspace-local path.
///
/// Lives here rather than in `main.rs` so the startup sequence is one call: the
/// path check, the secret choice and the genesis anchor are a single decision
/// about evidence, and splitting them across a long `main` is how one of them
/// gets edited without the others.
///
/// The secret defaults to a session-derived value when no audit secret is
/// configured. That is weaker than an operator-held secret — a pod that derives
/// its own signing key can re-sign a rewritten chain — and is reported as a
/// limitation by the verifier rather than passed off as tamper-evidence.
pub(crate) fn open_log(
    path: &Path,
    audit_secret: Option<&str>,
    work_dir: &Path,
    session_id: &str,
) -> Result<Arc<Art12Log>, String> {
    reject_workspace_path(path, work_dir).map_err(|e| e.to_string())?;
    let secret = audit_secret.map_or_else(
        || format!("art12:{session_id}").into_bytes(),
        |s| s.as_bytes().to_vec(),
    );
    // A dedicated genesis string rather than a borrowed hash: the audit log is
    // constructed later in startup, and reaching for a value that does not exist
    // yet is how an anchor silently becomes the empty string.
    let genesis = format!("art12-genesis:{session_id}");
    let log = Art12Log::open(path, secret, genesis, false)
        .map_err(|e| format!("failed to open Article 12 log: {e:?}"))?;
    Ok(Arc::new(log))
}

/// The Article 12 log's state, for `/v1/health`.
///
/// `configured: false` says plainly that no log is being kept, rather than
/// leaving a host to infer it from an absent field — the same reason
/// `dlc_admission` reports "unprovisioned" instead of going quiet.
///
/// The chain head is published so a host can tie the log it holds to the process
/// that wrote it. It is a hash of records the runtime made ABOUT this session,
/// not session content.
pub(crate) fn health_json(log: Option<&Arc<Art12Log>>) -> serde_json::Value {
    match log {
        None => serde_json::json!({ "configured": false }),
        Some(log) => {
            let (head, records) = log.head().unwrap_or_else(|_| (String::new(), 0));
            serde_json::json!({
                "configured": true,
                "degraded": log.is_degraded(),
                "records": records,
                "dropped": log.dropped(),
                "chain_head": head,
            })
        }
    }
}

/// Appends an Article 12 record for every verdict, then delegates.
pub(crate) struct Art12Sink {
    inner: Arc<dyn VerdictSink>,
    log: Arc<Art12Log>,
    /// Streams each record to the host as it is produced, when configured.
    ///
    /// The local log stays regardless: it is the fast path and the thing the
    /// chain head is computed over. The shipper is the copy the pod cannot
    /// retract, which is what makes the host's attestation bind something it
    /// observed rather than something the pod reported.
    shipper: Option<Arc<crate::art12_shipper::Art12Shipper>>,
    session_id: String,
    policy_checksum: String,
    dlc_provisioned: bool,
    /// Opt-in: issue a signed `MediationReceipt` per verdict (default `None`).
    receipt_signer: Option<ReceiptSigner>,
}

impl Art12Sink {
    pub(crate) fn new(
        inner: Arc<dyn VerdictSink>,
        log: Arc<Art12Log>,
        session_id: String,
        policy_checksum: String,
        dlc_provisioned: bool,
        shipper: Option<Arc<crate::art12_shipper::Art12Shipper>>,
        receipt_signer: Option<ReceiptSigner>,
    ) -> Self {
        Self {
            inner,
            log,
            shipper,
            session_id,
            policy_checksum,
            dlc_provisioned,
            receipt_signer,
        }
    }

    /// Project a verdict into an Article 12 record draft.
    ///
    /// A total function of the context plus this sink's session fields — no
    /// ambient state, no I/O. Chain fields (`seq`, `prev_hash`, `hash`,
    /// `signature`) are assigned by `Art12Log::append` and left empty here.
    ///
    /// Extracted and public-in-crate so the test asserts on the SAME function
    /// the sink calls, rather than restating what it expects the sink to do.
    pub(crate) fn project(&self, ctx: &VerdictContext) -> Art12Record {
        let ext = |k: &str| ctx.extensions.get(k).cloned();

        let (verdict, deny_reason) = match &ctx.outcome {
            VerdictOutcome::Allow => ("allow", None),
            VerdictOutcome::RequiresApproval { .. } => ("requires_approval", None),
            VerdictOutcome::Deny { reason } => (
                "deny",
                Some(DenyInfo {
                    // The machine-stable code the kernel recorded, when this is
                    // a kernel decision; handler-side refusals carry none, and
                    // saying so beats inventing one.
                    code: ext("deny_code").unwrap_or_else(|| "unclassified".to_string()),
                    detail: Some(reason.clone()),
                }),
            ),
            // `VerdictOutcome` is #[non_exhaustive]: an outcome this build does
            // not know must not read as "allow" in a regulatory record.
            other => (
                "error",
                Some(DenyInfo {
                    code: "unclassified_outcome".to_string(),
                    detail: Some(format!("{other:?}")),
                }),
            ),
        };

        // Everything the recorder attached that is not already a named field
        // travels as extensions — including `flow_cross_check` (#2144), so the
        // DAG's second opinion is in the regulatory record and not only in a log.
        let extensions = ctx
            .extensions
            .iter()
            .filter(|(k, _)| {
                !matches!(
                    k.as_str(),
                    "transport" | "decision_sequence" | "gate_class" | "deny_code"
                )
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        Art12Record {
            // Assigned by `Art12Log::append`.
            schema_version: 0,
            seq: 0,
            prev_hash: String::new(),
            hash: String::new(),
            signature: String::new(),

            timestamp_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            session_id: self.session_id.clone(),
            transport: ext("transport").unwrap_or_else(|| "unknown".to_string()),
            actor: match &ctx.actor {
                ActorIdentity::Authenticated { spiffe_id } => Actor {
                    kind: "authenticated".to_string(),
                    spiffe_id: Some(spiffe_id.clone()),
                },
                ActorIdentity::StdioGuest => Actor {
                    kind: "stdio_guest".to_string(),
                    spiffe_id: None,
                },
                ActorIdentity::Unknown => Actor {
                    kind: "unknown".to_string(),
                    spiffe_id: None,
                },
            },
            operation: operation_name(ctx.operation).to_string(),
            subject: ctx.subject.clone(),
            verdict: verdict.to_string(),
            gate_class: ext("gate_class").unwrap_or_else(|| "none".to_string()),
            deny_reason,
            policy_checksum: self.policy_checksum.clone(),
            policy_rule: ctx.policy_rule.clone(),
            dlc_admission: if self.dlc_provisioned {
                if verdict == "allow" {
                    "admitted".to_string()
                } else {
                    "not_admitted".to_string()
                }
            } else {
                "unprovisioned".to_string()
            },
            lockdown_active: ext("lockdown_active").is_some_and(|v| v == "true"),
            decision_sequence: ext("decision_sequence").and_then(|s| s.parse().ok()),
            extensions,
        }
    }
}

/// Canonical operation names, matching the audit log's vocabulary.
fn operation_name(op: Operation) -> &'static str {
    match op {
        Operation::ReadFiles => "read_files",
        Operation::WriteFiles => "write_files",
        Operation::EditFiles => "edit_files",
        Operation::RunBash => "run_bash",
        Operation::GlobSearch => "glob_search",
        Operation::GrepSearch => "grep_search",
        Operation::WebSearch => "web_search",
        Operation::WebFetch => "web_fetch",
        Operation::GitCommit => "git_commit",
        Operation::GitPush => "git_push",
        Operation::CreatePr => "create_pr",
        Operation::ManagePods => "manage_pods",
        Operation::SpawnAgent => "spawn_agent",
    }
}

impl VerdictSink for Art12Sink {
    fn record(&self, ctx: VerdictContext) -> Result<(), SinkError> {
        let draft = self.project(&ctx);
        // Clone the draft for the receipt ONLY when one will be issued (so the
        // append can move `draft` on the common path). The receipt binds the
        // record's chained hash, including its `extensions`/`dlc_admission` —
        // which is where an upstream checkpoint's authority record flows.
        let receipt_draft = self.receipt_signer.as_ref().map(|_| draft.clone());

        // Ship BEFORE the local append. The record the host witnesses is the
        // one built from this decision, and ordering it first means a pod that
        // crashes between the two has told the host more than it kept, never
        // less.
        if let Some(shipper) = &self.shipper {
            match serde_json::to_string(&draft) {
                Ok(line) => shipper.submit(line),
                Err(e) => {
                    tracing::error!(error = %e, "could not serialize an Article 12 record for the host")
                }
            }
        }

        match self.log.append(draft) {
            Ok((hash, seq)) => {
                // Opt-in signed MediationReceipt binding this record's hash.
                if let (Some(signer), Some(mut rec)) = (self.receipt_signer.as_ref(), receipt_draft)
                {
                    rec.hash = hash.clone();
                    rec.seq = seq;
                    rec.decision_sequence = Some(seq);
                    let receipt = MediationReceipt::issue(
                        &rec,
                        &signer.mediator_spiffe_id,
                        signer.signer_assurance,
                        &signer.signer_backend,
                        &signer.key,
                    );
                    // Durable telemetry — the receipt (signature + hashes) is
                    // forensic, not secret; the signing key is never logged.
                    tracing::info!(
                        target: "nucleus_mediation_receipt",
                        seq,
                        art12_record_hash = %hash,
                        verdict = %rec.verdict,
                        mediator = %signer.mediator_spiffe_id,
                        "emitted signed MediationReceipt"
                    );
                    if let Ok(mut v) = signer.emitted.lock() {
                        v.push(receipt);
                    }
                }
            }
            Err(e) => {
                // The log has latched `degraded` and counted the drop; the next
                // preflight fails closed. Do not fail this call: its effect may
                // already have happened, and returning an error here would invite
                // a retry that duplicates it.
                tracing::error!(error = ?e, "article 12 record could not be written -- evidence gap");
            }
        }
        self.inner.record(ctx)
    }

    fn preflight(&self, operation: Operation) -> Result<(), SinkError> {
        // The evidence channel failing is as disqualifying as the local log
        // failing: in both cases the next operation would execute without its
        // record reaching somewhere the pod cannot retract it.
        if let Some(shipper) = &self.shipper {
            if shipper.is_degraded() {
                tracing::error!(
                    ?operation,
                    unshipped = shipper.unshipped(),
                    "refusing: Article 12 records are not reaching the host"
                );
                return Err(SinkError::Locked);
            }
        }
        if self.log.is_degraded() {
            tracing::error!(
                ?operation,
                dropped = self.log.dropped(),
                "refusing: the Article 12 log is degraded and this operation would not be recorded"
            );
            return Err(SinkError::Locked);
        }
        self.inner.preflight(operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    struct NullSink;
    impl VerdictSink for NullSink {
        fn record(&self, _c: VerdictContext) -> Result<(), SinkError> {
            Ok(())
        }
        fn preflight(&self, _o: Operation) -> Result<(), SinkError> {
            Ok(())
        }
    }

    fn sink_with(log: Arc<Art12Log>) -> Art12Sink {
        Art12Sink::new(
            Arc::new(NullSink),
            log,
            "sess".to_string(),
            "checksum".to_string(),
            false,
            None,
            None,
        )
    }

    fn open_log(dir: &TempDir) -> Arc<Art12Log> {
        Arc::new(
            Art12Log::open(
                &dir.path().join("a12.jsonl"),
                b"k".to_vec(),
                "g".into(),
                false,
            )
            .unwrap(),
        )
    }

    /// **Brick 5 (b): a signed MediationReceipt is emitted per verdict, binding
    /// the record's chained hash.** With a signer, `record` issues a receipt whose
    /// `art12_record_hash` equals the log head, whose verdict matches, and which
    /// verifies (strict) under the mediator's public key.
    #[test]
    fn a_configured_signer_emits_a_verifying_receipt_bound_to_the_record_hash() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey = key.verifying_key();
        let emitted = Arc::new(Mutex::new(Vec::new()));
        let sink = Art12Sink::new(
            Arc::new(NullSink),
            Arc::clone(&log),
            "sess".to_string(),
            "checksum".to_string(),
            false,
            None,
            Some(ReceiptSigner {
                mediator_spiffe_id: "spiffe://td/mediator".to_string(),
                signer_assurance: 0,
                signer_backend: "software".to_string(),
                key,
                emitted: Arc::clone(&emitted),
            }),
        );

        sink.record(ctx(VerdictOutcome::Allow, &[])).unwrap();

        let receipts = emitted.lock().unwrap();
        assert_eq!(receipts.len(), 1, "one receipt per recorded verdict");
        let r = &receipts[0];
        let (head_hash, _seq) = log.head().unwrap();
        assert_eq!(
            r.art12_record_hash, head_hash,
            "receipt binds the record's chained hash"
        );
        assert_eq!(r.verdict, "allow");
        assert!(
            r.verify(&pubkey).is_ok(),
            "receipt verifies under the mediator key"
        );
        // Anti-forgery: a different key does NOT verify.
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(r.verify(&other).is_err());
    }

    /// Without a signer, no receipt is emitted (default behavior unchanged).
    #[test]
    fn without_a_signer_no_receipt_is_emitted() {
        let dir = TempDir::new().unwrap();
        let sink = sink_with(open_log(&dir));
        // Records fine; there is simply no receipt path.
        assert!(sink.record(ctx(VerdictOutcome::Allow, &[])).is_ok());
    }

    fn ctx(outcome: VerdictOutcome, ext: &[(&str, &str)]) -> VerdictContext {
        let mut extensions = BTreeMap::new();
        for (k, v) in ext {
            extensions.insert((*k).to_string(), (*v).to_string());
        }
        VerdictContext {
            operation: Operation::RunBash,
            subject: "rm -rf /".to_string(),
            outcome,
            actor: ActorIdentity::StdioGuest,
            policy_rule: None,
            extensions,
        }
    }

    /// **The reason this module exists.** A refusal must be recorded. An
    /// Article 12 log containing only allows is non-empty, plausible, and wrong
    /// in the most dangerous direction.
    #[test]
    fn a_refusal_is_recorded_with_its_machine_stable_code() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);
        let sink = sink_with(log.clone());

        sink.record(ctx(
            VerdictOutcome::Deny {
                reason: "blocked by the command lattice".to_string(),
            },
            &[("deny_code", "command_blocked"), ("gate_class", "hard")],
        ))
        .unwrap();

        let lines = std::fs::read_to_string(dir.path().join("a12.jsonl")).unwrap();
        assert_eq!(lines.lines().count(), 1, "the refusal must be on disk");
        let rec: serde_json::Value = serde_json::from_str(lines.lines().next().unwrap()).unwrap();
        assert_eq!(rec["verdict"], "deny");
        assert_eq!(rec["deny_reason"]["code"], "command_blocked");
        assert_eq!(rec["gate_class"], "hard");
    }

    /// The DAG's second opinion (#2144) belongs in the regulatory record, not
    /// only in a log line — it is the runtime's own evidence that the decision
    /// followed from the causal graph.
    #[test]
    fn the_flow_cross_check_survives_into_the_record() {
        let dir = TempDir::new().unwrap();
        let sink = sink_with(open_log(&dir));
        sink.record(ctx(
            VerdictOutcome::Allow,
            &[("flow_cross_check", "unconfirmed:mismatch")],
        ))
        .unwrap();

        let line = std::fs::read_to_string(dir.path().join("a12.jsonl")).unwrap();
        let rec: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(
            rec["extensions"]["flow_cross_check"],
            "unconfirmed:mismatch"
        );
    }

    /// An unknown outcome must not read as `allow` in a regulatory record.
    /// `VerdictOutcome` is `#[non_exhaustive]`, so this is reachable by a
    /// version skew rather than only in principle.
    #[test]
    fn a_deny_without_a_code_says_unclassified_rather_than_inventing_one() {
        let dir = TempDir::new().unwrap();
        let sink = sink_with(open_log(&dir));
        // A handler-side refusal: no kernel decision, so no `deny_code`.
        sink.record(ctx(
            VerdictOutcome::Deny {
                reason: "validation: bad path".to_string(),
            },
            &[],
        ))
        .unwrap();

        let line = std::fs::read_to_string(dir.path().join("a12.jsonl")).unwrap();
        let rec: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(rec["deny_reason"]["code"], "unclassified");
        assert_ne!(rec["verdict"], "allow");
    }

    /// **Fail closed.** Once the log is degraded the NEXT operation is refused —
    /// a record-keeping log that keeps going after it stops recording leaves an
    /// invisible gap in the artifact, which is worse than no log at all.
    #[test]
    fn a_degraded_log_refuses_the_next_operation() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);
        let sink = sink_with(log.clone());
        assert!(
            sink.preflight(Operation::RunBash).is_ok(),
            "a healthy log must permit, or the assertion below proves nothing"
        );

        log.force_degraded();

        assert!(
            sink.preflight(Operation::RunBash).is_err(),
            "a degraded Article 12 log must refuse the next operation"
        );
    }

    /// A record whose effect may already have happened is still delegated: the
    /// latch is read at preflight, not at record, so a write failure does not
    /// retroactively fail a call and invite a duplicating retry.
    #[test]
    fn a_degraded_log_does_not_fail_the_call_in_flight() {
        let dir = TempDir::new().unwrap();
        let log = open_log(&dir);
        let sink = sink_with(log.clone());
        log.force_degraded();
        assert!(
            sink.record(ctx(VerdictOutcome::Allow, &[])).is_ok(),
            "recording must not fail a call whose effect already happened"
        );
    }

    /// **The lesson from #2145, enforced at startup.** The Article 12 log is a
    /// strictly richer record than the exit report — every decision, with gate
    /// class and deny code — so it must never land where the agent can read it.
    #[test]
    fn a_log_path_inside_the_workspace_is_refused() {
        let work = TempDir::new().unwrap();
        assert!(
            reject_workspace_path(&work.path().join("evidence.jsonl"), work.path()).is_err(),
            "a log path inside the agent workspace must be refused"
        );
        assert!(
            reject_workspace_path(&work.path().join("nested/deep/a.jsonl"), work.path()).is_err(),
            "nesting must not evade the check"
        );
    }

    /// The control: a host-private path is accepted, so the check above is not
    /// simply refusing everything.
    #[test]
    fn a_host_private_log_path_is_accepted() {
        let work = TempDir::new().unwrap();
        let elsewhere = TempDir::new().unwrap();
        assert!(reject_workspace_path(&elsewhere.path().join("a.jsonl"), work.path()).is_ok());
    }
}
