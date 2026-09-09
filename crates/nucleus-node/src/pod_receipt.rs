//! The execution receipt: what a pod did, as a value both transports serve.
//!
//! # Why this exists as a module
//!
//! The receipt was assembled inline in the gRPC handler, which made gRPC the only way to get one.
//! `Operation::GetReceipt` had existed in the authorization enum the whole time, and the Python
//! SDK has been calling `GET /v1/pods/{id}/receipt` — a route that did not exist, so the call
//! 404'd. A receipt that is produced and cannot be read is not evidence of anything.
//!
//! So the assembly moves here and both transports call it. One implementation rather than two
//! spellings, which is the shape that drifts: the whole reason the receipt is a content hash is
//! that two parties should be able to compute the same value, and that argument dies immediately
//! if the node itself has two ways of computing it.
//!
//! # The reporting side effect stays on gRPC, deliberately
//!
//! Building a receipt over gRPC also fires an *external* report to the trust API. That is a real
//! oddity — a read with an outward-facing side effect, so asking twice reports twice — and it
//! belongs at pod exit rather than at read time. It is not changed here: something outside this
//! repository may depend on it, and quietly dropping an outward-facing call is not a refactor.
//!
//! What this does refuse to do is *propagate* it. The HTTP route reads and does not report, which
//! is what a GET should be. The asymmetry is the bug being contained rather than spread, and it is
//! written down here so the next person finds a decision instead of an inconsistency.

use std::sync::Arc;

use serde::Serialize;

use crate::{NodeState, PodHandle, PodState};

/// The receipt as served. Field-for-field the proto message, so the two transports cannot
/// disagree about what a receipt IS — `main.rs` converts, it does not re-derive.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Receipt {
    pub pod_id: String,
    pub workspace_hash: String,
    pub audit_tail_hash: String,
    pub audit_entry_count: u64,
    pub timestamp_unix: u64,
    pub manifest_hash: String,
    pub sandbox_tier: String,
    pub spiffe_id: String,
    pub version: u32,
    pub v1_content_hash: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cost_usd: f64,
}

/// Why a receipt could not be produced.
///
/// Three cases rather than one string, because they mean different things to a caller: wait, look
/// elsewhere, and something is broken.
#[derive(Debug)]
pub(crate) enum ReceiptError {
    /// The pod is still running. Not an error so much as "not yet".
    NotExited,
    /// The pod exited without leaving an exit report — the tool proxy writes it at shutdown, so
    /// its absence usually means the pod died before shutdown ran.
    NoExitReport(String),
    /// The report is there and unreadable.
    Malformed(String),
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotExited => write!(f, "pod has not exited yet; receipt not available"),
            Self::NoExitReport(why) => write!(f, "exit report not found: {why}"),
            Self::Malformed(why) => write!(f, "failed to parse exit report: {why}"),
        }
    }
}

/// Everything the receipt was built from, kept so the trust report does not recompute any of it.
pub(crate) struct Built {
    pub receipt: Receipt,
    pub report: nucleus_spec::ExitReport,
    pub trust_bracket: Option<String>,
    pub trust_profile: Option<String>,
    pub agent_identity: String,
    pub exit_code: i32,
}

/// Assemble the receipt for an exited pod.
///
/// # Errors
///
/// [`ReceiptError`] — still running, no exit report, or an unreadable one.
pub(crate) async fn build(handle: &Arc<PodHandle>) -> Result<Built, ReceiptError> {
    let id = handle.id;
    let state = handle.status().await;
    let PodState::Exited { code, .. } = state else {
        return Err(ReceiptError::NotExited);
    };

    let report_path = handle.spec.spec.work_dir.join(".nucleus-exit-report.json");
    let report_json = tokio::fs::read_to_string(&report_path)
        .await
        .map_err(|e| ReceiptError::NoExitReport(format!("{}: {e}", report_path.display())))?;
    let report: nucleus_spec::ExitReport =
        serde_json::from_str(&report_json).map_err(|e| ReceiptError::Malformed(e.to_string()))?;

    let spec_yaml = serde_yaml::to_string(&handle.spec).unwrap_or_default();
    let manifest_hash =
        nucleus_identity::approval_bundle::compute_manifest_hash(spec_yaml.as_bytes());
    let v1_content_hash =
        crate::trust_gate::compute_v1_content_hash(&id.to_string(), &manifest_hash, &report);

    let labels = &handle.spec.metadata.labels;
    let trust_bracket = labels.get("trust.coproduct.one/bracket").cloned();
    let trust_profile = labels.get("trust.coproduct.one/profile").cloned();
    let agent_identity = labels
        .get("trust.coproduct.one/agent-id")
        .or_else(|| labels.get("spiffe.io/identity"))
        .cloned()
        .or_else(|| handle.spec.metadata.name.clone())
        .unwrap_or_else(|| id.to_string());
    let spiffe_id = labels
        .get("spiffe.io/identity")
        .cloned()
        .unwrap_or_default();

    Ok(Built {
        receipt: Receipt {
            pod_id: id.to_string(),
            workspace_hash: report.workspace_hash.clone(),
            audit_tail_hash: report.audit_tail_hash.clone(),
            audit_entry_count: report.audit_entry_count,
            timestamp_unix: report.timestamp_unix,
            manifest_hash,
            sandbox_tier: trust_profile.clone().unwrap_or_default(),
            spiffe_id,
            version: 1,
            v1_content_hash,
            input_tokens: report.input_tokens,
            output_tokens: report.output_tokens,
            cache_read_tokens: report.cache_read_tokens,
            cost_usd: report.cost_usd,
        },
        report,
        trust_bracket,
        trust_profile,
        agent_identity,
        exit_code: code.unwrap_or(-1),
    })
}

/// Report the receipt to the external trust API, in the background.
///
/// Unchanged in behaviour from when this lived inline in the gRPC handler, including that it is
/// fire-and-forget: a trust API that is down must not make a receipt unreadable.
pub(crate) fn report_to_trust_gate(state: &NodeState, built: &Built) {
    let id = built.receipt.pod_id.clone();
    let r = &built.report;
    let receipt_report = crate::trust_gate::ReceiptReport {
        agent_id: built.agent_identity.clone(),
        session_id: id.clone(),
        success: built.exit_code == 0,
        cost_usd: r.cost_usd,
        tool_call_count: r.audit_entry_count,
        workspace_hash: r.workspace_hash.clone(),
        audit_tail_hash: r.audit_tail_hash.clone(),
        trust_bracket: built.trust_bracket.clone(),
        trust_profile: built.trust_profile.clone(),
        attested_execution: built.trust_bracket.is_some(),
        // Verified exposure from the tool proxy's GradedExposureGuard, written to
        // .nucleus-exit-report.json at shutdown.
        observed_exposure_labels: r.observed_exposure_labels.clone(),
        observed_risk_tier: if r.observed_risk_tier.is_empty() {
            "unknown".to_string()
        } else {
            r.observed_risk_tier.clone()
        },
        uninhabitable_reached: r.uninhabitable_reached,
        // Runtime-verification findings from the tool proxy's TraceMonitor.
        monitor_violations: r.monitor_violations.clone(),
        monitor_violations_dropped: r.monitor_violations_dropped,
        // Signed with the executor key, which the pod never sees. Taken at pod exit — after the
        // pod has stopped — so the head it binds is one the pod can no longer move.
        art12_attestation: crate::trust_gate::attest_art12(
            r,
            // What the HOST received, not what the pod reported.
            crate::art12_collector::observed_chain(&state.state_dir, &id).as_ref(),
            &id,
            &state.trust_gate.executor_id,
            &state.trust_gate.executor_signing_key,
        ),
        // Cryptographic session identity — required for the SandboxAttested upgrade path in the
        // trust-service session-complete handler.
        sandbox_identity: if built.receipt.spiffe_id.is_empty() {
            built.agent_identity.clone()
        } else {
            built.receipt.spiffe_id.clone()
        },
        v1_content_hash: built.receipt.v1_content_hash.clone(),
    };
    let trust_config = state.trust_gate.clone();
    let http_client = state.http_client.clone();
    tokio::spawn(async move {
        // In secure mode, pre-register the v1_content_hash so the handler can validate it when
        // observed_exposure_labels are present. Without this, session-complete returns 422 and the
        // NameHeuristic -> SandboxAttested upgrade is silently dropped.
        crate::trust_gate::register_receipt_hash(&trust_config, &receipt_report, &http_client)
            .await;
        crate::trust_gate::report_receipt(&trust_config, &receipt_report, &http_client).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Receipt {
        Receipt {
            pod_id: "11111111-1111-1111-1111-111111111111".into(),
            workspace_hash: "ws".into(),
            audit_tail_hash: "tail".into(),
            audit_entry_count: 3,
            timestamp_unix: 1_757_000_000,
            manifest_hash: "mf".into(),
            sandbox_tier: "restricted".into(),
            spiffe_id: "spiffe://nucleus.local/ns/pods/sa/1".into(),
            version: 1,
            v1_content_hash: "v1".into(),
            input_tokens: 10,
            output_tokens: 20,
            cache_read_tokens: 5,
            cost_usd: 0.5,
        }
    }

    /// The HTTP body names exactly the fields the proto does.
    ///
    /// The two transports serve one value, and this is the half a compiler cannot check: the
    /// gRPC conversion in `main.rs` is a struct literal, so a missing field there is a compile
    /// error, but nothing stops the JSON from drifting into a different vocabulary. A client
    /// reading `workspace_hash` over gRPC must find `workspace_hash` over HTTP.
    #[test]
    fn the_http_body_names_the_same_fields_the_proto_does() {
        let json = serde_json::to_value(sample()).expect("a receipt serializes");
        let keys: std::collections::BTreeSet<&str> = json
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        // `extensions` is deliberately absent: it is a proto-level escape hatch the node always
        // sends empty, and an empty map in JSON would be noise a client has to ignore.
        let expected: std::collections::BTreeSet<&str> = [
            "pod_id",
            "workspace_hash",
            "audit_tail_hash",
            "audit_entry_count",
            "timestamp_unix",
            "manifest_hash",
            "sandbox_tier",
            "spiffe_id",
            "version",
            "v1_content_hash",
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cost_usd",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            keys, expected,
            "the HTTP body and the proto must name one vocabulary"
        );
    }

    /// The three refusals stay distinguishable, because they ask the caller for different things.
    ///
    /// "Not finished yet" means retry, "no exit report" means look at why the pod died, and
    /// "malformed" means something is broken. Collapsing them into one string — which is what the
    /// inline version effectively did, since it built `Status` messages ad hoc — makes a caller
    /// unable to tell waiting from failing.
    #[test]
    fn each_reason_a_receipt_is_unavailable_reads_differently() {
        let rendered: Vec<String> = [
            ReceiptError::NotExited,
            ReceiptError::NoExitReport("/w/.nucleus-exit-report.json: ENOENT".into()),
            ReceiptError::Malformed("expected value at line 1".into()),
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert!(rendered[0].contains("has not exited"), "{rendered:?}");
        assert!(
            rendered[1].contains("exit report not found"),
            "{rendered:?}"
        );
        assert!(rendered[2].contains("failed to parse"), "{rendered:?}");
        let unique: std::collections::BTreeSet<&String> = rendered.iter().collect();
        assert_eq!(unique.len(), 3, "each must read differently: {rendered:?}");
    }
}
