//! Owner decisions as agent tools: `/v1/decision/read` and `/v1/decision/list`.
//!
//! A decision reaches the agent here only after [`nucleus_signed_decision::verify`] has minted a
//! `SignedDecision` from a bundle: the owner's signature against the operator's trust roots, the
//! canonical bytes, the tenant, the question and option digests, the chosen option, the scope
//! and the window. A file in the bundle directory that fails any of these is reported as refused
//! and its bytes are never returned or observed. Text elsewhere that claims to be a decision (a
//! brief, an issue comment, a memory record) has no path into this module at all, so nothing
//! promotes it: it keeps the label of the channel it arrived by.
//!
//! **Into the flow graph.** A verified decision is observed onto the authoritative `FlowGraph`
//! through the existing `observe_with_label_and_content_hash`, with the label the design gives it
//! (control plane `docs/signed-decisions.md` §5.3): `Trusted`, `Directive`, `USER`, `Internal`,
//! `Deterministic`. No new `NodeKind`: the node is tagged `UserPrompt`, the principal's
//! instruction, and the label is explicit. The graph's ordinary join applies afterwards, so a
//! decision read in a tainted session launders nothing.
//!
//! **Provisioning.** Trust roots are operator configuration, never workload input: a JSON file
//! of `{kid, public_key, who}` (the control plane's approvers shape) at a node-provisioned path
//! outside the workspace, the same rule the memory journal and the Article 12 log follow. Bundles
//! are untrusted bytes in a node-provisioned directory, one `<decision id>.json` each. A pod with
//! no roots configured has no decision routes, rather than routes that always refuse.
//!
//! Both handlers spend an [`Authority`] earned for `(ReadFiles, AuditLogAppend)` on their own
//! subject before reading anything, as memory recall does: a read brings bytes in, so any
//! session may read a decision, and its label is what the graph carries afterwards.

use std::path::{Path, PathBuf};

use axum::{Extension, Json, extract::State};
use nucleus::portcullis::NodeKind;
use nucleus::portcullis::flow_graph::FlowGraph;
use nucleus_ifc_kernel::{
    AuthorityLevel, ConfLevel, DerivationClass, Freshness, IFCLabel, IntegLevel, Operation,
    ProvenanceSet,
};
use nucleus_signed_decision::{
    DecisionBundle, DecisionLedger, OptionBody, OwnerDecision, OwnerDecisionId, QuestionCore,
    Scope, SignedDecision, TrustRoots, Window,
};
use portcullis::{Act, FilePath, ReadSink};
use portcullis_effects::authority::Authority;
use serde::{Deserialize, Serialize};

use crate::ApiError;

/// The largest bundle file read. A batch is at most 25 decisions of short strings.
const MAX_BUNDLE_BYTES: u64 = 1024 * 1024;
/// The largest trust-roots file read.
const MAX_ROOTS_BYTES: u64 = 64 * 1024;

/// Where owner decisions come from. All three or none.
#[derive(clap::Args, Debug)]
pub(crate) struct DecisionArgs {
    /// Operator trust roots for owner decisions: a JSON array of `{kid, public_key, who}`,
    /// outside the agent workspace. Unset means the pod has no decision tools.
    #[arg(
        long,
        env = "NUCLEUS_DECISION_TRUST_ROOTS",
        requires_all = ["decision_bundles", "decision_tenant"]
    )]
    decision_trust_roots: Option<PathBuf>,
    /// Node-provisioned directory of decision bundles, one `<decision id>.json` each, outside
    /// the agent workspace.
    #[arg(
        long,
        env = "NUCLEUS_DECISION_BUNDLES",
        requires = "decision_trust_roots"
    )]
    decision_bundles: Option<PathBuf>,
    /// The tenant every decision must name (`github~owner~name`).
    #[arg(
        long,
        env = "NUCLEUS_DECISION_TENANT",
        requires = "decision_trust_roots"
    )]
    decision_tenant: Option<String>,
}

/// The verified decisions this pod can read, and where they come from.
pub(crate) struct DecisionDesk {
    roots: TrustRoots,
    tenant: String,
    bundles: PathBuf,
    ledger: tokio::sync::Mutex<DecisionLedger>,
}

/// Read an operator-provisioned file of at most `cap` bytes: a regular file (not a symlink), its
/// size checked before the read and the bytes read checked after it.
fn read_capped(path: &Path, cap: u64) -> std::io::Result<Vec<u8>> {
    let too_big = || std::io::Error::new(std::io::ErrorKind::InvalidData, "over the size cap");
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if meta.len() > cap {
        return Err(too_big());
    }
    let out = std::fs::read(path)?;
    if !u64::try_from(out.len()).is_ok_and(|n| n <= cap) {
        return Err(too_big());
    }
    Ok(out)
}

impl DecisionArgs {
    /// Load the trust roots and check the paths. `Ok(None)` when nothing is configured; any
    /// partial or malformed configuration is fatal at startup.
    pub(crate) fn open(&self, workspace: &Path) -> Result<Option<DecisionDesk>, ApiError> {
        let fail = |m: String| ApiError::Spec(format!("owner decisions: {m}"));
        let (roots_path, bundles, tenant) = match (
            &self.decision_trust_roots,
            &self.decision_bundles,
            &self.decision_tenant,
        ) {
            (None, None, None) => return Ok(None),
            (Some(r), Some(b), Some(t)) => (r, b, t),
            _ => {
                return Err(fail(
                    "trust roots, bundle directory and tenant must be configured together".into(),
                ));
            }
        };
        if tenant.is_empty() {
            return Err(fail("tenant is empty".into()));
        }
        for (what, p) in [("trust roots", roots_path), ("bundle directory", bundles)] {
            if !p.is_absolute() {
                return Err(fail(format!("{what} path must be absolute")));
            }
            crate::art12_sink::reject_workspace_path(p, workspace)
                .map_err(|_| fail(format!("{what} must be outside the workspace")))?;
        }
        if !bundles.is_dir() {
            return Err(fail("bundle directory is not a directory".into()));
        }
        let text = read_capped(roots_path, MAX_ROOTS_BYTES)
            .map_err(|e| fail(format!("cannot read trust roots: {e}")))?;
        let text = String::from_utf8(text).map_err(|_| fail("trust roots are not UTF-8".into()))?;
        let roots = TrustRoots::from_json(&text).map_err(|e| fail(e.to_string()))?;
        Ok(Some(DecisionDesk {
            roots,
            tenant: tenant.clone(),
            bundles: bundles.clone(),
            ledger: tokio::sync::Mutex::new(DecisionLedger::empty()),
        }))
    }
}

impl DecisionDesk {
    /// How many trust roots are pinned, for the boot log.
    pub(crate) fn root_count(&self) -> usize {
        self.roots.len()
    }

    /// Read and verify the bundle for `id`. The file name is the id, and the verified decision
    /// must have that id: a bundle filed under another decision's name is refused.
    fn load(&self, id: OwnerDecisionId, now: u64) -> Result<SignedDecision, String> {
        let path = self.bundles.join(format!("{id}.json"));
        let bytes = read_capped(&path, MAX_BUNDLE_BYTES).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => "no bundle for this decision id".to_string(),
            _ => format!("cannot read bundle: {e}"),
        })?;
        let bundle = DecisionBundle::from_slice(&bytes).map_err(|e| e.to_string())?;
        let decision = nucleus_signed_decision::verify(&bundle, &self.roots, now, &self.tenant)
            .map_err(|e| e.to_string())?;
        if decision.id() != id {
            return Err(format!(
                "bundle filed as {id} verifies as decision {}",
                decision.id()
            ));
        }
        Ok(decision)
    }
}

/// The label a verified decision is observed with (`docs/signed-decisions.md` §5.3).
pub(crate) fn decision_label(now: u64) -> IFCLabel {
    IFCLabel {
        confidentiality: ConfLevel::Internal,
        integrity: IntegLevel::Trusted,
        provenance: ProvenanceSet::USER,
        freshness: Freshness {
            observed_at: now,
            ttl_secs: 0,
        },
        authority: AuthorityLevel::Directive,
        derivation: DerivationClass::Deterministic,
    }
}

/// Read one verified decision.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReadReq {
    /// The decision id, 64 lowercase hex.
    pub id: String,
}

/// A verified decision as the agent sees it: the record plus each option's full text.
#[derive(Debug, Serialize)]
pub struct DecisionView {
    /// The decision id.
    pub id: String,
    /// The trust root that signed it.
    pub kid: String,
    /// `owner/name`.
    pub repo: String,
    /// The question decided.
    pub question_id: String,
    /// The question's text.
    pub question: String,
    /// Every option the owner was shown, in order.
    pub options: Vec<OptionBody>,
    /// The chosen option's id.
    pub chosen: String,
    /// What the decision authorizes.
    pub scope: Scope,
    /// The owner's conditions: constraints, never authority.
    pub conditions: Vec<String>,
    /// Whether the decision may be spent once only.
    pub single_use: bool,
    /// The decision this one replaced.
    pub supersedes: Option<String>,
    /// Unix seconds.
    pub valid_from: u64,
    /// Unix seconds.
    pub not_after: u64,
}

impl DecisionView {
    /// Built from what a decision shows, not from the decision: a view never borrows the right
    /// itself (ADR 0007 C-4).
    fn of(id: OwnerDecisionId, kid: &str, r: &OwnerDecision, q: &QuestionCore) -> Self {
        Self {
            id: id.to_hex(),
            kid: kid.to_string(),
            repo: r.repo.clone(),
            question_id: r.question_id.clone(),
            question: q.question.clone(),
            options: q.options.clone(),
            chosen: r.chosen.clone(),
            scope: r.scope.clone(),
            conditions: r.conditions.clone(),
            single_use: r.single_use,
            supersedes: r.supersedes.clone(),
            valid_from: r.valid_from,
            not_after: r.not_after,
        }
    }
}

/// Result of a decision read.
#[derive(Debug, Serialize)]
pub struct DecisionReadResp {
    /// The verified decision.
    pub decision: DecisionView,
}

/// A bundle file that did not verify, and why. Its bytes are never returned.
#[derive(Debug, Serialize)]
pub struct RefusedBundle {
    /// The file name.
    pub file: String,
    /// The verifier's reason.
    pub reason: String,
}

/// Result of a decision listing.
#[derive(Debug, Serialize)]
pub struct DecisionListResp {
    /// The verified, live decisions this pod holds.
    pub decisions: Vec<DecisionView>,
    /// Files in the bundle directory that did not verify.
    pub refused: Vec<RefusedBundle>,
}

/// The subject a read is discharged for and spent against: `decision://<id>`.
pub fn read_subject(req: &DecisionReadReq) -> String {
    format!("decision://{}", req.id)
}

/// The subject a listing is discharged for and spent against.
pub const LIST_SUBJECT: &str = "decision://list";

fn spend_read(authority: Authority, subject: &str) -> Result<(), ApiError> {
    let act = Act::Read {
        path: FilePath::new(subject.to_string()),
        sink: ReadSink::AuditLog,
    };
    authority
        .spend_on(&act)
        .map(|_spent| ())
        .map_err(|e| ApiError::IfcDenied(format!("decision read refused: {e}")))
}

fn observe_decisions(
    graph: &mut FlowGraph,
    now: u64,
    views: &[&SignedDecision],
) -> Result<(), ApiError> {
    for d in views {
        let bytes = d
            .message()
            .map_err(|e| ApiError::Spec(format!("decision encoding: {e}")))?;
        graph
            .observe_with_label_and_content_hash(
                NodeKind::UserPrompt,
                decision_label(now),
                &[],
                now,
                crate::ingest_content_hash(&bytes),
            )
            .map_err(|e| ApiError::IfcDenied(format!("flow-graph observe failed: {e}")))?;
    }
    Ok(())
}

/// Core read: spend `authority`, then load, verify, hold and observe the decision. Fail-closed:
/// a refusal observes nothing and returns none of the bundle's bytes.
pub(crate) fn decision_read_core(
    desk: &DecisionDesk,
    ledger: &mut DecisionLedger,
    graph: &mut FlowGraph,
    now: u64,
    req: DecisionReadReq,
    authority: Authority,
) -> Result<DecisionReadResp, ApiError> {
    spend_read(authority, &read_subject(&req))?;
    let id = OwnerDecisionId::from_hex(&req.id)
        .map_err(|_| ApiError::Body("decision id is not 64 lowercase hex".into()))?;
    let decision = desk
        .load(id, now)
        .map_err(|why| ApiError::IfcDenied(format!("owner decision {id} refused: {why}")))?;
    let id = ledger
        .hold(decision)
        .map_err(|e| ApiError::IfcDenied(format!("owner decision refused: {e}")))?;
    let held = ledger
        .get(id)
        .ok_or_else(|| ApiError::IfcDenied(format!("owner decision {id} is not held")))?;
    observe_decisions(graph, now, &[held])?;
    Ok(DecisionReadResp {
        decision: DecisionView::of(held.id(), held.kid(), held.record(), held.question()),
    })
}

/// Core listing: spend `authority`, verify every bundle in the directory, hold the ones that
/// verify, and return and observe the live ones.
pub(crate) fn decision_list_core(
    desk: &DecisionDesk,
    ledger: &mut DecisionLedger,
    graph: &mut FlowGraph,
    now: u64,
    authority: Authority,
) -> Result<DecisionListResp, ApiError> {
    spend_read(authority, LIST_SUBJECT)?;
    let mut names: Vec<String> = std::fs::read_dir(&desk.bundles)?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    let mut refused = Vec::new();
    for file in names.into_iter().take(nucleus_signed_decision::MAX_HELD) {
        let Some(id) = file
            .strip_suffix(".json")
            .and_then(|stem| OwnerDecisionId::from_hex(stem).ok())
        else {
            refused.push(RefusedBundle {
                file,
                reason: "not named <decision id>.json".into(),
            });
            continue;
        };
        let held = desk
            .load(id, now)
            .and_then(|d| ledger.hold(d).map_err(|e| e.to_string()));
        if let Err(reason) = held {
            refused.push(RefusedBundle { file, reason });
        }
    }
    let live: Vec<&SignedDecision> = ledger
        .iter()
        .filter(|d| d.window(now) == Window::Live)
        .collect();
    observe_decisions(graph, now, &live)?;
    Ok(DecisionListResp {
        decisions: live
            .into_iter()
            .map(|d| DecisionView::of(d.id(), d.kid(), d.record(), d.question()))
            .collect(),
        refused,
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn desk(state: &crate::AppState) -> Result<&DecisionDesk, ApiError> {
    state
        .decisions
        .as_deref()
        .ok_or_else(|| ApiError::Spec("owner decisions are not configured on this pod".into()))
}

/// POST `/v1/decision/read` — one verified owner decision, observed as directive.
pub(crate) async fn decision_read(
    State(state): State<crate::AppState>,
    auth: Option<Extension<crate::auth::AuthContext>>,
    certified: Option<Extension<crate::pod_cert::CertifiedPermissions>>,
    Json(req): Json<DecisionReadReq>,
) -> Result<Json<DecisionReadResp>, ApiError> {
    use nucleus_ifc_kernel::discharge::PreflightResult;
    let desk = desk(&state)?;
    let _dt = crate::http_kernel_decide(
        &state,
        Operation::ReadFiles,
        "decision://read",
        auth.as_ref().map(|e| &e.0),
    )
    .await?;
    let subject = read_subject(&req);
    let levels = state.ceiling(Operation::ReadFiles, certified.as_ref());
    let flow = state.flow_graph.lock().await;
    let scope = state.session_task_token.verified_scope();
    let preflight = crate::run_gate::preflight_read_fs(scope, levels, &subject, &flow);
    drop(flow);
    let authority = match preflight {
        PreflightResult::Allowed(b) => {
            Authority::new(b).witnessed_by(std::sync::Arc::clone(&state.receipts))
        }
        PreflightResult::Denied { reason, .. } | PreflightResult::RequiresApproval { reason } => {
            return Err(ApiError::IfcDenied(format!("discharge denied: {reason}")));
        }
    };
    let mut ledger = desk.ledger.lock().await;
    let mut graph = state.flow_graph.lock().await;
    let resp = decision_read_core(desk, &mut ledger, &mut graph, unix_now(), req, authority)?;
    Ok(Json(resp))
}

/// POST `/v1/decision/list` — the verified, live owner decisions this pod holds.
pub(crate) async fn decision_list(
    State(state): State<crate::AppState>,
    auth: Option<Extension<crate::auth::AuthContext>>,
    certified: Option<Extension<crate::pod_cert::CertifiedPermissions>>,
) -> Result<Json<DecisionListResp>, ApiError> {
    use nucleus_ifc_kernel::discharge::PreflightResult;
    let desk = desk(&state)?;
    let _dt = crate::http_kernel_decide(
        &state,
        Operation::ReadFiles,
        LIST_SUBJECT,
        auth.as_ref().map(|e| &e.0),
    )
    .await?;
    let levels = state.ceiling(Operation::ReadFiles, certified.as_ref());
    let flow = state.flow_graph.lock().await;
    let scope = state.session_task_token.verified_scope();
    let preflight = crate::run_gate::preflight_read_fs(scope, levels, LIST_SUBJECT, &flow);
    drop(flow);
    let authority = match preflight {
        PreflightResult::Allowed(b) => {
            Authority::new(b).witnessed_by(std::sync::Arc::clone(&state.receipts))
        }
        PreflightResult::Denied { reason, .. } | PreflightResult::RequiresApproval { reason } => {
            return Err(ApiError::IfcDenied(format!("discharge denied: {reason}")));
        }
    };
    let mut ledger = desk.ledger.lock().await;
    let mut graph = state.flow_graph.lock().await;
    let resp = decision_list_core(desk, &mut ledger, &mut graph, unix_now(), authority)?;
    Ok(Json(resp))
}

#[cfg(test)]
#[path = "owner_decision_tests.rs"]
mod tests;
