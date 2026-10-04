//! Issuing a lockdown, holding it, and who it reaches.
//!
//! Its own module because `main.rs` carries a line ratchet and anything added
//! must be paid for by something taken out -- and because the fail-open rule
//! below is the one place in this subsystem that deliberately inverts the
//! project's fail-closed default, which is easier to find here than buried
//! among request handlers.
//!
//! # A pod's lockdown is its subtree's
//!
//! A pod's children hold authority delegated from it, so a lockdown of the pod
//! covers every pod below it in the registry: each is audited, each watcher is
//! told, and none of them may create a pod while it holds. The node keeps the
//! lockdowns in force ([`Active`]) rather than only broadcasting them, so that
//! the same rule decides at admission and for a watcher that connects after
//! the broadcast went out. Admission also refuses a pod that has stopped, or
//! has a stopped pod above it: its subtree's authority is withdrawn at once,
//! not one reaper pass per generation.

use std::collections::HashMap;
use std::sync::Arc;

use uuid::Uuid;

use crate::proto::{LockdownCommand, LockdownRequest, LockdownResponse, lockdown_request};

/// Who issued a lockdown: the peer the gRPC interceptor VERIFIED, never the
/// request's own `operator_id`.
///
/// `LockdownRequest.operator_id` is a string the caller writes. Logging it as
/// the operator let any caller allowed to issue a lockdown record someone else
/// as its author, in the node log, in every pod's lifecycle audit and in the
/// command broadcast to proxies. The name the caller gives is kept, quoted and
/// labelled as a claim, beside the identity that was proved; it never stands in
/// for it.
///
/// Returns the request's body so a handler cannot read `operator_id` without
/// having gone through here: the attribution and the body come out together.
pub(crate) fn attributed(
    request: tonic::Request<crate::proto::LockdownRequest>,
) -> Result<(String, crate::proto::LockdownRequest), tonic::Status> {
    let verified = crate::auth::get_auth_context(&request)
        .map(|ctx| ctx.spiffe_id.clone())
        .ok_or_else(|| tonic::Status::unauthenticated("no authenticated peer"))?;
    let req = request.into_inner();
    let operator = if req.operator_id.is_empty() {
        verified
    } else {
        format!("{verified} (claims {:?})", req.operator_id)
    };
    Ok((operator, req))
}

/// Forward broadcast lockdown commands to one watcher's stream, filtered.
///
/// Lives beside `reaches` rather than in the gRPC handler so the decision and
/// the rule it applies are read together. Every proxy used to receive every
/// command and filter locally, which put pod A's uuid and the operator's
/// free-text reason into every other pod's VM -- the same mistake as returning
/// a full pod list and refusing individually, since the information has already
/// crossed by the time the check runs.
///
/// A watcher that connects while a lockdown covers it is told first: the
/// broadcast it missed is not repeated.
pub(crate) fn spawn_filtered_forwarder(
    state: crate::NodeState,
    mut rx: tokio::sync::broadcast::Receiver<LockdownCommand>,
    tx: tokio::sync::mpsc::Sender<Result<LockdownCommand, tonic::Status>>,
    watcher: Option<Uuid>,
) {
    tokio::spawn(async move {
        if let Some(cmd) = in_force(&state, watcher).await
            && tx.send(Ok(cmd)).await.is_err()
        {
            return;
        }
        while let Ok(cmd) = rx.recv().await {
            let Some(cmd) = delivery(&state, &cmd, watcher).await else {
                continue;
            };
            if tx.send(Ok(cmd)).await.is_err() {
                break; // client disconnected
            }
        }
    });
}

/// The lockdowns in force. Label-selector lockdowns are not held: the proxies
/// apply those to every pod (see [`reaches`]), and the node does not yet
/// evaluate them for itself.
#[derive(Debug, Default)]
pub(crate) struct Active {
    /// Node-wide, with the command that applied it.
    all: Option<LockdownCommand>,
    /// Per locked pod: covers the pod and every pod below it.
    pods: HashMap<Uuid, LockdownCommand>,
}

enum Target {
    All,
    Pod(Uuid),
    Other,
}

fn target(scope: &str) -> Target {
    if scope.is_empty() || scope == "all" {
        return Target::All;
    }
    match scope.strip_prefix("pod:").map(Uuid::parse_str) {
        Some(Ok(id)) => Target::Pod(id),
        _ => Target::Other,
    }
}

impl Active {
    /// Hold `cmd`, or lift what it lifts. Lifting a node-wide lockdown lifts
    /// every lockdown, as it does at every proxy, which holds one switch.
    pub(crate) fn apply(&mut self, cmd: &LockdownCommand) {
        match (target(&cmd.scope), cmd.active) {
            (Target::All, true) => self.all = Some(cmd.clone()),
            (Target::All, false) => *self = Self::default(),
            (Target::Pod(id), true) => {
                self.pods.insert(id, cmd.clone());
            }
            (Target::Pod(id), false) => {
                self.pods.remove(&id);
            }
            (Target::Other, _) => {}
        }
    }

    /// The lockdown that covers a pod whose lineage -- itself, then each pod
    /// above it -- is `lineage`.
    pub(crate) fn covering(&self, lineage: &[Uuid]) -> Option<&LockdownCommand> {
        self.all
            .as_ref()
            .or_else(|| lineage.iter().find_map(|id| self.pods.get(id)))
    }
}

fn held(state: &crate::NodeState) -> std::sync::MutexGuard<'_, Active> {
    state
        .lockdowns
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

type Registry = HashMap<Uuid, Arc<crate::PodHandle>>;

/// `pod`, then each pod above it in the registry. Bounded by the registry's
/// size, so a cycle cannot loop.
fn lineage_in(pods: &Registry, pod: Uuid) -> Vec<Uuid> {
    let mut out = vec![pod];
    while out.len() <= pods.len() {
        let Some(up) = out
            .last()
            .and_then(|id| pods.get(id))
            .and_then(|p| p.parent_pod_id)
        else {
            break;
        };
        out.push(up);
    }
    out
}

async fn lineage(state: &crate::NodeState, pod: Uuid) -> Vec<Uuid> {
    lineage_in(&*state.pods.lock().await, pod)
}

/// What `watcher` is sent for a broadcast `cmd`; `None` is nothing.
///
/// A pod-scoped command reaches the pod's whole subtree. A proxy applies a
/// `pod:` command only when it names the proxy's own pod, so a pod below the
/// target is sent it addressed to itself. A lift reaches only a watcher no
/// other lockdown still covers: lifting a pod's lockdown must not unlock a
/// child that its parent's lockdown still holds.
pub(crate) async fn delivery(
    state: &crate::NodeState,
    cmd: &LockdownCommand,
    watcher: Option<Uuid>,
) -> Option<LockdownCommand> {
    let Some(w) = watcher else {
        return Some(cmd.clone()); // unresolved: deliver, see `reaches`
    };
    let lineage = lineage(state, w).await;
    let reached = match target(&cmd.scope) {
        Target::Pod(t) => lineage.contains(&t),
        _ => reaches(&cmd.scope, Some(w)),
    };
    if !reached || (!cmd.active && held(state).covering(&lineage).is_some()) {
        return None;
    }
    Some(addressed(cmd, w))
}

/// The lockdown in force over `watcher`, addressed to it.
pub(crate) async fn in_force(
    state: &crate::NodeState,
    watcher: Option<Uuid>,
) -> Option<LockdownCommand> {
    let Some(w) = watcher else {
        return held(state).all.clone();
    };
    let lineage = lineage(state, w).await;
    let cmd = held(state).covering(&lineage).cloned()?;
    Some(addressed(&cmd, w))
}

fn addressed(cmd: &LockdownCommand, watcher: Uuid) -> LockdownCommand {
    let mut out = cmd.clone();
    if matches!(target(&cmd.scope), Target::Pod(t) if t != watcher) {
        out.scope = format!("pod:{watcher}");
    }
    out
}

/// Refuse a create a pod asks for while a lockdown covers it, or while it or
/// any pod above it has stopped.
///
/// # Errors
/// [`crate::ApiError::Authority`], naming which.
pub(crate) async fn admits(
    state: &crate::NodeState,
    caller: Option<Uuid>,
) -> Result<(), crate::ApiError> {
    let Some(pod) = caller else {
        return Ok(());
    };
    let (lineage, handles): (Vec<Uuid>, Vec<Arc<crate::PodHandle>>) = {
        let pods = state.pods.lock().await;
        let lineage = lineage_in(&pods, pod);
        let handles = lineage
            .iter()
            .filter_map(|id| pods.get(id).cloned())
            .collect();
        (lineage, handles)
    };
    if let Some(cmd) = held(state).covering(&lineage) {
        tracing::warn!(pod = %pod, lockdown = %cmd.scope, "create refused: the caller is under lockdown");
        return Err(crate::ApiError::Authority(format!(
            "pod {pod} is under lockdown"
        )));
    }
    for h in handles {
        if !matches!(h.status().await, crate::PodState::Running) {
            tracing::warn!(pod = %pod, stopped = %h.id, "create refused: the caller's lineage has stopped");
            return Err(crate::ApiError::Authority(format!(
                "pod {pod} or a pod above it has stopped"
            )));
        }
    }
    Ok(())
}

/// Issue or lift a lockdown attributed to `operator` (see [`attributed`]):
/// hold it, broadcast it, and audit it in every pod it covers.
pub(crate) async fn issue(
    state: &crate::NodeState,
    operator: String,
    req: LockdownRequest,
) -> LockdownResponse {
    let reason = if req.reason.is_empty() {
        "emergency lockdown".to_string()
    } else {
        req.reason.clone()
    };
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let scope = match &req.scope {
        Some(lockdown_request::Scope::PodId(id)) => format!("pod:{id}"),
        Some(lockdown_request::Scope::LabelSelector(sel)) => format!("label:{sel}"),
        None => "all".to_string(),
    };
    let cmd = LockdownCommand {
        active: !req.restore,
        reason: reason.clone(),
        operator_id: operator.clone(),
        timestamp_unix: timestamp,
        scope: scope.clone(),
    };
    // Held BEFORE it is broadcast, so a watcher deciding on the broadcast
    // decides against it.
    held(state).apply(&cmd);
    let broadcast_receivers = state.lockdown_tx.receiver_count();
    let _ = state.lockdown_tx.send(cmd);

    let affected: Vec<Arc<crate::PodHandle>> = {
        let pods = state.pods.lock().await;
        match (&req.scope, target(&scope)) {
            (Some(lockdown_request::Scope::LabelSelector(sel)), _) => pods
                .values()
                .filter(|p| crate::matches_label_selector(&p.spec.metadata.labels, sel))
                .cloned()
                .collect(),
            (Some(lockdown_request::Scope::PodId(_)), Target::Pod(root)) => pods
                .values()
                .filter(|p| lineage_in(&pods, p.id).contains(&root))
                .cloned()
                .collect(),
            (Some(lockdown_request::Scope::PodId(_)), _) => Vec::new(),
            (None, _) => pods.values().cloned().collect(),
        }
    };
    tracing::warn!(
        reason = %reason,
        operator = %operator,
        restore = req.restore,
        scope = %scope,
        affected_pods = affected.len(),
        broadcast_receivers,
        "LOCKDOWN RPC — broadcast to connected proxies"
    );
    let action = if req.restore {
        "lockdown_restored"
    } else {
        "lockdown_applied"
    };
    for pod in &affected {
        tracing::info!(pod_id = %pod.id, action, reason = %reason, operator = %operator, "lockdown: pod affected");
        let pod_dir = pod
            .log_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        crate::lifecycle::write_lifecycle_audit(
            pod_dir,
            action,
            &pod.id.to_string(),
            &format!("reason={reason}, operator={operator}"),
        )
        .await;
    }
    LockdownResponse {
        affected_pods: u32::try_from(affected.len()).unwrap_or(u32::MAX),
        // Not wired until per-pod `AuditEntry::ExecutionBlocked` exists. Do
        // not fabricate counts.
        audit_entries_created: 0,
        timestamp_unix: timestamp,
    }
}

/// Should a lockdown command scoped `scope` reach a watcher that is `watcher`?
///
/// # The direction of the doubt is deliberately opposite to the rest of this arc
///
/// Everything else here fails CLOSED: when the node cannot establish something,
/// it withholds. This fails OPEN, and on purpose. Lockdown is a *safety* control
/// — an operator halting a workload — so the cost of over-delivering is that a
/// pod learns another pod was locked down, while the cost of under-delivering is
/// that a pod the operator meant to stop keeps running. Those are not
/// comparable, and confidentiality does not get to win that trade.
///
/// So anything unresolvable is delivered: an unidentified watcher, an
/// unparseable id, a label selector, an unrecognised scope form. What this
/// removes is the case that is both resolvable and was leaking —
/// `pod:<uuid>` reaching pods that are not that uuid.
///
/// Label selectors are still broadcast. The node holds the PodSpecs and could
/// evaluate them properly — which would also fix the proxy applying label
/// lockdowns it cannot evaluate and so over-applies — but that is a behaviour
/// change to the lockdown semantics rather than to who hears about them, and it
/// belongs in its own change.
pub(crate) fn reaches(scope: &str, watcher: Option<Uuid>) -> bool {
    let Some(watcher) = watcher else {
        return true;
    };
    if scope.is_empty() || scope == "all" {
        return true;
    }
    match scope.strip_prefix("pod:") {
        Some(id) => match Uuid::parse_str(id) {
            Ok(target) => target == watcher,
            // Malformed scope: deliver. See above — a lockdown nobody can parse
            // must not become a lockdown nobody receives.
            Err(_) => true,
        },
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::reaches as lockdown_reaches;
    use uuid::Uuid;

    fn a() -> Uuid {
        Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap()
    }
    fn b() -> Uuid {
        Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap()
    }

    /// **The disclosure this closes.** A lockdown aimed at pod A no longer
    /// reaches pod B, so B's VM never receives A's uuid or the operator's
    /// free-text reason.
    #[test]
    fn a_pod_scoped_lockdown_does_not_reach_other_pods() {
        assert!(!lockdown_reaches(&format!("pod:{}", a()), Some(b())));
    }

    /// And it does still reach its target, or the control would be broken
    /// rather than narrowed.
    #[test]
    fn a_pod_scoped_lockdown_reaches_its_target() {
        assert!(lockdown_reaches(&format!("pod:{}", a()), Some(a())));
    }

    /// A node-wide lockdown reaches everyone. Nothing about scoping may weaken
    /// the operator's blunt instrument.
    #[test]
    fn an_all_scoped_lockdown_reaches_everyone() {
        assert!(lockdown_reaches("all", Some(b())));
        assert!(lockdown_reaches("", Some(b())));
    }

    /// **The fail-OPEN legs**, stated as tests because they are the deliberate
    /// exception to this arc's fail-closed rule. Under-delivering a lockdown
    /// leaves a pod running that an operator meant to stop; over-delivering only
    /// discloses that some pod was locked down. Those costs are not comparable.
    #[test]
    fn anything_unresolvable_is_still_delivered() {
        // No proved identity: cannot decide, so deliver.
        assert!(lockdown_reaches(&format!("pod:{}", a()), None));
        // Label selectors: the node could evaluate these but does not yet.
        assert!(lockdown_reaches("label:tier=prod", Some(b())));
        // Malformed target: a lockdown nobody can parse must not become a
        // lockdown nobody receives.
        assert!(lockdown_reaches("pod:not-a-uuid", Some(b())));
        // Unrecognised scope form.
        assert!(lockdown_reaches("something-new", Some(b())));
    }
}

// Issuing and lifting a lockdown, run against the real `GrpcService` on the pod-API fixture.
#[cfg(all(test, feature = "local-driver"))]
mod authz_tests;
