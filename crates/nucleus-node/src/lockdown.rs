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

/// The lockdowns in force. Label-selector lockdowns are not held. They are
/// delivered as they are issued, to the watchers whose labels match (see
/// [`reaches`]). A watcher that connects afterwards is not told of one, and
/// admission does not refuse on one.
#[derive(Debug, Default)]
pub(crate) struct Active {
    /// Node-wide, with the command that applied it.
    all: Option<LockdownCommand>,
    /// Per locked pod: covers the pod and every pod below it.
    pods: HashMap<Uuid, LockdownCommand>,
}

enum Target<'a> {
    All,
    Pod(Uuid),
    /// `label:<selector>`: the pods whose OWN labels match, the same set
    /// [`issue`] audits.
    Label(&'a str),
    Other,
}

fn target(scope: &str) -> Target<'_> {
    if scope.is_empty() || scope == "all" {
        return Target::All;
    }
    if let Some(selector) = scope.strip_prefix("label:") {
        return Target::Label(selector);
    }
    match scope.strip_prefix("pod:").map(Uuid::parse_str) {
        Some(Ok(id)) => Target::Pod(id),
        _ => Target::Other,
    }
}

/// What the node knows of a watcher, read from its registry: the pod itself
/// then each pod above it, and its own labels. `labels` is `None` when the pod
/// is not in the registry, so no label selector can match it.
pub(crate) struct Watcher<'a> {
    pub(crate) lineage: &'a [Uuid],
    pub(crate) labels: Option<&'a std::collections::BTreeMap<String, String>>,
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
            // Label lockdowns are not held; see `in_force`.
            (Target::Label(_) | Target::Other, _) => {}
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

/// The watcher's lineage and own labels, read under one lock of the registry.
async fn watcher_view(
    state: &crate::NodeState,
    pod: Uuid,
) -> (Vec<Uuid>, Option<std::collections::BTreeMap<String, String>>) {
    let pods = state.pods.lock().await;
    let labels = pods.get(&pod).map(|p| p.spec.metadata.labels.clone());
    (lineage_in(&pods, pod), labels)
}

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
    let (lineage, labels) = watcher_view(state, w).await;
    let reached = reaches(
        &cmd.scope,
        Some(&Watcher {
            lineage: &lineage,
            labels: labels.as_ref(),
        }),
    );
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

/// Should a lockdown command scoped `scope` reach `watcher`?
///
/// The one decider for who hears a lockdown: [`delivery`] reads the watcher's
/// lineage and labels from the registry and asks this.
///
/// - `all`: everyone.
/// - `pod:<uuid>`: the pod and every pod below it (its lineage contains the
///   target).
/// - `label:<selector>`: exactly the pods whose own labels match. The node
///   evaluates the selector with the same `matches_label_selector` that
///   [`issue`] audits with.
///
/// A label lockdown used to be broadcast to every proxy. A pod the selector did
/// not match was still sent the operator's free-text reason and the selector
/// itself, which names another pod's labels. The proxy cannot evaluate a
/// selector, so it then applied the lockdown to itself. That was a leak and an
/// over-application in one.
///
/// # The direction of the doubt for what the node cannot resolve
///
/// Everything else here fails CLOSED. This fails OPEN in two cases, on
/// purpose:
/// - an unidentified watcher (`None`). This is never a pod peer, because a pod
///   peer always resolves.
/// - a scope the node cannot parse.
///
/// Lockdown is a *safety* control. Over-delivering costs a watcher learning
/// that some pod was locked down. Under-delivering costs a pod the operator
/// meant to stop that keeps running. A label selector is not in that set: the
/// node holds every PodSpec, so the selector is resolvable, and it is resolved.
pub(crate) fn reaches(scope: &str, watcher: Option<&Watcher<'_>>) -> bool {
    let Some(watcher) = watcher else {
        return true;
    };
    match target(scope) {
        Target::All | Target::Other => true,
        Target::Pod(t) => watcher.lineage.contains(&t),
        Target::Label(selector) => watcher
            .labels
            .is_some_and(|labels| crate::matches_label_selector(labels, selector)),
    }
}

#[cfg(test)]
mod tests {
    use super::{Watcher, reaches as lockdown_reaches};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn a() -> Uuid {
        Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap()
    }
    fn b() -> Uuid {
        Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap()
    }
    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// **The disclosure this closes.** A lockdown aimed at pod A no longer
    /// reaches pod B, so B's VM never receives A's uuid or the operator's
    /// free-text reason.
    #[test]
    fn a_pod_scoped_lockdown_does_not_reach_other_pods() {
        let lineage = [b()];
        let w = Watcher {
            lineage: &lineage,
            labels: None,
        };
        assert!(!lockdown_reaches(&format!("pod:{}", a()), Some(&w)));
    }

    /// And it does still reach its target, or the control would be broken
    /// rather than narrowed.
    #[test]
    fn a_pod_scoped_lockdown_reaches_its_target() {
        let lineage = [a()];
        let w = Watcher {
            lineage: &lineage,
            labels: None,
        };
        assert!(lockdown_reaches(&format!("pod:{}", a()), Some(&w)));
    }

    /// **The label disclosure this closes.** A label lockdown reaches exactly
    /// the pods whose own labels match it. A pod it does not match is sent
    /// nothing: not the reason, and not the selector naming another pod's
    /// labels.
    #[test]
    fn a_label_scoped_lockdown_reaches_only_the_pods_it_matches() {
        let lineage = [b()];
        let prod = labels(&[("tier", "prod"), ("team", "x")]);
        let dev = labels(&[("tier", "dev")]);
        let matched = Watcher {
            lineage: &lineage,
            labels: Some(&prod),
        };
        let unmatched = Watcher {
            lineage: &lineage,
            labels: Some(&dev),
        };
        let unregistered = Watcher {
            lineage: &lineage,
            labels: None,
        };
        assert!(lockdown_reaches("label:tier=prod", Some(&matched)));
        assert!(lockdown_reaches("label:tier=prod,team=x", Some(&matched)));
        assert!(!lockdown_reaches("label:tier=prod", Some(&unmatched)));
        assert!(!lockdown_reaches("label:tier=prod,team=y", Some(&matched)));
        assert!(!lockdown_reaches("label:tier=prod", Some(&unregistered)));
        // The empty selector matches every pod, as it does in `issue`.
        assert!(lockdown_reaches("label:", Some(&unmatched)));
    }

    /// A node-wide lockdown reaches everyone. Nothing about scoping may weaken
    /// the operator's blunt instrument.
    #[test]
    fn an_all_scoped_lockdown_reaches_everyone() {
        let lineage = [b()];
        let w = Watcher {
            lineage: &lineage,
            labels: None,
        };
        assert!(lockdown_reaches("all", Some(&w)));
        assert!(lockdown_reaches("", Some(&w)));
    }

    /// **The fail-OPEN legs**, stated as tests because they are the deliberate
    /// exception to this arc's fail-closed rule.
    #[test]
    fn anything_unresolvable_is_still_delivered() {
        let lineage = [b()];
        let w = Watcher {
            lineage: &lineage,
            labels: None,
        };
        // No proved identity: cannot decide, so deliver.
        assert!(lockdown_reaches(&format!("pod:{}", a()), None));
        assert!(lockdown_reaches("label:tier=prod", None));
        // Malformed target: a lockdown nobody can parse must not become a
        // lockdown nobody receives.
        assert!(lockdown_reaches("pod:not-a-uuid", Some(&w)));
        // Unrecognised scope form.
        assert!(lockdown_reaches("something-new", Some(&w)));
    }
}

// Issuing and lifting a lockdown, run against the real `GrpcService` on the pod-API fixture.
#[cfg(all(test, feature = "local-driver"))]
mod authz_tests;
