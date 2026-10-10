//! Issuing a lockdown, holding it, and who it reaches.
//!
//! Its own module because `main.rs` carries a line ratchet and anything added
//! must be paid for by something taken out -- and because who hears a
//! lockdown, and who may create a pod while one holds, is easier to read in
//! one place than buried among request handlers.
//!
//! # A lockdown is held, whatever its scope
//!
//! The node keeps every lockdown in force ([`Active`]) rather than only
//! broadcasting it, so that the same rule ([`reaches`]) decides at admission
//! and for a watcher that connects after the broadcast went out.
//!
//! - A pod's children hold authority delegated from it, so a lockdown of the
//!   pod covers every pod below it in the registry: each is audited, each
//!   watcher is told, and none of them may create a pod while it holds.
//! - A label lockdown covers the pods whose own labels match its selector,
//!   including one that is created, or connects, after it was issued. A create
//!   whose spec carries labels the selector matches is refused while it holds.
//!
//! Admission also refuses a pod that has stopped, or has a stopped pod above
//! it: its subtree's authority is withdrawn at once, not one reaper pass per
//! generation.

use std::collections::{BTreeMap, HashMap};
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

/// The pod a `WatchLockdown` stream is for, or the stream is refused.
///
/// Only a pod watches: the one real watcher is a pod's tool-proxy, which
/// presents its pod certificate. A peer the node cannot resolve to a pod used
/// to be sent every command unfiltered -- every pod's uuid and every
/// operator's free-text reason -- which made an operator credential a
/// read-everything tap. Refusing it costs no watcher anything, because none
/// depends on it.
///
/// # Errors
/// `PERMISSION_DENIED` when the authenticated peer is not a pod.
pub(crate) fn watcher(
    state: &crate::NodeState,
    md: &tonic::metadata::MetadataMap,
    extensions: &tonic::Extensions,
) -> Result<Uuid, tonic::Status> {
    crate::pod_api::grpc_caller(state, md, extensions)?
        .pod()
        .ok_or_else(|| tonic::Status::permission_denied("only a pod may watch for lockdowns"))
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
    watcher: Uuid,
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

/// The lockdowns in force, each with the command that applied it.
#[derive(Debug, Default)]
pub(crate) struct Active {
    /// Node-wide.
    all: Option<LockdownCommand>,
    /// Per locked pod: covers the pod and every pod below it.
    pods: HashMap<Uuid, LockdownCommand>,
    /// Per label selector: covers the pods whose own labels match it, and
    /// refuses creating one.
    labels: BTreeMap<String, LockdownCommand>,
}

enum Target<'a> {
    All,
    Pod(Uuid),
    /// `label:<selector>`: the pods whose OWN labels match, the same set
    /// [`issue`] audits.
    Label(&'a str),
    /// Reaches nobody. [`issue`] refuses to issue one, so only a command from
    /// somewhere else could carry it.
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
    pub(crate) labels: Option<&'a BTreeMap<String, String>>,
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
            (Target::Label(selector), true) => {
                self.labels.insert(selector.to_string(), cmd.clone());
            }
            (Target::Label(selector), false) => {
                self.labels.remove(selector);
            }
            // Reaches nobody, so there is nothing to hold.
            (Target::Other, _) => {}
        }
    }

    /// The first lockdown in force that [`reaches`] `watcher`: node-wide, then
    /// its own pod's and each pod's above it, then a label lockdown.
    pub(crate) fn covering(&self, watcher: &Watcher<'_>) -> Option<&LockdownCommand> {
        self.all
            .iter()
            .chain(watcher.lineage.iter().filter_map(|id| self.pods.get(id)))
            .chain(self.labels.values())
            .find(|cmd| reaches(&cmd.scope, watcher))
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
) -> (Vec<Uuid>, Option<BTreeMap<String, String>>) {
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

/// What `watcher` is sent for a broadcast `cmd`; `None` is nothing.
///
/// A pod-scoped command reaches the pod's whole subtree. A proxy applies a
/// `pod:` command only when it names the proxy's own pod, so a pod below the
/// target is sent it addressed to itself. A lift reaches only a watcher no
/// other lockdown still covers: lifting one lockdown must not unlock a pod
/// that another -- its parent's, or a label's -- still holds.
pub(crate) async fn delivery(
    state: &crate::NodeState,
    cmd: &LockdownCommand,
    watcher: Uuid,
) -> Option<LockdownCommand> {
    let (lineage, labels) = watcher_view(state, watcher).await;
    let w = Watcher {
        lineage: &lineage,
        labels: labels.as_ref(),
    };
    if !reaches(&cmd.scope, &w) || (!cmd.active && held(state).covering(&w).is_some()) {
        return None;
    }
    Some(addressed(cmd, watcher))
}

/// The lockdown in force over `watcher`, addressed to it.
pub(crate) async fn in_force(state: &crate::NodeState, watcher: Uuid) -> Option<LockdownCommand> {
    let (lineage, labels) = watcher_view(state, watcher).await;
    let w = Watcher {
        lineage: &lineage,
        labels: labels.as_ref(),
    };
    let cmd = held(state).covering(&w).cloned()?;
    Some(addressed(&cmd, watcher))
}

fn addressed(cmd: &LockdownCommand, watcher: Uuid) -> LockdownCommand {
    let mut out = cmd.clone();
    if matches!(target(&cmd.scope), Target::Pod(t) if t != watcher) {
        out.scope = format!("pod:{watcher}");
    }
    out
}

/// Refuse a create a pod asks for while a lockdown covers it, or while it or
/// any pod above it has stopped; and refuse, whoever asks, a pod whose own
/// `labels` a label lockdown in force matches.
///
/// The refusal of a labelled create names the lockdown by its scope and when
/// it was issued, never by its reason: the reason goes only to pods the
/// selector matches, and a pod being created is not one yet. The selector is
/// named, because it matches labels the creator wrote.
///
/// # Errors
/// [`crate::ApiError::Authority`], naming which.
pub(crate) async fn admits(
    state: &crate::NodeState,
    caller: Option<Uuid>,
    labels: &BTreeMap<String, String>,
) -> Result<(), crate::ApiError> {
    if let Some(pod) = caller {
        let (lineage, own, handles) = {
            let pods = state.pods.lock().await;
            let lineage = lineage_in(&pods, pod);
            let own = pods.get(&pod).map(|p| p.spec.metadata.labels.clone());
            let handles: Vec<Arc<crate::PodHandle>> = lineage
                .iter()
                .filter_map(|id| pods.get(id).cloned())
                .collect();
            (lineage, own, handles)
        };
        let w = Watcher {
            lineage: &lineage,
            labels: own.as_ref(),
        };
        if let Some(cmd) = held(state).covering(&w) {
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
    }
    // The pod being created: no lineage of its own in the registry yet, only
    // the labels its spec carries. Only a label lockdown can match that.
    let new = Watcher {
        lineage: &[],
        labels: Some(labels),
    };
    if let Some(cmd) = held(state)
        .labels
        .values()
        .find(|cmd| reaches(&cmd.scope, &new))
    {
        tracing::warn!(lockdown = %cmd.scope, issued = cmd.timestamp_unix, "create refused: a label lockdown matches the pod's labels");
        return Err(crate::ApiError::Authority(format!(
            "the lockdown {} issued at {} (unix seconds) matches this pod's labels",
            cmd.scope, cmd.timestamp_unix
        )));
    }
    Ok(())
}

/// The scope `req` names, written as a command carries it; or the request is
/// refused, before anything is held or broadcast.
///
/// A scope the node cannot parse used to be issued and then delivered to every
/// watcher: `pod:not-a-uuid` locked down every pod and told each one the
/// reason. It is refused instead, where the operator who wrote it sees why.
fn requested_scope(scope: Option<&lockdown_request::Scope>) -> Result<String, tonic::Status> {
    match scope {
        None => Ok("all".to_string()),
        Some(lockdown_request::Scope::PodId(id)) => Uuid::parse_str(id)
            .map(|id| format!("pod:{id}"))
            .map_err(|_| tonic::Status::invalid_argument(format!("pod id {id:?} is not a uuid"))),
        Some(lockdown_request::Scope::LabelSelector(selector)) => {
            // The empty selector matches every pod; otherwise every
            // comma-separated pair is `key=value` with a non-empty key.
            let parses = selector.is_empty()
                || selector.split(',').all(|pair| {
                    pair.split_once('=')
                        .is_some_and(|(key, _)| !key.trim().is_empty())
                });
            if parses {
                Ok(format!("label:{selector}"))
            } else {
                Err(tonic::Status::invalid_argument(format!(
                    "label selector {selector:?} is not a comma-separated list of key=value"
                )))
            }
        }
    }
}

/// Issue or lift a lockdown attributed to `operator` (see [`attributed`]):
/// hold it, broadcast it, and audit it in every pod it covers.
///
/// # Errors
/// `INVALID_ARGUMENT` for a scope the node cannot parse; nothing is held,
/// broadcast or audited.
pub(crate) async fn issue(
    state: &crate::NodeState,
    operator: String,
    req: LockdownRequest,
) -> Result<LockdownResponse, tonic::Status> {
    let scope = requested_scope(req.scope.as_ref())?;
    let reason = if req.reason.is_empty() {
        "emergency lockdown".to_string()
    } else {
        req.reason.clone()
    };
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
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
        match target(&scope) {
            Target::All => pods.values().cloned().collect(),
            Target::Label(selector) => pods
                .values()
                .filter(|p| crate::matches_label_selector(&p.spec.metadata.labels, selector))
                .cloned()
                .collect(),
            Target::Pod(root) => pods
                .values()
                .filter(|p| lineage_in(&pods, p.id).contains(&root))
                .cloned()
                .collect(),
            Target::Other => Vec::new(),
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
    Ok(LockdownResponse {
        affected_pods: u32::try_from(affected.len()).unwrap_or(u32::MAX),
        // Not wired until per-pod `AuditEntry::ExecutionBlocked` exists. Do
        // not fabricate counts.
        audit_entries_created: 0,
        timestamp_unix: timestamp,
    })
}

/// Should a lockdown command scoped `scope` reach `watcher`?
///
/// The one decider for who hears a lockdown and whom a held one covers:
/// [`delivery`], [`in_force`] and [`admits`] all ask this, through
/// [`Active::covering`] or directly.
///
/// - `all`: everyone.
/// - `pod:<uuid>`: the pod and every pod below it (its lineage contains the
///   target).
/// - `label:<selector>`: exactly the pods whose own labels match. The node
///   evaluates the selector with the same `matches_label_selector` that
///   [`issue`] audits with.
/// - anything else: nobody.
///
/// A label lockdown used to be broadcast to every proxy. A pod the selector did
/// not match was still sent the operator's free-text reason and the selector
/// itself, which names another pod's labels. The proxy cannot evaluate a
/// selector, so it then applied the lockdown to itself. That was a leak and an
/// over-application in one.
///
/// This used to fail OPEN in two cases: an unidentified watcher, and a scope
/// the node could not parse. Both are closed at their source rather than here:
/// [`watcher`] refuses a stream to anyone but a pod, and [`issue`] refuses a
/// scope it could not parse. What is left unparseable reaches nobody.
pub(crate) fn reaches(scope: &str, watcher: &Watcher<'_>) -> bool {
    match target(scope) {
        Target::All => true,
        Target::Pod(t) => watcher.lineage.contains(&t),
        Target::Label(selector) => watcher
            .labels
            .is_some_and(|labels| crate::matches_label_selector(labels, selector)),
        Target::Other => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{Watcher, reaches as lockdown_reaches, requested_scope};
    use crate::proto::lockdown_request::Scope;
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
        assert!(!lockdown_reaches(&format!("pod:{}", a()), &w));
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
        assert!(lockdown_reaches(&format!("pod:{}", a()), &w));
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
        assert!(lockdown_reaches("label:tier=prod", &matched));
        assert!(lockdown_reaches("label:tier=prod,team=x", &matched));
        assert!(!lockdown_reaches("label:tier=prod", &unmatched));
        assert!(!lockdown_reaches("label:tier=prod,team=y", &matched));
        assert!(!lockdown_reaches("label:tier=prod", &unregistered));
        // The empty selector matches every pod, as it does in `issue`.
        assert!(lockdown_reaches("label:", &unmatched));
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
        assert!(lockdown_reaches("all", &w));
        assert!(lockdown_reaches("", &w));
    }

    /// **The fail-open leg this closes.** A scope the node cannot parse used to
    /// reach every watcher. It now reaches nobody, and [`requested_scope`]
    /// refuses to issue one.
    #[test]
    fn an_unparseable_scope_reaches_nobody() {
        let lineage = [b()];
        let w = Watcher {
            lineage: &lineage,
            labels: None,
        };
        assert!(!lockdown_reaches("pod:not-a-uuid", &w));
        assert!(!lockdown_reaches("something-new", &w));
    }

    /// The scopes a request may name, and the ones refused before anything is
    /// held or broadcast.
    #[test]
    fn an_unparseable_scope_is_refused_at_issue() {
        let pod = |s: &str| Some(Scope::PodId(s.to_string()));
        let sel = |s: &str| Some(Scope::LabelSelector(s.to_string()));
        for ok in [
            None,
            pod(&a().to_string()),
            sel(""),
            sel("tier=prod"),
            sel("tier=prod, team=x"),
            sel("tier="),
        ] {
            assert!(requested_scope(ok.as_ref()).is_ok(), "{ok:?}");
        }
        for bad in [
            pod("not-a-uuid"),
            pod(""),
            sel("tier"),
            sel("=prod"),
            sel(" =prod"),
            sel("tier=prod,"),
            sel("tier=prod,team"),
        ] {
            let got = requested_scope(bad.as_ref()).map_err(|s| s.code());
            assert_eq!(got, Err(tonic::Code::InvalidArgument), "{bad:?}");
        }
    }
}

// Issuing and lifting a lockdown, run against the real `GrpcService` on the pod-API fixture.
#[cfg(all(test, feature = "local-driver"))]
mod authz_tests;
