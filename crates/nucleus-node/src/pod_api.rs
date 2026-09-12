//! The pod-management HTTP surface: list, logs, cancel.
//!
//! Extracted from `main.rs` because the line ratchet on that file requires
//! anything added to be paid for by something taken out, and these four
//! functions are the most cohesive block available: they are the entire
//! read/cancel API over `NodeState.pods`, and they are what the ownership work
//! extends next. Extracting them here means that change edits a 60-line module
//! rather than growing a 4000-line one further.
//!
//! Nothing about the behaviour changes in this move.

use crate::{ApiError, NodeState, PodHandle, PodInfo};
use axum::Json;
use axum::extract::{Extension, Path as AxumPath, State};
use std::sync::Arc;
use uuid::Uuid;

/// The node's live pod registry: pod id → handle, behind an async lock. A
/// read-only clone of this `Arc` is what a [`PodListView`] holds to serve the
/// guest→host `PodList` command, so `NodeState.pods` and that seam name one type.
pub(crate) type PodRegistry =
    Arc<tokio::sync::Mutex<std::collections::HashMap<Uuid, Arc<PodHandle>>>>;

/// May `caller` manage `pod`?
///
/// # Why this is node-side
///
/// The equivalent check used to live in the tool-proxy, which is where
/// `check_manage_pods` already sat. That placement had a stated residual: every
/// proxy holds the node-wide auth secret, so a compromised proxy could simply
/// not perform the check. Enforcement here does not depend on the caller
/// behaving, because the caller's identity is established by the node from a
/// token it minted and the lineage is recorded by the node at creation.
///
/// # The unidentified case is deliberately permitted
///
/// `None` means no pod identity was proved -- an operator, or a client holding
/// the node auth secret directly. That secret is *already* full node authority,
/// so refusing here would break existing operators while granting no security:
/// anyone who can reach this code path without a pod identity could equally
/// create a pod and act through it. The check narrows authority for pods, which
/// is where the excess authority actually was.
///
/// # Why `ManagePods` was not enough
///
/// `check_manage_pods` asks whether the caller holds the capability. It never
/// asked WHICH pods that authorises, so any pod holding it could list, read the
/// logs of, and cancel every pod on the node -- including other tenants'. The
/// node had recorded lineage all along and consulted it only for cascade-cancel.
fn caller_may_manage(caller: Option<Uuid>, pod_id: Uuid, parent_pod_id: Option<Uuid>) -> bool {
    let Some(caller) = caller else {
        return true;
    };
    // DIRECT children, and itself -- not the transitive descendant closure.
    //
    // A grandparent cannot manage a grandchild through this API. That is
    // deliberate: the transitive version would have to walk the pod map per
    // check, which is a cycle risk on a field that is only as acyclic as the
    // code maintaining it, and it would widen authority on the strength of a
    // graph traversal rather than a single recorded fact. Cascade-cancel already
    // walks lineage recursively where recursion is actually wanted.
    //
    // If a grandparent needs reach, the honest way to get it is for the
    // intermediate pod to expose it, not for this predicate to grow a search.
    parent_pod_id == Some(caller) || pod_id == caller
}

/// The parent to record for a pod being created.
///
/// A proved caller identity wins outright; the header is only consulted when
/// nothing was proved. See the call site for why the header alone is not
/// trustworthy.
pub(crate) fn resolve_parent_pod_id(caller: Option<Uuid>, header: Option<&str>) -> Option<Uuid> {
    match caller {
        Some(pod_id) => Some(pod_id),
        None => header.and_then(|s| Uuid::parse_str(s).ok()),
    }
}

pub(crate) async fn list_pods(
    State(state): State<NodeState>,
    Extension(caller): Extension<Option<Uuid>>,
) -> Result<Json<Vec<PodInfo>>, ApiError> {
    let infos = collect_pod_infos(&state, caller).await;
    Ok(Json(infos))
}

/// The lineage facts the cross-pod scoping predicate reads.
///
/// Abstracting the two fields the filter consults lets the SAME selection run
/// over the live registry (`Arc<PodHandle>`) and over a lightweight test
/// registry, so the shipped set operation cannot diverge from what the test
/// checks — the pointwise `caller_may_manage` tests never exercised the actual
/// `.filter` as a SET (a sibling being *excluded* vs never present).
trait Lineage {
    fn lineage_id(&self) -> Uuid;
    fn lineage_parent(&self) -> Option<Uuid>;
}

impl Lineage for Arc<PodHandle> {
    fn lineage_id(&self) -> Uuid {
        self.id
    }
    fn lineage_parent(&self) -> Option<Uuid> {
        self.parent_pod_id
    }
}

/// Select the items an identified pod `caller` may manage, by the same
/// `caller_may_manage` predicate the HTTP listing and the management gate use.
///
/// This is the SET operation the cross-pod listing performs. `caller` is a
/// concrete pod id — never the operator `None` — because a pod view is always
/// identified; the operator (all-pods) case stays in `collect_pod_infos` where
/// the absence of an identity is what it means. It is factored out precisely so
/// C2 G3's guest→host `PodList` command can apply the identical filter with a
/// socket-bound caller, over this one tested function rather than a copy.
fn scope_to_caller<T: Lineage + Clone>(items: &[T], caller: Uuid) -> Vec<T> {
    items
        .iter()
        .filter(|it| caller_may_manage(Some(caller), it.lineage_id(), it.lineage_parent()))
        .cloned()
        .collect()
}

/// A read-only, scope-frozen window on the pod registry for ONE pod.
///
/// This is the authority the guest→host `PodList` command (`workload_api_vsock`)
/// is given, and it is deliberately the least it can be: a clone of the registry
/// `Arc` and a `caller` bound at construction with no setter, so no dispatch path
/// can widen the scope by supplying a different pod id. The caller is the pod
/// that owns the vsock socket the request arrived on — the socket authenticates
/// it, so nothing the guest says is trusted.
///
/// It carries NONE of the node's secrets (`caller_secret`, `proxy_auth_secret`,
/// the signing keys live on `NodeState`, not here), and exposes only
/// `scoped_infos`. A pod reaching it learns exactly the `PodInfo`s its own
/// lineage already entitles it to over `/v1/pods` — its own row and its direct
/// children — and nothing about a sibling.
pub(crate) struct PodListView {
    pods: PodRegistry,
    caller: Uuid,
}

impl PodListView {
    /// Bind the view to `caller` — the pod that owns the socket the request
    /// arrived on. Frozen here; there is no setter and no other constructor.
    pub(crate) fn for_pod(pods: PodRegistry, caller: Uuid) -> Self {
        Self { pods, caller }
    }

    /// The pod summaries this pod is entitled to — its own lineage only, by the
    /// SAME `scope_to_caller` filter the `/v1/pods` listing runs, so a sibling
    /// is excluded. Identical composition to `collect_pod_infos(_, Some(caller))`.
    pub(crate) async fn scoped_infos(&self) -> Vec<PodInfo> {
        let pods: Vec<Arc<PodHandle>> = {
            let guard = self.pods.lock().await;
            scope_to_caller(&guard.values().cloned().collect::<Vec<_>>(), self.caller)
        };
        let mut infos = Vec::with_capacity(pods.len());
        for pod in pods {
            infos.push(pod.info().await);
        }
        infos
    }
}

/// Pod summaries the caller is entitled to see.
///
/// Filtering here rather than at the handler is deliberate: the listing is how a
/// caller LEARNS the pod UUIDs it would then pass to `pod_logs` or `cancel_pod`.
/// Returning the full list and refusing individually would hand out the
/// identifiers first and refuse afterwards.
pub(crate) async fn collect_pod_infos(state: &NodeState, caller: Option<Uuid>) -> Vec<PodInfo> {
    let pods: Vec<Arc<PodHandle>> = {
        let guard = state.pods.lock().await;
        let all: Vec<Arc<PodHandle>> = guard.values().cloned().collect();
        // An identified pod is scoped by the shared set filter; an operator
        // (`None` — holds the node auth secret directly) sees every pod.
        match caller {
            Some(c) => scope_to_caller(&all, c),
            None => all,
        }
    };

    let mut infos = Vec::with_capacity(pods.len());
    for pod in pods {
        infos.push(pod.info().await);
    }

    infos
}

pub(crate) async fn pod_logs(
    State(state): State<NodeState>,
    Extension(caller): Extension<Option<Uuid>>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<String, ApiError> {
    let pod = get_pod_for_caller(&state, id, caller).await?;
    let logs = tokio::fs::read_to_string(&pod.log_path)
        .await
        .unwrap_or_default();
    Ok(logs)
}

pub(crate) async fn cancel_pod(
    State(state): State<NodeState>,
    Extension(caller): Extension<Option<Uuid>>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pod = get_pod_for_caller(&state, id, caller).await?;
    pod.cancel().await?;
    Ok(Json(serde_json::json!({"status": "cancelled"})))
}

pub(crate) async fn get_pod(state: &NodeState, id: Uuid) -> Result<Arc<PodHandle>, ApiError> {
    let guard = state.pods.lock().await;
    guard.get(&id).cloned().ok_or(ApiError::NotFound)
}

/// Resolve a pod, but only if this caller may manage it.
///
/// Returns `NotFound` -- not a distinct "forbidden" -- when the pod exists and
/// the caller may not touch it. Distinguishing the two would answer "does pod
/// <uuid> exist on this node?" for any caller willing to probe, which is exactly
/// the fact that filtering the listing withholds. The refusal must not restore
/// by oracle what the filter removed.
pub(crate) async fn get_pod_for_caller(
    state: &NodeState,
    id: Uuid,
    caller: Option<Uuid>,
) -> Result<Arc<PodHandle>, ApiError> {
    let pod = get_pod(state, id).await?;
    scoped_lookup(std::slice::from_ref(&pod), id, caller).ok_or_else(|| {
        tracing::warn!(
            %id,
            caller = ?caller,
            "a pod tried to manage a pod it does not own"
        );
        ApiError::NotFound
    })
}

/// The single-item form of the scoping filter: `id` resolves for `caller` iff
/// it is present AND `caller_may_manage` admits it. The same predicate as
/// `scope_to_caller`, so a pod that is filtered OUT of the listing cannot be
/// reached by id either — over HTTP or gRPC, which both call this.
fn scoped_lookup<T: Lineage + Clone>(items: &[T], id: Uuid, caller: Option<Uuid>) -> Option<T> {
    items
        .iter()
        .find(|it| {
            it.lineage_id() == id && caller_may_manage(caller, it.lineage_id(), it.lineage_parent())
        })
        .cloned()
}

/// WHICH pod a gRPC request proves it is, from the same two metadata entries
/// the HTTP middleware reads — and with the same outcome for an unprovable
/// claim (`.ok()`: treated as no identity, exactly as `auth_middleware` does),
/// so the two transports cannot disagree about who is calling (#2475).
pub(crate) fn grpc_caller(caller_secret: &[u8], md: &tonic::metadata::MetadataMap) -> Option<Uuid> {
    crate::pod_caller_identity::identify_from_metadata(caller_secret, md).ok()
}

/// Resolve a pod named on the wire for a gRPC caller: parse the id, identify
/// the caller, and look the pod up through the SAME ownership-scoped path the
/// HTTP handlers use. A pod the caller may not manage is `NOT_FOUND`, never a
/// distinguishable refusal (#2475; the oracle argument on `get_pod_for_caller`).
pub(crate) async fn grpc_scoped_pod(
    state: &NodeState,
    md: &tonic::metadata::MetadataMap,
    raw_id: &str,
) -> Result<Arc<PodHandle>, tonic::Status> {
    let id =
        Uuid::parse_str(raw_id).map_err(|_| tonic::Status::invalid_argument("invalid pod id"))?;
    let caller = grpc_caller(state.caller_secret.as_ref(), md);
    get_pod_for_caller(state, id, caller)
        .await
        .map_err(|_| tonic::Status::not_found("pod not found"))
}

/// Take a base snapshot of a running pod.
///
/// # Why this is an explicit request and not automatic
///
/// Create costs ~480 ms because it writes the whole guest memory to disk, against ~10 ms to
/// restore. Snapshotting every pod at its barrier would pay that on every launch to build bases
/// that mostly go unused. So the decision belongs to whoever knows this program is worth basing —
/// an orchestrator asks, and the node answers with a verdict rather than a courtesy.
///
/// # What it refuses, and why the refusal is the interesting part
///
/// The safety verdict is computed from the HOST's record of what it served this guest, never from
/// anything the guest says: `at_snapshot_barrier` and `personalized` are set as a side effect of
/// answering vsock commands. A pod that has already been handed its broker secret is refused,
/// because that secret is served exactly once and a clone would share it — the failure this
/// barrier exists to prevent, and one that is otherwise completely silent.
pub(crate) async fn snapshot_pod(
    State(state): State<NodeState>,
    Extension(caller): Extension<Option<Uuid>>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pod = get_pod_for_caller(&state, id, caller).await?;
    snapshot_running_pod(&state, &pod).await
}

#[cfg(not(target_os = "linux"))]
async fn snapshot_running_pod(
    _state: &NodeState,
    _pod: &Arc<PodHandle>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Err(ApiError::Driver(
        "snapshots require the Firecracker driver, which is Linux-only".to_string(),
    ))
}

#[cfg(target_os = "linux")]
async fn snapshot_running_pod(
    state: &NodeState,
    pod: &Arc<PodHandle>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use crate::snapshot_store::{HostIdentity, Lookup, PublishError, SnapshotStore};

    let crate::DriverState::Firecracker(fc) = &pod.driver_state else {
        return Err(ApiError::Driver(
            "only a Firecracker pod can be snapshotted".to_string(),
        ));
    };
    // Absent only when the VMM's `--version` was unreadable at launch. That is already refused
    // upstream, so reaching here means something changed underneath — which is exactly when
    // naming a snapshot after an assumed version would be worst.
    let Some(inputs) = fc.snapshot.as_ref() else {
        return Err(ApiError::Driver(
            "this pod's VMM version was never established, so a base cannot be named".to_string(),
        ));
    };

    // The two host-recorded facts. A pod whose bridge is gone cannot be shown to be at its
    // barrier, and "cannot be shown" must read as "not", or the gate is decorative.
    let (at_barrier, personalized) = {
        let bridge = fc.workload_api_bridge.lock().await;
        bridge.as_ref().map_or((false, false), |b| {
            let m = b.material();
            (
                m.at_snapshot_barrier
                    .load(std::sync::atomic::Ordering::SeqCst),
                m.personalized.load(std::sync::atomic::Ordering::SeqCst),
            )
        })
    };
    let safety = crate::snapshot::clone_safety(
        &inputs.boot_args,
        at_barrier,
        personalized,
        // No scratch at all is `NeverMounted`: nothing to carry stale metadata.
        &inputs
            .scratch_path
            .as_deref()
            .map_or(crate::snapshot::MountState::NeverMounted, |p| {
                crate::snapshot::mount_state(p)
            }),
    );

    let program = nucleus_spec::identity::program_digest(&pod.spec)
        .map_err(|e| ApiError::Driver(format!("this pod has no program identity: {e}")))?;
    let derivation = inputs.derivation(program);
    let name = derivation.name();

    let store = SnapshotStore::new(state.state_dir.join("snapshots"), HostIdentity::detect());
    match store.lookup(&derivation) {
        // Idempotent: asking twice for a base that exists is not an error, and re-taking it would
        // spend 480 ms to produce a byte-different snapshot of the same program.
        Lookup::Present(m) => {
            return Ok(Json(serde_json::json!({
                "status": "already-present", "derivation": name,
                "created_unix": m.created_unix, "mem_bytes": m.mem_bytes
            })));
        }
        Lookup::ForeignHost {
            taken_on,
            running_on,
        } => {
            // Both machines, deliberately. The whole reason this is a refusal rather than a miss
            // is so somebody can read it and see WHICH two hosts disagree.
            return Err(ApiError::Driver(format!(
                "a base for this derivation exists but was taken on {}/{}, and this node is \
                 {}/{} — restoring across hosts is refused",
                taken_on.arch, taken_on.cpu_model, running_on.arch, running_on.cpu_model
            )));
        }
        Lookup::Damaged(why) => {
            return Err(ApiError::Driver(format!(
                "the existing base for this derivation is unreadable ({why}); remove it first"
            )));
        }
        Lookup::Absent => {}
    }

    let pod_dir = pod
        .log_path
        .parent()
        .ok_or_else(|| ApiError::Driver("this pod has no directory".to_string()))?;
    let sock = {
        let jail = fc.jail.lock().await;
        crate::firecracker_api::api_socket_path(jail.as_ref(), pod_dir)
    };

    // Reclaim what previous attempts stranded before adding another memory image to the disk.
    // A failure here is logged, not fatal: not reclaiming space is a worse reason to refuse a
    // snapshot than running out of it would be to fail one.
    match store.sweep_staging() {
        Ok(swept) if !swept.is_empty() => {
            tracing::info!(count = swept.len(), "reclaimed stranded snapshot staging")
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "could not sweep snapshot staging"),
    }

    let incoming = store
        .begin()
        .map_err(|e| ApiError::Driver(format!("could not stage a snapshot: {e}")))?;
    let created = crate::snapshot_vmm::create(&sock, &safety, &incoming.artifacts).await;

    // Resume BEFORE publishing, and regardless of whether the snapshot succeeded. `create` leaves
    // the microVM Paused, so any early return between here and there strands a running pod frozen
    // — a snapshot request must not be able to kill the workload it snapshotted.
    //
    // Resuming the origin is safe by the barrier's own argument: nothing per-pod has been served
    // yet, so the origin and any future clone are not yet distinguishable in a way that matters.
    let resumed = crate::snapshot_vmm::resume(&sock).await;
    created.map_err(ApiError::Driver)?;
    resumed
        .map_err(|e| ApiError::Driver(format!("snapshot taken, but the pod stayed paused: {e}")))?;

    // What the host was NOT providing when this base was taken. Recorded on the artifact rather
    // than checked here: nothing shares memory across pods yet, so refusing an unhardened host
    // would block the only thing that works for a risk that does not exist. But it is a fact about
    // THIS base and cannot be recovered later — harden the host tomorrow and the base would look
    // safer than it was.
    let unmet_hardening: Vec<String> = crate::host_requirements::unmet(
        &crate::host_requirements::sharing_requirements(),
        crate::host_requirements::observe,
    )
    .iter()
    .map(|r| r.what.to_string())
    .collect();
    if !unmet_hardening.is_empty() {
        tracing::info!(
            unmet = ?unmet_hardening,
            "taking a base on a host that is not hardened for cross-pod sharing; recorded on the \
             base so a later sharing decision reads evidence rather than assuming"
        );
    }

    match store.publish(incoming, &derivation, unmet_hardening.clone()) {
        Ok(_) => Ok(Json(serde_json::json!({
            "status": "published", "derivation": name,
            "unmet_hardening": unmet_hardening
        }))),
        // Another launch published the same base while this one was writing. The base the caller
        // wanted exists, which is the outcome they asked for.
        Err(PublishError::AlreadyPresent) => Ok(Json(serde_json::json!({
            "status": "already-present", "derivation": name
        }))),
        Err(e) => Err(ApiError::Driver(format!("could not publish the base: {e}"))),
    }
}

/// Serve a pod's execution receipt.
///
/// The route the SDKs have been calling all along. `Operation::GetReceipt` has existed in the
/// authorization enum since receipts did, and the gRPC surface has served them — but over HTTP
/// this was a 404, so `sdk/python/nucleus_sdk/client.py`'s `get_receipt` could never have worked.
///
/// Read-only, unlike its gRPC twin, which also fires an outward report to the trust API. That
/// asymmetry is deliberate and `pod_receipt`'s module docs carry the argument: a GET should not
/// have an external side effect, and the existing one is contained rather than propagated.
pub(crate) async fn get_receipt(
    State(state): State<NodeState>,
    Extension(caller): Extension<Option<Uuid>>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<Json<crate::pod_receipt::Receipt>, ApiError> {
    use crate::pod_receipt::ReceiptError;
    let pod = get_pod_for_caller(&state, id, caller).await?;
    match crate::pod_receipt::build(&pod).await {
        Ok(built) => Ok(Json(built.receipt)),
        // A pod that has not finished has no receipt YET, which is not the same as not having one
        // — and neither is the same as not existing. `NoExitReport` maps to NotFound because the
        // artifact genuinely is not there; the others say what they are.
        Err(e @ ReceiptError::NotExited) => Err(ApiError::Driver(e.to_string())),
        Err(ReceiptError::NoExitReport(_)) => Err(ApiError::NotFound),
        Err(e @ ReceiptError::Malformed(_)) => Err(ApiError::Driver(e.to_string())),
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::{caller_may_manage, resolve_parent_pod_id};
    use uuid::Uuid;

    fn a() -> Uuid {
        Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap()
    }
    fn b() -> Uuid {
        Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap()
    }
    fn child_of_a() -> Uuid {
        Uuid::parse_str("cccccccc-cccc-4ccc-8ccc-cccccccccccc").unwrap()
    }

    /// **The property this whole arc exists for.** Pod B cannot touch pod A's
    /// child. Before this, any pod holding `ManagePods` could list, read the
    /// logs of, and cancel every pod on the node -- including other tenants'.
    #[test]
    fn a_pod_cannot_manage_another_pods_child() {
        assert!(!caller_may_manage(Some(b()), child_of_a(), Some(a())));
    }

    /// ...and the same for a pod with no recorded parent, which is the state
    /// every pod created by an external orchestrator is in. "Unowned" must not
    /// read as "owned by whoever asks".
    #[test]
    fn an_unparented_pod_is_not_managed_by_an_identified_pod() {
        assert!(!caller_may_manage(Some(b()), child_of_a(), None));
    }

    /// The positive leg: a pod manages its own children.
    #[test]
    fn a_pod_manages_its_own_child() {
        assert!(caller_may_manage(Some(a()), child_of_a(), Some(a())));
    }

    /// And itself, so a pod can read its own logs and cancel itself.
    #[test]
    fn a_pod_manages_itself() {
        assert!(caller_may_manage(Some(a()), a(), None));
    }

    /// **C2 model↔runtime parity.** The abstract cross-pod noninterference theorem
    /// (`crates/portcullis-core/lean/PodCrossView.lean`, `cross_pod_noninterference`)
    /// proves a pod's view is independent of any other pod's secrets over the view
    /// relation whose lineage filter is `ownedBy p q := q.parent == p || q.id == p`.
    /// That theorem is only *about the code that ships* if the SHIPPED filter is
    /// that same predicate. This pins it: exhaustively over a domain of pod ids,
    /// `caller_may_manage(Some(caller), pod, parent)` — the predicate the live
    /// listing (`.filter` above, #2199) and the management gate both use — equals
    /// the abstract `ownedBy` formula. Change the shipped predicate and this reds,
    /// so the Lean theorem cannot quietly describe a filter the node does not run.
    ///
    /// Scope: `Some(caller)` only — a pod is always an identified caller. The
    /// `caller = None` branch is the node/operator (sees all), which is outside the
    /// pod-vs-pod subject the theorem is about.
    #[test]
    fn caller_may_manage_matches_the_podview_lineage_filter() {
        let ids = [a(), b(), child_of_a()];
        let parents = [Some(a()), Some(b()), Some(child_of_a()), None];
        let mut saw_true = false;
        let mut saw_false = false;
        for &caller in &ids {
            for &pod in &ids {
                for &parent in &parents {
                    // PodCrossView `ownedBy caller {id = pod, parent}`:
                    //   q.parent == p || q.id == p
                    let abstract_owned = parent == Some(caller) || pod == caller;
                    let shipped = caller_may_manage(Some(caller), pod, parent);
                    assert_eq!(
                        shipped, abstract_owned,
                        "shipped caller_may_manage diverged from PodCrossView::ownedBy \
                         at caller={caller}, pod={pod}, parent={parent:?}"
                    );
                    if abstract_owned {
                        saw_true = true;
                    } else {
                        saw_false = true;
                    }
                }
            }
        }
        // Non-vacuity: the domain must exercise BOTH verdicts, or the equivalence
        // could hold trivially (a constant predicate would pass a one-sided sweep).
        assert!(
            saw_true && saw_false,
            "parity domain did not exercise both owned and not-owned cases"
        );
    }

    /// **C2 cross-pod set exclusion — the SET the listing actually computes.** The
    /// parity test above pins `caller_may_manage` pointwise; this pins the `.filter`
    /// in `collect_pod_infos` as a set operation: over a registry holding A, A's
    /// child, and a non-lineage sibling B, the scope minted for A yields exactly
    /// {A, child} and *excludes* B. This is the exact function C2 G3's guest→host
    /// `PodList` command will run with a socket-bound caller, so proving it here
    /// proves it for that path too — no second implementation to drift.
    #[test]
    fn scope_to_caller_excludes_a_non_lineage_sibling() {
        #[derive(Clone)]
        struct P {
            id: Uuid,
            parent: Option<Uuid>,
        }
        impl super::Lineage for P {
            fn lineage_id(&self) -> Uuid {
                self.id
            }
            fn lineage_parent(&self) -> Option<Uuid> {
                self.parent
            }
        }
        let (a, b, child) = (a(), b(), child_of_a());
        let registry = [
            P {
                id: a,
                parent: None,
            }, // A: an operator-created orchestrator
            P {
                id: child,
                parent: Some(a),
            }, // A's direct child
            P {
                id: b,
                parent: None,
            }, // sibling B — NOT A's child
        ];
        let seen: std::collections::BTreeSet<Uuid> = super::scope_to_caller(&registry, a)
            .iter()
            .map(|p| p.id)
            .collect();
        // A sees itself and its child...
        assert!(seen.contains(&a), "A's scoped listing must contain A");
        assert!(seen.contains(&child), "A must see its own child");
        // ...and NOT the sibling — cross-pod non-interference at the shared filter.
        assert!(
            !seen.contains(&b),
            "sibling B leaked into A's scoped listing"
        );
        // Non-vacuity: B was genuinely in the input, so this is exclusion, not
        // "B was never there"; and scoping strictly removed something (2 of 3).
        assert!(
            registry.iter().any(|p| p.id == b),
            "test bug: B not in the input registry"
        );
        assert_eq!(seen.len(), 2, "expected exactly {{A, child}}");
    }

    /// **C2 cross-pod isolation, exercised over the live request path.** A pod's
    /// listing is filtered by lineage — but only if the two functions a request
    /// actually traverses agree: the node must (1) identify the caller from the
    /// token it minted, then (2) filter by that identity. The `caller_may_manage`
    /// tests above cover (2) in isolation; the `pod_caller_identity` tests cover
    /// (1). This drives BOTH together through the pod-B-cannot-observe-pod-A
    /// scenario, INCLUDING the forgery `identify_caller` exists to stop — a pod
    /// that could claim another's identity would bypass the filter entirely.
    ///
    /// It is the request-path integration of the same relation `PodCrossView.lean`
    /// proves and increment 2 pinned to the shipped predicate: auth binds the
    /// caller, the filter isolates by lineage, and forgery is rejected. (VM-level
    /// guest isolation and a fully-booted-node HTTP e2e are separate.)
    #[test]
    fn pod_b_cannot_observe_pod_a_across_the_auth_and_filter_path() {
        use crate::pod_caller_identity::{derive_token, identify_caller};
        const SECRET: &[u8] = b"node-wide-management-secret";
        // A and B are node-created siblings — neither is the other's parent.
        let (a, b, a_child) = (a(), b(), child_of_a());

        // (1) Auth: B presents its OWN token and is identified as B.
        let b_token = derive_token(SECRET, b);
        assert_eq!(
            identify_caller(SECRET, Some(&b.to_string()), Some(&b_token)),
            Ok(b),
            "B's own token must identify it as B"
        );

        // The attack the whole mechanism exists to stop: B, holding only its own
        // token, cannot CLAIM to be A — else the lineage filter below is bypassed.
        assert!(
            identify_caller(SECRET, Some(&a.to_string()), Some(&b_token)).is_err(),
            "B's token must NOT authenticate as A"
        );

        // (2) Filter: identified as B, the listing excludes sibling A and A's
        // child, and keeps B itself.
        assert!(
            !caller_may_manage(Some(b), a, None),
            "B must not see sibling A"
        );
        assert!(
            !caller_may_manage(Some(b), a_child, Some(a)),
            "B must not see A's child"
        );
        assert!(caller_may_manage(Some(b), b, None), "B still sees itself");

        // Symmetric non-vacuity: A, correctly identified from its own token, DOES
        // see A and A's child — so the isolation is not the vacuous "nobody sees
        // anything" — but still not sibling B.
        let a_token = derive_token(SECRET, a);
        assert_eq!(
            identify_caller(SECRET, Some(&a.to_string()), Some(&a_token)),
            Ok(a)
        );
        assert!(caller_may_manage(Some(a), a, None));
        assert!(caller_may_manage(Some(a), a_child, Some(a)));
        assert!(
            !caller_may_manage(Some(a), b, None),
            "A must not see sibling B"
        );
    }

    /// A grandchild is NOT reachable: the rule is direct children, not the
    /// descendant closure. Pinned so the narrower scope is a decision on record
    /// rather than something a later reader assumes is a bug.
    #[test]
    fn a_grandchild_is_not_directly_manageable() {
        let grandchild = Uuid::parse_str("dddddddd-dddd-4ddd-8ddd-dddddddddddd").unwrap();
        // grandchild's parent is child_of_a; a() is its grandparent.
        assert!(!caller_may_manage(
            Some(a()),
            grandchild,
            Some(child_of_a())
        ));
    }

    /// An unidentified caller is unchanged. This is what keeps the change from
    /// altering a verdict for operators, who hold the node auth secret and
    /// already have full node authority.
    #[test]
    fn an_unidentified_caller_is_unrestricted() {
        assert!(caller_may_manage(None, child_of_a(), Some(a())));
        assert!(caller_may_manage(None, child_of_a(), None));
    }

    /// Lineage comes from the proof, not the claim. A pod that proves it is B
    /// but names A as parent is recorded as B's child -- otherwise it could
    /// plant a pod under a victim, or disown its own.
    #[test]
    fn a_proved_caller_overrides_the_claimed_parent() {
        assert_eq!(
            resolve_parent_pod_id(Some(b()), Some(&a().to_string())),
            Some(b())
        );
    }

    /// The header still applies when nothing was proved, so external
    /// orchestrators keep working exactly as before.
    #[test]
    fn the_header_still_applies_to_unidentified_callers() {
        assert_eq!(
            resolve_parent_pod_id(None, Some(&a().to_string())),
            Some(a())
        );
        assert_eq!(resolve_parent_pod_id(None, None), None);
        assert_eq!(resolve_parent_pod_id(None, Some("not-a-uuid")), None);
    }

    /// The two legs together: what a forged header buys an identified caller is
    /// nothing. Stated as its own test because this is the sentence the design
    /// rests on, and it should fail by name if the precedence is ever flipped.
    #[test]
    fn forging_the_parent_header_gains_an_identified_pod_nothing() {
        // B claims to be A's child, hoping to be handed A's children.
        let recorded = resolve_parent_pod_id(Some(b()), Some(&a().to_string()));
        assert_eq!(recorded, Some(b()), "the proof must win");
        // And it still cannot reach A's child.
        assert!(!caller_may_manage(Some(b()), child_of_a(), Some(a())));
    }

    // ── #2475: the gRPC surface uses the same ownership predicate ─────────

    /// The HTTP-side property, run against the lookup the gRPC handlers now
    /// call: pod B cannot resolve A's child by id; A can; the operator can.
    #[test]
    fn scoped_lookup_refuses_another_pods_child_by_id() {
        #[derive(Clone)]
        struct P {
            id: Uuid,
            parent: Option<Uuid>,
        }
        impl super::Lineage for P {
            fn lineage_id(&self) -> Uuid {
                self.id
            }
            fn lineage_parent(&self) -> Option<Uuid> {
                self.parent
            }
        }
        let (a, b, child) = (a(), b(), child_of_a());
        let registry = [
            P {
                id: a,
                parent: None,
            },
            P {
                id: child,
                parent: Some(a),
            },
            P {
                id: b,
                parent: None,
            },
        ];
        assert!(
            super::scoped_lookup(&registry, child, Some(b)).is_none(),
            "B cannot reach A's child"
        );
        assert!(
            super::scoped_lookup(&registry, child, Some(a)).is_some(),
            "A manages its child"
        );
        assert!(
            super::scoped_lookup(&registry, child, None).is_some(),
            "the operator sees everything"
        );
        assert!(
            super::scoped_lookup(&registry, a, Some(b)).is_none(),
            "a sibling is out of reach"
        );
        assert!(
            super::scoped_lookup(&registry, Uuid::new_v4(), None).is_none(),
            "absent is absent"
        );
    }

    /// gRPC identifies the caller from the same two metadata entries the HTTP
    /// middleware reads, with the same outcome for a claim that does not verify.
    #[test]
    fn grpc_caller_mirrors_the_http_middleware() {
        let secret = [7u8; 32];
        let pod = a();
        let token = crate::pod_caller_identity::derive_token(&secret, pod);
        let mut md = tonic::metadata::MetadataMap::new();
        assert_eq!(
            super::grpc_caller(&secret, &md),
            None,
            "nothing claimed: operator scope"
        );
        md.insert(
            nucleus_client::HEADER_POD_ID,
            pod.to_string().parse().unwrap(),
        );
        md.insert(nucleus_client::HEADER_POD_TOKEN, token.parse().unwrap());
        assert_eq!(super::grpc_caller(&secret, &md), Some(pod));
        assert_eq!(
            super::grpc_caller(&[8u8; 32], &md),
            None,
            "an unprovable claim is no identity, as over HTTP"
        );
    }

    /// Structural: no gRPC pod-management handler reaches the registry through
    /// the unscoped lookup any more, and the listing is scoped.
    #[test]
    fn every_grpc_pod_handler_goes_through_the_scoped_lookup() {
        let main = include_str!("main.rs");
        let start = main
            .find("impl NodeService for GrpcService")
            .expect("the gRPC service impl");
        let grpc = &main[start..];
        assert!(
            !grpc.contains("pod_api::get_pod("),
            "an unscoped lookup survived in the gRPC impl"
        );
        assert!(
            !grpc.contains("collect_pod_infos(&self.state, None)"),
            "the gRPC listing is unscoped"
        );
        assert!(
            grpc.matches("grpc_scoped_pod(").count() >= 6,
            "every id-taking handler is scoped"
        );
    }
}

// ── The handlers, against a real `NodeState` ────────────────────────────────
//
// Everything in `ownership_tests` is about the pure predicates. The handlers
// themselves — the things a request actually reaches — were covered by nothing,
// because each takes a `NodeState`, and nothing outside `main()` built one.
//
// It turns out `NodeState` is built almost entirely from parsed `Args`, so a
// test can parse the same defaults an operator would get and assemble the rest.
// No subsystem is faked: this is the real `PodAuthority`, the real
// `NetworkAllocator`, the real signing key loaded off disk.
//
// `local-driver` is not a default feature; CI's coverage job runs
// `--all-features`, which compiles this.
#[cfg(all(test, feature = "local-driver"))]
mod handler_tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// The arguments an operator running the local driver would get, with only
    /// the two that have no default supplied.
    fn args(state_dir: &std::path::Path) -> crate::Args {
        <crate::Args as clap::Parser>::parse_from([
            "nucleus-node",
            "--state-dir",
            state_dir.to_str().expect("utf-8 tempdir"),
            "--driver",
            "local",
            "--allow-local-driver",
            "--proxy-auth-secret",
            "test-auth-secret",
            "--proxy-approval-secret",
            "test-approval-secret",
        ])
    }

    /// Mirrors `main()`'s construction. A field added to `NodeState` breaks this
    /// at compile time, which is the right failure: the fixture should not drift
    /// silently away from what the node actually runs with.
    fn state(dir: &tempfile::TempDir) -> NodeState {
        // `main()` installs this before building any client; this crate takes
        // reqwest with `rustls-no-provider`, so `Client::new()` PANICS without
        // it. Idempotent, so every test may call it.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let a = args(dir.path());
        let authority = Arc::new(crate::pod_authority::PodAuthority::from_args(&a));
        NodeState {
            pods: Arc::new(Mutex::new(HashMap::new())),
            state_dir: a.state_dir.clone(),
            driver: a.driver.clone(),
            tool_proxy_path: a.tool_proxy_path.clone(),
            firecracker_path: a.firecracker_path.clone(),
            firecracker_pool: None,
            firecracker_api_boot: a.firecracker_api_boot,
            firecracker_netns: a.firecracker_netns,
            firecracker_netns_drift_check: a.firecracker_netns_drift_check,
            firecracker_netns_drift_interval: std::time::Duration::from_secs(
                a.firecracker_netns_drift_interval_secs,
            ),
            firecracker_seccomp_verify: a.firecracker_seccomp_verify,
            firecracker_jailer: a.firecracker_jailer,
            jailer_path: a.jailer_path.clone(),
            jailer_chroot_base: a.jailer_chroot_base.clone(),
            jailer_uid: a.jailer_uid,
            jailer_gid: a.jailer_gid,
            network_allocator: Arc::new(crate::net::NetworkAllocator::new()),
            listen_addr: a.listen.clone(),
            proxy_auth_secret: a.proxy_auth_secret.clone(),
            caller_secret: Arc::new([7u8; 32]),
            proxy_approval_secret: a.proxy_approval_secret.clone(),
            approval_signer: Arc::new(crate::trust_gate::load_or_create_approval_signing_key(
                &a.state_dir,
            )),
            proxy_actor: None,
            trusted_postures: crate::posture::PostureRegistry::from_operator_str(""),
            drand_config: None,
            identity_manager: None,
            identity_vsock_port: a.identity_workload_api_vsock_port,
            broker_listen: a.broker_listen,
            broker_enforcing: a.broker_enforcing,
            broker_vsock_port: a.broker_vsock_port,
            github_oidc: None,
            authz_policy: crate::auth::AuthorizationPolicy::new(&a.identity_trust_domain),
            container_image: a.container_image.clone(),
            container_network: a.container_network.clone(),
            container_proxy_unix: a.container_proxy_unix,
            container_pool: None,
            docker: None,
            trust_gate: crate::trust_gate::TrustGateConfig::from_env(&a.state_dir),
            authority,
            http_client: reqwest::Client::new(),
            lockdown_tx: tokio::sync::broadcast::channel::<crate::proto::LockdownCommand>(16).0,
        }
    }

    /// A registered pod, running, optionally owned by `parent`.
    async fn register(st: &NodeState, parent: Option<uuid::Uuid>) -> uuid::Uuid {
        let dir = st.state_dir.join("w");
        std::fs::create_dir_all(&dir).expect("work dir");
        let mut spec: nucleus_spec::PodSpec =
            serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#)
                .expect("minimal spec");
        spec.spec.work_dir = dir;
        let id = uuid::Uuid::new_v4();
        let child = tokio::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("a child spawns");
        let handle = Arc::new(crate::PodHandle {
            id,
            spec,
            created_at: 1_757_000_000,
            log_path: st.state_dir.join("pod.log"),
            proxy_addr: Mutex::new(Some("http://127.0.0.1:1".to_string())),
            driver_state: crate::DriverState::Local(Box::new(crate::LocalPod {
                child: Mutex::new(child),
                signed_proxy: Mutex::new(None),
            })),
            parent_pod_id: parent,
            posture_stamp: None,
        });
        st.pods.lock().await.insert(id, handle);
        id
    }

    async fn cancel_all(st: &NodeState) {
        for (_, h) in st.pods.lock().await.iter() {
            let _ = h.cancel().await;
        }
    }

    /// An unidentified caller — an operator on the node's own API — sees every
    /// pod. A pod caller sees only its own lineage. This is the same rule the
    /// predicates state, asserted here through the handler that applies it.
    #[tokio::test]
    async fn collect_pod_infos_scopes_to_the_callers_lineage() {
        let dir = tempfile::tempdir().expect("tempdir");
        let st = state(&dir);
        let a = register(&st, None).await;
        let b = register(&st, None).await;
        let child_of_a = register(&st, Some(a)).await;

        let all = collect_pod_infos(&st, None).await;
        assert_eq!(all.len(), 3, "an operator sees every pod");

        let seen: Vec<uuid::Uuid> = collect_pod_infos(&st, Some(a))
            .await
            .into_iter()
            .map(|i| i.id)
            .collect();
        assert!(seen.contains(&a), "a pod sees itself");
        assert!(seen.contains(&child_of_a), "and its own child");
        assert!(!seen.contains(&b), "never a sibling: {seen:?}");
        cancel_all(&st).await;
    }

    /// A pod that exists is found; one that does not is a 404 rather than a
    /// panic or an empty success.
    #[tokio::test]
    async fn get_pod_finds_a_registered_pod_and_refuses_an_unknown_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let st = state(&dir);
        let id = register(&st, None).await;

        let found = get_pod(&st, id).await.expect("a registered pod is found");
        assert_eq!(found.id, id);

        let Err(err) = get_pod(&st, uuid::Uuid::new_v4()).await else {
            panic!("an unknown id must not resolve");
        };
        assert!(matches!(err, ApiError::NotFound), "{err:?}");
        cancel_all(&st).await;
    }

    /// The scoped lookup is the one a pod's request goes through, and it must
    /// refuse a sibling BY ID — otherwise lineage scoping is only a filter on
    /// listings and not on access.
    #[tokio::test]
    async fn a_pod_cannot_fetch_a_sibling_by_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let st = state(&dir);
        let a = register(&st, None).await;
        let b = register(&st, None).await;

        assert!(
            get_pod_for_caller(&st, a, Some(a)).await.is_ok(),
            "a pod reaches itself"
        );
        assert!(
            get_pod_for_caller(&st, b, Some(a)).await.is_err(),
            "a pod must not reach a sibling by naming its id"
        );
        assert!(
            get_pod_for_caller(&st, b, None).await.is_ok(),
            "an operator reaches any pod"
        );
        cancel_all(&st).await;
    }

    /// Cancelling stops the pod but LEAVES it in the registry.
    ///
    /// Worth pinning because it is easy to assume otherwise — nothing in the
    /// node removes a pod from `state.pods`, so a cancelled pod stays listable
    /// and fetchable with its state now `Exited`. A reader who assumed removal
    /// would misread the 404 the receipt route returns next (see below).
    #[tokio::test]
    async fn a_cancelled_pod_stops_but_stays_addressable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let st = state(&dir);
        let id = register(&st, None).await;

        let _cancelled = cancel_pod(
            axum::extract::State(st.clone()),
            axum::Extension(None),
            axum::extract::Path(id),
        )
        .await
        .expect("a running pod cancels");

        let pod = get_pod(&st, id)
            .await
            .expect("a cancelled pod is still registered");
        assert!(
            matches!(pod.status().await, crate::PodState::Exited { .. }),
            "cancel must actually stop the child"
        );
    }

    /// **A pod that exists gets `404 pod not found` from the receipt route.**
    ///
    /// `get_receipt` maps `NoExitReport` onto `ApiError::NotFound`, whose
    /// message is "pod not found" — so a cancelled pod, still listed by
    /// `GET /v1/pods` and still fetchable by id, is reported missing when the
    /// only missing thing is the exit report the proxy writes at shutdown.
    ///
    /// The mapping is deliberate (the comment at the call site argues the
    /// artifact genuinely is not there) and the MESSAGE is what misleads. This
    /// test pins the behaviour as it is rather than asserting the wording I
    /// would prefer; changing `ApiError::NotFound`'s text is a decision for a
    /// change that is about denials, not for this one.
    #[tokio::test]
    async fn a_pod_with_no_exit_report_is_reported_as_a_missing_pod() {
        let dir = tempfile::tempdir().expect("tempdir");
        let st = state(&dir);
        let id = register(&st, None).await;
        let _cancelled = cancel_pod(
            axum::extract::State(st.clone()),
            axum::Extension(None),
            axum::extract::Path(id),
        )
        .await
        .expect("cancels");

        // The pod is demonstrably still there ...
        assert!(get_pod(&st, id).await.is_ok());
        // ... and the receipt route says it is not.
        let Err(err) = get_receipt(
            axum::extract::State(st.clone()),
            axum::Extension(None),
            axum::extract::Path(id),
        )
        .await
        else {
            panic!("no exit report, so no receipt");
        };
        assert!(matches!(err, ApiError::NotFound), "{err:?}");
        assert_eq!(
            err.to_string(),
            "pod not found",
            "recorded because it names the wrong thing: the POD is found, the \
             exit report is not"
        );
    }

    /// A receipt is refused for a pod that has not exited — the handler carries
    /// `pod_receipt`'s distinction rather than flattening it.
    #[tokio::test]
    async fn a_receipt_for_a_running_pod_is_refused_not_fabricated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let st = state(&dir);
        let id = register(&st, None).await;

        let Err(err) = get_receipt(
            axum::extract::State(st.clone()),
            axum::Extension(None),
            axum::extract::Path(id),
        )
        .await
        else {
            panic!("a running pod has no receipt");
        };
        let rendered = format!("{err:?}");
        assert!(
            rendered.contains("has not exited"),
            "the caller must be told to wait, not that the pod is missing: {rendered}"
        );
        cancel_all(&st).await;
    }
}
