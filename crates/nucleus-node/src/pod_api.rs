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
use axum::extract::{Extension, Path as AxumPath, State};
use axum::Json;
use std::sync::Arc;
use uuid::Uuid;

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

/// Pod summaries the caller is entitled to see.
///
/// Filtering here rather than at the handler is deliberate: the listing is how a
/// caller LEARNS the pod UUIDs it would then pass to `pod_logs` or `cancel_pod`.
/// Returning the full list and refusing individually would hand out the
/// identifiers first and refuse afterwards.
pub(crate) async fn collect_pod_infos(state: &NodeState, caller: Option<Uuid>) -> Vec<PodInfo> {
    let pods: Vec<Arc<PodHandle>> = {
        let guard = state.pods.lock().await;
        guard
            .values()
            .filter(|pod| caller_may_manage(caller, pod.id, pod.parent_pod_id))
            .cloned()
            .collect()
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
async fn get_pod_for_caller(
    state: &NodeState,
    id: Uuid,
    caller: Option<Uuid>,
) -> Result<Arc<PodHandle>, ApiError> {
    let pod = get_pod(state, id).await?;
    if !caller_may_manage(caller, pod.id, pod.parent_pod_id) {
        tracing::warn!(
            %id,
            caller = ?caller,
            "a pod tried to manage a pod it does not own"
        );
        return Err(ApiError::NotFound);
    }
    Ok(pod)
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
}
