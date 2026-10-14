//! Releasing a pod: retiring its certificate and settling its allocation back
//! into its parent's ledger, and the day that allocation was charged to.
//!
//! What a release consumes is decided by the host, never the guest: an
//! unspawned reservation consumes nothing, a pod that ran consumes its whole
//! allocation, or, when its federated binding settles `metered`, what the host
//! metered into its own ledger, at most its allocation (ADR 0007 A-1, C-1).

use std::path::Path;

use uuid::Uuid;

use super::{Inner, Parent, authority_path, egress, micro_usd, persist_external, persist_pod};

// No caller-supplied spend amount can authorize a refund (ADR 0007 C-1).
pub(super) enum ReleaseKind {
    Unspawned,
    Exited,
}

/// Retire `pod_id`'s certificate and return its allocation to its parent's
/// ledger. The one body [`super::PodAuthority::release_child`] and a dropped
/// [`super::Reservation`] share.
///
/// The parent's record is written first, naming the child as retired, and
/// only then is the child's file removed; see the module docs. If the parent's
/// record cannot be written the child's file is KEPT, so a restart restores
/// the child as a live allocation: the same budget held, never handed back.
/// Only the reservation owner selects `Unspawned`.
pub(super) async fn release(
    inner: &tokio::sync::Mutex<Inner>,
    state_dir: &Path,
    pod_id: Uuid,
    kind: ReleaseKind,
) {
    let mut guard = inner.lock().await;
    let inner = &mut *guard;
    let Some(entry) = inner.pods.remove(&pod_id) else {
        return;
    };
    if let crate::host_decide::PolicyHistory::Live(policy) = &entry.host_policy {
        crate::host_decide::PodPolicy::revoke(policy);
    }
    // Its descendants still charge its account; nothing will restore it.
    if let egress::PodEgress::Live(chain) = &entry.egress {
        chain.own().retire();
    }
    let allocation = entry.cert.effective_permissions().budget.max_cost_usd;
    let consumed = match kind {
        ReleaseKind::Unspawned => rust_decimal::Decimal::ZERO,
        // Host-authoritative settlement: what the host metered into the pod's
        // own ledger, never more than the allocation. Unreadable is the whole
        // allocation, never zero (ADR 0007 A-1).
        ReleaseKind::Exited if entry.settle_metered => {
            entry.ledger.snapshot().map_or(allocation, |l| {
                let core = l.core();
                micro_usd(
                    core.parent_consumed_units()
                        .saturating_add(core.allocated_units()),
                )
                .min(allocation)
            })
        }
        ReleaseKind::Exited => allocation,
    };
    let recorded = match entry.parent {
        Parent::Root => Ok(()),
        Parent::Pod(p) => match inner.pods.get_mut(&p) {
            Some(parent) => match parent.ledger.release(pod_id.as_u128(), consumed) {
                Ok(_) => {
                    parent.retired.push(pod_id);
                    retain_unremoved(state_dir, &mut parent.retired);
                    persist_pod(state_dir, p, parent).await
                }
                Err(e) => {
                    tracing::debug!(pod = %pod_id, error = %e, "budget release found no live allocation");
                    Ok(())
                }
            },
            None => Ok(()),
        },
        Parent::External(fp) => match inner.external.get_mut(&fp) {
            Some(chain) => match chain.ledger.release(pod_id.as_u128(), consumed) {
                Ok(_) => {
                    // The day agrees with the ledger: a refund is credited to
                    // the day it was charged to, a pod that ran keeps its charge.
                    match kind {
                        ReleaseKind::Unspawned => chain.days.refund(pod_id),
                        ReleaseKind::Exited => chain.days.settle_spent(pod_id, micro_of(consumed)),
                    }
                    chain.retired.push(pod_id);
                    retain_unremoved(state_dir, &mut chain.retired);
                    persist_external(state_dir, &fp, chain).await
                }
                Err(e) => {
                    tracing::debug!(pod = %pod_id, error = %e, "budget release found no live allocation");
                    Ok(())
                }
            },
            None => Ok(()),
        },
    };
    match recorded {
        Ok(()) => {
            let _ = tokio::fs::remove_file(authority_path(state_dir, pod_id)).await;
        }
        Err(e) => tracing::error!(
            pod = %pod_id,
            error = %e,
            "could not record a released allocation in its parent's ledger; the pod's \
             authority file is kept, so a restart restores it as still allocated"
        ),
    }
}

/// Keep, of `retired`, only the children whose authority file still exists:
/// the ones a restore could otherwise mistake for live. Bounded by the
/// releases whose file removal has not happened yet.
pub(super) fn retain_unremoved(state_dir: &Path, retired: &mut Vec<Uuid>) {
    retired.retain(|id| authority_path(state_dir, *id).exists());
}

/// `usd` in micro-USD, rounded UP: a settled charge never undercounts by a
/// fraction of a micro-dollar. Negative is zero.
fn micro_of(usd: rust_decimal::Decimal) -> u64 {
    use rust_decimal::prelude::ToPrimitive;
    (usd * rust_decimal::Decimal::from(1_000_000_u32))
        .ceil()
        .to_u64()
        .unwrap_or(0)
}
