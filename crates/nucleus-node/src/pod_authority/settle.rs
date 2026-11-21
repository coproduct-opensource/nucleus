//! Releasing a pod: retiring its certificate and settling its allocation back
//! into its parent's ledger, and the day that allocation was charged to.
//!
//! What a release consumes is decided by the host, never the guest: an
//! unspawned reservation consumes nothing, a pod that ran consumes its whole
//! allocation, or, when its federated binding settles `metered`, what the host
//! metered into its own ledger, at most its allocation (ADR 0007 A-1, C-1).
//!
//! What a release charged a ledger is kept beside the pod, in
//! `pods/<id>/settled-spend.json`, written once that ledger's record is durable
//! and before the pod's authority file is removed. It outlives the registry and
//! the node's life, so `GET /v1/pods/{id}/ended` can report it (`spent_micro_usd`).
//! No file is written for a pod with no ledger above it (admitted by the root
//! minter), or whose ledger held no allocation for it: nothing was charged, and
//! the reader reports 'unknown', never 0.

use std::path::Path;

use uuid::Uuid;

use super::{
    Inner, Parent, authority_path, egress, micro_usd, persist_external, persist_pod, write_whole,
};

/// Beside `authority.json` in the pod's directory; outlives it.
const SETTLED_FILE: &str = "settled-spend.json";

/// What one release charged a ledger for one pod, in micro-USD.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settled {
    version: u8,
    pod: Uuid,
    spent_micro: u64,
}

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
    // `Ok(Some(_))` only when a ledger above the pod took `consumed`: what
    // `settled-spend.json` reports. A pod with no ledger above it reports nothing.
    let recorded = match entry.parent {
        Parent::Root => Ok(None),
        Parent::Pod(p) => match inner.pods.get_mut(&p) {
            Some(parent) => match parent.ledger.release(pod_id.as_u128(), consumed) {
                Ok(_) => {
                    parent.retired.push(pod_id);
                    retain_unremoved(state_dir, &mut parent.retired);
                    persist_pod(state_dir, p, parent)
                        .await
                        .map(|()| Some(consumed))
                }
                Err(e) => {
                    tracing::debug!(pod = %pod_id, error = %e, "budget release found no live allocation");
                    Ok(None)
                }
            },
            None => Ok(None),
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
                    persist_external(state_dir, &fp, chain)
                        .await
                        .map(|()| Some(consumed))
                }
                Err(e) => {
                    tracing::debug!(pod = %pod_id, error = %e, "budget release found no live allocation");
                    Ok(None)
                }
            },
            None => Ok(None),
        },
    };
    match recorded {
        Ok(charged) => {
            if let Some(charged) = charged {
                record_settled(state_dir, pod_id, micro_of(charged)).await;
            }
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

/// Keep what `pod_id`'s release charged its ledger. Written only into a pod
/// directory that exists: creating one would make the next life read this pod
/// as one of its own previous life's. A failed write is logged and leaves the
/// spend unknown, which a reader treats as the whole allocation, never as 0.
async fn record_settled(state_dir: &Path, pod_id: Uuid, spent_micro: u64) {
    let dir = crate::lifecycle::pod_dir(state_dir, pod_id);
    if !dir.is_dir() {
        return;
    }
    let record = Settled {
        version: 1,
        pod: pod_id,
        spent_micro,
    };
    let written = match serde_json::to_vec(&record) {
        Ok(bytes) => write_whole(&dir.join(SETTLED_FILE), &bytes).await,
        Err(e) => Err(std::io::Error::other(e)),
    };
    if let Err(e) = written {
        tracing::warn!(pod = %pod_id, error = %e, "could not keep a released pod's settled spend; it reads as unknown");
    }
}

/// What `pod_id`'s release charged its ledger, in micro-USD, as
/// [`record_settled`] kept it. `None` when no record exists, or it cannot be
/// read, is not version 1, or names another pod: unknown, never 0.
pub(super) async fn settled_spend(state_dir: &Path, pod_id: Uuid) -> Option<u64> {
    let path = crate::lifecycle::pod_dir(state_dir, pod_id).join(SETTLED_FILE);
    let bytes = tokio::fs::read(&path).await.ok()?;
    let record: Settled = serde_json::from_slice(&bytes).ok()?;
    (record.version == 1 && record.pod == pod_id).then_some(record.spent_micro)
}
