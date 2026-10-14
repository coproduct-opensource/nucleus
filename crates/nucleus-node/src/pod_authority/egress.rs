//! Egress bytes are delegated the way cost is: meet-only, and conserved across a pod's
//! descendants (#2905).
//!
//! # The defect this closes
//!
//! Admission never read a child's `network.egress`. A pod holding a 1 MiB ceiling could create
//! a child declaring 1 GiB, and the child's meter enforced the 1 GiB. Every generation could
//! re-declare, so delegation multiplied the byte budget instead of dividing it.
//!
//! # The model
//!
//! Every admitted pod holds one [`EgressAccount`]: its admitted ceiling and the bytes charged to
//! it. A pod's [`EgressChain`] is its own account followed by each ancestor's, up to the first
//! pod with no pod parent. Every send a pod's meter admits reserves from EVERY account on its
//! chain, all or nothing, so a byte a child sends is a byte its parent and grandparent have
//! spent too, and `Σ bytes sent by a pod's subtree ≤ that pod's ceiling` holds at every node of
//! the tree.
//!
//! At admission a child's ceiling is the meet of what it declared and what its chain has left,
//! [`EgressChain::remaining`]: the least remaining over every account on it. The same convention
//! as cost (`try_allocate`, "budget conservation"):
//!
//! * a child that DECLARED more than the chain has left is refused, by name: the caller gets the
//!   pod it asked for or none (ADR 0010 §1);
//! * a child that declared nothing asked for no amount. It gets the finite default met with
//!   what is left, and the clamp is recorded in the spec the node delivers.
//!
//! Children are not carved out of their parent in advance. A carve would reserve a child's whole
//! ceiling at admission, so a child that declared nothing (the default, 1 GiB) would take
//! everything its parent had left before sending a byte, and the parent's own egress would be
//! refused. Charging bytes as they are sent conserves the same total and leaves unspent bytes
//! with whoever spends them first. The price is that a child can spend up to what it was
//! admitted with, which may be all its parent had left: a parent that wants to keep egress for
//! itself declares a smaller ceiling for the child.
//!
//! # Persistence: a restart may not hand bytes back
//!
//! A pod's account is checkpointed to `pods/<id>/egress-consumption.json` AHEAD of its counted
//! bytes: before a reservation would take what the account has counted past the durable mark,
//! the mark is raised (written whole, synced, renamed — `write_whole_sync`) and only then is the
//! reservation made. So the durable mark is always at least what the account has counted, and a
//! restore that charges the mark can only under-state what is left, never over-state it. The
//! mark is raised by a fixed step, `ceil(ceiling / CHECKPOINT_STEPS)`, so an account writes at
//! most `CHECKPOINT_STEPS + 1` times in its life however many packets it admits, and a restart
//! costs a pod at most one step it did not spend. A write that fails faults the account: every
//! later reservation through it is refused, never admitted unrecorded.
//!
//! A pod restored from a record written before this existed has no admitted egress on record,
//! and a pod whose parent's account is gone cannot rebuild its chain. Neither may delegate: an
//! [`PodEgress::Unrecoverable`] pod's children are refused by name, the fail-closed reading
//! `unreadable_pod` already gives an unreadable record.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use portcullis::{
    EgressBytes, EgressCeiling, EgressDecision, EgressHold, EgressLedger, EgressNovelty,
    EgressPace, EgressRefusal, EgressSettlement, EgressUploadHold, UploadPace,
};
use uuid::Uuid;

/// How many steps a durable mark climbs from zero to the ceiling.
pub(crate) const CHECKPOINT_STEPS: u64 = 256;

const CHECKPOINT_FILE: &str = "egress-consumption.json";

/// `pods/<id>/egress-consumption.json`.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u8,
    pod: Uuid,
    /// At least the bytes this pod's account has counted.
    committed: EgressBytes,
}

/// One pod's egress balance: what it was admitted, and what it and its descendants have spent.
pub(crate) struct EgressAccount {
    ceiling: EgressCeiling,
    // None means accounting failed; it never means an unlimited balance (ADR 0007 B-2).
    ledger: Mutex<Option<EgressLedger>>,
    /// The durable mark. Only ever raised, and only after the write that records it.
    committed: AtomicU64,
    /// Serializes raises, so a smaller mark can never be renamed over a larger one.
    raising: tokio::sync::Mutex<()>,
    /// Where the mark is written; `None` for an account nothing restores (tests).
    checkpoint: Option<(Uuid, PathBuf)>,
    /// The pod's authority was released: nothing will restore this account, so its mark is no
    /// longer written. Its descendants still charge it.
    retired: AtomicBool,
    step: EgressBytes,
}

impl std::fmt::Debug for EgressAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressAccount")
            .field("ceiling", &self.ceiling)
            .field("committed", &self.committed.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl EgressAccount {
    fn build(
        ceiling: EgressCeiling,
        ledger: EgressLedger,
        committed: EgressBytes,
        checkpoint: Option<(Uuid, PathBuf)>,
    ) -> Arc<Self> {
        Arc::new(Self {
            ceiling,
            ledger: Mutex::new(Some(ledger)),
            committed: AtomicU64::new(committed),
            raising: tokio::sync::Mutex::new(()),
            checkpoint,
            retired: AtomicBool::new(false),
            step: ceiling.max_bytes().div_ceil(CHECKPOINT_STEPS).max(1),
        })
    }

    /// A fresh account for a pod admitted with `ceiling`, checkpointed into `pod_dir`.
    pub(crate) fn admitted(
        ceiling: EgressCeiling,
        pod: Uuid,
        pod_dir: &std::path::Path,
    ) -> Arc<Self> {
        Self::build(
            ceiling,
            EgressLedger::new(ceiling),
            0,
            Some((pod, pod_dir.join(CHECKPOINT_FILE))),
        )
    }

    /// An account nothing restores: for meters built outside admission, in tests.
    #[cfg(test)]
    pub(crate) fn memory(ceiling: EgressCeiling) -> Arc<Self> {
        Self::build(ceiling, EgressLedger::new(ceiling), 0, None)
    }

    /// The account of a pod admitted with `ceiling`, as its checkpoint in `pod_dir` left it.
    ///
    /// No checkpoint means the pod never raised its mark, which it must do before admitting a
    /// byte: it spent nothing. A checkpoint that exists and cannot be read is refused.
    pub(crate) fn restore(
        ceiling: EgressCeiling,
        pod: Uuid,
        pod_dir: &std::path::Path,
    ) -> Result<Arc<Self>, &'static str> {
        let path = pod_dir.join(CHECKPOINT_FILE);
        let committed = match std::fs::read(&path) {
            Ok(bytes) => {
                let record: Checkpoint =
                    serde_json::from_slice(&bytes).map_err(|_| "egress checkpoint malformed")?;
                if record.version != 1 || record.pod != pod {
                    return Err("egress checkpoint invalid");
                }
                record.committed.min(ceiling.max_bytes())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(_) => return Err("egress checkpoint unreadable"),
        };
        Ok(Self::build(
            ceiling,
            EgressLedger::restored(ceiling, committed),
            committed,
            Some((pod, path)),
        ))
    }

    /// What this account was admitted.
    pub(crate) const fn ceiling(&self) -> EgressCeiling {
        self.ceiling
    }

    /// Bytes still available, or `None` when the account cannot say (faulted or poisoned).
    pub(crate) fn remaining(&self) -> Option<EgressBytes> {
        let state = self.ledger.lock().ok()?;
        state.as_ref().map(EgressLedger::remaining)
    }

    /// Bytes counted against this account: its own and its descendants' sends.
    #[cfg(test)]
    pub(crate) fn counted(&self) -> Option<EgressBytes> {
        let state = self.ledger.lock().ok()?;
        state.as_ref().map(EgressLedger::counted)
    }

    /// Decide a reservation of `bytes` with `decide`, raising the durable mark first when the
    /// reservation would pass it. `refused` builds the ledger-fault refusal.
    async fn within_mark<T>(
        &self,
        bytes: EgressBytes,
        refused: impl Fn(EgressNovelty) -> T,
        mut decide: impl FnMut(&mut EgressLedger) -> T,
    ) -> T {
        loop {
            let need = {
                // A poisoned lock: the balance cannot be trusted (ADR 0007 A-1).
                let Ok(mut state) = self.ledger.lock() else {
                    return refused(EgressNovelty::First);
                };
                let Some(ledger) = state.as_mut() else {
                    return refused(EgressNovelty::Repeat);
                };
                let need = ledger.counted().saturating_add(bytes);
                // Within the mark, or past the ceiling (refused and latched, so nothing is
                // admitted that a mark must cover): decide now, under this lock.
                if self.checkpoint.is_none()
                    || need <= self.committed.load(Ordering::SeqCst)
                    || need > self.ceiling.max_bytes()
                {
                    return decide(ledger);
                }
                need
            };
            if !self.raise(need).await {
                self.fault();
                return refused(EgressNovelty::First);
            }
        }
    }

    /// Reserve `bytes` for a send at `now_unix`.
    pub(crate) async fn reserve(&self, bytes: EgressBytes, now_unix: u64) -> EgressDecision {
        self.within_mark(
            bytes,
            |novelty| EgressDecision::Refused(EgressRefusal::LedgerFault, novelty),
            |ledger| ledger.reserve(bytes, now_unix),
        )
        .await
    }

    /// Reserve a whole staged upload of `bytes`; its slices are paced by [`Self::pace_upload`].
    pub(crate) async fn reserve_upload(
        &self,
        bytes: EgressBytes,
    ) -> Result<EgressUploadHold, (EgressRefusal, EgressNovelty)> {
        self.within_mark(
            bytes,
            |novelty| Err((EgressRefusal::LedgerFault, novelty)),
            |ledger| ledger.reserve_upload(bytes),
        )
        .await
    }

    /// Settle an upload this account reserved.
    pub(crate) fn settle_upload(&self, upload: EgressUploadHold, outcome: EgressSettlement) {
        if let Ok(mut state) = self.ledger.lock() {
            if let Some(ledger) = state.as_mut() {
                if let Err(e) = ledger.settle_upload(upload, outcome) {
                    tracing::error!("upload settle refused: {e}");
                }
            }
        }
    }

    /// Make the durable mark at least `need`. `false` when it could not be written.
    async fn raise(&self, need: EgressBytes) -> bool {
        let _raising = self.raising.lock().await;
        if self.committed.load(Ordering::SeqCst) >= need {
            return true;
        }
        let target = need.saturating_add(self.step).min(self.ceiling.max_bytes());
        let Some((pod, path)) = &self.checkpoint else {
            return true;
        };
        if !self.retired.load(Ordering::SeqCst) {
            let record = Checkpoint {
                version: 1,
                pod: *pod,
                committed: target,
            };
            let written = match serde_json::to_vec(&record) {
                Ok(bytes) => super::write_whole(path, &bytes).await,
                Err(e) => Err(std::io::Error::other(e)),
            };
            if let Err(e) = written {
                tracing::error!(pod = %pod, error = %e, "egress checkpoint failed; the account is faulted");
                return false;
            }
        }
        self.committed.store(target, Ordering::SeqCst);
        true
    }

    /// Settle a hold this account decided.
    pub(crate) fn settle(&self, hold: EgressHold, outcome: EgressSettlement) {
        // Poisoned: the hold stays reserved — counted as sent, the fail-closed reading.
        if let Ok(mut state) = self.ledger.lock() {
            let Some(ledger) = state.as_mut() else { return };
            if let Err(e) = ledger.settle(hold, outcome) {
                tracing::error!("egress settle refused: {e}");
            }
        }
    }

    /// Refuse every later reservation through this account. `true` the first time.
    pub(crate) fn fault(&self) -> bool {
        self.ledger
            .lock()
            .map(|mut ledger| ledger.take().is_some())
            .unwrap_or(true)
    }

    /// The pod's authority was released: stop writing a mark nothing will restore.
    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::SeqCst);
    }
}

/// A pod's own account followed by each ancestor's: every account a send of its must draw on.
#[derive(Debug, Clone)]
pub(crate) struct EgressChain {
    accounts: Vec<Arc<EgressAccount>>,
}

impl EgressChain {
    /// The chain of a pod with no pod parent: its own account alone.
    pub(crate) fn root(own: Arc<EgressAccount>) -> Self {
        Self {
            accounts: vec![own],
        }
    }

    /// The chain of a child of the pod whose chain this is.
    pub(crate) fn child(&self, own: Arc<EgressAccount>) -> Self {
        let mut accounts = Vec::with_capacity(self.accounts.len() + 1);
        accounts.push(own);
        accounts.extend(self.accounts.iter().cloned());
        Self { accounts }
    }

    /// The pod's own account.
    pub(crate) fn own(&self) -> &Arc<EgressAccount> {
        &self.accounts[0]
    }

    /// Every account, own first.
    pub(crate) fn accounts(&self) -> &[Arc<EgressAccount>] {
        &self.accounts
    }

    /// The next slice of an upload `holds` reserved (one hold per account, in order): the
    /// least every account admits, decided with every account's lock held, so each counts
    /// exactly the slice that is sent.
    ///
    /// Locks are taken own first, then each ancestor in turn: one order for every chain (a
    /// descendant before its ancestors), so two chains sharing ancestors cannot deadlock. On an
    /// error the holds are dropped and their allocations retained, as one ledger's are.
    pub(crate) fn pace_upload(
        &self,
        holds: Vec<EgressUploadHold>,
        requested: EgressBytes,
        now_unix: u64,
    ) -> Result<(Vec<EgressUploadHold>, UploadPace), EgressRefusal> {
        if holds.len() != self.accounts.len() {
            return Err(EgressRefusal::LedgerFault);
        }
        let mut guards = Vec::with_capacity(self.accounts.len());
        for account in &self.accounts {
            guards.push(
                account
                    .ledger
                    .lock()
                    .map_err(|_| EgressRefusal::LedgerFault)?,
            );
        }
        let mut slice = UploadPace::Ready(requested);
        let mut asked = Vec::with_capacity(holds.len());
        for (guard, hold) in guards.iter().zip(holds) {
            let ledger = guard.as_ref().ok_or(EgressRefusal::LedgerFault)?;
            let (hold, allowed) = ledger.upload_allowance(hold, requested, now_unix)?;
            asked.push(hold);
            slice = match (slice, allowed) {
                (UploadPace::Complete, _) | (_, UploadPace::Complete) => UploadPace::Complete,
                (UploadPace::Wait { seconds: a }, UploadPace::Wait { seconds: b }) => {
                    UploadPace::Wait { seconds: a.max(b) }
                }
                (wait @ UploadPace::Wait { .. }, UploadPace::Ready(_))
                | (UploadPace::Ready(_), wait @ UploadPace::Wait { .. }) => wait,
                (UploadPace::Ready(a), UploadPace::Ready(b)) => UploadPace::Ready(a.min(b)),
            };
        }
        let bytes = match slice {
            UploadPace::Ready(bytes) => bytes,
            wait_or_complete @ (UploadPace::Wait { .. } | UploadPace::Complete) => {
                return Ok((asked, wait_or_complete));
            }
        };
        let mut paced = Vec::with_capacity(asked.len());
        for (guard, hold) in guards.iter_mut().zip(asked) {
            let ledger = guard.as_mut().ok_or(EgressRefusal::LedgerFault)?;
            let (hold, pace) = ledger.pace_upload(hold, bytes, now_unix)?;
            // Every account allowed at least `bytes` under these same locks.
            if pace != UploadPace::Ready(bytes) {
                return Err(EgressRefusal::LedgerFault);
            }
            paced.push(hold);
        }
        Ok((paced, UploadPace::Ready(bytes)))
    }

    /// The least any account on the chain has left: what a new child of this pod may be
    /// admitted. `None` when an account cannot say, which refuses the child.
    pub(crate) fn remaining(&self) -> Option<EgressBytes> {
        self.accounts
            .iter()
            .map(|a| a.remaining())
            .try_fold(EgressBytes::MAX, |least, r| r.map(|r| least.min(r)))
    }
}

/// A pod's egress standing in the authority. Two arms, not an `Option`: an account that could
/// not be rebuilt after a restart is not an unlimited one (ADR 0007 B-2).
#[derive(Clone)]
pub(crate) enum PodEgress {
    Live(EgressChain),
    /// Restored without the record a chain needs; the reason, for the refusal.
    Unrecoverable(&'static str),
}

/// After a restore, rebuild every restored pod's chain from its own account and its parent's
/// chain. Each pod was restored with its own account alone; a pod whose parent was not
/// restored (released before the restart, or unreadable) cannot be relinked, and is
/// [`PodEgress::Unrecoverable`]: its descendants' sends could no longer be charged to it.
pub(super) fn relink(pods: &mut std::collections::HashMap<Uuid, super::PodCert>) {
    use std::collections::HashMap;
    let parents: HashMap<Uuid, super::Parent> =
        pods.iter().map(|(id, pod)| (*id, pod.parent)).collect();
    let own: HashMap<Uuid, Result<Arc<EgressAccount>, &'static str>> = pods
        .iter()
        .map(|(id, pod)| {
            let account = match &pod.egress {
                PodEgress::Live(chain) => Ok(Arc::clone(chain.own())),
                PodEgress::Unrecoverable(why) => Err(*why),
            };
            (*id, account)
        })
        .collect();
    let mut linked: HashMap<Uuid, PodEgress> = HashMap::new();
    for id in own.keys() {
        resolve(*id, &parents, &own, &mut linked, 0);
    }
    for (id, egress) in linked {
        if let Some(pod) = pods.get_mut(&id) {
            pod.egress = egress;
        }
    }
}

fn resolve(
    id: Uuid,
    parents: &std::collections::HashMap<Uuid, super::Parent>,
    own: &std::collections::HashMap<Uuid, Result<Arc<EgressAccount>, &'static str>>,
    linked: &mut std::collections::HashMap<Uuid, PodEgress>,
    depth: usize,
) -> PodEgress {
    if let Some(done) = linked.get(&id) {
        return done.clone();
    }
    let gone = PodEgress::Unrecoverable("its parent's egress account was not restored");
    let result = match own.get(&id) {
        None => PodEgress::Unrecoverable("its authority record was not restored"),
        Some(Err(why)) => PodEgress::Unrecoverable(why),
        Some(Ok(account)) => match parents.get(&id) {
            // Records that name each other as parents: no chain ends.
            Some(super::Parent::Pod(_)) if depth > super::DEFAULT_MAX_CHAIN_DEPTH => {
                PodEgress::Unrecoverable("its parent chain does not end")
            }
            Some(super::Parent::Pod(parent)) if own.contains_key(parent) => {
                match resolve(*parent, parents, own, linked, depth + 1) {
                    PodEgress::Live(chain) => PodEgress::Live(chain.child(Arc::clone(account))),
                    PodEgress::Unrecoverable(_) => gone,
                }
            }
            Some(super::Parent::Pod(_)) => gone,
            Some(super::Parent::Root | super::Parent::External(_)) | None => {
                PodEgress::Live(EgressChain::root(Arc::clone(account)))
            }
        },
    };
    linked.insert(id, result.clone());
    result
}

/// `network.egress` as admitted, in the shape the spec and `authority.json` carry it.
pub(crate) fn spec_of(ceiling: EgressCeiling) -> nucleus_spec::EgressBudgetSpec {
    nucleus_spec::EgressBudgetSpec {
        max_bytes: ceiling.max_bytes(),
        rate: match ceiling.pace() {
            EgressPace::Unpaced => None,
            EgressPace::PerWindow { bytes, window_secs } => {
                Some(nucleus_spec::EgressRateSpec { bytes, window_secs })
            }
        },
    }
}

/// The ceiling a child declaring `declared` (its `network.egress`, if any) is admitted under,
/// when its chain has `remaining` left. See the module docs for why a declaration is refused
/// where the default is met.
pub(crate) fn meet(
    declared: Option<&nucleus_spec::EgressBudgetSpec>,
    remaining: EgressBytes,
) -> Result<EgressCeiling, String> {
    match declared {
        Some(spec) if spec.max_bytes > remaining => Err(format!(
            "egress conservation: the child declares network.egress.max_bytes = {} and its \
             parent's chain has {remaining} bytes left",
            spec.max_bytes
        )),
        Some(spec) => Ok(spec.ceiling()),
        None => {
            let default = EgressCeiling::undeclared();
            Ok(EgressCeiling::new(
                default.max_bytes().min(remaining),
                default.pace(),
            ))
        }
    }
}
