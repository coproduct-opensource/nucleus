//! Minting a run's binding, admitting it, and publishing its branch (Program B, M3).
//!
//! # What a run is given
//!
//! A binding pins the space's head when it is minted, and the node writes the run its own copy
//! of that version as its view sees it: a fresh journal in a private directory of the binding's
//! own (`<root>/bindings/<binding id>`), in the layout every proxy opens
//! (`nucleus_provenance_memory::write_delivery`). The run's proxy is that journal's only writer:
//!
//! * a `Read` binding's writes stay in its copy, and nothing of them can be published;
//! * a `ReadPropose` binding's copy is its **branch**: the pinned base plus its own writes. Two
//!   runs of one space share the base and never each other's writes. A publish takes the
//!   branch's records that are not in the delivered base as its patch.
//!
//! Nothing here assumes the run shares a filesystem with the space: what crosses is one file,
//! written by the node and read back by the node. (Firecracker still refuses memory, #3100.)
//!
//! # The publish verdict, and the channel it does not open
//!
//! A publish is compare-and-swap onto an expected head, and the **whole candidate** is
//! validated (`BindingValidator`): the records are within the binding's view, keyed conflicts
//! and label monotonicity hold over the head (the store's own invariants, the memory-context
//! kernel's per-key clauses), and the quota. The kernel's quota is global, which makes its
//! accept/refuse a channel: an entry the run cannot see spends it (M1's README). Here the quota
//! is split: each publishing binding reserves an allocation when it is minted, the allocations
//! never exceed the space's quota, and a publish is refused only when it would overspend the
//! binding's OWN allocation. So the quota half of the verdict depends on nothing outside the
//! binding. What still depends on others is declared, not hidden:
//!
//! * minting a publishing binding is refused when the space has no unreserved bytes left
//!   (`QuotaFullyAllocated`): a bind-time availability channel, receipted by its absence;
//! * a stale base (`StaleBase`) says the head moved: a version count, which a rebind shows
//!   anyway;
//! * a keyed conflict or a lowered label says a record with the same content hash as one the
//!   run itself proposes is at the head.
use std::cell::Cell;
use std::collections::BTreeMap;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nucleus_memory_context::extracted::admit::{ADMITTED, EXPIRED, FOREIGN_EPOCH, admit_code};
use nucleus_provenance_memory::{
    Candidate, CandidateRefusal, CandidateValidator, ContentHash, Epoch, JournalError,
    JournalLocation, JournalPart, MAX_JOURNAL_BYTES, MemoryRecord, Patch, Pin, PinnedSnapshot,
    ProvenanceMemorySet, PublishRefusal, PublishedJournal, PublisherBinding, ReachCheck,
    StoreInvariants, TransformRegistry, read_unlocked, write_delivery,
};
use uuid::Uuid;

use crate::ApiError;
use crate::memory_flow::{FlowClaim, FlowEvent, Recorder};
use crate::memory_space::{
    Binding, BindingPolicy, DecisionCiter, Expiry, MemoryRefusal, MemorySpace, Mode, PodMatch,
    PolicyAuthority, Principal, Registry, SpaceId, SpaceName, TenantKey, ViewSpec, bind_capability,
    policy_liveness, publish_capability,
};

/// The journal file in every space and binding directory.
pub(crate) const JOURNAL: &str = "memory.jsonl";
/// A binding is forgotten this long after its `not_after`: until then a late publish is refused
/// as `Expired`, by name, rather than as an unknown binding.
const FORGET_AFTER_SECS: u64 = 24 * 60 * 60;

/// Every journal and directory under the memory root must be its owner's: anything another uid
/// owns could have been replaced or read by that uid.
pub(crate) struct NodeOwned {
    uid: u32,
}

impl ReachCheck for NodeOwned {
    fn admit(&self, part: JournalPart, owner_uid: u32) -> Result<(), String> {
        if owner_uid == self.uid {
            Ok(())
        } else {
            Err(format!(
                "memory {part:?} is owned by uid {owner_uid}, not by the memory root's owner {}",
                self.uid
            ))
        }
    }
}

/// A run asking for a space at pod creation.
pub(crate) struct BindRequest<'a> {
    pub(crate) tenant: &'a TenantKey,
    pub(crate) name: &'a SpaceName,
    pub(crate) pod: Uuid,
    pub(crate) matched: PodMatch<'a>,
    /// When the run's own lifetime ends, plus the window in which its branch may still be
    /// published.
    pub(crate) run_ends: u64,
    pub(crate) now: u64,
}

/// What the pod is handed: its binding's directory and the namespace its journal carries.
#[derive(Debug)]
pub(crate) struct Delivered {
    pub(crate) directory: PathBuf,
    pub(crate) namespace: String,
    pub(crate) binding: Uuid,
}

/// Who asks for a publish.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Publisher<'a> {
    /// The binding's tenant's root identity.
    TenantRoot(&'a TenantKey),
    /// The pod that holds the binding.
    Pod(Uuid),
}

/// A binding admitted for one publish: minted only by [`Registry::admit_publish`], consumed by
/// [`Registry::publish`] (ADR 0007 C-1, C-4). Carries the epoch and `not_after` it was admitted
/// under.
#[must_use = "an admitted publish that is never used is a publish that was decided and not made"]
#[derive(Debug)]
pub(crate) struct AdmittedPublish {
    binding: Uuid,
    epoch: u32,
    not_after: u64,
    allocation_left: u64,
}

/// `root/<segments...>`, each level created private, and each checked private when it exists.
pub(crate) fn ensure_path(root: &Path, segments: &[&str]) -> Result<PathBuf, ApiError> {
    let mut path = root.to_path_buf();
    for segment in segments {
        path.push(segment);
        ensure_directory(&path)?;
    }
    Ok(path)
}

pub(crate) fn private_directory(path: &Path) -> Result<(), ApiError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(ApiError::Driver(
            "memory directories must be private real directories (mode 0700)".into(),
        ));
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<(), ApiError> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                std::fs::File::open(parent)?.sync_all()?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    private_directory(path)
}

fn journal_error(e: JournalError) -> ApiError {
    match e {
        JournalError::Io(io) => ApiError::Io(io),
        other => ApiError::Driver(format!("memory journal: {other}")),
    }
}

/// The records `view` is given of `set`, in an order a replay admits: a visible record whose
/// every cited input is given too. A record citing one the view does not see is withheld as
/// well, since it could not be re-derived without it.
pub(crate) fn deliverable(set: &ProvenanceMemorySet, view: &ViewSpec) -> Vec<MemoryRecord> {
    let mut pending: Vec<&MemoryRecord> = set.iter().filter(|r| view.sees(r)).collect();
    let mut given: BTreeMap<ContentHash, ()> = BTreeMap::new();
    let mut out = Vec::new();
    loop {
        let before = pending.len();
        pending.retain(|record| {
            let ready = record
                .derivation
                .input_record_hashes()
                .iter()
                .all(|input| given.contains_key(input));
            if ready {
                given.insert(record.content_hash(), ());
                out.push((*record).clone());
            }
            !ready
        });
        if pending.len() == before {
            return out;
        }
    }
}

/// The policy's authority, re-cited at `now` when it is a decision: `Ok(None)` when no decision
/// stands behind it, `Ok(Some(not_after))` when one does and still covers it.
fn recite(
    policy: &BindingPolicy,
    space: &SpaceId,
    citer: Option<&dyn DecisionCiter>,
    now: u64,
    publish: bool,
) -> Result<Option<u64>, MemoryRefusal> {
    match &policy.authority {
        PolicyAuthority::Decision { id } => {
            let refuse = |why: String| MemoryRefusal::DecisionRefused {
                policy: policy.id,
                decision: id.clone(),
                why,
            };
            let citer =
                citer.ok_or_else(|| refuse("this node verifies no owner decisions".into()))?;
            let mut not_after = citer
                .cite(id, &bind_capability(space), now)
                .map_err(refuse)?;
            if publish {
                not_after = not_after.min(
                    citer
                        .cite(id, &publish_capability(space), now)
                        .map_err(refuse)?,
                );
            }
            Ok(Some(not_after))
        }
        PolicyAuthority::TenantRoot
        | PolicyAuthority::LineageDefault
        | PolicyAuthority::Migration => Ok(None),
    }
}

/// A pinned position the journal no longer holds, by name.
fn pin_refusal(space: &MemorySpace, held: Pin, e: JournalError) -> ApiError {
    match e {
        JournalError::VersionAbsent { requested, head } => MemoryRefusal::Truncated {
            space: space.id.reference(),
            held: requested,
            found: head,
        }
        .into(),
        JournalError::PinMismatch { version } => MemoryRefusal::Rewritten {
            space: space.id.reference(),
            version,
        }
        .into(),
        other => {
            tracing::warn!(
                version = held.version(),
                "a pinned memory read failed: {other}"
            );
            journal_error(other)
        }
    }
}

/// The higher of two positions, by version.
fn higher(a: Option<Pin>, b: Pin) -> Pin {
    match a {
        Some(a) if a.version() > b.version() => a,
        Some(_) | None => b,
    }
}

impl Registry {
    fn location(&self, segments: &[String], namespace: &str) -> Result<JournalLocation, ApiError> {
        let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
        let dir = ensure_path(&self.root, &segments)?;
        JournalLocation::new(&dir.join(JOURNAL), namespace).map_err(journal_error)
    }

    fn space_location(&self, space: &MemorySpace) -> Result<JournalLocation, ApiError> {
        let (segments, namespace) = space
            .store()
            .ok_or_else(|| ApiError::Driver("memory space has no location for its id".into()))?;
        self.location(&segments, &namespace)
    }

    fn reach(&self) -> Result<NodeOwned, ApiError> {
        Ok(NodeOwned {
            uid: self.owner_uid()?,
        })
    }

    /// Bytes the space's live publishing bindings have reserved and not yet spent.
    fn reserved(&self, space: &MemorySpace, now: u64) -> u64 {
        self.bindings
            .values()
            .filter(|b| b.tenant == space.tenant && b.space == space.id)
            .map(|b| b.reserves(space.epoch, now))
            .fold(0u64, u64::saturating_add)
    }

    /// Mint the run's binding: resolve the space and the policy that admits the pod, re-cite a
    /// decision behind it, pin the head (refusing a journal rolled back below any earlier pin),
    /// reserve the allocation, write the snapshot, and keep its delivery receipt — all before the
    /// pod is handed the directory. A receipt that is not kept undoes the binding and removes
    /// the snapshot.
    pub(crate) fn bind(
        &mut self,
        request: BindRequest<'_>,
        citer: Option<&dyn DecisionCiter>,
        record: Recorder<'_>,
    ) -> Result<Delivered, ApiError> {
        let now = request.now;
        self.bindings
            .retain(|_, b| b.not_after.saturating_add(FORGET_AFTER_SECS) >= now);
        let (space_id, policy_id) = self.resolve(
            request.tenant,
            request.name,
            &request.matched,
            now,
            &mut *record,
        )?;
        let key = (request.tenant.clone(), space_id.clone());
        let space = self.space(request.tenant, &space_id)?;
        let policy = self
            .policies
            .get(&policy_id)
            .ok_or(MemoryRefusal::UnknownPolicy(policy_id))?;
        let decided = recite(policy, &space_id, citer, now, policy.may_publish)?;
        let policy_ends = match policy.expiry {
            Expiry::At(at) => at.saturating_sub(1),
            Expiry::UntilRevoked => u64::MAX,
        };
        let not_after = request
            .run_ends
            .min(policy_ends)
            .min(decided.unwrap_or(u64::MAX));

        let reach = self.reach()?;
        let transforms = TransformRegistry::new();
        let loc = self.space_location(space)?;
        let journal =
            PublishedJournal::open(loc.clone(), &reach, &transforms).map_err(journal_error)?;
        let head = journal.head().map_err(journal_error)?;
        if let Some(held) = space.high_water {
            if head.version() < held.version() {
                return Err(MemoryRefusal::Truncated {
                    space: space_id.reference(),
                    held: held.version(),
                    found: head.version(),
                }
                .into());
            }
            PinnedSnapshot::open(&loc, held, &reach, &transforms)
                .map_err(|e| pin_refusal(space, held, e))?;
        }
        let allocation = if policy.may_publish {
            policy.allocation_bytes
        } else {
            0
        };
        if allocation > 0 {
            let used = journal
                .bytes()
                .map_err(journal_error)?
                .saturating_add(self.reserved(space, now));
            let free = space.quota_bytes.saturating_sub(used);
            if allocation > free {
                return Err(MemoryRefusal::QuotaFullyAllocated {
                    space: space_id.reference(),
                    free,
                    allocation,
                }
                .into());
            }
        }
        let records = deliverable(journal.records().map_err(journal_error)?, &policy.view);
        drop(journal);

        let binding_id = Uuid::new_v4();
        let mut binding = Binding {
            binding_id,
            tenant: request.tenant.clone(),
            space: space_id.clone(),
            policy: policy_id,
            principal: Principal {
                pod: request.pod,
                lineage: request.matched.lineage,
            },
            view: policy.view.clone(),
            base: head,
            mode: policy.mode,
            may_publish: policy.may_publish,
            epoch: space.epoch,
            not_after,
            allocation_bytes: allocation,
            spent_bytes: 0,
            delivered_sha256: String::new(),
        };
        let (segments, namespace) = binding.store();
        let delivered = self.location(&segments, &namespace)?;
        let directory = delivered
            .path()
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| ApiError::Driver("binding directory has no path".into()))?;
        let digest = match write_delivery(&delivered, &records, &transforms) {
            Ok(digest) => digest,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&directory);
                return Err(journal_error(e));
            }
        };
        binding.delivered_sha256 = hex::encode(digest);

        let previous = space.high_water;
        if let Some(space) = self.spaces.get_mut(&key) {
            space.high_water = Some(higher(previous, head));
        }
        self.bindings.insert(binding_id, binding);
        let kept = {
            let binding = &self.bindings[&binding_id];
            let policy = &self.policies[&policy_id];
            let claim = FlowClaim::new(
                request.tenant,
                &binding.space,
                now,
                FlowEvent::SnapshotDelivery {
                    binding: binding_id,
                    pod: request.pod,
                    lineage: request.matched.lineage,
                    policy: policy_id,
                    audience: &policy.audience,
                    mode: binding.mode,
                    view: &binding.view,
                    view_digest: binding.view.digest(),
                    base: binding.base,
                    records: records.len(),
                    bytes_sha256: binding.delivered_sha256.clone(),
                    epoch: binding.epoch,
                    not_after: binding.not_after,
                    allocation_bytes: binding.allocation_bytes,
                },
            );
            self.keep(&[claim], record)
        };
        if let Err(e) = kept {
            self.bindings.remove(&binding_id);
            if let Some(space) = self.spaces.get_mut(&key) {
                space.high_water = previous;
            }
            let _ = std::fs::remove_dir_all(&directory);
            return Err(e);
        }
        tracing::info!(
            pod = %request.pod,
            binding = %binding_id,
            space = %space_id.reference(),
            policy = %policy_id,
            version = head.version(),
            "a run was bound to a memory space and handed its pinned snapshot"
        );
        Ok(Delivered {
            directory,
            namespace,
            binding: binding_id,
        })
    }

    /// Admit `binding` for one publish at `now`: its policy is live, its epoch is the space's
    /// and it is not past `not_after` (the memory-context kernel's admission slice, epoch
    /// first), it may publish, and a decision behind its policy still covers publishing.
    pub(crate) fn admit_publish(
        &self,
        binding: Uuid,
        caller: Publisher<'_>,
        now: u64,
        citer: Option<&dyn DecisionCiter>,
    ) -> Result<AdmittedPublish, MemoryRefusal> {
        let unknown = MemoryRefusal::UnknownBinding(binding);
        let held = self
            .bindings
            .get(&binding)
            .filter(|b| match caller {
                Publisher::TenantRoot(tenant) => &b.tenant == tenant,
                Publisher::Pod(pod) => b.principal.pod == pod,
            })
            .ok_or_else(|| unknown.clone())?;
        let space = self
            .space(&held.tenant, &held.space)
            .map_err(|_| unknown.clone())?;
        let foreign = || MemoryRefusal::ForeignEpoch {
            binding,
            space: held.space.reference(),
            binding_epoch: held.epoch,
            current: space.epoch,
        };
        match admit_code(held.epoch, held.not_after, space.epoch, now) {
            ADMITTED => {}
            EXPIRED => {
                return Err(MemoryRefusal::Expired {
                    binding,
                    not_after: held.not_after,
                });
            }
            FOREIGN_EPOCH => return Err(foreign()),
            // A code the slice does not name is refused, never admitted (ADR 0007 B-3).
            _ => return Err(foreign()),
        }
        let policy = self.policies.get(&held.policy).ok_or(unknown)?;
        policy_liveness(policy, space, now)?;
        let publishes = match held.mode {
            Mode::Read => false,
            Mode::ReadPropose => held.may_publish,
        };
        if !publishes {
            return Err(MemoryRefusal::MayNotPublish(binding));
        }
        recite(policy, &held.space, citer, now, true)?;
        Ok(AdmittedPublish {
            binding,
            epoch: held.epoch,
            not_after: held.not_after,
            allocation_left: held.allocation_bytes.saturating_sub(held.spent_bytes),
        })
    }

    /// Publish an admitted binding's branch onto the space, compare-and-swap on `expected`.
    ///
    /// The patch is the branch's records that are not in the snapshot the binding was given,
    /// over the binding's pinned base. The base is re-read from the space's journal at the pin,
    /// so a journal rolled back below it is refused by name. The publish's receipt is kept
    /// before the commit is appended (`PublishedJournal::publish_with`); a receipt that is not
    /// kept appends nothing.
    pub(crate) fn publish(
        &mut self,
        admitted: AdmittedPublish,
        expected: Pin,
        now: u64,
        record: Recorder<'_>,
    ) -> Result<Pin, ApiError> {
        let AdmittedPublish {
            binding: binding_id,
            epoch,
            not_after,
            allocation_left,
        } = admitted;
        if now > not_after {
            return Err(MemoryRefusal::Expired {
                binding: binding_id,
                not_after,
            }
            .into());
        }
        let binding = self
            .bindings
            .get(&binding_id)
            .ok_or(MemoryRefusal::UnknownBinding(binding_id))?;
        let space = self.space(&binding.tenant, &binding.space)?;
        let reach = self.reach()?;
        let transforms = TransformRegistry::new();
        let loc = self.space_location(space)?;
        let mut journal =
            PublishedJournal::open(loc.clone(), &reach, &transforms).map_err(journal_error)?;
        let base = PinnedSnapshot::open(&loc, binding.base, &reach, &transforms)
            .map_err(|e| pin_refusal(space, binding.base, e))?;
        let given: BTreeMap<ContentHash, MemoryRecord> = deliverable(base.records(), &binding.view)
            .into_iter()
            .map(|r| (r.content_hash(), r))
            .collect();
        let (segments, namespace) = binding.store();
        let branch = read_unlocked(&self.location(&segments, &namespace)?, &reach, &transforms)
            .map_err(journal_error)?;
        let additions: Vec<MemoryRecord> = branch
            .into_iter()
            .filter(|r| given.get(&r.content_hash()) != Some(r))
            .collect();
        let validator = BindingValidator {
            store: StoreInvariants::new(usize::MAX, MAX_JOURNAL_BYTES),
            view: &binding.view,
            bytes_before: journal.bytes().map_err(journal_error)?,
            allocation_left,
            spend: Cell::new(0),
        };
        let patch = Patch::new(binding.base, additions);
        let by = (
            PublisherBinding::from_bytes(binding.publisher()),
            Epoch::new(u64::from(epoch)),
        );
        let published = journal.publish_with(
            &patch,
            expected,
            by,
            &validator,
            &transforms,
            &mut |commit| {
                let claim = FlowClaim::new(
                    &binding.tenant,
                    &binding.space,
                    now,
                    FlowEvent::PublishAuthorized {
                        binding: binding_id,
                        pod: binding.principal.pod,
                        base: binding.base,
                        expected,
                        head: commit.head(),
                        records: commit.records().len(),
                        spend_bytes: validator.spend.get(),
                        epoch,
                    },
                );
                record(&claim).map_err(|e| e.to_string())
            },
        );
        let head = published.map_err(|refusal| publish_refusal(space, refusal))?;
        let spend = validator.spend.get();
        drop(journal);
        let key = (binding.tenant.clone(), binding.space.clone());
        if let Some(binding) = self.bindings.get_mut(&binding_id) {
            binding.spent_bytes = binding.spent_bytes.saturating_add(spend);
        }
        if let Some(space) = self.spaces.get_mut(&key) {
            space.high_water = Some(higher(space.high_water, head));
        }
        if let Err(e) = self.persist() {
            // The commit is in the hash-chained journal and its receipt is kept; only the
            // registry's copy of the spend is behind until the next write.
            tracing::error!(binding = %binding_id, "memory registry not updated after a publish: {e}");
        }
        Ok(head)
    }
}

fn publish_refusal(space: &MemorySpace, refusal: PublishRefusal) -> ApiError {
    let space = space.id.reference();
    match refusal {
        PublishRefusal::StaleBase { current } => ApiError::Conflict(format!(
            "stale base: memory space {space} is at version {} (head {}); publish again with that head as expected",
            current.version(),
            current.head().to_hex()
        )),
        PublishRefusal::ForeignBase { base } => MemoryRefusal::Rewritten {
            space,
            version: base.version(),
        }
        .into(),
        PublishRefusal::NothingToPublish => {
            ApiError::InvalidSpec("the binding's branch has nothing to publish".into())
        }
        PublishRefusal::Invalid(
            invalid @ (CandidateRefusal::AllocationExceeded { .. }
            | CandidateRefusal::OutsideView { .. }),
        ) => ApiError::Authority(format!("memory publish refused: {invalid}")),
        PublishRefusal::Invalid(invalid @ CandidateRefusal::KeyedConflict { .. }) => {
            ApiError::Conflict(format!("memory publish refused: {invalid}"))
        }
        PublishRefusal::Invalid(
            invalid @ (CandidateRefusal::LabelLowered { .. }
            | CandidateRefusal::RecordCap { .. }
            | CandidateRefusal::ByteCap { .. }),
        ) => ApiError::InvalidSpec(format!("memory publish refused: {invalid}")),
        PublishRefusal::Provenance { .. } => {
            ApiError::InvalidSpec(format!("memory publish refused: {refusal}"))
        }
        PublishRefusal::Capacity => {
            ApiError::CapacityExhausted(format!("memory space {space}'s journal is at capacity"))
        }
        PublishRefusal::Uncertain(io) => ApiError::Io(io),
        PublishRefusal::Unavailable
        | PublishRefusal::Commit(_)
        | PublishRefusal::Encoding(_)
        | PublishRefusal::NotRecorded(_) => {
            ApiError::Driver(format!("memory publish failed: {refusal}"))
        }
    }
}

/// The whole-candidate check of one binding's publish. The memory-context kernel's
/// `validate_candidate` clauses over real records, with its global quota replaced by the
/// binding's own allocation (see the module docs).
struct BindingValidator<'a> {
    /// Keyed conflicts and label monotonicity. Its record cap is off and its byte cap is the
    /// journal's hard limit, which the allocations keep out of reach: neither decides a verdict.
    store: StoreInvariants,
    view: &'a ViewSpec,
    /// The journal's size before this commit; the writer's lock holds it still.
    bytes_before: u64,
    allocation_left: u64,
    /// What the accepted commit spends, for the receipt and the binding's account.
    spend: Cell<u64>,
}

impl CandidateValidator for BindingValidator<'_> {
    fn validate(&self, candidate: &Candidate<'_>) -> Result<(), CandidateRefusal> {
        for record in candidate.additions {
            if !self.view.may_write(record) {
                return Err(CandidateRefusal::OutsideView {
                    hash: record.content_hash(),
                });
            }
        }
        let spend = candidate.journal_bytes.saturating_sub(self.bytes_before);
        if spend > self.allocation_left {
            return Err(CandidateRefusal::AllocationExceeded {
                spend,
                allocation: self.allocation_left,
            });
        }
        self.store.validate(candidate)?;
        self.spend.set(spend);
        Ok(())
    }
}

#[cfg(test)]
#[path = "memory_binding_tests.rs"]
mod tests;
