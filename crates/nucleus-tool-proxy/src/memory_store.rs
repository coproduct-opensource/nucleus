//! Operator-owned journal for the live memory surface; replay never trusts set serialization.
//!
//! Only the proxy may reach the journal (#3454). Its children are not held
//! off it by Landlock (the child ruleset is the guest layout's and applies
//! only under `MicroVM`, which never provisions memory), so the boundary is
//! the uid: a `0600` file in a `0700` directory, and no child whose uid could
//! open, append to or replace it. [`ChildReach`] is that last clause as
//! evidence, and [`MemoryStoreArgs::open`] cannot open a persistent journal
//! without it.
//!
//! The journal format (schema v2), its v1 -> v2 migration, pinned readers,
//! branch overlays and compare-and-swap publish live in
//! `nucleus_provenance_memory::journal`, which asks [`ChildReach`] about the
//! directory before anything is created and about the file before it is read.
//! This module binds the journal to the proxy's configuration and to its live
//! write path.
use crate::{
    api_error::ApiError,
    memory::{MemoryWriteReq, MemoryWriteResp},
};
use nucleus_provenance_memory::{
    ContentHash, Epoch, JournalError, JournalLocation, JournalPart, MAX_JOURNAL_BYTES, Patch,
    ProvenanceMemorySet, PublishRefusal, PublishedJournal, PublisherBinding, ReachCheck,
    RecomputeMemory, StoreInvariants,
};
use portcullis_effects::authority::Authority;
use std::path::PathBuf;

#[derive(clap::Args, Debug)]
pub(crate) struct MemoryStoreArgs {
    /// Operator-owned journal outside the agent workspace. Its parent must exist and be private.
    #[arg(long, env = "NUCLEUS_MEMORY_STORE", requires = "memory_namespace")]
    memory_store: Option<PathBuf>,
    /// Stable operator namespace, checked on every journal reopen.
    #[arg(long, env = "NUCLEUS_MEMORY_NAMESPACE", requires = "memory_store")]
    memory_namespace: Option<String>,
}

/// Process-local memory, or the versioned journal.
enum Journal {
    Ephemeral(ProvenanceMemorySet),
    Persistent(PublishedJournal),
}

pub(crate) struct Store {
    journal: Journal,
}

/// Who this proxy's children run as, asked of the deciders their spawns ask
/// (#3454, ADR 0007 G-1): `ChildConfinement::for_containment` for every
/// `/v1/run` child and `ChildConfinement::workload` for the pod's workload,
/// with the inputs the spawns pass. Evidence (C-1): minted only by
/// [`Self::of`], so the journal is checked against the uids the children get,
/// not against a restatement of them.
pub(crate) struct ChildReach {
    children: Vec<nucleus::ChildUid>,
}

impl ChildReach {
    pub(crate) fn of(
        workload: Option<&nucleus_spec::WorkloadSpec>,
        containment: nucleus::ContainmentMode,
        opt_in: nucleus::UnsandboxedOptIn,
        landlock: nucleus::LandlockWaiver,
    ) -> Self {
        let run = nucleus::ChildConfinement::for_containment(containment, opt_in, landlock);
        let workload = workload
            .map(|w| nucleus::ChildConfinement::workload(containment, w.uid, opt_in, landlock));
        // A refusal is not a lookup that failed (A-1): the spawn asks the same
        // decider with the same inputs and is refused by it, so that child
        // never exists and reaches nothing.
        let children = std::iter::once(run)
            .chain(workload)
            .filter_map(Result::ok)
            .map(|c| c.child_uid())
            .collect();
        Self { children }
    }

    /// Children that run as exactly these uids (the store's tests).
    #[cfg(test)]
    pub(crate) fn for_test(children: Vec<nucleus::ChildUid>) -> Self {
        Self { children }
    }

    /// Refuse, by name, a journal part (`what`) owned by `owner` that a child
    /// could reach: any child at the runtime's own uid (it can open the
    /// journal outright), or a child that is `owner` (owning the directory it
    /// can unlink or replace the journal; owning the file it can read it).
    /// No `_` arm (B-3): a new `ChildUid` must say what it reaches.
    fn excludes(&self, what: &str, owner: u32) -> Result<(), String> {
        for child in &self.children {
            match *child {
                nucleus::ChildUid::SharedWithRuntime => {
                    return Err(
                        "a child of this proxy runs at the proxy's own uid (the bare host tier), \
                         so it could read and append the journal directly; persistent memory \
                         requires children separated from the proxy's uid"
                            .into(),
                    );
                }
                nucleus::ChildUid::Distinct(uid) if uid == owner => {
                    return Err(format!(
                        "the journal's {what} is owned by uid {uid}, which a child of this proxy \
                         runs as, so that child could replace or read the journal"
                    ));
                }
                nucleus::ChildUid::Distinct(_) => {}
            }
        }
        Ok(())
    }
}

impl ReachCheck for ChildReach {
    fn admit(&self, part: JournalPart, owner_uid: u32) -> Result<(), String> {
        let what = match part {
            JournalPart::Directory => "directory",
            JournalPart::File => "file",
        };
        self.excludes(what, owner_uid)
    }
}

impl From<JournalError> for ApiError {
    fn from(e: JournalError) -> Self {
        match e {
            JournalError::Io(io) => ApiError::Io(io),
            other => ApiError::Spec(format!("memory store: {other}")),
        }
    }
}

impl MemoryStoreArgs {
    pub(crate) fn open(
        &self,
        workspace: &std::path::Path,
        registry: &dyn RecomputeMemory,
        children: &ChildReach,
    ) -> Result<Store, ApiError> {
        let fail = |message: &str| ApiError::Spec(format!("memory store: {message}"));
        let (path, namespace) = match (&self.memory_store, &self.memory_namespace) {
            (None, None) => {
                return Ok(Store {
                    journal: Journal::Ephemeral(ProvenanceMemorySet::new()),
                });
            }
            (Some(path), Some(namespace)) => (path, namespace),
            _ => {
                return Err(fail(
                    "journal path and namespace must be configured together",
                ));
            }
        };
        let location = JournalLocation::new(path, namespace)?;
        crate::art12_sink::reject_workspace_path(location.path(), workspace)
            .map_err(|_| fail("journal must be outside the workspace"))?;
        Ok(Store {
            journal: Journal::Persistent(PublishedJournal::open(location, children, registry)?),
        })
    }
}

impl Store {
    pub(crate) fn records(&self) -> Result<&ProvenanceMemorySet, ApiError> {
        match &self.journal {
            Journal::Ephemeral(set) => Ok(set),
            Journal::Persistent(journal) => Ok(journal.records()?),
        }
    }

    pub(crate) fn prepare(
        &mut self,
        registry: &dyn RecomputeMemory,
        req: MemoryWriteReq,
        authority: Authority,
    ) -> Result<PreparedWrite<'_>, ApiError> {
        let mut candidate = self.records()?.clone();
        let response = crate::memory::memory_write_core(&mut candidate, registry, req, authority)?;
        Ok(PreparedWrite {
            store: self,
            candidate,
            response,
        })
    }
}

impl PreparedWrite<'_> {
    /// Persist an admitted write as one commit on the current head, synced
    /// before the new state is visible. The write is not made under a
    /// node-minted binding, so it carries the fixed operator publisher and the
    /// pre-binding epoch. `registry` replays the record's provenance once more
    /// against the head it is committed on. Synchronous, so a cancelled request
    /// cannot stop it part-way.
    pub(crate) fn commit(
        self,
        registry: &dyn RecomputeMemory,
    ) -> Result<MemoryWriteResp, ApiError> {
        let PreparedWrite {
            store,
            candidate,
            response,
        } = self;
        store.records()?;
        if !response.admitted {
            return Ok(response);
        }
        let hash = ContentHash::from_hex(&response.content_hash)
            .map_err(|_| ApiError::Spec("invalid admitted memory hash".into()))?;
        let record = candidate
            .get(&hash)
            .ok_or_else(|| ApiError::Spec("admitted record missing".into()))?;
        match &mut store.journal {
            Journal::Ephemeral(set) => *set = candidate,
            Journal::Persistent(journal) => {
                let head = journal.head()?;
                let patch = Patch::new(head, vec![record.clone()]);
                match journal.publish(
                    &patch,
                    head,
                    PublisherBinding::operator_direct(),
                    Epoch::PRE_BINDING,
                    &StoreInvariants::new(usize::MAX, MAX_JOURNAL_BYTES),
                    registry,
                ) {
                    // A duplicate accepted record adds no commit.
                    Ok(_) | Err(PublishRefusal::NothingToPublish) => {}
                    Err(PublishRefusal::Uncertain(io)) => return Err(ApiError::Io(io)),
                    Err(refused) => {
                        return Err(ApiError::Spec(format!("memory journal: {refused}")));
                    }
                }
            }
        }
        Ok(response)
    }
}

#[must_use]
pub(crate) struct PreparedWrite<'a> {
    store: &'a mut Store,
    candidate: ProvenanceMemorySet,
    response: MemoryWriteResp,
}

#[cfg(test)]
#[path = "memory_store_tests.rs"]
mod tests;
