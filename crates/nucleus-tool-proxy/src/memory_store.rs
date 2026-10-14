//! Operator-owned journal for the live memory surface; replay never trusts set serialization.
//!
//! Only the proxy may reach the journal (#3454). Its children are not held
//! off it by Landlock (the child ruleset is the guest layout's and applies
//! only under `MicroVM`, which never provisions memory), so the boundary is
//! the uid: a `0600` file in a `0700` directory, and no child whose uid could
//! open, append to or replace it. [`ChildReach`] (`child_reach`, the one
//! decider of what a child reaches, #3461) is that last clause as evidence,
//! and [`MemoryStoreArgs::open`] cannot open a persistent journal without it.
//!
//! The journal format (schema v2), its v1 -> v2 migration, pinned readers,
//! branch overlays and compare-and-swap publish live in
//! `nucleus_provenance_memory::journal`, which asks [`ChildReach`] about the
//! directory before anything is created and about the file before it is read.
//! This module binds the journal to the proxy's configuration and to its live
//! write path.
use crate::child_reach::ChildReach;
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
