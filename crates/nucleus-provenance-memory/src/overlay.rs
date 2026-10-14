//! A branch's private overlay journal over a pinned base.
//!
//! An overlay is its own private file with its own lock: a header naming the
//! space and the base [`Pin`], then one record per line. Writes go to the
//! overlay only; the published journal is untouched until the overlay's
//! [`Patch`] is published. Two overlays over one base share the base and never
//! each other's writes.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crdt::ProvenanceMemorySet;
use crate::hash::ContentHash;
use crate::journal::{
    Create, JournalError, JournalLocation, LockedLog, Opened, PinnedSnapshot, ReachCheck,
    SCHEMA_OVERLAY, admit_directory, admit_file, complete_lines, encode_line, open_locked,
    read_capped, sync_dir, verdict_reason,
};
use crate::recompute::RecomputeMemory;
use crate::record::MemoryRecord;
use crate::version::{Patch, Pin};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OverlayHeader {
    schema: String,
    namespace: String,
    base: Pin,
}

/// A writable branch over a pinned base.
pub struct Overlay {
    base: Pin,
    view: ProvenanceMemorySet,
    own: Vec<MemoryRecord>,
    log: LockedLog,
}

impl Overlay {
    /// Open (or create) the overlay at `path` over `base`, a snapshot of the
    /// journal at `journal`. The overlay must be a different file from the
    /// journal and its staging file; whether it is inside an agent's workspace
    /// is the caller's check, and `reach` is asked about its directory and file
    /// as for the journal. A reopened overlay must name the same base.
    pub fn open(
        path: &Path,
        journal: &JournalLocation,
        base: PinnedSnapshot,
        reach: &dyn ReachCheck,
        registry: &dyn RecomputeMemory,
    ) -> Result<Self, JournalError> {
        if base.namespace() != journal.namespace() {
            return Err(JournalError::NamespaceDiffers);
        }
        let location = JournalLocation::new(path, journal.namespace())?;
        if location.path() == journal.path() || location.path() == journal.staging_path() {
            return Err(JournalError::Location(
                "overlay must be a different file from the journal",
            ));
        }
        let pin = base.pin();
        let mut view = base.records().clone();
        let mut own = Vec::new();
        admit_directory(reach, location.parent())?;
        let file = match open_locked(location.path(), Create::OrOpen)? {
            Opened::Fresh(mut file) => {
                use std::io::Write;
                file.write_all(&encode_line(&OverlayHeader {
                    schema: SCHEMA_OVERLAY.into(),
                    namespace: journal.namespace().into(),
                    base: pin,
                })?)?;
                file.sync_all()?;
                sync_dir(location.parent())?;
                file
            }
            Opened::Existing(file) => {
                admit_file(reach, &file)?;
                let bytes = read_capped(&file)?;
                let lines = complete_lines(&bytes)?;
                let (header, body) = lines.split_first().ok_or(JournalError::Incomplete)?;
                let header: OverlayHeader =
                    serde_json::from_slice(header).map_err(|_| JournalError::InvalidHeader)?;
                if header.schema != SCHEMA_OVERLAY {
                    return Err(JournalError::UnknownSchema(
                        header.schema.chars().take(64).collect(),
                    ));
                }
                if header.namespace != journal.namespace() {
                    return Err(JournalError::NamespaceDiffers);
                }
                if header.base != pin {
                    return Err(JournalError::BaseDiffers);
                }
                for (index, line) in body.iter().enumerate() {
                    let number = index + 2;
                    let record: MemoryRecord = serde_json::from_slice(line)
                        .map_err(|_| JournalError::InvalidLine { line: number })?;
                    let hash = record.content_hash();
                    if view.get(&hash) == Some(&record) {
                        return Err(JournalError::Restated { line: number });
                    }
                    let verdict = view.verified_admit(&record, registry);
                    if !verdict.is_match() {
                        return Err(JournalError::Replay {
                            line: number,
                            hash,
                            reason: verdict_reason(&verdict),
                        });
                    }
                    own.push(record);
                }
                file
            }
        };
        Ok(Self {
            base: pin,
            view,
            own,
            log: LockedLog::new(file)?,
        })
    }

    /// The base this overlay is pinned to.
    pub fn base(&self) -> Pin {
        self.base
    }

    /// What this branch observes: the base plus its own writes.
    pub fn records(&self) -> Result<&ProvenanceMemorySet, JournalError> {
        self.log.available()?;
        Ok(&self.view)
    }

    /// Admit `record` against the base plus this branch's writes and append it
    /// to the overlay. A record already present, identically, is not rewritten.
    pub fn stage(
        &mut self,
        record: MemoryRecord,
        registry: &dyn RecomputeMemory,
    ) -> Result<ContentHash, JournalError> {
        self.log.available()?;
        let hash = record.content_hash();
        if self.view.get(&hash) == Some(&record) {
            return Ok(hash);
        }
        let mut candidate = self.view.clone();
        let verdict = candidate.verified_admit(&record, registry);
        if !verdict.is_match() {
            return Err(JournalError::Admission {
                hash,
                reason: verdict_reason(&verdict),
            });
        }
        let line = encode_line(&record)?;
        let next = self.log.after(line.len()).ok_or(JournalError::Capacity)?;
        self.log.append(&line, next)?;
        self.view = candidate;
        self.own.push(record);
        Ok(hash)
    }

    /// This branch's records that are not in its base, in admission order,
    /// as a patch over the base.
    pub fn patch(&self) -> Result<Patch, JournalError> {
        self.log.available()?;
        Ok(Patch::new(self.base, self.own.clone()))
    }
}
