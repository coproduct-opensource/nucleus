//! Operator-owned journal for the live memory surface; replay never trusts set serialization.
use crate::{
    api_error::ApiError,
    memory::{MemoryWriteReq, MemoryWriteResp},
};
use nucleus_provenance_memory::{ContentHash, MemoryRecord, ProvenanceMemorySet, RecomputeMemory};
use portcullis_effects::authority::Authority;
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};
use tokio::io::AsyncWriteExt;

const MAX_BYTES: u64 = 64 * 1024 * 1024;
const SCHEMA: &str = "nucleus.memory-journal.v1";

#[derive(clap::Args, Debug)]
pub(crate) struct MemoryStoreArgs {
    /// Operator-owned journal outside the agent workspace. Its parent must exist and be private.
    #[arg(long, env = "NUCLEUS_MEMORY_STORE", requires = "memory_namespace")]
    memory_store: Option<PathBuf>,
    /// Stable operator namespace, checked on every journal reopen.
    #[arg(long, env = "NUCLEUS_MEMORY_NAMESPACE", requires = "memory_store")]
    memory_namespace: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema: String,
    namespace: String,
}

enum Journal {
    Ephemeral,
    Persistent {
        file: tokio::fs::File,
        bytes: u64,
        failed: bool,
    },
}

pub(crate) struct Store {
    set: ProvenanceMemorySet,
    journal: Journal,
}

impl MemoryStoreArgs {
    #[expect(
        clippy::disallowed_methods,
        reason = "ADR 0007 G-1: exclusive operator journal, one writer under the memory mutex; each append is synced before publication"
    )]
    pub(crate) fn open(
        &self,
        workspace: &std::path::Path,
        registry: &dyn RecomputeMemory,
    ) -> Result<Store, ApiError> {
        let fail = |message: &str| ApiError::Spec(format!("memory store: {message}"));
        let (path, namespace) = match (&self.memory_store, &self.memory_namespace) {
            (None, None) => {
                return Ok(Store {
                    set: ProvenanceMemorySet::new(),
                    journal: Journal::Ephemeral,
                });
            }
            (Some(path), Some(namespace)) => (path, namespace),
            _ => {
                return Err(fail(
                    "journal path and namespace must be configured together",
                ));
            }
        };
        if !path.is_absolute() || namespace.is_empty() || namespace.len() > 256 {
            return Err(fail(
                "requires an absolute path and a namespace of 1 to 256 bytes",
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| fail("missing parent directory"))?
            .canonicalize()?;
        if parent.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(fail(
                "parent directory must not grant group or other access",
            ));
        }
        let path = parent.join(
            path.file_name()
                .ok_or_else(|| fail("missing journal filename"))?,
        );
        crate::art12_sink::reject_workspace_path(&path, workspace)
            .map_err(|_| fail("journal must be outside the workspace"))?;
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if !meta.is_file() => {
                return Err(fail("journal must be a regular file, not a symlink"));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let (mut file, fresh) = match OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => (file, true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (
                OpenOptions::new().read(true).append(true).open(&path)?,
                false,
            ),
            Err(e) => return Err(e.into()),
        };
        file.try_lock()
            .map_err(|_| fail("journal is already owned by another proxy"))?;
        if file.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(fail("journal must be private"));
        }
        let set = if fresh {
            let mut header = serde_json::to_vec(&Header {
                schema: SCHEMA.into(),
                namespace: namespace.clone(),
            })
            .map_err(|_| fail("cannot encode header"))?;
            header.push(b'\n');
            file.write_all(&header)?;
            file.sync_all()?;
            std::fs::File::open(&parent)?.sync_all()?;
            ProvenanceMemorySet::new()
        } else {
            let mut bytes = Vec::new();
            (&mut file).take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_BYTES || bytes.last() != Some(&b'\n') {
                return Err(fail("journal is oversized or incomplete"));
            }
            let mut lines = bytes[..bytes.len() - 1].split(|b| *b == b'\n');
            let header: Header =
                serde_json::from_slice(lines.next().ok_or_else(|| fail("missing header"))?)
                    .map_err(|_| fail("invalid header"))?;
            if header.schema != SCHEMA || header.namespace != *namespace {
                return Err(fail("schema or namespace differs"));
            }
            let mut set = ProvenanceMemorySet::new();
            for line in lines {
                let record: MemoryRecord =
                    serde_json::from_slice(line).map_err(|_| fail("invalid record"))?;
                if !set.verified_admit(&record, registry).is_match() {
                    return Err(fail("record failed provenance replay"));
                }
            }
            set
        };
        let bytes = file.metadata()?.len();
        Ok(Store {
            set,
            journal: Journal::Persistent {
                file: tokio::fs::File::from_std(file),
                bytes,
                failed: false,
            },
        })
    }
}

impl Store {
    pub(crate) fn records(&self) -> Result<&ProvenanceMemorySet, ApiError> {
        if matches!(&self.journal, Journal::Persistent { failed: true, .. }) {
            return Err(ApiError::Spec(
                "memory journal unavailable after an uncertain write".into(),
            ));
        }
        Ok(&self.set)
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
    pub(crate) async fn commit(self) -> Result<MemoryWriteResp, ApiError> {
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
        if store.set.get(&hash) != Some(record) {
            if let Journal::Persistent {
                file,
                bytes,
                failed,
            } = &mut store.journal
            {
                let mut encoded = serde_json::to_vec(record)
                    .map_err(|_| ApiError::Spec("memory record encoding failed".into()))?;
                encoded.push(b'\n');
                let next = bytes
                    .checked_add(encoded.len() as u64)
                    .filter(|n| *n <= MAX_BYTES)
                    .ok_or_else(|| ApiError::Spec("memory journal capacity exhausted".into()))?;
                *failed = true;
                file.write_all(&encoded).await?;
                file.flush().await?;
                file.sync_all().await?;
                *bytes = next;
                *failed = false;
            }
        }
        store.set = candidate;
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
