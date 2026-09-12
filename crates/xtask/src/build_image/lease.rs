//! Host controller liveness, independent of workload inputs and build evidence.
//! A worker atomically replaces this file while it holds its durable lease.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

pub(super) struct Watch {
    binding: Option<(PathBuf, String)>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Heartbeat {
    schema: String,
    attempt: String,
    expires_micros: u64,
}

impl Watch {
    pub(super) fn new(path: Option<PathBuf>, attempt: Option<String>) -> Result<Self> {
        let binding = match (path, attempt) {
            (None, None) => None,
            (Some(path), Some(attempt)) => {
                ensure!(
                    !attempt.is_empty() && attempt.len() <= 128,
                    "invalid controller attempt"
                );
                Some((path, attempt))
            }
            _ => anyhow::bail!("lease file and attempt ID must be supplied together"),
        };
        Ok(Self { binding })
    }

    pub(super) fn check(&self) -> Result<()> {
        self.check_at(super::execute::now()?)
    }

    fn check_at(&self, now: u64) -> Result<()> {
        let Some((path, attempt)) = &self.binding else {
            return Ok(());
        };
        let mut bytes = Vec::new();
        File::open(path)
            .context("worker heartbeat missing; controller revoked")?
            .take(4097)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 4096, "worker heartbeat exceeds size limit");
        let beat: Heartbeat = serde_json::from_slice(&bytes).context("invalid worker heartbeat")?;
        ensure!(
            beat.schema == "nucleus.controller-lease.v1" && beat.attempt == *attempt,
            "worker heartbeat belongs to a different attempt"
        );
        ensure!(
            beat.expires_micros > now,
            "worker lease expired; controller revoked"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_is_attempt_bound_expiring_and_missing_means_revoked() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("lease.json");
        let watch = Watch::new(Some(path.clone()), Some("attempt-1".into()))?;
        assert!(watch.check_at(10).is_err());
        std::fs::write(&path, br#"{"schema":"nucleus.controller-lease.v1","attempt":"attempt-1","expires_micros":20}"#)?;
        watch.check_at(19)?;
        assert!(watch.check_at(20).is_err());
        std::fs::write(&path, br#"{"schema":"nucleus.controller-lease.v1","attempt":"attempt-2","expires_micros":30}"#)?;
        assert!(watch.check_at(19).is_err());
        std::fs::write(&path, b"{}")?;
        assert!(watch.check_at(19).is_err());
        std::fs::remove_file(&path)?;
        assert!(watch.check_at(19).is_err());
        Ok(())
    }
}
