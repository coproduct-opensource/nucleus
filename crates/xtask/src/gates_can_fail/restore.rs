use std::fs;
use std::path::PathBuf;

/// The perturbed files, restored when this is dropped -- including on the way out of an early
/// return. An interrupt is handled by `Harness::interrupted`, which restores explicitly.
///
/// More than one file because some defects ARE two edits: a dropped witness the inert-authority
/// manifest records as debt is a source line and a manifest row, and either alone is a different
/// defect (the census bails on the mismatch before the scorecard decides anything).
pub(super) struct Restore {
    /// Files still owed their original bytes, in the order they were perturbed.
    pending: Vec<(PathBuf, Vec<u8>)>,
}

impl Restore {
    pub(super) fn new(path: PathBuf, original: Vec<u8>) -> Self {
        Self {
            pending: vec![(path, original)],
        }
    }

    /// One more file this guard owes back. Registered BEFORE the file is written, so a write
    /// that half-lands is still restored.
    pub(super) fn also(&mut self, path: PathBuf, original: Vec<u8>) {
        self.pending.push((path, original));
    }

    /// Restore every pending file. A file whose write fails stays pending for a retry; the first
    /// error is returned after every other file has been attempted.
    pub(super) fn restore(&mut self) -> std::io::Result<()> {
        let mut first_error = None;
        self.pending.retain(|(path, original)| match fs::write(path, original) {
            Ok(()) => false,
            Err(e) => {
                first_error.get_or_insert(e);
                true
            }
        });
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for Restore {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            for (path, _) in &self.pending {
                eprintln!("ERROR: could not restore {}: {error}", path.display());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_restore_remains_active_for_retry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        fs::create_dir(&path).unwrap();
        let mut guard = Restore::new(path.clone(), b"original".to_vec());
        assert!(guard.restore().is_err());
        assert_eq!(guard.pending.len(), 1, "a failed write cannot discharge restoration");
        fs::remove_dir(&path).unwrap();
        guard.restore().unwrap();
        assert!(guard.pending.is_empty());
        assert_eq!(fs::read(&path).unwrap(), b"original");
    }

    #[test]
    fn every_file_is_restored_and_one_failure_does_not_stop_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let (a, blocked, c) = (
            dir.path().join("a"),
            dir.path().join("blocked"),
            dir.path().join("c"),
        );
        fs::write(&a, "perturbed").unwrap();
        fs::create_dir(&blocked).unwrap();
        fs::write(&c, "perturbed").unwrap();
        let mut guard = Restore::new(a.clone(), b"a".to_vec());
        guard.also(blocked.clone(), b"b".to_vec());
        guard.also(c.clone(), b"c".to_vec());
        assert!(guard.restore().is_err());
        assert_eq!(fs::read(&a).unwrap(), b"a");
        assert_eq!(fs::read(&c).unwrap(), b"c", "a failure before it must not skip it");
        assert_eq!(guard.pending.len(), 1);
        fs::remove_dir(&blocked).unwrap();
        drop(guard);
        assert_eq!(fs::read(&blocked).unwrap(), b"b", "the drop retries what is still owed");
    }
}
