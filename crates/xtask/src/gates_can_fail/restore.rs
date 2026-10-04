use std::fs;
use std::path::PathBuf;

/// A perturbed target, restored when this is dropped -- including on the way out of an early
/// return. An interrupt is handled by `Harness::interrupted`, which restores explicitly.
pub(super) struct Restore {
    path: PathBuf,
    original: Vec<u8>,
    active: bool,
}

impl Restore {
    pub(super) fn new(path: PathBuf, original: Vec<u8>) -> Self {
        Self {
            path,
            original,
            active: true,
        }
    }
    pub(super) fn restore(&mut self) -> std::io::Result<()> {
        if self.active {
            fs::write(&self.path, &self.original)?;
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for Restore {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("ERROR: could not restore {}: {error}", self.path.display());
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
        assert!(guard.active, "a failed write cannot discharge restoration");
        fs::remove_dir(&path).unwrap();
        guard.restore().unwrap();
        assert!(!guard.active);
        assert_eq!(fs::read(&path).unwrap(), b"original");
    }
}
