//! Hold one open lock file for the node's entire lifetime. Never unlink it:
//! replacing the inode would let a second node lock a different file.
use std::{fs::File, path::Path};

pub(crate) fn acquire(state_dir: &Path) -> Result<File, crate::ApiError> {
    let path = state_dir.join("node.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    file.try_lock().map_err(|error| {
        crate::ApiError::Driver(format!(
            "cannot exclusively lock node state {}: {error}; stop the other node before restarting",
            state_dir.display()
        ))
    })?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_directory_is_exclusive_until_owner_exits() {
        let dir = tempfile::tempdir().unwrap();
        let first = acquire(dir.path()).unwrap();
        assert!(acquire(dir.path()).is_err());
        let other = tempfile::tempdir().unwrap();
        drop(acquire(other.path()).unwrap());
        drop(first);
        drop(acquire(dir.path()).unwrap());
        assert!(dir.path().join("node.lock").exists());
    }
}
