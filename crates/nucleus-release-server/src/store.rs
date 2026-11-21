//! The checkpoint store: files kept under the digest they were measured to
//! have, and measured again before they are handed out.
//!
//! A checkpoint is a directory named by its digest, holding one or more
//! tensor files. [`CheckpointStore::put`] measures the files it is given and
//! files them under the result; no caller supplies a digest. A
//! [`CheckpointStore::measured`] lookup reads the files back and returns
//! their paths only if they still measure to the name of the directory they
//! are in.

use std::fs;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};

use nucleus_weight_patch::{ApplyError, CheckpointDigest, Indexer};

/// Why the store could not hand out, or take in, a checkpoint.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The store cannot be read or written.
    #[error("checkpoint store: {0}")]
    Io(#[from] io::Error),
    /// The store has no checkpoint with this digest.
    #[error("the store has no checkpoint {digest}")]
    Absent {
        /// The digest asked for.
        digest: CheckpointDigest,
    },
    /// The files are not readable as a checkpoint.
    #[error("the files are not a checkpoint: {0}")]
    NotACheckpoint(#[from] ApplyError),
    /// The files filed under a digest no longer measure to it.
    #[error("the files under {filed} measure to {measured}")]
    Mismatch {
        /// The digest they are filed under.
        filed: CheckpointDigest,
        /// What they measure to now.
        measured: CheckpointDigest,
    },
    /// A file has no usable name.
    #[error("a checkpoint file has no file name: {path}")]
    Unnamed {
        /// The path.
        path: String,
    },
}

/// A directory of checkpoints, each under its measured digest.
#[derive(Clone, Debug)]
pub struct CheckpointStore {
    dir: PathBuf,
}

/// The digest of the checkpoint made of `files`, read in the order given.
///
/// # Errors
///
/// [`StoreError`] if a file cannot be read or is not a tensor file.
pub fn measure(files: &[PathBuf]) -> Result<CheckpointDigest, StoreError> {
    let mut indexer = Indexer::start();
    for file in files {
        indexer = indexer.file(BufReader::new(fs::File::open(file)?))?;
    }
    Ok(indexer.finish().digest())
}

impl CheckpointStore {
    /// The store rooted at `dir`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] if the directory cannot be created.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_owned(),
        })
    }

    fn home(&self, digest: CheckpointDigest) -> PathBuf {
        self.dir.join(digest.to_hex())
    }

    /// Measures `files` and files copies of them under the result.
    ///
    /// Putting a checkpoint the store already holds changes nothing.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the files cannot be read as a checkpoint or copied.
    pub fn put(&self, files: &[PathBuf]) -> Result<CheckpointDigest, StoreError> {
        let digest = measure(files)?;
        let home = self.home(digest);
        if home.try_exists()? {
            return Ok(digest);
        }
        // Copy beside the destination and rename, so a reader never finds a
        // directory under a digest with only some of its files.
        let staging = self.dir.join(format!("{}.incoming", digest.to_hex()));
        if staging.try_exists()? {
            fs::remove_dir_all(&staging)?;
        }
        fs::create_dir_all(&staging)?;
        for file in files {
            let Some(name) = file.file_name() else {
                return Err(StoreError::Unnamed {
                    path: file.display().to_string(),
                });
            };
            fs::copy(file, staging.join(name))?;
        }
        fs::rename(&staging, &home)?;
        Ok(digest)
    }

    /// The files of the checkpoint `digest`, after measuring them again.
    ///
    /// # Errors
    ///
    /// [`StoreError::Absent`] if nothing is filed under `digest`;
    /// [`StoreError::Mismatch`] if what is filed there measures differently.
    pub fn measured(&self, digest: CheckpointDigest) -> Result<Vec<PathBuf>, StoreError> {
        let home = self.home(digest);
        let entries = match fs::read_dir(&home) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::Absent { digest });
            }
            Err(e) => return Err(e.into()),
        };
        let mut files = Vec::new();
        for entry in entries {
            files.push(entry?.path());
        }
        files.sort();
        let measured = measure(&files)?;
        if measured != digest {
            return Err(StoreError::Mismatch {
                filed: digest,
                measured,
            });
        }
        Ok(files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_weight_patch::{Dtype, write_checkpoint};

    fn file(dir: &Path, name: &str, value: u8) -> PathBuf {
        let mut bytes = Vec::new();
        write_checkpoint(&[("t", Dtype::U8, &[1], &[value])], &mut bytes).unwrap();
        let path = dir.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn what_is_put_is_handed_back_under_its_measured_digest() {
        let dir = tempfile::tempdir().unwrap();
        let store = CheckpointStore::open(&dir.path().join("store")).unwrap();
        let source = file(dir.path(), "model.bin", 1);
        let digest = store.put(std::slice::from_ref(&source)).unwrap();
        assert_eq!(digest, measure(std::slice::from_ref(&source)).unwrap());
        let files = store.measured(digest).unwrap();
        assert_eq!(measure(&files).unwrap(), digest);
        assert_eq!(
            store.put(&[source]).unwrap(),
            digest,
            "putting twice is the same"
        );
    }

    #[test]
    fn a_digest_nothing_is_filed_under_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let store = CheckpointStore::open(&dir.path().join("store")).unwrap();
        let elsewhere = measure(&[file(dir.path(), "model.bin", 1)]).unwrap();
        assert!(matches!(
            store.measured(elsewhere),
            Err(StoreError::Absent { .. })
        ));
    }

    #[test]
    fn files_changed_after_filing_are_not_handed_out() {
        let dir = tempfile::tempdir().unwrap();
        let store = CheckpointStore::open(&dir.path().join("store")).unwrap();
        let digest = store.put(&[file(dir.path(), "model.bin", 1)]).unwrap();
        let filed = store.measured(digest).unwrap();
        // Replace the filed bytes with another valid checkpoint.
        fs::copy(file(dir.path(), "other.bin", 2), &filed[0]).unwrap();
        assert!(matches!(
            store.measured(digest),
            Err(StoreError::Mismatch { .. })
        ));
    }
}
