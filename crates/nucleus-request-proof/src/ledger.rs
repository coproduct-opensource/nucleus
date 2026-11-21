//! Replay storage behind a [`ProofGate`](crate::ProofGate).
//!
//! Replay protection is only as strong as the store that remembers what was
//! spent: a proof or assertion retired in memory is live again after a
//! restart. So the ledger is durable: the vendored native Olog store
//! (`vendor/olog-store`, `vendor/olog-ledger`, MIT; see
//! `vendor/OLOG-PROVENANCE.md`), one exclusive writer per directory, every
//! commit recorded with the principal that made it. Its on-disk form is the
//! `request-proof` workspace of an `olog_ledger::Ledgered` at the gate's path.
//!
//! The `volatile-test-ledger` feature supplies an in-process ledger in its
//! place, for the tests of this crate's dependents. It survives a gate being
//! dropped and reopened within one process, not a process restart, and it
//! exists only in debug builds. This crate's own tests use the durable ledger.

use std::path::Path;

use crate::Error;

/// One atomic change to the ledger: every put and delete lands, or none does.
pub(crate) struct Batch {
    pub(crate) puts: Vec<(Vec<u8>, Vec<u8>)>,
    pub(crate) deletes: Vec<Vec<u8>>,
}

impl Batch {
    pub(crate) fn new() -> Self {
        Self {
            puts: Vec::new(),
            deletes: Vec::new(),
        }
    }

    pub(crate) fn put(&mut self, key: &[u8], value: &[u8]) {
        self.puts.push((key.to_vec(), value.to_vec()));
    }

    pub(crate) fn delete(&mut self, key: &[u8]) {
        self.deletes.push(key.to_vec());
    }
}

/// Key/value rows, in key order.
pub(crate) type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// Durable, single-writer key/value storage for spent proofs and assertions.
pub(crate) trait ReplayLedger: Send {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;
    fn scan_prefix(&self, prefix: &[u8]) -> Result<Rows, Error>;
    fn is_empty(&self) -> Result<bool, Error>;
    /// Commit `batch` atomically on behalf of `principal`, which presented
    /// `credential` (recorded with the commit).
    fn commit(&mut self, principal: &str, credential: &str, batch: Batch) -> Result<(), Error>;
}

/// Whether this build can open a replay ledger. Every build can: the durable
/// ledger is part of this crate. Kept so adapters that check it at
/// configuration time need not change.
pub(crate) const AVAILABLE: bool = true;

/// Open the replay ledger at `path`, held by exactly one writer.
#[cfg(not(all(feature = "volatile-test-ledger", debug_assertions)))]
pub(crate) fn open(path: &Path) -> Result<Box<dyn ReplayLedger>, Error> {
    durable::open(path)
}

#[cfg(all(feature = "volatile-test-ledger", debug_assertions))]
pub(crate) fn open(path: &Path) -> Result<Box<dyn ReplayLedger>, Error> {
    volatile::open(path)
}

/// The durable ledger: an Olog `Ledgered` workspace named `request-proof`.
#[cfg(not(all(feature = "volatile-test-ledger", debug_assertions)))]
mod durable {
    use std::path::Path;

    use olog_ledger::{Actor, Ledgered};

    use super::{Batch, ReplayLedger, Rows};
    use crate::Error;

    /// The workspace name, and so the on-disk layout, a gate's directory holds.
    const WORKSPACE: &str = "request-proof";

    pub(super) fn open(path: &Path) -> Result<Box<dyn ReplayLedger>, Error> {
        let db = Ledgered::open(path, WORKSPACE).map_err(|_| Error::Unavailable)?;
        // A ledger whose hash chain does not verify is not trusted to say what
        // was spent.
        db.verify().map_err(|_| Error::Unavailable)?;
        Ok(Box::new(Durable { db }))
    }

    struct Durable {
        db: Ledgered,
    }

    impl ReplayLedger for Durable {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
            self.db.store().try_get(key).map_err(|_| Error::Unavailable)
        }

        fn scan_prefix(&self, prefix: &[u8]) -> Result<Rows, Error> {
            self.db
                .store()
                .try_scan_prefix(prefix)
                .map_err(|_| Error::Unavailable)
        }

        fn is_empty(&self) -> Result<bool, Error> {
            Ok(self.db.is_empty())
        }

        fn commit(&mut self, principal: &str, credential: &str, batch: Batch) -> Result<(), Error> {
            let mut ops = olog_store::Batch::new();
            for key in &batch.deletes {
                ops.delete(key);
            }
            for (key, value) in &batch.puts {
                ops.put(key, value);
            }
            self.db
                .write(
                    Actor {
                        principal: principal.into(),
                        credential: credential.into(),
                    },
                    |s| s.commit(ops),
                )
                .map_err(|_| Error::Unavailable)
        }
    }
}

#[cfg(all(feature = "volatile-test-ledger", debug_assertions))]
mod volatile {
    use std::collections::{BTreeMap, HashMap};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex, OnceLock};

    use super::{Batch, ReplayLedger};
    use crate::Error;

    type Rows = BTreeMap<Vec<u8>, Vec<u8>>;

    struct Slot {
        rows: Arc<Mutex<Rows>>,
        open: bool,
    }

    fn registry() -> &'static Mutex<HashMap<PathBuf, Slot>> {
        static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, Slot>>> = OnceLock::new();
        REGISTRY.get_or_init(Default::default)
    }

    pub(super) fn open(path: &Path) -> Result<Box<dyn ReplayLedger>, Error> {
        let mut registry = registry().lock().map_err(|_| Error::Unavailable)?;
        let slot = registry.entry(path.to_path_buf()).or_insert_with(|| Slot {
            rows: Arc::default(),
            open: false,
        });
        // One writer per path, as the durable store enforces with a lock.
        if slot.open {
            return Err(Error::Unavailable);
        }
        slot.open = true;
        Ok(Box::new(Volatile {
            path: path.to_path_buf(),
            rows: Arc::clone(&slot.rows),
        }))
    }

    struct Volatile {
        path: PathBuf,
        rows: Arc<Mutex<Rows>>,
    }

    impl Drop for Volatile {
        fn drop(&mut self) {
            if let Ok(mut registry) = registry().lock()
                && let Some(slot) = registry.get_mut(&self.path)
            {
                slot.open = false;
            }
        }
    }

    impl ReplayLedger for Volatile {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
            let rows = self.rows.lock().map_err(|_| Error::Unavailable)?;
            Ok(rows.get(key).cloned())
        }

        fn scan_prefix(&self, prefix: &[u8]) -> Result<super::Rows, Error> {
            let rows = self.rows.lock().map_err(|_| Error::Unavailable)?;
            Ok(rows
                .range(prefix.to_vec()..)
                .take_while(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        }

        fn is_empty(&self) -> Result<bool, Error> {
            let rows = self.rows.lock().map_err(|_| Error::Unavailable)?;
            Ok(rows.is_empty())
        }

        fn commit(
            &mut self,
            _principal: &str,
            _credential: &str,
            batch: Batch,
        ) -> Result<(), Error> {
            let mut rows = self.rows.lock().map_err(|_| Error::Unavailable)?;
            for key in batch.deletes {
                rows.remove(&key);
            }
            for (key, value) in batch.puts {
                rows.insert(key, value);
            }
            Ok(())
        }
    }
}

/// The durable ledger writes to disk, not to this process: a fresh Olog handle
/// on the same directory, with no gate and no shared memory, reads what a
/// closed ledger committed and who committed it. The volatile ledger fails
/// this (it writes nothing to the directory).
#[cfg(all(test, not(all(feature = "volatile-test-ledger", debug_assertions))))]
mod durable_tests {
    use super::{Batch, open};

    #[test]
    fn a_closed_ledgers_commits_are_on_disk_with_their_principal() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let mut ledger = open(dir.path()).expect("opens");
            let mut batch = Batch::new();
            batch.put(b"seen/proof/abc", b"123");
            ledger
                .commit("thumb", "verified-request-proof", batch)
                .expect("commits");
            assert!(open(dir.path()).is_err(), "one writer per directory");
        }
        let db = olog_ledger::Ledgered::open(dir.path(), "request-proof").expect("reopens");
        assert_eq!(db.verify().expect("chain verifies"), 1);
        assert_eq!(
            db.store().try_get(b"seen/proof/abc").expect("reads"),
            Some(b"123".to_vec())
        );
        let records = db.records().expect("records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].actor.principal, "thumb");
        assert_eq!(records[0].actor.credential, "verified-request-proof");
    }
}
