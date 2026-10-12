//! Replay storage behind a [`ProofGate`](crate::ProofGate).
//!
//! Replay protection is only as strong as the store that remembers what was
//! spent: a proof or assertion retired in memory is live again after a
//! restart. The public build therefore ships no ledger at all. Opening a gate
//! here fails with [`Error::NoDurableLedger`] unless a build supplies a durable
//! one, and a configuration that asks for request proofs is refused at startup
//! rather than run with a weaker store.
//!
//! Tests, and the `volatile-test-ledger` feature, supply an in-process ledger so the
//! verifier and its adapters stay tested. It survives a gate being dropped and
//! reopened within one process, which is what the restart tests exercise, and
//! it exists only in debug builds.

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

/// Durable, single-writer key/value storage for spent proofs and assertions.
pub(crate) trait ReplayLedger: Send {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;
    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error>;
    fn is_empty(&self) -> Result<bool, Error>;
    /// Commit `batch` atomically on behalf of `principal`.
    fn commit(&mut self, principal: &str, batch: Batch) -> Result<(), Error>;
}

/// Whether this build can open a replay ledger at all. Callers check it to
/// refuse a request-proof configuration before acting on it, rather than
/// discovering the refusal halfway through.
pub(crate) const AVAILABLE: bool = cfg!(all(
    any(test, feature = "volatile-test-ledger"),
    debug_assertions
));

/// Open the replay ledger at `path`, held by exactly one writer.
#[cfg(not(all(any(test, feature = "volatile-test-ledger"), debug_assertions)))]
pub(crate) fn open(_path: &Path) -> Result<Box<dyn ReplayLedger>, Error> {
    Err(Error::NoDurableLedger)
}

#[cfg(all(any(test, feature = "volatile-test-ledger"), debug_assertions))]
pub(crate) fn open(path: &Path) -> Result<Box<dyn ReplayLedger>, Error> {
    volatile::open(path)
}

#[cfg(all(any(test, feature = "volatile-test-ledger"), debug_assertions))]
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

        fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
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

        fn commit(&mut self, _principal: &str, batch: Batch) -> Result<(), Error> {
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
