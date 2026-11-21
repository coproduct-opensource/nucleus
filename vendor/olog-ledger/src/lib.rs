//! # olog-ledger — who wrote what, recorded inside the store
//!
//! [`olog_store::Store`] records *what* is in a workspace. It does not record who put it
//! there, or in what order, and an audit needs both. This crate adds that without touching
//! how anything reads or writes the store.
//!
//! ## How
//!
//! [`Ledgered`] owns a store and installs a [`CommitHook`] on it. Every batch the store
//! commits (from the chase, an ingest, or a direct write) gets one more entry in the same
//! batch: a [`Record`] holding the workspace, a sequence number, the previous record's
//! hash, the [`Actor`] that made the write, a timestamp, and the batch's own ops. Because
//! the record is in the same batch, it is durable exactly when the data is. A record cannot
//! describe a write that did not happen, and a write cannot land without its record.
//!
//! The record's `hash` is SHA-256 over the RFC 8785 canonical JSON of its other fields,
//! and each record names its parent's hash, so the records form a chain: editing any past
//! record changes every hash after it. Canonical JSON is the encoding `nucleus-receipt`
//! signs, so signing a record later means signing exactly these bytes.
//!
//! ## What is enforced, and where
//!
//! - **Every write is attributed.** The store is private. The only way to get `&mut Store`
//!   is [`Ledgered::write`], which takes an [`Actor`] and makes it the author of every
//!   commit made inside the closure. Chase and ingest code run inside it unchanged.
//! - **The ledger cannot be written around from inside.** A batch that touches the ledger's
//!   own keyspace is refused.
//! - **The chain is checked on open.** Sequence, parent links, workspace and every hash.
//! - **The data is checked on demand.** [`Ledgered::verify`] replays every recorded op
//!   into an empty map and compares it with the store, key by key. A write made by opening
//!   the directory without the ledger shows up there as a divergence. This is the check an
//!   auditor or a restore drill runs.
//! - **One writer.** An exclusive file lock per workspace across processes, and
//!   [`Registry`] hands every caller in a process the same handle.
//!
//! ## Keyspace
//!
//! Everything this crate writes is under `L\0`, a tag no other crate uses:
//!
//! ```text
//!   L \0 c \0 <seq, 20 digits>   -> Record (JSON)
//!   L \0 h                       -> Head   (JSON: next seq, head hash)
//! ```

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use olog_store::{Batch, CommitHook, Store, StoreError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Parent of the first record.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Wire version of [`Record`]. Bump on any change to the hashed fields.
pub const RECORD_VERSION: u32 = 1;

const LEDGER_PREFIX: &[u8] = b"L\0";
const RECORD_PREFIX: &[u8] = b"L\0c\0";
const HEAD_KEY: &[u8] = b"L\0h";

/// Who made a write, and how the server knew.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// The principal that made the write.
    pub principal: String,
    /// How that principal was established: `session`, `api_key`, `svid`, `local`,
    /// `adopt`, ... Recorded so an auditor can tell a verified identity from a local one.
    pub credential: String,
}

/// One write to the store, as recorded. Keys and values are base64.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordOp {
    pub key: String,
    /// `None` is a delete.
    pub value: Option<String>,
}

/// One entry in the ledger: one committed batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub version: u32,
    pub workspace: String,
    pub seq: u64,
    pub parent: String,
    pub actor: Actor,
    pub ts_ms: u64,
    pub ops: Vec<RecordOp>,
    pub hash: String,
}

#[derive(Serialize)]
struct Unhashed<'a> {
    version: u32,
    workspace: &'a str,
    seq: u64,
    parent: &'a str,
    actor: &'a Actor,
    ts_ms: u64,
    ops: &'a [RecordOp],
}

impl Record {
    /// The hash these fields should have.
    pub fn compute_hash(&self) -> String {
        let body = Unhashed {
            version: self.version,
            workspace: &self.workspace,
            seq: self.seq,
            parent: &self.parent,
            actor: &self.actor,
            ts_ms: self.ts_ms,
            ops: &self.ops,
        };
        let bytes = serde_json_canonicalizer::to_vec(&body).expect("records serialize");
        hex::encode(Sha256::digest(bytes))
    }

    /// The ops, decoded back to bytes.
    pub fn decoded_ops(&self) -> Result<Vec<(Vec<u8>, Option<Vec<u8>>)>, LedgerError> {
        self.ops
            .iter()
            .map(|op| {
                let k = B64.decode(&op.key).map_err(|e| corrupt(self.seq, &e.to_string()))?;
                let v = match &op.value {
                    Some(v) => Some(B64.decode(v).map_err(|e| corrupt(self.seq, &e.to_string()))?),
                    None => None,
                };
                Ok((k, v))
            })
            .collect()
    }
}

#[derive(Serialize, Deserialize)]
struct Head {
    next_seq: u64,
    head: String,
}

#[derive(Debug)]
pub enum LedgerError {
    Store(StoreError),
    /// The chain, or the data against the chain, does not verify.
    Corrupt(String),
    /// Another process holds the workspace.
    Locked,
    InvalidWorkspace(String),
    /// [`Ledgered::adopt`] on a workspace that already has records.
    AlreadyLedgered,
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerError::Store(e) => write!(f, "{e}"),
            LedgerError::Corrupt(why) => write!(f, "ledger does not verify: {why}"),
            LedgerError::Locked => write!(f, "workspace is open in another process"),
            LedgerError::InvalidWorkspace(w) => write!(f, "invalid workspace name {w:?}"),
            LedgerError::AlreadyLedgered => write!(f, "workspace already has a ledger"),
        }
    }
}

impl std::error::Error for LedgerError {}

impl From<StoreError> for LedgerError {
    fn from(e: StoreError) -> Self {
        LedgerError::Store(e)
    }
}

impl From<std::io::Error> for LedgerError {
    fn from(e: std::io::Error) -> Self {
        LedgerError::Store(StoreError::Io(e))
    }
}

fn corrupt(seq: u64, why: &str) -> LedgerError {
    LedgerError::Corrupt(format!("record {seq}: {why}"))
}

/// The chain state the hook advances. Shared between [`Ledgered`] and the hook installed
/// in its store.
struct Chain {
    workspace: String,
    next_seq: u64,
    head: String,
    /// The author of commits made right now; `None` outside [`Ledgered::write`].
    actor: Option<Actor>,
    /// The record `before_commit` built, made real by `committed`.
    staged: Option<String>,
}

struct Hook(Arc<Mutex<Chain>>);

impl CommitHook for Hook {
    fn before_commit(&mut self, batch: &mut Batch) -> Result<(), String> {
        let mut chain = self.0.lock().map_err(|_| "ledger lock poisoned".to_string())?;
        let actor = chain
            .actor
            .clone()
            .ok_or("unattributed write: commits go through Ledgered::write")?;
        if batch.ops().iter().any(|(k, _)| k.starts_with(LEDGER_PREFIX)) {
            return Err("a batch may not write the ledger's own keys".into());
        }
        let ops = batch
            .ops()
            .iter()
            .map(|(k, v)| RecordOp { key: B64.encode(k), value: v.as_ref().map(|v| B64.encode(v)) })
            .collect();
        let mut record = Record {
            version: RECORD_VERSION,
            workspace: chain.workspace.clone(),
            seq: chain.next_seq,
            parent: chain.head.clone(),
            actor,
            ts_ms: now_ms(),
            ops,
            hash: String::new(),
        };
        record.hash = record.compute_hash();
        let head = Head { next_seq: record.seq + 1, head: record.hash.clone() };
        batch.put(&record_key(record.seq), &serde_json::to_vec(&record).map_err(|e| e.to_string())?);
        batch.put(HEAD_KEY, &serde_json::to_vec(&head).map_err(|e| e.to_string())?);
        chain.staged = Some(record.hash);
        Ok(())
    }

    fn committed(&mut self) {
        let mut chain = self.0.lock().expect("ledger lock poisoned");
        if let Some(hash) = chain.staged.take() {
            chain.head = hash;
            chain.next_seq += 1;
        }
    }

    fn aborted(&mut self) {
        self.0.lock().expect("ledger lock poisoned").staged = None;
    }
}

/// A workspace's store, with every write attributed and chained.
pub struct Ledgered {
    store: Store,
    chain: Arc<Mutex<Chain>>,
    _lock: File,
}

impl Ledgered {
    /// Open (creating if absent) the workspace under `root`, and verify its chain.
    pub fn open(root: &Path, workspace: &str) -> Result<Ledgered, LedgerError> {
        validate_workspace(workspace)?;
        let dir = root.join(workspace);
        std::fs::create_dir_all(&dir)?;
        let lock = OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("LEDGER.lock"))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(LedgerError::Locked),
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
        let mut store = Store::open(&dir)?;
        let records = read_records(&store)?;
        verify_chain(workspace, &records)?;
        let (next_seq, head) = match records.last() {
            Some(r) => (r.seq + 1, r.hash.clone()),
            None => (0, GENESIS.to_string()),
        };
        match store.try_get(HEAD_KEY)? {
            Some(bytes) => {
                let h: Head = serde_json::from_slice(&bytes)
                    .map_err(|e| LedgerError::Corrupt(format!("head: {e}")))?;
                if h.next_seq != next_seq || h.head != head {
                    return Err(LedgerError::Corrupt("head does not name the last record".into()));
                }
            }
            None if records.is_empty() => {}
            None => return Err(LedgerError::Corrupt("records without a head".into())),
        }
        let chain = Arc::new(Mutex::new(Chain {
            workspace: workspace.to_string(),
            next_seq,
            head,
            actor: None,
            staged: None,
        }));
        store.set_hook(Some(Box::new(Hook(chain.clone()))));
        Ok(Ledgered { store, chain, _lock: lock })
    }

    /// Run `f` with write access to the store. Every commit `f` makes is recorded with
    /// `actor` as its author.
    pub fn write<T, E>(&mut self, actor: Actor, f: impl FnOnce(&mut Store) -> Result<T, E>) -> Result<T, E> {
        struct ClearActor<'a>(&'a Mutex<Chain>);
        impl Drop for ClearActor<'_> {
            fn drop(&mut self) {
                if let Ok(mut c) = self.0.lock() {
                    c.actor = None;
                }
            }
        }
        self.chain.lock().expect("ledger lock poisoned").actor = Some(actor);
        let _clear = ClearActor(&self.chain);
        f(&mut self.store)
    }

    /// Read access to the store.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Hash of the latest record, or [`GENESIS`].
    pub fn head(&self) -> String {
        self.chain.lock().expect("ledger lock poisoned").head.clone()
    }

    /// Number of records.
    pub fn len(&self) -> u64 {
        self.chain.lock().expect("ledger lock poisoned").next_seq
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Record `seq`, read by key (no scan). Its chain position was verified when the
    /// ledger was opened or when it was written.
    pub fn record(&self, seq: u64) -> Result<Option<Record>, LedgerError> {
        match self.store.try_get(&record_key(seq))? {
            Some(v) => serde_json::from_slice(&v).map(Some).map_err(|e| corrupt(seq, &e.to_string())),
            None => Ok(None),
        }
    }

    /// Every record, in order, with the chain re-verified.
    pub fn records(&self) -> Result<Vec<Record>, LedgerError> {
        let records = read_records(&self.store)?;
        let workspace = self.chain.lock().expect("ledger lock poisoned").workspace.clone();
        verify_chain(&workspace, &records)?;
        Ok(records)
    }

    /// Check the data against the ledger: replay every recorded op into an empty map and
    /// compare it, key by key, with what the store holds. Returns the number of live keys
    /// checked.
    pub fn verify(&self) -> Result<usize, LedgerError> {
        let mut replayed: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        for r in self.records()? {
            for (k, v) in r.decoded_ops()? {
                replayed.insert(k, v);
            }
        }
        let mut live = 0usize;
        for (k, v) in self.store.try_scan_prefix(b"")? {
            if k.starts_with(LEDGER_PREFIX) {
                continue;
            }
            match replayed.get(&k) {
                Some(Some(rv)) if *rv == v => live += 1,
                _ => return Err(LedgerError::Corrupt(format!("key {} is not what the ledger recorded", show(&k)))),
            }
        }
        for (k, v) in &replayed {
            if v.is_some() && !self.store.try_contains(k)? {
                return Err(LedgerError::Corrupt(format!("key {} was recorded but is missing", show(k))));
            }
        }
        Ok(live)
    }

    /// Bring a store that predates the ledger under it: one record, authored by `actor`,
    /// whose ops are the store's current contents. Refused if records already exist.
    pub fn adopt(&mut self, actor: Actor) -> Result<(), LedgerError> {
        if !self.is_empty() {
            return Err(LedgerError::AlreadyLedgered);
        }
        let mut batch = Batch::new();
        for (k, v) in self.store.try_scan_prefix(b"")? {
            batch.put(&k, &v);
        }
        if batch.is_empty() {
            return Ok(());
        }
        Ok(self.write(actor, |s| s.commit(batch))?)
    }
}

/// Every workspace under one root, each opened at most once per process, so all callers
/// share one handle and one writer.
pub struct Registry {
    root: PathBuf,
    open: Mutex<HashMap<String, Arc<Mutex<Ledgered>>>>,
}

impl Registry {
    pub fn new(root: impl Into<PathBuf>) -> Registry {
        Registry { root: root.into(), open: Mutex::new(HashMap::new()) }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The shared handle for `workspace`, opening and verifying it on first use.
    pub fn workspace(&self, workspace: &str) -> Result<Arc<Mutex<Ledgered>>, LedgerError> {
        let mut open = self.open.lock().expect("registry lock poisoned");
        if let Some(h) = open.get(workspace) {
            return Ok(h.clone());
        }
        let h = Arc::new(Mutex::new(Ledgered::open(&self.root, workspace)?));
        open.insert(workspace.to_string(), h.clone());
        Ok(h)
    }
}

/// Workspace names become directory names, so they are kept to a path-safe alphabet.
pub fn validate_workspace(w: &str) -> Result<(), LedgerError> {
    let ok = !w.is_empty()
        && w.len() <= 64
        && !w.starts_with('.')
        && w.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if ok { Ok(()) } else { Err(LedgerError::InvalidWorkspace(w.to_string())) }
}

fn record_key(seq: u64) -> Vec<u8> {
    let mut k = RECORD_PREFIX.to_vec();
    k.extend_from_slice(format!("{seq:020}").as_bytes());
    k
}

fn read_records(store: &Store) -> Result<Vec<Record>, LedgerError> {
    store
        .try_scan_prefix(RECORD_PREFIX)?
        .into_iter()
        .enumerate()
        .map(|(i, (_, v))| {
            serde_json::from_slice(&v).map_err(|e| LedgerError::Corrupt(format!("record {i}: {e}")))
        })
        .collect()
}

/// Check that `records` are a whole, untampered chain for `workspace` from its first
/// record: sequence, parent links, workspace and every hash. What an auditor runs on
/// records received from elsewhere.
pub fn verify_records(workspace: &str, records: &[Record]) -> Result<(), LedgerError> {
    verify_chain(workspace, records)
}

fn verify_chain(workspace: &str, records: &[Record]) -> Result<(), LedgerError> {
    let mut parent = GENESIS.to_string();
    for (i, r) in records.iter().enumerate() {
        let i = i as u64;
        if r.version != RECORD_VERSION {
            return Err(corrupt(i, "unknown version"));
        }
        if r.workspace != workspace {
            return Err(corrupt(i, "belongs to another workspace"));
        }
        if r.seq != i {
            return Err(corrupt(i, "out of sequence"));
        }
        if r.parent != parent {
            return Err(corrupt(i, "parent is not the previous record"));
        }
        if r.compute_hash() != r.hash {
            return Err(corrupt(i, "hash does not match contents"));
        }
        parent = r.hash.clone();
    }
    Ok(())
}

fn show(k: &[u8]) -> String {
    String::from_utf8_lossy(k).replace('\0', "\\0")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
