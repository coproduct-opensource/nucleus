//! The durable, versioned memory journal (schema v2) and its v1 migration.
//!
//! A journal is one private JSONL file: a header naming the schema and the
//! space, then one [`Commit`] per line. Opening it replays every commit through
//! the chain check ([`Commit::verify`]) and every record through
//! [`ProvenanceMemorySet::verified_admit`]; nothing is trusted from a
//! serialized set. One writer holds an exclusive lock on the file for its
//! lifetime, and checks the path still names the file it locked.
//!
//! - [`PublishedJournal`] is the single writer. [`PublishedJournal::publish`] is
//!   compare-and-swap: it refuses unless the head is the one the caller expects,
//!   validates the whole candidate, and appends one commit with one write that
//!   is flushed and synced before the new head is visible. A failed or
//!   uncertain write latches the journal unavailable until it is reopened.
//! - [`PinnedSnapshot`] reads the journal as of one version. Later commits do not
//!   change what it observes, and a pin whose head does not match is refused.
//! - A v1 journal (`nucleus.memory-journal.v1`: header, then one record per line)
//!   is replayed and verified first, then rewritten as v2 whose version-1 commit
//!   holds every v1 record in admission order — through a staging file, synced,
//!   renamed over the journal, with the parent directory synced. A crash at any
//!   step leaves either the old v1 file or the complete v2 file.
//!
//! The overlay journal a branch writes to is in [`crate::overlay`].

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crdt::ProvenanceMemorySet;
use crate::hash::ContentHash;
use crate::recompute::RecomputeMemory;
use crate::record::MemoryRecord;
use crate::version::{
    Candidate, CandidateRefusal, CandidateValidator, Commit, CommitError, Epoch, Patch, Pin,
    PublisherBinding,
};

/// The most bytes a journal (or overlay) may hold.
pub const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const SCHEMA_V1: &str = "nucleus.memory-journal.v1";
const SCHEMA_V2: &str = "nucleus.memory-journal.v2";
pub(crate) const SCHEMA_OVERLAY: &str = "nucleus.memory-overlay.v2";
const STAGING_SUFFIX: &str = ".v2-staging";

/// Why a journal could not be opened, read or written.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The configured location is unusable.
    #[error("{0}")]
    Location(&'static str),
    /// Someone the caller excludes could reach the journal's storage.
    #[error("{0}")]
    Reachable(String),
    /// An I/O operation failed.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    /// Another writer holds the file.
    #[error("journal is already owned by another writer")]
    Locked,
    /// The path no longer names the file that was opened and locked.
    #[error("journal path no longer names the opened file")]
    Replaced,
    /// The file grants group or other access.
    #[error("journal must be private")]
    NotPrivate,
    /// The file is over the cap or ends in a partial line.
    #[error("journal is oversized or incomplete")]
    Incomplete,
    /// The header names a schema this reader does not know.
    #[error("unknown journal schema {0:?}")]
    UnknownSchema(String),
    /// The header does not parse as the schema it names.
    #[error("journal header is invalid")]
    InvalidHeader,
    /// The header names a different space.
    #[error("journal namespace differs")]
    NamespaceDiffers,
    /// A line does not parse.
    #[error("line {line} is not a valid entry")]
    InvalidLine {
        /// One-based line number (the header is line 1).
        line: usize,
    },
    /// A commit does not follow its predecessor.
    #[error("line {line} breaks the commit chain: {source}")]
    Chain {
        /// One-based line number.
        line: usize,
        /// What is wrong with it.
        source: CommitError,
    },
    /// A record does not re-derive from its cited parents.
    #[error("line {line}: record {} failed provenance replay: {reason}", .hash.to_hex())]
    Replay {
        /// One-based line number.
        line: usize,
        /// The record.
        hash: ContentHash,
        /// The verdict.
        reason: String,
    },
    /// A line restates a record that is already admitted, identically.
    #[error("line {line} restates an admitted record")]
    Restated {
        /// One-based line number.
        line: usize,
    },
    /// The requested version has not been published.
    #[error("version {requested} is not published (head is {head})")]
    VersionAbsent {
        /// The pinned version.
        requested: u64,
        /// The last complete version.
        head: u64,
    },
    /// The journal's head at the pinned version is not the pinned head.
    #[error("version {version} has a different head than the pin")]
    PinMismatch {
        /// The pinned version.
        version: u64,
    },
    /// A pinned reader found a v1 journal; only its writer migrates it.
    #[error("journal is v1; its writer migrates it on open")]
    NotMigrated,
    /// An overlay was reopened over a different base than it was created over.
    #[error("overlay was created over a different base")]
    BaseDiffers,
    /// A previous write did not complete; the file's state is unknown.
    #[error("journal unavailable after an uncertain write")]
    Unavailable,
    /// The write would take the file over [`MAX_JOURNAL_BYTES`].
    #[error("journal capacity exhausted")]
    Capacity,
    /// A record could not be encoded.
    #[error("encoding failed: {0}")]
    Encoding(String),
    /// A staged record does not re-derive from its cited parents.
    #[error("record {} failed provenance admission: {reason}", .hash.to_hex())]
    Admission {
        /// The record.
        hash: ContentHash,
        /// The verdict.
        reason: String,
    },
}

/// Why a publish was refused. Every variant except [`PublishRefusal::Uncertain`]
/// leaves the journal exactly as it was.
#[derive(Debug, thiserror::Error)]
pub enum PublishRefusal {
    /// The head moved. Rebase onto `current` and publish again.
    #[error("stale base: the head is version {}", current.version())]
    StaleBase {
        /// The head now.
        current: Pin,
    },
    /// The patch's base is not a version of this journal.
    #[error("patch base is not a version of this journal")]
    ForeignBase {
        /// The base the patch named.
        base: Pin,
    },
    /// Every record in the patch is already at the head.
    #[error("nothing to publish")]
    NothingToPublish,
    /// The commit could not be sealed.
    #[error("commit: {0}")]
    Commit(CommitError),
    /// The commit could not be encoded.
    #[error("encoding failed: {0}")]
    Encoding(String),
    /// The whole candidate is not a valid next state.
    #[error("invalid candidate: {0}")]
    Invalid(CandidateRefusal),
    /// A record does not re-derive from its cited parents.
    #[error("record {} failed provenance admission: {reason}", .hash.to_hex())]
    Provenance {
        /// The record.
        hash: ContentHash,
        /// The verdict.
        reason: String,
    },
    /// The journal would exceed [`MAX_JOURNAL_BYTES`].
    #[error("journal capacity exhausted")]
    Capacity,
    /// An earlier write was uncertain; the journal is latched.
    #[error("journal unavailable after an uncertain write")]
    Unavailable,
    /// This write failed part-way; the journal is now latched.
    #[error("uncertain write: {0}")]
    Uncertain(std::io::Error),
}

/// A validated journal location: an absolute path in a private, existing
/// parent directory, and the space it holds. Whether the path is inside an
/// agent's workspace is the caller's check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalLocation {
    path: PathBuf,
    parent: PathBuf,
    namespace: String,
}

impl JournalLocation {
    /// Validate `path` and `namespace` (1 to 256 bytes).
    pub fn new(path: &Path, namespace: &str) -> Result<Self, JournalError> {
        if !path.is_absolute() || namespace.is_empty() || namespace.len() > 256 {
            return Err(JournalError::Location(
                "requires an absolute path and a namespace of 1 to 256 bytes",
            ));
        }
        let parent = path
            .parent()
            .ok_or(JournalError::Location("missing parent directory"))?
            .canonicalize()?;
        if parent.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(JournalError::Location(
                "parent directory must not grant group or other access",
            ));
        }
        let name = path
            .file_name()
            .ok_or(JournalError::Location("missing journal filename"))?;
        Ok(Self {
            path: parent.join(name),
            parent,
            namespace: namespace.to_owned(),
        })
    }

    /// The canonical path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The space.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub(crate) fn parent(&self) -> &Path {
        &self.parent
    }

    pub(crate) fn staging_path(&self) -> PathBuf {
        let mut name = OsString::from(self.path.file_name().unwrap_or_default());
        name.push(STAGING_SUFFIX);
        self.parent.join(name)
    }
}

/// Dispatch-only view of a header: which schema it names. The named header is
/// then parsed strictly.
#[derive(Deserialize)]
struct SchemaName {
    schema: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema: String,
    namespace: String,
}

enum Format {
    V1,
    V2,
}

fn header_format(line: &[u8], namespace: &str) -> Result<Format, JournalError> {
    let name: SchemaName = serde_json::from_slice(line).map_err(|_| JournalError::InvalidHeader)?;
    let format = match name.schema.as_str() {
        SCHEMA_V1 => Format::V1,
        SCHEMA_V2 => Format::V2,
        other => {
            return Err(JournalError::UnknownSchema(
                other.chars().take(64).collect(),
            ));
        }
    };
    let header: Header = serde_json::from_slice(line).map_err(|_| JournalError::InvalidHeader)?;
    if header.namespace != namespace {
        return Err(JournalError::NamespaceDiffers);
    }
    Ok(format)
}

pub(crate) fn encode_line<T: Serialize>(value: &T) -> Result<Vec<u8>, JournalError> {
    let mut line = serde_json::to_vec(value).map_err(|e| JournalError::Encoding(e.to_string()))?;
    line.push(b'\n');
    Ok(line)
}

fn header_line(namespace: &str) -> Result<Vec<u8>, JournalError> {
    encode_line(&Header {
        schema: SCHEMA_V2.into(),
        namespace: namespace.into(),
    })
}

/// How [`open_locked`] treats an absent or present file.
pub(crate) enum Create {
    /// The file must not exist yet.
    New,
    /// Create it if absent, open it if present.
    OrOpen,
}

/// What [`open_locked`] found.
pub(crate) enum Opened {
    /// The file was created by this call and is empty.
    Fresh(File),
    /// The file already existed.
    Existing(File),
}

/// Open (or create, mode 0600) a private regular file, take its exclusive lock,
/// and check the path still names the locked file.
#[expect(
    clippy::disallowed_methods,
    reason = "ADR 0007 G-1/H-3: a single-writer journal is owned through its locked handle; each entry is one write_all, flushed and synced before it is published"
)]
pub(crate) fn open_locked(path: &Path, create: Create) -> Result<Opened, JournalError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_file() => {
            return Err(JournalError::Location(
                "journal must be a regular file, not a symlink",
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let fresh = OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(true)
        .mode(0o600)
        .open(path);
    let opened = match (fresh, create) {
        (Ok(file), Create::New | Create::OrOpen) => Opened::Fresh(file),
        (Err(e), Create::OrOpen) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Opened::Existing(OpenOptions::new().read(true).append(true).open(path)?)
        }
        (Err(e), Create::New | Create::OrOpen) => return Err(e.into()),
    };
    let file = match &opened {
        Opened::Fresh(file) | Opened::Existing(file) => file,
    };
    file.try_lock().map_err(|e| match e {
        std::fs::TryLockError::WouldBlock => JournalError::Locked,
        std::fs::TryLockError::Error(e) => JournalError::Io(e),
    })?;
    check_names_file(path, file)?;
    Ok(opened)
}

/// Which part of a journal's storage an owner check is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalPart {
    /// The directory holding the journal: its owner can replace the file.
    Directory,
    /// The journal file itself: its owner can read and append to it.
    File,
}

/// Who besides the writer could reach a journal's storage. Asked about the
/// directory before anything is created in it, and about the opened file (its
/// owner, not the path's) before a byte of it is read. The caller decides; the
/// journal only refuses on its answer.
pub trait ReachCheck {
    /// `Ok` if no one the caller excludes could reach `part`, owned by `owner_uid`.
    fn admit(&self, part: JournalPart, owner_uid: u32) -> Result<(), String>;
}

pub(crate) fn admit_directory(reach: &dyn ReachCheck, dir: &Path) -> Result<(), JournalError> {
    reach
        .admit(JournalPart::Directory, std::fs::metadata(dir)?.uid())
        .map_err(JournalError::Reachable)
}

pub(crate) fn admit_file(reach: &dyn ReachCheck, file: &File) -> Result<(), JournalError> {
    reach
        .admit(JournalPart::File, file.metadata()?.uid())
        .map_err(JournalError::Reachable)
}

/// The path still names `file` (same device and inode, not via a symlink), and
/// the file is private.
pub(crate) fn check_names_file(path: &Path, file: &File) -> Result<(), JournalError> {
    let held = file.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    if held.dev() != named.dev() || held.ino() != named.ino() {
        return Err(JournalError::Replaced);
    }
    if held.permissions().mode() & 0o077 != 0 {
        return Err(JournalError::NotPrivate);
    }
    Ok(())
}

fn over_cap(len: usize) -> bool {
    !u64::try_from(len).is_ok_and(|n| n <= MAX_JOURNAL_BYTES)
}

pub(crate) fn read_capped(file: &File) -> Result<Vec<u8>, JournalError> {
    let mut bytes = Vec::new();
    Read::take(file, MAX_JOURNAL_BYTES + 1).read_to_end(&mut bytes)?;
    if over_cap(bytes.len()) {
        return Err(JournalError::Incomplete);
    }
    Ok(bytes)
}

/// Lines of a file its writer owns: it must end in a newline.
pub(crate) fn complete_lines(bytes: &[u8]) -> Result<Vec<&[u8]>, JournalError> {
    match bytes.split_last() {
        Some((b'\n', body)) => Ok(body.split(|b| *b == b'\n').collect()),
        Some(_) | None => Err(JournalError::Incomplete),
    }
}

/// Lines of a file another process may be appending to: only newline-terminated
/// lines count; a partial tail is not yet written.
fn terminated_lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut lines: Vec<&[u8]> = bytes.split(|b| *b == b'\n').collect();
    lines.pop();
    lines
}

pub(crate) fn sync_dir(dir: &Path) -> Result<(), JournalError> {
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// An exclusively held log file and the uncertain-write latch.
pub(crate) struct LockedLog {
    pub(crate) file: File,
    pub(crate) bytes: u64,
    pub(crate) failed: bool,
}

impl LockedLog {
    pub(crate) fn new(file: File) -> Result<Self, JournalError> {
        let bytes = file.metadata()?.len();
        Ok(Self {
            file,
            bytes,
            failed: false,
        })
    }

    pub(crate) fn available(&self) -> Result<(), JournalError> {
        if self.failed {
            return Err(JournalError::Unavailable);
        }
        Ok(())
    }

    /// Size after appending `len` bytes, if within the cap.
    pub(crate) fn after(&self, len: usize) -> Option<u64> {
        u64::try_from(len)
            .ok()
            .and_then(|len| self.bytes.checked_add(len))
            .filter(|n| *n <= MAX_JOURNAL_BYTES)
    }

    /// One write, flushed and synced. The latch is set before the write and
    /// cleared only after the sync, so a failure (or a panic) leaves it set.
    pub(crate) fn append(&mut self, line: &[u8], next: u64) -> std::io::Result<()> {
        self.failed = true;
        self.file.write_all(line)?;
        self.file.flush()?;
        self.file.sync_all()?;
        self.bytes = next;
        self.failed = false;
        Ok(())
    }
}

pub(crate) fn verdict_reason(verdict: &crate::recompute::RecomputeVerdict) -> String {
    format!("{verdict:?}")
}

/// One published version: its position and the keys its commit added.
#[derive(Debug, Clone)]
struct Published {
    pin: Pin,
    keys: BTreeSet<ContentHash>,
}

/// Why a commit could not be applied to a history.
enum ApplyError {
    Chain(CommitError),
    Restated,
    Admission { hash: ContentHash, reason: String },
}

/// A replayed history: the records at the head and every version's position.
#[derive(Debug, Clone)]
pub(crate) struct History {
    set: ProvenanceMemorySet,
    genesis: Published,
    commits: Vec<Published>,
}

impl History {
    fn genesis(space: &str) -> Self {
        Self {
            set: ProvenanceMemorySet::new(),
            genesis: Published {
                pin: Pin::genesis(space),
                keys: BTreeSet::new(),
            },
            commits: Vec::new(),
        }
    }

    fn head(&self) -> Pin {
        match self.commits.last() {
            Some(last) => last.pin,
            None => self.genesis.pin,
        }
    }

    fn at(&self, version: u64) -> Option<&Published> {
        match version.checked_sub(1) {
            None => Some(&self.genesis),
            Some(index) => usize::try_from(index)
                .ok()
                .and_then(|i| self.commits.get(i)),
        }
    }

    /// Keys added by commits after `version`.
    fn concurrent_since(&self, version: u64) -> BTreeSet<ContentHash> {
        let mut keys = BTreeSet::new();
        for published in &self.commits {
            if published.pin.version() > version {
                keys.extend(published.keys.iter().copied());
            }
        }
        keys
    }

    fn apply(&mut self, commit: &Commit, registry: &dyn RecomputeMemory) -> Result<(), ApplyError> {
        let pin = commit.verify(&self.head()).map_err(ApplyError::Chain)?;
        let mut keys = BTreeSet::new();
        for record in commit.records() {
            let hash = record.content_hash();
            if self.set.get(&hash) == Some(record) {
                return Err(ApplyError::Restated);
            }
            let verdict = self.set.verified_admit(record, registry);
            if !verdict.is_match() {
                return Err(ApplyError::Admission {
                    hash,
                    reason: verdict_reason(&verdict),
                });
            }
            keys.insert(hash);
        }
        self.commits.push(Published { pin, keys });
        Ok(())
    }

    fn replay(
        lines: &[&[u8]],
        space: &str,
        registry: &dyn RecomputeMemory,
        stop_at: Option<u64>,
    ) -> Result<Self, JournalError> {
        let mut history = Self::genesis(space);
        for (index, line) in lines.iter().enumerate() {
            if stop_at.is_some_and(|stop| history.head().version() >= stop) {
                break;
            }
            let number = index + 2;
            let commit: Commit = serde_json::from_slice(line)
                .map_err(|_| JournalError::InvalidLine { line: number })?;
            history.apply(&commit, registry).map_err(|e| match e {
                ApplyError::Chain(source) => JournalError::Chain {
                    line: number,
                    source,
                },
                ApplyError::Restated => JournalError::Restated { line: number },
                ApplyError::Admission { hash, reason } => JournalError::Replay {
                    line: number,
                    hash,
                    reason,
                },
            })?;
        }
        Ok(history)
    }
}

/// Replay a v1 body (one record per line) exactly as the v1 reader did, and
/// return the admitted records in admission order.
fn replay_v1(
    lines: &[&[u8]],
    registry: &dyn RecomputeMemory,
) -> Result<Vec<MemoryRecord>, JournalError> {
    let mut set = ProvenanceMemorySet::new();
    let mut ordered = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let number = index + 2;
        let record: MemoryRecord =
            serde_json::from_slice(line).map_err(|_| JournalError::InvalidLine { line: number })?;
        let hash = record.content_hash();
        let restated = set.get(&hash) == Some(&record);
        let verdict = set.verified_admit(&record, registry);
        if !verdict.is_match() {
            return Err(JournalError::Replay {
                line: number,
                hash,
                reason: verdict_reason(&verdict),
            });
        }
        if !restated {
            ordered.push(record);
        }
    }
    Ok(ordered)
}

/// A step of the v1 -> v2 migration, after which a crash is survivable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStep {
    /// The staging file exists, empty, and is locked.
    StagingCreated,
    /// The v2 bytes are written to the staging file.
    StagingWritten,
    /// The staging file is synced.
    StagingSynced,
    /// The staging file has been renamed over the journal.
    Renamed,
    /// The parent directory is synced.
    ParentSynced,
}

impl MigrationStep {
    /// Every step, in order.
    pub const ALL: [MigrationStep; 5] = [
        MigrationStep::StagingCreated,
        MigrationStep::StagingWritten,
        MigrationStep::StagingSynced,
        MigrationStep::Renamed,
        MigrationStep::ParentSynced,
    ];
}

type Fault<'a> = &'a mut dyn FnMut(MigrationStep) -> std::io::Result<()>;

fn migrate(
    loc: &JournalLocation,
    records: Vec<MemoryRecord>,
    registry: &dyn RecomputeMemory,
    fault: Fault<'_>,
) -> Result<(File, History), JournalError> {
    let staging = loc.staging_path();
    match std::fs::remove_file(&staging) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut file = match open_locked(&staging, Create::New)? {
        Opened::Fresh(file) => file,
        Opened::Existing(_) => return Err(JournalError::Replaced),
    };
    fault(MigrationStep::StagingCreated)?;
    let mut history = History::genesis(loc.namespace());
    let mut body = header_line(loc.namespace())?;
    if !records.is_empty() {
        let commit = Commit::seal(
            history.head(),
            records,
            PublisherBinding::v1_migration(),
            Epoch::PRE_BINDING,
        )
        .map_err(|source| JournalError::Chain { line: 2, source })?;
        history.apply(&commit, registry).map_err(|e| match e {
            ApplyError::Chain(source) => JournalError::Chain { line: 2, source },
            ApplyError::Restated => JournalError::Restated { line: 2 },
            ApplyError::Admission { hash, reason } => JournalError::Replay {
                line: 2,
                hash,
                reason,
            },
        })?;
        body.extend(encode_line(&commit)?);
    }
    if over_cap(body.len()) {
        return Err(JournalError::Capacity);
    }
    file.write_all(&body)?;
    fault(MigrationStep::StagingWritten)?;
    file.sync_all()?;
    fault(MigrationStep::StagingSynced)?;
    std::fs::rename(&staging, loc.path())?;
    fault(MigrationStep::Renamed)?;
    sync_dir(loc.parent())?;
    fault(MigrationStep::ParentSynced)?;
    check_names_file(loc.path(), &file)?;
    Ok((file, history))
}

/// The single writer of a published journal.
pub struct PublishedJournal {
    location: JournalLocation,
    log: LockedLog,
    history: History,
}

impl PublishedJournal {
    /// Open (creating, or migrating a v1 journal) and replay the journal at
    /// `location`, holding its lock until drop. `reach` is asked about the
    /// directory before anything is created and about the file before it is read.
    pub fn open(
        location: JournalLocation,
        reach: &dyn ReachCheck,
        registry: &dyn RecomputeMemory,
    ) -> Result<Self, JournalError> {
        Self::open_with(location, reach, registry, &mut |_| Ok(()))
    }

    pub(crate) fn open_with(
        location: JournalLocation,
        reach: &dyn ReachCheck,
        registry: &dyn RecomputeMemory,
        fault: Fault<'_>,
    ) -> Result<Self, JournalError> {
        admit_directory(reach, location.parent())?;
        let (mut file, history) = match open_locked(location.path(), Create::OrOpen)? {
            Opened::Fresh(file) => {
                // The created file's owner is this process; a child running
                // as it would reach the file as surely as an existing one's.
                admit_file(reach, &file)?;
                (file, None)
            }
            Opened::Existing(file) => {
                admit_file(reach, &file)?;
                let bytes = read_capped(&file)?;
                let lines = complete_lines(&bytes)?;
                let (header, body) = lines.split_first().ok_or(JournalError::Incomplete)?;
                match header_format(header, location.namespace())? {
                    Format::V2 => {
                        let history = History::replay(body, location.namespace(), registry, None)?;
                        (file, Some(history))
                    }
                    Format::V1 => {
                        let records = replay_v1(body, registry)?;
                        let (migrated, history) = migrate(&location, records, registry, fault)?;
                        drop(file);
                        (migrated, Some(history))
                    }
                }
            }
        };
        let history = match history {
            Some(history) => history,
            None => {
                file.write_all(&header_line(location.namespace())?)?;
                file.sync_all()?;
                sync_dir(location.parent())?;
                History::genesis(location.namespace())
            }
        };
        Ok(Self {
            location,
            log: LockedLog::new(file)?,
            history,
        })
    }

    /// The location.
    pub fn location(&self) -> &JournalLocation {
        &self.location
    }

    /// The records at the head, unless a write was uncertain.
    pub fn records(&self) -> Result<&ProvenanceMemorySet, JournalError> {
        self.log.available()?;
        Ok(&self.history.set)
    }

    /// The head, unless a write was uncertain.
    pub fn head(&self) -> Result<Pin, JournalError> {
        self.log.available()?;
        Ok(self.history.head())
    }

    /// Compare-and-swap publish. Refuses unless the head is `expected`; then
    /// validates the whole candidate (the head plus the patch's records that are
    /// not already there) through `validator` and provenance replay, and appends
    /// one commit. Returns the new head.
    pub fn publish(
        &mut self,
        patch: &Patch,
        expected: Pin,
        publisher: PublisherBinding,
        epoch: Epoch,
        validator: &dyn CandidateValidator,
        registry: &dyn RecomputeMemory,
    ) -> Result<Pin, PublishRefusal> {
        if self.log.failed {
            return Err(PublishRefusal::Unavailable);
        }
        let head = self.history.head();
        if expected != head {
            return Err(PublishRefusal::StaleBase { current: head });
        }
        let base = patch.base();
        match self.history.at(base.version()) {
            Some(published) if published.pin == base => {}
            Some(_) | None => return Err(PublishRefusal::ForeignBase { base }),
        }
        let additions: Vec<MemoryRecord> = patch
            .records()
            .iter()
            .filter(|r| self.history.set.get(&r.content_hash()) != Some(*r))
            .cloned()
            .collect();
        if additions.is_empty() {
            return Err(PublishRefusal::NothingToPublish);
        }
        let commit =
            Commit::seal(head, additions, publisher, epoch).map_err(PublishRefusal::Commit)?;
        let line = encode_line(&commit).map_err(|e| PublishRefusal::Encoding(e.to_string()))?;
        let journal_bytes = u64::try_from(line.len())
            .ok()
            .and_then(|len| self.log.bytes.checked_add(len))
            .ok_or(PublishRefusal::Capacity)?;
        let concurrent = self.history.concurrent_since(base.version());
        validator
            .validate(&Candidate {
                head: &self.history.set,
                concurrent: &concurrent,
                patch,
                additions: commit.records(),
                journal_bytes,
            })
            .map_err(PublishRefusal::Invalid)?;
        let next_bytes = self.log.after(line.len()).ok_or(PublishRefusal::Capacity)?;
        let mut next = self.history.clone();
        next.apply(&commit, registry).map_err(|e| match e {
            ApplyError::Chain(source) => PublishRefusal::Commit(source),
            ApplyError::Restated => PublishRefusal::NothingToPublish,
            ApplyError::Admission { hash, reason } => PublishRefusal::Provenance { hash, reason },
        })?;
        self.log
            .append(&line, next_bytes)
            .map_err(PublishRefusal::Uncertain)?;
        self.history = next;
        Ok(commit.head())
    }
}

/// The journal as of one version. Owns its records: later commits cannot change
/// what it observes.
#[derive(Debug, Clone)]
pub struct PinnedSnapshot {
    pin: Pin,
    namespace: String,
    set: ProvenanceMemorySet,
}

impl PinnedSnapshot {
    /// Read the journal at `location` as of `pin`, replaying (and verifying)
    /// every commit up to it. Refuses a version not yet published and a pin whose
    /// head differs from the journal's at that version. Takes no lock: it reads
    /// only complete lines and stops at the pin. `reach` is asked about the
    /// directory and the file before it is read.
    pub fn open(
        location: &JournalLocation,
        pin: Pin,
        reach: &dyn ReachCheck,
        registry: &dyn RecomputeMemory,
    ) -> Result<Self, JournalError> {
        admit_directory(reach, location.parent())?;
        match std::fs::symlink_metadata(location.path()) {
            Ok(meta) if !meta.is_file() => {
                return Err(JournalError::Location(
                    "journal must be a regular file, not a symlink",
                ));
            }
            Ok(_) => {}
            Err(e) => return Err(e.into()),
        }
        let file = File::open(location.path())?;
        check_names_file(location.path(), &file)?;
        admit_file(reach, &file)?;
        let bytes = read_capped(&file)?;
        let lines = terminated_lines(&bytes);
        let (header, body) = lines.split_first().ok_or(JournalError::Incomplete)?;
        match header_format(header, location.namespace())? {
            Format::V2 => {}
            Format::V1 => return Err(JournalError::NotMigrated),
        }
        let history = History::replay(body, location.namespace(), registry, Some(pin.version()))?;
        let reached = history.head();
        if reached.version() < pin.version() {
            return Err(JournalError::VersionAbsent {
                requested: pin.version(),
                head: reached.version(),
            });
        }
        if reached != pin {
            return Err(JournalError::PinMismatch {
                version: pin.version(),
            });
        }
        Ok(Self {
            pin,
            namespace: location.namespace().to_owned(),
            set: history.set,
        })
    }

    /// The version observed.
    pub fn pin(&self) -> Pin {
        self.pin
    }

    /// The space.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The records as of the pin.
    pub fn records(&self) -> &ProvenanceMemorySet {
        &self.set
    }
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
