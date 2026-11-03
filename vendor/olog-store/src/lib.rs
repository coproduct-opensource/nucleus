//! # olog-store — a durable ordered map
//!
//! ## Why this exists
//!
//! `olog-chase-sql` runs on SQLite, and the mandate is that the olog is the database. But
//! reading what the chase actually asks of its store settles what has to be built: twelve
//! `NOT EXISTS`, seven `INSERT OR IGNORE`, six `COUNT(*)`, two `ORDER BY`, two
//! `DELETE FROM`. No joins beyond the anti-join, no `GROUP BY`, no aggregation, no
//! subquery that is not an existence check.
//!
//! That is not a database. It is a **persistent ordered map**: insert-if-absent, point
//! lookup, ordered scan, range delete, atomic batch. So this crate is that, and nothing
//! more — the SQL was never the point, the B-tree under it was.
//!
//! There is deliberately **no storage-engine dependency**. Swapping SQLite for `redb` or
//! `sled` would be the same category of thing the mandate rules out.
//!
//! ## What durability means here
//!
//! A store that loses data announces nothing: it returns `Ok`, the process exits, and the
//! loss surfaces later in something that assumed the data was there. So the design is
//! arranged so that the failure modes are *representable* rather than silent:
//!
//! * **The log is the truth until a flush.** Every commit appends one length-prefixed,
//!   CRC-checked record and fsyncs. An incomplete tail is trimmed and synced before
//!   accepting writes; a complete invalid record refuses recovery. A batch is one
//!   record, so a batch is all-or-nothing by construction rather than by care.
//!
//! * **The manifest is the only authority on which segments exist.** Segments are written
//!   to a temporary name, fsynced, renamed, and the directory fsynced — and only then is
//!   the manifest rewritten by the same discipline. A crash between those steps leaves a
//!   well-formed segment that no manifest names, and it is ignored. A store that trusted
//!   the directory listing instead would resurrect whatever that segment held, which is
//!   how deleted rows come back from the dead.
//!
//! * **A delete is a tombstone, not an absence.** An older segment still physically holds
//!   the value; only a newer tombstone hides it. Dropping tombstones on flush would
//!   un-delete rows.
//!
//! ## What it is not
//!
//! Not concurrent — one writer, no readers during a write. The chase is a batch pipeline
//! and does not need MVCC, and inventing it unused would be inventing the hard part of a
//! database for nobody.
//!
//! Not authenticated. The store records *what* was written, not *who* wrote it or in
//! what order relative to anything outside it. That is the job of a [`CommitHook`]:
//! `olog-ledger` installs one that appends a hash-chained, attributed record to every
//! batch, inside the same record as the batch, so the store stays dependency-free and the
//! record cannot drift from the data it describes.
//!
//! Not compacting. Segments accumulate, so a key rewritten *n* times costs *n* segments to
//! look past. [`Store::flush`] is explicit for that reason: the caller decides when a
//! segment is worth making. Compaction is the obvious next piece and it is not here.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt;

const SEG_MAGIC: &[u8; 8] = b"OLOGSEG1";
const MANIFEST_MAGIC: &[u8; 8] = b"OLOGMAN1";
/// Keys per sparse-index block. A read binary-searches the index, then scans one block —
/// so resident memory is a function of the index, not of the data.
const BLOCK: usize = 64;

// ── CRC32 (IEEE), table-less ────────────────────────────────────────────────────────
// Forty lines rather than a dependency, in a crate whose whole point is not depending on
// a storage engine.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn u32le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}
fn u64le(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}
fn rd_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
fn rd_u64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// What can go wrong that the caller can do something about.
#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    /// A file exists but is not what it claims to be. Distinguished from `Io` because it
    /// means corruption rather than a missing path, and the two deserve different alarm.
    Corrupt(String),
    /// A [`CommitHook`] refused the batch. Nothing was written.
    Refused(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "io: {e}"),
            StoreError::Corrupt(m) => write!(f, "corrupt: {m}"),
            StoreError::Refused(m) => write!(f, "refused: {m}"),
        }
    }
}
impl std::error::Error for StoreError {}
impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

type Result<T> = std::result::Result<T, StoreError>;

/// A set of writes applied together or not at all.
#[derive(Debug, Default, Clone)]
pub struct Batch {
    ops: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

impl Batch {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn put(&mut self, key: &[u8], value: &[u8]) {
        self.ops.push((key.to_vec(), Some(value.to_vec())));
    }
    pub fn delete(&mut self, key: &[u8]) {
        self.ops.push((key.to_vec(), None));
    }
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
    pub fn len(&self) -> usize {
        self.ops.len()
    }
    /// The writes, in the order they were added. `None` is a delete.
    pub fn ops(&self) -> &[(Vec<u8>, Option<Vec<u8>>)] {
        &self.ops
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.ops.len() * 32);
        out.extend_from_slice(&u32le(self.ops.len() as u32));
        for (k, v) in &self.ops {
            out.extend_from_slice(&u32le(k.len() as u32));
            match v {
                Some(v) => {
                    out.extend_from_slice(&u32le(v.len() as u32));
                    out.extend_from_slice(k);
                    out.extend_from_slice(v);
                }
                // u32::MAX as the value length is the tombstone marker: a length no real
                // value can have, so a tombstone cannot be confused with data.
                None => {
                    out.extend_from_slice(&u32le(u32::MAX));
                    out.extend_from_slice(k);
                }
            }
        }
        out
    }

    fn decode(buf: &[u8]) -> Option<Vec<(Vec<u8>, Option<Vec<u8>>)>> {
        let n = rd_u32(buf, 0)? as usize;
        let mut at = 4;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let klen = rd_u32(buf, at)? as usize;
            let vlen = rd_u32(buf, at + 4)?;
            at += 8;
            let k = buf.get(at..at + klen)?.to_vec();
            at += klen;
            if vlen == u32::MAX {
                out.push((k, None));
            } else {
                let v = buf.get(at..at + vlen as usize)?.to_vec();
                at += vlen as usize;
                out.push((k, Some(v)));
            }
        }
        Some(out)
    }
}

/// An immutable sorted run, read through a sparse index rather than held in memory.
struct Segment {
    id: u64,
    file: File,
    /// First key of each block, and where the block starts.
    index: Vec<(Vec<u8>, u64)>,
    /// Where the entries end and the footer begins.
    data_end: u64,
}

impl Segment {
    fn open(path: &Path, id: u64) -> Result<Self> {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len();
        if len < 20 {
            return Err(StoreError::Corrupt(format!("{} is too short", path.display())));
        }
        let mut tail = vec![0u8; len as usize];
        file.read_exact(&mut tail)?;
        if &tail[len as usize - 8..] != SEG_MAGIC {
            return Err(StoreError::Corrupt(format!(
                "{} has no segment magic — it is not a finished segment",
                path.display()
            )));
        }
        let footer_at = rd_u64(&tail, len as usize - 16)
            .ok_or_else(|| StoreError::Corrupt("footer pointer".into()))?
            as usize;
        let stored_crc = rd_u32(&tail, len as usize - 20)
            .ok_or_else(|| StoreError::Corrupt("footer crc".into()))?;
        if footer_at > len as usize - 20 {
            return Err(StoreError::Corrupt("footer pointer out of range".into()));
        }
        if crc32(&tail[..footer_at]) != stored_crc {
            return Err(StoreError::Corrupt(format!(
                "{} failed its checksum",
                path.display()
            )));
        }
        // Footer: [nblocks:u32] then nblocks × ([klen:u32][key][offset:u64])
        let nblocks = rd_u32(&tail, footer_at)
            .ok_or_else(|| StoreError::Corrupt("block count".into()))? as usize;
        let mut at = footer_at + 4;
        let mut index = Vec::with_capacity(nblocks);
        for _ in 0..nblocks {
            let klen = rd_u32(&tail, at).ok_or_else(|| StoreError::Corrupt("index".into()))? as usize;
            at += 4;
            let key = tail
                .get(at..at + klen)
                .ok_or_else(|| StoreError::Corrupt("index key".into()))?
                .to_vec();
            at += klen;
            let off = rd_u64(&tail, at).ok_or_else(|| StoreError::Corrupt("index off".into()))?;
            at += 8;
            index.push((key, off));
        }
        Ok(Segment {
            id,
            file,
            index,
            data_end: footer_at as u64,
        })
    }

    fn read_block_at(&self, start: u64) -> Result<Vec<(Vec<u8>, Option<Vec<u8>>)>> {
        let end = self
            .index
            .iter()
            .map(|(_, o)| *o)
            .find(|o| *o > start)
            .unwrap_or(self.data_end);
        let mut buf = vec![0u8; (end - start) as usize];
        #[cfg(unix)]
        self.file.read_exact_at(&mut buf, start)?;
        #[cfg(not(unix))]
        {
            use std::io::{Read, Seek, SeekFrom};
            let mut f = &self.file;
            f.seek(SeekFrom::Start(start))?;
            f.read_exact(&mut buf)?;
        }
        let mut out = Vec::new();
        let mut at = 0usize;
        while at < buf.len() {
            let klen = rd_u32(&buf, at).ok_or_else(|| StoreError::Corrupt("entry".into()))? as usize;
            let vlen = rd_u32(&buf, at + 4).ok_or_else(|| StoreError::Corrupt("entry".into()))?;
            at += 8;
            let k = buf
                .get(at..at + klen)
                .ok_or_else(|| StoreError::Corrupt("key".into()))?
                .to_vec();
            at += klen;
            if vlen == u32::MAX {
                out.push((k, None));
            } else {
                let v = buf
                    .get(at..at + vlen as usize)
                    .ok_or_else(|| StoreError::Corrupt("value".into()))?
                    .to_vec();
                at += vlen as usize;
                out.push((k, Some(v)));
            }
        }
        Ok(out)
    }

    /// The block that could contain `key`, if any.
    fn block_for(&self, key: &[u8]) -> Option<u64> {
        match self.index.binary_search_by(|(k, _)| k.as_slice().cmp(key)) {
            Ok(i) => Some(self.index[i].1),
            Err(0) => None, // before the first key of the segment
            Err(i) => Some(self.index[i - 1].1),
        }
    }

    fn get(&self, key: &[u8]) -> Result<Option<Option<Vec<u8>>>> {
        let Some(start) = self.block_for(key) else {
            return Ok(None);
        };
        for (k, v) in self.read_block_at(start)? {
            if k == key {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }

    fn entries(&self) -> Result<Vec<(Vec<u8>, Option<Vec<u8>>)>> {
        let mut out = Vec::new();
        for (_, off) in &self.index {
            out.extend(self.read_block_at(*off)?);
        }
        Ok(out)
    }

    /// Only the entries under `prefix`, reading only the blocks that can hold them.
    ///
    /// The first version of `scan_prefix` called [`Segment::entries`] and filtered, so a
    /// scan of a small delta read every block of every segment — O(corpus) per scan, per
    /// generator, per round. It measured 7.8x slower than SQLite on the chase. The sparse
    /// index already knows which blocks a prefix can touch; not using it was the whole gap.
    fn entries_with_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Option<Vec<u8>>)>> {
        if prefix.is_empty() {
            return self.entries();
        }
        // Blocks whose first key is already past the prefix cannot contain it, and neither
        // can any block after them.
        let start = match self.index.binary_search_by(|(k, _)| k.as_slice().cmp(prefix)) {
            Ok(i) => i,
            Err(0) => 0,
            Err(i) => i - 1,
        };
        let mut out = Vec::new();
        for (first_key, off) in &self.index[start..] {
            if first_key.as_slice() > prefix && !first_key.starts_with(prefix) {
                break;
            }
            for (k, v) in self.read_block_at(*off)? {
                if k.starts_with(prefix) {
                    out.push((k, v));
                }
            }
        }
        Ok(out)
    }
}

/// Encode a sorted run into segment bytes.
fn encode_segment(entries: &[(Vec<u8>, Option<Vec<u8>>)]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut index: Vec<(Vec<u8>, u64)> = Vec::new();
    for (i, (k, v)) in entries.iter().enumerate() {
        if i % BLOCK == 0 {
            index.push((k.clone(), body.len() as u64));
        }
        body.extend_from_slice(&u32le(k.len() as u32));
        match v {
            Some(v) => {
                body.extend_from_slice(&u32le(v.len() as u32));
                body.extend_from_slice(k);
                body.extend_from_slice(v);
            }
            None => {
                body.extend_from_slice(&u32le(u32::MAX));
                body.extend_from_slice(k);
            }
        }
    }
    let footer_at = body.len() as u64;
    let crc = crc32(&body);
    body.extend_from_slice(&u32le(index.len() as u32));
    for (k, off) in &index {
        body.extend_from_slice(&u32le(k.len() as u32));
        body.extend_from_slice(k);
        body.extend_from_slice(&u64le(*off));
    }
    body.extend_from_slice(&u32le(crc));
    body.extend_from_slice(&u64le(footer_at));
    body.extend_from_slice(SEG_MAGIC);
    body
}

/// Helpers the crash tests need to forge on-disk state. Not part of the store's contract.
pub mod testing {
    /// Build well-formed segment bytes, so a test can plant a segment the manifest does
    /// not name and prove it is ignored.
    pub fn encode_segment(entries: &[(Vec<u8>, Option<Vec<u8>>)]) -> Vec<u8> {
        super::encode_segment(entries)
    }
}

/// Atomic file write: temp → fsync → rename → fsync(dir).
///
/// The rename is what makes it atomic; the two fsyncs are what make the rename durable.
/// Omitting the directory fsync is the classic way to have a file that is atomically
/// replaced and then absent after a crash.
///
/// Public because this crate is where the workspace's durability discipline lives, and a
/// caller writing an artifact that must survive a crash — a receipt, say — should reach
/// for this rather than grow a second copy of the same four steps.
pub fn write_atomic_at(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| StoreError::Corrupt(format!("{} has no file name", path.display())))?;
    write_atomic(dir, name, bytes)
}

fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let tmp = dir.join(format!(".{name}.tmp"));
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, dir.join(name))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Runs inside [`Store::commit`], around the write of each non-empty batch.
///
/// `before_commit` sees the batch and may append to it; what it appends is part of the
/// same record, so it is durable exactly when the batch is. Returning an error refuses the
/// commit and nothing is written. Then exactly one of `committed` (the record is durable)
/// or `aborted` (the write failed and was rolled back) is called, so a hook can stage
/// state in `before_commit` and only make it real once the batch is.
pub trait CommitHook: Send {
    fn before_commit(&mut self, batch: &mut Batch) -> std::result::Result<(), String>;
    fn committed(&mut self);
    fn aborted(&mut self);
}

/// A durable ordered map.
pub struct Store {
    dir: PathBuf,
    log: File,
    mem: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    /// Oldest first. A later segment's answer wins.
    segments: Vec<Segment>,
    next_id: u64,
    hook: Option<Box<dyn CommitHook>>,
}

impl Store {
    /// Open or create a store in `dir`.
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;

        // The manifest is the ONLY authority on which segments are live. Anything else on
        // disk is debris from a crash and is not read.
        let ids = Self::read_manifest(dir)?;
        let mut segments = Vec::new();
        for id in &ids {
            let p = dir.join(format!("{id:010}.seg"));
            segments.push(Segment::open(&p, *id)?);
        }
        segments.sort_by_key(|s| s.id);
        let next_id = segments.last().map(|s| s.id + 1).unwrap_or(0);

        let mut mem = BTreeMap::new();
        Self::replay_log(dir, &mut mem)?;

        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("LOG"))?;

        Ok(Store {
            dir: dir.to_path_buf(),
            log,
            mem,
            segments,
            next_id,
            hook: None,
        })
    }

    fn read_manifest(dir: &Path) -> Result<Vec<u64>> {
        let p = dir.join("MANIFEST");
        let bytes = match std::fs::read(&p) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        if bytes.len() < 16 || &bytes[bytes.len() - 8..] != MANIFEST_MAGIC {
            return Err(StoreError::Corrupt("MANIFEST is not a manifest".into()));
        }
        let body = &bytes[..bytes.len() - 12];
        let crc = rd_u32(&bytes, bytes.len() - 12)
            .ok_or_else(|| StoreError::Corrupt("manifest crc".into()))?;
        if crc32(body) != crc {
            return Err(StoreError::Corrupt("MANIFEST failed its checksum".into()));
        }
        let n = rd_u32(body, 0).ok_or_else(|| StoreError::Corrupt("manifest count".into()))? as usize;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            out.push(
                rd_u64(body, 4 + i * 8).ok_or_else(|| StoreError::Corrupt("manifest id".into()))?,
            );
        }
        Ok(out)
    }

    fn write_manifest(&self) -> Result<()> {
        let mut body = Vec::new();
        body.extend_from_slice(&u32le(self.segments.len() as u32));
        for s in &self.segments {
            body.extend_from_slice(&u64le(s.id));
        }
        let crc = crc32(&body);
        body.extend_from_slice(&u32le(crc));
        body.extend_from_slice(MANIFEST_MAGIC);
        write_atomic(&self.dir, "MANIFEST", &body)
    }

    /// Replay the log, repairing an incomplete tail and refusing complete invalid records.
    ///
    /// Never skip a damaged record to reach later records. Repaired tails are synced
    /// before accepting writes so later acknowledged commits survive the next restart.
    fn replay_log(dir: &Path, mem: &mut BTreeMap<Vec<u8>, Option<Vec<u8>>>) -> Result<()> {
        let bytes = match std::fs::read(dir.join("LOG")) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let mut at = 0usize;
        while at + 8 <= bytes.len() {
            let len = match rd_u32(&bytes, at) {
                Some(l) => l as usize,
                None => break,
            };
            let crc = match rd_u32(&bytes, at + 4) {
                Some(c) => c,
                None => break,
            };
            let Some(payload) = bytes.get(at + 8..at + 8 + len) else {
                break; // torn tail: the record never finished reaching the disk
            };
            if crc32(payload) != crc {
                return Err(StoreError::Corrupt("WAL record checksum mismatch".into()));
            }
            let Some(ops) = Batch::decode(payload) else {
                return Err(StoreError::Corrupt("WAL record could not be decoded".into()));
            };
            for (k, v) in ops {
                mem.insert(k, v);
            }
            at += 8 + len;
        }
        // New acknowledged commits must not be appended behind an unreadable
        // torn tail: the next recovery would stop there and lose those commits.
        // Complete but invalid records above are corruption, never repaired.
        if at < bytes.len() {
            let log = OpenOptions::new().write(true).open(dir.join("LOG"))?;
            log.set_len(at as u64)?;
            log.sync_all()?;
        }
        Ok(())
    }

    /// Apply a batch, durably. One record, one fsync: a batch is all-or-nothing because it
    /// is one record, not because anything took care to make it so.
    ///
    /// If the write or the fsync fails, the log is truncated back to where it was, so the
    /// failed record cannot sit in front of later ones. Without that, replay would stop at
    /// the damaged record and silently drop every commit acknowledged after it.
    pub fn commit(&mut self, mut batch: Batch) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        if let Some(hook) = self.hook.as_mut() {
            hook.before_commit(&mut batch).map_err(StoreError::Refused)?;
        }
        let payload = batch.encode();
        let mut rec = Vec::with_capacity(payload.len() + 8);
        rec.extend_from_slice(&u32le(payload.len() as u32));
        rec.extend_from_slice(&u32le(crc32(&payload)));
        rec.extend_from_slice(&payload);
        let written = self.log.metadata().map(|m| m.len()).and_then(|before| {
            self.log.write_all(&rec).and_then(|()| self.log.sync_all()).inspect_err(|_| {
                let _ = self.log.set_len(before).and_then(|()| self.log.sync_all());
            })
        });
        if let Err(e) = written {
            if let Some(hook) = self.hook.as_mut() {
                hook.aborted();
            }
            return Err(e.into());
        }
        for (k, v) in batch.ops {
            self.mem.insert(k, v);
        }
        if let Some(hook) = self.hook.as_mut() {
            hook.committed();
        }
        Ok(())
    }

    /// Install (or with `None`, remove) the hook run around every commit.
    pub fn set_hook(&mut self, hook: Option<Box<dyn CommitHook>>) {
        self.hook = hook;
    }

    /// Turn the memtable into a segment.
    ///
    /// Order matters and is the whole of the crash story: write the segment, make it
    /// durable, name it in the manifest, and only then discard the log that still holds
    /// the same writes. A crash at any point leaves either the log or the segment holding
    /// the data, never neither.
    pub fn flush(&mut self) -> Result<()> {
        if self.mem.is_empty() {
            return Ok(());
        }
        let entries: Vec<(Vec<u8>, Option<Vec<u8>>)> =
            self.mem.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let id = self.next_id;
        let name = format!("{id:010}.seg");
        write_atomic(&self.dir, &name, &encode_segment(&entries))?;

        let seg = Segment::open(&self.dir.join(&name), id)?;
        self.segments.push(seg);
        self.next_id += 1;
        self.write_manifest()?;

        // Only now is the log redundant.
        self.log.set_len(0)?;
        self.log.sync_all()?;
        self.mem.clear();
        Ok(())
    }

    /// The value for `key`, if it has one.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.try_get(key).expect("Olog read failed; refusing an absent/stale answer")
    }

    /// A storage error must not be interpreted as an absent key or older value.
    pub fn try_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(v) = self.mem.get(key) { return Ok(v.clone()); }
        for seg in self.segments.iter().rev() {
            if let Some(v) = seg.get(key)? { return Ok(v); }
        }
        Ok(None)
    }

    pub fn contains(&self, key: &[u8]) -> bool {
        self.try_contains(key).expect("Olog read failed; refusing an absent answer")
    }

    pub fn try_contains(&self, key: &[u8]) -> Result<bool> {
        Ok(self.try_get(key)?.is_some())
    }

    /// Every live key beginning with `prefix`, in order.
    ///
    /// Materialises the range before yielding, because merging N segments lazily needs a
    /// heap of open cursors and the chase scans deltas, which are small by construction.
    /// If a scan of a whole object ever becomes hot, this is the function to make lazy.
    pub fn scan_prefix(&self, prefix: &[u8]) -> impl Iterator<Item = (Vec<u8>, Vec<u8>)> + use<> {
        self.try_scan_prefix(prefix).expect("Olog scan failed; refusing a partial answer").into_iter()
    }

    pub fn try_scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        // FAST PATH: with no segments there is nothing to merge, so the answer is the
        // memtable range itself and the intermediate `BTreeMap` is pure copying. This is
        // the state a batch pipeline is in between flushes, which is most of the time.
        if self.segments.is_empty() {
            let out: Vec<(Vec<u8>, Vec<u8>)> = self
                .mem
                .range(prefix.to_vec()..)
                .take_while(|(k, _)| k.starts_with(prefix))
                .filter_map(|(k, v)| v.as_ref().map(|v| (k.clone(), v.clone())))
                .collect();
            return Ok(out);
        }

        let mut merged: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        for seg in &self.segments {
            for (k, v) in seg.entries_with_prefix(prefix)? {
                merged.insert(k, v);
            }
        }
        // A RANGE, not a filtered iteration. `for (k, v) in &self.mem { if
        // k.starts_with(prefix) }` walks the whole memtable for every scan, which is
        // O(instance) per generator per round — and since a benchmark that never flushes
        // keeps everything in the memtable, it was the entire 7.8x gap against SQLite.
        // Bounding the segment scan by the sparse index first changed nothing, which is
        // what said the segments were not where the time went.
        for (k, v) in self.mem.range(prefix.to_vec()..) {
            if !k.starts_with(prefix) {
                break;
            }
            merged.insert(k.clone(), v.clone());
        }
        Ok(merged
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v)))
            .collect())
    }

    /// How many live keys the store holds. Counts, rather than estimating.
    pub fn len(&self) -> usize {
        self.scan_prefix(b"").count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
