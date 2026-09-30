//! Build an ext4 image whose bytes are a function of its content and a seed.
//!
//! This is the one ext4 writer in the crate: [`crate::workspace::seed`] builds
//! through it, and so does an OCI rootfs tar (`nucleus-oci-rootfs`). Both
//! return the digest a spec pins, so an image that differed run to run would be
//! an image nobody could pin in advance.
//!
//! # What plain `mkfs.ext4` leaks into the image
//!
//! - a random filesystem UUID and directory-hash seed (and the metadata
//!   checksum seed derived from the UUID);
//! - the wall clock, in the superblock and in every inode mke2fs creates;
//! - the host's `/etc/mke2fs.conf`, which chooses features and inode ratio;
//! - a size-dependent "usage type" that changes features again;
//! - for `-d <dir>`: host ownership, host mtimes, and readdir order.
//!
//! [`build`] pins each: `-U`/`hash_seed` from [`Ext4Spec::seed`], mke2fs's own
//! fake clock at [`FIXED_EPOCH`], the shipped `mke2fs.conf` via
//! `MKE2FS_CONFIG` with `-T nucleus`, and a cleared environment. Tar input
//! pins the rest, because a tar carries its own ownership, times and order.
//!
//! # Which mke2fs
//!
//! Tar input needs e2fsprogs 1.47.1 or later built with libarchive (it is
//! `dlopen`ed, so the library must also be installed). [`probe`] reads
//! `mke2fs -V` and then actually builds and reads back a one-file tar, because
//! "the version says it should" and "it did" are different answers. The layout
//! algorithm is mke2fs's, so the accepted version range is pinned
//! ([`ACCEPTED`]) and the version that built an image is recorded beside it in
//! `<image>.provenance.json`.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use nucleus_spec::ArtifactDigest;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

pub(crate) mod tree_tar;

/// The mke2fs configuration every image is built under. See the file.
const MKE2FS_CONF: &str = include_str!("ext4/mke2fs.conf");

/// The time every image says it was made, and every seeded entry's mtime:
/// 2000-01-01T00:00:00Z.
///
/// Not zero: e2fsprogs reads `E2FSPROGS_FAKE_TIME=0` as "unset" and falls back
/// to the wall clock, so the epoch itself cannot pin anything.
pub const FIXED_EPOCH: u64 = 946_684_800;

const MIB: u64 = 1024 * 1024;
const BLOCK: u64 = 4096;
const INODE_SIZE: u64 = 256;
/// The journal every image gets. Pinned because mke2fs's default is a step
/// function of image size, so content growth would change the layout twice.
const JOURNAL_MIB: u64 = 16;
/// ext4 reserves inodes 1–10 and mke2fs makes `lost+found` at 11.
const RESERVED_INODES: u64 = 16;
/// Superblock, group descriptors, reserved GDT for resize, bitmaps: a fixed
/// floor, before the proportional allowance in [`layout`].
const FIXED_OVERHEAD_BLOCKS: u64 = 2048;
/// mke2fs refuses a journal larger than half the filesystem ("Total journal
/// size too big for filesystem"), so the smallest image is twice the journal
/// plus the fixed overhead.
const MIN_BLOCKS: u64 = 2 * (JOURNAL_MIB * MIB / BLOCK) + FIXED_OVERHEAD_BLOCKS;

/// The e2fsprogs releases whose layout this module is pinned to: 1.47.1
/// (the first with tar input) through the last 1.47.x.
pub const ACCEPTED: VersionRange = VersionRange {
    min: Mke2fsVersion {
        major: 1,
        minor: 47,
        patch: 1,
    },
    below: Mke2fsVersion {
        major: 1,
        minor: 48,
        patch: 0,
    },
};

/// What an image is built from.
#[derive(Debug, Clone, Copy)]
pub enum Ext4Input<'a> {
    /// A tar whose headers carry every entry's owner, mode and time; mke2fs
    /// takes them as written. This is the deterministic input.
    Tar(&'a Path),
    /// A directory, copied as the host sees it: its entries' ownership and
    /// mtimes go into the image verbatim. The image is determined by the tree's
    /// metadata as well as its content — two checkouts of the same commit are
    /// different directories. [`crate::workspace::seed`] therefore does NOT use
    /// this; it normalizes the tree into a tar first.
    Dir(&'a Path),
}

impl Ext4Input<'_> {
    fn path(&self) -> &Path {
        match self {
            Ext4Input::Tar(p) | Ext4Input::Dir(p) => p,
        }
    }

    fn kind(&self) -> InputKind {
        match self {
            Ext4Input::Tar(_) => InputKind::Tar,
            Ext4Input::Dir(_) => InputKind::Dir,
        }
    }
}

/// [`Ext4Input`] without its path, for the record and the refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    Tar,
    Dir,
}

/// Who owns the image's root directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RootOwner {
    pub uid: u32,
    pub gid: u32,
}

/// Everything besides content that decides an image's bytes.
///
/// No `Default`: a zero seed would make every caller's images share a UUID, and
/// a default owner would be root (B-1).
#[derive(Debug, Clone, Copy)]
pub struct Ext4Spec {
    /// Where the filesystem UUID and directory-hash seed come from. Use a
    /// digest of the content (the seed tar's, the OCI rootfs's), so the same
    /// content gives the same image and different content a different UUID.
    pub seed: [u8; 32],
    /// The root directory's owner (`-E root_owner`).
    pub owner: RootOwner,
    /// Free space beyond what the content needs, in MiB.
    pub extra_mib: u32,
    /// Free inodes beyond what the content needs.
    pub extra_inodes: u32,
}

/// An e2fsprogs release number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Mke2fsVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl std::fmt::Display for Mke2fsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Mke2fsVersion {
    /// Parse `1.47.2` (a trailing `-rc1`/`~wip` on the last part is ignored).
    fn parse(s: &str) -> Option<Self> {
        let mut parts = s.split('.');
        let mut next = || -> Option<u16> {
            let part = parts.next()?;
            let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        };
        let v = Mke2fsVersion {
            major: next()?,
            minor: next()?,
            patch: next().unwrap_or(0),
        };
        Some(v)
    }
}

/// A half-open range of versions, `min <= v < below`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRange {
    pub min: Mke2fsVersion,
    pub below: Mke2fsVersion,
}

impl VersionRange {
    pub fn contains(&self, v: Mke2fsVersion) -> bool {
        self.min <= v && v < self.below
    }
}

impl std::fmt::Display for VersionRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, ">= {}, < {}", self.min, self.below)
    }
}

/// What this host's mke2fs can build. Four answers, because "not installed",
/// "installed but not a release we are pinned to" and "pinned but cannot read a
/// tar" each need a different remedy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mke2fsSupport {
    /// No usable mke2fs, or its version could not be read.
    Absent { reason: String },
    /// A release outside [`ACCEPTED`]; nothing is built with it.
    Unpinned { version: Mke2fsVersion },
    /// A pinned release that failed the tar smoke build (no libarchive, most
    /// likely). Directory input only.
    DirOnly {
        version: Mke2fsVersion,
        tar_refused: String,
    },
    /// A pinned release that built and read back a tar.
    DirAndTar { version: Mke2fsVersion },
}

impl Mke2fsSupport {
    /// The version to build `kind` with, or why this host cannot.
    pub fn admit(&self, kind: InputKind) -> Result<Mke2fsVersion, Ext4Error> {
        match (self, kind) {
            (Mke2fsSupport::DirAndTar { version }, InputKind::Tar | InputKind::Dir)
            | (Mke2fsSupport::DirOnly { version, .. }, InputKind::Dir) => Ok(*version),
            (
                Mke2fsSupport::DirOnly { .. }
                | Mke2fsSupport::Unpinned { .. }
                | Mke2fsSupport::Absent { .. },
                _,
            ) => Err(Ext4Error::Unsupported {
                input: kind,
                support: self.clone(),
            }),
        }
    }
}

impl std::fmt::Display for Mke2fsSupport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mke2fsSupport::Absent { reason } => write!(f, "no usable mke2fs ({reason})"),
            Mke2fsSupport::Unpinned { version } => write!(
                f,
                "mke2fs {version} is outside the pinned range {ACCEPTED}; install e2fsprogs in \
                 that range (Debian trixie ships 1.47.2; bookworm and Ubuntu 24.04 ship 1.47.0)"
            ),
            Mke2fsSupport::DirOnly {
                version,
                tar_refused,
            } => write!(
                f,
                "mke2fs {version} cannot build from a tar ({tar_refused}); install libarchive \
                 (libarchive13) or an e2fsprogs built with it"
            ),
            Mke2fsSupport::DirAndTar { version } => {
                write!(f, "mke2fs {version}, directory and tar input")
            }
        }
    }
}

/// Why an image was not built.
#[derive(Debug)]
pub enum Ext4Error {
    /// This host's mke2fs cannot build this input. Carries the probe's answer.
    Unsupported {
        input: InputKind,
        support: Mke2fsSupport,
    },
    /// The input is not what its variant says, or the output already exists.
    Refused(String),
    /// An entry that has no faithful ext4 image in a workspace.
    Unrepresentable { path: PathBuf, what: String },
    /// The content's size does not fit the arithmetic, or its inode count
    /// does not fit ext4's 32 bits.
    TooLarge(String),
    /// I/O around mke2fs.
    Io(String),
    /// mke2fs ran and failed.
    Failed(String),
}

impl std::fmt::Display for Ext4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ext4Error::Unsupported { input, support } => {
                write!(
                    f,
                    "cannot build an ext4 image from {input:?} input: {support}"
                )
            }
            Ext4Error::Refused(why) => write!(f, "refusing to build: {why}"),
            Ext4Error::Unrepresentable { path, what } => {
                write!(f, "{} cannot go into the image: {what}", path.display())
            }
            Ext4Error::TooLarge(what) => write!(f, "too large: {what}"),
            Ext4Error::Io(e) => write!(f, "building the ext4 image: {e}"),
            Ext4Error::Failed(e) => write!(f, "mke2fs failed: {e}"),
        }
    }
}

impl std::error::Error for Ext4Error {}

/// Ask this host's mke2fs what it can build.
///
/// Runs `mke2fs -V`, and for a pinned release builds a one-file tar into an
/// image and reads the file back with `debugfs`. Only a successful read-back
/// is [`Mke2fsSupport::DirAndTar`].
pub fn probe() -> Mke2fsSupport {
    let out = match Command::new("mke2fs").arg("-V").output() {
        Ok(out) => out,
        Err(e) => {
            return Mke2fsSupport::Absent {
                reason: format!("running mke2fs -V: {e}"),
            };
        }
    };
    // mke2fs prints its banner on stderr.
    let banner = String::from_utf8_lossy(&out.stderr);
    let version = match parse_banner(&banner) {
        Ok(v) => v,
        Err(reason) => return Mke2fsSupport::Absent { reason },
    };
    if !ACCEPTED.contains(version) {
        return Mke2fsSupport::Unpinned { version };
    }
    match tar_smoke() {
        Ok(()) => Mke2fsSupport::DirAndTar { version },
        Err(tar_refused) => Mke2fsSupport::DirOnly {
            version,
            tar_refused,
        },
    }
}

/// The version from `mke2fs -V`, which must agree with the library's: the
/// binary parses flags, the library lays out the filesystem, and a mismatch
/// means the pin describes neither.
fn parse_banner(banner: &str) -> Result<Mke2fsVersion, String> {
    let field = |prefix: &str| {
        banner.lines().find_map(|l| {
            l.trim()
                .strip_prefix(prefix)
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(Mke2fsVersion::parse)
        })
    };
    let binary = field("mke2fs ").ok_or_else(|| format!("unrecognised banner {banner:?}"))?;
    match field("Using EXT2FS Library version ") {
        Some(lib) if lib == binary => Ok(binary),
        Some(lib) => Err(format!("mke2fs {binary} is linked against libext2fs {lib}")),
        None => Err(format!("no library version in banner {banner:?}")),
    }
}

/// Build a one-file tar into an image and read the file back.
fn tar_smoke() -> Result<(), String> {
    const PAYLOAD: &[u8] = b"nucleus ext4 tar probe\n";
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let tree = dir.path().join("tree");
    std::fs::create_dir(&tree).map_err(|e| format!("tree: {e}"))?;
    std::fs::write(tree.join("probe"), PAYLOAD).map_err(|e| format!("file: {e}"))?;
    let owner = RootOwner { uid: 0, gid: 0 };
    let entries = tree_tar::walk(&tree).map_err(|e| e.to_string())?;
    let tar = dir.path().join("probe.tar");
    let file = std::fs::File::create(&tar).map_err(|e| format!("tar: {e}"))?;
    tree_tar::emit(&tree, &entries, owner, file).map_err(|e| e.to_string())?;
    let image = dir.path().join("probe.ext4");
    let spec = Ext4Spec {
        seed: [0; 32],
        owner,
        extra_mib: 0,
        extra_inodes: 0,
    };
    let content = Content::of_entries(&entries).map_err(|e| e.to_string())?;
    let layout = layout(&content, &spec).map_err(|e| e.to_string())?;
    make_image(Ext4Input::Tar(&tar), &image, &layout, &spec).map_err(|e| e.to_string())?;
    let cat = Command::new("debugfs")
        .args(["-R", "cat /probe"])
        .arg(&image)
        .output()
        .map_err(|e| format!("running debugfs: {e}"))?;
    if cat.stdout == PAYLOAD {
        Ok(())
    } else {
        Err(format!(
            "mke2fs accepted the tar but the file did not arrive ({})",
            String::from_utf8_lossy(&cat.stderr).trim()
        ))
    }
}

/// How much an input needs, before free space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Content {
    inodes: u64,
    data_blocks: u64,
    dirent_bytes: u64,
}

/// One entry's contribution to [`Content`].
enum Shape {
    Dir,
    File {
        size: u64,
    },
    Symlink {
        target_len: u64,
    },
    /// A tar hard link: a name for an inode another entry made.
    HardLink,
    /// A FIFO or device node from a tar: an inode and nothing else.
    Special,
}

fn overflow(what: &str) -> Ext4Error {
    Ext4Error::TooLarge(format!("{what} overflows u64"))
}

impl Content {
    const EMPTY: Content = Content {
        inodes: 0,
        data_blocks: 0,
        dirent_bytes: 0,
    };

    fn add(&mut self, name_len: u64, shape: Shape) -> Result<(), Ext4Error> {
        let (inodes, blocks) = match shape {
            Shape::Dir => (1, 1),
            // One extent maps at most 128 MiB; past four, the extent tree needs
            // index blocks. One per 128 MiB over-counts, safely.
            Shape::File { size } => (
                1,
                size.div_ceil(BLOCK)
                    .checked_add(size / (128 * MIB))
                    .ok_or_else(|| overflow("file blocks"))?,
            ),
            // Up to 59 bytes live in the inode ("fast" symlink).
            Shape::Symlink { target_len } => (1, u64::from(target_len > 59)),
            Shape::HardLink => (0, 0),
            Shape::Special => (1, 0),
        };
        // A directory entry is 8 bytes of header and the name, 4-aligned.
        let dirent = name_len
            .checked_add(8 + 3)
            .map(|n| n & !3)
            .ok_or_else(|| overflow("dirent"))?;
        self.inodes = self
            .inodes
            .checked_add(inodes)
            .ok_or_else(|| overflow("inodes"))?;
        self.data_blocks = self
            .data_blocks
            .checked_add(blocks)
            .ok_or_else(|| overflow("blocks"))?;
        self.dirent_bytes = self
            .dirent_bytes
            .checked_add(dirent)
            .ok_or_else(|| overflow("dirents"))?;
        Ok(())
    }

    pub(crate) fn of_entries(entries: &[tree_tar::Entry]) -> Result<Content, Ext4Error> {
        let mut c = Content::EMPTY;
        for e in entries {
            let name_len = e
                .rel
                .file_name()
                .map_or(0, |n| u64::try_from(n.len()).unwrap_or(u64::MAX));
            let shape = match &e.kind {
                tree_tar::Kind::Dir => Shape::Dir,
                tree_tar::Kind::File { size } => Shape::File { size: *size },
                tree_tar::Kind::Symlink { target } => Shape::Symlink {
                    target_len: u64::try_from(target.as_os_str().len()).unwrap_or(u64::MAX),
                },
            };
            c.add(name_len, shape)?;
        }
        Ok(c)
    }

    fn of_tar(tar: &Path) -> Result<Content, Ext4Error> {
        let io = |e: std::io::Error| Ext4Error::Io(format!("reading {}: {e}", tar.display()));
        let file = std::fs::File::open(tar).map_err(io)?;
        let mut archive = tar::Archive::new(std::io::BufReader::new(file));
        let mut c = Content::EMPTY;
        for entry in archive.entries().map_err(io)? {
            let entry = entry.map_err(io)?;
            let path = entry.path().map_err(io)?;
            let name_len = path
                .file_name()
                .map_or(0, |n| u64::try_from(n.len()).unwrap_or(u64::MAX));
            let header = entry.header();
            let shape = match header.entry_type() {
                tar::EntryType::Directory => Shape::Dir,
                tar::EntryType::Regular | tar::EntryType::Continuous => Shape::File {
                    size: header.size().map_err(io)?,
                },
                tar::EntryType::Symlink => Shape::Symlink {
                    target_len: entry
                        .link_name_bytes()
                        .map_or(0, |t| u64::try_from(t.len()).unwrap_or(u64::MAX)),
                },
                tar::EntryType::Link => Shape::HardLink,
                tar::EntryType::Fifo | tar::EntryType::Char | tar::EntryType::Block => {
                    Shape::Special
                }
                // Metadata records (long names, pax) are consumed by the reader
                // and never reach here; anything else is a kind mke2fs would
                // have to guess at, so it is refused by name (B-3).
                other => {
                    return Err(Ext4Error::Unrepresentable {
                        path: path.into_owned(),
                        what: format!("tar entry type {other:?}"),
                    });
                }
            };
            c.add(name_len, shape)?;
        }
        Ok(c)
    }
}

/// The two numbers mke2fs is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct Layout {
    bytes: u64,
    inodes: u32,
}

/// Size and inode count for `content` plus the spec's free space: every block
/// the content, its directories, the inode table and the journal need, a
/// sixteenth more for group metadata, rounded up to a MiB, then `extra_mib`.
fn layout(content: &Content, spec: &Ext4Spec) -> Result<Layout, Ext4Error> {
    let inodes = content
        .inodes
        .checked_add(RESERVED_INODES)
        .and_then(|n| n.checked_add(u64::from(spec.extra_inodes)))
        .ok_or_else(|| overflow("inode count"))?;
    let inodes = u32::try_from(inodes)
        .map_err(|_| Ext4Error::TooLarge(format!("{inodes} inodes exceed ext4's 2^32")))?;
    let itable_blocks = u64::from(inodes)
        .checked_mul(INODE_SIZE)
        .ok_or_else(|| overflow("inode table"))?
        .div_ceil(BLOCK);
    let blocks = [
        content.dirent_bytes.div_ceil(BLOCK),
        itable_blocks,
        JOURNAL_MIB * MIB / BLOCK,
        FIXED_OVERHEAD_BLOCKS,
    ]
    .into_iter()
    .try_fold(content.data_blocks, u64::checked_add)
    .ok_or_else(|| overflow("blocks"))?;
    let blocks = blocks
        .checked_add(blocks / 16)
        .ok_or_else(|| overflow("blocks"))?
        .max(MIN_BLOCKS);
    let bytes = blocks
        .checked_mul(BLOCK)
        .map(|b| b.div_ceil(MIB))
        .and_then(|mib| mib.checked_add(u64::from(spec.extra_mib)))
        .and_then(|mib| mib.checked_mul(MIB))
        .ok_or_else(|| overflow("image size"))?;
    Ok(Layout { bytes, inodes })
}

/// The filesystem UUID (and directory-hash seed) for `seed`: the first 16
/// bytes of `sha256("nucleus-ext4-uuid-v1\0" || seed)`, marked as an RFC 9562
/// version-8 (custom) UUID so tools that check the variant accept it.
pub fn uuid_for(seed: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"nucleus-ext4-uuid-v1\0");
    h.update(seed);
    let d: [u8; 32] = h.finalize().into();
    let [
        a0,
        a1,
        a2,
        a3,
        a4,
        a5,
        a6,
        a7,
        a8,
        a9,
        a10,
        a11,
        a12,
        a13,
        a14,
        a15,
        ..,
    ] = d;
    let a6 = (a6 & 0x0f) | 0x80;
    let a8 = (a8 & 0x3f) | 0x80;
    format!(
        "{a0:02x}{a1:02x}{a2:02x}{a3:02x}-{a4:02x}{a5:02x}-{a6:02x}{a7:02x}-{a8:02x}{a9:02x}-\
         {a10:02x}{a11:02x}{a12:02x}{a13:02x}{a14:02x}{a15:02x}"
    )
}

/// What `<image>.provenance.json` records: everything besides the input that
/// decided the image's bytes. The image's digest is not restated here; it is
/// the file's, measured by whoever needs it (F-3).
#[derive(Serialize)]
struct Provenance<'a> {
    mke2fs: Mke2fsVersion,
    accepted: String,
    config_sha256: String,
    input: InputKind,
    uuid: &'a str,
    fixed_epoch: u64,
    owner: RootOwner,
    layout: Layout,
}

/// Where [`build`] records how `image` was made.
pub fn provenance_path(image: &Path) -> PathBuf {
    let mut p = image.as_os_str().to_owned();
    p.push(".provenance.json");
    PathBuf::from(p)
}

/// Build `input` into a new ext4 image at `out` and return its digest, as
/// `image.scratch_digest` / a rootfs pin takes it.
///
/// The bytes of `out` are a function of the input's bytes (tar) or the tree's
/// content and metadata (dir), `spec`, and the mke2fs release; not of the host
/// clock, the host's mke2fs.conf, the environment, or the output path. `out`
/// and its provenance record must not exist: overwriting is never what building
/// an image means, and `out` may be a disk a running pod still has.
pub async fn build(
    input: Ext4Input<'_>,
    out: &Path,
    spec: Ext4Spec,
) -> Result<ArtifactDigest, Ext4Error> {
    let version = probe().admit(input.kind())?;
    let content = match input {
        Ext4Input::Tar(tar) if tar.is_file() => Content::of_tar(tar)?,
        Ext4Input::Dir(dir) if dir.is_dir() => Content::of_entries(&tree_tar::walk(dir)?)?,
        Ext4Input::Tar(p) | Ext4Input::Dir(p) => {
            return Err(Ext4Error::Refused(format!(
                "{} is not a {}",
                p.display(),
                match input.kind() {
                    InputKind::Tar => "file",
                    InputKind::Dir => "directory",
                }
            )));
        }
    };
    let layout = layout(&content, &spec)?;
    let record = provenance_path(out);
    if record.exists() {
        return Err(Ext4Error::Refused(format!("{} exists", record.display())));
    }
    make_image(input, out, &layout, &spec)?;
    let provenance = Provenance {
        mke2fs: version,
        accepted: ACCEPTED.to_string(),
        config_sha256: hex::encode(Sha256::digest(MKE2FS_CONF.as_bytes())),
        input: input.kind(),
        uuid: &uuid_for(&spec.seed),
        fixed_epoch: FIXED_EPOCH,
        owner: spec.owner,
        layout,
    };
    let written = serde_json::to_vec_pretty(&provenance)
        .map_err(|e| Ext4Error::Io(format!("serialising provenance: {e}")))
        .and_then(|json| {
            std::fs::File::create_new(&record)
                .and_then(|mut f| f.write_all(&json).and_then(|()| f.write_all(b"\n")))
                .map_err(|e| Ext4Error::Io(format!("writing {}: {e}", record.display())))
        });
    if let Err(e) = written {
        let _ = std::fs::remove_file(out);
        return Err(e);
    }
    let digest = nucleus_identity::attestation::measure_artifact(out)
        .await
        .map_err(|e| Ext4Error::Io(format!("measuring {}: {e}", out.display())))?;
    ArtifactDigest::parse(&format!("sha-256:{}", hex::encode(digest))).map_err(Ext4Error::Io)
}

/// Create `image` at `layout.bytes` and run mke2fs into it. On failure the
/// image is removed, so a retry is not refused by `create_new`.
fn make_image(
    input: Ext4Input<'_>,
    image: &Path,
    layout: &Layout,
    spec: &Ext4Spec,
) -> Result<(), Ext4Error> {
    let conf_dir = tempfile::tempdir().map_err(|e| Ext4Error::Io(format!("tempdir: {e}")))?;
    let conf = conf_dir.path().join("mke2fs.conf");
    std::fs::write(&conf, MKE2FS_CONF)
        .map_err(|e| Ext4Error::Io(format!("writing {}: {e}", conf.display())))?;

    let file = std::fs::File::create_new(image)
        .map_err(|e| Ext4Error::Refused(format!("cannot create {} ({e})", image.display())))?;
    let sized = file
        .set_len(layout.bytes)
        .map_err(|e| Ext4Error::Io(format!("sizing {}: {e}", image.display())));
    drop(file);
    let result = sized.and_then(|()| run_mke2fs(&conf, input.path(), image, layout, spec));
    if result.is_err() {
        let _ = std::fs::remove_file(image);
    }
    result
}

fn run_mke2fs(
    conf: &Path,
    source: &Path,
    image: &Path,
    layout: &Layout,
    spec: &Ext4Spec,
) -> Result<(), Ext4Error> {
    let uuid = uuid_for(&spec.seed);
    let epoch = FIXED_EPOCH.to_string();
    let mut cmd = Command::new("mke2fs");
    // Nothing from the caller's environment reaches mke2fs: MKE2FS_SYNC,
    // MKE2FS_DEVICE_SECTSIZE, MKE2FS_FIRST_META_BG and friends each change the
    // layout. PATH only, to find the binary.
    cmd.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    cmd.env("LC_ALL", "C")
        .env("MKE2FS_CONFIG", conf)
        // Two names for one clock: 1.47.1+ reads SOURCE_DATE_EPOCH as well as
        // its own E2FSPROGS_FAKE_TIME, and either alone pins the image (each
        // measured: remove one, still identical; remove both, red). Both are
        // set so a release that drops either still builds the same bytes.
        .env("E2FSPROGS_FAKE_TIME", &epoch)
        .env("SOURCE_DATE_EPOCH", &epoch)
        .args(["-q", "-F", "-t", "ext4", "-T", "nucleus"])
        .args(["-b", "4096", "-I", "256", "-m", "0"])
        .arg("-N")
        .arg(layout.inodes.to_string())
        .arg("-J")
        .arg(format!("size={JOURNAL_MIB}"))
        .arg("-U")
        .arg(&uuid)
        .arg("-E")
        .arg(format!(
            "hash_seed={uuid},root_owner={}:{},lazy_itable_init=0,nodiscard",
            spec.owner.uid, spec.owner.gid
        ))
        .arg("-d")
        .arg(source)
        .arg(image);
    match cmd.output() {
        Err(e) => Err(Ext4Error::Io(format!("running mke2fs: {e}"))),
        Ok(o) if !o.status.success() => Err(Ext4Error::Failed(
            String::from_utf8_lossy(&o.stderr).trim().to_string(),
        )),
        Ok(_) => Ok(()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn the_banner_parses_and_must_agree_with_the_library() {
        let v = parse_banner("mke2fs 1.47.2 (1-Jan-2025)\n\tUsing EXT2FS Library version 1.47.2\n")
            .expect("parses");
        assert_eq!(
            v,
            Mke2fsVersion {
                major: 1,
                minor: 47,
                patch: 2
            }
        );
        assert!(
            parse_banner("mke2fs 1.47.2 (1-Jan-2025)\n\tUsing EXT2FS Library version 1.46.5\n")
                .is_err()
        );
        assert!(parse_banner("mke2fs 1.47.2 (1-Jan-2025)\n").is_err());
        assert!(parse_banner("").is_err());
    }

    #[test]
    fn the_pin_admits_only_1_47_1_and_later_1_47() {
        let v = |patch, minor| Mke2fsVersion {
            major: 1,
            minor,
            patch,
        };
        assert!(!ACCEPTED.contains(v(0, 47)), "1.47.0 has no tar input");
        assert!(ACCEPTED.contains(v(1, 47)));
        assert!(ACCEPTED.contains(v(2, 47)));
        assert!(!ACCEPTED.contains(v(0, 48)));
        assert!(!ACCEPTED.contains(v(5, 46)));
    }

    #[test]
    fn support_admits_each_input_only_where_it_can_build() {
        let version = ACCEPTED.min;
        let both = Mke2fsSupport::DirAndTar { version };
        let dir = Mke2fsSupport::DirOnly {
            version,
            tar_refused: "no libarchive".into(),
        };
        let old = Mke2fsSupport::Unpinned {
            version: Mke2fsVersion {
                major: 1,
                minor: 47,
                patch: 0,
            },
        };
        let none = Mke2fsSupport::Absent {
            reason: "not found".into(),
        };
        assert!(both.admit(InputKind::Tar).is_ok());
        assert!(both.admit(InputKind::Dir).is_ok());
        assert!(dir.admit(InputKind::Dir).is_ok());
        let err = dir.admit(InputKind::Tar).expect_err("refused");
        assert!(err.to_string().contains("libarchive"), "{err}");
        for s in [&old, &none] {
            assert!(s.admit(InputKind::Tar).is_err());
            assert!(s.admit(InputKind::Dir).is_err());
        }
        assert!(
            old.admit(InputKind::Tar)
                .expect_err("refused")
                .to_string()
                .contains("1.47.0 is outside the pinned range >= 1.47.1, < 1.48.0")
        );
    }

    #[test]
    fn the_uuid_is_a_function_of_the_seed_and_a_valid_v8() {
        let a = uuid_for(&[1; 32]);
        assert_eq!(a, uuid_for(&[1; 32]));
        assert_ne!(a, uuid_for(&[2; 32]));
        assert_eq!(a.len(), 36);
        assert_eq!(a.as_bytes()[14], b'8', "version 8: {a}");
        assert!(
            matches!(a.as_bytes()[19], b'8' | b'9' | b'a' | b'b'),
            "RFC variant: {a}"
        );
    }

    #[test]
    fn the_layout_grows_with_content_and_extra() {
        let spec = Ext4Spec {
            seed: [0; 32],
            owner: RootOwner { uid: 1, gid: 1 },
            extra_mib: 0,
            extra_inodes: 0,
        };
        let mut small = Content::EMPTY;
        small.add(4, Shape::File { size: 10 }).expect("add");
        let mut big = small;
        big.add(4, Shape::File { size: 200 * MIB }).expect("add");
        let s = layout(&small, &spec).expect("layout");
        let b = layout(&big, &spec).expect("layout");
        assert!(b.bytes >= (200 + JOURNAL_MIB) * MIB, "{s:?} {b:?}");
        assert_eq!(s.bytes, MIN_BLOCKS * BLOCK, "a small tree gets the floor");
        assert_eq!(s.bytes % MIB, 0, "whole MiB");
        let roomy = layout(
            &small,
            &Ext4Spec {
                extra_mib: 64,
                extra_inodes: 1000,
                ..spec
            },
        )
        .expect("layout");
        assert_eq!(roomy.bytes, s.bytes + 64 * MIB);
        assert_eq!(roomy.inodes, s.inodes + 1000);
        assert!(matches!(
            layout(
                &Content {
                    inodes: u64::from(u32::MAX),
                    ..small
                },
                &spec
            ),
            Err(Ext4Error::TooLarge(_))
        ));
    }

    // ---- end to end: these need e2fsprogs in `ACCEPTED`, with libarchive ----

    const WORKLOAD: RootOwner = RootOwner {
        uid: 65534,
        gid: 65534,
    };

    /// True when this host can run the end-to-end tests; otherwise says why.
    ///
    /// With `NUCLEUS_E2FSPROGS_REQUIRED` set, a host that cannot is a failure
    /// rather than a skip: a skip passes, so on the host that is meant to run
    /// these, a probe that wrongly answered "cannot" would turn every one of
    /// them green without running it. (It did, once: the smoke image was
    /// smaller than twice its journal.)
    pub(crate) fn tar_capable() -> bool {
        match probe() {
            Mke2fsSupport::DirAndTar { .. } => true,
            other if std::env::var_os("NUCLEUS_E2FSPROGS_REQUIRED").is_some() => {
                panic!("NUCLEUS_E2FSPROGS_REQUIRED is set and {other}")
            }
            other => {
                eprintln!("skipping: {other}");
                false
            }
        }
    }

    /// A tree with the shapes that go wrong: nesting, odd modes, a fast and a
    /// slow symlink, a name past ustar's 100 bytes, an empty directory.
    fn sample_tree(root: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let t = root.join("tree");
        let long = "n".repeat(120);
        std::fs::create_dir_all(t.join("src/nested")).expect("dirs");
        std::fs::create_dir_all(t.join("empty")).expect("dirs");
        std::fs::create_dir_all(t.join(&long)).expect("dirs");
        std::fs::write(t.join("README"), b"a workspace\n").expect("file");
        std::fs::write(t.join("src/lib.rs"), b"pub fn f() {}\n").expect("file");
        std::fs::write(t.join("src/nested/data.bin"), vec![0xA5u8; 100_000]).expect("file");
        std::fs::write(t.join(&long).join("inner"), b"deep\n").expect("file");
        std::fs::write(t.join("run.sh"), b"#!/bin/sh\n").expect("file");
        std::fs::set_permissions(t.join("run.sh"), std::fs::Permissions::from_mode(0o750))
            .expect("chmod");
        std::fs::set_permissions(t.join("README"), std::fs::Permissions::from_mode(0o600))
            .expect("chmod");
        // Every mode the tests read back is set here, not left to the umask: a
        // host with umask 002 (Ubuntu's default for a user) made data.bin 0664.
        for (path, mode) in [
            ("src/lib.rs", 0o644),
            ("src/nested/data.bin", 0o644),
            ("empty", 0o755),
        ] {
            std::fs::set_permissions(t.join(path), std::fs::Permissions::from_mode(mode))
                .expect("chmod");
        }
        std::os::unix::fs::symlink("src/lib.rs", t.join("fast")).expect("symlink");
        std::os::unix::fs::symlink("x/".repeat(40), t.join("slow")).expect("symlink");
        t
    }

    /// Tar `tree` as the workload and build it, as a seed does, with the tar's
    /// digest as the spec seed.
    async fn tar_and_build(tree: &Path, image: &Path) -> ArtifactDigest {
        let entries = tree_tar::walk(tree).expect("walk");
        let tar = image.with_extension("tar");
        let file = std::fs::File::create(&tar).expect("tar file");
        let seed = tree_tar::emit(tree, &entries, WORKLOAD, file).expect("emit");
        let spec = Ext4Spec {
            seed,
            owner: WORKLOAD,
            extra_mib: 8,
            extra_inodes: 128,
        };
        build(Ext4Input::Tar(&tar), image, spec)
            .await
            .expect("build")
    }

    fn sha256_of(path: &Path) -> String {
        hex::encode(Sha256::digest(std::fs::read(path).expect("image")))
    }

    /// `(uid, gid, mode)` of `guest` in `image`, from `debugfs stat`.
    pub(crate) fn debugfs_stat(image: &Path, guest: &str) -> (u32, u32, u32) {
        let out = Command::new("debugfs")
            .args(["-R", &format!("stat \"{guest}\"")])
            .arg(image)
            .output()
            .expect("debugfs");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let after = |key: &str| -> String {
            text.split(key)
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
                .unwrap_or_else(|| panic!("no {key:?} for {guest}: {text}"))
                .to_string()
        };
        (
            after("User:").parse().expect("uid"),
            after("Group:").parse().expect("gid"),
            u32::from_str_radix(&after("Mode:"), 8).expect("mode"),
        )
    }

    /// The claim this module exists for. Two trees written at different times
    /// into two different temp dirs (different absolute paths, different
    /// mtimes, possibly different readdir order), tarred and built to two
    /// different output paths more than a second apart on the wall clock:
    /// byte-identical images.
    ///
    /// A-19, measured on e2fsprogs 1.47.2: red with `-U` removed (a random
    /// UUID), and red with both `E2FSPROGS_FAKE_TIME` and `SOURCE_DATE_EPOCH`
    /// removed (the wall clock in the superblock). Removing either clock alone
    /// stays green, because each pins it.
    #[tokio::test]
    async fn two_builds_in_two_places_at_two_times_are_byte_identical() {
        if !tar_capable() {
            return;
        }
        let one = tempfile::tempdir().expect("tempdir");
        let two = tempfile::tempdir().expect("tempdir");
        let t1 = sample_tree(one.path());
        let image1 = one.path().join("first.ext4");
        let d1 = tar_and_build(&t1, &image1).await;

        std::thread::sleep(std::time::Duration::from_millis(1500));
        let t2 = sample_tree(two.path());
        let image2 = two.path().join("elsewhere/second.ext4");
        std::fs::create_dir_all(image2.parent().expect("parent")).expect("dir");
        let d2 = tar_and_build(&t2, &image2).await;

        let (h1, h2) = (sha256_of(&image1), sha256_of(&image2));
        eprintln!("build 1: {h1}\nbuild 2: {h2}");
        assert_eq!(h1, h2, "same content, same spec, different bytes");
        assert_eq!(d1, d2);
        // The digest returned is the node's own measurement of the file.
        assert_eq!(d1.hex(), h1);
        let measured = nucleus_identity::attestation::measure_artifact(&image1)
            .await
            .expect("measure");
        assert_eq!(d1.hex(), hex::encode(measured));

        // The provenance record names the release that built it.
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(provenance_path(&image1)).expect("record"))
                .expect("json");
        let Mke2fsSupport::DirAndTar { version } = probe() else {
            panic!("probed above");
        };
        assert_eq!(record["mke2fs"]["minor"], version.minor);
        assert_eq!(record["mke2fs"]["patch"], version.patch);
        assert_eq!(record["uuid"].as_str().expect("uuid").len(), 36);
    }

    /// Different content must not collide: the determinism above is not the
    /// builder ignoring its input.
    #[tokio::test]
    async fn different_content_is_a_different_image() {
        if !tar_capable() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let t = sample_tree(dir.path());
        let a = tar_and_build(&t, &dir.path().join("a.ext4")).await;
        std::fs::write(t.join("README"), b"a workspace, edited\n").expect("edit");
        let b = tar_and_build(&t, &dir.path().join("b.ext4")).await;
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn debugfs_reads_back_owner_mode_and_symlink_targets() {
        if !tar_capable() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let t = sample_tree(dir.path());
        let image = dir.path().join("ws.ext4");
        tar_and_build(&t, &image).await;

        let want = [
            ("/README", 0o600),
            ("/run.sh", 0o750),
            ("/src/lib.rs", 0o644),
            ("/src/nested/data.bin", 0o644),
            ("/empty", 0o755),
        ];
        let (uid, gid, _) = debugfs_stat(&image, "/");
        assert_eq!((uid, gid), (65534, 65534), "the root");
        for (guest, mode) in want {
            let (uid, gid, got) = debugfs_stat(&image, guest);
            assert_eq!((uid, gid), (65534, 65534), "{guest} owner");
            assert_eq!(got & 0o7777, mode, "{guest} mode {got:o}");
        }
        let long = format!("/{}/inner", "n".repeat(120));
        assert_eq!(debugfs_stat(&image, &long).0, 65534, "a GNU long name");

        let out = dir.path().join("out");
        crate::workspace::harvest(&image, &out).expect("harvest");
        assert_eq!(
            std::fs::read_link(out.join("fast")).expect("fast"),
            Path::new("src/lib.rs")
        );
        assert_eq!(
            std::fs::read_link(out.join("slow")).expect("slow"),
            Path::new(&"x/".repeat(40))
        );
        assert_eq!(
            std::fs::read(out.join("src/nested/data.bin")).expect("data"),
            vec![0xA5u8; 100_000]
        );
    }

    /// Directory input builds too, with the root owned as specified.
    #[tokio::test]
    async fn dir_input_sets_the_root_owner() {
        if !tar_capable() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let t = sample_tree(dir.path());
        let image = dir.path().join("dir.ext4");
        let spec = Ext4Spec {
            seed: [7; 32],
            owner: RootOwner {
                uid: 4242,
                gid: 4343,
            },
            extra_mib: 0,
            extra_inodes: 0,
        };
        build(Ext4Input::Dir(&t), &image, spec)
            .await
            .expect("build");
        let (uid, gid, _) = debugfs_stat(&image, "/");
        assert_eq!((uid, gid), (4242, 4343));
    }

    #[tokio::test]
    async fn build_refuses_a_mislabelled_input_and_an_existing_output() {
        if !tar_capable() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let t = sample_tree(dir.path());
        let spec = Ext4Spec {
            seed: [0; 32],
            owner: WORKLOAD,
            extra_mib: 0,
            extra_inodes: 0,
        };
        let fresh = dir.path().join("fresh.ext4");
        assert!(matches!(
            build(Ext4Input::Tar(&t), &fresh, spec).await,
            Err(Ext4Error::Refused(_))
        ));
        assert!(!fresh.exists());
        let taken = dir.path().join("taken.ext4");
        std::fs::write(&taken, b"a running pod's disk").expect("file");
        assert!(matches!(
            build(Ext4Input::Dir(&t), &taken, spec).await,
            Err(Ext4Error::Refused(_))
        ));
        assert_eq!(
            std::fs::read(&taken).expect("kept"),
            b"a running pod's disk"
        );
    }
}
