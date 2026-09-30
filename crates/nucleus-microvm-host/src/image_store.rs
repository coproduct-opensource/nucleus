//! The node's content-addressed image store: where an imported OCI rootfs becomes
//! a file a pod can boot (2026-09-30).
//!
//! ```text
//! <image-root>/
//!   sha256/<rootfs hex>/rootfs.ext4                   the image a pod boots, named by ITS digest
//!   sha256/<rootfs hex>/rootfs.ext4.provenance.json   how `ext4::build` laid it out
//!   sha256/<rootfs hex>/import.json                   a [`StoredImport`]: where it came from
//!   tmp/                                              builds in flight; never read as content
//! ```
//!
//! # Two stages, two digests
//!
//! Stage one (`nucleus image import`, `nucleus-oci-rootfs`) turns a pinned OCI image
//! into one normalized tar and an `ImportRecord`. Stage two, [`build`], runs on the
//! node host: it overlays the runtime's guest layer onto that tar, builds a
//! deterministic ext4 from the result, and files it here under the ext4's own
//! digest — the digest a spec pins as `image.rootfs_digest`.
//!
//! The directory name is therefore the INTEGRITY check's key: the node derives
//! `sha256/<rootfs_digest hex>/rootfs.ext4` from the spec and measures it against
//! the same pin (`image_identity::verify`). `import.json` answers a different
//! question — CONSISTENCY: is the image under that digest the one the spec's
//! `rootfs_oci` says it is? A spec naming image A's reference with image B's
//! digest measures fine (B's bytes are B's digest) and would boot B under A's name.
//! [`StoredImport::check`] is the one place that is refused.
//!
//! # The overlay
//!
//! [`overlay`] copies the user tar's entries byte-for-byte, then appends the
//! guest layer's. A guest entry may only ADD: a guest directory the user tar
//! already has as a directory is dropped (the user's stays), and any other
//! collision is refused, as is a guest entry under a user symlink or file (it
//! would be written through it) or before its parent exists. The flattener
//! already refuses user entries on reserved guest paths; this is the second,
//! independent check at the point where the two trees meet.
//!
//! The ext4 seed is `sha256("nucleus-image-store-seed-v1\0" ‖ manifest digest ‖
//! "\0" ‖ guest layer digest)`: the two inputs that decide the content, so the
//! same image with the same guest layer gives the same bytes on every host.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use nucleus_oci_rootfs::ImportRecord;
use nucleus_spec::{ArtifactDigest, OciRootfs};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::ext4::{self, Ext4Error, Ext4Input, Ext4Spec, Mke2fsVersion, RootOwner};

/// The image store's directory under a node's state dir, when no `--image-root` is given.
pub const IMAGES_DIR: &str = "images";
/// The bootable image in a store entry.
pub const ROOTFS_FILE: &str = "rootfs.ext4";
/// The [`StoredImport`] beside it.
pub const RECORD_FILE: &str = "import.json";
const SHA256_DIR: &str = "sha256";
const TMP_DIR: &str = "tmp";
const BLOCK: u64 = 512;

/// `<root>/sha256/<hex>`: the entry for the image whose ext4 digest is `rootfs_digest`.
pub fn entry_dir(root: &Path, rootfs_digest: &ArtifactDigest) -> PathBuf {
    root.join(SHA256_DIR).join(rootfs_digest.hex())
}

/// `<root>/sha256/<hex>/rootfs.ext4`: the one path an OCI rootfs may boot from.
pub fn rootfs_path(root: &Path, rootfs_digest: &ArtifactDigest) -> PathBuf {
    entry_dir(root, rootfs_digest).join(ROOTFS_FILE)
}

/// The record's format. One variant: a record this build does not understand is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoreFormat {
    #[serde(rename = "nucleus-image-store/v1")]
    V1,
}

/// What `import.json` in a store entry says. The ext4's digest is not restated:
/// it is the directory's name, and the file's own hash (F-3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredImport {
    pub format: StoreFormat,
    /// The flattener's record, as it wrote it: pinned, manifest and config
    /// digests, layers, everything stripped, and the importer's version.
    pub import: ImportRecord,
    /// sha-256 of the guest layer tar overlaid onto the flattened rootfs.
    pub guest_layer_digest: ArtifactDigest,
    /// The e2fsprogs release that laid the ext4 out.
    pub mke2fs: Mke2fsVersion,
    /// `nucleus-microvm-host`'s version, which decided the overlay and the seed.
    pub builder_version: String,
}

/// Which of a spec's `rootfs_oci` fields disagreed with the stored record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciField {
    ReferenceDigest,
    ManifestDigest,
    GuestLayerDigest,
}

impl OciField {
    fn name(self) -> &'static str {
        match self {
            OciField::ReferenceDigest => "reference digest",
            OciField::ManifestDigest => "manifest_digest",
            OciField::GuestLayerDigest => "guest_layer_digest",
        }
    }
}

/// A spec's `rootfs_oci` names a different image than the store entry holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordMismatch {
    pub field: OciField,
    pub spec: String,
    pub stored: String,
}

impl std::fmt::Display for RecordMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the spec's rootfs_oci {} is {} but the image stored under its rootfs_digest was \
             imported with {}; the digest names another image's rootfs",
            self.field.name(),
            self.spec,
            self.stored
        )
    }
}

impl StoredImport {
    /// Refuse unless this entry is the image `oci` names. Every field is compared;
    /// the first difference is reported.
    pub fn check(&self, oci: &OciRootfs) -> Result<(), RecordMismatch> {
        let OciRootfs {
            reference,
            manifest_digest,
            guest_layer_digest,
        } = oci;
        let pairs = [
            (
                OciField::ReferenceDigest,
                reference.digest().as_str().to_owned(),
                self.import.pinned.to_string(),
            ),
            (
                OciField::ManifestDigest,
                manifest_digest.as_str().to_owned(),
                self.import.manifest_digest.to_string(),
            ),
            (
                OciField::GuestLayerDigest,
                guest_layer_digest.as_str().to_owned(),
                self.guest_layer_digest.as_str().to_owned(),
            ),
        ];
        for (field, spec, stored) in pairs {
            if spec != stored {
                return Err(RecordMismatch {
                    field,
                    spec,
                    stored,
                });
            }
        }
        Ok(())
    }

    /// The flattener version that produced the rootfs tar.
    pub fn importer_version(&self) -> &str {
        &self.import.crate_version
    }
}

/// Why a store operation refused or failed.
#[derive(Debug)]
pub enum StoreError {
    Io {
        what: String,
        source: io::Error,
    },
    /// A record did not parse as what it claims to be.
    Record {
        path: PathBuf,
        error: String,
    },
    /// The rootfs tar is not the one its import record describes.
    TarMismatch {
        recorded: String,
        actual: String,
    },
    /// A tar could not be read.
    Tar {
        which: &'static str,
        error: String,
    },
    /// A guest layer entry would replace or reach through a user entry.
    Collision {
        path: String,
        user: &'static str,
    },
    /// A guest layer entry sits under a user file or symlink.
    ThroughNonDirectory {
        path: String,
        ancestor: String,
    },
    /// A guest layer entry arrives before its parent directory.
    MissingParent {
        path: String,
    },
    /// A guest layer entry is a kind the overlay does not carry, or has a bad name.
    Unsupported {
        path: String,
        what: String,
    },
    Ext4(Ext4Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io { what, source } => write!(f, "{what}: {source}"),
            StoreError::Record { path, error } => {
                write!(f, "{} is not an import record: {error}", path.display())
            }
            StoreError::TarMismatch { recorded, actual } => write!(
                f,
                "the rootfs tar hashes to {actual}, but its import record names {recorded}; \
                 re-run `nucleus image import`"
            ),
            StoreError::Tar { which, error } => write!(f, "reading the {which} tar: {error}"),
            StoreError::Collision { path, user } => write!(
                f,
                "the guest layer's {path:?} collides with the image's {user} at the same path; \
                 the runtime's paths are reserved"
            ),
            StoreError::ThroughNonDirectory { path, ancestor } => write!(
                f,
                "the guest layer's {path:?} would be written through the image's {ancestor:?}, \
                 which is not a directory"
            ),
            StoreError::MissingParent { path } => write!(
                f,
                "the guest layer's {path:?} has no parent directory in either tar"
            ),
            StoreError::Unsupported { path, what } => {
                write!(f, "the guest layer's {path:?} cannot be overlaid: {what}")
            }
            StoreError::Ext4(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StoreError {}

fn io_at(what: impl Into<String>) -> impl FnOnce(io::Error) -> StoreError {
    let what = what.into();
    move |source| StoreError::Io { what, source }
}

/// Read a store entry's record.
pub fn read_record(path: &Path) -> Result<StoredImport, StoreError> {
    let bytes = std::fs::read(path).map_err(io_at(format!("reading {}", path.display())))?;
    serde_json::from_slice(&bytes).map_err(|e| StoreError::Record {
        path: path.to_path_buf(),
        error: e.to_string(),
    })
}

/// sha256 of a file's bytes, streamed.
fn hash_file(path: &Path) -> Result<[u8; 32], StoreError> {
    let mut file = File::open(path).map_err(io_at(format!("opening {}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(io_at(format!("reading {}", path.display())))?;
        match buf.get(..n) {
            Some([]) | None => break,
            Some(chunk) => hasher.update(chunk),
        }
    }
    Ok(hasher.finalize().into())
}

/// The ext4 seed for an image: see the module docs.
pub fn seed(import: &ImportRecord, guest_layer: &ArtifactDigest) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"nucleus-image-store-seed-v1\0");
    h.update(import.manifest_digest.to_string().as_bytes());
    h.update(b"\0");
    h.update(guest_layer.as_str().as_bytes());
    h.finalize().into()
}

/// The inputs to stage two.
#[derive(Debug, Clone, Copy)]
pub struct BuildInputs<'a> {
    /// The flattened rootfs tar (`<cache>/rootfs/sha256/<hex>/rootfs.tar`).
    pub rootfs_tar: &'a Path,
    /// Its `import.json`.
    pub import_record: &'a Path,
    /// The runtime's guest layer tar.
    pub guest_layer: &'a Path,
    /// The node's image root.
    pub image_root: &'a Path,
}

/// What stage two filed.
#[derive(Debug)]
pub struct Stored {
    /// `<image-root>/sha256/<hex>`.
    pub dir: PathBuf,
    /// The digest a spec pins as `image.rootfs_digest`.
    pub rootfs_digest: ArtifactDigest,
    pub record: StoredImport,
    /// The entry already existed (same content), and the new build was discarded.
    pub reused: bool,
}

/// Stage two: overlay, build, measure, and atomically file the image. See the module docs.
pub async fn build(inputs: BuildInputs<'_>) -> Result<Stored, StoreError> {
    let BuildInputs {
        rootfs_tar,
        import_record,
        guest_layer,
        image_root,
    } = inputs;
    let raw = std::fs::read(import_record)
        .map_err(io_at(format!("reading {}", import_record.display())))?;
    let import: ImportRecord = serde_json::from_slice(&raw).map_err(|e| StoreError::Record {
        path: import_record.to_path_buf(),
        error: e.to_string(),
    })?;
    let actual = format!("sha256:{}", hex::encode(hash_file(rootfs_tar)?));
    let recorded = import.rootfs.digest.to_string();
    if actual != recorded {
        return Err(StoreError::TarMismatch { recorded, actual });
    }
    let guest_layer_digest =
        ArtifactDigest::parse(&format!("sha-256:{}", hex::encode(hash_file(guest_layer)?)))
            .map_err(|e| StoreError::Io {
                what: "digest".into(),
                source: io::Error::other(e),
            })?;

    let tmp_root = image_root.join(TMP_DIR);
    for dir in [&tmp_root, &image_root.join(SHA256_DIR)] {
        std::fs::create_dir_all(dir).map_err(io_at(format!("creating {}", dir.display())))?;
    }
    let work = tempfile::Builder::new()
        .prefix("build-")
        .tempdir_in(&tmp_root)
        .map_err(io_at(format!(
            "creating a build dir in {}",
            tmp_root.display()
        )))?;
    let merged = work.path().join("merged.tar");
    {
        let out = File::create_new(&merged).map_err(io_at("creating the merged tar"))?;
        overlay(rootfs_tar, guest_layer, out)?;
    }
    let built = ext4::build_recorded(
        Ext4Input::Tar(&merged),
        &work.path().join(ROOTFS_FILE),
        Ext4Spec {
            seed: seed(&import, &guest_layer_digest),
            owner: RootOwner { uid: 0, gid: 0 },
            extra_mib: 0,
            extra_inodes: 0,
        },
    )
    .await
    .map_err(StoreError::Ext4)?;
    std::fs::remove_file(&merged).map_err(io_at("removing the merged tar"))?;
    let record = StoredImport {
        format: StoreFormat::V1,
        import,
        guest_layer_digest,
        mke2fs: built.mke2fs,
        builder_version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    let json = serde_json::to_vec_pretty(&record).map_err(|e| StoreError::Io {
        what: "serialising the record".into(),
        source: io::Error::other(e),
    })?;
    std::fs::write(work.path().join(RECORD_FILE), json).map_err(io_at("writing the record"))?;

    let dir = entry_dir(image_root, &built.digest);
    if dir.exists() {
        // Content-addressed: an entry under this digest already holds these bytes.
        return Ok(Stored {
            dir,
            rootfs_digest: built.digest,
            record,
            reused: true,
        });
    }
    let staged = work.keep();
    if let Err(e) = std::fs::rename(&staged, &dir) {
        let _ = std::fs::remove_dir_all(&staged);
        return Err(io_at(format!("filing {}", dir.display()))(e));
    }
    Ok(Stored {
        dir,
        rootfs_digest: built.digest,
        record,
        reused: false,
    })
}

/// What overlaying kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overlaid {
    /// Guest entries appended.
    pub added: u64,
    /// Guest directories the user tar already had.
    pub shared_dirs: u64,
}

/// How a path already in the merged tree is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    Dir,
    NonDir,
}

/// One entry's byte range (its metadata records, header and padded data) and name.
struct Span {
    start: u64,
    end: u64,
    path: String,
    kind: tar::EntryType,
    /// A hard link's target, normalized; `None` for every other kind (a
    /// symlink's target is the guest's to interpret and is never read here).
    link: Option<String>,
}

fn normalize(raw: &[u8], which: &'static str) -> Result<String, StoreError> {
    let s = std::str::from_utf8(raw).map_err(|_| StoreError::Tar {
        which,
        error: format!("non-UTF-8 name {}", hex::encode(raw)),
    })?;
    let mut s = s;
    while let Some(rest) = s.strip_prefix("./").or_else(|| s.strip_prefix('/')) {
        s = rest;
    }
    let s = s.trim_end_matches('/');
    if s == "." {
        return Ok(String::new());
    }
    if s.split('/').any(|c| c.is_empty() || c == "." || c == "..") && !s.is_empty() {
        return Err(StoreError::Unsupported {
            path: s.to_owned(),
            what: "a name with an empty, `.` or `..` component".into(),
        });
    }
    Ok(s.to_owned())
}

/// Every entry of a tar, with where it starts and ends in the file.
fn spans(path: &Path, which: &'static str) -> Result<Vec<Span>, StoreError> {
    let tar_err = |e: io::Error| StoreError::Tar {
        which,
        error: e.to_string(),
    };
    let file = File::open(path).map_err(io_at(format!("opening {}", path.display())))?;
    let mut archive = tar::Archive::new(BufReader::new(file));
    let mut out = Vec::new();
    let mut start = 0u64;
    for entry in archive.entries().map_err(tar_err)? {
        let entry = entry.map_err(tar_err)?;
        let size = entry.header().entry_size().map_err(tar_err)?;
        let padded = size
            .div_ceil(BLOCK)
            .checked_mul(BLOCK)
            .ok_or_else(|| tar_err(io::Error::other("entry size overflows")))?;
        let end = entry
            .raw_file_position()
            .checked_add(padded)
            .ok_or_else(|| tar_err(io::Error::other("entry end overflows")))?;
        let kind = entry.header().entry_type();
        let link = match (kind, entry.link_name_bytes()) {
            (tar::EntryType::Link, Some(l)) => Some(normalize(&l, which)?),
            _ => None,
        };
        out.push(Span {
            start,
            end,
            path: normalize(&entry.path_bytes(), which)?,
            kind,
            link,
        });
        start = end;
    }
    Ok(out)
}

fn copy_range(
    from: &mut File,
    span_start: u64,
    span_end: u64,
    out: &mut impl Write,
) -> io::Result<()> {
    from.seek(SeekFrom::Start(span_start))?;
    let len = span_end.saturating_sub(span_start);
    let copied = io::copy(&mut Read::by_ref(from).take(len), out)?;
    if copied == len {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "tar ended inside an entry",
        ))
    }
}

/// Write `user`'s entries, then `guest`'s, to `out` as one tar. See the module docs
/// for what a guest entry may and may not do.
pub fn overlay(user: &Path, guest: &Path, out: impl Write) -> Result<Overlaid, StoreError> {
    let user_spans = spans(user, "rootfs")?;
    let guest_spans = spans(guest, "guest layer")?;
    let mut held: BTreeMap<String, Held> = BTreeMap::new();
    held.insert(String::new(), Held::Dir);
    for s in &user_spans {
        let h = if s.kind.is_dir() {
            Held::Dir
        } else {
            Held::NonDir
        };
        held.insert(s.path.clone(), h);
    }
    let mut guest_files: BTreeMap<String, ()> = BTreeMap::new();
    let mut keep = Vec::new();
    let mut shared_dirs = 0u64;
    for s in &guest_spans {
        let is_dir = s.kind.is_dir();
        match s.kind {
            tar::EntryType::Directory
            | tar::EntryType::Regular
            | tar::EntryType::Symlink
            | tar::EntryType::Link => {}
            other => {
                return Err(StoreError::Unsupported {
                    path: s.path.clone(),
                    what: format!("tar entry type {other:?}"),
                });
            }
        }
        if s.path.is_empty() {
            shared_dirs = shared_dirs.saturating_add(1);
            continue;
        }
        let mut ancestor = s.path.as_str();
        while let Some((parent, _)) = ancestor.rsplit_once('/') {
            match held.get(parent) {
                Some(Held::Dir) => {}
                Some(Held::NonDir) => {
                    return Err(StoreError::ThroughNonDirectory {
                        path: s.path.clone(),
                        ancestor: parent.to_owned(),
                    });
                }
                None => {
                    return Err(StoreError::MissingParent {
                        path: s.path.clone(),
                    });
                }
            }
            ancestor = parent;
        }
        match (held.get(&s.path), is_dir) {
            (None, _) => {}
            (Some(Held::Dir), true) => {
                shared_dirs = shared_dirs.saturating_add(1);
                continue;
            }
            (Some(Held::Dir), false) => {
                return Err(StoreError::Collision {
                    path: s.path.clone(),
                    user: "directory",
                });
            }
            (Some(Held::NonDir), _) => {
                return Err(StoreError::Collision {
                    path: s.path.clone(),
                    user: "file",
                });
            }
        }
        if s.kind == tar::EntryType::Link {
            let target_is_guest_file = s.link.as_ref().is_some_and(|t| guest_files.contains_key(t));
            if !target_is_guest_file {
                return Err(StoreError::Unsupported {
                    path: s.path.clone(),
                    what: "a hard link to something the guest layer did not add".into(),
                });
            }
        }
        if s.kind == tar::EntryType::Regular {
            guest_files.insert(s.path.clone(), ());
        }
        held.insert(
            s.path.clone(),
            if is_dir { Held::Dir } else { Held::NonDir },
        );
        keep.push(s);
    }

    let mut out = io::BufWriter::new(out);
    let write_err = io_at("writing the merged tar");
    let user_end = user_spans.last().map_or(0, |s| s.end);
    let mut user_file = File::open(user).map_err(io_at(format!("opening {}", user.display())))?;
    copy_range(&mut user_file, 0, user_end, &mut out).map_err(io_at("copying the rootfs tar"))?;
    let mut guest_file =
        File::open(guest).map_err(io_at(format!("opening {}", guest.display())))?;
    for s in &keep {
        copy_range(&mut guest_file, s.start, s.end, &mut out)
            .map_err(io_at("copying the guest layer"))?;
    }
    // End of archive: two zero blocks.
    out.write_all(&[0u8; 1024]).map_err(write_err)?;
    out.flush().map_err(io_at("flushing the merged tar"))?;
    Ok(Overlaid {
        added: u64::try_from(keep.len()).unwrap_or(u64::MAX),
        shared_dirs,
    })
}

#[cfg(test)]
#[path = "image_store_tests.rs"]
mod tests;
