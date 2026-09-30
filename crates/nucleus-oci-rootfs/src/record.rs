//! The import record: what was imported, from what, and everything changed on the way.

use crate::digest::Sha256Digest;
use crate::limits::ImportLimits;

/// A guest path as recorded: UTF-8 when it is, otherwise its bytes in hex.
///
/// Never lossy. A record that rewrote a non-UTF-8 name into U+FFFD could not
/// say which file it meant.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum RecordedPath {
    /// A UTF-8 path.
    Utf8(String),
    /// A path that is not UTF-8.
    Bytes {
        /// The path's bytes, lowercase hex.
        bytes_hex: String,
    },
}

impl RecordedPath {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        match std::str::from_utf8(bytes) {
            Ok(s) => Self::Utf8(s.to_owned()),
            Err(_) => Self::Bytes {
                bytes_hex: hex::encode(bytes),
            },
        }
    }
}

/// A special file this crate does not put in a guest rootfs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DroppedKind {
    /// A character device node.
    CharDevice,
    /// A block device node.
    BlockDevice,
}

/// An entry dropped from a layer (owner decision: devices are dropped and reported, not refused).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DroppedEntry {
    /// Zero-based layer index.
    pub layer: usize,
    /// The entry's normalized path.
    pub path: RecordedPath,
    /// What it was.
    pub kind: DroppedKind,
}

/// A setuid/setgid bit removed from an entry's mode.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StrippedSetId {
    /// Zero-based layer index.
    pub layer: usize,
    /// The entry's normalized path.
    pub path: RecordedPath,
    /// The bits removed (a subset of `0o6000`).
    pub bits: u32,
}

/// An extended attribute not carried into the rootfs.
///
/// `security.capability` is the one the owner decision names; every other
/// xattr is dropped too, because the emitted tar carries none (no pax records).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StrippedXattr {
    /// Zero-based layer index.
    pub layer: usize,
    /// The entry's normalized path.
    pub path: RecordedPath,
    /// The attribute's name, as the layer's pax record spelled it.
    pub name: RecordedPath,
}

/// Everything flattening changed or removed, in layer order.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FlattenReport {
    /// Device nodes dropped.
    pub dropped: Vec<DroppedEntry>,
    /// setuid/setgid bits stripped.
    pub stripped_setid: Vec<StrippedSetId>,
    /// `security.capability` xattrs stripped.
    pub stripped_capabilities: Vec<StrippedXattr>,
    /// Other xattrs dropped.
    pub dropped_xattrs: Vec<StrippedXattr>,
}

impl FlattenReport {
    pub(crate) fn empty() -> Self {
        Self {
            dropped: Vec::new(),
            stripped_setid: Vec::new(),
            stripped_capabilities: Vec::new(),
            dropped_xattrs: Vec::new(),
        }
    }
}

/// How a layer blob is compressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    /// A plain tar.
    None,
    /// gzip (one or more members).
    Gzip,
    /// zstd (one or more frames).
    Zstd,
}

/// One layer as imported.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LayerRecord {
    /// The blob's digest (compressed).
    pub digest: Sha256Digest,
    /// The config's `diff_id` (uncompressed), which the content was checked against.
    pub diff_id: Sha256Digest,
    /// The blob's size in bytes.
    pub size: u64,
    /// Its compression.
    pub compression: Compression,
}

/// The emitted rootfs tar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RootfsRecord {
    /// sha256 of the tar's bytes.
    pub digest: Sha256Digest,
    /// The tar's length in bytes.
    pub bytes: u64,
    /// Entries emitted (hardlinks count; GNU long-name records do not).
    pub entries: u64,
}

/// The platform an image was imported for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlatformRecord {
    /// Always `linux`; any other OS is refused.
    pub os: LinuxOs,
    /// The architecture requested and matched.
    pub architecture: crate::Arch,
}

/// The only OS this crate imports for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxOs {
    /// `linux`.
    Linux,
}

/// What one import did, for the caller to keep beside the rootfs it describes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImportRecord {
    /// `nucleus-oci-rootfs`'s version, so a record names the rules it was made under.
    pub crate_version: String,
    /// The digest the caller pinned.
    pub pinned: Sha256Digest,
    /// The image index the platform was selected from, when the pin named one.
    pub index_digest: Option<Sha256Digest>,
    /// The platform manifest.
    pub manifest_digest: Sha256Digest,
    /// The image config.
    pub config_digest: Sha256Digest,
    /// The platform.
    pub platform: PlatformRecord,
    /// The layers, bottom first.
    pub layers: Vec<LayerRecord>,
    /// Everything flattening changed or removed.
    pub report: FlattenReport,
    /// The limits the import ran under.
    pub limits: ImportLimits,
    /// The emitted tar.
    pub rootfs: RootfsRecord,
}
