//! Every refusal this crate can make, each with its own name.
//!
//! One variant per reason (ADR 0007 A-3: no blanket `map_err`). An I/O failure
//! carries what was being read, so "could not look" is never folded into a
//! verdict about the image (A-2).

use crate::digest::Sha256Digest;

/// Which kind of blob a digest or size check was about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobRole {
    /// An image index (multi-platform list) reached from `index.json`.
    Index,
    /// An image manifest.
    Manifest,
    /// An image configuration.
    Config,
    /// A filesystem layer.
    Layer,
}

impl std::fmt::Display for BlobRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Index => "index",
            Self::Manifest => "manifest",
            Self::Config => "config",
            Self::Layer => "layer",
        })
    }
}

/// Why an import was refused.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    // ── the reference ────────────────────────────────────────────────────
    /// The reference names a tag, not a digest. Tags move; an import is pinned.
    #[error(
        "reference `{reference}` has no digest; a tag-only reference is refused (pin `@sha256:…`)"
    )]
    TagOnlyReference {
        /// The reference as given.
        reference: String,
    },
    /// A digest using an algorithm other than sha256.
    #[error("digest `{digest}` uses an unsupported algorithm; only sha256 is accepted")]
    UnsupportedDigestAlgorithm {
        /// The digest as given.
        digest: String,
    },
    /// A digest that is not `sha256:` followed by 64 lowercase hex digits.
    #[error("digest `{digest}` is malformed; expected `sha256:` and 64 lowercase hex digits")]
    MalformedDigest {
        /// The digest as given.
        digest: String,
    },

    // ── the layout ───────────────────────────────────────────────────────
    /// A legacy `docker save` archive: `manifest.json` but no `index.json`.
    #[error(
        "legacy docker-save archive (manifest.json without index.json) is refused; \
         re-save as an OCI archive (docker 25+, `podman save --format oci-archive`)"
    )]
    LegacyDockerSave,
    /// Neither an OCI layout nor a legacy archive.
    #[error("not an OCI image layout: `oci-layout` is missing")]
    NotAnOciLayout,
    /// `oci-layout` present, `index.json` absent.
    #[error("OCI image layout has no `index.json`")]
    MissingIndex,
    /// An `imageLayoutVersion` this crate does not read.
    #[error("unsupported OCI image layout version `{version}` (expected 1.0.0)")]
    UnsupportedLayoutVersion {
        /// The version found.
        version: String,
    },
    /// A blob named by a descriptor is not in the layout.
    #[error("blob {digest} is not present in the layout")]
    MissingBlob {
        /// The absent blob.
        digest: Sha256Digest,
    },
    /// A [`crate::BlobSource`] outside this crate (a registry client) could not
    /// produce a file. Its own typed error is kept whole as the source, so a
    /// caller can downcast to it instead of reading a folded string (A-3).
    #[error("{what}: {source}")]
    Source {
        /// What was being fetched.
        what: String,
        /// The source's own error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    /// A member of an oci-archive that is not a regular file was asked for.
    #[error("archive member `{name}` is not a regular file")]
    ArchiveMemberNotRegular {
        /// The member's name.
        name: String,
    },
    /// An oci-archive names the same member twice; which one is meant is ambiguous.
    #[error("archive member `{name}` appears more than once")]
    DuplicateArchiveMember {
        /// The member's name.
        name: String,
    },
    /// An oci-archive member whose name has no normal form (`..`, NUL, empty).
    #[error("archive member `{name}` has an invalid name")]
    InvalidArchiveMember {
        /// The member's name, lossily decoded.
        name: String,
    },
    /// Reading the layout failed.
    #[error("reading {what}: {source}")]
    Io {
        /// What was being read.
        what: String,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A JSON document failed to parse as what its descriptor says it is.
    #[error("{role} JSON is malformed: {detail}")]
    MalformedJson {
        /// Which document.
        role: BlobRole,
        /// The parser's complaint.
        detail: String,
    },
    /// `oci-layout` or `index.json` failed to parse.
    #[error("{file} is malformed: {detail}")]
    MalformedLayoutJson {
        /// Which file.
        file: &'static str,
        /// The parser's complaint.
        detail: String,
    },
    /// A JSON document exceeds [`crate::ImportLimits::max_metadata_bytes`].
    #[error("{what} exceeds the metadata limit of {limit} bytes")]
    MetadataTooLarge {
        /// Which document.
        what: String,
        /// The limit.
        limit: u64,
    },
    /// A blob's length differs from its descriptor's `size`.
    #[error("{role} blob {digest}: descriptor says {expected} bytes, blob has {actual}")]
    BlobSizeMismatch {
        /// Which blob.
        role: BlobRole,
        /// Its digest.
        digest: Sha256Digest,
        /// The descriptor's size.
        expected: u64,
        /// What was read (at most `expected + 1`).
        actual: u64,
    },
    /// A blob's content does not hash to the digest that names it.
    #[error("{role} blob digest mismatch: expected {expected}, content hashes to {actual}")]
    BlobDigestMismatch {
        /// Which blob.
        role: BlobRole,
        /// The digest that named it.
        expected: Sha256Digest,
        /// What its content hashes to.
        actual: Sha256Digest,
    },
    /// The pinned digest is not reachable from `index.json`.
    #[error("{digest} is not referenced by the layout's index.json")]
    ReferenceNotInLayout {
        /// The pinned digest.
        digest: Sha256Digest,
    },
    /// Image indexes nest deeper than this crate follows.
    #[error("image index nesting is deeper than {limit}")]
    IndexNestingTooDeep {
        /// The depth followed.
        limit: usize,
    },
    /// An image index has no manifest for the requested platform.
    #[error("no manifest for linux/{arch} in the image index")]
    NoManifestForPlatform {
        /// The requested architecture.
        arch: crate::Arch,
    },
    /// An image index has more than one manifest for the requested platform.
    #[error("{count} manifests match linux/{arch}; which one is meant is ambiguous")]
    AmbiguousPlatform {
        /// The requested architecture.
        arch: crate::Arch,
        /// How many matched.
        count: usize,
    },
    /// The image is for a different platform than requested.
    #[error("image platform is {found}, requested linux/{expected}")]
    PlatformMismatch {
        /// The requested architecture.
        expected: crate::Arch,
        /// The platform the image declares.
        found: String,
    },
    /// A descriptor's media type is not one this crate reads in that position.
    #[error("unsupported {role} media type `{media_type}`")]
    UnsupportedMediaType {
        /// Where it appeared.
        role: BlobRole,
        /// The media type.
        media_type: String,
    },
    /// The config's `rootfs.diff_ids` does not have one entry per manifest layer.
    #[error("manifest has {layers} layers but config lists {diff_ids} diff_ids")]
    LayerCountMismatch {
        /// Layers in the manifest.
        layers: usize,
        /// Entries in `rootfs.diff_ids`.
        diff_ids: usize,
    },
    /// A layer's uncompressed content does not hash to its `diff_id`.
    #[error("layer {layer}: uncompressed content hashes to {actual}, config diff_id is {expected}")]
    DiffIdMismatch {
        /// Zero-based layer index.
        layer: usize,
        /// The config's diff_id.
        expected: Sha256Digest,
        /// What the content hashes to.
        actual: Sha256Digest,
    },

    // ── the reserved-path table ──────────────────────────────────────────
    /// An empty reserved-path table: every path would be the workload's.
    #[error("the reserved guest path table is empty; refusing to import with nothing reserved")]
    EmptyReservedTable,
    /// A reserved-path table entry that is not a normal relative path.
    #[error("reserved guest path `{path}` is not a normal path")]
    InvalidReservedPath {
        /// The entry as given.
        path: String,
    },

    // ── flattening ───────────────────────────────────────────────────────
    /// A layer's tar stream could not be read.
    #[error("layer {layer}: reading the tar stream: {source}")]
    LayerRead {
        /// Zero-based layer index.
        layer: usize,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// Decompressed bytes across all layers exceed the limit.
    #[error("uncompressed layer content exceeds the limit of {limit} bytes")]
    UncompressedLimitExceeded {
        /// The limit.
        limit: u64,
    },
    /// Tar entries across all layers exceed the limit.
    #[error("layers contain more than {limit} entries")]
    TooManyEntries {
        /// The limit.
        limit: u64,
    },
    /// A path or link target longer than the limit.
    #[error("layer {layer}: a path of {len} bytes exceeds the limit of {limit}")]
    PathTooLong {
        /// Zero-based layer index.
        layer: usize,
        /// The path's length.
        len: usize,
        /// The limit.
        limit: u64,
    },
    /// A path or link target containing a NUL byte.
    #[error("layer {layer}: path `{path}` contains a NUL byte")]
    PathHasNul {
        /// Zero-based layer index.
        layer: usize,
        /// The path, lossily decoded.
        path: String,
    },
    /// An entry with an empty name.
    #[error("layer {layer}: an entry has an empty path")]
    EmptyPath {
        /// Zero-based layer index.
        layer: usize,
    },
    /// A path with a `..` component.
    #[error("layer {layer}: path `{path}` has a `..` component")]
    DotDotComponent {
        /// Zero-based layer index.
        layer: usize,
        /// The path, lossily decoded.
        path: String,
    },
    /// A non-directory entry naming the root itself.
    #[error("layer {layer}: a non-directory entry names the root")]
    RootNotDirectory {
        /// Zero-based layer index.
        layer: usize,
    },
    /// A tar entry type this crate does not import (sparse, unknown).
    #[error("layer {layer}: `{path}` has unsupported tar entry type {type_byte:#04x}")]
    UnsupportedEntryType {
        /// Zero-based layer index.
        layer: usize,
        /// The path, lossily decoded.
        path: String,
        /// The raw type flag.
        type_byte: u8,
    },
    /// A tar header field that does not parse.
    #[error("layer {layer}: `{path}` has an invalid header: {source}")]
    InvalidHeader {
        /// Zero-based layer index.
        layer: usize,
        /// The path, lossily decoded.
        path: String,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A malformed whiteout name (`.wh.` alone, `.wh..wh.x`, or `.wh.` in a directory name).
    #[error("layer {layer}: `{path}` is not a valid whiteout")]
    InvalidWhiteout {
        /// Zero-based layer index.
        layer: usize,
        /// The path, lossily decoded.
        path: String,
    },
    /// A user layer places an entry at a path the guest reserves.
    #[error("layer {layer}: `{path}` is inside reserved guest path `{reserved}`")]
    ReservedPath {
        /// Zero-based layer index.
        layer: usize,
        /// The path, lossily decoded.
        path: String,
        /// The reserved entry it falls in.
        reserved: String,
    },
    /// A whiteout or opaque marker whose effect reaches a reserved guest path.
    #[error("layer {layer}: whiteout of `{path}` reaches reserved guest path `{reserved}`")]
    WhiteoutOverReserved {
        /// Zero-based layer index.
        layer: usize,
        /// What the whiteout removes (for an opaque marker, the directory it clears).
        path: String,
        /// The reserved entry it reaches.
        reserved: String,
    },
    /// In the flattened tree, an ancestor of a reserved guest path is not a real directory.
    #[error("`{path}` must be a real directory (it contains reserved guest path `{reserved}`)")]
    ReservedAncestorNotDirectory {
        /// The offending entry, lossily decoded.
        path: String,
        /// The reserved entry beneath it.
        reserved: String,
    },
    /// An entry whose parent is not a directory (a symlink, a file).
    #[error("layer {layer}: `{path}` lies under `{ancestor}`, which is not a directory")]
    AncestorNotDirectory {
        /// Zero-based layer index.
        layer: usize,
        /// The entry, lossily decoded.
        path: String,
        /// The non-directory ancestor, lossily decoded.
        ancestor: String,
    },
    /// A hardlink whose target is not in the tree.
    #[error("layer {layer}: hardlink `{path}` targets `{target}`, which does not exist")]
    HardlinkTargetMissing {
        /// Zero-based layer index.
        layer: usize,
        /// The link, lossily decoded.
        path: String,
        /// Its target, lossily decoded.
        target: String,
    },
    /// A hardlink whose target is not a regular file.
    #[error("layer {layer}: hardlink `{path}` targets `{target}`, which is not a regular file")]
    HardlinkTargetNotRegular {
        /// Zero-based layer index.
        layer: usize,
        /// The link, lossily decoded.
        path: String,
        /// Its target, lossily decoded.
        target: String,
    },
    /// A link entry with no target.
    #[error("layer {layer}: link `{path}` has no target")]
    MissingLinkTarget {
        /// Zero-based layer index.
        layer: usize,
        /// The link, lossily decoded.
        path: String,
    },

    // ── output ───────────────────────────────────────────────────────────
    /// Writing the flattened tar failed.
    #[error("writing the rootfs tar: {source}")]
    Emit {
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
}

/// Lossily decode a path for an error message or report. Never used to decide anything.
pub(crate) fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
