//! Reading a local OCI image: a layout directory or an oci-archive tar.
//!
//! Both have the same shape — `oci-layout`, `index.json`, `blobs/sha256/<hex>`
//! — and differ only in how a file is opened, which is the one method of
//! [`BlobSource`]. Everything above that is shared.
//!
//! Every blob is checked against the digest that names it:
//!
//! - a JSON blob (index, manifest, config) is read whole, bounded by
//!   [`ImportLimits::max_metadata_bytes`], and verified before it is parsed;
//! - a layer blob is hashed end to end by [`verify_layer_blob`] before its tar
//!   is parsed at all, then hashed **again** while it is decompressed and
//!   parsed, and the second digest checked too. The first pass means a
//!   mismatched layer never reaches the tar parser; the second means a file
//!   that changes between the two passes is refused rather than trusted. Its
//!   uncompressed bytes are checked against the config's `diff_id` as well.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;

use flate2::read::MultiGzDecoder;
use oci_spec::image::{Descriptor, ImageConfiguration, ImageIndex, ImageManifest, MediaType, Os};

use crate::Arch;
use crate::digest::{HashingReader, PinnedReference, Sha256Digest};
use crate::error::{BlobRole, ImportError, lossy};
use crate::flatten::Flattener;
use crate::limits::ImportLimits;
use crate::path::{self, Normalized};
use crate::record::Compression;

const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const DOCKER_MANIFEST_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
const DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
const DOCKER_LAYER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";

/// How deep `index.json` → index → index is followed looking for the pinned digest.
const MAX_INDEX_DEPTH: usize = 2;

/// A file in an OCI image layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutFile {
    /// `oci-layout`.
    OciLayout,
    /// `index.json`.
    Index,
    /// `manifest.json`: present in a legacy `docker save`, used only to name that refusal.
    LegacyManifest,
    /// `blobs/sha256/<hex>`.
    Blob(Sha256Digest),
}

impl LayoutFile {
    fn relative(&self) -> String {
        match self {
            Self::OciLayout => "oci-layout".to_owned(),
            Self::Index => "index.json".to_owned(),
            Self::LegacyManifest => "manifest.json".to_owned(),
            Self::Blob(digest) => format!("blobs/sha256/{}", digest.hex()),
        }
    }
}

/// Where an image's files come from. Each call opens the file afresh at its first byte.
pub trait BlobSource {
    /// Open `file`, or `Ok(None)` when the layout does not have it.
    fn open(&self, file: LayoutFile) -> Result<Option<Box<dyn Read + '_>>, ImportError>;
}

/// An OCI image layout directory on the local filesystem.
#[derive(Clone, Debug)]
pub struct LayoutDir {
    root: PathBuf,
}

impl LayoutDir {
    /// The layout rooted at `root` (the directory holding `oci-layout`).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl BlobSource for LayoutDir {
    fn open(&self, file: LayoutFile) -> Result<Option<Box<dyn Read + '_>>, ImportError> {
        let path = self.root.join(file.relative());
        match File::open(&path) {
            Ok(f) => Ok(Some(Box::new(f))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(ImportError::Io {
                what: path.display().to_string(),
                source,
            }),
        }
    }
}

/// Where a member's bytes sit in an oci-archive.
#[derive(Clone, Copy, Debug)]
enum Member {
    Regular { offset: u64, size: u64 },
    NotRegular,
}

/// An oci-archive: an OCI image layout, tarred (`docker save` from Docker 25,
/// `podman save --format oci-archive`, `container image save`).
///
/// The archive is indexed once; each member is then read in place by seeking,
/// so nothing is extracted to disk.
#[derive(Clone, Debug)]
pub struct OciArchive {
    path: PathBuf,
    members: BTreeMap<Vec<u8>, Member>,
}

impl OciArchive {
    /// Index the archive at `path`. Its entry count is bounded by `limits.max_entries`.
    pub fn open(path: impl Into<PathBuf>, limits: &ImportLimits) -> Result<Self, ImportError> {
        let path = path.into();
        let io_err = |source: io::Error| ImportError::Io {
            what: path.display().to_string(),
            source,
        };
        let file = File::open(&path).map_err(io_err)?;
        let mut archive = tar::Archive::new(file);
        let mut members = BTreeMap::new();
        let mut count: u64 = 0;
        for entry in archive.entries_with_seek().map_err(io_err)? {
            let entry = entry.map_err(io_err)?;
            count = count.saturating_add(1);
            if count > limits.max_entries {
                return Err(ImportError::TooManyEntries {
                    limit: limits.max_entries,
                });
            }
            let raw = entry.path_bytes().into_owned();
            let name = match path::normalize(&raw, limits.max_path_bytes) {
                Ok(Normalized::Path(p)) => p,
                Ok(Normalized::Root) => continue,
                Err(_) => {
                    return Err(ImportError::InvalidArchiveMember { name: lossy(&raw) });
                }
            };
            let member = match entry.header().entry_type() {
                tar::EntryType::Regular | tar::EntryType::Continuous => Member::Regular {
                    offset: entry.raw_file_position(),
                    size: entry.size(),
                },
                tar::EntryType::Directory | tar::EntryType::XGlobalHeader => continue,
                tar::EntryType::Link
                | tar::EntryType::Symlink
                | tar::EntryType::Char
                | tar::EntryType::Block
                | tar::EntryType::Fifo
                | tar::EntryType::GNULongName
                | tar::EntryType::GNULongLink
                | tar::EntryType::GNUSparse
                | tar::EntryType::XHeader
                | tar::EntryType::__Nonexhaustive(_) => Member::NotRegular,
            };
            if members.insert(name.clone(), member).is_some() {
                return Err(ImportError::DuplicateArchiveMember { name: lossy(&name) });
            }
        }
        Ok(Self { path, members })
    }
}

impl BlobSource for OciArchive {
    fn open(&self, file: LayoutFile) -> Result<Option<Box<dyn Read + '_>>, ImportError> {
        let name = file.relative();
        let (offset, size) = match self.members.get(name.as_bytes()) {
            None => return Ok(None),
            Some(Member::NotRegular) => return Err(ImportError::ArchiveMemberNotRegular { name }),
            Some(Member::Regular { offset, size }) => (*offset, *size),
        };
        let io_err = |source: io::Error| ImportError::Io {
            what: format!("{} in {}", name, self.path.display()),
            source,
        };
        let mut f = File::open(&self.path).map_err(io_err)?;
        f.seek(SeekFrom::Start(offset)).map_err(io_err)?;
        Ok(Some(Box::new(f.take(size))))
    }
}

/// One layer to apply.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LayerRef {
    pub(crate) digest: Sha256Digest,
    pub(crate) size: u64,
    pub(crate) compression: Compression,
    pub(crate) diff_id: Sha256Digest,
}

/// An image resolved from a pinned digest to one platform's layers.
#[derive(Debug)]
pub(crate) struct Resolved {
    pub(crate) index_digest: Option<Sha256Digest>,
    pub(crate) manifest_digest: Sha256Digest,
    pub(crate) config_digest: Sha256Digest,
    pub(crate) config: ImageConfiguration,
    pub(crate) layers: Vec<LayerRef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManifestKind {
    Index,
    Manifest,
}

fn manifest_kind(media_type: &MediaType) -> Option<ManifestKind> {
    match media_type {
        MediaType::ImageIndex => Some(ManifestKind::Index),
        MediaType::ImageManifest => Some(ManifestKind::Manifest),
        MediaType::Other(s) if s == DOCKER_MANIFEST_LIST => Some(ManifestKind::Index),
        MediaType::Other(s) if s == DOCKER_MANIFEST => Some(ManifestKind::Manifest),
        MediaType::Other(_)
        | MediaType::Descriptor
        | MediaType::LayoutHeader
        | MediaType::ImageLayer
        | MediaType::ImageLayerGzip
        | MediaType::ImageLayerZstd
        | MediaType::ImageLayerNonDistributable
        | MediaType::ImageLayerNonDistributableGzip
        | MediaType::ImageLayerNonDistributableZstd
        | MediaType::ImageConfig
        | MediaType::ArtifactManifest
        | MediaType::EmptyJSON => None,
    }
}

fn layer_compression(media_type: &MediaType) -> Result<Compression, ImportError> {
    match media_type {
        MediaType::ImageLayer | MediaType::ImageLayerNonDistributable => Ok(Compression::None),
        MediaType::ImageLayerGzip | MediaType::ImageLayerNonDistributableGzip => {
            Ok(Compression::Gzip)
        }
        MediaType::ImageLayerZstd | MediaType::ImageLayerNonDistributableZstd => {
            Ok(Compression::Zstd)
        }
        MediaType::Other(s) if s == DOCKER_LAYER_GZIP => Ok(Compression::Gzip),
        MediaType::Other(_)
        | MediaType::Descriptor
        | MediaType::LayoutHeader
        | MediaType::ImageManifest
        | MediaType::ImageIndex
        | MediaType::ImageConfig
        | MediaType::ArtifactManifest
        | MediaType::EmptyJSON => Err(ImportError::UnsupportedMediaType {
            role: BlobRole::Layer,
            media_type: media_type.to_string(),
        }),
    }
}

fn is_config(media_type: &MediaType) -> bool {
    match media_type {
        MediaType::ImageConfig => true,
        MediaType::Other(s) => s == DOCKER_CONFIG,
        MediaType::Descriptor
        | MediaType::LayoutHeader
        | MediaType::ImageManifest
        | MediaType::ImageIndex
        | MediaType::ImageLayer
        | MediaType::ImageLayerGzip
        | MediaType::ImageLayerZstd
        | MediaType::ImageLayerNonDistributable
        | MediaType::ImageLayerNonDistributableGzip
        | MediaType::ImageLayerNonDistributableZstd
        | MediaType::ArtifactManifest
        | MediaType::EmptyJSON => false,
    }
}

fn variant_matches(arch: Arch, variant: Option<&str>) -> bool {
    match arch {
        Arch::Amd64 => variant.is_none(),
        Arch::Arm64 => matches!(variant, None | Some("v8")),
    }
}

/// Read a whole bounded file from the layout.
fn read_bounded(
    src: &dyn BlobSource,
    file: LayoutFile,
    limit: u64,
) -> Result<Option<Vec<u8>>, ImportError> {
    let Some(reader) = src.open(file)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| ImportError::Io {
            what: file.relative(),
            source,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(ImportError::MetadataTooLarge {
            what: file.relative(),
            limit,
        });
    }
    Ok(Some(bytes))
}

fn check_blob(
    role: BlobRole,
    digest: Sha256Digest,
    expected_size: u64,
    actual: Sha256Digest,
    actual_size: u64,
) -> Result<(), ImportError> {
    if actual_size != expected_size {
        return Err(ImportError::BlobSizeMismatch {
            role,
            digest,
            expected: expected_size,
            actual: actual_size,
        });
    }
    if actual != digest {
        return Err(ImportError::BlobDigestMismatch {
            role,
            expected: digest,
            actual,
        });
    }
    Ok(())
}

fn descriptor_digest(desc: &Descriptor) -> Result<Sha256Digest, ImportError> {
    Sha256Digest::parse(desc.digest().as_ref())
}

fn open_blob(
    src: &dyn BlobSource,
    digest: Sha256Digest,
) -> Result<Box<dyn Read + '_>, ImportError> {
    src.open(LayoutFile::Blob(digest))?
        .ok_or(ImportError::MissingBlob { digest })
}

/// Read a JSON blob whole, verify its size and digest, and only then parse it.
fn load_json<T: serde::de::DeserializeOwned>(
    src: &dyn BlobSource,
    desc: &Descriptor,
    role: BlobRole,
    limits: &ImportLimits,
) -> Result<(Sha256Digest, T), ImportError> {
    let digest = descriptor_digest(desc)?;
    let size = desc.size();
    if size > limits.max_metadata_bytes {
        return Err(ImportError::MetadataTooLarge {
            what: format!("{role} {digest}"),
            limit: limits.max_metadata_bytes,
        });
    }
    let mut bytes = Vec::new();
    open_blob(src, digest)?
        .take(size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| ImportError::Io {
            what: format!("{role} blob {digest}"),
            source,
        })?;
    check_blob(
        role,
        digest,
        size,
        Sha256Digest::of(&bytes),
        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    )?;
    let parsed = serde_json::from_slice(&bytes).map_err(|e| ImportError::MalformedJson {
        role,
        detail: e.to_string(),
    })?;
    Ok((digest, parsed))
}

/// Find the descriptor named `target` under `manifests`, following nested indexes.
fn find_descriptor(
    src: &dyn BlobSource,
    manifests: &[Descriptor],
    target: Sha256Digest,
    limits: &ImportLimits,
    depth: usize,
) -> Result<Option<Descriptor>, ImportError> {
    for desc in manifests {
        if descriptor_digest(desc)? == target {
            return Ok(Some(desc.clone()));
        }
    }
    for desc in manifests {
        if manifest_kind(desc.media_type()) == Some(ManifestKind::Index) {
            if depth >= MAX_INDEX_DEPTH {
                return Err(ImportError::IndexNestingTooDeep {
                    limit: MAX_INDEX_DEPTH,
                });
            }
            let (_, nested): (_, ImageIndex) = load_json(src, desc, BlobRole::Index, limits)?;
            let next = depth.saturating_add(1);
            if let Some(found) = find_descriptor(src, nested.manifests(), target, limits, next)? {
                return Ok(Some(found));
            }
        }
    }
    Ok(None)
}

/// Resolve a pinned digest to one linux/`arch` manifest, its config, and its layers.
pub(crate) fn resolve(
    src: &dyn BlobSource,
    pinned: &PinnedReference,
    arch: Arch,
    limits: &ImportLimits,
) -> Result<Resolved, ImportError> {
    let has_legacy_manifest =
        || -> Result<bool, ImportError> { Ok(src.open(LayoutFile::LegacyManifest)?.is_some()) };
    let Some(layout) = read_bounded(src, LayoutFile::OciLayout, limits.max_metadata_bytes)? else {
        return Err(if has_legacy_manifest()? {
            ImportError::LegacyDockerSave
        } else {
            ImportError::NotAnOciLayout
        });
    };
    let layout: oci_spec::image::OciLayout =
        serde_json::from_slice(&layout).map_err(|e| ImportError::MalformedLayoutJson {
            file: "oci-layout",
            detail: e.to_string(),
        })?;
    if layout.image_layout_version() != "1.0.0" {
        return Err(ImportError::UnsupportedLayoutVersion {
            version: layout.image_layout_version().clone(),
        });
    }
    let Some(index) = read_bounded(src, LayoutFile::Index, limits.max_metadata_bytes)? else {
        return Err(if has_legacy_manifest()? {
            ImportError::LegacyDockerSave
        } else {
            ImportError::MissingIndex
        });
    };
    let index: ImageIndex =
        serde_json::from_slice(&index).map_err(|e| ImportError::MalformedLayoutJson {
            file: "index.json",
            detail: e.to_string(),
        })?;

    let target = pinned.digest();
    let pinned_desc = find_descriptor(src, index.manifests(), target, limits, 0)?
        .ok_or(ImportError::ReferenceNotInLayout { digest: target })?;

    let (index_digest, manifest_desc) = match manifest_kind(pinned_desc.media_type()) {
        Some(ManifestKind::Manifest) => (None, pinned_desc),
        Some(ManifestKind::Index) => {
            let (digest, list): (_, ImageIndex) =
                load_json(src, &pinned_desc, BlobRole::Index, limits)?;
            let candidates: Vec<&Descriptor> = list
                .manifests()
                .iter()
                .filter(|d| manifest_kind(d.media_type()) == Some(ManifestKind::Manifest))
                .filter(|d| {
                    d.platform().as_ref().is_some_and(|p| {
                        *p.os() == Os::Linux
                            && arch.matches(p.architecture())
                            && variant_matches(arch, p.variant().as_deref())
                    })
                })
                .collect();
            let chosen = match candidates.as_slice() {
                [] => return Err(ImportError::NoManifestForPlatform { arch }),
                [one] => (*one).clone(),
                many => {
                    return Err(ImportError::AmbiguousPlatform {
                        arch,
                        count: many.len(),
                    });
                }
            };
            (Some(digest), chosen)
        }
        None => {
            return Err(ImportError::UnsupportedMediaType {
                role: BlobRole::Manifest,
                media_type: pinned_desc.media_type().to_string(),
            });
        }
    };

    let (manifest_digest, manifest): (_, ImageManifest) =
        load_json(src, &manifest_desc, BlobRole::Manifest, limits)?;
    let config_desc = manifest.config();
    if !is_config(config_desc.media_type()) {
        return Err(ImportError::UnsupportedMediaType {
            role: BlobRole::Config,
            media_type: config_desc.media_type().to_string(),
        });
    }
    let (config_digest, config): (_, ImageConfiguration) =
        load_json(src, config_desc, BlobRole::Config, limits)?;

    if *config.os() != Os::Linux
        || !arch.matches(config.architecture())
        || !variant_matches(arch, config.variant().as_deref())
    {
        return Err(ImportError::PlatformMismatch {
            expected: arch,
            found: format!(
                "{}/{}{}",
                config.os(),
                config.architecture(),
                config
                    .variant()
                    .as_deref()
                    .map(|v| format!("/{v}"))
                    .unwrap_or_default()
            ),
        });
    }

    let diff_ids = config
        .rootfs()
        .diff_ids()
        .iter()
        .map(|d| Sha256Digest::parse(d))
        .collect::<Result<Vec<_>, _>>()?;
    if diff_ids.len() != manifest.layers().len() {
        return Err(ImportError::LayerCountMismatch {
            layers: manifest.layers().len(),
            diff_ids: diff_ids.len(),
        });
    }
    let layers = manifest
        .layers()
        .iter()
        .zip(diff_ids)
        .map(|(desc, diff_id)| {
            Ok(LayerRef {
                digest: descriptor_digest(desc)?,
                size: desc.size(),
                compression: layer_compression(desc.media_type())?,
                diff_id,
            })
        })
        .collect::<Result<Vec<_>, ImportError>>()?;

    Ok(Resolved {
        index_digest,
        manifest_digest,
        config_digest,
        config,
        layers,
    })
}

/// First pass: hash a layer blob end to end, before its tar is parsed at all.
pub(crate) fn verify_layer_blob(src: &dyn BlobSource, layer: &LayerRef) -> Result<(), ImportError> {
    let reader = open_blob(src, layer.digest)?;
    let mut hashing = HashingReader::new(reader.take(layer.size.saturating_add(1)));
    io::copy(&mut hashing, &mut io::sink()).map_err(|source| ImportError::Io {
        what: format!("layer blob {}", layer.digest),
        source,
    })?;
    let (_, actual, size) = hashing.finish();
    check_blob(BlobRole::Layer, layer.digest, layer.size, actual, size)
}

/// A layer blob's decompressor, which can hand back the compressed stream beneath it.
enum Decoder<R: Read> {
    Plain(R),
    Gzip(MultiGzDecoder<R>),
    Zstd(zstd::stream::read::Decoder<'static, BufReader<R>>),
}

impl<R: Read> Decoder<R> {
    fn new(inner: R, compression: Compression) -> io::Result<Self> {
        Ok(match compression {
            Compression::None => Self::Plain(inner),
            Compression::Gzip => Self::Gzip(MultiGzDecoder::new(inner)),
            Compression::Zstd => Self::Zstd(zstd::stream::read::Decoder::new(inner)?),
        })
    }

    /// The compressed stream. Bytes a decoder buffered were already read from it.
    fn into_inner(self) -> R {
        match self {
            Self::Plain(r) => r,
            Self::Gzip(d) => d.into_inner(),
            Self::Zstd(d) => d.finish().into_inner(),
        }
    }
}

impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(r) => r.read(buf),
            Self::Gzip(d) => d.read(buf),
            Self::Zstd(d) => d.read(buf),
        }
    }
}

/// Second pass: decompress, flatten, and re-verify both digests.
pub(crate) fn apply_layer(
    src: &dyn BlobSource,
    index: usize,
    layer: &LayerRef,
    flattener: &mut Flattener<'_>,
) -> Result<(), ImportError> {
    let reader = open_blob(src, layer.digest)?;
    let compressed = HashingReader::new(reader.take(layer.size.saturating_add(1)));
    let decoded =
        Decoder::new(compressed, layer.compression).map_err(|source| ImportError::LayerRead {
            layer: index,
            source,
        })?;
    let uncompressed = flattener.apply_layer(HashingReader::new(decoded))?;
    let (decoded, diff_id, _) = uncompressed.finish();
    let mut compressed = decoded.into_inner();
    io::copy(&mut compressed, &mut io::sink()).map_err(|source| ImportError::LayerRead {
        layer: index,
        source,
    })?;
    let (_, actual, size) = compressed.finish();
    check_blob(BlobRole::Layer, layer.digest, layer.size, actual, size)?;
    if diff_id != layer.diff_id {
        return Err(ImportError::DiffIdMismatch {
            layer: index,
            expected: layer.diff_id,
            actual: diff_id,
        });
    }
    Ok(())
}
