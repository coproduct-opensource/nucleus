//! A registry, read by the importer as if it were an OCI layout.
//!
//! [`RegistrySource`] is a [`BlobSource`] over the cache's blob store that fetches a
//! blob the first time the importer asks for it. It decides nothing about the
//! image: which index entry matches the platform, which blobs are layers, what
//! every digest must be — all of that is `nucleus_oci_rootfs::import`'s, the same
//! code a local `--oci-layout` goes through. So a registry and a layout of the same
//! image cannot flatten to different bytes (G-1).
//!
//! The one thing it must know that a layout does not: a digest named in an index is
//! a manifest, and a registry serves manifests from `/manifests/`, not `/blobs/`.
//! It learns that by reading the `manifests[].digest` of every index it serves,
//! starting with the pinned one.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::io::{Cursor, Read};

use nucleus_oci_rootfs::{BlobSource, ImportError, LayoutDir, LayoutFile, Sha256Digest};

use super::cache::ImageCache;
use super::registry::{Endpoint, RegistryClient, RegistryError};

const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

/// The fields of a manifest document this module reads: which kind it is, and its children.
#[derive(serde::Deserialize)]
struct ManifestShape {
    #[serde(default, rename = "mediaType")]
    media_type: Option<String>,
    #[serde(default)]
    manifests: Option<Vec<Child>>,
}

#[derive(serde::Deserialize)]
struct Child {
    digest: String,
}

/// See the module docs.
pub struct RegistrySource<'a> {
    client: &'a RegistryClient,
    cache: &'a ImageCache,
    layout: LayoutDir,
    index_json: Vec<u8>,
    manifests: RefCell<BTreeSet<Sha256Digest>>,
    /// Manifests whose children have been read into `manifests`.
    expanded: RefCell<BTreeSet<Sha256Digest>>,
}

fn source_err(what: String, e: RegistryError) -> ImportError {
    ImportError::Source {
        what,
        source: Box::new(e),
    }
}

impl<'a> RegistrySource<'a> {
    /// Fetch the pinned manifest (or index) and present it as the layout's only `index.json` entry.
    pub fn prepare(
        client: &'a RegistryClient,
        cache: &'a ImageCache,
        pinned: Sha256Digest,
    ) -> Result<Self, ImportError> {
        let source = Self {
            client,
            cache,
            layout: cache.layout(),
            index_json: Vec::new(),
            manifests: RefCell::new(BTreeSet::from([pinned])),
            expanded: RefCell::new(BTreeSet::new()),
        };
        let path = client
            .fetch(Endpoint::Manifest, pinned, cache)
            .map_err(|e| source_err(format!("fetching {pinned}"), e))?;
        let bytes = std::fs::read(&path).map_err(|source| ImportError::Io {
            what: path.display().to_string(),
            source,
        })?;
        // The media type is read from the verified bytes, never from a header: the
        // bytes are what the digest vouches for.
        let shape = source.expand(pinned, &bytes)?;
        let media_type = match (shape.media_type, shape.manifests.is_some()) {
            (Some(mt), _) => mt,
            (None, true) => OCI_INDEX.to_owned(),
            (None, false) => OCI_MANIFEST.to_owned(),
        };
        let index = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_INDEX,
            "manifests": [{
                "mediaType": media_type,
                "digest": pinned.to_string(),
                "size": bytes.len(),
            }],
        });
        Ok(Self {
            index_json: serde_json::to_vec(&index).map_err(|e| ImportError::MalformedJson {
                role: nucleus_oci_rootfs::BlobRole::Index,
                detail: e.to_string(),
            })?,
            ..source
        })
    }

    /// Record the children of a manifest document as manifests.
    fn expand(&self, digest: Sha256Digest, bytes: &[u8]) -> Result<ManifestShape, ImportError> {
        let shape: ManifestShape =
            serde_json::from_slice(bytes).map_err(|e| ImportError::MalformedJson {
                role: nucleus_oci_rootfs::BlobRole::Manifest,
                detail: e.to_string(),
            })?;
        for child in shape.manifests.iter().flatten() {
            self.manifests
                .borrow_mut()
                .insert(Sha256Digest::parse(&child.digest)?);
        }
        self.expanded.borrow_mut().insert(digest);
        Ok(shape)
    }
}

impl BlobSource for RegistrySource<'_> {
    fn open(&self, file: LayoutFile) -> Result<Option<Box<dyn Read + '_>>, ImportError> {
        match file {
            LayoutFile::OciLayout => Ok(Some(Box::new(Cursor::new(
                br#"{"imageLayoutVersion":"1.0.0"}"#.as_slice(),
            )))),
            LayoutFile::Index => Ok(Some(Box::new(Cursor::new(self.index_json.as_slice())))),
            LayoutFile::LegacyManifest => Ok(None),
            LayoutFile::Blob(digest) => {
                let is_manifest = self.manifests.borrow().contains(&digest);
                let endpoint = if is_manifest {
                    Endpoint::Manifest
                } else {
                    Endpoint::Blob
                };
                let path = self
                    .client
                    .fetch(endpoint, digest, self.cache)
                    .map_err(|e| source_err(format!("fetching {digest}"), e))?;
                if is_manifest && !self.expanded.borrow().contains(&digest) {
                    let bytes = std::fs::read(&path).map_err(|source| ImportError::Io {
                        what: path.display().to_string(),
                        source,
                    })?;
                    self.expand(digest, &bytes)?;
                }
                self.layout.open(LayoutFile::Blob(digest))
            }
        }
    }
}
