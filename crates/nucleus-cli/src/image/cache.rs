//! The image cache under the nucleus data directory.
//!
//! ```text
//! <cache>/
//!   oci/oci-layout                     an OCI layout's marker; the blob store below is one
//!   oci/blobs/sha256/<hex>             every fetched manifest, config and layer, by digest
//!   rootfs/sha256/<hex>/rootfs.tar     a flattened rootfs, by the digest of the tar
//!   rootfs/sha256/<hex>/import.json    the import record that produced it
//!   tmp/                               downloads and tars in flight; never read as content
//! ```
//!
//! Nothing reaches a content-addressed path except by `rename` from `tmp/`, and a
//! blob only after its digest was verified ([`ImageCache::store`]). The importer
//! re-verifies every blob it reads, so a cache file altered after the fact is
//! refused at import rather than trusted.

use std::fs::{self, File};
use std::io;
use std::path::PathBuf;

use nucleus_oci_rootfs::{LayoutDir, Sha256Digest};

use super::registry::RegistryError;

/// A file in `tmp/` that is removed unless it was renamed into place.
struct TempFile {
    path: PathBuf,
    armed: bool,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// The on-disk cache. See the module docs for its layout.
#[derive(Clone, Debug)]
pub struct ImageCache {
    root: PathBuf,
}

fn io_err(what: impl Into<String>) -> impl FnOnce(io::Error) -> RegistryError {
    let what = what.into();
    move |source| RegistryError::Io { what, source }
}

impl ImageCache {
    /// The default location: `<data dir>/nucleus/images`.
    pub fn default_root() -> Option<PathBuf> {
        dirs::data_local_dir().map(|d| d.join("nucleus").join("images"))
    }

    /// Open (creating if needed) the cache rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, RegistryError> {
        let cache = Self { root: root.into() };
        for dir in [
            cache.blobs_dir(),
            cache.tmp_dir(),
            cache.root.join("rootfs/sha256"),
        ] {
            fs::create_dir_all(&dir).map_err(io_err(dir.display().to_string()))?;
        }
        let marker = cache.oci_root().join("oci-layout");
        if !marker.exists() {
            fs::write(&marker, br#"{"imageLayoutVersion":"1.0.0"}"#)
                .map_err(io_err(marker.display().to_string()))?;
        }
        Ok(cache)
    }

    /// The root of the blob store, an OCI layout without an `index.json` of its own.
    pub fn oci_root(&self) -> PathBuf {
        self.root.join("oci")
    }

    /// The blob store as the importer reads it.
    pub fn layout(&self) -> LayoutDir {
        LayoutDir::new(self.oci_root())
    }

    fn blobs_dir(&self) -> PathBuf {
        self.oci_root().join("blobs/sha256")
    }

    fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    fn blob_path(&self, digest: Sha256Digest) -> PathBuf {
        self.blobs_dir().join(digest.hex())
    }

    /// The cached blob for `digest`, if present.
    pub fn blob(&self, digest: Sha256Digest) -> Option<PathBuf> {
        let p = self.blob_path(digest);
        p.is_file().then_some(p)
    }

    fn temp(&self, what: &str) -> Result<(TempFile, File), RegistryError> {
        let path = self
            .tmp_dir()
            .join(format!("{}.partial", uuid::Uuid::new_v4().simple()));
        let file = File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(io_err(format!("{what}: {}", path.display())))?;
        Ok((TempFile { path, armed: true }, file))
    }

    /// Write `digest` through `fill`, which must verify it; rename into place only on `Ok`.
    pub fn store(
        &self,
        digest: Sha256Digest,
        what: &str,
        fill: impl FnOnce(&mut File) -> Result<(), RegistryError>,
    ) -> Result<PathBuf, RegistryError> {
        let (mut temp, mut file) = self.temp(what)?;
        fill(&mut file)?;
        drop(file);
        let dest = self.blob_path(digest);
        fs::rename(&temp.path, &dest).map_err(io_err(format!("{what}: {}", dest.display())))?;
        temp.armed = false;
        Ok(dest)
    }

    /// Write a flattened rootfs through `write`, then file it under its own digest.
    ///
    /// `write` returns the tar's digest (from the import record, which hashed every
    /// byte it emitted) and the record JSON to keep beside it.
    pub fn stage_rootfs<T>(
        &self,
        write: impl FnOnce(&mut File) -> anyhow::Result<(Sha256Digest, Vec<u8>, T)>,
    ) -> anyhow::Result<(PathBuf, T)> {
        let (mut temp, mut file) = self.temp("rootfs.tar")?;
        let (digest, record, extra) = write(&mut file)?;
        file.sync_all()?;
        drop(file);
        let dir = self.root.join("rootfs/sha256").join(digest.hex());
        fs::create_dir_all(&dir)?;
        let tar = dir.join("rootfs.tar");
        fs::rename(&temp.path, &tar)?;
        temp.armed = false;
        let (mut rec_temp, rec_file) = self.temp("import.json")?;
        drop(rec_file);
        fs::write(&rec_temp.path, record)?;
        fs::rename(&rec_temp.path, dir.join("import.json"))?;
        rec_temp.armed = false;
        Ok((dir, extra))
    }
}
