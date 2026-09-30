//! Flatten a local OCI image into one verified, normalized, deterministic rootfs tar.
//!
//! # What this crate does
//!
//! [`import`] takes an image a caller has **pinned by digest**, reads it from a
//! local OCI layout directory ([`LayoutDir`]) or oci-archive ([`OciArchive`]),
//! verifies every blob against the digest that names it, applies its layers
//! for one `linux/<arch>` platform to an in-memory tree under the OCI rules,
//! refuses anything that would reach into the guest paths the runtime owns,
//! and writes the result as one tar whose bytes depend only on the tree.
//!
//! Layer content is never written to the host filesystem by path: layers are
//! read as streams, the tree lives in memory (bounded by [`ImportLimits`]),
//! and the only output is the caller's writer.
//!
//! # Decisions the crate encodes
//!
//! - **Tag-only references are refused** ([`PinnedReference`]): a tag can move.
//! - **Device nodes are dropped and reported**, not refused; sockets cannot
//!   appear in a tar; FIFOs are kept.
//! - **setuid/setgid bits and `security.capability` xattrs are stripped and
//!   recorded.** The emitted tar carries no xattrs, so every other xattr is
//!   dropped and recorded too.
//! - **uid/gid are preserved exactly**; user and group *names* are dropped.
//! - **Reserved guest paths come from the caller** ([`ReservedPaths`]). This
//!   crate has no copy of the table, so it cannot drift from the guest layout.
//! - **A root workload is refused** ([`resolve_workload`]).
//!
//! # What this crate does not do
//!
//! Fetch from a registry, pull by tag, or read a legacy `docker save` archive
//! (one without `index.json`), which is refused by name.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Declared panic-free for the shipped build (the scorecard's `tot` family): an
// importer reading untrusted images must refuse with an `Err`, never abort.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

mod config;
mod digest;
mod emit;
mod error;
mod flatten;
mod layout;
mod limits;
mod path;
mod record;
mod reserved;

use std::io::Write;

pub use config::{WorkloadConfig, resolve_workload};
pub use digest::{PinnedReference, Sha256Digest};
pub use emit::{Emitted, NORMALIZED_MTIME};
pub use error::{BlobRole, ImportError};
pub use flatten::{Flattened, Flattener};
pub use layout::{BlobSource, LayoutDir, LayoutFile, OciArchive};
pub use limits::ImportLimits;
pub use record::{
    Compression, DroppedEntry, DroppedKind, FlattenReport, ImportRecord, LayerRecord, LinuxOs,
    PlatformRecord, RecordedPath, RootfsRecord, StrippedSetId, StrippedXattr,
};
pub use reserved::{ReservedPath, ReservedPaths};

/// A guest CPU architecture this crate imports for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    /// `amd64` (x86_64).
    Amd64,
    /// `arm64` (aarch64).
    Arm64,
}

impl Arch {
    /// The OCI spelling.
    pub fn oci_name(self) -> &'static str {
        match self {
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
        }
    }

    fn matches(self, oci: &oci_spec::image::Arch) -> bool {
        match self {
            Self::Amd64 => *oci == oci_spec::image::Arch::Amd64,
            Self::Arm64 => *oci == oci_spec::image::Arch::ARM64,
        }
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.oci_name())
    }
}

/// A finished import.
#[derive(Debug)]
pub struct Imported {
    /// What was imported, and everything changed on the way.
    pub record: ImportRecord,
    /// The workload the image describes, its user resolved.
    pub workload: WorkloadConfig,
}

/// Import the image `reference` pins from `source` for `linux/<arch>`, writing
/// the flattened rootfs tar to `out`.
///
/// Every check runs before the first byte is written: an `Err` means `out`
/// received nothing.
pub fn import<W: Write>(
    source: &dyn BlobSource,
    reference: &PinnedReference,
    arch: Arch,
    reserved: &ReservedPaths,
    limits: ImportLimits,
    out: W,
) -> Result<Imported, ImportError> {
    let resolved = layout::resolve(source, reference, arch, &limits)?;
    // Every layer is verified before any layer is parsed.
    for layer in &resolved.layers {
        layout::verify_layer_blob(source, layer)?;
    }
    let mut flattener = Flattener::new(reserved, limits);
    for (index, layer) in resolved.layers.iter().enumerate() {
        layout::apply_layer(source, index, layer, &mut flattener)?;
    }
    let flattened = flattener.finish()?;
    let workload = resolve_workload(&resolved.config, &flattened)?;
    let emitted = flattened.emit(out)?;
    let Emitted { rootfs, report } = emitted;
    Ok(Imported {
        record: ImportRecord {
            crate_version: env!("CARGO_PKG_VERSION").to_owned(),
            pinned: reference.digest(),
            index_digest: resolved.index_digest,
            manifest_digest: resolved.manifest_digest,
            config_digest: resolved.config_digest,
            platform: PlatformRecord {
                os: LinuxOs::Linux,
                architecture: arch,
            },
            layers: resolved
                .layers
                .iter()
                .map(|l| LayerRecord {
                    digest: l.digest,
                    diff_id: l.diff_id,
                    size: l.size,
                    compression: l.compression,
                })
                .collect(),
            report,
            limits,
            rootfs,
        },
        workload,
    })
}
