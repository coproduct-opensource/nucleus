//! The pre-mount scan: what a workspace carries for git to execute, read on the
//! host before the pod that receives it exists (ADR 0013, "Repository-borne exec
//! config before approval").
//!
//! # What enters a pod, and where it is read
//!
//! [`sources`] is the one list, exhaustive over the driver (ADR 0007 E-2):
//!
//! - **Firecracker** (and Apple VZ, which shares the spec shape): the caller's
//!   `image.scratch_path`, the ext4 disk the guest mounts at `/work`, and
//!   `image.data_path`, the read-only cache disk. A pod without a caller
//!   scratch gets an empty disk the node makes itself, so nothing enters. A
//!   disk is read with `debugfs rdump` into a private directory under the
//!   node's state, as written: an image whose journal needs recovery is not
//!   read, because the guest would replay it and see a tree the scan did not.
//! - **Container**: `work_dir`, bind-mounted read-write at `/workspace`.
//! - **Local**: `work_dir`, which the workload runs in on this host.
//!
//! Each source is scanned by [`portcullis::git_exec::scan`], the list the
//! command executor's consume guard also reads (G-1).
//!
//! # What each profile does with a finding
//!
//! - **Eval cell**: refused at create, naming every offending path and key. A
//!   scan that could not finish is refused too: "could not look" is never
//!   "looked and it was fine" (A-2). A `*.sample` hook is inert and is not a
//!   finding.
//! - **Standard**: admitted as before, with a warning in the node's log and the
//!   findings recorded in the pod's spec under [`LABEL`], so the signed pod
//!   receipt's `manifest_hash` covers them and a reader of the spec sees them.
//!   That is the pattern the isolation clamp set (`record_isolation`): the node
//!   records what it observed at admission in the spec, rather than changing
//!   what a standard pod is allowed. A clean scan writes no label, so a clean
//!   standard pod's spec and program identity are what they were before this
//!   scan existed. A standard pod's disk images are not read: the read copies
//!   the whole disk, a cost the standard profile does not ask for.

use std::path::{Path, PathBuf};

use nucleus_spec::PodSpec;
use nucleus_spec::isolation_profile::IsolationProfile;
use portcullis::git_exec::{self, Finding};
use tracing::warn;
use uuid::Uuid;

use crate::ApiError;
use crate::driver::DriverKind;

/// The label a standard pod's findings are recorded under.
pub(crate) const LABEL: &str = "workspace.coproduct.one/exec-config";

/// Findings named in a label before the rest are counted.
const LABEL_LISTED: usize = 20;

/// How a source reaches the pod, which decides how it is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Form {
    /// A host directory the pod shares.
    Directory,
    /// An ext4 disk image the guest mounts.
    Image,
}

/// One host path whose contents enter a pod.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Source {
    /// The spec field that names it.
    pub(crate) field: &'static str,
    pub(crate) form: Form,
    pub(crate) path: PathBuf,
}

/// Every host path whose contents enter a pod of `spec` on `driver`.
pub(crate) fn sources(spec: &PodSpec, driver: &DriverKind) -> Vec<Source> {
    let work_dir = || Source {
        field: "work_dir",
        form: Form::Directory,
        path: spec.spec.work_dir.clone(),
    };
    match driver {
        DriverKind::Container => vec![work_dir()],
        #[cfg(feature = "local-driver")]
        DriverKind::Local => vec![work_dir()],
        // `work_dir` is a guest path here; the host's contribution is the disks.
        DriverKind::Firecracker | DriverKind::AppleVz => {
            let Some(image) = spec.spec.image.as_ref() else {
                return Vec::new();
            };
            [
                ("image.scratch_path", image.scratch_path.as_ref()),
                ("image.data_path", image.data_path.as_ref()),
            ]
            .into_iter()
            .filter_map(|(field, path)| {
                path.map(|p| Source {
                    field,
                    form: Form::Image,
                    path: p.clone(),
                })
            })
            .collect()
        }
    }
}

/// What reading one source found.
#[derive(Debug)]
pub(crate) enum Read {
    /// Scanned to the end. Empty: nothing git would execute.
    Scanned(Vec<Finding>),
    /// Could not be scanned to the end, and why.
    CouldNotLook(String),
    /// Not read under this profile (a standard pod's disk image).
    Skipped,
}

/// Whether `profile` reads a source of `form`. Exhaustive, no `_` (E-2).
fn reads(profile: IsolationProfile, form: Form) -> bool {
    match (profile, form) {
        (IsolationProfile::EvalCell, Form::Directory | Form::Image)
        | (IsolationProfile::Standard, Form::Directory) => true,
        (IsolationProfile::Standard, Form::Image) => false,
    }
}

/// Read one source. Blocking: a directory walk, or a disk copied out and walked.
fn read(source: &Source, profile: IsolationProfile, staging: &Path) -> Read {
    if !reads(profile, source.form) {
        return Read::Skipped;
    }
    let scanned = |root: &Path| match git_exec::scan(root) {
        Ok(found) => Read::Scanned(found),
        Err(e) => Read::CouldNotLook(e.to_string()),
    };
    match source.form {
        Form::Directory => scanned(&source.path),
        Form::Image => {
            let out = staging.join(source.field);
            if let Err(e) = std::fs::create_dir_all(&out) {
                return Read::CouldNotLook(format!("staging {}: {e}", out.display()));
            }
            let read = match nucleus_microvm_host::scratch_readback::dump_tree_as_written(
                &source.path,
                &out,
            ) {
                Ok(()) => scanned(&out),
                Err(e) => Read::CouldNotLook(e.to_string()),
            };
            if let Err(e) = std::fs::remove_dir_all(&out) {
                warn!(path = %out.display(), error = %e, "workspace scan: staging not removed");
            }
            read
        }
    }
}

/// An eval cell refused for what its workspace carries.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "the eval-cell profile is refused: the workspace carries configuration git would execute \
     before any approval: {listing}. Remove it (a `.sample` hook is inert and may stay), or \
     run the pod under the standard profile (ADR 0013)"
)]
pub(crate) struct Refused {
    pub(crate) listing: String,
}

/// Decide `profile` over what was read. Pure.
///
/// `Ok(None)`: admitted, nothing to record. `Ok(Some(v))`: a standard pod,
/// admitted, with `v` recorded under [`LABEL`].
pub(crate) fn decide(
    profile: IsolationProfile,
    reads: &[(Source, Read)],
) -> Result<Option<String>, Refused> {
    let mut items: Vec<String> = Vec::new();
    for (source, read) in reads {
        match read {
            Read::Scanned(found) => {
                items.extend(found.iter().map(|f| format!("{}: {f}", source.field)));
            }
            Read::CouldNotLook(why) => {
                items.push(format!("{} could not be scanned ({why})", source.field))
            }
            Read::Skipped => {}
        }
    }
    if items.is_empty() {
        return Ok(None);
    }
    match profile {
        IsolationProfile::EvalCell => Err(Refused {
            listing: items.join("; "),
        }),
        IsolationProfile::Standard => {
            let total = items.len();
            let mut value = items
                .into_iter()
                .take(LABEL_LISTED)
                .collect::<Vec<_>>()
                .join("; ");
            if total > LABEL_LISTED {
                value.push_str(&format!("; and {} more", total - LABEL_LISTED));
            }
            Ok(Some(value))
        }
    }
}

/// Scan what enters the pod `id`, and refuse or record by `profile`.
///
/// Called from `create_pod_internal` after `host_paths::admit` (every path is
/// confined and resolved) and the eval-cell admission (the profile is known),
/// and before any driver runs.
pub(crate) async fn admit(
    state_dir: &Path,
    driver: &DriverKind,
    spec: &mut PodSpec,
    profile: IsolationProfile,
    id: Uuid,
) -> Result<(), ApiError> {
    // The node's record, never the caller's: a value a caller wrote is dropped,
    // so the label says only what this scan found.
    spec.metadata.labels.remove(LABEL);
    let sources = sources(spec, driver);
    if sources.is_empty() {
        return Ok(());
    }
    let staging = state_dir.join("workspace-scan").join(id.to_string());
    let read_staging = staging.clone();
    let reads = tokio::task::spawn_blocking(move || {
        sources
            .into_iter()
            .map(|s| {
                let r = read(&s, profile, &read_staging);
                (s, r)
            })
            .collect::<Vec<_>>()
    })
    .await
    .map_err(|e| ApiError::Driver(format!("workspace scan did not finish: {e}")))?;
    // Only the per-pod directory; a sibling pod's staging is its own.
    match std::fs::remove_dir_all(&staging) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            warn!(path = %staging.display(), error = %e, "workspace scan: staging not removed")
        }
    }
    match decide(profile, &reads) {
        Ok(None) => Ok(()),
        Ok(Some(recorded)) => {
            warn!(
                pod_id = %id,
                findings = %recorded,
                "workspace carries configuration git would execute; admitted under the standard \
                 profile and recorded in the spec's {LABEL} label"
            );
            spec.metadata.labels.insert(LABEL.to_string(), recorded);
            Ok(())
        }
        Err(refused) => Err(ApiError::InvalidSpec(refused.to_string())),
    }
}

#[cfg(test)]
#[path = "workspace_scan_tests.rs"]
mod tests;
