//! Confining a caller-supplied `image.scratch_path` to one node directory.
//!
//! # The defect this closes
//!
//! `ImageSpec.scratch_path` is written by whoever creates the pod, and the
//! Firecracker path hard-links it into the jail as the guest's WRITABLE second
//! drive (`firecracker_config::jail_resources`, `Placement::HardLinkOnly`). Nothing
//! checked where it pointed. A pod creator could name the node's own CA key under
//! `<state-dir>/ca/`, or any other file the node can read and link, and the guest
//! would get it as a block device it can read and overwrite. `scratch_digest` does
//! not help: it is optional, and a caller who names the file can also measure it.
//!
//! # The rule
//!
//! A caller-supplied `scratch_path` must contain no `..` and must resolve —
//! every symlink followed — to a regular file strictly inside `--scratch-root`
//! (default `<state-dir>/scratch`). The resolved path replaces the one in the spec,
//! so what the jail links is what was checked rather than a name that is resolved
//! again later. A relative path resolves against the node's working directory
//! and is held to the same rule, which keeps the examples' `./build/...` specs
//! working under a matching `--scratch-root`. Refused at admission, before the driver runs, so no hard link is
//! ever attempted for a refused path.
//!
//! The node-provisioned scratch disk (`scratch_for_pod`) is decided after this
//! and does not pass through it: the node chooses that path itself.
//!
//! # What this does not cover
//!
//! - **Someone who can write inside the root.** A hard link placed there by a
//!   local user aliases whatever file they could already link. The threat here is
//!   a remote pod creator who can only NAME paths.
//! - **The other image paths.** `rootfs_path`, `kernel_path` and `data_path` are
//!   caller-supplied host paths with no confinement either; `data_path` is placed
//!   into the jail as a readable drive. That is the same class and is not fixed
//!   here.

use std::path::{Component, Path, PathBuf};

use nucleus_spec::PodSpec;

use crate::api_error::ApiError;

/// `--scratch-root`, flattened into the node's `Args`.
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct ScratchArgs {
    /// The only directory a caller-supplied `image.scratch_path` may name a file
    /// in. Symlinks are resolved before the check. Defaults to
    /// `<state-dir>/scratch`, which is created at startup.
    #[arg(long = "scratch-root", env = "NUCLEUS_NODE_SCRATCH_ROOT")]
    pub scratch_root: Option<PathBuf>,
}

impl ScratchArgs {
    /// The root in force, created if absent so a fresh node can accept a seeded
    /// scratch image without a separate setup step.
    pub(crate) fn ensure(&self, state_dir: &Path) -> std::io::Result<PathBuf> {
        let root = self
            .scratch_root
            .clone()
            .unwrap_or_else(|| state_dir.join("scratch"));
        std::fs::create_dir_all(&root)?;
        Ok(root)
    }
}

/// Why a caller-supplied scratch path was refused. Every arm is a refusal; there
/// is no "could not tell, allow it" case.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A `..` component, refused lexically even when it would land inside.
    ParentComponent(PathBuf),
    /// The path does not resolve (missing, a dangling symlink, unreadable).
    Unresolvable { path: PathBuf, error: String },
    /// The root itself does not resolve, so nothing can be shown to be inside it.
    RootUnresolvable { root: PathBuf, error: String },
    /// It resolves somewhere that is not strictly inside the root.
    Outside { resolved: PathBuf, root: PathBuf },
    /// It resolves inside the root but is not a regular file.
    NotRegularFile(PathBuf),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::ParentComponent(p) => {
                write!(f, "scratch_path {} must not contain `..`", p.display())
            }
            Refusal::Unresolvable { path, error } => {
                write!(
                    f,
                    "scratch_path {} does not resolve: {error}",
                    path.display()
                )
            }
            Refusal::RootUnresolvable { root, error } => write!(
                f,
                "the node's scratch root {} does not resolve ({error}), so no caller-supplied \
                 scratch_path can be admitted",
                root.display()
            ),
            Refusal::Outside { resolved, root } => write!(
                f,
                "scratch_path resolves to {}, which is not inside the node's scratch root {} \
                 (--scratch-root); a writable guest disk may only come from there",
                resolved.display(),
                root.display()
            ),
            Refusal::NotRegularFile(p) => {
                write!(f, "scratch_path {} is not a regular file", p.display())
            }
        }
    }
}

/// Resolve `path` and return it only if it is a regular file strictly inside `root`.
pub(crate) fn confine(path: &Path, root: &Path) -> Result<PathBuf, Refusal> {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(Refusal::ParentComponent(path.to_path_buf()));
    }
    let root = root.canonicalize().map_err(|e| Refusal::RootUnresolvable {
        root: root.to_path_buf(),
        error: e.to_string(),
    })?;
    let resolved = path.canonicalize().map_err(|e| Refusal::Unresolvable {
        path: path.to_path_buf(),
        error: e.to_string(),
    })?;
    if resolved == root || !resolved.starts_with(&root) {
        return Err(Refusal::Outside { resolved, root });
    }
    match std::fs::metadata(&resolved) {
        Ok(m) if m.is_file() => Ok(resolved),
        _ => Err(Refusal::NotRegularFile(resolved)),
    }
}

/// Admission: confine the spec's caller-supplied scratch path, if any, and
/// replace it with the resolved path that was checked.
pub(crate) fn admit(spec: &mut PodSpec, root: &Path) -> Result<(), ApiError> {
    let Some(image) = spec.spec.image.as_mut() else {
        return Ok(());
    };
    let Some(requested) = image.scratch_path.as_ref() else {
        return Ok(());
    };
    let resolved = confine(requested, root).map_err(|r| ApiError::InvalidSpec(r.to_string()))?;
    image.scratch_path = Some(resolved);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_with_scratch(path: &Path) -> PodSpec {
        let mut spec: PodSpec = serde_json::from_str(
            r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"image":{
                "kernel_path":"/k","rootfs_path":"/r"}}}"#,
        )
        .expect("minimal spec");
        spec.spec.image.as_mut().expect("image").scratch_path = Some(path.to_path_buf());
        spec
    }

    /// A node state dir laid out as provisioning makes it: the CA beside the
    /// scratch root, both under one state dir.
    fn node() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let state = tempfile::tempdir().expect("state dir");
        let root = ScratchArgs { scratch_root: None }
            .ensure(state.path())
            .expect("scratch root");
        let ca = state.path().join("ca");
        std::fs::create_dir_all(&ca).expect("ca dir");
        let key = ca.join("ca.key");
        std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----").expect("ca key");
        (state, root, key)
    }

    /// THE defect: the node's CA key named as a pod's writable scratch disk.
    #[test]
    fn the_node_ca_key_is_refused_as_scratch() {
        let (_state, root, key) = node();
        let mut spec = spec_with_scratch(&key);
        let err = admit(&mut spec, &root).expect_err("the CA key must never become a guest disk");
        assert!(matches!(err, ApiError::InvalidSpec(_)), "{err:?}");
        assert!(err.to_string().contains("--scratch-root"), "{err}");
    }

    #[test]
    fn a_symlink_inside_the_root_pointing_outside_is_refused() {
        let (_state, root, key) = node();
        let link = root.join("innocent.ext4");
        std::os::unix::fs::symlink(&key, &link).expect("symlink");
        let refusal = confine(&link, &root).expect_err("a symlink out must not pass");
        assert!(matches!(refusal, Refusal::Outside { .. }), "{refusal:?}");
    }

    #[test]
    fn a_parent_component_is_refused_even_when_it_lands_inside() {
        let (_state, root, _key) = node();
        std::fs::write(root.join("a.ext4"), b"x").expect("image");
        std::fs::create_dir_all(root.join("sub")).expect("sub");
        let dotted = root.join("sub").join("..").join("a.ext4");
        assert!(matches!(
            confine(&dotted, &root),
            Err(Refusal::ParentComponent(_))
        ));
        let escaping = root.join("..").join("ca").join("ca.key");
        assert!(matches!(
            confine(&escaping, &root),
            Err(Refusal::ParentComponent(_))
        ));
    }

    /// Non-vacuity: a real file inside the root is admitted, and the spec then
    /// names the resolved path the check actually looked at.
    #[test]
    fn a_regular_file_inside_the_root_is_admitted_and_resolved() {
        let (_state, root, _key) = node();
        let image = root.join("workspace.ext4");
        std::fs::write(&image, b"ext4 bytes").expect("image");
        let mut spec = spec_with_scratch(&image);
        admit(&mut spec, &root).expect("a file inside the root is admitted");
        let admitted = spec.spec.image.expect("image").scratch_path.expect("kept");
        assert_eq!(admitted, image.canonicalize().expect("canonical"));
    }

    #[test]
    fn the_root_itself_a_directory_and_a_missing_file_are_refused() {
        let (_state, root, _key) = node();
        assert!(matches!(
            confine(&root, &root),
            Err(Refusal::Outside { .. })
        ));
        std::fs::create_dir_all(root.join("dir")).expect("dir");
        assert!(matches!(
            confine(&root.join("dir"), &root),
            Err(Refusal::NotRegularFile(_))
        ));
        assert!(matches!(
            confine(&root.join("missing.ext4"), &root),
            Err(Refusal::Unresolvable { .. })
        ));
    }

    /// A spec with no scratch path is untouched; the node provisions its own later.
    #[test]
    fn a_spec_without_scratch_is_untouched() {
        let (_state, root, _key) = node();
        let mut spec = spec_with_scratch(Path::new("/unused"));
        spec.spec.image.as_mut().expect("image").scratch_path = None;
        admit(&mut spec, &root).expect("nothing to confine");
        assert!(spec.spec.image.expect("image").scratch_path.is_none());
    }

    /// Wired: `create_pod_internal` calls `admit` at function-body level, before
    /// any driver spawns (and so before any jail placement hard-links a file).
    #[test]
    fn create_pod_internal_confines_scratch_before_spawning() {
        let main = include_str!("main.rs");
        let body = main
            .find("async fn create_pod_internal(")
            .expect("create_pod_internal exists");
        let call = main[body..]
            .find("scratch_root::admit(&mut spec, &state.scratch_root)?;")
            .map(|i| body + i)
            .expect("create_pod_internal must confine the caller's scratch_path");
        let spawn = main[body..]
            .find("let spawned = match state.driver")
            .map(|i| body + i)
            .expect("the spawn is in create_pod_internal");
        assert!(call < spawn, "confined before any driver runs");
        let indent = main[..call].rsplit('\n').next().unwrap_or("");
        assert_eq!(
            indent, "    ",
            "at function-body level, not under a condition"
        );
    }
}
