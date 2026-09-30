//! Confining every host path a pod creator writes into its spec to the one node
//! directory that path's ROLE may come from.
//!
//! # The defect this closes
//!
//! A `PodSpec` is written by whoever creates the pod — an operator, a pod
//! delegating to a child, and (with federation) another tenant's node. Several of
//! its fields are HOST paths the node then opens, links or mounts on the
//! creator's behalf, and until 2026-09-29 none of them was checked:
//!
//! - `image.data_path` is placed into the jail and attached to the guest as a
//!   readable drive (`firecracker_config::jail_resources`). Naming the node's CA
//!   key under `<state-dir>/ca/`, or any root-readable host file, handed its bytes
//!   to the guest. That is a cross-tenant secret read, measured: before this
//!   module, a spec with `data_path` = the CA key and `kernel_path` =
//!   `rootfs_path` = `/etc/shadow` was ADMITTED
//!   (`a_node_ca_key_is_refused_as_data`, red on the parent commit).
//! - `image.kernel_path` and `image.rootfs_path` are booted, so a creator could
//!   boot the guest from any host file, and a `read_only: false` rootfs is
//!   hard-linked writable.
//! - `image.scratch_path` is the guest's writable second drive; #3070 confined it
//!   alone, in `scratch_root.rs`, which this module replaces.
//! - `spec.work_dir`, under the container driver, is bind-mounted read-write at
//!   `/workspace` — `work_dir: /var/lib/nucleus/state` gave the container the CA.
//! - `seccomp.filter_path` is copied into the jail for the VMM to load, and
//!   `cgroup.path` plus each `settings[].file` are WRITTEN as root on the
//!   direct-spawn path (`cgroup::apply_cgroup`). Production builds refuse both
//!   already (`admit_seccomp`; `--firecracker-jailer` cannot be turned off, and the
//!   jailer ignores `cgroup.path`), so these are reachable only in `local-driver`
//!   builds. They are confined here anyway, because "a different gate happens to
//!   refuse it first" is not a property of this field.
//!
//! # The rule: one decider, by role
//!
//! [`admit`] is the only place a spec's host path is decided, and it runs from
//! `create_pod_internal` before anything reads the spec's paths — the posture
//! gate's rootfs measurement, any driver, any hard link or attach. Each path has a
//! [`Role`], and `Role::root` maps every role to its root in one exhaustive
//! match (ADR 0007 A-rules: a new role is a compile error there before it is an
//! unconfined path):
//!
//! | role                 | root                                    | shape     |
//! |----------------------|-----------------------------------------|-----------|
//! | kernel, rootfs, seccomp filter | `--artifacts-root` (default the provisioned `HOST_ARTIFACTS_DIR`) | file |
//! | scratch              | `--scratch-root` (default `<state>/scratch`)   | file  |
//! | data                 | `--data-root` (default `<state>/data`)         | file  |
//! | container `work_dir` | `--workspace-root` (default `<state>/workspaces`) | directory |
//! | cgroup               | `/sys/fs/cgroup`, lexically             | directory |
//!
//! A resolved path must contain no `..` and must resolve — every symlink
//! followed — to a file (or directory) of the role's shape strictly inside its
//! root. The resolved path REPLACES the one in the spec, so what the jail links
//! is what was checked, not a name resolved again later; `image_identity`'s digest
//! checks then read those same paths (or the jail copies of them) unchanged. A
//! relative path resolves against the node's working directory and is held to the
//! same rule, which keeps the examples' `./build/firecracker/...` specs working
//! under `--artifacts-root ./build/firecracker --scratch-root ./build/firecracker`.
//! The cgroup path is checked lexically because it names a directory the node
//! creates, and cgroupfs has no symlinks for a caller to plant.
//!
//! Which fields are host paths is decided by destructuring `PodSpecInner`,
//! `ImageSpec` and `CgroupSpec` without `..` (E-rule): a new spec field does not
//! compile here until someone says whether it is a host path.
//!
//! `work_dir` is a host path only for the container driver. Under Firecracker it
//! is a guest path (a microVM shares no host directory; `pod_receipt` stopped
//! reading it on the host), the Apple VZ driver boots nothing yet, and the local
//! driver runs the workload as a host process with no isolation to protect —
//! confining a path there would be decoration. The container default `.` was
//! never a valid bind source (Docker reads it as a volume name and refuses), so
//! a container pod must now name a `work_dir` inside `--workspace-root`.
//!
//! # What this does not cover
//!
//! - **Someone who can write inside a root.** A hard link placed there by a local
//!   user aliases whatever file they could already link. The threat here is a
//!   remote pod creator who can only NAME paths.
//! - **Overlapping roots.** Nothing stops an operator pointing `--scratch-root` at
//!   the artifacts directory (the examples do, for a dev tree); a pod could then
//!   take the shared rootfs as its writable scratch disk. Roots are the operator's
//!   choice; provisioned nodes keep them disjoint.
//! - **A writable rootfs.** `read_only: false` still hard-links the rootfs from
//!   `--artifacts-root` writable (#2784). It can no longer be a host secret, but it
//!   can be the shared artifact; that is `ImageSpec::read_only`'s default-true, not
//!   this module.
//! - **`credentials.workload_identity[].source`** (`static_file` path, SPIFFE
//!   `socket_path`) is a host path no runtime reads yet. The runtime that reads it
//!   must add a role here.
//! - **The jailer's own `--cgroup file=value`.** `settings[].file` is held to one
//!   path component here, which also keeps it from steering the jailer's write.

use std::path::{Component, Path, PathBuf};

use nucleus_spec::{CgroupSpec, ImageSpec, PodSpec, PodSpecInner, SeccompSpec};

use crate::api_error::ApiError;
use crate::driver::DriverKind;

/// The only place cgroup placement may write. Lexical: see the module docs.
const CGROUP_FS: &str = "/sys/fs/cgroup";

/// The node's root flags, flattened into `Args`.
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct HostPathArgs {
    /// The only directory a caller-supplied `image.scratch_path` may name a file
    /// in. Symlinks are resolved before the check. Defaults to
    /// `<state-dir>/scratch`, which is created at startup.
    #[arg(long = "scratch-root", env = "NUCLEUS_NODE_SCRATCH_ROOT")]
    pub scratch_root: Option<PathBuf>,
    /// The only directory a pod's `image.kernel_path`, `image.rootfs_path` and
    /// custom seccomp `filter_path` may name a file in. Not created: an absent
    /// artifacts root admits no microVM pod.
    #[arg(
        long = "artifacts-root",
        env = "NUCLEUS_NODE_ARTIFACTS_ROOT",
        default_value = nucleus_spec::tier2_artifacts::HOST_ARTIFACTS_DIR
    )]
    pub artifacts_root: PathBuf,
    /// The only directory a pod's read-only `image.data_path` may name a file in.
    /// Defaults to `<state-dir>/data`, which is created at startup.
    #[arg(long = "data-root", env = "NUCLEUS_NODE_DATA_ROOT")]
    pub data_root: Option<PathBuf>,
    /// The only directory a container-driver pod's `work_dir` may be (a directory
    /// strictly inside it), since that directory is bind-mounted read-write.
    /// Defaults to `<state-dir>/workspaces`, which is created at startup.
    #[arg(long = "workspace-root", env = "NUCLEUS_NODE_WORKSPACE_ROOT")]
    pub workspace_root: Option<PathBuf>,
}

/// The roots in force. No `Default`: a root is a grant, and there is no neutral one.
#[derive(Debug, Clone)]
pub(crate) struct Roots {
    scratch: PathBuf,
    artifacts: PathBuf,
    data: PathBuf,
    workspace: PathBuf,
}

impl HostPathArgs {
    /// The roots in force. The per-node ones (under the state dir by default) are
    /// created if absent, so a fresh node can accept a staged image without a
    /// separate setup step; the artifacts root is installed, never created.
    pub(crate) fn ensure(&self, state_dir: &Path) -> std::io::Result<Roots> {
        let under_state = |set: &Option<PathBuf>, name: &str| -> std::io::Result<PathBuf> {
            let root = set.clone().unwrap_or_else(|| state_dir.join(name));
            std::fs::create_dir_all(&root)?;
            Ok(root)
        };
        Ok(Roots {
            scratch: under_state(&self.scratch_root, "scratch")?,
            artifacts: self.artifacts_root.clone(),
            data: under_state(&self.data_root, "data")?,
            workspace: under_state(&self.workspace_root, "workspaces")?,
        })
    }
}

/// What a caller-supplied host path is FOR, which decides where it may come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Kernel,
    Rootfs,
    Scratch,
    Data,
    SeccompFilter,
    ContainerWorkDir,
    Cgroup,
}

/// Which node directory a role's path may come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootName {
    Artifacts,
    Scratch,
    Data,
    Workspace,
    /// Checked lexically: see the module docs.
    CgroupFs,
}

impl RootName {
    /// The flag that sets it, for the refusal message.
    fn flag(self) -> &'static str {
        match self {
            RootName::Artifacts => "--artifacts-root",
            RootName::Scratch => "--scratch-root",
            RootName::Data => "--data-root",
            RootName::Workspace => "--workspace-root",
            RootName::CgroupFs => "the cgroup filesystem",
        }
    }
}

impl Roots {
    fn get(&self, name: RootName) -> &Path {
        match name {
            RootName::Artifacts => &self.artifacts,
            RootName::Scratch => &self.scratch,
            RootName::Data => &self.data,
            RootName::Workspace => &self.workspace,
            RootName::CgroupFs => Path::new(CGROUP_FS),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    File,
    Directory,
}

impl Role {
    /// The spec field, for the refusal message.
    fn field(self) -> &'static str {
        match self {
            Role::Kernel => "image.kernel_path",
            Role::Rootfs => "image.rootfs_path",
            Role::Scratch => "image.scratch_path",
            Role::Data => "image.data_path",
            Role::SeccompFilter => "seccomp.filter_path",
            Role::ContainerWorkDir => "work_dir",
            Role::Cgroup => "cgroup.path",
        }
    }

    /// THE decision: which root each role may name a path in. Exhaustive, and
    /// the only place it is written.
    fn root(self) -> RootName {
        match self {
            Role::Kernel | Role::Rootfs | Role::SeccompFilter => RootName::Artifacts,
            Role::Scratch => RootName::Scratch,
            Role::Data => RootName::Data,
            Role::ContainerWorkDir => RootName::Workspace,
            Role::Cgroup => RootName::CgroupFs,
        }
    }

    /// Whether the path names a file or a directory.
    fn shape(self) -> Shape {
        match self {
            Role::ContainerWorkDir | Role::Cgroup => Shape::Directory,
            Role::Kernel | Role::Rootfs | Role::Scratch | Role::Data | Role::SeccompFilter => {
                Shape::File
            }
        }
    }
}

/// Why a caller-supplied host path was refused. Every arm is a refusal; there is
/// no "could not tell, allow it" case.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub role: Role,
    pub reason: Reason,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    /// A `..` component, refused lexically even when it would land inside.
    ParentComponent(PathBuf),
    /// The path does not resolve (missing, a dangling symlink, unreadable).
    Unresolvable { path: PathBuf, error: String },
    /// The root itself does not resolve, so nothing can be shown to be inside it.
    RootUnresolvable { root: PathBuf, error: String },
    /// It resolves somewhere that is not strictly inside the root.
    Outside { resolved: PathBuf, root: PathBuf },
    /// It is inside the root but not the role's shape (a file, or a directory).
    WrongShape(PathBuf),
    /// A cgroup setting's file name is not exactly one path component.
    NotOneComponent(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let field = self.role.field();
        let flag = self.role.root().flag();
        match &self.reason {
            Reason::ParentComponent(p) => {
                write!(f, "{field} {} must not contain `..`", p.display())
            }
            Reason::Unresolvable { path, error } => {
                write!(f, "{field} {} does not resolve: {error}", path.display())
            }
            Reason::RootUnresolvable { root, error } => write!(
                f,
                "the node's root for {field}, {} ({flag}), does not resolve ({error}), so no \
                 caller-supplied {field} can be admitted",
                root.display()
            ),
            Reason::Outside { resolved, root } => write!(
                f,
                "{field} resolves to {}, which is not inside the node's root {} ({flag}); \
                 a pod may only name a host path there",
                resolved.display(),
                root.display()
            ),
            Reason::WrongShape(p) => {
                let shape = match self.role.shape() {
                    Shape::File => "a regular file",
                    Shape::Directory => "a directory",
                };
                write!(f, "{field} {} is not {shape}", p.display())
            }
            Reason::NotOneComponent(file) => write!(
                f,
                "cgroup setting file {file:?} must be a single file name inside cgroup.path"
            ),
        }
    }
}

/// Return `path` resolved, only if it is `role`'s shape strictly inside `role`'s root.
pub(crate) fn confine(path: &Path, role: Role, roots: &Roots) -> Result<PathBuf, Refusal> {
    let refuse = |reason| Refusal { role, reason };
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(refuse(Reason::ParentComponent(path.to_path_buf())));
    }
    let name = role.root();
    let root = roots.get(name);
    if name == RootName::CgroupFs {
        // Lexical: absolute, no `..` (above), strictly under the root.
        if path.is_absolute() && path != root && path.starts_with(root) {
            return Ok(path.to_path_buf());
        }
        return Err(refuse(Reason::Outside {
            resolved: path.to_path_buf(),
            root: root.to_path_buf(),
        }));
    }
    let root = root.canonicalize().map_err(|e| {
        refuse(Reason::RootUnresolvable {
            root: root.to_path_buf(),
            error: e.to_string(),
        })
    })?;
    let resolved = path.canonicalize().map_err(|e| {
        refuse(Reason::Unresolvable {
            path: path.to_path_buf(),
            error: e.to_string(),
        })
    })?;
    if resolved == root || !resolved.starts_with(&root) {
        return Err(refuse(Reason::Outside { resolved, root }));
    }
    let fits = std::fs::metadata(&resolved).is_ok_and(|m| match role.shape() {
        Shape::File => m.is_file(),
        Shape::Directory => m.is_dir(),
    });
    if fits {
        Ok(resolved)
    } else {
        Err(refuse(Reason::WrongShape(resolved)))
    }
}

/// Whether `work_dir` names a HOST directory under this driver. Exhaustive, so a
/// new driver decides it rather than inheriting "no".
fn work_dir_role(driver: &DriverKind) -> Option<Role> {
    match driver {
        DriverKind::Container => Some(Role::ContainerWorkDir),
        // A guest path: nothing on the host is opened at it.
        DriverKind::Firecracker | DriverKind::AppleVz => None,
        // The workload IS a host process; there is no boundary to confine for.
        #[cfg(feature = "local-driver")]
        DriverKind::Local => None,
    }
}

/// Admission: confine every host path in the spec by its role and replace each
/// with the resolved path that was checked. Refuses the whole spec on the first
/// path that fails.
pub(crate) fn admit(
    spec: &mut PodSpec,
    driver: &DriverKind,
    roots: &Roots,
) -> Result<(), ApiError> {
    admit_inner(&mut spec.spec, driver, roots).map_err(|r| ApiError::InvalidSpec(r.to_string()))
}

fn admit_inner(spec: &mut PodSpecInner, driver: &DriverKind, roots: &Roots) -> Result<(), Refusal> {
    // No `..`: a field added to the spec is a compile error here until it is
    // classified as a host path or not (E-rule).
    let PodSpecInner {
        work_dir,
        timeout_seconds: _,
        policy: _,
        budget_model: _,
        resources: _,
        network: _,
        image,
        credentialed_egress: _,
        workload: _, // guest command and guest-relative artifact paths
        vsock: _,
        seccomp,
        cgroup,
        audit_sink: _,
        // `workload_identity[].source` carries host paths no runtime reads yet;
        // see "What this does not cover".
        credentials: _,
    } = spec;

    if let Some(role) = work_dir_role(driver) {
        *work_dir = confine(work_dir, role, roots)?;
    }
    if let Some(image) = image.as_mut() {
        let ImageSpec {
            kernel_path,
            rootfs_path,
            boot_args: _,
            read_only: _,
            scratch_path,
            kernel_digest: _,
            rootfs_digest: _,
            scratch_digest: _,
            data_path,
            data_digest: _,
        } = image;
        *kernel_path = confine(kernel_path, Role::Kernel, roots)?;
        *rootfs_path = confine(rootfs_path, Role::Rootfs, roots)?;
        for (path, role) in [(scratch_path, Role::Scratch), (data_path, Role::Data)] {
            if let Some(p) = path.as_mut() {
                *p = confine(p, role, roots)?;
            }
        }
    }
    match seccomp {
        Some(SeccompSpec::Custom { filter_path }) => {
            *filter_path = confine(filter_path, Role::SeccompFilter, roots)?;
        }
        Some(SeccompSpec::Default | SeccompSpec::Disabled) | None => {}
    }
    if let Some(CgroupSpec { path, settings }) = cgroup.as_mut() {
        *path = confine(path, Role::Cgroup, roots)?;
        for setting in settings.iter() {
            let mut parts = Path::new(&setting.file).components();
            if !matches!(
                (parts.next(), parts.next()),
                (Some(Component::Normal(_)), None)
            ) {
                return Err(Refusal {
                    role: Role::Cgroup,
                    reason: Reason::NotOneComponent(setting.file.clone()),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "host_paths_tests.rs"]
mod tests;
