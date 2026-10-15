//! The Landlock ruleset a confined child's filesystem is held to (#2696 P3c).
//!
//! # Why
//!
//! The uid drop (#3119) and the syscall filter (#3162) leave the child every
//! file its uid can reach by DAC: in the guest that is the whole rootfs, the
//! tmpfs under `/run`, and any file the image left world-readable or
//! world-writable. Landlock makes "what the child may touch" a kernel-enforced
//! allowlist instead.
//!
//! # One table, compiled (ADR 0007 G-1)
//!
//! What the child may do is not written here. It is
//! `nucleus_spec::guest_layout::RESERVED`, whose every entry states a
//! [`WorkloadFs`] beside the reason the runtime owns the path. This module only
//! compiles that table against the filesystem it finds:
//!
//! * a path no entry roots is the image's, and is granted read and execute;
//! * `Hidden` paths (the pod spec, `/run`, `/etc/nucleus`) get no rule;
//! * `ReadWrite` paths (`/work`, `/tmp`, `/cache`) get every right the ABI has;
//! * `/dev` grants only `WORKLOAD_DEVICES`.
//!
//! A Landlock rule grants a whole subtree and cannot carve a hole in one, so a
//! directory with a hidden entry beneath it (`/`, `/etc`) is not granted
//! whole: its children are granted one by one, and the hole is the child left
//! out. Symlinks get no rule: a rule binds an inode, and a link is governed
//! where its target lives, so `/var/run -> /run` stays hidden and
//! `/lib -> usr/lib` is readable through `/usr`.
//!
//! # The write layer: a read-only workspace (#2907)
//!
//! A pod whose lattice says `write_files: never` and `edit_files: never` must
//! not have its workspace written by a child either. Before this, the tool
//! proxy refused the agent's own write tool while `run_bash` children wrote
//! `/work` freely. Seccomp cannot see paths, so the rule is a second Landlock
//! layer, [`write_scope`]: it handles every WRITE right (write, truncate,
//! make, remove, refer) and nothing else, and grants those rights only to the
//! runtime's scratch, [`WRITE_SCRATCH`], each entry with its reason. Reading,
//! listing and exec are left to the layer beneath (the guest layout above, in
//! a microVM) or to DAC (a host child). Landlock layers intersect, so the
//! workspace stays readable and becomes unwritable wherever it is.
//!
//! The layer is an allowlist, so no hole has to be cut in it: anything not in
//! [`WRITE_SCRATCH`] is unwritable, the workspace included. The one way it
//! could still grant the workspace is by overlap (a workspace under `/tmp`,
//! say), and that refuses the compile by name rather than holding less than
//! it claims.
//!
//! # ABI
//!
//! The kernel side is the upstream `landlock` crate, which carries the
//! syscalls, so this module has no `unsafe`. The minimum is ABI 2 (6.1's):
//! every filesystem right of ABI 1 plus `REFER`,
//! so a file cannot be renamed or linked across a rule boundary into a place
//! with wider rights. `TRUNCATE` (ABI 3) and `IOCTL_DEV` (ABI 5) are handled
//! when the kernel has them. Below ABI 2 there is no ruleset to compile; what
//! happens then is `ChildConfinement`'s decision, not this module's.

use std::path::{Path, PathBuf};

use nucleus_spec::guest_layout::{
    COMPANION_HOME_NAME, WORKLOAD_DEVICES, WORKLOAD_HOME_NAME, WorkloadFs, reserved_at,
    workload_must_descend,
};

/// The lowest Landlock ABI a confined child is started under (#3148's
/// "fail closed below ABI 2").
pub const MIN_LANDLOCK_ABI: u32 = 2;

/// What the running kernel enforces, asked through the `landlock` crate with
/// `CompatLevel::HardRequirement`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockSupport {
    /// Landlock enforces every filesystem right of this ABI level: the
    /// highest of 1, 2, 3 and 5 (the levels that added filesystem rights) the
    /// kernel accepts. A newer kernel reports 5: the ruleset asks for no more.
    Abi(u32),
    /// No filesystem right is enforceable: Landlock compiled out (the
    /// Firecracker CI 6.1.141 guest kernel answers `ENOSYS`), built but not
    /// enabled at boot (`EOPNOTSUPP`), or not Linux.
    Unavailable,
}

impl LandlockSupport {
    /// Ask the running kernel.
    #[must_use]
    pub fn probe() -> Self {
        imp::probe()
    }

    /// The ABI to enforce at, if it reaches [`MIN_LANDLOCK_ABI`].
    #[must_use]
    pub fn enforceable(self) -> Option<u32> {
        match self {
            Self::Abi(abi) if abi >= MIN_LANDLOCK_ABI => Some(abi),
            Self::Abi(_) | Self::Unavailable => None,
        }
    }
}

impl std::fmt::Display for LandlockSupport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Abi(abi) => write!(f, "Landlock ABI {abi}"),
            Self::Unavailable => write!(
                f,
                "no Landlock (not built into the kernel, or not enabled at boot)"
            ),
        }
    }
}

/// The access one compiled rule grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Grant {
    /// Read files, list directories, execute.
    Read,
    /// Every right the ABI handles.
    ReadWrite,
    /// Every WRITE right the ABI handles, and no read, list or execute right:
    /// the write layer's one grant (#2907).
    Write,
}

/// What a directory entry is, as the walk sees it (not following links).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Kind {
    Dir,
    Other,
    Symlink,
}

/// How the walk lists a directory: its entries' names and kinds. `read_dir`
/// in production, a fixed tree in the tests.
pub(crate) type Lister<'a> = dyn FnMut(&Path) -> std::io::Result<Vec<(String, Kind)>> + 'a;

/// One rule of the compiled ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rule {
    pub(crate) path: PathBuf,
    pub(crate) grant: Grant,
}

/// Compile `guest_layout::RESERVED` against a filesystem, given a way to list
/// a directory. Pure: the tests hand it a tree, the child's spawn hands it
/// `read_dir`.
///
/// # Errors
/// A directory that cannot be listed. Not skipped: a walk that stopped early
/// would be a ruleset that grants less than the table says, which fails the
/// workload in ways that look like its own bugs, and nothing would say why.
pub(crate) fn plan(list: &mut Lister<'_>) -> std::io::Result<Vec<Rule>> {
    let mut rules = Vec::new();
    walk(Path::new("/"), list, &mut rules)?;
    Ok(rules)
}

fn walk(dir: &Path, list: &mut Lister<'_>, rules: &mut Vec<Rule>) -> std::io::Result<()> {
    let mut entries = list(dir)?;
    entries.sort();
    for (name, kind) in entries {
        let path = dir.join(&name);
        let Some(spelled) = path.to_str() else {
            // A non-UTF-8 name is no reserved path, so it is the image's; but
            // a rule cannot be keyed on what the table cannot spell either.
            // Read, like every other image path.
            push_unless_link(rules, path, kind, Grant::Read);
            continue;
        };
        match reserved_at(spelled).map(|r| r.workload) {
            Some(WorkloadFs::Hidden) => {}
            Some(WorkloadFs::Read) => push_unless_link(rules, path, kind, Grant::Read),
            Some(WorkloadFs::ReadWrite) => push_unless_link(rules, path, kind, Grant::ReadWrite),
            Some(WorkloadFs::Devices) => {
                if kind == Kind::Dir {
                    let mut devices = list(&path)?;
                    devices.sort();
                    for (device, dkind) in devices {
                        if WORKLOAD_DEVICES.contains(&device.as_str()) {
                            push_unless_link(rules, path.join(device), dkind, Grant::ReadWrite);
                        }
                    }
                }
            }
            None if kind == Kind::Dir && workload_must_descend(spelled) => {
                walk(&path, list, rules)?;
            }
            None => push_unless_link(rules, path, kind, Grant::Read),
        }
    }
    Ok(())
}

fn push_unless_link(rules: &mut Vec<Rule>, path: PathBuf, kind: Kind, grant: Grant) {
    match kind {
        Kind::Symlink => {}
        Kind::Dir | Kind::Other => rules.push(Rule { path, grant }),
    }
}

/// Where an entry of the write layer's scratch lives (#2907).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScratchRoot {
    /// A fixed absolute path, resolved first, so a `/tmp` that is a link is
    /// granted where it leads. If it is absent, it grants nothing.
    Absolute(&'static str),
    /// Each of `guest_layout::WORKLOAD_DEVICES` under `/dev`, and nothing else
    /// there.
    Devices,
    /// A directory directly under the workspace that the RUNTIME makes, by a
    /// name fixed here, never one the pod chose.
    InWorkspace(&'static str),
}

/// One path the write layer leaves writable, and why the runtime needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Scratch {
    pub(crate) root: ScratchRoot,
    pub(crate) why: &'static str,
}

/// Everything a child of a read-only-workspace pod may still write (#2907):
/// the runtime's own scratch, never the workspace. Each entry says why it is
/// here. A child writes nothing else, wherever it runs.
pub(crate) const WRITE_SCRATCH: &[Scratch] = &[
    Scratch {
        root: ScratchRoot::Absolute("/tmp"),
        why: "temporary files: shells and toolchains assume a writable /tmp (the guest's \
              boot tmpfs; the container's or the host's /tmp elsewhere)",
    },
    Scratch {
        root: ScratchRoot::Absolute("/cache"),
        why: "the guest's pinned compiler cache; absent off the guest, where it grants nothing",
    },
    Scratch {
        root: ScratchRoot::Devices,
        why: "the data sinks every program opens for writing (`>/dev/null`): \
              guest_layout::WORKLOAD_DEVICES and nothing else under /dev",
    },
    Scratch {
        root: ScratchRoot::InWorkspace(WORKLOAD_HOME_NAME),
        why: "the workload's default HOME, which the runtime makes and hands to its uid: a \
              HOME that cannot be written makes ordinary tools fail as if broken",
    },
    Scratch {
        root: ScratchRoot::InWorkspace(COMPANION_HOME_NAME),
        why: "the companion's HOME, which the runtime makes beside the workload's",
    },
];

/// The write layer's rules for a pod whose workspace is `workspace` (#2907):
/// each [`WRITE_SCRATCH`] entry granted [`Grant::Write`], and nothing else.
/// Pure except for `resolve`, which is `std::fs::canonicalize` in production
/// and a fixed map in the tests.
///
/// # Errors
/// * The workspace cannot be resolved. A layer that does not know where the
///   workspace is cannot say it is not granting it.
/// * An absolute entry exists and cannot be resolved (anything but `ENOENT`).
/// * The workspace and an absolute entry or a device overlap, in either
///   direction. Granting that entry would grant part of the workspace, so the
///   layer would hold less than it claims. This is refused, never narrowed
///   silently.
pub(crate) fn write_scope(
    workspace: &Path,
    resolve: &mut dyn FnMut(&Path) -> std::io::Result<PathBuf>,
) -> Result<Vec<Rule>, CompileError> {
    let ws = resolve(workspace).map_err(|e| CompileError {
        path: workspace.to_path_buf(),
        error: format!("the workspace cannot be resolved: {e}"),
    })?;
    let overlaps = |granted: &Path| -> Result<(), CompileError> {
        if ws.starts_with(granted) || granted.starts_with(&ws) {
            Err(CompileError {
                path: ws.clone(),
                error: format!(
                    "the workspace overlaps the writable scratch {}, so it cannot be held \
                     read-only; place the workspace outside the runtime's scratch",
                    granted.display()
                ),
            })
        } else {
            Ok(())
        }
    };
    let mut rules = Vec::new();
    for scratch in WRITE_SCRATCH {
        tracing::debug!(root = ?scratch.root, why = scratch.why, "write layer: scratch the workspace does not own");
        match scratch.root {
            ScratchRoot::Absolute(path) => {
                let path = Path::new(path);
                let resolved = match resolve(path) {
                    Ok(resolved) => resolved,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => {
                        return Err(CompileError {
                            path: path.to_path_buf(),
                            error: e.to_string(),
                        });
                    }
                };
                overlaps(&resolved)?;
                rules.push(Rule {
                    path: resolved,
                    grant: Grant::Write,
                });
            }
            ScratchRoot::Devices => {
                for device in WORKLOAD_DEVICES {
                    let path = Path::new("/dev").join(device);
                    overlaps(&path)?;
                    rules.push(Rule {
                        path,
                        grant: Grant::Write,
                    });
                }
            }
            // Beneath the resolved workspace, by a fixed name. The rule's fd
            // is opened `O_NOFOLLOW` and a link gets no rule, so a link the
            // workspace planted at this name grants nothing.
            ScratchRoot::InWorkspace(name) => rules.push(Rule {
                path: ws.join(name),
                grant: Grant::Write,
            }),
        }
    }
    Ok(rules)
}

/// The filesystem ABI levels this ruleset is designed for, newest first: the
/// levels at which Landlock gained a filesystem right (`REFER` at 2,
/// `TRUNCATE` at 3, `IOCTL_DEV` at 5). The ruleset never asks for more than
/// ABI 5's rights. ABI 9's `RESOLVE_UNIX` would govern connecting to a named
/// Unix socket, and the workload door under hidden `/run` must stay
/// connectable, so handling it is a deliberate future decision, not a side
/// effect of a newer kernel.
const FS_ABI_LEVELS: [u32; 4] = [5, 3, 2, 1];

/// What a failed `O_PATH` open of a GRANTED path means for the ruleset.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenFailure {
    /// The path grants nothing: no rule, and the compile goes on. Every rule
    /// is a grant (hidden paths never become rules), so skipping one can only
    /// take access away.
    GrantsNothing,
    /// Anything else: the compile fails, by name (fail closed).
    Refuse,
}

/// The one decider for a granted path whose `O_PATH` open failed (ADR 0007
/// G-1, A-1):
///
/// * `ENOENT`, any path: absent, so it grants nothing.
/// * `ENXIO` / `ENODEV` on a device node: the node exists and has no backing
///   driver or device. Measured on the x86_64 guest (6.1.186, musl): even an
///   `O_PATH` open of `/dev/tty` (5:0) answered `ENXIO`. A device the kernel
///   cannot back cannot be used either, so a rule on it would grant nothing.
/// * every other errno, and `ENXIO`/`ENODEV` on a non-device: refuse.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn open_failure(err: &std::io::Error, device: bool) -> OpenFailure {
    match err.raw_os_error() {
        Some(libc::ENOENT) => OpenFailure::GrantsNothing,
        Some(libc::ENXIO | libc::ENODEV) if device => OpenFailure::GrantsNothing,
        Some(_) | None => OpenFailure::Refuse,
    }
}

/// Why the ruleset could not be compiled: the path it stopped at and what
/// the kernel or filesystem said. Carried to the spawn's refusal by name
/// (`NucleusError::LandlockRuleset`), never collapsed to an errno.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompileError {
    pub(crate) path: PathBuf,
    pub(crate) error: String,
}

pub(crate) use imp::Ruleset;

#[cfg(target_os = "linux")]
mod imp {
    //! The kernel half, through the `landlock` crate (the upstream binding,
    //! maintained by Landlock's author): no `unsafe` here. Every compatibility
    //! question is asked with `CompatLevel::HardRequirement`, so a right the
    //! kernel cannot enforce is an error, never a silent best-effort drop.

    use std::io;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    use landlock::{
        ABI, Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, RulesetAttr,
        RulesetCreated, RulesetCreatedAttr, RulesetStatus,
    };

    use super::{
        CompileError, FS_ABI_LEVELS, Grant, Kind, LandlockSupport, Rule, plan, write_scope,
    };

    fn abi(level: u32) -> ABI {
        ABI::from(i32::try_from(level).unwrap_or(0))
    }

    /// Every filesystem right `level` can govern: the ruleset handles all of
    /// them, so anything a rule does not grant is denied.
    pub(super) fn handled(level: u32) -> BitFlags<AccessFs> {
        AccessFs::from_all(abi(level))
    }

    /// Every WRITE right `level` can govern, and no other: what the write
    /// layer handles (#2907). `IoctlDev` (ABI 5) does not write the
    /// filesystem, so it is left to the layer beneath.
    pub(super) fn write_rights(level: u32) -> BitFlags<AccessFs> {
        let mut rights = AccessFs::from_write(abi(level));
        rights.remove(AccessFs::IoctlDev);
        rights
    }

    /// The rights one rule carries, masked to what the kernel accepts for the
    /// kind of file it is on (a directory right on a file rule is refused).
    pub(super) fn rights(grant: Grant, level: u32, is_dir: bool) -> BitFlags<AccessFs> {
        let wanted = match grant {
            Grant::Read => AccessFs::from_read(abi(level)),
            Grant::ReadWrite => handled(level),
            Grant::Write => write_rights(level),
        };
        if is_dir {
            wanted
        } else {
            wanted & AccessFs::from_file(abi(level))
        }
    }

    fn hard() -> landlock::Ruleset {
        landlock::Ruleset::default().set_compatibility(CompatLevel::HardRequirement)
    }

    /// The highest filesystem level the kernel enforces in full: the first of
    /// [`FS_ABI_LEVELS`] whose rights it accepts as a hard requirement.
    pub(super) fn probe() -> LandlockSupport {
        FS_ABI_LEVELS
            .into_iter()
            .find(|level| hard().handle_access(handled(*level)).is_ok())
            .map_or(LandlockSupport::Unavailable, LandlockSupport::Abi)
    }

    fn failed(path: &Path, e: impl std::fmt::Display) -> CompileError {
        CompileError {
            path: path.to_path_buf(),
            error: e.to_string(),
        }
    }

    /// A ruleset compiled in the PARENT: created and every rule added. The
    /// child only restricts itself with it (the `pre_exec` contract).
    #[derive(Debug)]
    pub(crate) struct Ruleset {
        created: Option<RulesetCreated>,
        /// What the ruleset grants `/proc`, for a procfs the child mounts
        /// after this was compiled ([`Self::grant_own_proc`], #3344).
        proc: Option<BitFlags<AccessFs>>,
    }

    fn list(dir: &Path) -> io::Result<Vec<(String, Kind)>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            // `file_type` does not follow symlinks.
            let ft = entry.file_type()?;
            let kind = if ft.is_symlink() {
                Kind::Symlink
            } else if ft.is_dir() {
                Kind::Dir
            } else {
                Kind::Other
            };
            out.push((entry.file_name().to_string_lossy().into_owned(), kind));
        }
        Ok(out)
    }

    /// The rule's fd: `O_PATH | O_NOFOLLOW | O_CLOEXEC`, opened here rather
    /// than through the crate's `PathFd`, so the flags are stated where the
    /// ruleset is built. `O_PATH` resolves the path and NEVER opens the file:
    /// no device driver runs, so `/dev/tty` without a controlling terminal
    /// (`ENXIO` on a real open) or `/dev/ptmx` without devpts (`ENOENT`) still
    /// yields a rule. A device's presence is checked by `O_PATH`/`fstat` only.
    /// `O_NOFOLLOW` keeps a link from becoming a grant on its target.
    pub(super) fn path_fd(path: &Path) -> io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    impl Ruleset {
        /// Compile the guest layout at filesystem level `level`.
        ///
        /// # Errors
        /// Any failure to create the ruleset, list a directory, open a path or
        /// add a rule, including a right the kernel cannot enforce. The caller
        /// refuses the spawn on any of them.
        pub(crate) fn compile(level: u32) -> Result<Self, CompileError> {
            let rules = plan(&mut list).map_err(|e| failed(Path::new("/"), e))?;
            Self::compile_rules(level, &rules)
        }

        /// Compile the write layer for a pod whose workspace is `workspace`
        /// (#2907). It handles only [`write_rights`] and grants them only to
        /// [`super::WRITE_SCRATCH`].
        ///
        /// # Errors
        /// Everything [`write_scope`] refuses, and every failure
        /// [`Self::compile_rules`] names.
        pub(crate) fn compile_write_scope(
            level: u32,
            workspace: &Path,
        ) -> Result<Self, CompileError> {
            let rules = write_scope(workspace, &mut |p: &Path| std::fs::canonicalize(p))?;
            Self::compile_handling(level, write_rights(level), &rules)
        }

        /// # Absent paths
        ///
        /// A rule whose path is absent when it is opened (`ENOENT`), or which
        /// turns out to be a symlink, grants nothing and is skipped, with a
        /// debug line naming it. That is the safe direction: every rule here
        /// is a GRANT (hidden paths never become rules at all), so skipping
        /// one can only take access away. Measured on the x86_64 live boot: a
        /// `/dev/ptmx` the walk had listed could not be opened (`ENOENT`, the
        /// shape of a link to an unmounted `/dev/pts/ptmx`), and failing the
        /// whole ruleset on it refused every workload on that rootfs. Any
        /// OTHER failure (a path that exists and cannot be opened, a right the
        /// kernel refuses) still fails the compile, and the spawn with it.
        pub(crate) fn compile_rules(level: u32, rules: &[Rule]) -> Result<Self, CompileError> {
            Self::compile_handling(level, handled(level), rules)
        }

        /// [`Self::compile_rules`] with the handled rights stated: every right
        /// in `handled` that no rule grants is denied.
        fn compile_handling(
            level: u32,
            handled: BitFlags<AccessFs>,
            rules: &[Rule],
        ) -> Result<Self, CompileError> {
            let mut created = hard()
                .handle_access(handled)
                .and_then(landlock::Ruleset::create)
                .map_err(|e| failed(Path::new("/"), e))?;
            for rule in rules {
                let meta = match std::fs::symlink_metadata(&rule.path) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        tracing::debug!(path = %rule.path.display(), "a symlink gets no Landlock rule; skipped");
                        continue;
                    }
                    Ok(meta) => meta,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        tracing::debug!(path = %rule.path.display(), "absent, so it grants nothing; no Landlock rule");
                        continue;
                    }
                    Err(e) => return Err(failed(&rule.path, e)),
                };
                let fd = match path_fd(&rule.path) {
                    Ok(fd) => fd,
                    Err(e) => {
                        use std::os::unix::fs::{FileTypeExt, MetadataExt};
                        let ft = meta.file_type();
                        let device = ft.is_char_device() || ft.is_block_device();
                        match super::open_failure(&e, device) {
                            super::OpenFailure::GrantsNothing => {
                                tracing::debug!(
                                    path = %rule.path.display(),
                                    errno = ?e.raw_os_error(),
                                    rdev = format_args!("{:#x}", meta.rdev()),
                                    "absent or unbacked, so it grants nothing; no Landlock rule"
                                );
                                continue;
                            }
                            // Name what the path IS beside the error.
                            super::OpenFailure::Refuse => {
                                return Err(failed(
                                    &rule.path,
                                    format!(
                                        "O_PATH open failed: {e} (file type {ft:?}, rdev {:#x})",
                                        meta.rdev()
                                    ),
                                ));
                            }
                        }
                    }
                };
                created = created
                    .add_rule(PathBeneath::new(
                        fd,
                        rights(rule.grant, level, meta.is_dir()),
                    ))
                    .map_err(|e| failed(&rule.path, e))?;
            }
            let proc = rules
                .iter()
                .find(|rule| rule.path == Path::new("/proc"))
                .map(|rule| rights(rule.grant, level, true) & handled);
            Ok(Self {
                created: Some(created),
                proc,
            })
        }

        /// Grant the procfs a child mounted for its own PID namespace (#3344)
        /// what this ruleset grants `/proc`, and nothing when it grants
        /// nothing. The parent's rule is on the runtime's procfs, whose root
        /// the new mount covers, and Landlock decides by inode, so the new
        /// procfs needs a rule of its own. In the forked child, before
        /// [`Self::restrict_self`]: one `O_PATH` open of a static path and
        /// one `landlock_add_rule`, no allocation on success.
        pub(crate) fn grant_own_proc(&mut self) -> io::Result<()> {
            use rustix::fs::{Mode, OFlags};
            let Some(rights) = self.proc else {
                return Ok(());
            };
            let created = self
                .created
                .take()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;
            let fd = rustix::fs::open(
                c"/proc",
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::DIRECTORY,
                Mode::empty(),
            )?;
            let created = created
                .add_rule(PathBeneath::new(fd, rights))
                .map_err(|_| io::Error::from_raw_os_error(libc::EOPNOTSUPP))?;
            self.created = Some(created);
            Ok(())
        }

        /// Restrict the calling process to the ruleset. Runs in the forked
        /// child after `no_new_privs`: the crate's one `landlock_restrict_self`
        /// (and an idempotent `no_new_privs`). Anything short of fully
        /// enforced is an error, and so is a second call.
        pub(crate) fn restrict_self(&mut self) -> io::Result<()> {
            let created = self
                .created
                .take()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;
            match created.restrict_self() {
                Ok(status) if status.ruleset == RulesetStatus::FullyEnforced => Ok(()),
                Ok(_) => Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
                Err(_) => Err(io::Error::last_os_error()),
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::{CompileError, LandlockSupport};

    pub(super) fn probe() -> LandlockSupport {
        LandlockSupport::Unavailable
    }

    /// No Landlock off Linux, so nothing is ever compiled: the decision
    /// (`ChildConfinement`) never asks for a ruleset where the probe answered
    /// `Unavailable`.
    #[derive(Debug)]
    pub(crate) enum Ruleset {}

    impl Ruleset {
        /// Never reached (see above); refuses by name if it were.
        pub(crate) fn compile(_level: u32) -> Result<Self, CompileError> {
            Err(CompileError {
                path: std::path::PathBuf::from("/"),
                error: "no Landlock off Linux".to_string(),
            })
        }

        /// Never reached either: a read-only workspace is refused by name
        /// where the probe answered `Unavailable` (#2907).
        pub(crate) fn compile_write_scope(
            _level: u32,
            workspace: &std::path::Path,
        ) -> Result<Self, CompileError> {
            Err(CompileError {
                path: workspace.to_path_buf(),
                error: "no Landlock off Linux".to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A guest-shaped tree: what `build-rootfs.sh` lays down, plus the boot
    /// mounts, plus the traps (a link into `/run`, a merged-usr `/lib`).
    fn guest_tree() -> BTreeMap<&'static str, Vec<(&'static str, Kind)>> {
        use Kind::{Dir, Other, Symlink};
        BTreeMap::from([
            (
                "/",
                vec![
                    ("bin", Symlink),
                    ("cache", Dir),
                    ("cache-seed", Dir),
                    ("dev", Dir),
                    ("etc", Dir),
                    ("home", Dir),
                    ("init", Other),
                    ("lib", Symlink),
                    ("pod.yaml", Other),
                    ("proc", Dir),
                    ("run", Dir),
                    ("sys", Dir),
                    ("tmp", Dir),
                    ("usr", Dir),
                    ("var", Dir),
                    ("work", Dir),
                ],
            ),
            (
                "/etc",
                vec![
                    ("nucleus", Dir),
                    ("passwd", Other),
                    ("ssl", Dir),
                    ("mtab", Symlink),
                ],
            ),
            (
                "/dev",
                vec![
                    ("null", Other),
                    ("urandom", Other),
                    ("pts", Dir),
                    ("vda", Other),
                    ("vsock", Other),
                    ("kmsg", Other),
                    ("stdout", Symlink),
                ],
            ),
        ])
    }

    fn plan_of(tree: &BTreeMap<&'static str, Vec<(&'static str, Kind)>>) -> Vec<Rule> {
        plan(&mut |dir: &Path| {
            Ok(tree
                .get(dir.to_str().unwrap())
                .unwrap_or_else(|| {
                    panic!("the walk listed {} which it must not enter", dir.display())
                })
                .iter()
                .map(|(n, k)| ((*n).to_string(), *k))
                .collect())
        })
        .unwrap()
    }

    fn grant_of(rules: &[Rule], path: &str) -> Option<Grant> {
        rules
            .iter()
            .find(|r| r.path == Path::new(path))
            .map(|r| r.grant)
    }

    /// THE derivation (#2696 P3c): runtime state hidden, scratch writable,
    /// the image readable, only the named devices.
    #[test]
    fn the_guest_layout_compiles_to_the_expected_ruleset() {
        let rules = plan_of(&guest_tree());
        // Hidden: no rule names them or anything beneath them.
        for hidden in ["/run", "/etc/nucleus", "/pod.yaml"] {
            assert!(
                rules.iter().all(|r| !r.path.starts_with(hidden)),
                "{hidden} must get no rule: {rules:?}"
            );
        }
        // Writable: the scratch, the temp dir and the compiler cache.
        for rw in ["/work", "/tmp", "/cache"] {
            assert_eq!(grant_of(&rules, rw), Some(Grant::ReadWrite), "{rw}");
        }
        // Readable: the image, whole where no hole is needed.
        for ro in [
            "/usr",
            "/home",
            "/var",
            "/etc/passwd",
            "/etc/ssl",
            "/proc",
            "/sys",
            "/init",
            "/cache-seed",
        ] {
            assert_eq!(grant_of(&rules, ro), Some(Grant::Read), "{ro}");
        }
        // Only the named devices; never the disk, the vsock or the kernel log.
        assert_eq!(grant_of(&rules, "/dev/null"), Some(Grant::ReadWrite));
        assert_eq!(grant_of(&rules, "/dev/urandom"), Some(Grant::ReadWrite));
        for denied in [
            "/dev",
            "/dev/vda",
            "/dev/vsock",
            "/dev/kmsg",
            "/dev/pts",
            "/",
        ] {
            assert_eq!(grant_of(&rules, denied), None, "{denied}");
        }
        // Directories holding a hole are not granted whole.
        assert_eq!(grant_of(&rules, "/etc"), None);
    }

    /// A link gets no rule: `/bin -> usr/bin` is covered by `/usr`, and a
    /// link into a hidden directory must not become a grant on it.
    #[test]
    fn symlinks_get_no_rule() {
        let rules = plan_of(&guest_tree());
        for link in ["/bin", "/lib", "/etc/mtab", "/dev/stdout"] {
            assert_eq!(grant_of(&rules, link), None, "{link}");
        }
    }

    /// The walk enters only `/`, the directories holding a hole, and `/dev`:
    /// `plan_of` panics if it lists anything else, so a ruleset that walked
    /// the whole rootfs on every spawn reds here.
    #[test]
    fn the_walk_enters_only_where_a_hole_is_cut() {
        let _ = plan_of(&guest_tree());
    }

    /// A directory that cannot be listed fails the compile, never shrinks it.
    #[test]
    fn an_unlistable_directory_fails_the_plan() {
        let err = plan(&mut |dir: &Path| {
            if dir == Path::new("/etc") {
                Err(std::io::Error::from_raw_os_error(libc::EACCES))
            } else {
                Ok(vec![("etc".to_string(), Kind::Dir)])
            }
        })
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EACCES));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rights_follow_the_abi_and_the_file_kind() {
        use super::imp::{handled, rights};
        use landlock::AccessFs;
        assert!(!handled(1).contains(AccessFs::Refer));
        assert!(handled(2).contains(AccessFs::Refer));
        assert!(!handled(2).contains(AccessFs::Truncate));
        assert!(handled(3).contains(AccessFs::Truncate));
        assert!(handled(5).contains(AccessFs::IoctlDev));
        // Read never writes; a file rule never carries a directory right.
        let read = rights(Grant::Read, 5, true);
        assert!(!read.contains(AccessFs::WriteFile));
        assert!(read.contains(AccessFs::ReadDir));
        assert!(!rights(Grant::ReadWrite, 5, false).contains(AccessFs::ReadDir));
        assert_eq!(rights(Grant::ReadWrite, 2, true), handled(2));
    }

    /// THE x86_64 live-boot failure (#3273): `/dev/ptmx` was listed and then
    /// could not be opened (`ENOENT`, a link to an unmounted `/dev/pts/ptmx`),
    /// and the whole ruleset failed, refusing every workload. An absent or
    /// dangling grant now grants nothing and is skipped; the rest of the
    /// ruleset compiles. Red if the compile fails on the first absent path.
    /// Needs a kernel with Landlock to create a ruleset at all.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_absent_or_dangling_granted_path_is_skipped_not_fatal() {
        let Some(level) = LandlockSupport::probe().enforceable() else {
            eprintln!("SKIPPED: this kernel has no Landlock ABI >= 2; nothing to compile");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let dangling = dir.path().join("ptmx");
        std::os::unix::fs::symlink("pts/ptmx", &dangling).unwrap();
        let rules = [
            Rule {
                path: dir.path().to_path_buf(),
                grant: Grant::ReadWrite,
            },
            Rule {
                path: dangling,
                grant: Grant::ReadWrite,
            },
            Rule {
                path: dir.path().join("absent-device"),
                grant: Grant::ReadWrite,
            },
        ];
        if let Err(e) = Ruleset::compile_rules(level, &rules) {
            panic!("an absent grant must be skipped, not fatal: {e:?}");
        }
    }

    /// The x86_64 live boot's second failure (#3273): the rule for `/dev/tty`
    /// failed with `ENXIO`, which is what OPENING the tty driver answers in a
    /// session without a controlling terminal. A rule fd must only resolve the
    /// path (`O_PATH`), never open the device. Asserted only where a real open
    /// of `/dev/tty` does fail (run under `setsid`, or in CI, which has no
    /// terminal), so the case is the measured one. Red if `path_fd` opens.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_device_whose_open_fails_still_gets_a_rule() {
        let Some(level) = LandlockSupport::probe().enforceable() else {
            eprintln!("SKIPPED: this kernel has no Landlock ABI >= 2; nothing to compile");
            return;
        };
        let tty = std::path::Path::new("/dev/tty");
        match std::fs::File::open(tty) {
            Err(e) if e.raw_os_error() == Some(libc::ENXIO) => {}
            other => {
                eprintln!(
                    "SKIPPED: /dev/tty opens here ({other:?}); run under `setsid` to drop the \
                     controlling terminal"
                );
                return;
            }
        }
        assert!(
            super::imp::path_fd(tty).is_ok(),
            "O_PATH must not open the tty driver"
        );
        if let Err(e) = Ruleset::compile_rules(
            level,
            &[Rule {
                path: tty.to_path_buf(),
                grant: Grant::ReadWrite,
            }],
        ) {
            panic!("a device that cannot be opened must still get a rule: {e:?}");
        }
    }

    /// The third x86_64 live-boot failure (#3273): an `O_PATH` open of the
    /// device `/dev/tty` (5:0) answered `ENXIO`. On a device node, `ENXIO`
    /// and `ENODEV` (no backing driver) grant nothing and are skipped, like
    /// `ENOENT` on any path. Red if either device errno refuses the compile.
    #[test]
    fn an_unbacked_device_grants_nothing() {
        for errno in [libc::ENXIO, libc::ENODEV] {
            let e = std::io::Error::from_raw_os_error(errno);
            assert_eq!(open_failure(&e, true), OpenFailure::GrantsNothing, "{e}");
        }
        for device in [true, false] {
            let e = std::io::Error::from_raw_os_error(libc::ENOENT);
            assert_eq!(open_failure(&e, device), OpenFailure::GrantsNothing);
        }
    }

    /// Fail closed everywhere else: any other errno on any path, and
    /// `ENXIO`/`ENODEV` on a path that is not a device node, refuse the
    /// compile. Red if the skip widens past the measured case.
    #[test]
    fn every_other_open_failure_refuses_the_compile() {
        for errno in [
            libc::EACCES,
            libc::EPERM,
            libc::EIO,
            libc::ELOOP,
            libc::EINVAL,
        ] {
            for device in [true, false] {
                let e = std::io::Error::from_raw_os_error(errno);
                assert_eq!(
                    open_failure(&e, device),
                    OpenFailure::Refuse,
                    "{e} device={device}"
                );
            }
        }
        for errno in [libc::ENXIO, libc::ENODEV] {
            let e = std::io::Error::from_raw_os_error(errno);
            assert_eq!(
                open_failure(&e, false),
                OpenFailure::Refuse,
                "{e} on a non-device"
            );
        }
        assert_eq!(
            open_failure(&std::io::Error::other("no errno"), true),
            OpenFailure::Refuse
        );
    }

    /// `/dev/tty` is not granted: the workload has no controlling terminal.
    #[test]
    fn the_device_list_is_minimal() {
        assert_eq!(
            WORKLOAD_DEVICES,
            &["null", "zero", "full", "random", "urandom"]
        );
    }

    /// The skip is for ABSENT paths only: a path that exists and cannot be
    /// examined still fails the compile, naming the path (fail closed).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_present_path_that_cannot_be_examined_still_fails_the_compile() {
        use std::os::unix::fs::PermissionsExt;
        let Some(level) = LandlockSupport::probe().enforceable() else {
            eprintln!("SKIPPED: this kernel has no Landlock ABI >= 2; nothing to compile");
            return;
        };
        if crate::runtime_uid() == 0 {
            eprintln!("SKIPPED: root reads through a mode-000 directory");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let inside = locked.join("x");
        let err = Ruleset::compile_rules(
            level,
            &[Rule {
                path: inside.clone(),
                grant: Grant::Read,
            }],
        )
        .expect_err("EACCES is not absence");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(err.path, inside);
    }

    /// The ruleset never handles more than ABI 5's filesystem rights: a newer
    /// right (ABI 9's `RESOLVE_UNIX`) would govern connecting to the workload
    /// door, and taking it on is a decision, not a kernel upgrade's side effect.
    #[test]
    fn the_ruleset_is_capped_at_the_levels_it_was_designed_for() {
        assert_eq!(FS_ABI_LEVELS, [5, 3, 2, 1]);
        #[cfg(target_os = "linux")]
        assert_eq!(
            super::imp::handled(5),
            <landlock::AccessFs as landlock::Access>::from_all(landlock::ABI::V5)
        );
    }

    /// A resolver over a fixed host: every path resolves to itself except
    /// those named absent.
    fn resolver(absent: &'static [&'static str]) -> impl FnMut(&Path) -> std::io::Result<PathBuf> {
        move |p: &Path| {
            if absent.iter().any(|a| p == Path::new(a)) {
                Err(std::io::Error::from(std::io::ErrorKind::NotFound))
            } else {
                Ok(p.to_path_buf())
            }
        }
    }

    /// THE write layer (#2907): what a child of a read-only-workspace pod may
    /// write is the runtime's scratch and nothing else. No rule is the
    /// workspace or above it, and the only rules beneath it are the two HOMEs
    /// the runtime makes. Red if the layer grants the workspace, or any write
    /// right is granted outside the table.
    #[test]
    fn the_write_layer_grants_only_the_runtime_scratch() {
        let rules = write_scope(Path::new("/work"), &mut resolver(&[])).unwrap();
        assert!(rules.iter().all(|r| r.grant == Grant::Write), "{rules:?}");
        let mut paths: Vec<_> = rules.iter().map(|r| r.path.clone()).collect();
        paths.sort();
        let mut expected: Vec<PathBuf> = ["/tmp", "/cache", "/work/.home", "/work/.companion-home"]
            .iter()
            .map(PathBuf::from)
            .chain(WORKLOAD_DEVICES.iter().map(|d| Path::new("/dev").join(d)))
            .collect();
        expected.sort();
        assert_eq!(paths, expected);
        for rule in &rules {
            assert!(
                !Path::new("/work").starts_with(&rule.path),
                "{} grants the workspace",
                rule.path.display()
            );
        }
        for scratch in WRITE_SCRATCH {
            assert!(
                !scratch.why.is_empty(),
                "{:?} states no reason",
                scratch.root
            );
        }
    }

    /// The scratch is granted where it RESOLVES (a `/tmp` link is granted at
    /// its target), and an absent entry grants nothing rather than failing.
    #[test]
    fn the_write_layer_resolves_its_scratch_and_skips_what_is_absent() {
        let rules = write_scope(Path::new("/work"), &mut |p: &Path| {
            if p == Path::new("/tmp") {
                Ok(PathBuf::from("/private/tmp"))
            } else if p == Path::new("/cache") {
                Err(std::io::Error::from(std::io::ErrorKind::NotFound))
            } else {
                Ok(p.to_path_buf())
            }
        })
        .unwrap();
        assert!(rules.iter().any(|r| r.path == Path::new("/private/tmp")));
        assert!(rules.iter().all(|r| r.path != Path::new("/tmp")));
        assert!(rules.iter().all(|r| r.path != Path::new("/cache")));
    }

    /// Fail closed on overlap (#2907): a workspace under the scratch, or a
    /// workspace the scratch lies under, cannot be held read-only by a layer
    /// that grants the scratch. Refused BY NAME, naming the workspace and the
    /// entry, never narrowed silently. Red if either direction compiles.
    #[test]
    fn a_workspace_that_overlaps_the_scratch_is_refused_by_name() {
        for (workspace, entry) in [
            ("/tmp/nucleus-ws", "/tmp"),
            ("/", "/tmp"),
            ("/dev", "/dev/null"),
        ] {
            let err = write_scope(Path::new(workspace), &mut resolver(&[])).unwrap_err();
            assert_eq!(err.path, Path::new(workspace));
            assert!(err.error.contains(entry), "{workspace}: {}", err.error);
            assert!(err.error.contains("read-only"), "{}", err.error);
        }
        // The overlap is checked where the workspace RESOLVES: a link into
        // the scratch is the scratch.
        let err = write_scope(Path::new("/srv/ws"), &mut |p: &Path| {
            if p == Path::new("/srv/ws") {
                Ok(PathBuf::from("/tmp/ws"))
            } else {
                Ok(p.to_path_buf())
            }
        })
        .unwrap_err();
        assert!(err.error.contains("/tmp"), "{}", err.error);
    }

    /// A workspace that cannot be resolved is refused, never assumed disjoint.
    #[test]
    fn an_unresolvable_workspace_refuses_the_write_layer() {
        let err = write_scope(Path::new("/gone"), &mut resolver(&["/gone"])).unwrap_err();
        assert_eq!(err.path, Path::new("/gone"));
        let err = write_scope(Path::new("/work"), &mut |p: &Path| {
            if p == Path::new("/tmp") {
                Err(std::io::Error::from_raw_os_error(libc::EACCES))
            } else {
                Ok(p.to_path_buf())
            }
        })
        .unwrap_err();
        assert_eq!(err.path, Path::new("/tmp"), "EACCES is not absence");
    }

    /// The write layer handles writes and only writes: no read, list or exec
    /// right (those stay with the layer beneath, so the workspace stays
    /// readable), and no `IoctlDev`. Red if it handles a read right.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_write_layer_handles_writes_alone() {
        use super::imp::write_rights;
        use landlock::AccessFs;
        for level in FS_ABI_LEVELS {
            let w = write_rights(level);
            for read in [
                AccessFs::ReadFile,
                AccessFs::ReadDir,
                AccessFs::Execute,
                AccessFs::IoctlDev,
            ] {
                assert!(!w.contains(read), "level {level} handles {read:?}");
            }
            for write in [
                AccessFs::WriteFile,
                AccessFs::MakeReg,
                AccessFs::MakeDir,
                AccessFs::MakeSym,
                AccessFs::RemoveFile,
                AccessFs::RemoveDir,
            ] {
                assert!(w.contains(write), "level {level} misses {write:?}");
            }
        }
        assert!(write_rights(2).contains(AccessFs::Refer));
        assert!(write_rights(3).contains(AccessFs::Truncate));
    }

    #[test]
    fn the_minimum_abi_is_two() {
        assert_eq!(LandlockSupport::Abi(1).enforceable(), None);
        assert_eq!(LandlockSupport::Abi(2).enforceable(), Some(2));
        assert_eq!(LandlockSupport::Abi(5).enforceable(), Some(5));
        assert_eq!(LandlockSupport::Unavailable.enforceable(), None);
    }
}
