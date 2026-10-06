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
    WORKLOAD_DEVICES, WorkloadFs, reserved_at, workload_must_descend,
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

/// The filesystem ABI levels this ruleset is designed for, newest first: the
/// levels at which Landlock gained a filesystem right (`REFER` at 2,
/// `TRUNCATE` at 3, `IOCTL_DEV` at 5). The ruleset never asks for more than
/// ABI 5's rights. ABI 9's `RESOLVE_UNIX` would govern connecting to a named
/// Unix socket, and the workload door under hidden `/run` must stay
/// connectable, so handling it is a deliberate future decision, not a side
/// effect of a newer kernel.
const FS_ABI_LEVELS: [u32; 4] = [5, 3, 2, 1];

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

    use super::{CompileError, FS_ABI_LEVELS, Grant, Kind, LandlockSupport, Rule, plan};

    fn abi(level: u32) -> ABI {
        ABI::from(i32::try_from(level).unwrap_or(0))
    }

    /// Every filesystem right `level` can govern: the ruleset handles all of
    /// them, so anything a rule does not grant is denied.
    pub(super) fn handled(level: u32) -> BitFlags<AccessFs> {
        AccessFs::from_all(abi(level))
    }

    /// The rights one rule carries, masked to what the kernel accepts for the
    /// kind of file it is on (a directory right on a file rule is refused).
    pub(super) fn rights(grant: Grant, level: u32, is_dir: bool) -> BitFlags<AccessFs> {
        let wanted = match grant {
            Grant::Read => AccessFs::from_read(abi(level)),
            Grant::ReadWrite => handled(level),
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
            let mut created = hard()
                .handle_access(handled(level))
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
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        tracing::debug!(path = %rule.path.display(), "vanished before it was opened, so it grants nothing; no Landlock rule");
                        continue;
                    }
                    // Name what the path IS beside the error: an O_PATH open
                    // that fails for a present path is the case to diagnose.
                    Err(e) => {
                        use std::os::unix::fs::MetadataExt;
                        return Err(failed(
                            &rule.path,
                            format!(
                                "O_PATH open failed: {e} (file type {:?}, rdev {:#x})",
                                meta.file_type(),
                                meta.rdev()
                            ),
                        ));
                    }
                };
                created = created
                    .add_rule(PathBeneath::new(
                        fd,
                        rights(rule.grant, level, meta.is_dir()),
                    ))
                    .map_err(|e| failed(&rule.path, e))?;
            }
            Ok(Self {
                created: Some(created),
            })
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

    #[test]
    fn the_minimum_abi_is_two() {
        assert_eq!(LandlockSupport::Abi(1).enforceable(), None);
        assert_eq!(LandlockSupport::Abi(2).enforceable(), Some(2));
        assert_eq!(LandlockSupport::Abi(5).enforceable(), Some(5));
        assert_eq!(LandlockSupport::Unavailable.enforceable(), None);
    }
}
