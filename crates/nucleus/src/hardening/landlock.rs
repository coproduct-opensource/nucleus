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

pub(crate) use imp::Ruleset;

#[cfg(target_os = "linux")]
mod imp {
    //! The kernel half, through the `landlock` crate (the upstream binding,
    //! maintained by Landlock's author): no `unsafe` here. Every compatibility
    //! question is asked with `CompatLevel::HardRequirement`, so a right the
    //! kernel cannot enforce is an error, never a silent best-effort drop.

    use std::io;
    use std::path::Path;

    use landlock::{
        ABI, Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd, RulesetAttr,
        RulesetCreated, RulesetCreatedAttr, RulesetStatus,
    };

    use super::{FS_ABI_LEVELS, Grant, Kind, LandlockSupport, Rule, plan};

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

    fn other(what: &Path, e: impl std::fmt::Display) -> io::Error {
        io::Error::other(format!("{}: {e}", what.display()))
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

    impl Ruleset {
        /// Compile the guest layout at filesystem level `level`.
        ///
        /// # Errors
        /// Any failure to create the ruleset, list a directory, open a path or
        /// add a rule, including a right the kernel cannot enforce. The caller
        /// refuses the spawn on any of them.
        pub(crate) fn compile(level: u32) -> io::Result<Self> {
            Self::compile_rules(level, &plan(&mut list)?)
        }

        pub(crate) fn compile_rules(level: u32, rules: &[Rule]) -> io::Result<Self> {
            let root = Path::new("/");
            let mut created = hard()
                .handle_access(handled(level))
                .and_then(landlock::Ruleset::create)
                .map_err(|e| other(root, e))?;
            for rule in rules {
                let is_dir = std::fs::symlink_metadata(&rule.path)?.is_dir();
                let fd = PathFd::new(&rule.path).map_err(|e| other(&rule.path, e))?;
                created = created
                    .add_rule(PathBeneath::new(fd, rights(rule.grant, level, is_dir)))
                    .map_err(|e| other(&rule.path, e))?;
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
    use super::LandlockSupport;

    pub(super) fn probe() -> LandlockSupport {
        LandlockSupport::Unavailable
    }

    /// No Landlock off Linux, so nothing is ever compiled: the decision
    /// (`ChildConfinement`) never asks for a ruleset where the probe answered
    /// `Unavailable`.
    #[derive(Debug)]
    pub(crate) enum Ruleset {}
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
        assert_eq!(grant_of(&rules, "/dev/pts"), Some(Grant::ReadWrite));
        for denied in ["/dev", "/dev/vda", "/dev/vsock", "/dev/kmsg", "/"] {
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
