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
//! The minimum is ABI 2 (6.1's): every filesystem right of ABI 1 plus `REFER`,
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

/// What the running kernel offers, as `landlock_create_ruleset(NULL, 0,
/// LANDLOCK_CREATE_RULESET_VERSION)` answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockSupport {
    /// Landlock is up, at this ABI.
    Abi(u32),
    /// The call failed with this errno: `ENOSYS` when Landlock is compiled
    /// out (the Firecracker CI 6.1.141 guest kernel), `EOPNOTSUPP` when it is
    /// built but not enabled at boot. Also what a non-Linux build reports.
    Unavailable {
        /// The errno.
        errno: i32,
    },
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
            Self::Abi(_) | Self::Unavailable { .. } => None,
        }
    }
}

impl std::fmt::Display for LandlockSupport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Abi(abi) => write!(f, "Landlock ABI {abi}"),
            Self::Unavailable { errno } => write!(
                f,
                "no Landlock (landlock_create_ruleset: {})",
                std::io::Error::from_raw_os_error(*errno)
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

/// `LANDLOCK_ACCESS_FS_*` from uapi `linux/landlock.h`. Local because the
/// `libc` crate binds the syscall numbers and not these.
pub(crate) mod access {
    pub(crate) const EXECUTE: u64 = 1 << 0;
    pub(crate) const WRITE_FILE: u64 = 1 << 1;
    pub(crate) const READ_FILE: u64 = 1 << 2;
    pub(crate) const READ_DIR: u64 = 1 << 3;
    /// `REMOVE_DIR` through `MAKE_SYM`: bits 4..=12, ABI 1.
    pub(crate) const ABI1_ALL: u64 = (1 << 13) - 1;
    pub(crate) const REFER: u64 = 1 << 13;
    pub(crate) const TRUNCATE: u64 = 1 << 14;
    pub(crate) const IOCTL_DEV: u64 = 1 << 15;
    /// The rights the kernel accepts on a rule for a non-directory.
    pub(crate) const FILE: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;
}

/// Every filesystem right `abi` can govern: the ruleset handles all of them,
/// so anything not granted by a rule is denied.
pub(crate) fn handled(abi: u32) -> u64 {
    let mut rights = access::ABI1_ALL;
    if abi >= 2 {
        rights |= access::REFER;
    }
    if abi >= 3 {
        rights |= access::TRUNCATE;
    }
    if abi >= 5 {
        rights |= access::IOCTL_DEV;
    }
    rights
}

/// The rights one rule carries, masked to what the kernel accepts for the kind
/// of file it is on (a directory right on a file rule is `EINVAL`).
pub(crate) fn rights(grant: Grant, abi: u32, is_dir: bool) -> u64 {
    let wanted = match grant {
        Grant::Read => access::EXECUTE | access::READ_FILE | access::READ_DIR,
        Grant::ReadWrite => u64::MAX,
    } & handled(abi);
    if is_dir {
        wanted
    } else {
        wanted & access::FILE
    }
}

pub(crate) use imp::Ruleset;

#[cfg(target_os = "linux")]
#[expect(
    unsafe_code,
    reason = "audited exception: the three Landlock syscalls take pointers to the uapi structs below"
)]
mod imp {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    use super::{Kind, LandlockSupport, Rule, handled, plan, rights};

    /// `LANDLOCK_CREATE_RULESET_VERSION`.
    const CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;
    /// `LANDLOCK_RULE_PATH_BENEATH`.
    const RULE_PATH_BENEATH: libc::c_int = 1;

    /// `struct landlock_ruleset_attr`, ABI 1–3 layout (filesystem only). The
    /// kernel takes the size, so a shorter struct is the older ABI's, not a
    /// truncated newer one: no network or scope rights are handled here.
    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
    }

    /// `struct landlock_path_beneath_attr`, which uapi declares packed.
    #[repr(C, packed)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    pub(super) fn probe() -> LandlockSupport {
        // SAFETY: a NULL attribute with size 0 and the VERSION flag is the
        // documented ABI query; it reads no memory.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<RulesetAttr>(),
                0usize,
                CREATE_RULESET_VERSION,
            )
        };
        if rc < 0 {
            LandlockSupport::Unavailable {
                errno: io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::ENOSYS),
            }
        } else {
            LandlockSupport::Abi(u32::try_from(rc).unwrap_or(0))
        }
    }

    /// A ruleset compiled in the PARENT: created, every rule added, held as
    /// an fd. The child only calls `landlock_restrict_self` on it, which
    /// allocates nothing (the `pre_exec` contract).
    #[derive(Debug)]
    pub(crate) struct Ruleset {
        fd: OwnedFd,
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
        /// Compile the guest layout at `abi`.
        ///
        /// # Errors
        /// Any failure to create the ruleset, list a directory, open a path or
        /// add a rule. The caller refuses the spawn on any of them.
        pub(crate) fn compile(abi: u32) -> io::Result<Self> {
            Self::compile_rules(abi, &plan(&mut list)?)
        }

        pub(crate) fn compile_rules(abi: u32, rules: &[Rule]) -> io::Result<Self> {
            let attr = RulesetAttr {
                handled_access_fs: handled(abi),
            };
            // SAFETY: `attr` is a live, initialised `RulesetAttr` and its size is
            // passed beside it. The returned fd is owned below.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_landlock_create_ruleset,
                    &raw const attr,
                    std::mem::size_of::<RulesetAttr>(),
                    0 as libc::c_uint,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            let raw = libc::c_int::try_from(rc)
                .map_err(|_| io::Error::other("landlock_create_ruleset returned no fd"))?;
            // SAFETY: the kernel just returned this fd to us; nothing else owns it.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            for rule in rules {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&rule.path)
                    .map_err(|e| {
                        io::Error::new(e.kind(), format!("{}: {e}", rule.path.display()))
                    })?;
                // A rule on anything but a directory may carry file rights only.
                let is_dir = file.metadata()?.is_dir();
                let attr = PathBeneathAttr {
                    allowed_access: rights(rule.grant, abi, is_dir),
                    parent_fd: file.as_raw_fd(),
                };
                // SAFETY: `attr` is a live, initialised packed struct the kernel
                // reads by value; `fd` and `file` outlive the call.
                let rc = unsafe {
                    libc::syscall(
                        libc::SYS_landlock_add_rule,
                        fd.as_raw_fd(),
                        RULE_PATH_BENEATH,
                        &raw const attr,
                        0 as libc::c_uint,
                    )
                };
                if rc != 0 {
                    let e = io::Error::last_os_error();
                    return Err(io::Error::new(
                        e.kind(),
                        format!("landlock_add_rule {}: {e}", rule.path.display()),
                    ));
                }
            }
            Ok(Self { fd })
        }

        /// Restrict the calling process to the ruleset. Runs in the forked
        /// child after `no_new_privs`: one syscall, no allocation.
        pub(crate) fn restrict_self(&self) -> io::Result<()> {
            // SAFETY: a scalar fd and flags; async-signal-safe.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_landlock_restrict_self,
                    self.fd.as_raw_fd(),
                    0 as libc::c_uint,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::LandlockSupport;

    pub(super) fn probe() -> LandlockSupport {
        LandlockSupport::Unavailable {
            errno: libc::ENOSYS,
        }
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

    #[test]
    fn rights_follow_the_abi_and_the_file_kind() {
        assert_eq!(handled(1) & access::REFER, 0);
        assert_ne!(handled(2) & access::REFER, 0);
        assert_eq!(handled(2) & access::TRUNCATE, 0);
        assert_ne!(handled(3) & access::TRUNCATE, 0);
        assert_ne!(handled(5) & access::IOCTL_DEV, 0);
        // Read never writes; a file rule never carries a directory right.
        let read = rights(Grant::Read, 7, true);
        assert_eq!(read & access::WRITE_FILE, 0);
        assert_ne!(read & access::READ_DIR, 0);
        assert_eq!(rights(Grant::ReadWrite, 7, false) & !access::FILE, 0);
        assert_eq!(rights(Grant::ReadWrite, 2, true), handled(2));
    }

    #[test]
    fn the_minimum_abi_is_two() {
        assert_eq!(LandlockSupport::Abi(1).enforceable(), None);
        assert_eq!(LandlockSupport::Abi(2).enforceable(), Some(2));
        assert_eq!(LandlockSupport::Abi(7).enforceable(), Some(7));
        assert_eq!(
            LandlockSupport::Unavailable {
                errno: libc::ENOSYS
            }
            .enforceable(),
            None
        );
    }
}
