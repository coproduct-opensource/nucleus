//! Subordinate host ids: the local driver's realization contract (Program C,
//! C2).
//!
//! # Why a user namespace alone is not separation
//!
//! An unprivileged process can create a user namespace in which it is "uid 0",
//! but the kernel checks file access against the HOST credentials, and that
//! namespace's only mapping sends its uid 0 back to the caller's own host uid.
//! A bare-tier child in such a namespace still opens every file the node can,
//! the node's 0700 state directory and its signing keys included. Separation
//! needs a DIFFERENT host uid and gid for the child.
//!
//! # What this module does
//!
//! A non-root node's user may be delegated subordinate host ids (`/etc/subuid`,
//! `/etc/subgid`), which the setuid helpers `newuidmap` / `newgidmap` validate
//! before writing a child's id maps. [`SubordinateRange`] is that delegation,
//! read for the runtime's user; [`SubordinateIds`] is one pod's uid/gid inside
//! it. A child confined with one (`Posture::Subordinate` in `hardening`) enters
//! a fresh user namespace whose ONLY mapping is `id id 1` for that subordinate
//! id: host uid = namespace uid = the subordinate id, never the node's. The
//! hook then reads its own `uid_map` and `gid_map` back and refuses to exec
//! unless they are exactly that ([`map_is_exactly`]), so a mapping that sends
//! the child to the node's uid, or to namespace uid 0 over it, is not run.
//!
//! # The realization contract
//!
//! [`LocalRealization::check`] is the ONE decider (ADR 0007 G-1) of whether
//! the local driver's children are separated from the node. Its clauses:
//!
//! 1. **The node's signing material is unreachable.** The child's host uid is
//!    not the node's and not 0, and the state directory is the node's own,
//!    private (no group or other bits, no access ACL).
//! 2. **The child cannot impersonate, signal or ptrace the node.** A distinct
//!    host uid: `SO_PEERCRED` names the subordinate uid, `kill(2)` and
//!    `ptrace(2)` need the node's uid or a capability in the node's user
//!    namespace, and the child's capabilities are in its own namespace only.
//! 3. **Protected effects stay mediated.** The child installs the workload
//!    syscall denylist and the pod's derived classes, like a microVM child.
//! 4. **It holds across child creation.** The denylist refuses every new
//!    namespace (so no descendant remaps itself), and `no_new_privs` refuses
//!    setuid helpers to every descendant (so none runs `newuidmap` itself).
//!
//! Clauses 1 and 2 are then measured, not assumed: a probe child is spawned
//! through the real hook and must fail to enter the state directory and fail
//! to signal the node ([`LocalRealization::check`]). A host where any clause
//! fails is [`LocalRealization::SharedUid`], with the reason: the bare tier
//! stays the declared insecure mode (Program C, C0), never claimed separated.

use std::ffi::CStr;
use std::path::{Path, PathBuf};

/// Where the setuid id-map helpers are looked for, in order. Fixed paths, not
/// `PATH`: the node execs the first one it finds with its own credentials.
const UIDMAP_HELPERS: [&CStr; 3] = [
    c"/usr/bin/newuidmap",
    c"/bin/newuidmap",
    c"/usr/sbin/newuidmap",
];
const GIDMAP_HELPERS: [&CStr; 3] = [
    c"/usr/bin/newgidmap",
    c"/bin/newgidmap",
    c"/usr/sbin/newgidmap",
];

/// The delegation files `newuidmap` and `newgidmap` validate against.
const SUBUID_FILE: &str = "/etc/subuid";
const SUBGID_FILE: &str = "/etc/subgid";

/// The offset in a [`SubordinateRange`] the realization probe runs as. Pods
/// are given ids from [`FIRST_POD_OFFSET`] on, so no pod shares the probe's.
pub const PROBE_OFFSET: u32 = 0;
/// The first offset a pod's children are given.
pub const FIRST_POD_OFFSET: u32 = 1;

/// The two setuid helpers, found and checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MapHelpers {
    pub(crate) uidmap: &'static CStr,
    pub(crate) gidmap: &'static CStr,
}

/// One pod's subordinate host uid and gid, delegated to the runtime's user.
///
/// Evidence (ADR 0007 C-1): private fields, minted only by
/// [`SubordinateRange::ids`] and [`SubordinateIds::delegated`], both of which
/// read the delegation files and refuse the runtime's own uid and 0. `Copy`
/// because it is a decision, not an authority: it names ids the child is
/// moved TO, which only take away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubordinateIds {
    uid: u32,
    gid: u32,
    helpers: MapHelpers,
}

impl SubordinateIds {
    /// The host uid a child confined with these ids runs as.
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// The host gid a child confined with these ids runs as.
    #[must_use]
    pub fn gid(&self) -> u32 {
        self.gid
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn helpers(&self) -> MapHelpers {
        self.helpers
    }

    /// The ids `uid`:`gid`, if the runtime's user is delegated both: what the
    /// tool-proxy checks of the ids its node handed it (`--subordinate-ids`).
    ///
    /// # Errors
    /// [`SeparationUnmet`] naming the first clause that failed.
    pub fn delegated(uid: u32, gid: u32) -> Result<Self, SeparationUnmet> {
        let runtime = super::runtime_uid();
        let user = Delegation::read(runtime)?;
        check_ids(uid, gid, runtime)?;
        if !user.uids.iter().any(|r| r.contains(uid)) || !user.gids.iter().any(|r| r.contains(gid))
        {
            return Err(SeparationUnmet::IdsNotDelegated { uid, gid });
        }
        Ok(Self {
            uid,
            gid,
            helpers: find_helpers()?,
        })
    }

    /// Ids a unit test can confine a child with WITHOUT any delegation: the
    /// decision tables only. Never applied (the hook's maps would fail).
    #[cfg(test)]
    pub(crate) fn for_test(uid: u32, gid: u32) -> Self {
        Self {
            uid,
            gid,
            helpers: MapHelpers {
                uidmap: UIDMAP_HELPERS[0],
                gidmap: GIDMAP_HELPERS[0],
            },
        }
    }
}

/// Why the local driver's children are NOT separated from the node on this
/// host. Each is one failed clause of the realization contract, named.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SeparationUnmet {
    /// Subordinate ids and user namespaces are Linux features.
    #[error("subordinate host ids need Linux")]
    NotLinux,
    /// A root runtime drops its children to an unprivileged uid already; this
    /// contract is the non-root runtime's.
    #[error("the runtime is root; subordinate ids are the non-root bare tier's contract")]
    RuntimeIsRoot,
    /// The runtime's uid has no name in `/etc/passwd`, so no delegation line
    /// can be matched to it.
    #[error("uid {uid} has no entry in /etc/passwd, so no subordinate-id delegation names it")]
    UnknownUser {
        /// The runtime's uid.
        uid: u32,
    },
    /// A delegation file could not be read.
    #[error("{file} could not be read: {error}")]
    Unreadable {
        /// The file.
        file: &'static str,
        /// What the filesystem said.
        error: String,
    },
    /// No range is delegated to the runtime's user.
    #[error("{file} delegates no range to {user} (uid {uid})")]
    NoDelegation {
        /// The file.
        file: &'static str,
        /// The user's name.
        user: String,
        /// The user's uid.
        uid: u32,
    },
    /// A setuid helper is missing.
    #[error("{helper} is not installed (the `uidmap` package)")]
    HelperMissing {
        /// The helper's name.
        helper: &'static str,
    },
    /// A helper exists but is not one the node may exec with its credentials.
    #[error("{path} is not a root-owned helper writable only by root: {why}")]
    HelperUntrusted {
        /// Where it was found.
        path: String,
        /// Why it was refused.
        why: String,
    },
    /// A delegated id is the runtime's own uid or 0: a child mapped to it is
    /// the node, or root.
    #[error(
        "subordinate id {id} is the runtime's uid ({runtime}) or root: a child mapped there is \
         not separated from the node"
    )]
    IdIsNotSubordinate {
        /// The id.
        id: u32,
        /// The runtime's uid.
        runtime: u32,
    },
    /// Ids the runtime's user is not delegated.
    #[error("uid {uid} / gid {gid} are not delegated to the runtime's user")]
    IdsNotDelegated {
        /// The uid.
        uid: u32,
        /// The gid.
        gid: u32,
    },
    /// The delegated range is used up: an id is never given to two pods.
    #[error("the delegated subordinate range ({count} ids) is used up")]
    Exhausted {
        /// The range's size.
        count: u32,
    },
    /// The state directory is reachable by another uid.
    #[error("the state directory {path} is not private to the node: {why}")]
    StateDirShared {
        /// The directory.
        path: String,
        /// What makes it reachable.
        why: String,
    },
    /// The probe child, spawned through the real hook, was not separated.
    #[error("a probe child spawned at subordinate uid {uid} was not separated: {why}")]
    Probe {
        /// The probe's uid.
        uid: u32,
        /// What it observed, or why it could not run.
        why: String,
    },
}

/// The runtime user's delegated subordinate ranges, uid and gid, paired by
/// offset: offset `k` is uid `uid_start + k` and gid `gid_start + k`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubordinateRange {
    uid_start: u32,
    gid_start: u32,
    count: u32,
    runtime_uid: u32,
    helpers: MapHelpers,
}

impl SubordinateRange {
    /// The first range each delegation file grants the runtime's user, and
    /// the helpers.
    ///
    /// # Errors
    /// [`SeparationUnmet`] for the first missing piece.
    pub fn of_runtime() -> Result<Self, SeparationUnmet> {
        if !cfg!(target_os = "linux") {
            return Err(SeparationUnmet::NotLinux);
        }
        let runtime_uid = super::runtime_uid();
        if runtime_uid == 0 {
            return Err(SeparationUnmet::RuntimeIsRoot);
        }
        let user = Delegation::read(runtime_uid)?;
        Self::from_delegation(&user, runtime_uid, find_helpers()?)
    }

    /// The first uid range and the first gid range, paired by offset.
    fn from_delegation(
        user: &Delegation,
        runtime_uid: u32,
        helpers: MapHelpers,
    ) -> Result<Self, SeparationUnmet> {
        match (user.uids.first(), user.gids.first()) {
            (Some(uids), Some(gids)) => Ok(Self {
                uid_start: uids.start,
                gid_start: gids.start,
                count: uids.count.min(gids.count),
                runtime_uid,
                helpers,
            }),
            (None, _) | (_, None) => Err(SeparationUnmet::NoDelegation {
                file: if user.uids.is_empty() {
                    SUBUID_FILE
                } else {
                    SUBGID_FILE
                },
                user: user.name.clone(),
                uid: runtime_uid,
            }),
        }
    }

    /// How many offsets the range has.
    #[must_use]
    pub fn count(&self) -> u32 {
        self.count
    }

    /// The ids at `offset`.
    ///
    /// # Errors
    /// [`SeparationUnmet::Exhausted`] past the range, and
    /// [`SeparationUnmet::IdIsNotSubordinate`] for an id that is the
    /// runtime's uid or 0 (a misdelegated range).
    pub fn ids(&self, offset: u32) -> Result<SubordinateIds, SeparationUnmet> {
        if offset >= self.count {
            return Err(SeparationUnmet::Exhausted { count: self.count });
        }
        let (Some(uid), Some(gid)) = (
            self.uid_start.checked_add(offset),
            self.gid_start.checked_add(offset),
        ) else {
            return Err(SeparationUnmet::Exhausted { count: self.count });
        };
        check_ids(uid, gid, self.runtime_uid)?;
        Ok(SubordinateIds {
            uid,
            gid,
            helpers: self.helpers,
        })
    }
}

/// Refuse an id pair that is not separation: the runtime's own uid, or 0.
fn check_ids(uid: u32, gid: u32, runtime: u32) -> Result<(), SeparationUnmet> {
    for id in [uid, gid] {
        if id == 0 || id == runtime {
            return Err(SeparationUnmet::IdIsNotSubordinate { id, runtime });
        }
    }
    Ok(())
}

/// One `start:count` range from a delegation file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IdRange {
    pub(crate) start: u32,
    pub(crate) count: u32,
}

impl IdRange {
    fn contains(&self, id: u32) -> bool {
        id >= self.start && u64::from(id) < u64::from(self.start) + u64::from(self.count)
    }
}

/// What the two delegation files grant the runtime's user.
struct Delegation {
    name: String,
    uids: Vec<IdRange>,
    gids: Vec<IdRange>,
}

impl Delegation {
    fn read(runtime_uid: u32) -> Result<Self, SeparationUnmet> {
        let passwd = read_file("/etc/passwd")?;
        let name = user_name(&passwd, runtime_uid)
            .ok_or(SeparationUnmet::UnknownUser { uid: runtime_uid })?
            .to_owned();
        let side = |file: &'static str| -> Result<Vec<IdRange>, SeparationUnmet> {
            let ranges = delegated_ranges(&read_file(file)?, &name, runtime_uid);
            if ranges.is_empty() {
                return Err(SeparationUnmet::NoDelegation {
                    file,
                    user: name.clone(),
                    uid: runtime_uid,
                });
            }
            Ok(ranges)
        };
        Ok(Self {
            uids: side(SUBUID_FILE)?,
            gids: side(SUBGID_FILE)?,
            name,
        })
    }
}

fn read_file(file: &'static str) -> Result<String, SeparationUnmet> {
    std::fs::read_to_string(file).map_err(|e| SeparationUnmet::Unreadable {
        file,
        error: e.to_string(),
    })
}

/// The login name of `uid` in an `/etc/passwd` body.
pub(crate) fn user_name(passwd: &str, uid: u32) -> Option<&str> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _password = fields.next()?;
        let id: u32 = fields.next()?.parse().ok()?;
        (id == uid && !name.is_empty()).then_some(name)
    })
}

/// The ranges a `/etc/subuid` or `/etc/subgid` body delegates to the user
/// `name` (or to its numeric `uid`, which `newuidmap` also accepts), in file
/// order. Comments, blank and malformed lines and zero-length ranges are
/// skipped: they delegate nothing.
pub(crate) fn delegated_ranges(body: &str, name: &str, uid: u32) -> Vec<IdRange> {
    body.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#') {
                return None;
            }
            let mut fields = line.split(':');
            let owner = fields.next()?;
            let start: u32 = fields.next()?.trim().parse().ok()?;
            let count: u32 = fields.next()?.trim().parse().ok()?;
            if fields.next().is_some() || count == 0 {
                return None;
            }
            let ours = owner == name || owner.parse::<u32>().ok() == Some(uid);
            ours.then_some(IdRange { start, count })
        })
        .collect()
}

/// Find both helpers at their fixed paths, root-owned and writable by root
/// alone.
fn find_helpers() -> Result<MapHelpers, SeparationUnmet> {
    Ok(MapHelpers {
        uidmap: find_helper(&UIDMAP_HELPERS, "newuidmap")?,
        gidmap: find_helper(&GIDMAP_HELPERS, "newgidmap")?,
    })
}

fn find_helper(
    candidates: &[&'static CStr],
    helper: &'static str,
) -> Result<&'static CStr, SeparationUnmet> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    for &candidate in candidates {
        let path = Path::new(std::ffi::OsStr::from_bytes(candidate.to_bytes()));
        let Ok(meta) = std::fs::metadata(path) else {
            continue;
        };
        let untrusted = |why: &str| SeparationUnmet::HelperUntrusted {
            path: path.display().to_string(),
            why: why.to_owned(),
        };
        if !meta.is_file() {
            return Err(untrusted("not a regular file"));
        }
        if meta.uid() != 0 {
            return Err(untrusted("not owned by root"));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(untrusted("writable by group or others"));
        }
        return Ok(candidate);
    }
    Err(SeparationUnmet::HelperMissing { helper })
}

/// Whether a `/proc/<pid>/uid_map` (or `gid_map`) body maps exactly `id` to
/// host `id`, one id, and nothing else.
///
/// Allocation-free: the child's hook calls it between fork and exec. Every
/// other shape is refused, the one `unshare -r` writes among them
/// (`0 <runtime uid> 1`: namespace uid 0 over the node's own host uid, which
/// is the node's file access under another name).
#[must_use]
pub fn map_is_exactly(body: &[u8], id: u32) -> bool {
    let mut fields = [0u64; 3];
    let mut n = 0usize;
    let mut current: Option<u64> = None;
    for &b in body {
        match b {
            b'0'..=b'9' => {
                let digit = u64::from(b - b'0');
                let next = match current {
                    Some(v) => v.checked_mul(10).and_then(|v| v.checked_add(digit)),
                    None => Some(digit),
                };
                match next {
                    Some(v) if v <= u64::from(u32::MAX) => current = Some(v),
                    _ => return false,
                }
            }
            b' ' | b'\t' | b'\n' => {
                if let Some(v) = current.take() {
                    if n == fields.len() {
                        return false;
                    }
                    fields[n] = v;
                    n += 1;
                }
            }
            _ => return false,
        }
    }
    if let Some(v) = current {
        if n == fields.len() {
            return false;
        }
        fields[n] = v;
        n += 1;
    }
    n == 3 && fields == [u64::from(id), u64::from(id), 1]
}

/// The local driver's realization contract on this host: met, with the range
/// its children are given ids from, or unmet, with the clause that failed.
/// See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalRealization {
    /// Every clause held, the probe included: children run at subordinate
    /// host ids from this range.
    Separated(SubordinateRange),
    /// A clause failed: children would share the node's uid, so the bare tier
    /// is the declared insecure mode.
    SharedUid(SeparationUnmet),
}

impl LocalRealization {
    /// The ONE decider: delegation, helpers, a private state directory, and a
    /// probe child spawned through the real hook at [`PROBE_OFFSET`] that can
    /// neither enter `state_dir` nor signal this process.
    ///
    /// `sh` is the probe's command, `/bin/sh`, made by the caller: a process is
    /// started only at the spawn sites the mediation census names. Everything
    /// else about it (arguments, environment, directory, stdio, confinement)
    /// is set here.
    #[must_use]
    pub fn check(state_dir: &Path, sh: std::process::Command) -> Self {
        match Self::clauses(state_dir, sh) {
            Ok(range) => Self::Separated(range),
            Err(unmet) => Self::SharedUid(unmet),
        }
    }

    fn clauses(
        state_dir: &Path,
        sh: std::process::Command,
    ) -> Result<SubordinateRange, SeparationUnmet> {
        let range = SubordinateRange::of_runtime()?;
        state_dir_private(state_dir, range.runtime_uid)?;
        probe(range.ids(PROBE_OFFSET)?, state_dir, sh)?;
        Ok(range)
    }
}

/// Clause 1's static half: the state directory is the runtime's, with no
/// group or other bits and no access ACL.
fn state_dir_private(state_dir: &Path, runtime_uid: u32) -> Result<(), SeparationUnmet> {
    use std::os::unix::fs::MetadataExt;
    let shared = |why: String| SeparationUnmet::StateDirShared {
        path: state_dir.display().to_string(),
        why,
    };
    let meta = std::fs::symlink_metadata(state_dir).map_err(|e| shared(e.to_string()))?;
    if !meta.is_dir() {
        return Err(shared("not a directory".into()));
    }
    if meta.uid() != runtime_uid {
        return Err(shared(format!("owned by uid {}", meta.uid())));
    }
    let mode = meta.mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(shared(format!("mode {mode:o} has group or other bits")));
    }
    if imp::has_access_acl(state_dir).map_err(|e| shared(e.to_string()))? {
        return Err(shared("it carries an access ACL".into()));
    }
    Ok(())
}

/// The probe's exit codes, one per observation.
const PROBE_ENTERED_STATE_DIR: i32 = 3;
const PROBE_SIGNALLED_NODE: i32 = 4;
const PROBE_WRONG_UID: i32 = 5;

/// Clauses 1 and 2, measured: `sh`, confined exactly as a pod's children are,
/// must run as the subordinate uid, fail to enter the state directory and fail
/// to signal this process.
fn probe(
    ids: SubordinateIds,
    state_dir: &Path,
    mut cmd: std::process::Command,
) -> Result<(), SeparationUnmet> {
    let failed = |why: String| SeparationUnmet::Probe { uid: ids.uid, why };
    let confinement = super::ChildConfinement::decide(
        crate::command::ContainmentMode::Unsandboxed,
        super::runtime_uid(),
        super::UnsandboxedOptIn::Subordinate(ids),
        super::LandlockSupport::probe(),
        super::LandlockWaiver::Absent,
    )
    .map_err(|e| failed(e.to_string()))?;
    let script = format!(
        "[ \"$(id -u)\" = \"$3\" ] || exit {PROBE_WRONG_UID}; \
         cd \"$1\" 2>/dev/null && exit {PROBE_ENTERED_STATE_DIR}; \
         kill -0 \"$2\" 2>/dev/null && exit {PROBE_SIGNALLED_NODE}; exit 0"
    );
    cmd.arg("-c")
        .arg(script)
        .arg("sh")
        .arg(state_dir)
        .arg(std::process::id().to_string())
        .arg(ids.uid.to_string())
        .current_dir("/")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    let hardening = confinement.apply(
        &mut cmd,
        super::RlimitPolicy::node_ceiling().at_ceiling(),
        portcullis::SeccompPolicy::derive(
            &portcullis::PermissionLattice::permissive(),
            portcullis::NetworkEgress::Declared,
        ),
        &super::WorkspaceWrites::Writable,
    );
    if !hardening.is_hardened() {
        return Err(failed("the confinement hook is not available here".into()));
    }
    let out = cmd.output().map_err(|e| failed(format!("spawn: {e}")))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    match out.status.code() {
        Some(0) => Ok(()),
        Some(PROBE_ENTERED_STATE_DIR) => Err(failed(format!(
            "it entered the state directory {}",
            state_dir.display()
        ))),
        Some(PROBE_SIGNALLED_NODE) => Err(failed("it could signal the node".into())),
        Some(PROBE_WRONG_UID) => Err(failed("it did not run as its subordinate uid".into())),
        other => Err(failed(format!("it exited {other:?}: {}", stderr.trim()))),
    }
}

/// Give `ids` what the runtime's user has on `root` and everything under it
/// (symlinks are not followed), by POSIX ACL: an access ACL naming the
/// subordinate uid and gid with the owner's permission bits, and on each
/// directory a default ACL that also names the runtime's uid, so what either
/// side creates there stays usable by the other. Nothing outside `root`
/// changes, and nothing under it gains a permission its owner lacks.
///
/// # Errors
/// The first path whose ACL could not be read or set.
pub fn grant_workspace(root: &Path, ids: SubordinateIds) -> std::io::Result<()> {
    let runtime_uid = super::runtime_uid();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            continue;
        }
        imp::grant(&path, &meta, ids, runtime_uid)
            .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
        if meta.is_dir() {
            for entry in std::fs::read_dir(&path)? {
                stack.push(entry?.path());
            }
        }
    }
    Ok(())
}

/// The POSIX ACL xattr encoding (`linux/posix_acl_xattr.h`), version 2.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod acl {
    const VERSION: u32 = 2;
    const USER_OBJ: u16 = 0x01;
    const USER: u16 = 0x02;
    const GROUP_OBJ: u16 = 0x04;
    const GROUP: u16 = 0x08;
    const MASK: u16 = 0x10;
    const OTHER: u16 = 0x20;
    const UNDEFINED_ID: u32 = u32::MAX;

    fn entry(out: &mut Vec<u8>, tag: u16, perm: u32, id: u32) {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&u16::try_from(perm & 0o7).unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&id.to_le_bytes());
    }

    /// An ACL for a file of `mode` naming `uid` and `gid` (and, for a
    /// default ACL, `also_uid` too) with the owner's bits. Entries sorted by
    /// tag, then id, as the kernel requires.
    pub(crate) fn encode(mode: u32, uid: u32, gid: u32, also_uid: Option<u32>) -> Vec<u8> {
        let owner = (mode >> 6) & 0o7;
        let mut users = vec![uid];
        if let Some(also) = also_uid
            && also != uid
        {
            users.push(also);
        }
        users.sort_unstable();
        let mut out = VERSION.to_le_bytes().to_vec();
        entry(&mut out, USER_OBJ, owner, UNDEFINED_ID);
        for u in users {
            entry(&mut out, USER, owner, u);
        }
        entry(&mut out, GROUP_OBJ, (mode >> 3) & 0o7, UNDEFINED_ID);
        entry(&mut out, GROUP, owner, gid);
        entry(&mut out, MASK, owner, UNDEFINED_ID);
        entry(&mut out, OTHER, mode & 0o7, UNDEFINED_ID);
        out
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::path::Path;

    use super::SubordinateIds;

    const ACCESS: &str = "system.posix_acl_access";
    const DEFAULT: &str = "system.posix_acl_default";

    pub(super) fn has_access_acl(path: &Path) -> std::io::Result<bool> {
        let mut buf = [0u8; 256];
        match rustix::fs::lgetxattr(path, ACCESS, &mut buf) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NODATA | rustix::io::Errno::OPNOTSUPP) => Ok(false),
            // Larger than the buffer: it exists.
            Err(rustix::io::Errno::RANGE) => Ok(true),
            Err(e) => Err(e.into()),
        }
    }

    pub(super) fn grant(
        path: &Path,
        meta: &std::fs::Metadata,
        ids: SubordinateIds,
        runtime_uid: u32,
    ) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode();
        let access = super::acl::encode(mode, ids.uid, ids.gid, None);
        rustix::fs::lsetxattr(path, ACCESS, &access, rustix::fs::XattrFlags::empty())?;
        if meta.is_dir() {
            let default =
                super::acl::encode(0o700 | (mode & 0o077), ids.uid, ids.gid, Some(runtime_uid));
            rustix::fs::lsetxattr(path, DEFAULT, &default, rustix::fs::XattrFlags::empty())?;
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::path::Path;

    use super::SubordinateIds;

    pub(super) fn has_access_acl(_path: &Path) -> std::io::Result<bool> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    pub(super) fn grant(
        _path: &Path,
        _meta: &std::fs::Metadata,
        _ids: SubordinateIds,
        _runtime_uid: u32,
    ) -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

#[cfg(test)]
#[path = "subordinate_tests.rs"]
mod tests;
