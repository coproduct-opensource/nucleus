//! What a pod's jail holds, and who owns each inode in it (#3152).
//!
//! # The defect this closes
//!
//! `prepare_jail` used to chown every file it put in the jail to the jail's uid. The kernel and
//! rootfs are put there by HARD LINK, and a hard link is the same inode as the node's installed
//! artifact, so the chown gave the artifact every pod boots to the jail user. #3151 made the
//! rootfs read-only to the guest; the owner was still the jail user. A process that escaped
//! Firecracker as that uid could rewrite the kernel the next pod boots: cross-pod persistence one
//! escape away.
//!
//! The same loop had a second door. A relaunch under the same pod id finds the previous jail's
//! entries still there, and the node wrote the config through whatever was at `/config.json` and
//! chowned whatever was at `/firecracker.log`, following a symlink or a hard link that the
//! previous, escaped VMM was free to plant (it owns the jail root).
//!
//! # One decision per role (ADR 0007 G-1, B-3)
//!
//! An entry in the jail is exactly one of two things, and they are two types:
//!
//! - **Placed** — an existing host file brought inside by [`place`], as its [`ArtifactRole`]'s
//!   [`Placement`] says. The node NEVER changes its owner or mode: a hard link is somebody
//!   else's inode. What the jail user may do with it is a property the inode must already have,
//!   checked by [`admit`] and refused by name otherwise. A copy, where one is allowed, is made
//!   root-owned and read-only.
//! - **Born in the jail** — a file the node makes for this pod (the config, the log, a
//!   node-provisioned scratch disk). Only a [`BornInJail`] can be given to the jail user, it can
//!   only be minted by `create_new` after the path is cleared, and the hand-over is an `fchown`
//!   on its open fd, which refuses an inode with a second link. So the inode handed over exists
//!   nowhere else.
//!
//! There is no function here that chowns a path. That is what makes "hard link" and "chown"
//! unable to meet on one inode, rather than a rule each call site has to remember.
//!
//! # What this does not cover
//!
//! - Access is decided from owner, group and mode bits. A POSIX ACL or a supplementary group of
//!   the jail user can grant more; the jailer drops to a uid/gid pair with no supplementary
//!   groups, and nucleus never sets ACLs, so neither arises on a provisioned node.
//! - A published snapshot base (`snapshot_restore`) is hard-linked too and is not placed through
//!   here; it never was chowned, but who owns it is decided by `snapshot_store`.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::firecracker_config::in_jail;

/// The uid/gid the jailed VMM drops to: the principal every check here is about. One type with
/// `nucleus-hostctl seed`, which must hand a written-through disk to the same principal.
pub(crate) use nucleus_microvm_host::jail_user::JailUser;

/// What a host file brought into the jail IS. The role decides the in-jail name and the
/// [`Placement`], in one exhaustive match each, so a new role is a compile error in both before
/// it is a file nobody decided the ownership of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArtifactRole {
    Kernel,
    Rootfs,
    /// The read-only data image (`image.data_path`).
    Data,
    /// A custom seccomp BPF filter, which the VMM opens after `chroot`.
    SeccompFilter,
    /// A caller-supplied `image.scratch_path`: the caller's own disk, which the guest writes and
    /// the caller harvests afterwards (`nucleus-hostctl harvest`).
    CallerScratch,
}

impl ArtifactRole {
    /// The name the VMM opens it by, after `chroot`.
    pub(crate) fn in_jail(self) -> &'static str {
        match self {
            ArtifactRole::Kernel => in_jail::KERNEL,
            ArtifactRole::Rootfs => in_jail::ROOTFS,
            ArtifactRole::Data => in_jail::DATA,
            ArtifactRole::SeccompFilter => in_jail::SECCOMP,
            ArtifactRole::CallerScratch => in_jail::SCRATCH,
        }
    }

    /// THE decision: how it gets into the jail and what the jail user may do with it.
    pub(crate) fn placement(self) -> Placement {
        match self {
            // `lower_drives` attaches the rootfs and data image read-only, and the kernel and
            // filter are not drives at all. Every one of them may be the same inode in every jail
            // on the node.
            ArtifactRole::Kernel
            | ArtifactRole::Rootfs
            | ArtifactRole::Data
            | ArtifactRole::SeccompFilter => Placement::SharedReadOnly,
            // `lower_drives` gives scratch `is_read_only: false` unconditionally.
            ArtifactRole::CallerScratch => Placement::GuestWritesThrough,
        }
    }

    /// The spec field it came from, so a refusal names what the operator wrote.
    pub(crate) fn field(self) -> &'static str {
        match self {
            ArtifactRole::Kernel => "image.kernel_path",
            ArtifactRole::Rootfs => "image.rootfs_path",
            ArtifactRole::Data => "image.data_path",
            ArtifactRole::SeccompFilter => "seccomp.filter_path",
            ArtifactRole::CallerScratch => "image.scratch_path",
        }
    }
}

/// How a host file may be brought into the jail, and what the jail user must already be able to
/// do with it. Neither arm changes the inode's owner or mode: that is the point of the type.
///
/// THE LINK-VERSUS-COPY HALF IS ABOUT DATA, NOT ISOLATION. A non-jailed Firecracker is handed the
/// caller's path directly, so the guest's writes to a scratch disk land in the caller's file.
/// Under a jail a hard link preserves exactly that, and a copy silently does not; so a
/// cross-device jail must be a LAUNCH FAILURE for anything the guest writes, never a quiet copy
/// that every pod appears to survive while its writes are discarded at teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placement {
    /// The guest only reads it, and it may be the inode every pod on the node boots. Hard link,
    /// or a root-owned read-only copy across devices. The jail user must be able to read it and
    /// must NOT be able to modify it — owning it counts, because an owner can `chmod`.
    SharedReadOnly,
    /// The guest writes through it to the caller's file. Hard link or fail. The jail user must
    /// ALREADY be able to read and write it: the node will not chown it, because the link is the
    /// caller's own inode.
    GuestWritesThrough,
}

/// One host file that must exist inside the jail before Firecracker execs.
#[derive(Debug, Clone)]
pub(crate) struct JailResource {
    /// Where it lives on the host now (already confined and resolved by `host_paths::admit`).
    pub host_source: PathBuf,
    pub role: ArtifactRole,
}

impl JailResource {
    pub(crate) fn in_jail(&self) -> &'static str {
        self.role.in_jail()
    }

    pub(crate) fn placement(&self) -> Placement {
        self.role.placement()
    }
}

/// What the jail user can do to an inode, from its owner, group and mode bits alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JailAccess {
    pub read: bool,
    /// Write it, or make it writable: an owner can `chmod` whatever the bits say.
    pub modify: bool,
}

/// POSIX permission selection: the owner class if the uid owns it, else the group class if the
/// gid matches, else other. Exactly one class applies — a group-readable file the owner has
/// `0o040` on is NOT readable by the owner.
pub(crate) fn jail_access(owner: u32, group: u32, mode: u32, who: JailUser) -> JailAccess {
    if owner == who.uid {
        JailAccess {
            read: mode & 0o400 != 0,
            modify: true,
        }
    } else if group == who.gid {
        JailAccess {
            read: mode & 0o040 != 0,
            modify: mode & 0o020 != 0,
        }
    } else {
        JailAccess {
            read: mode & 0o004 != 0,
            modify: mode & 0o002 != 0,
        }
    }
}

/// Why a host file may not go into a jail. Every arm is a refusal (B-3); there is no "could not
/// tell" arm that lets it through (A-2).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// It could not be inspected at all.
    CannotInspect {
        what: &'static str,
        path: PathBuf,
        error: String,
    },
    /// It is not a regular file.
    NotAFile { what: &'static str, path: PathBuf },
    /// A shared artifact the jailed VMM cannot open.
    JailCannotRead(Found),
    /// A shared artifact the jail user could rewrite for every later pod.
    JailCanModifyShared(Found),
    /// A disk the guest writes through, which the jail user cannot write.
    JailCannotWrite(Found),
}

/// The inode facts a refusal reports.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Found {
    pub what: &'static str,
    pub path: PathBuf,
    pub owner: u32,
    pub group: u32,
    pub mode: u32,
    pub who: JailUser,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::CannotInspect { what, path, error } => {
                write!(f, "{what} {} cannot be inspected: {error}", path.display())
            }
            Refusal::NotAFile { what, path } => {
                write!(f, "{what} {} is not a regular file", path.display())
            }
            Refusal::JailCannotRead(x) => write!(
                f,
                "{} {} is mode {:04o} owned by {}:{}, which the jailed VMM (uid {} gid {}) \
                 cannot read. A shared artifact is installed root-owned and world-readable: \
                 `chown 0:0 {p} && chmod 0444 {p}`, or rerun `nucleus setup`. The node does not \
                 chown it for you: it is hard-linked into every jail, so its owner is every \
                 pod's (#3152).",
                x.what,
                x.path.display(),
                x.mode,
                x.owner,
                x.group,
                x.who.uid,
                x.who.gid,
                p = x.path.display(),
            ),
            Refusal::JailCanModifyShared(x) => write!(
                f,
                "{} {} is mode {:04o} owned by {}:{}, so the jail user (uid {} gid {}) can \
                 modify it. It is hard-linked into every jail, so a process that escapes one pod \
                 could rewrite what every later pod boots (#3152). Make it root-owned and \
                 read-only: `chown 0:0 {p} && chmod 0444 {p}`, or rerun `nucleus setup`.",
                x.what,
                x.path.display(),
                x.mode,
                x.owner,
                x.group,
                x.who.uid,
                x.who.gid,
                p = x.path.display(),
            ),
            Refusal::JailCannotWrite(x) => write!(
                f,
                "{} {} is mode {:04o} owned by {}:{}, which the jailed VMM (uid {} gid {}) \
                 cannot read and write. It is the guest's writable disk and is hard-linked into \
                 the jail so the guest's writes reach it, so it must already be the jail user's: \
                 `chown {}:{} {p} && chmod 0600 {p}`. The node does not chown it: the link is \
                 the caller's own inode (#3152).",
                x.what,
                x.path.display(),
                x.mode,
                x.owner,
                x.group,
                x.who.uid,
                x.who.gid,
                x.who.uid,
                x.who.gid,
                p = x.path.display(),
            ),
        }
    }
}

/// Whether the inode at `path` already allows what `placement` needs, and nothing a shared
/// artifact must not allow. Reads only; changes nothing.
pub(crate) fn admit(
    path: &Path,
    what: &'static str,
    placement: Placement,
    who: JailUser,
) -> Result<(), Refusal> {
    let meta = std::fs::metadata(path).map_err(|e| Refusal::CannotInspect {
        what,
        path: path.to_path_buf(),
        error: e.to_string(),
    })?;
    if !meta.is_file() {
        return Err(Refusal::NotAFile {
            what,
            path: path.to_path_buf(),
        });
    }
    let access = jail_access(meta.uid(), meta.gid(), meta.mode(), who);
    let found = || Found {
        what,
        path: path.to_path_buf(),
        owner: meta.uid(),
        group: meta.gid(),
        mode: meta.mode() & 0o7777,
        who,
    };
    match placement {
        Placement::SharedReadOnly if !access.read => Err(Refusal::JailCannotRead(found())),
        Placement::SharedReadOnly if access.modify => Err(Refusal::JailCanModifyShared(found())),
        Placement::SharedReadOnly => Ok(()),
        Placement::GuestWritesThrough if access.read && access.modify => Ok(()),
        Placement::GuestWritesThrough => Err(Refusal::JailCannotWrite(found())),
    }
}

/// The artifacts `nucleus setup` installs, by the name a refusal gives them.
const INSTALLED: [(&str, &str); 2] = [
    (
        "installed guest kernel",
        nucleus_spec::tier2_artifacts::GUEST_KERNEL_FILE,
    ),
    (
        "installed guest rootfs",
        nucleus_spec::tier2_artifacts::GUEST_ROOTFS_FILE,
    ),
];

/// Node startup: refuse, by name, an installed artifact the jail user cannot read or could
/// modify, instead of discovering it at the first pod (or chowning it, which is #3152).
///
/// An artifact that is ABSENT is not checked and not refused: no pod can boot it, and a node
/// that serves only container pods has none. Returns how many were checked, so a caller can tell
/// "all fine" from "nothing there" (A-5).
pub(crate) fn check_installed_artifacts(
    artifacts_root: &Path,
    who: JailUser,
) -> Result<usize, Refusal> {
    let mut checked = 0;
    for (what, file) in INSTALLED {
        let path = artifacts_root.join(file);
        match std::fs::metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(Refusal::CannotInspect {
                    what,
                    path,
                    error: e.to_string(),
                });
            }
            Ok(_) => {
                admit(&path, what, Placement::SharedReadOnly, who)?;
                checked += 1;
            }
        }
    }
    Ok(checked)
}

/// Remove whatever is at `path` without following it. A symlink or hard link planted there by a
/// previous jail's VMM is unlinked, never written through.
fn clear_stale(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot inspect stale {}: {e}", path.display())),
        Ok(m) if m.is_dir() => Err(format!(
            "{} is a directory where the jail needs a file",
            path.display()
        )),
        Ok(_) => std::fs::remove_file(path)
            .map_err(|e| format!("cannot clear stale {}: {e}", path.display())),
    }
}

/// Bring one host file into the jail as its role's [`Placement`] says. Never changes the owner or
/// mode of `resource.host_source`, which a hard link shares.
///
/// Hard link first, always: it is cheap, it shares no page cache the file did not already share,
/// and it keeps the guest's writes visible at the caller's path exactly as the non-jailed path
/// does.
pub(crate) fn place(resource: &JailResource, dest: &Path, who: JailUser) -> Result<(), String> {
    let placement = resource.placement();
    admit(&resource.host_source, resource.role.field(), placement, who)
        .map_err(|r| r.to_string())?;
    clear_stale(dest)?;
    match std::fs::hard_link(&resource.host_source, dest) {
        Ok(()) => Ok(()),
        Err(err) => match placement {
            Placement::GuestWritesThrough => Err(format!(
                "cannot hard-link {} into the jail at {}: {err}. This resource is \
                 WRITABLE by the guest, so falling back to a copy would silently \
                 discard the guest's writes instead of landing them at the source \
                 path — which is what the non-jailed path does. Put the jail \
                 (--jailer-chroot-base) on the same filesystem as the image, or \
                 pass an image whose writable drives already live there.",
                resource.host_source.display(),
                dest.display()
            )),
            Placement::SharedReadOnly => {
                copy_read_only(&resource.host_source, dest).map_err(|copy_err| {
                    format!(
                        "cannot bring {} into the jail: hard link failed ({err}) and \
                         copy failed ({copy_err})",
                        resource.host_source.display()
                    )
                })
            }
        },
    }
}

/// A cross-device copy of a shared artifact: a new inode, owned by the node, `0444`. Readable by
/// the jail user for the same reason the source is, and writable by nobody but root.
fn copy_read_only(source: &Path, dest: &Path) -> std::io::Result<()> {
    let mut from = File::open(source)?;
    let mut to = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(dest)?;
    std::io::copy(&mut from, &mut to)?;
    // Creation is filtered by umask. Set the final mode through this new inode's fd so
    // a restrictive node umask cannot remove the jail user's read access.
    to.set_permissions(std::fs::Permissions::from_mode(0o444))?;
    to.sync_all()
}

/// A file the node made for this pod, inside the jail, that no other path names yet.
///
/// Minted only by [`BornInJail::create`] (C-1), and handed to the jail user only by
/// [`BornInJail::give_to_jail`], which takes it by value (C-4).
#[must_use = "a file born in the jail is either given to the jail user or dropped deliberately"]
pub(crate) struct BornInJail {
    file: File,
    path: PathBuf,
}

impl BornInJail {
    /// Clear `path` without following it, then create a fresh file there with `create_new`, which
    /// refuses to open anything that already exists.
    pub(crate) fn create(path: &Path) -> Result<Self, String> {
        clear_stale(path)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(path)
            .map_err(|e| format!("cannot create {} in the jail: {e}", path.display()))?;
        Ok(BornInJail {
            file,
            path: path.to_path_buf(),
        })
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    /// Write `bytes` as the whole content.
    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.file
            .write_all(bytes)
            .map_err(|e| format!("cannot write {}: {e}", self.path.display()))
    }

    /// Give the inode to the jail user, through the fd — never by path. Refuses an inode that has
    /// gained a second link since it was created: that would be the one way the chown could
    /// reach a file that exists somewhere else.
    pub(crate) fn give_to_jail(self, who: JailUser) -> Result<(), String> {
        let links = self
            .file
            .metadata()
            .map_err(|e| format!("cannot inspect {}: {e}", self.path.display()))?
            .nlink();
        if links != 1 {
            return Err(format!(
                "{} has {links} links; a file born in the jail is given to the jail user only \
                 while it is the only name for its inode",
                self.path.display()
            ));
        }
        std::os::unix::fs::fchown(&self.file, Some(who.uid), Some(who.gid)).map_err(|e| {
            format!(
                "cannot chown {} to {}:{}: {e}",
                self.path.display(),
                who.uid,
                who.gid
            )
        })
    }
}

#[cfg(test)]
#[path = "jail_placement_tests.rs"]
mod tests;
