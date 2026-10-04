//! A pinned, read-only rootfs measured once per node process instead of once per pod.
//!
//! # What this replaces, and why a stat cache could not
//!
//! `image_identity::verify` holds the PLACED rootfs to its pin before every boot. For a gate
//! image that is a full SHA-256 read of an 8 GiB file per pod step (p50 ~9.5 s), of a file
//! that has not changed since the last step. The obvious cache, keyed on
//! `(dev, ino, size, mtime)`, is not sound and was already removed once (#2972, gatehouse
//! F-161; see `IdentityManager::compute_attestation`): any writer can change the bytes and
//! put the mtime back, and ext4 has been seen to lose data blocks without moving any stat
//! field at all. Here it is worse than a guess, because the placed rootfs is a HARD LINK of
//! the shared catalog file and `prepare_jail` chowns it to the jailer uid: every jailed VMM
//! on the node owns that one inode.
//!
//! # What this does instead: identity implies content
//!
//! The node keeps its OWN copy of each pinned rootfs, in a directory only it can enter, and
//! makes that copy kernel-immutable before reading a byte of it:
//!
//! 1. `FICLONE` the source into `<dir>/<pin>.<n>` (a reflink: O(extents), no data copied),
//!    `fsync` it, close the only writable descriptor;
//! 2. set `FS_IMMUTABLE_FL`. From here no process -- root included -- can write, truncate,
//!    link, rename or unlink the inode without first clearing the flag, which needs
//!    `CAP_LINUX_IMMUTABLE` and moves the inode's `ctime`;
//! 3. record `(dev, ino, ctime, immutable)` from the descriptor the node keeps open, THEN
//!    measure it, and keep it only if the measurement equals the pin.
//!
//! A later pod pinning the same digest gets a fresh `FICLONE` of that sealed inode as its
//! jail rootfs, after the node re-reads the record from its open descriptor: still the same
//! inode, still immutable, `ctime` unchanged. "Unchanged since it was measured" is then a
//! kernel guarantee rather than an inference from timestamps, because the only way to change
//! the bytes goes through a flag change the record would see.
//!
//! The pod's clone is its OWN inode. A VMM that writes its rootfs (it opens it read-only; a
//! compromised one might not) breaks copy-on-write into its private extents and cannot reach
//! the sealed copy, the catalog file, or any other pod -- which the shared hard link it
//! replaces could not say.
//!
//! # Where it falls back, and to what
//!
//! Every failure here returns `None`, and `None` means the pod is placed and verified exactly
//! as before: hard link, full read, held to the pin. That covers a filesystem without reflink
//! (`FICLONE` refuses, e.g. ext4), a source on another filesystem (`EXDEV`), a node without
//! `CAP_LINUX_IMMUTABLE`, and any record that no longer matches. Nothing in this module can
//! turn a pod that boots into one that does not, or skip a read it cannot justify.
//!
//! # Why not fs-verity
//!
//! fs-verity would be stronger -- it also turns silent block corruption into `EIO` -- but the
//! production lane's scratch filesystem is XFS (reflink is why), and XFS answers
//! `FS_IOC_ENABLE_VERITY` with `ENOTTY`. ext4 has verity and no reflink. Immutable-plus-reflink
//! is the strongest seal the lane's filesystem offers.

use std::path::{Path, PathBuf};

use nucleus_identity::attestation::Hash256;

/// Evidence from sealing for one destination and one requested pin (ADR 0007 C-1/C-2).
/// Only this module constructs it; verification consumes it rather than accepting a raw hash.
/// A mismatched measurement is retained only to report the pin failure, never to bless bytes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RootfsMeasurement {
    dest: PathBuf,
    expected: String,
    measured: Hash256,
}

impl RootfsMeasurement {
    pub(crate) fn for_path(
        &self,
        dest: &Path,
        expected: &nucleus_spec::ArtifactDigest,
    ) -> Result<Hash256, String> {
        if self.dest != dest || self.expected != expected.hex() {
            return Err("sealed rootfs evidence belongs to another destination or pin".into());
        }
        Ok(self.measured)
    }

    #[cfg(test)]
    pub(crate) fn fixture(
        dest: &Path,
        expected: &nucleus_spec::ArtifactDigest,
        measured: Hash256,
    ) -> Self {
        Self {
            dest: dest.to_path_buf(),
            expected: expected.hex().to_string(),
            measured,
        }
    }
}

/// What the node recorded about a sealed inode, and re-reads before every reuse.
///
/// Equality of the whole record is the reuse condition. `ctime` is in it because every way
/// to change the bytes of an immutable inode first clears the flag, and a flag change is an
/// inode change: the kernel stamps `ctime`, and userspace cannot set it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct Seal {
    pub dev: u64,
    pub ino: u64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub immutable: bool,
}

/// The reuse decision, pure so it can be tested on any host and probed without a kernel.
///
/// Both records must be immutable: a seal that was never set proves nothing, and one that is
/// no longer set means some holder of `CAP_LINUX_IMMUTABLE` has opened the inode to writes.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn still_sealed(recorded: &Seal, now: &Seal) -> bool {
    recorded.immutable && now.immutable && recorded == now
}

/// How many sealed rootfs copies the node keeps. Each pins its extents after the catalog has
/// pruned the source, so this is a disk bound, not a performance knob: a lane uses one or two
/// gate images at a time, and an evicted digest is simply sealed again on its next pod.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const CAPACITY: usize = 4;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Entry {
    pin_hex: String,
    path: PathBuf,
    /// Held for the process lifetime: the inode cannot be freed and its number reused while
    /// this is open, and every reuse check and clone goes through it rather than the path.
    file: std::fs::File,
    seal: Seal,
    measured: Hash256,
}

/// The node's store of sealed rootfs copies. One per node process; nothing in it is trusted
/// across a restart (`open` empties the directory), so there is no on-disk record to forge.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct SealedRootfs {
    dir: PathBuf,
    /// Most recently used last. One lock for the store: a miss holds it for one measurement,
    /// once per digest per node life, and a hit for a few syscalls.
    entries: tokio::sync::Mutex<Vec<Entry>>,
    next: std::sync::atomic::AtomicU64,
}

/// The store a node runs with: `<chroot base>/.nucleus-sealed-rootfs` when sealing is on and
/// pods are jailed (a sibling of the jailer's `<exec>` directory, so `reclaim_orphaned_jails`
/// never walks it, and on the jails' filesystem by construction). A store that cannot be
/// opened is logged and absent: pods are then measured as before.
pub(crate) fn from_flags(
    enabled: bool,
    chroot_base: &Path,
) -> Option<std::sync::Arc<SealedRootfs>> {
    if !enabled {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        let dir = chroot_base.join(".nucleus-sealed-rootfs");
        match SealedRootfs::open(&dir) {
            Ok(store) => return Some(std::sync::Arc::new(store)),
            Err(e) => tracing::warn!(dir = %dir.display(), error = %e,
                "cannot open the sealed rootfs store; every pod's rootfs will be read before boot"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = chroot_base;
    None
}

#[cfg(target_os = "linux")]
mod sys {
    use std::os::fd::AsRawFd;

    /// `FS_IMMUTABLE_FL` from `<linux/fs.h>`; libc does not export the flag values.
    const FS_IMMUTABLE_FL: libc::c_int = 0x0000_0010;

    fn check(rc: libc::c_int) -> std::io::Result<()> {
        if rc < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn flags(file: &std::fs::File) -> std::io::Result<libc::c_int> {
        let mut flags: libc::c_int = 0;
        // SAFETY: FS_IOC_GETFLAGS writes one int through the pointer, which is valid for the
        // call; the descriptor is owned by `file` and open for its duration.
        check(unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) })?;
        Ok(flags)
    }

    pub(super) fn is_immutable(file: &std::fs::File) -> std::io::Result<bool> {
        Ok(flags(file)? & FS_IMMUTABLE_FL != 0)
    }

    pub(super) fn set_immutable(file: &std::fs::File, on: bool) -> std::io::Result<()> {
        let old = flags(file)?;
        let mut new = if on {
            old | FS_IMMUTABLE_FL
        } else {
            old & !FS_IMMUTABLE_FL
        };
        // SAFETY: FS_IOC_SETFLAGS reads one int through the pointer, valid for the call.
        check(unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_SETFLAGS, &mut new) })
    }

    /// Make `dst` share `src`'s extents. `dst` must be open for writing; `src` for reading.
    pub(super) fn clone_into(src: &std::fs::File, dst: &std::fs::File) -> std::io::Result<()> {
        // SAFETY: FICLONE takes the source descriptor by value; both are owned and open.
        check(unsafe { libc::ioctl(dst.as_raw_fd(), libc::FICLONE, src.as_raw_fd()) })
    }
}

#[cfg(target_os = "linux")]
fn seal_of(file: &std::fs::File) -> std::io::Result<Seal> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata()?;
    Ok(Seal {
        dev: m.dev(),
        ino: m.ino(),
        ctime_sec: m.ctime(),
        ctime_nsec: m.ctime_nsec(),
        immutable: sys::is_immutable(file)?,
    })
}

/// Clear the seal and remove the copy. Best-effort: what cannot be removed is disk, and the
/// next `open` sweeps it.
#[cfg(target_os = "linux")]
fn discard(path: &Path, file: &std::fs::File) {
    let _ = sys::set_immutable(file, false);
    let _ = std::fs::remove_file(path);
}

#[cfg(target_os = "linux")]
impl SealedRootfs {
    /// Open the store at `dir`, discarding everything a previous node life left there.
    ///
    /// `dir` must be on the filesystem of the rootfs sources and of the jails, or every
    /// `FICLONE` answers `EXDEV` and every pod falls back to today's path.
    pub(crate) fn open(dir: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        for entry in std::fs::read_dir(dir)?.flatten() {
            let path = entry.path();
            if let Ok(f) = std::fs::File::open(&path) {
                discard(&path, &f);
            } else {
                let _ = std::fs::remove_file(&path);
            }
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            entries: tokio::sync::Mutex::new(Vec::new()),
            next: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Put a clone of the sealed copy of `source` at the jail's rootfs path, and return the
    /// digest that copy was measured to have.
    ///
    /// `Some(evidence)` binds the measurement to `dest` and `pin`: they are a clone of an inode
    /// that was immutable when it was read and has stayed so. The measurement may differ from `pin` --
    /// a source that does not match its pin is measured, not placed, and `verify` refuses
    /// it with the usual message. `None` changes nothing: `dest` is still whatever
    /// `prepare_jail` put there, and the caller verifies it by reading.
    #[tracing::instrument(skip_all, fields(boot.stage = "image.seal"))]
    pub(crate) async fn place(
        &self,
        source: &Path,
        pin: &nucleus_spec::ArtifactDigest,
        dest: &Path,
        owner: (u32, u32),
    ) -> Option<RootfsMeasurement> {
        let mut entries = self.entries.lock().await;
        let at = match self.find_or_seal(&mut entries, source, pin.hex()).await {
            Ok(at) => at,
            Err(why) => {
                tracing::info!(source = %source.display(), %why, "rootfs not sealed; measuring it in place");
                return None;
            }
        };
        let entry = &entries[at];
        if hex::encode(entry.measured) != pin.hex() {
            // Measured, refused below by `verify`, and never kept.
            let measured = entry.measured;
            let gone = entries.remove(at);
            discard(&gone.path, &gone.file);
            return Some(RootfsMeasurement {
                dest: dest.to_path_buf(),
                expected: pin.hex().to_string(),
                measured,
            });
        }
        match clone_to(&entry.file, dest, owner) {
            Ok(()) => Some(RootfsMeasurement {
                dest: dest.to_path_buf(),
                expected: pin.hex().to_string(),
                measured: entry.measured,
            }),
            Err(why) => {
                tracing::info!(dest = %dest.display(), %why, "cannot clone the sealed rootfs into the jail; measuring it in place");
                None
            }
        }
    }

    /// The index of a usable entry for `pin_hex`, most recently used last.
    async fn find_or_seal(
        &self,
        entries: &mut Vec<Entry>,
        source: &Path,
        pin_hex: &str,
    ) -> Result<usize, String> {
        if let Some(i) = entries.iter().position(|e| e.pin_hex == pin_hex) {
            let e = entries.remove(i);
            match seal_of(&e.file) {
                Ok(now) if still_sealed(&e.seal, &now) => {
                    entries.push(e);
                    return Ok(entries.len() - 1);
                }
                now => {
                    tracing::warn!(path = %e.path.display(), recorded = ?e.seal, now = ?now,
                        "a sealed rootfs changed since it was measured; sealing it again");
                    discard(&e.path, &e.file);
                }
            }
        }
        let entry = self.seal(source, pin_hex).await?;
        while entries.len() >= CAPACITY {
            let old = entries.remove(0);
            discard(&old.path, &old.file);
        }
        entries.push(entry);
        Ok(entries.len() - 1)
    }

    /// Clone, sync, seal, record, and only then measure.
    async fn seal(&self, source: &Path, pin_hex: &str) -> Result<Entry, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let n = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = self.dir.join(format!("{pin_hex}.{n}"));
        let src = std::fs::File::open(source).map_err(|e| format!("open source: {e}"))?;
        let undo = |e: String| {
            let _ = std::fs::remove_file(&path);
            e
        };
        {
            let dst = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(&path)
                .map_err(|e| format!("create {}: {e}", path.display()))?;
            sys::clone_into(&src, &dst).map_err(|e| undo(format!("FICLONE: {e}")))?;
            dst.sync_all().map_err(|e| undo(format!("fsync: {e}")))?;
        } // the only writable descriptor this inode ever had is closed here
        let file = std::fs::File::open(&path).map_err(|e| undo(format!("reopen: {e}")))?;
        sys::set_immutable(&file, true).map_err(|e| undo(format!("FS_IMMUTABLE_FL: {e}")))?;
        let seal = seal_of(&file).map_err(|e| {
            discard(&path, &file);
            format!("stat: {e}")
        })?;
        if !seal.immutable {
            discard(&path, &file);
            return Err("the filesystem accepted FS_IMMUTABLE_FL and did not keep it".into());
        }
        // Measured by path, and the path is only reachable through a 0700 directory and
        // cannot be renamed or replaced while the flag is set; the record is checked again
        // afterwards so a measurement of anything else is discarded rather than kept.
        let measured = nucleus_identity::attestation::measure_artifact(&path).await;
        let after = seal_of(&file);
        let same_inode = std::fs::metadata(&path).is_ok_and(|m| {
            use std::os::unix::fs::MetadataExt;
            m.dev() == seal.dev && m.ino() == seal.ino
        });
        match (measured, after) {
            (Ok(measured), Ok(after)) if same_inode && still_sealed(&seal, &after) => Ok(Entry {
                pin_hex: pin_hex.to_string(),
                path,
                file,
                seal,
                measured,
            }),
            (measured, after) => {
                discard(&path, &file);
                Err(format!(
                    "the sealed copy did not hold while it was measured ({:?}, {:?})",
                    measured.err(),
                    after
                ))
            }
        }
    }
}

/// Clone `sealed` to `dest` without a moment where `dest` is missing or half-made: build the
/// clone beside it and rename over whatever `prepare_jail` placed. On any failure `dest` is
/// untouched, which is what lets the caller fall back to verifying it.
#[cfg(target_os = "linux")]
fn clone_to(sealed: &std::fs::File, dest: &Path, (uid, gid): (u32, u32)) -> Result<(), String> {
    use crate::jail_placement::{BornInJail, JailUser};
    use std::os::unix::fs::PermissionsExt;
    let tmp = dest.with_extension("sealed-clone");
    let result = (|| {
        let clone = BornInJail::create(&tmp)?;
        sys::clone_into(sealed, clone.file()).map_err(|e| format!("FICLONE: {e}"))?;
        clone
            .file()
            .set_permissions(std::fs::Permissions::from_mode(0o400))
            .map_err(|e| format!("chmod clone: {e}"))?;
        // The clone is private: hand over only the freshly created, single-link inode,
        // through its descriptor. A replaced pathname can never chown a shared artifact.
        clone.give_to_jail(JailUser { uid, gid })?;
        std::fs::rename(&tmp, dest).map_err(|e| format!("rename: {e}"))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
#[path = "sealed_rootfs_tests.rs"]
mod tests;
