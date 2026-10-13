//! Which guest this node boots by default, reported on `/v1/health` (#3223).
//!
//! The node is the one that can look: the default rootfs is a file in its
//! artifacts root, and `nucleus setup` records beside it where it came from and
//! the digest of the bytes it installed (`nucleus_spec::guest_release`). The
//! node measures the rootfs once, at startup, and reports the record's origin
//! only when its measurement equals the record's digest. Every other outcome is
//! [`NodeGuestReport::Unknown`] with the reason (ADR 0007 A-1).
//!
//! # Measured once, re-checked by identity
//!
//! The health route is public, so it never reads the rootfs: a request that
//! hashed a large file would be a lever anyone could pull. Each report re-reads
//! the file's identity instead (device, inode, length, mtime and ctime) and
//! reports [`UnknownGuest::RootfsChanged`] when it moved. `setup` replaces the
//! rootfs by rename, a new inode, so a reinstall is always seen. That is not a
//! content guarantee (`sealed_rootfs` explains why a stat key cannot be one),
//! and it does not need to be: the report feeds the CLI's preflight, and the
//! node's boot-time checks still refuse a guest that lacks what it requires.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nucleus_spec::guest_release::{
    GUEST_RELEASE_RECORD_FILE, GuestOrigin, GuestReleaseRecord, NodeGuestReport, UnknownGuest,
};
use nucleus_spec::microvm_host::HostInput;
use nucleus_spec::tier2_artifacts::GUEST_ROOTFS_FILE;

/// What the rootfs's identity was when it was measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl FileIdentity {
    fn of(path: &Path) -> std::io::Result<Self> {
        let m = std::fs::metadata(path)?;
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        })
    }
}

/// The node's measurement of its default rootfs, taken once.
#[derive(Debug)]
pub(crate) struct GuestReport {
    rootfs_path: PathBuf,
    decided: Decided,
}

#[derive(Debug)]
enum Decided {
    Known {
        origin: GuestOrigin,
        sha256: String,
        identity: FileIdentity,
    },
    Unknown(UnknownGuest),
}

impl GuestReport {
    /// Read the record in `artifacts_root` and measure the rootfs beside it.
    /// Blocking: it reads the whole rootfs when there is a record to hold it to.
    pub(crate) fn measure(artifacts_root: &Path) -> Self {
        let rootfs_path = artifacts_root.join(GUEST_ROOTFS_FILE);
        let decided = decide(
            &artifacts_root.join(GUEST_RELEASE_RECORD_FILE),
            &rootfs_path,
        );
        Self {
            rootfs_path,
            decided,
        }
    }

    /// What the node reports now: the measurement, unless the rootfs moved since.
    pub(crate) fn current(&self) -> NodeGuestReport {
        let unknown = |reason| NodeGuestReport::Unknown {
            rootfs_path: self.rootfs_path.clone(),
            reason,
        };
        match &self.decided {
            Decided::Unknown(reason) => unknown(reason.clone()),
            Decided::Known {
                origin,
                sha256,
                identity,
            } => match FileIdentity::of(&self.rootfs_path) {
                Ok(now) if now == *identity => NodeGuestReport::Known {
                    origin: origin.clone(),
                    rootfs_path: self.rootfs_path.clone(),
                    rootfs_sha256: sha256.clone(),
                },
                Ok(_) | Err(_) => unknown(UnknownGuest::RootfsChanged),
            },
        }
    }
}

impl std::fmt::Display for GuestReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.decided {
            Decided::Known { origin, sha256, .. } => write!(
                f,
                "{} is {origin} (sha256 {sha256})",
                self.rootfs_path.display()
            ),
            Decided::Unknown(reason) => write!(
                f,
                "cannot say which guest {} is: {reason}",
                self.rootfs_path.display()
            ),
        }
    }
}

fn decide(record_path: &Path, rootfs_path: &Path) -> Decided {
    let record = match std::fs::read(record_path) {
        Ok(bytes) => match GuestReleaseRecord::parse(&bytes) {
            Ok(record) => record,
            Err(e) => {
                return Decided::Unknown(UnknownGuest::RecordUnreadable {
                    detail: e.to_string(),
                });
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Decided::Unknown(UnknownGuest::NoRecord);
        }
        Err(e) => {
            return Decided::Unknown(UnknownGuest::RecordUnreadable {
                detail: e.to_string(),
            });
        }
    };
    let unreadable = |e: std::io::Error| {
        if e.kind() == std::io::ErrorKind::NotFound {
            UnknownGuest::NoRootfs
        } else {
            UnknownGuest::RootfsUnreadable {
                detail: e.to_string(),
            }
        }
    };
    // Identity before and after the read: a file that moved while it was being
    // hashed is not the file the hash describes.
    let before = match FileIdentity::of(rootfs_path) {
        Ok(identity) => identity,
        Err(e) => return Decided::Unknown(unreadable(e)),
    };
    let measured = match HostInput::measure(rootfs_path) {
        Ok(input) => input,
        Err(e) => return Decided::Unknown(unreadable(e)),
    };
    match FileIdentity::of(rootfs_path) {
        Ok(after) if after == before => {}
        Ok(_) | Err(_) => return Decided::Unknown(UnknownGuest::RootfsChanged),
    }
    if measured.sha256 != record.rootfs_sha256() {
        return Decided::Unknown(UnknownGuest::RootfsDiffers {
            recorded: record.rootfs_sha256().to_string(),
            measured: measured.sha256,
        });
    }
    Decided::Known {
        origin: record.origin().clone(),
        sha256: measured.sha256,
        identity: before,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    }

    fn write_record(root: &Path, origin: GuestOrigin, sha: &str) {
        let record = GuestReleaseRecord::new(origin, sha).unwrap();
        std::fs::write(
            root.join(GUEST_RELEASE_RECORD_FILE),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
    }

    fn release(v: &str) -> GuestOrigin {
        GuestOrigin::Release { version: v.into() }
    }

    fn reason(report: NodeGuestReport) -> UnknownGuest {
        match report {
            NodeGuestReport::Unknown { reason, .. } => reason,
            NodeGuestReport::Known { origin, .. } => panic!("reported {origin} as known"),
        }
    }

    /// The acceptance path: a rootfs whose bytes are the record's is reported
    /// with the record's release, at the path the node measured.
    #[test]
    fn a_recorded_rootfs_is_reported_with_its_release() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = b"a guest rootfs";
        std::fs::write(dir.path().join(GUEST_ROOTFS_FILE), rootfs).unwrap();
        write_record(dir.path(), release("2.7.0"), &sha256_hex(rootfs));
        let report = GuestReport::measure(dir.path()).current();
        assert_eq!(
            report,
            NodeGuestReport::Known {
                origin: release("2.7.0"),
                rootfs_path: dir.path().join(GUEST_ROOTFS_FILE),
                rootfs_sha256: sha256_hex(rootfs),
            }
        );
    }

    /// Every way the node cannot vouch for the guest is reported as unknown,
    /// by its own cause: no record, a refused record, no rootfs, and a rootfs
    /// that is not the recorded one.
    #[test]
    fn what_the_node_cannot_vouch_for_is_unknown_by_cause() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join(GUEST_ROOTFS_FILE), b"bytes").unwrap();
        assert_eq!(
            reason(GuestReport::measure(root).current()),
            UnknownGuest::NoRecord
        );

        std::fs::write(
            root.join(GUEST_RELEASE_RECORD_FILE),
            b"{\"release\":\"2.7.0\"}",
        )
        .unwrap();
        assert!(matches!(
            reason(GuestReport::measure(root).current()),
            UnknownGuest::RecordUnreadable { .. }
        ));

        let other = sha256_hex(b"other bytes");
        write_record(root, release("2.7.0"), &other);
        assert_eq!(
            reason(GuestReport::measure(root).current()),
            UnknownGuest::RootfsDiffers {
                recorded: other,
                measured: sha256_hex(b"bytes"),
            }
        );

        std::fs::remove_file(root.join(GUEST_ROOTFS_FILE)).unwrap();
        assert_eq!(
            reason(GuestReport::measure(root).current()),
            UnknownGuest::NoRootfs
        );
    }

    /// A rootfs replaced after the node measured it (the way `setup` replaces
    /// it: a new file renamed over the old) is no longer reported as known.
    #[test]
    fn a_rootfs_replaced_after_startup_is_no_longer_known() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let rootfs = root.join(GUEST_ROOTFS_FILE);
        std::fs::write(&rootfs, b"2.7.0 bytes").unwrap();
        write_record(root, release("2.7.0"), &sha256_hex(b"2.7.0 bytes"));
        let measured = GuestReport::measure(root);
        assert!(matches!(measured.current(), NodeGuestReport::Known { .. }));

        let next = root.join("rootfs.next");
        std::fs::write(&next, b"other bytes").unwrap();
        std::fs::rename(&next, &rootfs).unwrap();
        assert_eq!(reason(measured.current()), UnknownGuest::RootfsChanged);
    }
}
