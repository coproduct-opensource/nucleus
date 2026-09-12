//! Reading a file the GUEST wrote out of a microVM, from the host.
//!
//! # The gap this closes
//!
//! `pod_receipt::build` reads `<work_dir>/.nucleus-exit-report.json`. That is a
//! **host** path, and it works for the local and container drivers because they
//! share a directory with the workload. A Firecracker guest shares nothing:
//! `nucleus-spec` states it outright — *"A microVM has no host-directory mount
//! and there never will be one."* The guest's `/work` is a block device, an
//! ext4 image the host owns inside the jail.
//!
//! So `pod_receipt::build` returns `NoExitReport` for **every Firecracker pod**,
//! always has, and the receipt path has never been reachable from the driver
//! that matters. This is the read-back that makes it reachable.
//!
//! # Why `debugfs` and not a loopback mount
//!
//! Mounting needs `CAP_SYS_ADMIN` and a loop device, which is privilege the node
//! does not otherwise need and would have to hold for the lifetime of the read.
//! `debugfs -R "dump …"` reads the filesystem from userspace, unprivileged, with
//! the image still a plain file.
//!
//! It costs no new dependency: `provision_pod_scratch` already requires
//! e2ffsprogs to *create* the image (`mkfs.ext4`), and `debugfs` ships in the
//! same package. A host that can make a scratch disk can read one.
//!
//! # Why the host reads rather than the guest shipping
//!
//! There is a `SHIP_RECEIPT` command and this could have been `SHIP_EXIT_REPORT`
//! beside it. It is deliberately not.
//!
//! The exit report is an input to a receipt the HOST signs. Every field the
//! guest hands over is a field the receipt has to qualify as "the guest said
//! so", and the guest is the one thing in the system whose word the receipt is
//! supposed to not depend on. Reading the bytes out of an image the host owns
//! keeps the guest's contribution to what it actually is — content the host
//! measures — rather than a claim the host relays.
//!
//! # What this does NOT establish
//!
//! That the report is true. The guest wrote it, and a compromised workload
//! writes whatever it likes. What changes is only WHO IS QUOTED: the host says
//! "this is what was in the image", not "the guest told me this over a socket".
//! The signature over it is the host's either way, and neither form makes the
//! content trustworthy. See `pod_authority.rs` for the key, and
//! `attestation.rs:10-18` for the conditional the whole chain rests on.

use std::path::Path;

/// Why a read-back did not produce bytes.
#[derive(Debug)]
pub(crate) enum ReadbackError {
    /// `debugfs` is not installed. Named rather than folded into "no report":
    /// a host that cannot look is not a pod that produced nothing, and
    /// reporting the first as the second is the vacuity ADR 0002 was written
    /// about.
    ToolMissing(String),
    /// `debugfs` ran and failed.
    Failed(String),
    /// The path is not in the image. This one IS "the guest produced nothing",
    /// which is a legitimate outcome for a workload that crashed early.
    Absent(String),
}

impl std::fmt::Display for ReadbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadbackError::ToolMissing(e) => write!(
                f,
                "debugfs is not available on this host, so the scratch disk could not be read: \
                 {e} — install e2fsprogs (the same package mkfs.ext4 comes from). This is 'could \
                 not look', not 'the pod wrote nothing'"
            ),
            ReadbackError::Failed(e) => write!(f, "debugfs failed reading the scratch disk: {e}"),
            ReadbackError::Absent(p) => write!(f, "{p} is not in the scratch disk"),
        }
    }
}

/// `debugfs`'s own words when a path is not in the image.
const NOT_FOUND: &[&str] = &["File not found", "not found by ext2_lookup"];

/// Read `guest_path` out of the ext4 at `image`, as bytes.
///
/// `guest_path` is the path INSIDE the filesystem — the guest mounts the image
/// at `/work`, so `/work/.nucleus-exit-report.json` in the guest is
/// `/.nucleus-exit-report.json` here.
pub(crate) fn read_file(image: &Path, guest_path: &str) -> Result<Vec<u8>, ReadbackError> {
    let out_dir =
        tempfile_dir().map_err(|e| ReadbackError::Failed(format!("staging directory: {e}")))?;
    let staged = out_dir.join("readback");

    let out = std::process::Command::new("debugfs")
        .args([
            "-R",
            &format!("dump {guest_path} {}", staged.display()),
            &image.display().to_string(),
        ])
        .output()
        .map_err(|e| ReadbackError::ToolMissing(e.to_string()))?;

    // `debugfs -R` exits 0 even when the dump failed — it reports on stderr and
    // leaves no file. Exit status is NOT the signal here, the same trap the
    // dylint gates document for `cargo dylint`.
    let stderr = String::from_utf8_lossy(&out.stderr);
    if NOT_FOUND.iter().any(|m| stderr.contains(m)) {
        let _ = std::fs::remove_dir_all(&out_dir);
        return Err(ReadbackError::Absent(guest_path.to_string()));
    }

    let bytes = std::fs::read(&staged).map_err(|e| {
        if stderr.trim().is_empty() {
            ReadbackError::Absent(format!("{guest_path} ({e})"))
        } else {
            ReadbackError::Failed(format!("{}: {e}", stderr.trim()))
        }
    });
    let _ = std::fs::remove_dir_all(&out_dir);
    bytes
}

/// A private staging directory, named by pid and a counter.
///
/// Not the clock: nine tests sharing a wall-clock-nanos name was #2825, and the
/// same mistake here would have two pods' read-backs land on one path.
fn tempfile_dir() -> std::io::Result<std::path::PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "nucleus-readback-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn have_e2fsprogs() -> bool {
        std::process::Command::new("debugfs")
            .arg("-V")
            .output()
            .is_ok()
            && std::process::Command::new("mkfs.ext4")
                .arg("-V")
                .output()
                .is_ok()
    }

    /// Round trip: make an image, put a file in it the way a guest would, read
    /// it back from the host without mounting anything.
    ///
    /// Skips where e2fsprogs is absent (macOS), which is the same shape the
    /// snapshot tests use — and is why this is ALSO exercised on the Linux CI
    /// lane rather than only here.
    #[test]
    fn a_file_the_guest_wrote_is_readable_from_the_host() {
        if !have_e2fsprogs() {
            eprintln!("skipping: e2fsprogs not installed");
            return;
        }
        let dir = tempfile_dir().expect("staging");
        let image = dir.join("scratch.ext4");
        std::fs::write(&image, vec![0u8; 2 * 1024 * 1024]).expect("sparse image");
        assert!(
            std::process::Command::new("mkfs.ext4")
                .args(["-q", "-F", &image.display().to_string()])
                .output()
                .expect("mkfs")
                .status
                .success()
        );

        // `debugfs -w -R "write <src> <dst>"` is how a file gets in without a
        // mount — the host-side stand-in for the guest writing to /work.
        let src = dir.join("report.json");
        std::fs::write(&src, br#"{"workspace_hash":"abc"}"#).expect("src");
        let put = std::process::Command::new("debugfs")
            .args([
                "-w",
                "-R",
                &format!("write {} .nucleus-exit-report.json", src.display()),
                &image.display().to_string(),
            ])
            .output()
            .expect("debugfs write");
        assert!(
            put.status.success(),
            "{}",
            String::from_utf8_lossy(&put.stderr)
        );

        let got = read_file(&image, "/.nucleus-exit-report.json").expect("read back");
        assert_eq!(got, br#"{"workspace_hash":"abc"}"#);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A missing file is `Absent`, never `Failed`.** A workload that crashed
    /// before writing a report produced nothing, and that is a different fact
    /// from a host that could not look.
    #[test]
    fn a_path_not_in_the_image_is_absent_not_a_failure() {
        if !have_e2fsprogs() {
            eprintln!("skipping: e2fsprogs not installed");
            return;
        }
        let dir = tempfile_dir().expect("staging");
        let image = dir.join("scratch.ext4");
        std::fs::write(&image, vec![0u8; 2 * 1024 * 1024]).expect("image");
        let _ = std::process::Command::new("mkfs.ext4")
            .args(["-q", "-F", &image.display().to_string()])
            .output();

        let err = read_file(&image, "/nothing-here.json").expect_err("must not succeed");
        assert!(matches!(err, ReadbackError::Absent(_)), "{err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The three outcomes stay distinct in their own words: a host that cannot
    /// look must not read as a pod that wrote nothing.
    #[test]
    fn could_not_look_and_wrote_nothing_say_different_things() {
        let missing = ReadbackError::ToolMissing("No such file or directory".into()).to_string();
        let absent = ReadbackError::Absent("/x.json".into()).to_string();
        assert!(missing.contains("could not look"), "{missing}");
        assert!(!absent.contains("could not look"), "{absent}");
        assert!(missing.contains("e2fsprogs"), "{missing}");
    }
}
