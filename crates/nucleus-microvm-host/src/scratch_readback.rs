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
pub enum ReadbackError {
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
///
/// # Precondition: no VMM has the image open
///
/// The journal is replayed IN PLACE first. A microVM is ended by being killed, so
/// what the guest last wrote — including a report it `fsync`ed — can sit committed
/// in the ext4 journal and not yet checkpointed into the filesystem, with
/// `needs_recovery` set. `debugfs` does not replay the journal: measured on a
/// live pod (2026-09-16), it either refused the image ("Inode bitmap checksum
/// does not match") or, while the guest ran, listed the root as the template
/// left it, and the signed report appeared only after `e2fsck -E journal_only`.
/// Every caller reads after the VMM is gone — `pod_receipt::build` requires an
/// exited pod, and teardown preserves after the kill and before the jail is
/// removed — and the image is scratch that teardown deletes, so replaying in
/// place costs nothing and copying a multi-GiB image to spare it would.
pub fn read_file(image: &Path, guest_path: &str) -> Result<Vec<u8>, ReadbackError> {
    replay_journal(image)?;
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

/// Classify an `e2fsck -E journal_only` exit. Pure, so the table is testable on a
/// host without e2fsprogs.
///
/// 0, 1 and 2 are success. The code does NOT say whether a replay happened:
/// measured with e2fsprogs 1.47.0, a journal holding a committed transaction is
/// replayed ("recovering journal") and e2fsck still exits 0. So success is all
/// this reports, and the bytes read afterwards are the evidence.
///
/// `None` is a signal: the process was killed, and an interrupted replay is not
/// one that happened. Every other code (4 uncorrected, 8 operational error, 16
/// usage, 32 cancelled, 128 library error, and combinations) is a failure;
/// nothing unanticipated reads as success.
pub fn classify_replay(code: Option<i32>) -> Result<(), String> {
    match code {
        Some(0..=2) => Ok(()),
        Some(c) => Err(format!("e2fsck exit {c}")),
        None => Err("e2fsck was killed by a signal".to_string()),
    }
}

/// Replay the ext4 journal of `image`, changing nothing else.
///
/// See [`classify_replay`] for the exit codes. A missing `e2fsck` is
/// `ToolMissing`, never "the pod wrote nothing".
pub fn replay_journal(image: &Path) -> Result<(), ReadbackError> {
    let out = std::process::Command::new("e2fsck")
        .args(["-y", "-E", "journal_only"])
        .arg(image)
        .output()
        .map_err(|e| ReadbackError::ToolMissing(format!("e2fsck: {e}")))?;
    classify_replay(out.status.code()).map_err(|why| {
        ReadbackError::Failed(format!(
            "replaying the scratch disk's journal ({why}): {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    })
}

/// Copy the whole filesystem in `image` into the directory `out`, after
/// replaying its journal. Same precondition as [`read_file`]: no VMM has the
/// image open.
///
/// `out` must already exist. The empty `lost+found` that `mkfs.ext4` creates is
/// removed; a non-empty one is kept, because it holds what `e2fsck` recovered.
pub fn dump_tree(image: &Path, out: &Path) -> Result<(), ReadbackError> {
    replay_journal(image)?;
    let run = std::process::Command::new("debugfs")
        .args(["-R", &format!("rdump / {}", out.display())])
        .arg(image)
        .output()
        .map_err(|e| ReadbackError::ToolMissing(e.to_string()))?;
    // Exit status is not the signal (see `read_file`); stderr is.
    rdump_verdict(&String::from_utf8_lossy(&run.stderr)).map_err(ReadbackError::Failed)?;
    let lost = out.join("lost+found");
    if std::fs::read_dir(&lost).is_ok_and(|mut d| d.next().is_none()) {
        std::fs::remove_dir(&lost)
            .map_err(|e| ReadbackError::Failed(format!("removing empty lost+found: {e}")))?;
    }
    Ok(())
}

/// Judge `debugfs rdump`'s stderr. Pure.
///
/// The banner and "changing ownership" warnings are benign: an unprivileged
/// harvest cannot give files the image's owners, and the bytes are what is being
/// read back. Any other line is a failure — an allowlist of what is harmless, so
/// a message nobody anticipated refuses rather than passes.
pub fn rdump_verdict(stderr: &str) -> Result<(), String> {
    let bad: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter(|l| !l.starts_with("debugfs "))
        .filter(|l| !l.contains("while changing ownership of"))
        .collect();
    if bad.is_empty() {
        Ok(())
    } else {
        Err(format!("debugfs rdump: {}", bad.join("; ")))
    }
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

    /// The replay table: 0, 1 and 2 succeed, everything else fails,
    /// including a signal.
    #[test]
    fn replay_exit_codes_are_classified_totally() {
        for c in [0, 1, 2] {
            assert_eq!(classify_replay(Some(c)), Ok(()), "exit {c} is success");
        }
        for c in [3, 4, 8, 12, 16, 32, 128, -1] {
            assert!(classify_replay(Some(c)).is_err(), "exit {c} must fail");
        }
        assert!(
            classify_replay(None).is_err(),
            "a killed replay did not happen"
        );
    }

    /// rdump's stderr: banner and ownership warnings pass, anything else refuses.
    #[test]
    fn rdump_stderr_is_an_allowlist() {
        let benign = "debugfs 1.47.0 (5-Feb-2023)\n\
                      rdump: Operation not permitted while changing ownership of out//lost+found\n";
        assert!(rdump_verdict(benign).is_ok());
        assert!(rdump_verdict("").is_ok());
        let bad =
            "debugfs 1.47.0 (5-Feb-2023)\nrdump: File not found by ext2_lookup while dumping\n";
        assert!(rdump_verdict(bad).is_err());
        assert!(rdump_verdict("something new\n").is_err());
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
