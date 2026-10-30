//! Whether the workload can run code from a runtime directory (`/run`).
//!
//! The probe used to stage its executable with `tempfile::tempdir_in("/run")`.
//! Since #3184 guest-init mounts `/run` as a root-owned `mode=0755` tmpfs, and
//! guest-init creates everything under it with umask 077. So the workload
//! (uid 65534) cannot create anything there, the staging failed, and the probe
//! reported `could-not-look` on every guest built after #3184 (measured on the
//! arm64 lane, 2026-10-30, node `f23df095c`).
//!
//! "I could not create a file directly in `/run`" is not evidence on its own: a
//! writable subdirectory would still be a staging ground. And "nothing is
//! writable" is not the property the probe is named for: noexec is. So a
//! refusal now needs one of two observations:
//!
//! 1. An executable was staged somewhere under the root, and running it was
//!    denied with `EACCES` (the noexec answer). This is the old test, now run
//!    in any writable directory the search finds, not only the root.
//! 2. Every directory the workload can reach under the root refused a create
//!    with a permission error, AND the kernel reports every mount at or under
//!    the root as `noexec`. The first half says the workload cannot place
//!    code there. The second says it cannot execute what root placed there
//!    either. Read together, they cover the threat without a staged file.
//!
//! Anything else is `could-not-look` or a breach. A directory the workload can
//! search but not list could hide a writable child at a name it knows, so it
//! is `could-not-look`, never a refusal.

use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::{Attempt, Verdict, noexec_denied};

/// The script staged as the executable: a missing interpreter would answer
/// `ENOENT`, which `noexec_denied` already refuses to count.
pub const PAYLOAD: &[u8] = b"#!/bin/sh\nexit 0\n";

/// What the search for a staging directory found.
#[derive(Debug, PartialEq, Eq)]
pub enum Search {
    /// The payload was written here, mode 0700. The caller runs it and
    /// removes it.
    Staged(PathBuf),
    /// Every reachable directory refused a create with a permission error.
    NowhereWritable,
    /// The search could not finish, so it establishes nothing.
    Incomplete(&'static str),
}

/// What the probe observed, ready to classify.
#[derive(Debug)]
pub enum Staging {
    /// A staged payload was run; this is how the exec went.
    Ran(Attempt),
    /// See [`Search::NowhereWritable`].
    NowhereWritable,
    /// See [`Search::Incomplete`].
    Incomplete(&'static str),
}

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EACCES: i32 = 13;
const EROFS: i32 = 30;

fn denied(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(EPERM | EACCES | EROFS))
}

/// Look for a directory under `root` (the root included) where a file named
/// `name` can be created, and write [`PAYLOAD`] there. Symlinks are never
/// followed, and at most `limit` directories are tried.
#[must_use]
pub fn stage_under(root: &Path, name: &OsStr, limit: usize) -> Search {
    let mut pending = vec![root.to_path_buf()];
    let mut tried = 0_usize;
    while let Some(dir) = pending.pop() {
        tried = tried.saturating_add(1);
        if tried > limit {
            return Search::Incomplete("too many directories under the runtime root");
        }
        let path = dir.join(name);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&path)
        {
            Ok(mut file) => {
                return match file.write_all(PAYLOAD).and_then(|()| file.sync_all()) {
                    Ok(()) => Search::Staged(path),
                    Err(_) => {
                        let _ = fs::remove_file(&path);
                        Search::Incomplete("created a file but could not write the payload")
                    }
                };
            }
            Err(e) if denied(&e) => {}
            Err(_) => return Search::Incomplete("a create failed without a permission denial"),
        }
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if denied(&e) => {
                // Not listable. If it is still searchable, a child at a known
                // name could be writable, and this search cannot see it.
                match fs::symlink_metadata(&path) {
                    Err(e) if denied(&e) => continue,
                    Err(e) if e.raw_os_error() == Some(ENOENT) => {
                        return Search::Incomplete("a directory can be searched but not listed");
                    }
                    _ => return Search::Incomplete("an unlistable directory answered oddly"),
                }
            }
            Err(_) => return Search::Incomplete("a directory could not be listed"),
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return Search::Incomplete("a directory listing failed part way");
            };
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => pending.push(entry.path()),
                Ok(_) => {}
                Err(_) => return Search::Incomplete("an entry's type could not be read"),
            }
        }
    }
    Search::NowhereWritable
}

/// Whether every mount at or under `root` is `noexec`, from the text of
/// `/proc/self/mountinfo`. `None` when the text does not parse or `root` is
/// not itself a mount: then the kernel's answer is unknown.
#[must_use]
pub fn mounts_noexec(mountinfo: &str, root: &str) -> Option<bool> {
    let under = format!("{}/", root.trim_end_matches('/'));
    let mut root_seen = false;
    let mut all = true;
    for line in mountinfo.lines().filter(|l| !l.is_empty()) {
        let mut fields = line.split(' ');
        let point = fields.nth(4)?;
        let options = fields.next()?;
        if point == root || point.starts_with(&under) {
            root_seen |= point == root;
            all &= options.split(',').any(|o| o == "noexec");
        }
    }
    root_seen.then_some(all)
}

/// The verdict for "can the workload run code from the runtime root".
#[must_use]
pub fn runtime_exec_denied(staging: Staging, mounts_noexec: Option<bool>) -> Verdict {
    match staging {
        Staging::Ran(attempt) => noexec_denied(attempt),
        Staging::Incomplete(why) => Verdict::CouldNotLook(why),
        Staging::NowhereWritable => match mounts_noexec {
            Some(true) => Verdict::Refused,
            // Nothing can be staged, but the kernel would execute what is
            // there: the noexec layer this probe is named for is gone.
            Some(false) => Verdict::Breach,
            None => Verdict::CouldNotLook("nothing writable, and the mount flags are unknown"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct Tree(tempfile::TempDir);

    impl Tree {
        fn new() -> Self {
            Self(tempfile::tempdir().unwrap())
        }
        fn dir(&self, rel: &str, mode: u32) -> PathBuf {
            let path = self.0.path().join(rel);
            fs::create_dir_all(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            path
        }
        fn root(&self) -> &Path {
            self.0.path()
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            // Give every directory back its write bit so the temp dir can go.
            let mut pending = vec![self.0.path().to_path_buf()];
            while let Some(dir) = pending.pop() {
                let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
                if let Ok(entries) = fs::read_dir(&dir) {
                    for entry in entries.flatten() {
                        if entry.file_type().is_ok_and(|k| k.is_dir()) {
                            pending.push(entry.path());
                        }
                    }
                }
            }
        }
    }

    /// The fixtures rely on DAC. A privileged test runner (root, or
    /// CAP_DAC_OVERRIDE) writes through mode 0555, so it cannot build them.
    fn dac_binds(tree: &Tree) -> bool {
        let probe = tree.dir("dac-probe", 0o555);
        let binds = fs::write(probe.join("x"), b"").is_err();
        if !binds {
            eprintln!("this runner writes through mode 0555 (privileged): DAC fixtures skipped");
        }
        fs::set_permissions(&probe, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&probe).unwrap();
        binds
    }

    const NAME: &str = "nucleus-canary-stage";

    /// The measured guest: `/run` is 0755 root, its children 0700 root, so a
    /// workload can create nothing. Red on the probe before this change,
    /// which tried the root alone and reported could-not-look.
    #[test]
    fn a_root_the_workload_cannot_write_anywhere_is_nowhere_writable() {
        let tree = Tree::new();
        if !dac_binds(&tree) {
            return;
        }
        tree.dir("nucleus/identity", 0o000);
        tree.dir("nucleus", 0o000);
        tree.dir("lock", 0o555);
        fs::set_permissions(tree.root(), fs::Permissions::from_mode(0o555)).unwrap();
        assert_eq!(
            stage_under(tree.root(), OsStr::new(NAME), 64),
            Search::NowhereWritable
        );
    }

    /// The root refusing is not enough: a writable directory deeper down is a
    /// staging ground, and the search must find it and stage there.
    #[test]
    fn a_writable_directory_below_an_unwritable_root_is_found() {
        let tree = Tree::new();
        if !dac_binds(&tree) {
            return;
        }
        let deep = tree.dir("user/65534", 0o700);
        tree.dir("user", 0o555);
        fs::set_permissions(tree.root(), fs::Permissions::from_mode(0o555)).unwrap();
        let staged = deep.join(NAME);
        assert_eq!(
            stage_under(tree.root(), OsStr::new(NAME), 64),
            Search::Staged(staged.clone())
        );
        assert_eq!(fs::read(&staged).unwrap(), PAYLOAD);
        let mode = fs::metadata(&staged).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    /// A directory with `-wx` (writable, not listable) is still writable.
    #[test]
    fn a_writable_unlistable_directory_is_a_staging_ground() {
        let tree = Tree::new();
        if !dac_binds(&tree) {
            return;
        }
        let drop = tree.dir("drop", 0o300);
        fs::set_permissions(tree.root(), fs::Permissions::from_mode(0o555)).unwrap();
        assert_eq!(
            stage_under(tree.root(), OsStr::new(NAME), 64),
            Search::Staged(drop.join(NAME))
        );
    }

    /// Searchable but not listable: a child at a known name could be
    /// writable, so the search cannot claim nothing is.
    #[test]
    fn a_searchable_unlistable_directory_is_not_evidence() {
        let tree = Tree::new();
        if !dac_binds(&tree) {
            return;
        }
        tree.dir("hidden/inner", 0o777);
        tree.dir("hidden", 0o111);
        fs::set_permissions(tree.root(), fs::Permissions::from_mode(0o555)).unwrap();
        assert!(matches!(
            stage_under(tree.root(), OsStr::new(NAME), 64),
            Search::Incomplete(_)
        ));
    }

    #[test]
    fn a_search_past_its_bound_is_not_evidence() {
        let tree = Tree::new();
        if !dac_binds(&tree) {
            return;
        }
        for i in 0..4 {
            tree.dir(&format!("d{i}"), 0o555);
        }
        fs::set_permissions(tree.root(), fs::Permissions::from_mode(0o555)).unwrap();
        assert!(matches!(
            stage_under(tree.root(), OsStr::new(NAME), 3),
            Search::Incomplete(_)
        ));
    }

    /// A missing root is not a refusal.
    #[test]
    fn a_missing_root_is_not_evidence() {
        let tree = Tree::new();
        assert!(matches!(
            stage_under(&tree.root().join("absent"), OsStr::new(NAME), 64),
            Search::Incomplete(_)
        ));
    }

    // The lane's guest, 2026-10-30, as mountinfo prints it.
    const GUEST: &str = "\
22 1 254:0 / / ro,relatime - ext4 /dev/vda ro
23 22 0:5 / /dev rw,nosuid - devtmpfs dev rw
24 22 0:20 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw,hidepid=invisible
25 22 0:21 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw
26 22 0:22 / /run rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,mode=755
27 26 0:22 /nucleus/resolv.conf /run/nucleus/x rw,nosuid,nodev,noexec - tmpfs tmpfs rw
";

    #[test]
    fn every_mount_under_the_root_must_be_noexec() {
        assert_eq!(mounts_noexec(GUEST, "/run"), Some(true));
        // `/runner` is not under `/run`.
        let unrelated = format!("{GUEST}28 22 0:23 / /runner rw,relatime - tmpfs tmpfs rw\n");
        assert_eq!(mounts_noexec(&unrelated, "/run"), Some(true));
        let exec_child =
            format!("{GUEST}28 26 0:23 / /run/user/65534 rw,nosuid - tmpfs tmpfs rw\n");
        assert_eq!(mounts_noexec(&exec_child, "/run"), Some(false));
        let exec_root = GUEST.replace("/run rw,nosuid,nodev,noexec,", "/run rw,nosuid,nodev,");
        assert_eq!(mounts_noexec(&exec_root, "/run"), Some(false));
    }

    #[test]
    fn unknown_mount_flags_are_not_evidence() {
        assert_eq!(mounts_noexec("", "/run"), None);
        assert_eq!(mounts_noexec("26 22 0:22 / /run", "/run"), None);
        let no_run = GUEST
            .replace(" /run ", " /srv ")
            .replace("/run/nucleus/x", "/srv/x");
        assert_eq!(mounts_noexec(&no_run, "/run"), None);
    }

    #[test]
    fn only_a_denied_exec_or_nothing_writable_on_noexec_mounts_is_refused() {
        assert_eq!(
            runtime_exec_denied(Staging::Ran(Attempt::Failed(EACCES)), None),
            Verdict::Refused
        );
        assert_eq!(
            runtime_exec_denied(Staging::Ran(Attempt::Succeeded), Some(true)),
            Verdict::Breach
        );
        assert!(matches!(
            runtime_exec_denied(Staging::Ran(Attempt::Failed(ENOENT)), Some(true)),
            Verdict::CouldNotLook(_)
        ));
        assert_eq!(
            runtime_exec_denied(Staging::NowhereWritable, Some(true)),
            Verdict::Refused
        );
        assert_eq!(
            runtime_exec_denied(Staging::NowhereWritable, Some(false)),
            Verdict::Breach
        );
        assert!(matches!(
            runtime_exec_denied(Staging::NowhereWritable, None),
            Verdict::CouldNotLook(_)
        ));
        assert!(matches!(
            runtime_exec_denied(Staging::Incomplete("x"), Some(true)),
            Verdict::CouldNotLook(_)
        ));
    }
}
