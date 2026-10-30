//! Whether the workload can run code from a runtime directory (`/run`).
//!
//! The probe used to stage its executable with `tempfile::tempdir_in("/run")`.
//! Since #3184 guest-init mounts `/run` as a root-owned `mode=0755` tmpfs, and
//! guest-init creates everything under it with umask 077. So the workload
//! (uid 65534) cannot create anything there, the staging failed, and the probe
//! reported `could-not-look` on every guest built after #3184 (measured on the
//! arm64 lane, 2026-10-30, node `f23df095c`).
//!
//! The property the probe is named for is noexec, and the kernel states it
//! per mount in `/proc/self/mountinfo`. So the mount table decides first:
//!
//! - A mount at or under the root without `noexec` is a breach, whatever the
//!   search found. The kernel would execute a file there, whoever placed it.
//! - A staged executable that ran is a breach, whatever the mount table says.
//!
//! Otherwise a refusal needs one of two observations:
//!
//! 1. An executable was staged somewhere under the root, and running it was
//!    denied with `EACCES` (the noexec answer). This is the direct test, run
//!    in any writable directory the search finds, not only the root.
//! 2. No directory the search could see accepted a create, AND the kernel
//!    reports every mount at or under the root as `noexec`.
//!
//! A directory the workload can search but not list could hold a writable
//! child at a name the search cannot guess. The search records it and goes
//! on (it never decides "nothing executable there" by itself). Only the mount
//! flags can then decide: every file reachable through that directory is on a
//! mount at or under the root, and every such mount is `noexec`. If the flags
//! are unknown, it stays `could-not-look`. Either way the verdict names it.
//! On the trusted-launch guest, 2026-10-30, leaf 18056, it was exactly this
//! case, and the probe could not say which directory it was (gatehouse F-331).

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::{Attempt, Verdict, noexec_denied};

/// The script staged as the executable: a missing interpreter would answer
/// `ENOENT`, which `noexec_denied` already refuses to count.
pub const PAYLOAD: &[u8] = b"#!/bin/sh\nexit 0\n";

/// At most this many hidden directories are named in a verdict's detail.
const NAMED: usize = 8;

/// What the search for a staging directory found.
#[derive(Debug, PartialEq, Eq)]
pub enum Search {
    /// The payload was written here, mode 0700. The caller runs it and
    /// removes it.
    Staged(PathBuf),
    /// Every directory the search could see refused a create with a
    /// permission error. `hidden` are the directories it could search but
    /// not list: a child there at a name it cannot guess was not seen.
    NowhereWritable { hidden: Vec<PathBuf> },
    /// The search could not finish, so it establishes nothing.
    Incomplete(&'static str),
}

/// What the probe observed, ready to classify.
#[derive(Debug)]
pub enum Staging {
    /// A payload staged at `path` was run; this is how the exec went.
    Ran { path: PathBuf, attempt: Attempt },
    /// See [`Search::NowhereWritable`].
    NowhereWritable { hidden: Vec<PathBuf> },
    /// See [`Search::Incomplete`].
    Incomplete(&'static str),
}

/// What the kernel's mount table says about the mounts at or under the root.
#[derive(Debug, PartialEq, Eq)]
pub enum Mounts {
    /// The root is a mount, and it and every mount under it carry `noexec`.
    AllNoexec,
    /// This mount point, at or under the root, does not carry `noexec`.
    Exec(String),
    /// The text does not parse, or the root is not itself a mount.
    Unknown,
}

/// A verdict, and what the probe can say about where it came from.
#[derive(Debug, PartialEq, Eq)]
pub struct Decision {
    pub verdict: Verdict,
    /// Paths that decided it, for the reader of the run. Never secret: only
    /// directory and mount point names under the root.
    pub detail: Option<String>,
}

impl Decision {
    fn of(verdict: Verdict, detail: Option<String>) -> Self {
        Self { verdict, detail }
    }
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
    let mut hidden = Vec::new();
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
                // Not listable. Not searchable either: nothing inside is
                // reachable by path. Searchable: a child at a known name
                // could be writable, and this search cannot see it.
                match fs::symlink_metadata(&path) {
                    Err(e) if denied(&e) => continue,
                    Err(e) if e.raw_os_error() == Some(ENOENT) => {
                        hidden.push(dir);
                        continue;
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
    Search::NowhereWritable { hidden }
}

/// Whether every mount at or under `root` is `noexec`, from the text of
/// `/proc/self/mountinfo`, which is this process's own mount namespace. Every
/// mount listed there at or under `root` counts, including one the workload
/// could not reach by path or one covered by a later mount: that can only
/// make the answer stricter.
#[must_use]
pub fn mounts_noexec(mountinfo: &str, root: &str) -> Mounts {
    let under = format!("{}/", root.trim_end_matches('/'));
    let mut root_seen = false;
    let mut exec = None;
    for line in mountinfo.lines().filter(|l| !l.is_empty()) {
        let mut fields = line.split(' ');
        let (Some(point), Some(options)) = (fields.nth(4), fields.next()) else {
            return Mounts::Unknown;
        };
        if point == root || point.starts_with(&under) {
            root_seen |= point == root;
            if exec.is_none() && !options.split(',').any(|o| o == "noexec") {
                exec = Some(point.to_owned());
            }
        }
    }
    match (root_seen, exec) {
        (false, _) => Mounts::Unknown,
        (true, Some(point)) => Mounts::Exec(point),
        (true, None) => Mounts::AllNoexec,
    }
}

fn name_hidden(hidden: &[PathBuf]) -> String {
    let mut out = String::from("searchable, not listable:");
    for dir in hidden.iter().take(NAMED) {
        let _ = write!(out, " {}", dir.display());
    }
    if let Some(more) = hidden.len().checked_sub(NAMED).filter(|n| *n > 0) {
        let _ = write!(out, " (+{more} more)");
    }
    out
}

/// The verdict for "can the workload run code from the runtime root".
#[must_use]
pub fn runtime_exec_denied(staging: Staging, mounts: Mounts) -> Decision {
    match (staging, mounts) {
        (
            Staging::Ran {
                path,
                attempt: Attempt::Succeeded,
            },
            _,
        ) => Decision::of(
            Verdict::Breach,
            Some(format!("staged {} and it ran", path.display())),
        ),
        // Whatever the search saw, the kernel would execute a file on this
        // mount: the noexec layer this probe is named for is gone there.
        (_, Mounts::Exec(point)) => Decision::of(
            Verdict::Breach,
            Some(format!("the mount at {point} is not noexec")),
        ),
        (Staging::Ran { path, attempt }, _) => Decision::of(
            noexec_denied(attempt),
            Some(format!("staged {}", path.display())),
        ),
        (Staging::NowhereWritable { hidden }, Mounts::AllNoexec) => Decision::of(
            Verdict::Refused,
            (!hidden.is_empty()).then(|| {
                format!(
                    "{}; decided by the mount flags, every mount there is noexec",
                    name_hidden(&hidden)
                )
            }),
        ),
        (Staging::NowhereWritable { hidden }, Mounts::Unknown) if hidden.is_empty() => {
            Decision::of(
                Verdict::CouldNotLook("nothing writable, and the mount flags are unknown"),
                None,
            )
        }
        (Staging::NowhereWritable { hidden }, Mounts::Unknown) => Decision::of(
            Verdict::CouldNotLook(
                "a directory can be searched but not listed, and the mount flags are unknown",
            ),
            Some(name_hidden(&hidden)),
        ),
        (Staging::Incomplete(why), _) => Decision::of(Verdict::CouldNotLook(why), None),
    }
}

/// The whole probe over `root`, with the mount table read as `mountinfo`
/// (`None`: unreadable) for the mount point `mount_root`, and `run` the exec.
/// The staged payload is removed after it runs.
pub fn runtime_exec(
    root: &Path,
    name: &OsStr,
    limit: usize,
    mountinfo: Option<&str>,
    mount_root: &str,
    run: impl FnOnce(&Path) -> Attempt,
) -> Decision {
    let staging = match stage_under(root, name, limit) {
        Search::Staged(path) => {
            let attempt = run(&path);
            let _ = fs::remove_file(&path);
            Staging::Ran { path, attempt }
        }
        Search::NowhereWritable { hidden } => Staging::NowhereWritable { hidden },
        Search::Incomplete(why) => Staging::Incomplete(why),
    };
    let mounts = mountinfo.map_or(Mounts::Unknown, |text| mounts_noexec(text, mount_root));
    runtime_exec_denied(staging, mounts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
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
        fn seal_root(&self) {
            fs::set_permissions(self.root(), fs::Permissions::from_mode(0o555)).unwrap();
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

    // The lane's guest, 2026-10-30, as mountinfo prints it.
    const GUEST: &str = "\
22 1 254:0 / / ro,relatime - ext4 /dev/vda ro
23 22 0:5 / /dev rw,nosuid - devtmpfs dev rw
24 22 0:20 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw,hidepid=invisible
25 22 0:21 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw
26 22 0:22 / /run rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,mode=755
27 26 0:22 /nucleus/resolv.conf /run/nucleus/x rw,nosuid,nodev,noexec - tmpfs tmpfs rw
";

    /// The guest with one mount under `/run` that lacks `noexec`.
    fn guest_with_exec_child() -> String {
        format!("{GUEST}28 26 0:23 / /run/user/65534 rw,nosuid - tmpfs tmpfs rw\n")
    }

    /// The probe with a recorded exec that answers `answer`.
    fn probe(tree: &Tree, mountinfo: Option<&str>, answer: Attempt) -> (Decision, Vec<PathBuf>) {
        let ran = RefCell::new(Vec::new());
        let decision = runtime_exec(
            tree.root(),
            OsStr::new(NAME),
            64,
            mountinfo,
            "/run",
            |path| {
                ran.borrow_mut().push(path.to_path_buf());
                answer
            },
        );
        (decision, ran.into_inner())
    }

    /// The measured guest: `/run` is 0755 root, its children 0700 root, so a
    /// workload can create nothing.
    #[test]
    fn a_root_the_workload_cannot_write_anywhere_is_nowhere_writable() {
        let tree = Tree::new();
        if !dac_binds(&tree) {
            return;
        }
        tree.dir("nucleus/identity", 0o000);
        tree.dir("nucleus", 0o000);
        tree.dir("lock", 0o555);
        tree.seal_root();
        assert_eq!(
            stage_under(tree.root(), OsStr::new(NAME), 64),
            Search::NowhereWritable { hidden: vec![] }
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
        tree.seal_root();
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
        tree.seal_root();
        assert_eq!(
            stage_under(tree.root(), OsStr::new(NAME), 64),
            Search::Staged(drop.join(NAME))
        );
    }

    /// Searchable but not listable: a child at a known name could be
    /// writable. The search names the directory and goes on; it never counts
    /// it as empty.
    #[test]
    fn a_searchable_unlistable_directory_is_named_not_assumed_empty() {
        let tree = Tree::new();
        if !dac_binds(&tree) {
            return;
        }
        tree.dir("hidden/inner", 0o777);
        let hidden = tree.dir("hidden", 0o111);
        tree.dir("lock", 0o555);
        tree.seal_root();
        assert_eq!(
            stage_under(tree.root(), OsStr::new(NAME), 64),
            Search::NowhereWritable {
                hidden: vec![hidden]
            }
        );
    }

    /// A searchable, unlistable directory does not stop the search: a
    /// writable directory beside it is still found and staged in.
    #[test]
    fn a_hidden_directory_does_not_end_the_search() {
        let tree = Tree::new();
        if !dac_binds(&tree) {
            return;
        }
        tree.dir("hidden", 0o111);
        let open = tree.dir("open", 0o700);
        tree.seal_root();
        assert_eq!(
            stage_under(tree.root(), OsStr::new(NAME), 64),
            Search::Staged(open.join(NAME))
        );
    }

    /// F-331, the trusted-launch guest's case: nothing the search can see is
    /// writable, one directory can be searched but not listed, and every
    /// mount at or under `/run` is noexec. The mount flags decide it, and the
    /// verdict names the directory.
    #[test]
    fn a_hidden_directory_on_noexec_mounts_is_refused_and_named() {
        let tree = Tree::new();
        if !dac_binds(&tree) {
            return;
        }
        tree.dir("nucleus", 0o000);
        tree.dir("hidden/inner", 0o777);
        let hidden = tree.dir("hidden", 0o111);
        tree.seal_root();
        let (decision, ran) = probe(&tree, Some(GUEST), Attempt::Succeeded);
        assert_eq!(decision.verdict, Verdict::Refused);
        assert!(ran.is_empty());
        let detail = decision.detail.unwrap();
        assert!(detail.contains(&hidden.display().to_string()), "{detail}");
        assert!(detail.contains("mount flags"), "{detail}");
    }

    /// The red case the fix must not weaken: the same hidden directory, but
    /// one mount under `/run` lacks noexec. Whatever the hidden directory
    /// holds, the kernel would execute a file on that mount.
    #[test]
    fn a_hidden_directory_beside_an_exec_mount_is_a_breach() {
        let tree = Tree::new();
        if !dac_binds(&tree) {
            return;
        }
        tree.dir("hidden/inner", 0o777);
        tree.dir("hidden", 0o111);
        tree.seal_root();
        let (decision, _) = probe(&tree, Some(&guest_with_exec_child()), Attempt::Succeeded);
        assert_eq!(decision.verdict, Verdict::Breach);
        let detail = decision.detail.unwrap();
        assert!(detail.contains("/run/user/65534"), "{detail}");
    }

    /// Without the mount table nothing decides the hidden directory: it stays
    /// could-not-look, and now it says which directory.
    #[test]
    fn a_hidden_directory_without_mount_flags_could_not_look_and_is_named() {
        let tree = Tree::new();
        if !dac_binds(&tree) {
            return;
        }
        let hidden = tree.dir("hidden", 0o111);
        tree.seal_root();
        for mountinfo in [
            None,
            Some(""),
            Some("26 22 0:22 / /srv rw,noexec - tmpfs t rw\n"),
        ] {
            let (decision, _) = probe(&tree, mountinfo, Attempt::Succeeded);
            assert!(matches!(decision.verdict, Verdict::CouldNotLook(_)));
            let detail = decision.detail.unwrap();
            assert!(detail.contains(&hidden.display().to_string()), "{detail}");
        }
    }

    /// A staged exec denied with `EACCES` does not excuse another mount under
    /// `/run` that lacks noexec.
    #[test]
    fn a_denied_staged_exec_beside_an_exec_mount_is_a_breach() {
        let tree = Tree::new();
        if !dac_binds(&tree) {
            return;
        }
        tree.dir("user", 0o700);
        tree.seal_root();
        let (decision, ran) = probe(
            &tree,
            Some(&guest_with_exec_child()),
            Attempt::Failed(EACCES),
        );
        assert_eq!(ran.len(), 1);
        assert_eq!(decision.verdict, Verdict::Breach);
    }

    /// The direct test still runs where it can, and its file is removed.
    #[test]
    fn a_staged_payload_is_run_once_and_removed() {
        let tree = Tree::new();
        if !dac_binds(&tree) {
            return;
        }
        let user = tree.dir("user", 0o700);
        tree.seal_root();
        let (decision, ran) = probe(&tree, Some(GUEST), Attempt::Failed(EACCES));
        assert_eq!(decision.verdict, Verdict::Refused);
        assert_eq!(ran, vec![user.join(NAME)]);
        assert!(!user.join(NAME).exists());
        // The kernel ran it although the table says noexec: a breach.
        let (decision, _) = probe(&tree, Some(GUEST), Attempt::Succeeded);
        assert_eq!(decision.verdict, Verdict::Breach);
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
        tree.seal_root();
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

    #[test]
    fn every_mount_under_the_root_must_be_noexec() {
        assert_eq!(mounts_noexec(GUEST, "/run"), Mounts::AllNoexec);
        // `/runner` is not under `/run`.
        let unrelated = format!("{GUEST}28 22 0:23 / /runner rw,relatime - tmpfs tmpfs rw\n");
        assert_eq!(mounts_noexec(&unrelated, "/run"), Mounts::AllNoexec);
        assert_eq!(
            mounts_noexec(&guest_with_exec_child(), "/run"),
            Mounts::Exec("/run/user/65534".to_owned())
        );
        let exec_root = GUEST.replace("/run rw,nosuid,nodev,noexec,", "/run rw,nosuid,nodev,");
        assert_eq!(
            mounts_noexec(&exec_root, "/run"),
            Mounts::Exec("/run".to_owned())
        );
        // A second mount stacked on `/run` counts too.
        let stacked = format!("{GUEST}28 26 0:24 / /run rw,nosuid - tmpfs tmpfs rw\n");
        assert_eq!(
            mounts_noexec(&stacked, "/run"),
            Mounts::Exec("/run".to_owned())
        );
    }

    #[test]
    fn unknown_mount_flags_are_not_evidence() {
        assert_eq!(mounts_noexec("", "/run"), Mounts::Unknown);
        assert_eq!(mounts_noexec("26 22 0:22 / /run", "/run"), Mounts::Unknown);
        let no_run = GUEST
            .replace(" /run ", " /srv ")
            .replace("/run/nucleus/x", "/srv/x");
        assert_eq!(mounts_noexec(&no_run, "/run"), Mounts::Unknown);
    }

    #[test]
    fn only_a_denied_exec_or_nothing_seen_writable_on_noexec_mounts_is_refused() {
        let ran = |attempt| Staging::Ran {
            path: PathBuf::from("/run/user/x"),
            attempt,
        };
        let nowhere = || Staging::NowhereWritable { hidden: vec![] };
        let hidden = || Staging::NowhereWritable {
            hidden: vec![PathBuf::from("/run/h")],
        };
        let exec = || Mounts::Exec("/run/e".to_owned());
        let verdict = |s, m| runtime_exec_denied(s, m).verdict;
        assert_eq!(
            verdict(ran(Attempt::Failed(EACCES)), Mounts::Unknown),
            Verdict::Refused
        );
        assert_eq!(
            verdict(ran(Attempt::Failed(EACCES)), exec()),
            Verdict::Breach
        );
        assert_eq!(
            verdict(ran(Attempt::Succeeded), Mounts::AllNoexec),
            Verdict::Breach
        );
        assert!(matches!(
            verdict(ran(Attempt::Failed(ENOENT)), Mounts::AllNoexec),
            Verdict::CouldNotLook(_)
        ));
        assert_eq!(verdict(nowhere(), Mounts::AllNoexec), Verdict::Refused);
        assert_eq!(verdict(nowhere(), exec()), Verdict::Breach);
        assert!(matches!(
            verdict(nowhere(), Mounts::Unknown),
            Verdict::CouldNotLook(_)
        ));
        assert_eq!(verdict(hidden(), Mounts::AllNoexec), Verdict::Refused);
        assert_eq!(verdict(hidden(), exec()), Verdict::Breach);
        assert!(matches!(
            verdict(hidden(), Mounts::Unknown),
            Verdict::CouldNotLook(_)
        ));
        assert!(matches!(
            verdict(Staging::Incomplete("x"), Mounts::AllNoexec),
            Verdict::CouldNotLook(_)
        ));
        assert_eq!(verdict(Staging::Incomplete("x"), exec()), Verdict::Breach);
    }

    #[test]
    fn a_long_list_of_hidden_directories_is_cut_and_counted() {
        let many: Vec<PathBuf> = (0..11)
            .map(|i| PathBuf::from(format!("/run/h{i}")))
            .collect();
        let text = name_hidden(&many);
        assert!(text.contains("/run/h7"), "{text}");
        assert!(!text.contains("/run/h8"), "{text}");
        assert!(text.ends_with("(+3 more)"), "{text}");
        assert!(!name_hidden(&many[..2]).contains("more"));
    }
}
