//! Hold one open lock file for the node's entire lifetime. Never unlink it:
//! replacing the inode would let a second node lock a different file.
use std::{fs::File, path::Path};

/// Create the node's state directory, if it is missing, owner-only (0700)
/// whatever the process umask.
///
/// The directory holds the node's keys, and it is the federation key
/// directory itself, which refuses to be writable by group or others
/// (`KeyDir::check_dir`). Created with the ambient mode, a node started under
/// a umask of 002 (Ubuntu's per-user default) made its own state directory
/// 0775 and then refused it (#3190). Parents are created as before; an
/// existing directory is left as the operator made it.
pub(crate) fn create(state_dir: &Path) -> std::io::Result<()> {
    if let Some(parent) = state_dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut owner_only = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut owner_only, 0o700);
    match owner_only.create(state_dir) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && state_dir.is_dir() => Ok(()),
        created => created,
    }
}

/// A temporary state directory, owner-only as [`create`] makes one. A bare
/// `tempfile::tempdir()` takes the runner's umask, so a test whose directory
/// becomes a key directory passed under umask 022 and failed under 002 (#3190).
#[cfg(test)]
pub(crate) fn state_tempdir() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    builder.permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700));
    builder
        .tempdir()
        .expect("an owner-only temporary state directory")
}

pub(crate) fn acquire(state_dir: &Path) -> Result<File, crate::ApiError> {
    let path = state_dir.join("node.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    file.try_lock().map_err(|error| {
        crate::ApiError::Driver(format!(
            "cannot exclusively lock node state {}: {error}; stop the other node before restarting",
            state_dir.display()
        ))
    })?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, Read as _, Write as _};

    /// Set only on the child [`state_directory_is_exclusive_until_owner_exits`] starts.
    const HOLD: &str = "NUCLEUS_TEST_STATE_LOCK_HOLD";
    const HELD: &str = "state-lock: held";

    /// The owner, as a process of its own. Without [`HOLD`] it has nothing to hold and returns.
    ///
    /// The lock is flock(2), which belongs to the open file DESCRIPTION, and a child forked while
    /// a description is open shares it until the child execs. Sibling tests in this binary spawn
    /// processes on parallel threads (`cargo llvm-cov` runs a binary's tests in one process), so a
    /// lock taken, dropped and re-taken inside the test process can find a forked sibling still
    /// holding it: the coverage run lost that race on 2026-10-08. A lock held here, in a process
    /// that spawns nothing, is never shared with a fork, and its release is the owner's exit,
    /// which is the release the node relies on.
    #[test]
    fn hold_for_the_exclusivity_test() {
        let Some(dir) = std::env::var_os(HOLD) else {
            return;
        };
        let _held = acquire(Path::new(&dir)).expect("the holder takes the free lock");
        println!("{HELD}");
        std::io::stdout().flush().expect("announce");
        // Hold until the parent closes stdin.
        let mut rest = String::new();
        let _ = std::io::stdin().read_to_string(&mut rest);
    }

    #[test]
    fn state_directory_is_exclusive_until_owner_exits() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "state_lock::tests::hold_for_the_exclusivity_test",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(HOLD, dir.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("start the owner");
        let mut out = std::io::BufReader::new(owner.stdout.take().expect("piped"));
        let mut line = String::new();
        let announced = loop {
            line.clear();
            match out.read_line(&mut line) {
                Ok(0) | Err(_) => break false,
                // libtest writes `test <name> ... ` with no newline before the test runs, so the
                // marker ends the line rather than being all of it.
                Ok(_) if line.trim_end().ends_with(HELD) => break true,
                Ok(_) => {}
            }
        };
        assert!(
            announced,
            "the owner never held the lock: {:?}",
            owner.wait()
        );

        // Another process's lock refuses this one for as long as that process lives.
        assert!(acquire(dir.path()).is_err());
        // A lock refuses a second open in its own process too, and is per state directory.
        let other = tempfile::tempdir().unwrap();
        let first = acquire(other.path()).unwrap();
        assert!(acquire(other.path()).is_err());
        drop(first);

        // Release the owner, and keep reading so its harness never writes into a closed pipe.
        drop(owner.stdin.take());
        let mut rest = String::new();
        let _ = out.read_to_string(&mut rest);
        let exited = owner.wait().expect("the owner exits");
        assert!(exited.success(), "{exited}: {rest}");
        // The owner has exited, and the description it locked lived only in it.
        drop(acquire(dir.path()).unwrap());
        assert!(dir.path().join("node.lock").exists());
    }

    /// Set only on the child [`state_directory_is_owner_only_under_umask_002`] starts.
    const UMASK_002_STATE: &str = "NUCLEUS_TEST_STATE_DIR_UMASK_002";

    /// The node's start-up, as a process of its own under umask 002: umask(2)
    /// is per process, so it is never changed in a process running other tests.
    #[test]
    fn create_and_load_keys_under_umask_002() {
        let Some(dir) = std::env::var_os(UMASK_002_STATE) else {
            return;
        };
        let dir = Path::new(&dir);
        // SAFETY: umask(2) only replaces this process's file-creation mask.
        unsafe { libc::umask(0o002) };
        create(dir).expect("create the state directory");
        let custody =
            nucleus_federation::KeyCustody::File(nucleus_federation::FileCustody::NoTpmConfigured);
        crate::keys::load_or_create_jwt_svid_signing_key(dir, &custody)
            .expect("the node accepts the state directory it created as its key directory");
    }

    /// #3190: a node started under umask 002 created its state directory 0775
    /// and then refused it as its federation key directory.
    #[cfg(unix)]
    #[test]
    fn state_directory_is_owner_only_under_umask_002() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("var").join("state");
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "state_lock::tests::create_and_load_keys_under_umask_002",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(UMASK_002_STATE, &state)
            .output()
            .expect("start the child");
        assert!(
            out.status.success(),
            "{}: {}{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let mode = std::fs::metadata(&state).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o700, "state directory mode {mode:o}");
        // The child ran: the key it generated is in the directory.
        assert!(std::fs::read_dir(&state).unwrap().count() > 0);
    }
}
