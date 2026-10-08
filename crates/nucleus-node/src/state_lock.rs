//! Hold one open lock file for the node's entire lifetime. Never unlink it:
//! replacing the inode would let a second node lock a different file.
use std::{fs::File, path::Path};

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
}
