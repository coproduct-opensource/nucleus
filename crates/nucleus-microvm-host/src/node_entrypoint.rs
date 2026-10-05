//! Container PID-1 entrypoint: leave the delegated cgroup root empty before
//! the node can launch jailed VMMs with domain resource controllers.
use std::ffi::OsString;
use std::io;

/// Prepare this container's cgroup layout, then replace PID 1 with the node.
/// Only this process is moved; an occupied root is refused, never evacuated.
#[cfg(target_os = "linux")]
pub fn run(args: Vec<OsString>) -> io::Result<()> {
    let membership = std::fs::read_to_string("/proc/self/cgroup")?;
    check_entrypoint(std::process::id(), &membership)?;
    let root = std::path::Path::new("/sys/fs/cgroup");
    // Require a unified hierarchy before creating or moving anything.
    std::fs::read_to_string(root.join("cgroup.controllers"))?;
    let leaf = root.join("nucleus-host");
    std::fs::create_dir_all(&leaf)?;
    std::fs::write(leaf.join("cgroup.procs"), b"1")?;
    let remaining = std::fs::read_to_string(root.join("cgroup.procs"))?;
    let prepared = PreparedHost::check_empty(&remaining)?;
    prepared.exec(args)
}

/// Container host preparation is a Linux operation.
#[cfg(not(target_os = "linux"))]
pub fn run(_args: Vec<OsString>) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "run-node requires a Linux container with cgroup v2",
    ))
}

#[cfg(any(target_os = "linux", test))]
fn check_entrypoint(pid: u32, membership: &str) -> io::Result<()> {
    if pid != 1 || membership.trim() != "0::/" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "run-node must be PID 1 at the container's unified cgroup root",
        ));
    }
    Ok(())
}

/// Minted only after the delegated root has no internal processes (ADR C-1).
#[cfg(any(target_os = "linux", test))]
struct PreparedHost;

#[cfg(any(target_os = "linux", test))]
impl PreparedHost {
    fn check_empty(remaining: &str) -> io::Result<Self> {
        if !remaining.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                "container cgroup root still has processes; refusing to start the node",
            ));
        }
        Ok(Self)
    }

    #[cfg(target_os = "linux")]
    fn exec(self, args: Vec<OsString>) -> io::Result<()> {
        use std::os::unix::process::CommandExt;
        Err(std::process::Command::new("/usr/local/bin/nucleus-node")
            .args(args)
            .exec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_container_pid_one_at_the_unified_root_can_prepare() {
        assert!(check_entrypoint(1, "0::/\n").is_ok());
        for (pid, membership) in [
            (2, "0::/\n"),
            (1, "0::/system.slice/node.service\n"),
            (1, "1:cpu:/\n"),
            (1, "0::/\n1:cpu:/\n"),
        ] {
            assert_eq!(
                check_entrypoint(pid, membership).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn another_root_process_prevents_node_execution() {
        assert!(PreparedHost::check_empty("").is_ok());
        assert!(PreparedHost::check_empty("2\n").is_err());
        assert!(PreparedHost::check_empty("0\n").is_err());
    }
}
