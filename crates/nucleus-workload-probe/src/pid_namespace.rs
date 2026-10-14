//! #3344: the workload runs in a PID namespace of its own.
//!
//! The tool-proxy serves the workload's door, so the door's `SO_PEERCRED`
//! names the proxy, translated into THIS process's PID namespace. The kernel
//! answers 0 for a process outside it. So a peer pid of 0 is the namespace at
//! work: no pid the workload can name, `kill` or open under `/proc` denotes
//! the runtime. Any other pid is the runtime, visible, and the probe says what
//! `kill(pid, 0)` answered on it (`EPERM` is the uid fence, not the
//! namespace).
//!
//! Read off the kernel, not off `/proc`: a `/proc` mounted `hidepid=invisible`
//! hides the root runtime from a non-root workload in either namespace, so a
//! listing cannot tell the two apart.

/// What the door's peer pid says about the workload's PID namespace.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DoorPeer {
    /// The peer has no pid here: it is outside this PID namespace.
    Outside,
    /// The runtime is visible as `pid`, and what `kill(pid, 0)` answered.
    Visible { pid: i32, kill: Result<(), i32> },
    /// The observation failed, with why. Never read as `Outside` (ADR 0007
    /// A-2: "could not look" is not "looked and it was fine").
    Unobserved(String),
}

/// The failure, if any, for one observation.
pub(crate) fn failure(peer: &DoorPeer) -> Option<String> {
    match peer {
        DoorPeer::Outside => None,
        DoorPeer::Visible { pid, kill } => Some(format!(
            "the tool-proxy serving the workload door is pid {pid} in the workload's PID \
             namespace (kill(pid, 0): {}); the workload shares the runtime's PID namespace",
            match kill {
                Ok(()) => "delivered".to_string(),
                Err(errno) => format!("errno {errno}"),
            }
        )),
        DoorPeer::Unobserved(why) => Some(format!(
            "could not observe the workload's PID namespace: {why}"
        )),
    }
}

/// Connect to the door named by `NUCLEUS_TOOL_PROXY_URL` and classify its peer.
#[cfg(target_os = "linux")]
pub(crate) fn observe() -> DoorPeer {
    use std::os::fd::AsRawFd;
    let url = std::env::var("NUCLEUS_TOOL_PROXY_URL").unwrap_or_default();
    let Some(path) = url.strip_prefix("unix://") else {
        return DoorPeer::Unobserved(format!("the door is not a Unix socket: {url:?}"));
    };
    let stream = match std::os::unix::net::UnixStream::connect(path) {
        Ok(stream) => stream,
        Err(e) => return DoorPeer::Unobserved(format!("cannot connect to {path}: {e}")),
    };
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .unwrap_or(libc::socklen_t::MAX);
    // SAFETY: `cred` and `len` are live locals of the sizes the kernel is told.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return DoorPeer::Unobserved(format!(
            "SO_PEERCRED failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if cred.pid == 0 {
        return DoorPeer::Outside;
    }
    // SAFETY: signal 0 delivers nothing; it only asks whether one could be.
    let kill = if unsafe { libc::kill(cred.pid, 0) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))
    };
    DoorPeer::Visible {
        pid: cred.pid,
        kill,
    }
}

/// No PID namespaces off Linux; the guest is Linux.
#[cfg(not(target_os = "linux"))]
pub(crate) fn observe() -> DoorPeer {
    DoorPeer::Unobserved("not Linux".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a peer outside the namespace passes. A visible runtime fails
    /// whether or not the uid fence refused the signal, and a failed look
    /// fails too.
    #[test]
    fn only_a_door_peer_outside_the_namespace_passes() {
        assert_eq!(failure(&DoorPeer::Outside), None);
        let refused = failure(&DoorPeer::Visible {
            pid: 1,
            kill: Err(1),
        })
        .expect("a visible runtime fails");
        assert!(
            refused.contains("pid 1") && refused.contains("errno 1"),
            "{refused}"
        );
        assert!(
            failure(&DoorPeer::Visible {
                pid: 1,
                kill: Ok(())
            })
            .is_some()
        );
        assert!(failure(&DoorPeer::Unobserved("no door".into())).is_some());
    }
}
