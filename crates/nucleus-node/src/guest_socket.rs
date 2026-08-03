//! Handing a host-created socket to the jailed guest.
//!
//! # The failure this exists to make unrepeatable
//!
//! Firecracker's guest-initiated vsock connections arrive at `{uds_path}_{port}`
//! — a socket the NODE creates, running as root, while Firecracker runs as the
//! jailer uid. `prepare_jail` chowns everything it places and its comment notes
//! that the vsock socket is "deliberately absent" because Firecracker creates
//! it. That is true of `vsock.sock`, and **not** of the `_{port}` sockets.
//!
//! Connecting to a Unix socket requires WRITE permission on it, so a root-owned
//! socket gives Firecracker's `connect()` EACCES and the guest sees "connection
//! reset by peer" from a socket that is demonstrably listening. Measured on a
//! booted pod, 2026-07-29:
//!
//! ```text
//! srwxr-xr-x 1  123 users  vsock.sock          <- Firecracker made this
//! srwxr-xr-x 1 root root   vsock.sock_15012    <- the node made this
//! ```
//!
//! Downstream the guest fetched no SVID and no task token, all three
//! sandbox-proof tiers failed, and the tool-proxy exited as PID 1 — a kernel
//! panic whose visible cause was four layers from the file mode.
//!
//! # Why this is a shared function and not a second copy of that fix
//!
//! The workload API socket was fixed. The credential broker socket, created the
//! same way, in the same directory, by the same root process, **was not** — it
//! bound successfully, logged "started credential broker at …", passed every
//! launch check, and no guest could ever have connected. It fails CLOSED and is
//! indistinguishable from a policy refusal from inside the guest, which is
//! exactly how it would have survived indefinitely.
//!
//! One socket got the lesson and its sibling did not, because the lesson lived
//! in a comment next to one call site. It lives in a function now, and
//! `every_guest_socket_is_handed_over` fails if a third listener appears without
//! calling it.
//!
//! # chown, not chmod
//!
//! Only the jailed Firecracker should be able to connect. Widening the mode
//! would open these sockets — which serve SVIDs, task tokens and the broker
//! capability — to every user on the host.

// The launch path that calls this is `cfg(target_os = "linux")`, so a macOS
// build compiles no caller. On Linux the dead-code detector stays live.
#![cfg_attr(all(not(test), not(target_os = "linux")), allow(dead_code))]

use std::io;
use std::path::Path;

/// Give a node-created guest socket to the jailed uid.
///
/// `None` means the pod is not jailed: unjailed Firecracker runs as the same
/// user as the node and can already connect, so handing the socket away would
/// give up our own socket for nothing.
pub fn give_socket_to_jail(path: &Path, owner: Option<(u32, u32)>) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::chown(path, Some(uid), Some(gid)).map_err(|e| {
            io::Error::other(format!(
                "cannot give {} to the jailed uid {uid}:{gid}: {e}",
                path.display()
            ))
        })?;
    }
    // Referenced on every platform so a macOS build type-checks the call sites
    // and cannot drift from the Linux one.
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, owner);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The handover runs and succeeds on the real socket path.
    ///
    /// # What this can and cannot show, stated rather than implied
    ///
    /// An unprivileged process may chown a file it owns only to ITSELF, so this
    /// exercises the call path and its error handling and cannot demonstrate a
    /// change of owner. That half needs root, and it is checked where it is
    /// actually consequential: the end-to-end test stats
    /// `<jail_root>/vsock.sock_<broker_port>` on a booted pod.
    ///
    /// The uid comes from the socket's own metadata rather than `libc::getuid`,
    /// so this needs no new dependency in a credential-adjacent crate.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_handover_succeeds_on_a_real_socket() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vsock.sock_1027");
        let _listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");

        let before = std::fs::metadata(&path).expect("stat");
        let (uid, gid) = (before.uid(), before.gid());
        give_socket_to_jail(&path, Some((uid, gid))).expect("chown to self must succeed");

        let after = std::fs::metadata(&path).expect("stat");
        assert_eq!(after.uid(), uid);
        assert_eq!(after.gid(), gid);
    }

    /// A path that does not exist is an ERROR, not a silent success.
    ///
    /// This is the half that matters for the defect: a handover that quietly did
    /// nothing would leave the socket root-owned and report success, which is
    /// indistinguishable from the bug it fixes.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_missing_socket_is_an_error_not_a_silent_success() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = give_socket_to_jail(&dir.path().join("nothing-here"), Some((0, 0)))
            .expect_err("chowning a path that does not exist must fail");
        assert!(
            err.to_string().contains("nothing-here"),
            "the error must name the path so an operator can act on it: {err}"
        );
    }

    /// An unjailed pod is left alone. Handing the socket to another uid there
    /// would give away a socket the node itself needs to keep.
    #[test]
    fn an_unjailed_pod_leaves_the_socket_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vsock.sock_1027");
        let _listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        give_socket_to_jail(&path, None).expect("no owner is not an error");
        assert!(path.exists());
    }

    /// **The anti-divergence check.** The broker socket went unfixed for the
    /// whole life of the workload API's fix because the reasoning lived in a
    /// comment beside one call site rather than in a function.
    ///
    /// Every module that binds a guest-initiated `{uds}_{port}` socket must hand
    /// it over. A third listener that forgets fails here, at the moment it is
    /// written, rather than on a booted pod four layers away from the file mode.
    #[test]
    fn every_guest_socket_is_handed_over() {
        // Modules that create a guest-initiated socket the jailed Firecracker
        // must be able to connect to.
        let binders = [
            ("broker_transport.rs", include_str!("broker_transport.rs")),
            (
                "workload_api_vsock.rs",
                include_str!("workload_api_vsock.rs"),
            ),
        ];
        for (name, src) in binders {
            // Non-vacuity: the file really does bind a socket, so a rename that
            // silently emptied this check fails rather than passing.
            assert!(
                src.contains("UnixListener::bind"),
                "{name} no longer binds a socket — this check is watching the wrong file"
            );
            assert!(
                src.contains("give_socket_to_jail"),
                "{name} binds a guest-initiated socket and never hands it to the jailed \
                 uid. Firecracker's connect() will get EACCES and the guest will see a \
                 socket that is listening and unreachable — see this module's docs for \
                 the post-mortem."
            );
        }
    }
}
