//! Handing a host-created socket to the jailed guest.
//!
//! # The failure this exists to make unrepeatable
//!
//! Firecracker's guest-initiated vsock connections arrive at `{uds_path}_{port}`
//! — a socket the NODE creates, running as root, while Firecracker runs as the
//! jailer uid. `prepare_jail` gives the jail user the files it creates there and
//! its comment notes that the vsock socket is "deliberately absent" because Firecracker creates
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
use std::path::{Path, PathBuf};

use nucleus_ifc_kernel::VsockListener;

/// Where the host listens for guest-initiated connections to `listener`.
///
/// Firecracker routes a guest's `connect(VMADDR_CID_HOST, port)` to the Unix
/// socket `{uds_path}_{port}`. The port comes from the listener, never from a
/// caller's number: the host-listener inventory
/// (`nucleus_ifc_kernel::HostListener`) is the one place ports are written.
pub fn listener_path(uds_path: &Path, listener: VsockListener) -> PathBuf {
    let mut s = uds_path.as_os_str().to_os_string();
    s.push(format!("_{}", listener.port()));
    PathBuf::from(s)
}

/// Bind a guest-initiated vsock listener and hand it to the jailed uid.
///
/// **The only way the node binds a guest-reachable socket.** It takes a
/// [`VsockListener`], so a listener that is not in the inventory cannot be
/// bound, and its port is the inventory's (ADR 0007 G-1).
/// `every_vsock_bind_goes_through_the_typed_helper` fails if a production
/// `UnixListener::bind` appears anywhere else in the node.
///
/// The socket is prepared by `broker_transport::prepare_socket` (a stale socket
/// unlinked, a non-socket refused, the parent directory `0700`) and then given
/// to the jail by [`give_socket_to_jail`], the step a second copy once forgot.
pub fn bind_guest_listener(
    uds_path: &Path,
    listener: VsockListener,
    jail_owner: Option<(u32, u32)>,
) -> io::Result<(tokio::net::UnixListener, PathBuf)> {
    let path = listener_path(uds_path, listener);
    let bound = crate::broker_transport::prepare_socket(&path)?;
    give_socket_to_jail(&path, jail_owner)?;
    Ok((bound, path))
}

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

    /// **The anti-divergence check, by construction.** The broker socket once
    /// went un-handed-over because the reasoning lived in a comment beside one
    /// call site; and the broker once bound the SPIFFE Workload API's port
    /// because its port was a number a caller passed. Both are now one function
    /// that takes a [`VsockListener`].
    ///
    /// This census holds the node to it: in production code, the only
    /// `UnixListener::bind(` is the one inside `prepare_socket`, and the only
    /// caller of `prepare_socket(` is [`bind_guest_listener`]. A listener bound
    /// any other way fails here, when it is written, rather than on a booted pod.
    #[test]
    fn every_vsock_bind_goes_through_the_typed_helper() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let files = census::production_sources(&src);
        let count = |needle: &str| -> Vec<(String, usize)> {
            files
                .iter()
                .filter_map(|(rel, text)| {
                    let n = text.matches(needle).count();
                    (n > 0).then(|| (rel.clone(), n))
                })
                .collect()
        };
        // Non-vacuity rides on the equality: each expected site must be SEEN,
        // so a broken walker or a stripper that ate production code fails too.
        assert_eq!(
            count("UnixListener::bind("),
            vec![("broker_transport.rs".to_string(), 1)],
            "a production UnixListener::bind outside `prepare_socket`: bind a guest-reachable \
             socket through `guest_socket::bind_guest_listener`, which takes a VsockListener \
             (docs/architecture/mediated-set.md, 'Host listeners')"
        );
        assert_eq!(
            count("prepare_socket("),
            vec![
                ("broker_transport.rs".to_string(), 1),
                ("guest_socket.rs".to_string(), 1),
            ],
            "prepare_socket is called outside bind_guest_listener (broker_transport.rs's \
             one occurrence is its definition)"
        );
    }

    /// Each listener has its own path in a pod's directory: the SPIFFE API and
    /// the broker were once the same file.
    #[test]
    fn every_listener_has_its_own_path() {
        let base = Path::new("/srv/jailer/pod-1/root/vsock.sock");
        let paths: std::collections::BTreeSet<PathBuf> = VsockListener::ALL
            .iter()
            .map(|l| listener_path(base, *l))
            .collect();
        assert_eq!(paths.len(), VsockListener::ALL.len());
        assert!(paths.contains(Path::new("/srv/jailer/pod-1/root/vsock.sock_1027")));
        assert!(
            !paths.contains(base),
            "never the host-initiated path itself"
        );
    }

    /// **The defect, without a boot.** Every listener bound into ONE pod
    /// directory, in the order a pod launch binds them (workload API, SPIFFE,
    /// then the broker, then the decision channel), and a guest connection to
    /// each path must reach THAT listener.
    ///
    /// On main before this change the broker's port was 15013, the SPIFFE
    /// Workload API's: the broker's bind unlinked the SPIFFE socket and took its
    /// path, so a connection to `vsock.sock_15013` reached the broker and the
    /// SPIFFE listener never saw one. Here that is the SPIFFE accept timing out.
    #[tokio::test]
    async fn every_listener_still_answers_after_all_are_bound() {
        let dir = tempfile::tempdir().expect("tempdir");
        let uds = dir.path().join("vsock.sock");
        let mut bound = Vec::new();
        for l in VsockListener::ALL {
            let (listener, path) = bind_guest_listener(&uds, *l, None).expect("bind");
            bound.push((*l, listener, path));
        }
        for (l, listener, path) in &bound {
            assert!(path.exists(), "{l:?}'s socket was unlinked by a later bind");
            let _client = tokio::net::UnixStream::connect(path)
                .await
                .unwrap_or_else(|e| panic!("{l:?}: connect {}: {e}", path.display()));
            let accepted =
                tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept()).await;
            assert!(
                matches!(accepted, Ok(Ok(_))),
                "a guest connecting to {l:?}'s port did not reach {l:?}'s listener: another \
                 listener took its path"
            );
        }
    }

    /// A stale socket at a listener's path is replaced, and the helper hands
    /// back the path it bound — the one a guest's connect is routed to.
    #[tokio::test]
    async fn the_helper_binds_the_inventory_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let uds = dir.path().join("vsock.sock");
        let (_first, path) =
            bind_guest_listener(&uds, VsockListener::CredentialBroker, None).expect("bind");
        assert_eq!(path, dir.path().join("vsock.sock_1027"));
        let (_second, again) = bind_guest_listener(&uds, VsockListener::CredentialBroker, None)
            .expect("a stale socket must not block a rebind");
        assert_eq!(again, path);
    }

    #[test]
    fn the_census_stripper_drops_test_items_and_keeps_production() {
        let text = "fn a() { bind(); }\n#[cfg(test)]\nmod t {\n    fn x() { bind(); }\n}\n\
                    #[cfg(all(test, unix))]\nmod u;\n#[cfg(not(test))]\nfn b() { bind(); }\nfn c() {}\n";
        let kept = census::strip_test_items(text);
        assert_eq!(kept.matches("bind()").count(), 2, "{kept}");
        assert!(kept.contains("fn c()"));
    }
}

/// The source census behind `every_vsock_bind_goes_through_the_typed_helper`:
/// the node's production source, with `cfg(test)` items and test-only module
/// files removed.
#[cfg(test)]
mod census {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    /// Whether an attribute line gates its item on `test` (and not `not(test)`).
    fn is_test_cfg(line: &str) -> bool {
        let t = line.trim_start();
        t.starts_with("#[cfg(") && t.contains("test") && !t.contains("not(test)")
    }

    /// `text` without its `#[cfg(test)]`-gated items. An item ends at the line
    /// that closes its first brace, or at a `;`-terminated line with no brace.
    pub(super) fn strip_test_items(text: &str) -> String {
        let mut out = String::new();
        let mut lines = text.lines();
        while let Some(line) = lines.next() {
            if !is_test_cfg(line) {
                out.push_str(line);
                out.push('\n');
                continue;
            }
            let mut depth: i64 = 0;
            let mut opened = false;
            for item in lines.by_ref() {
                let t = item.trim_start();
                if !opened && t.starts_with("#[") {
                    continue; // further attributes of the same item
                }
                for c in item.chars() {
                    match c {
                        '{' => {
                            depth += 1;
                            opened = true;
                        }
                        '}' => depth -= 1,
                        _ => {}
                    }
                }
                if (opened && depth <= 0) || (!opened && item.trim_end().ends_with(';')) {
                    break;
                }
            }
        }
        out
    }

    /// Files declared by a `cfg(test)` `mod x;` (with or without `#[path]`),
    /// resolved against the declaring file.
    fn test_only_files(files: &BTreeMap<PathBuf, String>) -> BTreeSet<PathBuf> {
        let mut out = BTreeSet::new();
        for (file, text) in files {
            let dir = file.parent().unwrap_or(Path::new(""));
            let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let child_dir = if matches!(stem, "main" | "lib" | "mod") {
                dir.to_path_buf()
            } else {
                dir.join(stem)
            };
            let lines: Vec<&str> = text.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if !is_test_cfg(line) {
                    continue;
                }
                let mut path_attr = None;
                for next in lines.iter().skip(i + 1) {
                    let t = next.trim();
                    if let Some(rest) = t.strip_prefix("#[path = \"") {
                        path_attr = rest.strip_suffix("\"]").map(str::to_string);
                        continue;
                    }
                    if t.starts_with("#[") {
                        continue;
                    }
                    let decl = t
                        .trim_start_matches("pub(crate) ")
                        .trim_start_matches("pub ")
                        .strip_prefix("mod ")
                        .and_then(|r| r.strip_suffix(';'));
                    if let Some(name) = decl {
                        match &path_attr {
                            Some(p) => {
                                out.insert(dir.join(p));
                            }
                            None => {
                                out.insert(child_dir.join(format!("{name}.rs")));
                                out.insert(child_dir.join(name).join("mod.rs"));
                            }
                        }
                    }
                    break;
                }
            }
        }
        out
    }

    /// `(path relative to src, production text)` for every production `.rs`
    /// file under `src`, sorted by path.
    pub(super) fn production_sources(src: &Path) -> Vec<(String, String)> {
        let mut files = BTreeMap::new();
        let mut stack = vec![src.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read src dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).expect("read source");
                    files.insert(path, text);
                }
            }
        }
        assert!(files.len() > 50, "the census walked {} files", files.len());
        let test_only = test_only_files(&files);
        files
            .iter()
            .filter(|(p, _)| !test_only.contains(*p))
            .map(|(p, text)| {
                let rel = p.strip_prefix(src).expect("under src");
                (
                    rel.to_string_lossy().replace('\\', "/"),
                    strip_test_items(text),
                )
            })
            .collect()
    }
}
