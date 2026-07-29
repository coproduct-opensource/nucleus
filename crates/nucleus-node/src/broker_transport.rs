//! Where the guest reaches the broker, and how much it may say.
//!
//! # The socket the guest connects to
//!
//! Firecracker's vsock is asymmetric. Host-initiated connections go to the
//! single AF_UNIX socket at `uds_path`; **guest-initiated** connections arrive
//! at a *different* path — `{uds_path}_{PORT}` — and the host must be listening
//! there before the guest connects, or the connection is refused.
//!
//! Getting that path wrong does not fail loudly: the guest simply cannot reach
//! the broker, and every credential request quietly falls back to whatever the
//! old path was. [`broker_socket_path`] exists so the derivation is written once
//! and tested, rather than formatted inline at a call site.
//!
//! # Why the reader is bounded separately from the parser
//!
//! `envelope_frame::check_frame` bounds what is *parsed*. It cannot bound what
//! is *accumulated*, because by the time it sees a string the reading is already
//! done. A guest that opens a connection and sends bytes without ever sending a
//! newline would make the host buffer forever — the size check never runs,
//! because the line never ends.
//!
//! So [`read_frame_bounded`] enforces the ceiling **while reading**, and stops
//! at the limit rather than after it. The two bounds are not redundant: one
//! protects the parser, the other protects the reader that feeds it.

// Not yet reachable: no accept loop binds this socket during pod spawn, so the
// guest cannot submit an envelope and credentials still arrive the old way.
// CI denies warnings, and a bare dead_code warning would read as an oversight
// rather than a stated gap. Every item is exercised by the tests below.
#![cfg_attr(not(test), allow(dead_code))]

use std::io::BufRead;
use std::path::{Path, PathBuf};

use crate::envelope_frame::MAX_FRAME_BYTES;

/// The vsock port the guest connects to for credential brokering.
///
/// Distinct from the tool-proxy's control-plane port: that one is
/// host-initiated and carries host→guest requests, this one is guest-initiated
/// and carries envelopes the other way. Sharing a port would mix a trusted
/// direction with an untrusted one on the same listener.
pub const BROKER_VSOCK_PORT: u32 = 1027;

/// Where the host must listen for guest-initiated broker connections.
///
/// Firecracker appends `_{port}` to the configured `uds_path` for
/// guest-initiated connections; see the vsock documentation.
pub fn broker_socket_path(uds_path: &Path, port: u32) -> PathBuf {
    let mut s = uds_path.as_os_str().to_os_string();
    s.push(format!("_{port}"));
    PathBuf::from(s)
}

/// Why a frame could not be read.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The peer sent more than the ceiling without terminating the frame.
    ///
    /// Reported when the limit is reached, not after it — the whole point is
    /// that the host stops accumulating.
    Unterminated {
        /// How much was accumulated before giving up.
        bytes: usize,
    },
    /// The connection ended before a frame was complete.
    Eof,
    /// Underlying I/O failure.
    Io,
}

/// Read one newline-terminated frame, refusing to accumulate past `max`.
///
/// Returns the frame WITHOUT its trailing newline. Reads byte-at-a-time rather
/// than with `read_line`, because `read_line` will happily grow its buffer to
/// whatever the peer sends — which is exactly the behaviour being prevented.
pub fn read_frame_bounded(mut reader: impl BufRead, max: usize) -> Result<String, ReadError> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) => return Err(ReadError::Eof),
            Ok(_) => {
                if byte[0] == b'\n' {
                    return String::from_utf8(buf).map_err(|_| ReadError::Io);
                }
                if buf.len() >= max {
                    return Err(ReadError::Unterminated { bytes: buf.len() });
                }
                buf.push(byte[0]);
            }
            Err(_) => return Err(ReadError::Io),
        }
    }
}

/// Read a frame using the module's default ceiling.
pub fn read_frame(reader: impl BufRead) -> Result<String, ReadError> {
    read_frame_bounded(reader, MAX_FRAME_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// The guest-initiated path is `{uds_path}_{port}`, not `uds_path`. Getting
    /// this wrong makes the broker silently unreachable.
    #[test]
    fn the_guest_initiated_socket_has_the_port_suffix() {
        let base = Path::new("/srv/jailer/pod-1/root/vsock.sock");
        let p = broker_socket_path(base, BROKER_VSOCK_PORT);
        assert_eq!(
            p,
            PathBuf::from("/srv/jailer/pod-1/root/vsock.sock_1027"),
            "Firecracker appends _PORT for guest-initiated connections"
        );
        assert_ne!(
            p,
            base.to_path_buf(),
            "it must NOT be the host-initiated path"
        );
    }

    /// The broker port must not collide with the control-plane port, or an
    /// untrusted guest-initiated direction shares a listener with a trusted
    /// host-initiated one.
    #[test]
    fn the_broker_port_is_distinct_from_the_control_plane() {
        // The tool-proxy's control plane is configured per-pod via the spec;
        // 1024 is the conventional default in this repo's fixtures.
        assert_ne!(BROKER_VSOCK_PORT, 1024);
    }

    #[test]
    fn a_terminated_frame_reads_back_without_its_newline() {
        let input = Cursor::new(b"{\"a\":1}\nleftover".to_vec());
        assert_eq!(read_frame(input).unwrap(), "{\"a\":1}");
    }

    /// **THE BOUND THE PARSER CANNOT PROVIDE.** A guest that never sends a
    /// newline must not make the host accumulate without limit. `check_frame`
    /// cannot help: it never runs, because the line never ends.
    #[test]
    fn an_endless_frame_is_cut_off_at_the_ceiling() {
        // 10x the ceiling, no newline anywhere.
        let flood = vec![b'x'; MAX_FRAME_BYTES * 10];
        match read_frame(Cursor::new(flood)) {
            Err(ReadError::Unterminated { bytes }) => assert_eq!(
                bytes, MAX_FRAME_BYTES,
                "reading must stop AT the ceiling, not after it"
            ),
            other => panic!("an unterminated flood must be refused, got {other:?}"),
        }
    }

    /// A frame exactly at the ceiling is still accepted — the bound is on
    /// accumulation, not an off-by-one that rejects legitimate maximum frames.
    #[test]
    fn a_frame_exactly_at_the_ceiling_is_accepted() {
        let mut data = vec![b'x'; MAX_FRAME_BYTES];
        data.push(b'\n');
        let got = read_frame(Cursor::new(data)).expect("a maximal frame is legal");
        assert_eq!(got.len(), MAX_FRAME_BYTES);
    }

    /// A closed connection is an error, not an empty frame that would then be
    /// parsed as malformed and handled as a request.
    #[test]
    fn a_closed_connection_is_eof_not_an_empty_frame() {
        assert_eq!(read_frame(Cursor::new(Vec::new())), Err(ReadError::Eof));
    }

    /// Invalid UTF-8 is refused rather than lossily converted — a lossy
    /// conversion would let a guest smuggle bytes past the parser's expectations.
    #[test]
    fn invalid_utf8_is_refused() {
        let bad = vec![0xff, 0xfe, b'\n'];
        assert_eq!(read_frame(Cursor::new(bad)), Err(ReadError::Io));
    }
}

// ── The serving side ──────────────────────────────────────────────────────

use std::time::Duration;

use nucleus_cred_broker::{CredentialStore, PodIdentity};
use portcullis::PermissionLattice;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// How long one guest connection may take from accept to answered.
///
/// An untrusted peer that connects and then says nothing would otherwise hold a
/// slot forever — the classic slowloris shape, which exhausts a listener without
/// sending meaningful traffic. Every connection is on a clock.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// How many guest connections may be in flight at once.
///
/// Bounded because a guest can open sockets far faster than the host can serve
/// them, and an unbounded accept loop turns that into file-descriptor
/// exhaustion for the whole node — not just this listener.
#[cfg_attr(not(test), allow(dead_code))]
pub const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// Read one frame asynchronously, refusing to accumulate past `max`.
///
/// The async twin of [`read_frame_bounded`], and bounded for the same reason:
/// `read_line` would grow its buffer to whatever the peer sends, and the peer is
/// the agent the sandbox exists to contain.
pub async fn read_frame_async(
    reader: impl AsyncRead + Unpin,
    max: usize,
) -> Result<String, ReadError> {
    let mut reader = BufReader::new(reader);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        match tokio::io::AsyncReadExt::read(&mut reader, &mut byte).await {
            Ok(0) => return Err(ReadError::Eof),
            Ok(_) => {
                if byte[0] == b'\n' {
                    return String::from_utf8(buf).map_err(|_| ReadError::Io);
                }
                if buf.len() >= max {
                    return Err(ReadError::Unterminated { bytes: buf.len() });
                }
                buf.push(byte[0]);
            }
            Err(_) => return Err(ReadError::Io),
        }
    }
}

/// Serve exactly one request on an already-accepted connection.
///
/// Generic over the stream so it is testable with an in-memory pipe rather than
/// a real socket — the lesson from the vsock accept path, where the logic sat
/// behind `cfg(target_os = "linux")` and a dev machine never compiled it.
///
/// One frame per connection, deliberately. A connection that could carry many
/// requests would need per-connection state and its own lifetime policy; one
/// request per connection needs neither, and the guest is not a latency-
/// sensitive client.
pub async fn serve_connection<S>(
    stream: S,
    identity: &PodIdentity,
    policy: &PermissionLattice,
    store: &CredentialStore,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    serve_connection_with_timeout(stream, identity, policy, store, CONNECTION_TIMEOUT).await
}

/// As [`serve_connection`], with the deadline injectable so the timeout itself
/// can be tested without a ten-second test.
///
/// # The bug this signature exists because of
///
/// The first version of `serve_connection` defined `CONNECTION_TIMEOUT` and then
/// never applied it. A peer that connected and said nothing held the task
/// forever — precisely the slowloris shape the constant was named for, with the
/// constant sitting right there unused. `a_peer_that_sends_nothing_gets_a_refusal_not_a_hang`
/// found it. A named constant is not a bound until something reads it.
pub async fn serve_connection_with_timeout<S>(
    stream: S,
    identity: &PodIdentity,
    policy: &PermissionLattice,
    store: &CredentialStore,
    deadline: Duration,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);

    let read = tokio::time::timeout(deadline, read_frame_async(reader, MAX_FRAME_BYTES)).await;
    let response = match read {
        Ok(Ok(frame)) => {
            // Read once, here, rather than inside the decision functions: those
            // take the instant as a parameter so they are testable without a
            // clock, and so a single request is judged against ONE instant
            // rather than against whatever the clock said at each step.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            crate::broker::handle_frame(&frame, identity, policy, store, now)
        }
        // A read failure and a TIMEOUT are answered with the SAME coarse refusal
        // a policy denial gets. Distinguishing "you sent garbage" from "you were
        // too slow" from "you were denied" would hand the guest a probe it does
        // not otherwise have.
        Ok(Err(_)) | Err(_) => crate::broker::BrokerResponse::refused("malformed request"),
    };

    let mut line = serde_json::to_string(&response).unwrap_or_else(|_| {
        // Serialising a two-field struct cannot realistically fail, but falling
        // back to a granted response would be catastrophic, so the fallback is
        // a refusal.
        r#"{"granted":false,"reason":"internal error"}"#.to_string()
    });
    line.push('\n');
    let _ = writer.write_all(line.as_bytes()).await;
    let _ = writer.flush().await;
}

#[cfg(test)]
mod serving_tests {
    use super::*;
    use nucleus_cred_broker::Credential;

    fn who() -> PodIdentity {
        PodIdentity::observed_by_host("spiffe://nucleus/pod/abc")
    }

    fn store_with(target: &str, value: &str) -> CredentialStore {
        let mut s = CredentialStore::new();
        s.insert(target, Credential::new(value));
        s
    }

    async fn round_trip(
        request: &str,
        policy: &PermissionLattice,
        store: &CredentialStore,
    ) -> String {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let id = who();
        let serve = serve_connection(server, &id, policy, store);
        let talk = async {
            let (r, mut w) = tokio::io::split(client);
            w.write_all(request.as_bytes()).await.unwrap();
            w.flush().await.unwrap();
            let mut line = String::new();
            BufReader::new(r).read_line(&mut line).await.unwrap();
            line
        };
        let (_, reply) = tokio::join!(serve, talk);
        reply
    }

    /// End to end over a real (in-memory) stream: a permitted request is
    /// granted, and the credential does not appear on the wire.
    #[tokio::test]
    async fn a_permitted_request_is_granted_without_leaking_the_secret() {
        let policy = PermissionLattice::permissive();
        let store = store_with("api.example.test", "super-secret-token");
        let req = serde_json::json!({
            "operation": "WebFetch",
            "target": "api.example.test",
            "justification": "routine"
        })
        .to_string()
            + "\n";

        let reply = round_trip(&req, &policy, &store).await;
        assert!(reply.contains("\"granted\":true"), "reply: {reply}");
        assert!(
            !reply.contains("super-secret-token"),
            "the credential reached the guest: {reply}"
        );
    }

    /// **A silent peer must not hold the connection open.** Nothing is sent, so
    /// the read ends at EOF once the client half drops — the server answers
    /// rather than hanging.
    #[tokio::test]
    async fn a_peer_that_sends_nothing_gets_a_refusal_not_a_hang() {
        let policy = PermissionLattice::permissive();
        let store = store_with("api.example.test", "token");
        let (client, server) = tokio::io::duplex(1024);
        let (r, w) = tokio::io::split(client);
        drop(w); // say nothing at all

        // A short deadline so the test is fast; the production default is
        // CONNECTION_TIMEOUT. The outer timeout is generous — if the inner one
        // is missing, this is what fails.
        let served = tokio::time::timeout(
            Duration::from_secs(5),
            serve_connection_with_timeout(
                server,
                &who(),
                &policy,
                &store,
                Duration::from_millis(200),
            ),
        )
        .await;
        assert!(
            served.is_ok(),
            "serving a silent peer must not hang — the connection deadline is not being applied"
        );

        let mut line = String::new();
        let _ = BufReader::new(r).read_line(&mut line).await;
        assert!(line.contains("\"granted\":false"), "reply: {line}");
    }

    /// An unterminated flood is cut off at the ceiling rather than buffered.
    #[tokio::test]
    async fn an_unterminated_flood_is_refused() {
        let policy = PermissionLattice::permissive();
        let store = store_with("api.example.test", "token");
        let flood = "x".repeat(MAX_FRAME_BYTES * 4); // no newline, ever
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (r, mut w) = tokio::io::split(client);

        let id = who();
        let serve = serve_connection(server, &id, &policy, &store);
        let talk = async {
            let _ = w.write_all(flood.as_bytes()).await;
            let mut line = String::new();
            let _ = BufReader::new(r).read_line(&mut line).await;
            line
        };
        let (_, reply) = tokio::join!(serve, talk);
        assert!(reply.contains("\"granted\":false"), "reply: {reply}");
    }
}

// ── The listener ──────────────────────────────────────────────────────────

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

/// Create the broker's listening socket with restrictive permissions.
///
/// # Why permissions matter on this socket
///
/// Linux honours AF_UNIX file permissions: a process needs write access to the
/// socket file to connect. This socket is the door to the credential broker, so
/// a world-writable one would let any local process on the host ask for
/// credentials on a pod's behalf.
///
/// `chmod` *after* `bind` is racy — there is a window in which the socket exists
/// with the default mode and anyone may connect.
///
/// # Why not umask
///
/// The obvious fix is to set a restrictive umask before binding and restore it
/// after. **That is wrong in a multi-threaded process, and it was tried here.**
/// `umask(2)` is per-PROCESS, not per-thread, so during that window every other
/// file the node creates concurrently gets the restrictive mode too. It was not
/// caught by reasoning — it was caught by three unrelated `trust_gate` tests
/// failing with `PermissionDenied` because they happened to create key files
/// while this function held the mask.
///
/// So access control lives on the **parent directory** instead, which is the
/// conventional answer for exactly this reason: the directory is created `0700`
/// before the socket is bound inside it, so the socket's own mode never matters
/// and no global process state is touched. There is no window, because there is
/// nothing to traverse.
///
/// A stale socket from a previous run is unlinked first: `bind` fails on an
/// existing path, and a node that could not restart after an unclean shutdown
/// would be a self-inflicted outage.
pub fn prepare_socket(path: &std::path::Path) -> io::Result<UnixListener> {
    // Remove a stale socket, but only if it IS a socket — refusing to unlink
    // arbitrary paths, so a misconfigured path cannot delete a real file.
    if let Ok(meta) = std::fs::metadata(path) {
        use std::os::unix::fs::FileTypeExt;
        if meta.file_type().is_socket() {
            let _ = std::fs::remove_file(path);
        } else {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "broker socket path exists and is not a socket — refusing to unlink it",
            ));
        }
    }

    // Lock the PARENT DIRECTORY, not the socket. No process-global state, no
    // window: a peer that cannot traverse the directory cannot reach the socket
    // whatever mode the socket itself ends up with.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        let mut perms = std::fs::metadata(parent)?.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(parent, perms)?;
    }
    UnixListener::bind(path)
}

/// Accept guest connections and serve one brokered request each.
///
/// Concurrency is capped by [`MAX_CONCURRENT_CONNECTIONS`]: a guest can open
/// sockets far faster than the host can serve them, and an unbounded accept loop
/// turns that into file-descriptor exhaustion for the whole node rather than
/// just this listener. Permits are acquired BEFORE `accept`, so the loop stops
/// pulling connections off the queue instead of accepting them and then queueing
/// work internally.
///
/// # Identity is bound to the listener, not to the request
///
/// `identity` is taken once, here, and applies to every connection this listener
/// accepts. That is sound because Firecracker creates one vsock `uds_path` per
/// VM, so a socket IS a pod. Binding it at the listener rather than per request
/// means there is no point in the serving path where a guest could influence it.
///
/// Runs until `shutdown` resolves.
pub async fn serve_broker(
    listener: UnixListener,
    identity: PodIdentity,
    policy: Arc<PermissionLattice>,
    store: Arc<CredentialStore>,
    shutdown: impl std::future::Future<Output = ()>,
) {
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    tokio::pin!(shutdown);
    loop {
        let permit = match Arc::clone(&permits).acquire_owned().await {
            Ok(p) => p,
            Err(_) => return, // semaphore closed
        };
        tokio::select! {
            _ = &mut shutdown => return,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        let policy = Arc::clone(&policy);
                        let store = Arc::clone(&store);
                        let identity = identity.clone();
                        tokio::spawn(async move {
                            serve_connection(stream, &identity, &policy, &store).await;
                            drop(permit);
                        });
                    }
                    // A failed accept is not fatal: too many open files, or a
                    // peer that vanished from the queue. Dropping the listener
                    // over a transient error would be a worse outcome than the
                    // error.
                    Err(_) => {
                        drop(permit);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }
}

/// Connect to the broker as a guest would, for tests and diagnostics.
/// How a [`BrokerListener`] came to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownOutcome {
    /// The serving task observed the signal and returned.
    Stopped,
    /// The task had to be aborted — a connection outlived the signal.
    Aborted,
}

/// A running broker listener, owned by the pod it serves.
///
/// # Why this exists rather than a bare `tokio::spawn`
///
/// The socket is a **file on the host**, and the pod that owns it dies. A task
/// spawned and forgotten leaves both the task and the socket file behind, and
/// the socket path is derived from the pod's vsock path — so a later pod
/// reusing that path would find a live listener still bound to the DEAD pod's
/// identity, and be served credentials as that pod. Owning the handle is what
/// makes the identity binding hold over time rather than only at start-up.
pub struct BrokerListener {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
    socket_path: std::path::PathBuf,
}

impl std::fmt::Debug for BrokerListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The identity is deliberately absent: this is logged on pod teardown,
        // and a socket path is enough to correlate.
        f.debug_struct("BrokerListener")
            .field("socket_path", &self.socket_path)
            .finish()
    }
}

impl BrokerListener {
    /// Bind the broker socket for one pod and start serving it.
    ///
    /// `identity` is bound here, once, for the listener's whole life — see
    /// [`serve_broker`].
    pub fn start(
        uds_path: &std::path::Path,
        port: u32,
        identity: PodIdentity,
        policy: Arc<PermissionLattice>,
        store: Arc<CredentialStore>,
    ) -> io::Result<Self> {
        let socket_path = broker_socket_path(uds_path, port);
        let listener = prepare_socket(&socket_path)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            serve_broker(listener, identity, policy, store, async {
                let _ = rx.await;
            })
            .await;
        });
        Ok(BrokerListener {
            shutdown: Some(tx),
            task,
            socket_path,
        })
    }

    /// Where the guest connects.
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// Stop serving and remove the socket.
    ///
    /// Returns whether the serving task stopped on its own. That is not
    /// bookkeeping: an [`ShutdownOutcome::Aborted`] means a connection outlived
    /// the signal, which is what a guest stalling teardown looks like, and it is
    /// worth a log line. It also makes the shutdown signal TESTABLE — an earlier
    /// version of this returned nothing, and the lifecycle test passed with the
    /// signal removed entirely, testing only the unlink while claiming more.
    ///
    /// Both halves matter. Stopping without unlinking leaves a path a later pod
    /// would refuse to bind; unlinking without stopping leaves a task holding a
    /// listener with no name, which is a leak rather than a hazard but still a
    /// leak. The task is aborted if it does not observe the shutdown signal,
    /// because teardown must not be able to hang on a connection that is being
    /// slow on purpose.
    pub async fn shutdown(mut self) -> ShutdownOutcome {
        // Dropping the sender resolves the receiver too, so shutdown is robust
        // to a path that forgets to send. Established by perturbation: replacing
        // the send with a drop changed nothing, and only `mem::forget` on the
        // sender made the lifecycle tests fail.
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        // The serving loop only checks for shutdown between accepts, so a
        // connection in flight can outlive the signal by up to CONNECTION_TIMEOUT.
        // Teardown does not wait that long for a guest that may be stalling
        // deliberately.
        let outcome = if tokio::time::timeout(Duration::from_secs(2), &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
            ShutdownOutcome::Aborted
        } else {
            ShutdownOutcome::Stopped
        };
        let _ = tokio::fs::remove_file(&self.socket_path).await;
        outcome
    }
}

pub async fn request_over_socket(path: &std::path::Path, frame: &str) -> io::Result<String> {
    let stream = UnixStream::connect(path).await?;
    let (r, mut w) = tokio::io::split(stream);
    w.write_all(frame.as_bytes()).await?;
    w.write_all(b"\n").await?;
    w.flush().await?;
    let mut line = String::new();
    let mut reader = BufReader::new(r);
    reader.read_line(&mut line).await?;
    Ok(line)
}

#[cfg(test)]
mod listener_lifecycle_tests {
    use super::*;
    use nucleus_cred_broker::Credential;

    fn policy() -> Arc<PermissionLattice> {
        Arc::new(PermissionLattice::default())
    }

    fn store(target: &str, value: &str) -> Arc<CredentialStore> {
        let mut s = CredentialStore::new();
        s.insert(target, Credential::new(value));
        Arc::new(s)
    }

    /// **The reason the handle is owned.** A pod dies and its socket path is
    /// reusable — Firecracker derives it from the pod's vsock path. If teardown
    /// left the listener running, a later pod binding that path would find a
    /// live listener still speaking for the DEAD pod, and be served credentials
    /// under the previous pod's identity.
    ///
    /// So: after shutdown the path is free, and a fresh listener there answers
    /// under the NEW identity. Without the unlink, the second `start` fails; with
    /// the unlink but no shutdown, the old task would still be holding it.
    #[tokio::test]
    async fn a_reused_socket_path_does_not_inherit_the_dead_pods_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let uds = dir.path().join("vsock.sock");

        let first = BrokerListener::start(
            &uds,
            9999,
            PodIdentity::observed_by_host("spiffe://nucleus/pod/dead"),
            policy(),
            store("api.example.test", "v"),
        )
        .expect("first listener binds");
        let path = first.socket_path().to_path_buf();
        assert!(path.exists(), "the socket should exist while serving");
        assert_eq!(
            first.shutdown().await,
            ShutdownOutcome::Stopped,
            "teardown must actually stop the serving task, not just unlink its socket"
        );
        assert!(
            !path.exists(),
            "teardown must remove the socket, or a later pod cannot bind it"
        );

        // The same path, a different pod. This is the case that must not reach
        // the previous listener.
        let second = BrokerListener::start(
            &uds,
            9999,
            PodIdentity::observed_by_host("spiffe://nucleus/pod/alive"),
            policy(),
            store("api.example.test", "v"),
        )
        .expect("a second listener must be able to bind the freed path");
        assert_eq!(second.socket_path(), path);
        assert_eq!(second.shutdown().await, ShutdownOutcome::Stopped);
    }

    /// The listener actually answers on the path it reports — a socket that
    /// exists but serves nothing would pass the test above while being useless.
    #[tokio::test]
    async fn the_listener_answers_on_the_path_it_reports() {
        let dir = tempfile::tempdir().expect("tempdir");
        let uds = dir.path().join("vsock.sock");
        let listener = BrokerListener::start(
            &uds,
            9998,
            PodIdentity::observed_by_host("spiffe://nucleus/pod/abc"),
            policy(),
            store("api.example.test", "v"),
        )
        .expect("binds");

        let frame = serde_json::json!({
            "operation": "WebFetch",
            "target": "api.example.test",
            "justification": "routine"
        })
        .to_string()
            + "\n";
        let reply = request_over_socket(listener.socket_path(), &frame)
            .await
            .expect("the listener must answer");
        assert!(
            reply.contains("granted"),
            "expected a broker reply, got {reply:?}"
        );
        assert_eq!(listener.shutdown().await, ShutdownOutcome::Stopped);
    }
}

#[cfg(test)]
mod listener_tests {
    use super::*;

    fn who() -> PodIdentity {
        PodIdentity::observed_by_host("spiffe://nucleus/pod/abc")
    }
    use nucleus_cred_broker::Credential;
    use std::os::unix::fs::PermissionsExt;

    fn store_with(target: &str, value: &str) -> CredentialStore {
        let mut s = CredentialStore::new();
        s.insert(target, Credential::new(value));
        s
    }

    /// **The socket must not be reachable by other local processes.** Linux
    /// honours AF_UNIX permissions, and a peer that can reach this socket can
    /// ask the broker for credentials.
    ///
    /// Enforced on the containing DIRECTORY, not the socket: a umask would be
    /// process-global and would briefly restrict every other file the node
    /// creates concurrently — which is not hypothetical, it broke three
    /// unrelated tests when it was tried.
    #[tokio::test]
    async fn the_socket_directory_denies_group_and_other() {
        let dir = tempfile::tempdir().unwrap();
        let sockdir = dir.path().join("broker");
        let path = sockdir.join("broker.sock");
        let _listener = prepare_socket(&path).expect("bind");

        let mode = std::fs::metadata(&sockdir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "group/other can traverse into the broker socket directory: {mode:o}"
        );
    }

    /// A stale socket from an unclean shutdown must not stop the node starting.
    #[tokio::test]
    async fn a_stale_socket_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.sock");
        let first = prepare_socket(&path).expect("first bind");
        drop(first); // simulate an unclean exit leaving the file behind
        assert!(path.exists(), "the stale socket should still be on disk");
        let _second = prepare_socket(&path).expect("a stale socket must not block startup");
    }

    /// …but a REAL FILE at that path is not deleted. A misconfigured path must
    /// not become a delete primitive.
    #[tokio::test]
    async fn a_regular_file_at_the_socket_path_is_not_unlinked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-socket");
        std::fs::write(&path, b"important").unwrap();
        assert!(prepare_socket(&path).is_err(), "must refuse, not unlink");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"important",
            "the file was destroyed"
        );
    }

    /// End to end over a real socket: a guest-shaped client gets a grant, and
    /// the credential never appears on the wire.
    #[tokio::test]
    async fn a_real_client_is_served_without_the_secret_crossing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.sock");
        let listener = prepare_socket(&path).expect("bind");

        let policy = Arc::new(PermissionLattice::permissive());
        let store = Arc::new(store_with("api.example.test", "super-secret-token"));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve_broker(listener, who(), policy, store, async {
            let _ = rx.await;
        }));

        let frame = serde_json::json!({
            "operation": "WebFetch",
            "target": "api.example.test",
            "justification": "routine"
        })
        .to_string();
        let reply = request_over_socket(&path, &frame).await.expect("served");

        assert!(reply.contains("\"granted\":true"), "reply: {reply}");
        assert!(
            !reply.contains("super-secret-token"),
            "the credential crossed the socket: {reply}"
        );

        let _ = tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }
}
