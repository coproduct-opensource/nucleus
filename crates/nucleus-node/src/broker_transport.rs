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

use nucleus_cred_broker::CredentialStore;
use portcullis::PermissionLattice;
#[cfg(test)]
use tokio::io::AsyncBufReadExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

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
pub async fn serve_connection<S>(stream: S, policy: &PermissionLattice, store: &CredentialStore)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    serve_connection_with_timeout(stream, policy, store, CONNECTION_TIMEOUT).await
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
    policy: &PermissionLattice,
    store: &CredentialStore,
    deadline: Duration,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);

    let read = tokio::time::timeout(deadline, read_frame_async(reader, MAX_FRAME_BYTES)).await;
    let response = match read {
        Ok(Ok(frame)) => crate::broker::handle_frame(&frame, policy, store),
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
        let serve = serve_connection(server, policy, store);
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
            "pod_identity": "spiffe://nucleus/pod/abc",
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
            serve_connection_with_timeout(server, &policy, &store, Duration::from_millis(200)),
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

        let serve = serve_connection(server, &policy, &store);
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
