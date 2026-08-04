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

// The blanket allow this replaced claimed "no accept loop binds this socket
// during pod spawn". That has not been true since `start_broker_for_pod` gained
// its call site, and a stale "not yet wired" comment is the most convincing kind
// of wrong — it reads as inside knowledge. Measured instead: with the allow
// removed, Linux clippy names exactly four dead items here, annotated per-item
// below. Everything else is live.
//
// NON-LINUX ONLY: the launch path is `cfg(target_os = "linux")`, so a macOS
// build compiles none of the serving side and would warn about all of it.
#![cfg_attr(all(not(test), not(target_os = "linux")), allow(dead_code))]

use std::io::BufRead;
use std::path::{Path, PathBuf};

use crate::envelope_frame::MAX_FRAME_BYTES;

/// The vsock port the guest connects to for credential brokering.
///
/// Distinct from the tool-proxy's control-plane port: that one is
/// host-initiated and carries host→guest requests, this one is guest-initiated
/// and carries envelopes the other way. Sharing a port would mix a trusted
/// direction with an untrusted one on the same listener.
// Dead on BOTH platforms: the port reaches the launch path as
// `state.broker_vsock_port`, a configured value, so the constant is the
// documented default rather than the thing that is read.
#[allow(dead_code)]
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
// Dead on BOTH platforms: the serving path is async and uses
// `read_frame_async`. This is the synchronous twin, kept because it is what
// the bound is specified and tested against.
#[allow(dead_code)]
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
#[allow(dead_code)] // as `read_frame_bounded`.
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

use std::sync::Arc;
use std::time::Duration;

use nucleus_cred_broker::{CredentialStore, PodIdentity};
use nucleus_spec::CredentialedEgressSpec;
use portcullis::PermissionLattice;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::broker_perform::{
    GuestAsk, IdempotencyLedger, PerformContext, UpstreamCall, UpstreamResponse,
    MAX_PERFORM_FRAME_BYTES,
};

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

/// Split a signed frame into its signature and the payload it covers.
///
/// Delegates to [`nucleus_cred_protocol::frame::split`]. The guest builds these
/// frames and the host reads them, so the format is defined once, in the crate
/// both sides link, rather than twice in crates that agree until one changes.
pub fn split_signed_frame(frame: &str) -> Option<(&str, &str)> {
    nucleus_cred_protocol::frame::split(frame)
}

/// Whether a frame was signed by the holder of this pod's broker capability.
///
/// # One implementation, not two that agree
///
/// This was a local HMAC verification, and the guest client was going to grow a
/// local HMAC signing to match it. Two implementations of one format, in
/// different crates, each testable in isolation and each passing — which is the
/// exact shape of the defect that made the capability inert one increment ago.
/// Both sides now call [`nucleus_cred_protocol::frame`], where `sign` and
/// `is_authentic` are pinned to each other by a round-trip test.
///
/// The properties are unchanged and are documented at the definition: `None`
/// accepts NOTHING (the fail-open reading turns a provisioning failure into an
/// open door), and verification is constant-time (a byte-by-byte compare leaks
/// how much of a guessed signature was right, and a guest can retry freely).
#[must_use]
pub fn frame_is_authentic(frame: &str, secret: Option<&[u8]>) -> bool {
    nucleus_cred_protocol::frame::is_authentic(frame, secret)
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
pub async fn serve_connection<S>(stream: S, serving: &BrokerServing<'_>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    serve_connection_with_timeout(stream, serving, CONNECTION_TIMEOUT).await
}

/// Serialise a reply, falling back to a REFUSAL.
///
/// Serialising these structs cannot realistically fail, but the fallback still
/// matters: the only wrong answer here is a permissive one, so an encoder error
/// must not be able to produce a grant.
fn encode<T: serde::Serialize>(reply: &T) -> String {
    serde_json::to_string(reply).unwrap_or_else(|_| refusal_line("internal error"))
}

/// A refusal on the wire, in the shape both reply types share.
///
/// `granted` and `reason` are the fields `BrokerResponse` and `PerformReply`
/// have in common, and `PerformReply`'s `status` and `body` both `#[serde(default)]`,
/// so one refusal shape is readable as either. A guest knows which it asked for.
fn refusal_line(reason: &str) -> String {
    serde_json::json!({ "granted": false, "reason": reason }).to_string()
}

/// How the host actually makes an outbound call for a guest.
///
/// Injected rather than hard-wired so the serving path is testable without a
/// network — the same reason `serve_connection` is generic over its stream. A
/// broker test that had to reach a real host would be a test people learn to
/// re-run rather than read.
pub type UpstreamCaller = Arc<
    dyn Fn(
            UpstreamCall,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<UpstreamResponse, String>> + Send>,
        > + Send
        + Sync,
>;

/// What an operator configured for one pod, before the listener exists.
///
/// Distinct from [`PodBroker`], which is what the SERVING task holds: this has no
/// caller, because `start` decides that (and refuses to perform at all when no
/// crypto provider is installed). Grouping is not only clippy's argument count —
/// every field is per-pod, and a listener assembled from a mixture of two pods'
/// values is the failure this arc has already produced once.
pub struct PodBrokerConfig {
    /// Bound at the listener, never read from a frame.
    pub identity: PodIdentity,
    /// This pod's policy.
    pub policy: Arc<PermissionLattice>,
    /// This pod's credentials, from the node's environment.
    pub store: Arc<CredentialStore>,
    /// The upstreams the operator configured.
    pub upstreams: Arc<Vec<CredentialedEgressSpec>>,
    /// The capability the guest is served and this listener verifies.
    pub broker_secret: Arc<Vec<u8>>,
}

/// One pod's broker, owned, as the listener task needs it.
///
/// The borrowed [`BrokerServing`] is what a single connection is decided
/// against; this is the same set held across the listener's whole life. Two
/// types rather than one lifetime-parametrised type held in an `Arc`, because
/// the ownership difference is real: the identity is fixed when the socket is
/// bound and the ledger must outlive every connection served on it.
pub struct PodBroker {
    /// Bound at the listener, never read from a frame.
    pub identity: PodIdentity,
    /// This pod's policy.
    pub policy: Arc<PermissionLattice>,
    /// This pod's credentials.
    pub store: Arc<CredentialStore>,
    /// This pod's capability. `None` refuses every frame.
    pub broker_secret: Option<Arc<Vec<u8>>>,
    /// The upstreams the operator configured for this pod.
    pub upstreams: Arc<Vec<CredentialedEgressSpec>>,
    /// How to make an outbound call.
    pub caller: UpstreamCaller,
}

/// Everything the host needs to serve one pod, and nothing global.
///
/// A struct because the parameter list crossed clippy's threshold, and kept a
/// struct because every field is per-pod: the identity is bound to the listener,
/// the policy and credentials are this pod's, and the ledger is this pod's
/// memory of what it has already been asked to do. Nothing here is shared
/// between pods, which is the property that keeps this from becoming the
/// credential-concentrating gateway `CredentialedEgressSpec` warns about.
pub struct BrokerServing<'a> {
    /// Who is calling, from which socket accepted — never from the frame.
    pub identity: &'a PodIdentity,
    /// This pod's policy.
    pub policy: &'a PermissionLattice,
    /// This pod's credentials.
    pub store: &'a CredentialStore,
    /// This pod's capability. `None` refuses every frame.
    pub broker_secret: Option<&'a [u8]>,
    /// The upstreams this pod may reach, by name, with their bases fixed.
    pub upstreams: &'a [CredentialedEgressSpec],
    /// This pod's idempotency memory.
    pub ledger: &'a IdempotencyLedger,
    /// How to make the call.
    pub upstream_caller: UpstreamCaller,
}

/// A caller that cannot call, for a host with no usable HTTP client.
///
/// Refusing is the only honest answer: a broker that cannot reach an upstream
/// must not report a grant, and the alternative — refusing to start the listener
/// at all — would also take away the QUERY path, which needs no client.
#[must_use]
pub fn refusing_caller() -> UpstreamCaller {
    Arc::new(|_call: UpstreamCall| {
        Box::pin(std::future::ready(Err("no upstream client".to_string())))
    })
}

/// The production caller: a real request through a shared client.
///
/// Everything about *where* this goes was decided before it got here —
/// `handle_perform` built the URL from the pod spec's fixed base and refused a
/// path that tried to leave it. This function makes no decisions; giving it any
/// would put a policy choice below the layer that holds the credential.
#[must_use]
pub fn http_caller(client: reqwest::Client) -> UpstreamCaller {
    Arc::new(move |call: UpstreamCall| {
        let client = client.clone();
        Box::pin(async move {
            let resp = client
                .post(&call.url)
                .header(&call.header_name, &call.header_value)
                .header("content-type", "application/json")
                .body(call.body)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let body = resp.bytes().await.map_err(|e| e.to_string())?.to_vec();
            Ok(UpstreamResponse { status, body })
        })
    })
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
    serving: &BrokerServing<'_>,
    deadline: Duration,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);

    // The larger bound, because a perform frame carries a request body. A frame
    // that turns out to be a QUERY is still held to the original 8 KiB by
    // `classify` — adding perform must not quietly relax the envelope's bound.
    let read =
        tokio::time::timeout(deadline, read_frame_async(reader, MAX_PERFORM_FRAME_BYTES)).await;
    let line = match read {
        // An unsigned or wrongly-signed frame gets the SAME refusal a malformed
        // one does, deliberately. The capability exists to tell the mediating
        // proxy from every other process in the guest; a distinct reason would
        // tell a workload whether it holds it, which is precisely the fact it
        // is trying to learn.
        Ok(Ok(ref frame)) if !frame_is_authentic(frame, serving.broker_secret) => {
            // "not permitted" — the SAME reason a policy denial gives, not
            // "malformed request". The capability exists to tell the mediating
            // proxy from every other process in the guest, so a caller must not
            // be able to distinguish "I lack the capability" from "I have it and
            // policy said no". A distinct reason would answer exactly the
            // question a workload probing this socket is asking.
            refusal_line("not permitted")
        }
        Ok(Ok(frame)) => {
            // Authentic: decide against the PAYLOAD, not the signed wrapper.
            let frame = split_signed_frame(&frame)
                .map(|(_, payload)| payload.to_string())
                .unwrap_or(frame);
            // Read once, here, rather than inside the decision functions: those
            // take the instant as a parameter so they are testable without a
            // clock, and so a single request is judged against ONE instant
            // rather than against whatever the clock said at each step.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            // A query and a request to ACT are different asks and cannot be
            // confused for one another — see `GuestAsk`, where the property is
            // held by the types rather than by the order tried here.
            match crate::broker_perform::classify(&frame) {
                Ok(GuestAsk::Query(envelope)) => encode(&crate::broker::decide_envelope(
                    &envelope,
                    serving.identity,
                    serving.policy,
                    serving.store,
                    now,
                )),
                Ok(GuestAsk::Perform(request)) => {
                    let ctx = PerformContext {
                        identity: serving.identity,
                        policy: serving.policy,
                        store: serving.store,
                        upstreams: serving.upstreams,
                        ledger: serving.ledger,
                    };
                    let caller = Arc::clone(&serving.upstream_caller);
                    encode(
                        &crate::broker_perform::handle_perform(&request, &ctx, now, move |c| {
                            caller(c)
                        })
                        .await,
                    )
                }
                Err(_) => refusal_line("malformed request"),
            }
        }
        // A read failure and a TIMEOUT are answered with the SAME coarse refusal
        // a policy denial gets. Distinguishing "you sent garbage" from "you were
        // too slow" from "you were denied" would hand the guest a probe it does
        // not otherwise have.
        Ok(Err(_)) | Err(_) => refusal_line("malformed request"),
    };

    let mut line = line;
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

    /// The capability these tests speak with. Real pods get a minted one.
    const TEST_SECRET: &[u8] = b"test-broker-capability";

    /// Sign a payload the way the tool-proxy will: `<hex-hmac> <payload>`.
    fn sign(payload: &str, secret: &[u8]) -> String {
        use hmac::{digest::KeyInit, Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
        mac.update(payload.as_bytes());
        format!("{} {payload}\n", hex::encode(mac.finalize().into_bytes()))
    }

    /// Send a SIGNED request. Every pre-existing test here sent an unsigned one
    /// and is now routed through this, which is the point: unsigned frames are
    /// refused, so a test that still passed unsigned would be asserting the
    /// refusal path while claiming to assert the grant path.
    async fn round_trip(
        request: &str,
        policy: &PermissionLattice,
        store: &CredentialStore,
    ) -> String {
        round_trip_raw(&sign(request.trim_end(), TEST_SECRET), policy, store).await
    }

    /// The upstreams a test pod may reach. Empty unless a test says otherwise:
    /// a perform request naming an upstream nobody configured is refused, which
    /// is the correct default for every test that is not about perform.
    fn no_upstreams() -> Vec<CredentialedEgressSpec> {
        Vec::new()
    }

    /// An upstream caller that records what it was asked to do and never
    /// touches a network. A broker test that reached a real host would be a
    /// test people learn to re-run rather than read.
    pub(super) fn recording_caller() -> (UpstreamCaller, Arc<std::sync::Mutex<Vec<UpstreamCall>>>) {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let caller: UpstreamCaller = Arc::new(move |c: UpstreamCall| {
            sink.lock().expect("not poisoned").push(c);
            Box::pin(std::future::ready(Ok(UpstreamResponse {
                status: 200,
                body: b"{\"ok\":true}".to_vec(),
            })))
        });
        (caller, seen)
    }

    /// The serving context these tests speak to, assembled in one place so a
    /// new field cannot be quietly defaulted at four call sites.
    fn serving<'a>(
        identity: &'a PodIdentity,
        policy: &'a PermissionLattice,
        store: &'a CredentialStore,
        secret: Option<&'a [u8]>,
        upstreams: &'a [CredentialedEgressSpec],
        ledger: &'a IdempotencyLedger,
        caller: UpstreamCaller,
    ) -> BrokerServing<'a> {
        BrokerServing {
            identity,
            policy,
            store,
            broker_secret: secret,
            upstreams,
            ledger,
            upstream_caller: caller,
        }
    }

    /// Send bytes verbatim, signed or not.
    async fn round_trip_raw(
        request: &str,
        policy: &PermissionLattice,
        store: &CredentialStore,
    ) -> String {
        let (client, server) = tokio::io::duplex(512 * 1024);
        let id = who();
        let ups = no_upstreams();
        let ledger = IdempotencyLedger::new();
        let (caller, _seen) = recording_caller();
        let ctx = serving(&id, policy, store, Some(TEST_SECRET), &ups, &ledger, caller);
        let serve = serve_connection(server, &ctx);
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

    /// Send a frame to a broker that HAS an upstream configured, and report both
    /// the reply and what the host actually tried to call.
    ///
    /// Separate from `round_trip_raw` because the interesting assertion for a
    /// perform request is not only what came back — it is whether an upstream
    /// call happened at all. A refusal that still made the call is not a
    /// refusal.
    async fn perform_round_trip(
        frame: &str,
        policy: &PermissionLattice,
        store: &CredentialStore,
        upstreams: &[CredentialedEgressSpec],
        secret: Option<&[u8]>,
    ) -> (String, Vec<UpstreamCall>) {
        let (client, server) = tokio::io::duplex(512 * 1024);
        let id = who();
        let ledger = IdempotencyLedger::new();
        let (caller, seen) = recording_caller();
        let ctx = serving(&id, policy, store, secret, upstreams, &ledger, caller);
        let serve = serve_connection(server, &ctx);
        let talk = async {
            let (r, mut w) = tokio::io::split(client);
            w.write_all(frame.as_bytes()).await.unwrap();
            w.flush().await.unwrap();
            let mut line = String::new();
            BufReader::new(r).read_line(&mut line).await.unwrap();
            line
        };
        let (_, reply) = tokio::join!(serve, talk);
        let calls = seen.lock().expect("not poisoned").clone();
        (reply, calls)
    }

    fn test_upstream() -> CredentialedEgressSpec {
        CredentialedEgressSpec {
            name: "model-api".into(),
            upstream: "https://upstream.invalid/v1".into(),
            credential_env: "NUCLEUS_TEST_TRANSPORT_CRED".into(),
            header: "authorization".into(),
            value_prefix: "Bearer ".into(),
        }
    }

    fn perform_frame(path: &str) -> String {
        serde_json::json!({
            "operation": "WebFetch",
            "target": "model-api",
            "justification": "routine",
            "idempotency_key": "key-1",
            "path": path,
            "body": b"{\"prompt\":\"hi\"}".to_vec(),
        })
        .to_string()
    }

    /// **The perform path reaches the upstream through the socket.** The
    /// non-vacuity control for the perform tests below, which all assert that
    /// nothing was called.
    #[tokio::test]
    async fn a_signed_perform_request_is_dispatched_to_the_upstream() {
        let policy = PermissionLattice::permissive();
        let mut store = CredentialStore::new();
        store.insert("model-api", Credential::new("upstream-token"));
        let ups = vec![test_upstream()];

        let (reply, calls) = perform_round_trip(
            &sign(&perform_frame("/messages"), TEST_SECRET),
            &policy,
            &store,
            &ups,
            Some(TEST_SECRET),
        )
        .await;

        assert!(reply.contains("\"granted\":true"), "reply: {reply}");
        assert!(reply.contains("\"status\":200"), "reply: {reply}");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].url, "https://upstream.invalid/v1/messages");
        assert!(
            !reply.contains("upstream-token"),
            "the credential crossed the socket: {reply}"
        );
    }

    /// **The capability covers perform, not just queries.** Step 2 exists so
    /// only the mediating proxy can reach the broker; a new frame type that
    /// slipped past the signature check would reopen exactly that hole, and for
    /// the frame type that has an EFFECT.
    #[tokio::test]
    async fn an_unsigned_perform_request_is_refused_without_calling_anything() {
        let policy = PermissionLattice::permissive();
        let mut store = CredentialStore::new();
        store.insert("model-api", Credential::new("upstream-token"));
        let ups = vec![test_upstream()];

        let (reply, calls) = perform_round_trip(
            &format!("{}\n", perform_frame("/messages")),
            &policy,
            &store,
            &ups,
            Some(TEST_SECRET),
        )
        .await;

        assert!(reply.contains("\"granted\":false"), "reply: {reply}");
        assert!(
            calls.is_empty(),
            "an unsigned perform request reached the upstream anyway"
        );
    }

    /// A hostile path is refused at the host, over the real serving path — the
    /// unit test covers `handle_perform`, this covers that the frame actually
    /// gets there.
    #[tokio::test]
    async fn a_perform_request_cannot_redirect_the_upstream_over_the_socket() {
        let policy = PermissionLattice::permissive();
        let mut store = CredentialStore::new();
        store.insert("model-api", Credential::new("upstream-token"));
        let ups = vec![test_upstream()];

        let (reply, calls) = perform_round_trip(
            &sign(
                &perform_frame("https://attacker.invalid/steal"),
                TEST_SECRET,
            ),
            &policy,
            &store,
            &ups,
            Some(TEST_SECRET),
        )
        .await;

        assert!(reply.contains("\"granted\":false"), "reply: {reply}");
        assert!(calls.is_empty(), "the host called the guest's URL");
    }

    /// A pod whose operator configured no upstreams cannot perform anything —
    /// the ordinary case today, and it must be a refusal rather than a default.
    #[tokio::test]
    async fn a_pod_with_no_upstreams_refuses_every_perform_request() {
        let policy = PermissionLattice::permissive();
        let mut store = CredentialStore::new();
        store.insert("model-api", Credential::new("upstream-token"));

        let (reply, calls) = perform_round_trip(
            &sign(&perform_frame("/messages"), TEST_SECRET),
            &policy,
            &store,
            &no_upstreams(),
            Some(TEST_SECRET),
        )
        .await;

        assert!(reply.contains("\"granted\":false"), "reply: {reply}");
        assert!(calls.is_empty());
    }

    /// **The non-vacuity control, and it must come first.** Everything below
    /// asserts that some frame is REFUSED. A broker that refused every frame
    /// would pass all of them while being completely broken, so the first thing
    /// to establish is that a correctly-signed request is still served.
    #[tokio::test]
    async fn a_correctly_signed_request_is_still_served() {
        let policy = PermissionLattice::permissive();
        let store = store_with("api.example.test", "s3cret");
        let reply = round_trip(
            &serde_json::json!({
                "operation": "WebFetch",
                "target": "api.example.test",
                "justification": "routine"
            })
            .to_string(),
            &policy,
            &store,
        )
        .await;
        assert!(reply.contains("\"granted\":true"), "got {reply}");
    }

    /// **A host with no capability provisioned accepts NOTHING.**
    ///
    /// This is the fail-open case, and it was untested until a perturbation
    /// (`return true` when the secret is `None`) passed the entire suite. Absent
    /// a secret the host cannot authenticate anyone, so treating that as "no
    /// signature required" would turn a provisioning failure into an open door —
    /// and provisioning failures are exactly when nobody is watching.
    #[tokio::test]
    async fn with_no_capability_provisioned_even_a_signed_frame_is_refused() {
        let policy = PermissionLattice::permissive();
        let store = store_with("api.example.test", "s3cret");
        let payload = serde_json::json!({
            "operation": "WebFetch",
            "target": "api.example.test",
            "justification": "routine"
        })
        .to_string();

        let (client, server) = tokio::io::duplex(64 * 1024);
        let id = who();
        // No secret: nothing can be authentic, however well-formed.
        let ups = no_upstreams();
        let ledger = IdempotencyLedger::new();
        let (caller, _seen) = recording_caller();
        let ctx = serving(&id, &policy, &store, None, &ups, &ledger, caller);
        let serve = serve_connection(server, &ctx);
        let signed = sign(&payload, TEST_SECRET);
        let talk = async {
            let (r, mut w) = tokio::io::split(client);
            w.write_all(signed.as_bytes()).await.unwrap();
            w.flush().await.unwrap();
            let mut line = String::new();
            BufReader::new(r).read_line(&mut line).await.unwrap();
            line
        };
        let (_, reply) = tokio::join!(serve, talk);
        assert!(
            reply.contains("\"granted\":false"),
            "a host that cannot authenticate must accept nothing: {reply}"
        );
    }

    /// **An unsigned frame is refused.** This is the bypass being closed: any
    /// guest process can open AF_VSOCK, so reaching the socket cannot itself be
    /// the authorisation.
    #[tokio::test]
    async fn an_unsigned_frame_is_refused() {
        let policy = PermissionLattice::permissive();
        let store = store_with("api.example.test", "s3cret");
        let raw = serde_json::json!({
            "operation": "WebFetch",
            "target": "api.example.test",
            "justification": "routine"
        })
        .to_string()
            + "\n";
        let reply = round_trip_raw(&raw, &policy, &store).await;
        assert!(
            reply.contains("\"granted\":false"),
            "an unsigned frame must not be granted: {reply}"
        );
    }

    /// A frame signed with the wrong key is refused too — otherwise "signed"
    /// would mean "has something in the signature position".
    #[tokio::test]
    async fn a_wrongly_signed_frame_is_refused() {
        let policy = PermissionLattice::permissive();
        let store = store_with("api.example.test", "s3cret");
        let payload = serde_json::json!({
            "operation": "WebFetch",
            "target": "api.example.test",
            "justification": "routine"
        })
        .to_string();
        let reply = round_trip_raw(&sign(&payload, b"not-the-capability"), &policy, &store).await;
        assert!(reply.contains("\"granted\":false"), "got {reply}");
    }

    /// **The refusal must be indistinguishable from a policy denial.** The
    /// capability exists to tell the mediating proxy from every other process in
    /// the guest; a distinct reason would tell a workload whether it holds one,
    /// which is exactly the fact it is trying to learn.
    #[tokio::test]
    async fn an_authentication_refusal_looks_like_every_other_refusal() {
        let store = store_with("api.example.test", "s3cret");
        let payload = serde_json::json!({
            "operation": "WebFetch",
            "target": "api.example.test",
            "justification": "routine"
        })
        .to_string();

        let unsigned = round_trip_raw(
            &(payload.clone() + "\n"),
            &PermissionLattice::permissive(),
            &store,
        )
        .await;
        // A signed request the POLICY refuses. `default()` is not restrictive
        // enough — it granted, which this test caught.
        let mut deny = PermissionLattice::permissive();
        deny.capabilities.web_fetch = portcullis::CapabilityLevel::Never;
        let denied = round_trip(&payload, &deny, &store).await;
        assert!(
            denied.contains("\"granted\":false"),
            "the fixture must actually deny, or the comparison below is vacuous: {denied}"
        );

        let reason = |s: &str| {
            serde_json::from_str::<serde_json::Value>(s.trim())
                .ok()
                .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(str::to_string))
                .unwrap_or_default()
        };
        assert_eq!(
            reason(&unsigned),
            reason(&denied),
            "an unauthenticated caller must not be able to tell itself apart from an \
             unauthorised one"
        );
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
                &serving(
                    &who(),
                    &policy,
                    &store,
                    Some(TEST_SECRET),
                    &no_upstreams(),
                    &IdempotencyLedger::new(),
                    recording_caller().0,
                ),
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
        // Sized against the bound the READER actually applies, which is now the
        // perform bound. This said `MAX_FRAME_BYTES * 4` and would have kept
        // passing — 32 KiB is comfortably under 256 KiB, so the flood would have
        // been read to EOF and refused as malformed instead of being cut off at
        // the ceiling. Green, and testing something else. Assert the premise so
        // the next bound change cannot repeat it.
        const _: () = assert!(
            MAX_FRAME_BYTES * 4 < MAX_PERFORM_FRAME_BYTES,
            "the old fixture was under the read bound — that is why it moved"
        );
        let flood = "x".repeat(MAX_PERFORM_FRAME_BYTES * 2); // no newline, ever
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (r, mut w) = tokio::io::split(client);

        let id = who();
        let ups = no_upstreams();
        let ledger = IdempotencyLedger::new();
        let (caller, _seen) = recording_caller();
        let ctx = serving(
            &id,
            &policy,
            &store,
            Some(TEST_SECRET),
            &ups,
            &ledger,
            caller,
        );
        let serve = serve_connection(server, &ctx);
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
    // NEVER near the container runtime's own socket. A broker socket lives in a
    // per-pod directory; a path under a runtime socket directory means somebody
    // has confused "the socket the guest asks through" with "the socket that
    // controls the host". Mounting the Docker daemon socket into an agent
    // sandbox is the canonical escape — it hands the guest the ability to launch
    // privileged containers and mount the host filesystem — and the guard is
    // cheap enough that it costs nothing to refuse the shape outright.
    let as_str = path.to_string_lossy();
    for forbidden in ["docker.sock", "containerd.sock", "podman.sock", "crio.sock"] {
        if as_str.contains(forbidden) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "refusing to bind a broker socket at {as_str}: the path names a container \
                     runtime socket, and a guest that could reach one would control the host"
                ),
            ));
        }
    }

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
/// `broker_secret` is this pod's capability; `None` refuses every frame, because
/// a host that cannot authenticate must not accept. See `frame_is_authentic`.
///
/// Runs until `shutdown` resolves.
pub async fn serve_broker(
    listener: UnixListener,
    pod: PodBroker,
    shutdown: impl std::future::Future<Output = ()>,
) {
    let PodBroker {
        identity,
        policy,
        store,
        broker_secret,
        upstreams,
        caller,
    } = pod;
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    // One ledger for the LIFETIME OF THE LISTENER, which is the lifetime of the
    // pod. Per-connection would remember nothing — the connection ends with the
    // reply — so every retry would be a fresh call and the idempotency key would
    // be decoration.
    let ledger = Arc::new(IdempotencyLedger::new());
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
                        let broker_secret = broker_secret.clone();
                        let upstreams = Arc::clone(&upstreams);
                        let ledger = Arc::clone(&ledger);
                        let caller = Arc::clone(&caller);
                        tokio::spawn(async move {
                            serve_connection(
                                stream,
                                &BrokerServing {
                                    identity: &identity,
                                    policy: &policy,
                                    store: &store,
                                    broker_secret: broker_secret
                                        .as_deref()
                                        .map(|v| v.as_slice()),
                                    upstreams: &upstreams,
                                    ledger: &ledger,
                                    upstream_caller: caller,
                                },
                            )
                            .await;
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
        pod: PodBrokerConfig,
        jail_owner: Option<(u32, u32)>,
    ) -> io::Result<Self> {
        let PodBrokerConfig {
            identity,
            policy,
            store,
            upstreams,
            broker_secret,
        } = pod;
        let socket_path = broker_socket_path(uds_path, port);
        let listener = prepare_socket(&socket_path)?;
        // Without this the node binds, logs "started credential broker at …",
        // passes every launch check, and no jailed guest can ever connect: the
        // socket lands root-owned and `connect()` needs write permission on it.
        // The workload API socket in this same directory has always done this;
        // this one did not. See `guest_socket` for the post-mortem.
        crate::guest_socket::give_socket_to_jail(&socket_path, jail_owner)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        // One client for the pod's lifetime, so connections to the upstream are
        // pooled rather than rebuilt per request. Its TLS trust is the HOST's,
        // which is the point: the guest has no say in what the host will accept.
        //
        // The PRECONDITION is checked, not the failure — because there is no
        // failure to catch. Under this workspace's `rustls-no-provider` pin both
        // `Client::new()` and `Client::builder().build()` PANIC when no crypto
        // provider has been installed; `build()` returning `Result` makes it
        // look fallible and it is not.
        //
        // `main` installs a provider at start-up, so production is fine today.
        // That made every pod launch depend on an ordering nothing states, with
        // a panicked node as the failure mode. Two listener tests found it by
        // calling `start` without going through `main` — and the first fix,
        // matching on `build()`'s `Result`, changed nothing at all.
        let caller = if rustls::crypto::CryptoProvider::get_default().is_some() {
            http_caller(reqwest::Client::new())
        } else {
            tracing::warn!(
                "credential broker cannot make outbound calls: no rustls crypto provider is \
                 installed. Requests to PERFORM a call will be refused; queries are unaffected."
            );
            refusing_caller()
        };
        let task = tokio::spawn(async move {
            serve_broker(
                listener,
                PodBroker {
                    identity,
                    policy,
                    store,
                    // NOT `None`. This used to be `None` while the workload
                    // API served the guest a freshly minted secret, so the
                    // guest held a capability the verifier had never seen and
                    // every signed frame was refused. Both halves now come from
                    // one `BrokerCapability`.
                    broker_secret: Some(broker_secret),
                    upstreams,
                    caller,
                },
                async {
                    let _ = rx.await;
                },
            )
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

/// Connect to the broker as a guest would, for tests and diagnostics.
//
// Dead on BOTH platforms in production: the real client is the in-guest
// tool-proxy, which speaks over vsock. Kept because the listener tests need a
// guest-shaped caller and a test-only reimplementation would be a second
// client to keep in step with the wire format.
#[allow(dead_code)]
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

    /// These tests are about socket lifecycle, not authentication, so the value
    /// is arbitrary — but it must not be absent. `start` takes the capability
    /// now precisely because passing `None` there is what made the guest's
    /// fetched secret useless.
    const TEST_SECRET: &[u8] = b"lifecycle-test-capability";

    fn policy() -> Arc<PermissionLattice> {
        Arc::new(PermissionLattice::default())
    }

    fn store(target: &str, value: &str) -> Arc<CredentialStore> {
        let mut s = CredentialStore::new();
        s.insert(target, Credential::new(value));
        Arc::new(s)
    }

    /// **Never the runtime's own socket.** A guest that could reach the Docker
    /// daemon socket controls the host — it can launch privileged containers and
    /// mount the host filesystem. The broker socket is bind-mounted into a
    /// sandbox, so the one path shape that must never be accepted is one naming
    /// a runtime socket.
    #[tokio::test]
    async fn a_runtime_socket_path_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        for name in ["docker.sock", "containerd.sock", "podman.sock", "crio.sock"] {
            let path = dir.path().join(name);
            let err = prepare_socket(&path)
                .expect_err("a broker socket must never be bound at a runtime socket path");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{name}");
        }
        // Non-vacuity: an ordinary path in the same directory binds fine, so the
        // refusal is about the name and not about the directory.
        let ok = prepare_socket(&dir.path().join("broker.sock"))
            .expect("an ordinary broker socket path must still bind");
        drop(ok);
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
            PodBrokerConfig {
                identity: PodIdentity::observed_by_host("spiffe://nucleus/pod/dead"),
                policy: policy(),
                store: store("api.example.test", "v"),
                upstreams: Arc::new(Vec::new()),
                broker_secret: Arc::new(TEST_SECRET.to_vec()),
            },
            None,
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
            PodBrokerConfig {
                identity: PodIdentity::observed_by_host("spiffe://nucleus/pod/alive"),
                policy: policy(),
                store: store("api.example.test", "v"),
                upstreams: Arc::new(Vec::new()),
                broker_secret: Arc::new(TEST_SECRET.to_vec()),
            },
            None,
        )
        .expect("a second listener must be able to bind the freed path");
        assert_eq!(second.socket_path(), path);
        assert_eq!(second.shutdown().await, ShutdownOutcome::Stopped);
    }

    /// The listener answers on the path it reports **and honours the capability
    /// it was handed**.
    ///
    /// # What this test used to assert, and why that was nothing
    ///
    /// It sent an UNSIGNED frame and asserted `reply.contains("granted")` —
    /// which `"granted":false` satisfies. So it passed whether the listener used
    /// its capability or refused every frame on earth. A perturbation restoring
    /// `broker_secret: None` in `start` — the original defect, where the guest
    /// held a secret the verifier had never seen — left all 275 tests green.
    ///
    /// It now signs under the capability `start` was given and requires
    /// `"granted":true`. That is only reachable if the value survives the trip
    /// from `start` into `PodBroker` into `frame_is_authentic`.
    #[tokio::test]
    async fn the_listener_answers_on_the_path_it_reports() {
        let dir = tempfile::tempdir().expect("tempdir");
        let uds = dir.path().join("vsock.sock");
        let listener = BrokerListener::start(
            &uds,
            9998,
            PodBrokerConfig {
                identity: PodIdentity::observed_by_host("spiffe://nucleus/pod/abc"),
                policy: policy(),
                store: store("api.example.test", "v"),
                upstreams: Arc::new(Vec::new()),
                broker_secret: Arc::new(TEST_SECRET.to_vec()),
            },
            None,
        )
        .expect("binds");

        let payload = serde_json::json!({
            "operation": "WebFetch",
            "target": "api.example.test",
            "justification": "routine"
        })
        .to_string();
        // Signed under the SAME capability `start` was handed above.
        let frame = {
            use hmac::{digest::KeyInit, Hmac, Mac};
            use sha2::Sha256;
            let mut mac = Hmac::<Sha256>::new_from_slice(TEST_SECRET).expect("hmac key");
            mac.update(payload.as_bytes());
            format!("{} {payload}\n", hex::encode(mac.finalize().into_bytes()))
        };
        let reply = request_over_socket(listener.socket_path(), &frame)
            .await
            .expect("the listener must answer");
        assert!(
            reply.contains("\"granted\":true"),
            "a frame signed under the capability `start` was given must be SERVED. Got \
             {reply:?} — if this is a refusal, the listener is not using the capability it \
             was handed, and the guest holds a secret the verifier has never seen."
        );
        assert_eq!(listener.shutdown().await, ShutdownOutcome::Stopped);
    }
}

#[cfg(test)]
mod listener_tests {
    use super::*;

    /// Same capability the serving tests use; a real pod gets a minted one.
    const TEST_SECRET: &[u8] = b"test-broker-capability";

    /// Sign as the tool-proxy will: `<hex-hmac> <payload>`.
    fn sign(payload: &str) -> String {
        use hmac::{digest::KeyInit, Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(TEST_SECRET).expect("hmac key");
        mac.update(payload.as_bytes());
        format!("{} {payload}", hex::encode(mac.finalize().into_bytes()))
    }

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
        let (caller, _seen) = serving_tests::recording_caller();
        let server = tokio::spawn(serve_broker(
            listener,
            PodBroker {
                identity: who(),
                policy,
                store,
                broker_secret: Some(std::sync::Arc::new(TEST_SECRET.to_vec())),
                upstreams: Arc::new(Vec::new()),
                caller,
            },
            async {
                let _ = rx.await;
            },
        ));

        let frame = serde_json::json!({
            "operation": "WebFetch",
            "target": "api.example.test",
            "justification": "routine"
        })
        .to_string();
        let reply = request_over_socket(&path, &sign(&frame))
            .await
            .expect("served");

        assert!(reply.contains("\"granted\":true"), "reply: {reply}");
        assert!(
            !reply.contains("super-secret-token"),
            "the credential crossed the socket: {reply}"
        );

        let _ = tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }
}
