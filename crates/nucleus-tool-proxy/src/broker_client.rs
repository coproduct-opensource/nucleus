//! The guest's side of the credential broker.
//!
//! # What this replaces
//!
//! Today the tool-proxy reads credential values out of its own `PodSpec`, which
//! means those values are inside the guest — in a file the agent can read. The
//! broker exists so the values stay host-side and the guest asks for an action
//! instead of a secret.
//!
//! This is the asking half. It sends a
//! [`TaskRequestEnvelope`](nucleus_cred_protocol::TaskRequestEnvelope) over
//! vsock to the host and reads back an outcome. **It never receives a
//! credential**, and cannot: `Credential` (which lives in the host-only broker crate this one deliberately
//! does not link) has no
//! `Serialize` impl, so the host's response type could not carry one even if
//! someone tried.
//!
//! # Failure is a refusal, never a fallback
//!
//! Every failure — no socket, connection refused, timeout, malformed reply —
//! resolves to "not granted". The tempting alternative is to fall back to
//! reading the credential from the spec when the broker is unreachable, which
//! would make the broker advisory: an attacker who could break the connection
//! would restore the old exposure. A broker that can be bypassed by breaking it
//! is not a boundary.
//!
//! # On retries and idempotency
//!
//! Agents retry, and a timeout can hide a completed side effect. That matters
//! enormously for a broker that *performs actions*, where a duplicate retry is a
//! duplicate action — the standard answer is an idempotency key the server
//! remembers.
//!
//! This request carries none, deliberately, because it is currently a **query**:
//! "may I, and is a credential available". Asking twice changes nothing. The
//! moment the broker gains a `perform` operation, that stops being true and an
//! idempotency key becomes mandatory — recorded here so it is a decision rather
//! than an omission.
//!
//! **That moment has arrived, and the promise was kept.** The broker performs
//! calls now: `nucleus_cred_protocol::PerformRequest` carries a mandatory
//! `idempotency_key` (a `String`, not an `Option` — an optional key is a
//! suggestion), and the host claims it *before* the call rather than recording
//! it after, so two frames carrying one key cannot both reach the upstream.
//!
//! `perform_line` builds them here, and the obligation is no longer prose: it
//! takes an `Authority`, which is constructible only from a `DischargedBundle`,
//! which only `preflight_action` can mint. Spending it also RECORDS the attempt,
//! so a perform that reached the wire with no audit record is not expressible.

// Not yet called: the tool-proxy still reads credential values from its spec,
// and switching it over is gated on `BrokerRollout::Enforcing` on the host.
// Landed first so the fail-closed reply semantics are reviewable on their own,
// rather than inside the change that also rewires credential delivery.
#![cfg_attr(not(test), allow(dead_code))]

use std::time::Duration;

/// How long the guest waits for the host to answer.
///
/// Shorter than the host's own connection deadline so the guest gives up first
/// and reports a refusal, rather than both sides sitting on the same timeout and
/// racing to decide who reports the failure.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The outcome of asking the broker.
///
/// Deliberately not a `Result<Credential, _>`: there is no shape of this type
/// that carries a secret, because the guest is never supposed to hold one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerOutcome {
    /// The host authorised the request.
    Granted,
    /// The host refused, or could not be reached.
    ///
    /// One variant for both on purpose. A guest that could distinguish "denied"
    /// from "broker down" would learn something about host state from a failure
    /// it caused, and the correct behaviour is identical either way.
    NotGranted,
}

impl BrokerOutcome {
    /// Whether the action may proceed.
    pub fn is_granted(self) -> bool {
        matches!(self, BrokerOutcome::Granted)
    }
}

/// Interpret the host's reply line.
///
/// Fails closed on everything: unparseable JSON, a missing field, an unexpected
/// shape. Only an explicit `{"granted": true}` is a grant.
pub fn parse_reply(line: &str) -> BrokerOutcome {
    #[derive(serde::Deserialize)]
    struct Reply {
        granted: bool,
    }
    match serde_json::from_str::<Reply>(line) {
        Ok(r) if r.granted => BrokerOutcome::Granted,
        _ => BrokerOutcome::NotGranted,
    }
}

/// This pod's broker capability: the key to sign with and where to send it.
///
/// One type because they are one capability. Delivered together in a single
/// one-shot reply, and read together, so a proxy cannot end up able to sign and
/// unable to connect.
#[derive(Debug, Clone)]
pub struct Capability {
    /// The HMAC key. Never logged.
    pub secret: String,
    /// The vsock port the host broker listens on.
    pub port: u32,
}

/// Host CID for vsock. Always 2 in Firecracker.
///
/// Linux-only because only the Linux arm of `ask` dials anything.
#[cfg(target_os = "linux")]
const VMADDR_CID_HOST: u32 = 2;

/// Build the request line for a QUERY envelope.
///
/// Signed, and newline-terminated because the host frames on newlines — vsock
/// has no message boundaries, so the delimiter is the protocol.
///
/// # This did not sign, and the host had already started refusing
///
/// The unsigned form predates the host-side capability check. Left as it was, a
/// wired-up client would have produced frames the host refuses, and the failure
/// would have looked like a policy denial rather than a format mismatch —
/// because the two are deliberately indistinguishable on the wire.
///
/// Signing goes through `nucleus_cred_protocol::frame`, the same function the
/// host verifies with. Not a local HMAC that matches it today.
pub fn request_line(key: &[u8], envelope: &nucleus_cred_protocol::TaskRequestEnvelope) -> String {
    let payload = serde_json::to_string(envelope).unwrap_or_default();
    format!("{}\n", nucleus_cred_protocol::frame::sign(key, &payload))
}

/// Build the request line for a PERFORM — a request that the host ACT.
///
/// # The `Authority` is the whole point of this signature
///
/// `broker_perform`'s module docs on the host state an obligation the host
/// cannot check: *a `PerformRequest` is composed only past a minted
/// `DischargedBundle`*. The host applies a coarse capability check and
/// structurally cannot see the flow state — `FlowTracker`, the session taint
/// ceiling, the lethal-trifecta guard — that makes an egress safe or not. Those
/// live here, in the guest.
///
/// So the obligation is discharged here or nowhere, and this signature is what
/// stops it being prose. An [`Authority`] is constructible only from a
/// `DischargedBundle`, whose constructor is private to
/// `nucleus_ifc_kernel::discharge` — `preflight_action` is the only way to mint
/// one, and a struct literal naming all eight obligation fields still does not
/// compile outside that module.
///
/// # Why `Authority` and not `&DischargedBundle`
///
/// A `&DischargedBundle` parameter would be a witness the function ignores, and
/// an ignored parameter proves only that a caller had one to pass. Spending the
/// authority does two further things:
///
/// * it **records** the attempt — `spend` refuses an unwitnessed authority
///   outright (`SpendError::Unwitnessed`), so a perform that reached the wire
///   with no audit record is not expressible;
/// * it **binds the scope** — the bundle is spent at `(WebFetch, HTTPEgress)`,
///   the same pair a direct fetch spends, because a brokered call is HTTP egress
///   by exactly the definition that governs `web_fetch`. A bundle earned for a
///   file write cannot pay for this.
pub fn perform_line(
    authority: portcullis_effects::authority::Authority,
    key: &[u8],
    request: &nucleus_cred_protocol::PerformRequest,
) -> Result<String, portcullis_effects::authority::SpendError> {
    use nucleus_ifc_kernel::{Operation, SinkClass};
    // Spent BEFORE the frame is built. A frame that exists is a frame that could
    // be written to the socket by a later edit, so the refusal has to happen
    // before there is anything to write.
    let _bundle = authority.spend(Operation::WebFetch, SinkClass::HTTPEgress)?;
    let payload = serde_json::to_string(request).unwrap_or_default();
    Ok(format!(
        "{}\n",
        nucleus_cred_protocol::frame::sign(key, &payload)
    ))
}

/// Send one frame to the host broker over vsock and read the reply.
///
/// # One frame per connection
///
/// The host serves exactly one request per connection and closes. Matching that
/// here means no per-connection state and no lifetime policy on either side; the
/// guest is not a latency-sensitive client.
///
/// # Every failure is the same failure
///
/// A connect error, a write error, a timeout and a refusal all produce
/// [`BrokerOutcome::NotGranted`] at the call site. That is deliberate — see the
/// type's docs — and it is why this returns the raw line rather than a rich
/// error: there is nothing a caller should do differently, and a caller that
/// could tell "denied" from "broker down" would learn host state from a failure
/// it caused.
/// # Why this is `cfg`-split rather than `cfg`-gated
///
/// `tokio-vsock` is a Linux-only dependency, and the guest is always Linux. A
/// bare `#[cfg(target_os = "linux")]` on this function would force every CALLER
/// to be cfg-gated too — and the callers are the interesting code (the egress
/// path's kernel decision, the discharge, the taint observation). Splitting the
/// implementation instead keeps a macOS build type-checking all of that, which is
/// where most of this is actually reviewed.
#[cfg(target_os = "linux")]
pub async fn ask(port: u32, line: &str) -> std::io::Result<String> {
    // `AsyncReadExt` is needed for `.take()` on the reader. Its absence is a
    // LINUX-ONLY compile error: macOS builds the other arm of this cfg split and
    // never type-checks this body.
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    let fut = async {
        let mut stream =
            tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(VMADDR_CID_HOST, port))
                .await?;
        stream.write_all(line.as_bytes()).await?;
        stream.flush().await?;

        let (reader, _writer) = tokio::io::split(stream);
        let mut reply = String::new();
        // Bounded: the host's reply carries an upstream body, but a guest that
        // read without limit would let a compromised HOST exhaust the guest.
        // The trust here runs both ways less than it looks.
        let mut limited = BufReader::new(reader).take(MAX_REPLY_BYTES);
        limited.read_line(&mut reply).await?;
        Ok::<_, std::io::Error>(reply)
    };

    match tokio::time::timeout(REQUEST_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the broker did not answer within the request timeout",
        )),
    }
}

/// The non-Linux arm: there is no vsock, so there is no broker.
///
/// An error and never a bypass. A build that cannot reach the broker must refuse
/// the action, not fall back to some other way of getting the credential — the
/// module header says why at length, and this is the one line where getting it
/// wrong would be invisible on the platform CI does not gate.
#[cfg(not(target_os = "linux"))]
pub async fn ask(_port: u32, _line: &str) -> std::io::Result<String> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "vsock is Linux-only; there is no credential broker on this platform",
    ))
}

/// Largest reply the guest will read from the host.
///
/// Matches the host's own `MAX_UPSTREAM_BODY_BYTES` with room for the JSON
/// envelope around it: the body is serialised as a byte array, which is about
/// four times its length.
pub const MAX_REPLY_BYTES: u64 = 2 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_cred_protocol::TaskRequestEnvelope;

    /// The capability these tests speak with. A real pod's is minted per pod.
    const TEST_KEY: &[u8] = b"a-test-broker-capability";

    fn perform_request() -> nucleus_cred_protocol::PerformRequest {
        nucleus_cred_protocol::PerformRequest {
            operation: "WebFetch".to_string(),
            target: "model-api".to_string(),
            justification: "routine".to_string(),
            idempotency_key: "key-1".to_string(),
            path: "/messages".to_string(),
            body: b"{}".to_vec(),
        }
    }

    fn envelope() -> TaskRequestEnvelope {
        TaskRequestEnvelope {
            operation: "WebFetch".to_string(),
            target: "api.example.test".to_string(),
            justification: "routine".to_string(),
        }
    }

    /// Only an explicit grant is a grant, and `is_granted` agrees with the
    /// variant — the accessor is what call sites will branch on, so a version of
    /// it that disagreed with the enum would defeat the parsing above.
    #[test]
    fn an_explicit_grant_is_the_only_grant() {
        assert!(BrokerOutcome::Granted.is_granted());
        assert!(!BrokerOutcome::NotGranted.is_granted());
        assert_eq!(
            parse_reply(r#"{"granted":true,"reason":"granted"}"#),
            BrokerOutcome::Granted
        );
        assert_eq!(
            parse_reply(r#"{"granted":false,"reason":"not permitted"}"#),
            BrokerOutcome::NotGranted
        );
    }

    /// **Everything unrecognisable is a refusal.** A guest that treated a
    /// malformed or truncated reply as success would turn any disruption of the
    /// host connection into an authorisation bypass.
    #[test]
    fn every_malformed_reply_fails_closed() {
        for reply in [
            "",
            "not json",
            "{}",
            r#"{"granted":"true"}"#, // string, not bool
            r#"{"grant":true}"#,     // wrong field
            r#"{"granted":true"#,    // truncated mid-object
            "null",
            "[]",
        ] {
            assert_eq!(
                parse_reply(reply),
                BrokerOutcome::NotGranted,
                "a reply of {reply:?} must not be read as a grant"
            );
        }
    }

    /// The request is newline-terminated, because that is how the host frames.
    #[test]
    fn the_request_is_newline_terminated() {
        let line = request_line(TEST_KEY, &envelope());
        assert!(
            line.ends_with('\n'),
            "the host frames on newlines: {line:?}"
        );
        assert_eq!(line.matches('\n').count(), 1, "exactly one terminator");
    }

    /// **The transport refuses rather than bypassing, on a platform with no
    /// vsock.** The module header commits to "failure is a refusal, never a
    /// fallback", and this is the one place that could be got wrong invisibly:
    /// a non-Linux arm returning `Ok` with a synthesised grant would be a
    /// bypass on the platform CI does not gate.
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn there_is_no_broker_without_vsock() {
        let err = ask(1027, "frame\n").await.expect_err("must not succeed");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    /// On Linux the transport must fail rather than hang when nothing is
    /// listening. A guest blocked forever on a dead broker is a pod that never
    /// reports anything, which is worse than a refusal.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_dead_broker_is_an_error_not_a_hang() {
        // A port nothing binds. The connect fails fast; if it ever did not, the
        // REQUEST_TIMEOUT is the backstop and this still completes.
        let started = std::time::Instant::now();
        let err = ask(65_000, "frame\n")
            .await
            .expect_err("nothing is listening");
        assert!(
            started.elapsed() <= REQUEST_TIMEOUT + Duration::from_secs(2),
            "the transport must bound its own wait: {err}"
        );
    }

    /// The reply bound is large enough to carry what the host may return, and
    /// bounded at all — an unbounded read would let a compromised host exhaust
    /// the guest, and the trust here runs both ways less than it looks.
    #[test]
    fn the_reply_bound_admits_a_full_upstream_body() {
        const _: () = assert!(MAX_REPLY_BYTES >= 1024 * 1024);
    }

    /// **The cross-boundary round trip.** What the guest signs, the host both
    /// authenticates and parses.
    ///
    /// This used to parse the whole line as JSON, which worked only because the
    /// line was unsigned — and unsigned is precisely what the host refuses. It
    /// now does what the host does: authenticate, split, then parse the payload.
    /// A format drift on either side fails here rather than at a booted pod.
    #[test]
    fn the_request_is_authentic_and_parses_as_the_envelope_the_host_expects() {
        let line = request_line(TEST_KEY, &envelope());
        let frame = line.trim_end();

        assert!(
            nucleus_cred_protocol::frame::is_authentic(frame, Some(TEST_KEY)),
            "the host verifies with this function; if it refuses here it refuses in production"
        );
        let (_sig, payload) = nucleus_cred_protocol::frame::split(frame).expect("well formed");
        let back: TaskRequestEnvelope =
            serde_json::from_str(payload).expect("the host must be able to parse this");
        assert_eq!(back, envelope());
    }

    /// The non-vacuity control for the test above: a frame signed under a
    /// DIFFERENT capability must NOT authenticate, or `is_authentic` returning
    /// true unconditionally would satisfy it.
    #[test]
    fn a_request_signed_with_another_capability_is_not_authentic() {
        let line = request_line(b"someone-elses-capability", &envelope());
        assert!(!nucleus_cred_protocol::frame::is_authentic(
            line.trim_end(),
            Some(TEST_KEY)
        ));
    }

    /// **A perform request cannot be built without a discharge, and building one
    /// leaves a record.**
    ///
    /// `spend` refuses an unwitnessed authority, so this also pins that a perform
    /// frame reaching the wire with no audit entry is not expressible.
    #[test]
    fn a_witnessed_authority_produces_a_signed_perform_frame() {
        use portcullis_effects::authority::Authority;
        use std::sync::Arc;

        let log = Arc::new(portcullis_effects::receipt::ReceiptLog::new());
        let authority = Authority::new(nucleus_ifc_kernel::discharge::test_helpers::bundle_for(
            nucleus_ifc_kernel::Operation::WebFetch,
            nucleus_ifc_kernel::SinkClass::HTTPEgress,
        ))
        .witnessed_by(Arc::clone(&log));

        let line = perform_line(authority, TEST_KEY, &perform_request())
            .expect("a witnessed, correctly scoped authority must be spendable");
        assert!(nucleus_cred_protocol::frame::is_authentic(
            line.trim_end(),
            Some(TEST_KEY)
        ));
        assert_eq!(
            log.len(),
            1,
            "spending the authority must leave exactly one receipt"
        );
    }

    /// **An unwitnessed authority produces no frame at all.** The refusal has to
    /// happen before the frame exists — a frame that exists is a frame a later
    /// edit could write to the socket.
    #[test]
    fn an_unwitnessed_authority_cannot_produce_a_perform_frame() {
        use portcullis_effects::authority::{Authority, SpendError};

        let authority = Authority::new(nucleus_ifc_kernel::discharge::test_helpers::bundle_for(
            nucleus_ifc_kernel::Operation::WebFetch,
            nucleus_ifc_kernel::SinkClass::HTTPEgress,
        ));
        assert_eq!(
            perform_line(authority, TEST_KEY, &perform_request()).unwrap_err(),
            SpendError::Unwitnessed
        );
    }

    /// **A bundle earned for something else cannot pay for egress.** A file-write
    /// discharge is a real discharge; it is not THIS discharge.
    #[test]
    fn a_bundle_earned_for_a_file_write_cannot_pay_for_a_perform() {
        use portcullis_effects::authority::{Authority, SpendError};
        use std::sync::Arc;

        let log = Arc::new(portcullis_effects::receipt::ReceiptLog::new());
        let authority = Authority::new(nucleus_ifc_kernel::discharge::test_helpers::bundle_for(
            nucleus_ifc_kernel::Operation::WriteFiles,
            nucleus_ifc_kernel::SinkClass::WorkspaceWrite,
        ))
        .witnessed_by(log);

        assert!(matches!(
            perform_line(authority, TEST_KEY, &perform_request()).unwrap_err(),
            SpendError::ScopeMismatch(_)
        ));
    }

    /// The guest gives up before the host does, so the failure is reported once
    /// rather than raced between the two sides.
    #[test]
    fn the_guest_deadline_is_shorter_than_the_hosts() {
        // nucleus_node::broker_transport::CONNECTION_TIMEOUT is 10s; the guest
        // must be strictly under it. Duplicated as a literal because the guest
        // cannot depend on the node crate — that is the whole point of the
        // boundary — so this is a stated coupling, not an enforced one.
        const HOST_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
        assert!(
            REQUEST_TIMEOUT < HOST_CONNECTION_TIMEOUT,
            "the guest must time out first"
        );
    }
}
