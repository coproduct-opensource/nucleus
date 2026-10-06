//! Wire types for the credential broker.
//!
//! # Why these are not in `nucleus-cred-broker`
//!
//! The guest must be able to *ask* the broker for something, which means it
//! needs the request shape. It must never be able to *hold* a credential, which
//! means it must not link the crate containing `Credential` and
//! `CredentialStore`.
//!
//! Those two requirements are incompatible if the shapes and the secrets live
//! together — and they did. `deny.toml` lists `nucleus-cred-broker` with
//! `wrappers = ["nucleus-node"]`, so adding it to the guest's tool-proxy failed
//! the `deny (bans)` gate. That refusal was correct, and this crate is the
//! answer to it: protocol here, credential material there.
//!
//! Nothing in this crate can carry a secret. That is not a convention — there is
//! no type here capable of holding one.

use serde::{Deserialize, Serialize};

/// Wire framing for authenticated broker frames.
///
/// # Why the codec lives here and not on either side
///
/// The guest SIGNS and the host VERIFIES. Written separately those are two
/// implementations of one format, each testable in isolation, each passing, and
/// wrong together the moment one changes — the same shape as the defect one
/// increment ago, where the capability was minted in one file and the verifier
/// was handed `None` in another. Both sides call the functions below.
///
/// Nothing here holds anything. `sign` takes a key by reference and returns a
/// digest; the crate's guarantee — that no *type* here can carry credential
/// material — is untouched, and `no_type_here_can_carry_a_credential` still
/// scans for it.
///
/// # The wire form
///
/// `<hex-hmac-sha256> <payload-json>` — one space, signature first, newline
/// terminated by the transport. Not a JSON wrapper: the payload would need
/// escaping inside a JSON string, and a verifier that re-serialises in order to
/// check a signature is checking its own serialiser rather than what arrived.
pub mod frame {
    /// Sign `payload` under `key`, producing the wire form.
    ///
    /// No trailing newline — framing belongs to the transport, which is the only
    /// layer that knows whether it is writing to a socket or a buffer.
    #[must_use]
    pub fn sign(key: &[u8], payload: &str) -> String {
        use hmac::{Hmac, Mac, digest::KeyInit};
        use sha2::Sha256;
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
            // HMAC accepts a key of any length, so this cannot fail for any
            // `&[u8]`. Expressed as a fallback rather than an unwrap because a
            // panic here would take down the proxy over a frame.
            .expect("HMAC-SHA256 accepts keys of any length");
        mac.update(payload.as_bytes());
        format!("{} {payload}", hex::encode(mac.finalize().into_bytes()))
    }

    /// Split a signed frame into its signature and the payload it covers.
    ///
    /// `None` for anything that is not exactly that shape. A caller must treat
    /// `None` as a refusal — an unsigned frame is not a frame with an empty
    /// signature.
    #[must_use]
    pub fn split(frame: &str) -> Option<(&str, &str)> {
        let (sig, payload) = frame.split_once(' ')?;
        if sig.is_empty() || payload.is_empty() {
            return None;
        }
        Some((sig, payload))
    }

    /// Whether `frame` was signed under `key`.
    ///
    /// # A missing key verifies nothing
    ///
    /// `None` means no capability was provisioned, so nothing can be
    /// authenticated and therefore nothing is accepted. Treating "no key" as "no
    /// signature required" is the fail-OPEN reading, and it turns a provisioning
    /// failure into an open door at the moment nobody is watching.
    ///
    /// # Constant-time
    ///
    /// `verify_slice`, not `==` on the hex: a byte-by-byte compare leaks how
    /// much of a guessed signature was right, and a guest can retry freely.
    #[must_use]
    pub fn is_authentic(frame: &str, key: Option<&[u8]>) -> bool {
        use hmac::{Hmac, Mac, digest::KeyInit};
        use sha2::Sha256;

        let Some(key) = key else {
            return false;
        };
        let Some((sig_hex, payload)) = split(frame) else {
            return false;
        };
        let Ok(sig) = hex::decode(sig_hex) else {
            return false;
        };
        let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(key) else {
            return false;
        };
        mac.update(payload.as_bytes());
        mac.verify_slice(&sig).is_ok()
    }
}

/// A CB4A **Task Request Envelope**: what a guest submits to ask for an action.
///
/// Every field crosses from the guest, so every field is untrusted input.
///
/// # There is no identity field, and that is the point
///
/// An earlier version carried `pod_identity`, and the host built its
/// `AuthorizedRequest` from it. That is a confused deputy: the guest composes
/// this struct, so it could have named **any** pod, and the PDP would have
/// decided for the pod it was told about rather than the pod that asked.
///
/// The field is gone rather than validated. Identity is derived host-side from
/// *which socket accepted the connection* — Firecracker creates one vsock
/// `uds_path` per VM, so the host already knows who is calling and never needed
/// to be told. Removing the field beats comparing it against the truth: a claim
/// that cannot be expressed cannot be mishandled by a future caller who reaches
/// for the field because it is there.
/// # Unknown fields are refused, and that is load-bearing
///
/// The broker now also accepts [`PerformRequest`], which carries these three
/// fields plus three more. Serde's default — ignore what you do not recognise —
/// would let a perform request parse cleanly as a query, and a host that
/// classified by trying types in some order would be one refactor away from
/// answering "granted" to a request to ACT without acting.
///
/// `deny_unknown_fields` makes that impossible on the TYPE rather than in
/// whichever function happens to do the classifying.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRequestEnvelope {
    /// The operation being requested, as the policy layer names it.
    pub operation: String,
    /// The destination the operation targets.
    pub target: String,
    /// Free-text rationale.
    ///
    /// **Auditable evidence, NOT an authorization input.** CB4A is explicit that
    /// the justification must not influence the decision.
    pub justification: String,
}

/// What the host sends back.
///
/// Carries the outcome and nothing else. There is deliberately no field a
/// credential could occupy — the guest is never meant to hold one, so the reply
/// type gives it nowhere to put one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerReply {
    /// Whether the request was authorised and a credential was available.
    pub granted: bool,
    /// Why, in terms safe to hand to untrusted code.
    ///
    /// Coarse on purpose: a refusal that distinguished "policy said no" from
    /// "no such credential" would let a guest enumerate which credentials exist
    /// by watching which refusals differ.
    pub reason: String,
}

/// A request that the HOST perform an outbound call on the guest's behalf.
///
/// # Why a separate type from [`TaskRequestEnvelope`]
///
/// That one is a QUERY — "may I, and is a credential available" — and asking it
/// twice changes nothing. This one has an effect, and the difference is not
/// cosmetic: it is why `idempotency_key` exists and is not optional.
///
/// # The idempotency key is mandatory, and was promised before this type existed
///
/// `broker_client`'s module docs committed to it: *"the moment the broker gains
/// a `perform` operation, [asking twice changing nothing] stops being true and
/// an idempotency key becomes mandatory — recorded here so it is a decision
/// rather than an omission."* Agents retry, and a timeout hides whether the call
/// completed; without a key the host cannot tell a retry from a second request,
/// so a network blip becomes a duplicate side effect at the upstream.
///
/// It is a plain `String` the GUEST chooses. That is safe because the host uses
/// it only to deduplicate within one pod's own stream — it is not an
/// authorisation input, and a guest that reuses a key can only affect its own
/// requests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformRequest {
    /// The operation, as the policy layer names it.
    pub operation: String,
    /// The configured upstream this targets, by name. NOT a URL: the host holds
    /// the base and the guest cannot redirect where the credential is sent.
    pub target: String,
    /// Free-text rationale. Auditable evidence, never an authorisation input.
    pub justification: String,
    /// Deduplicates retries. See the type docs — mandatory, not optional.
    pub idempotency_key: String,
    /// Path beneath the upstream's configured base.
    pub path: String,
    /// Request body, verbatim.
    pub body: Vec<u8>,
}

/// What the host returns after performing the call.
///
/// # This one DOES carry content, and that is the whole point
///
/// [`BrokerReply`] has nowhere to put a credential because the guest is never
/// meant to hold one. This type carries the upstream's RESPONSE — the result of
/// an action taken with a credential, which is exactly what the guest is
/// supposed to receive instead of the credential itself.
///
/// The distinction is worth stating because it looks like a weakening and is
/// not: the credential still never crosses, only what it bought.
///
/// # The body is untrusted
///
/// It is whatever the upstream said, and on a model API it is also AI-authored.
/// The caller must observe it as such; the taint does not propagate by itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformReply {
    /// Whether the host authorised, found a credential, and completed the call.
    pub granted: bool,
    /// Coarse, for the same enumeration reason as [`BrokerReply::reason`].
    pub reason: String,
    /// Upstream HTTP status, when the call was made.
    #[serde(default)]
    pub status: u16,
    /// Upstream response body, when the call was made.
    #[serde(default)]
    pub body: Vec<u8>,
}

pub mod egress;
pub mod stream;

pub use egress::{EffectTable, EgressMethod, EgressOperation, UpstreamKind};

/// A request that the HOST perform a call whose body and reply are STREAMED.
///
/// # Why a third type, not a bigger [`PerformRequest`]
///
/// A perform frame carries its whole body inside one signed JSON line, and the
/// host bounds that line (256 KiB) because it must buffer it before it can
/// verify it. A model call's prompt is routinely larger, and its reply arrives
/// over minutes as server-sent events. Raising the bound would make the host
/// buffer whatever the guest sends; this type instead opens a stream whose body
/// follows as bounded chunks ([`stream`]), each one charged to the pod's egress
/// balance before the host forwards it.
///
/// # Which ask this is, by shape
///
/// Unknown fields are refused, so a [`PerformRequest`] (which has `body` and
/// `idempotency_key`) never reads as this, and this (which has neither) never
/// reads as a perform, because a perform requires both. A
/// [`TaskRequestEnvelope`] refuses this type's extra fields. So the three asks
/// are told apart by the types, whatever order a host tries them in.
///
/// # No idempotency key, and why that is honest
///
/// Each OPEN names one connection. The host stages its upload and can pause
/// that original request for approval, but never re-executes an upstream call
/// for a reconnecting guest. A guest retry opens a fresh stream. `nonce`
/// refuses replayed OPEN frames; it is not remote-effect idempotency.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamRequest {
    /// Additional guest-side deferral. The host must obtain action-bound review
    /// even when its own policy would allow this effect autonomously.
    #[serde(default)]
    pub require_approval: bool,
    /// Optional host-side pause for operator approval. Zero preserves immediate
    /// refusal; the host caps a nonzero request at `stream::MAX_APPROVAL_WAIT_SECONDS`.
    /// Keep the upload half open after END while waiting: EOF cancels the pause.
    #[serde(default, skip_serializing_if = "zero_approval_wait")]
    pub approval_wait_seconds: u64,
    /// The operation, as the policy layer names it.
    pub operation: String,
    /// The configured upstream this targets, by name. NOT a URL.
    pub target: String,
    /// Free-text rationale. Auditable evidence, never an authorisation input.
    pub justification: String,
    /// Unique per stream. The host refuses one it has already seen.
    pub nonce: String,
    /// The HTTP method the host performs. Required and closed (ADR 0007 B-3):
    /// see [`EgressMethod`]. An open without one (what a 2.3.x tool-proxy
    /// writes) is refused: the change is breaking, and the node and CLI pin a
    /// guest release that writes it (`GuestCapability::EgressMethodAndQuery`).
    pub method: EgressMethod,
    /// Path beneath the upstream's configured base.
    pub path: String,
    /// The query, without its `?`, held to the one rule guest and host share
    /// (`nucleus_spec::workload_egress::check_query`). `None` sends none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// The body's media type, forwarded as `content-type` on a method that
    /// carries a body. Guest-chosen, so the host counts it as upload bytes like
    /// the path.
    pub content_type: String,
    /// Request headers the guest PROPOSES, lower-case name to value.
    ///
    /// A proposal, not an instruction: the host forwards only names the
    /// operator's registry allows for this upstream, and never one that could
    /// carry what the host injects
    /// (`nucleus_spec::workload_egress::guest_may_propose_header`). What it
    /// drops it counts in the call's audit record.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub headers: std::collections::BTreeMap<String, String>,
}

fn zero_approval_wait(seconds: &u64) -> bool {
    *seconds == 0
}

/// The host's first answer on a stream: refused, or the upstream's status.
///
/// Sent once, after the request body has been read to its end (or refused part
/// way), so a refusal for exhausting the pod's egress balance mid-upload is
/// always a head the guest can read, named, rather than a dropped connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamHead {
    /// Whether the host authorised and performed the call.
    pub granted: bool,
    /// Why. Coarse for a policy refusal; NAMED for an egress-balance or size
    /// refusal, whose counts are the guest's own traffic.
    pub reason: String,
    /// Upstream HTTP status, when the call was made.
    #[serde(default)]
    pub status: u16,
    /// Upstream `content-type`, when the call was made and it sent one.
    #[serde(default)]
    pub content_type: String,
}

/// The host's last word on a stream whose head was granted.
///
/// A granted head says the upstream answered; this says whether ALL of the
/// answer was relayed. A reply cut at the per-call ceiling, an upstream that
/// failed part way and a stream that timed out are each `complete: false`
/// with the reason named, so a truncated reply is never mistaken for a short
/// one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamEnd {
    /// Whether the whole upstream reply was relayed.
    pub complete: bool,
    /// Why not, when it was not.
    pub reason: String,
}

#[cfg(test)]
mod frame_codec {
    use super::frame;

    const KEY: &[u8] = b"a-pod-broker-capability";

    /// **The property the shared codec exists for.** What `sign` produces,
    /// `is_authentic` accepts. Two implementations could pass their own tests
    /// and disagree with each other; this cannot.
    #[test]
    fn what_is_signed_verifies() {
        let f = frame::sign(KEY, r#"{"operation":"WebFetch"}"#);
        assert!(frame::is_authentic(&f, Some(KEY)));
    }

    /// **The non-vacuity control.** Everything below asserts a refusal, and an
    /// `is_authentic` that returned `false` always would satisfy all of it while
    /// making the broker unusable. Paired with the test above deliberately.
    #[test]
    fn a_wrong_key_is_refused_and_the_right_one_is_not() {
        let f = frame::sign(KEY, "payload");
        assert!(!frame::is_authentic(&f, Some(b"not-the-capability")));
        assert!(
            frame::is_authentic(&f, Some(KEY)),
            "the refusal above must be about the KEY, not about refusing everything"
        );
    }

    /// An unsigned frame is not a frame with an empty signature.
    #[test]
    fn an_unsigned_frame_is_refused() {
        assert!(!frame::is_authentic(
            r#"{"operation":"WebFetch"}"#,
            Some(KEY)
        ));
        assert!(!frame::is_authentic(" payload", Some(KEY)));
        assert!(!frame::is_authentic("deadbeef ", Some(KEY)));
        assert!(!frame::is_authentic("", Some(KEY)));
    }

    /// No key means nothing is accepted — the fail-CLOSED reading. The
    /// alternative turns a provisioning failure into an open door.
    #[test]
    fn no_key_accepts_nothing() {
        let f = frame::sign(KEY, "payload");
        assert!(!frame::is_authentic(&f, None));
    }

    /// A payload altered after signing must not verify. Signing covers the
    /// payload, not merely accompanies it.
    #[test]
    fn a_tampered_payload_is_refused() {
        let f = frame::sign(KEY, r#"{"target":"allowed"}"#);
        let (sig, _) = frame::split(&f).expect("well formed");
        let tampered = format!("{sig} {}", r#"{"target":"attacker"}"#);
        assert!(!frame::is_authentic(&tampered, Some(KEY)));
    }

    /// The payload survives the round trip byte for byte, including the spaces
    /// that the frame format also uses as its delimiter — `split_once` takes the
    /// FIRST space, so a payload containing spaces must still verify.
    #[test]
    fn a_payload_containing_spaces_round_trips() {
        let payload = r#"{"justification":"because the agent asked nicely"}"#;
        let f = frame::sign(KEY, payload);
        assert_eq!(frame::split(&f).map(|(_, p)| p), Some(payload));
        assert!(frame::is_authentic(&f, Some(KEY)));
    }

    /// Signing is deterministic, so a retry of the same request is byte-identical
    /// and the host's idempotency ledger sees one logical operation rather than
    /// two frames it cannot relate.
    #[test]
    fn signing_is_deterministic() {
        assert_eq!(frame::sign(KEY, "payload"), frame::sign(KEY, "payload"));
    }

    /// The signature comes FIRST. If the order ever flipped, every existing
    /// frame would still be well formed and none would verify — a change that
    /// looks cosmetic and is not.
    #[test]
    fn the_signature_is_the_first_field() {
        let f = frame::sign(KEY, "payload");
        let (sig, payload) = frame::split(&f).expect("well formed");
        assert_eq!(payload, "payload");
        assert_eq!(sig.len(), 64, "hex-encoded SHA-256 is 64 characters: {sig}");
        assert!(hex::decode(sig).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Declarations only, with prose stripped: the docs deliberately DISCUSS
    /// the forbidden names to explain why they are absent, and a scanner that
    /// counted prose would fire on the very explanation of the property it
    /// checks.
    fn declarations() -> String {
        // Every source file in the crate: the stream framing is wire format
        // the guest links too, so it is held to the same scan.
        [
            include_str!("lib.rs"),
            include_str!("stream.rs"),
            include_str!("egress.rs"),
            include_str!("egress/effects.rs"),
        ]
        .iter()
        .flat_map(|src| {
            src.split("#[cfg(test)]")
                .next()
                .expect("source before tests")
                .lines()
                .filter(|l| {
                    let t = l.trim_start();
                    !t.starts_with("///") && !t.starts_with("//!") && !t.starts_with("//")
                })
        })
        .collect::<Vec<_>>()
        .join("\n")
    }

    #[test]
    fn approval_wait_is_explicit_and_legacy_stream_frames_remain_immediate() {
        let mut request = stream_request();
        let legacy = serde_json::to_string(&request).unwrap();
        assert!(!legacy.contains("approval_wait_seconds"));
        assert_eq!(
            serde_json::from_str::<StreamRequest>(&legacy)
                .unwrap()
                .approval_wait_seconds,
            0
        );
        request.approval_wait_seconds = stream::MAX_APPROVAL_WAIT_SECONDS;
        let encoded = serde_json::to_string(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<StreamRequest>(&encoded)
                .unwrap()
                .approval_wait_seconds,
            stream::MAX_APPROVAL_WAIT_SECONDS
        );
        assert!(
            stream::GUEST_HEAD_WAIT.as_secs()
                > stream::MAX_APPROVAL_WAIT_SECONDS + stream::UPSTREAM_IDLE.as_secs()
        );
    }

    fn stream_request() -> StreamRequest {
        StreamRequest {
            require_approval: false,
            approval_wait_seconds: 0,
            operation: "WebFetch".into(),
            target: "model-api".into(),
            justification: "credentialed egress".into(),
            nonce: "n-1".into(),
            method: EgressMethod::Post,
            path: "/v1/complete".into(),
            query: None,
            content_type: "application/json".into(),
            headers: std::collections::BTreeMap::new(),
        }
    }

    /// The method is required: a frame without one is not read as the POST
    /// every older frame meant (B-3). The query and headers are optional and
    /// absent from the wire when empty.
    #[test]
    fn a_stream_open_must_name_its_method() {
        let mut json: serde_json::Value = serde_json::to_value(stream_request()).unwrap();
        assert!(json.get("query").is_none() && json.get("headers").is_none());
        let mut without = json.clone();
        without.as_object_mut().unwrap().remove("method");
        assert!(
            serde_json::from_value::<StreamRequest>(without).is_err(),
            "a frame without a method (a 2.3.x open) was accepted"
        );
        json["method"] = "PUT".into();
        assert!(serde_json::from_value::<StreamRequest>(json.clone()).is_err());
        json["method"] = "GET".into();
        json["query"] = "service=x".into();
        json["headers"] = serde_json::json!({"accept": "*/*"});
        let read: StreamRequest = serde_json::from_value(json).unwrap();
        assert_eq!(read.method, EgressMethod::Get);
        assert_eq!(read.query.as_deref(), Some("service=x"));
        assert_eq!(read.headers["accept"], "*/*");
    }

    /// **The three asks cannot be read as one another**, whichever order a
    /// host tries them in. The dangerous confusions are a stream or a query
    /// read as a perform (an effect nobody asked for), and a perform read as
    /// a stream (a body the host then waits for that never comes).
    #[test]
    fn a_stream_request_is_neither_a_perform_nor_a_query() {
        let stream = serde_json::to_string(&stream_request()).expect("serialises");
        assert!(serde_json::from_str::<PerformRequest>(&stream).is_err());
        assert!(serde_json::from_str::<TaskRequestEnvelope>(&stream).is_err());
        assert_eq!(
            serde_json::from_str::<StreamRequest>(&stream).expect("itself"),
            stream_request()
        );

        let perform = serde_json::to_string(&PerformRequest {
            operation: "WebFetch".into(),
            target: "model-api".into(),
            justification: "x".into(),
            idempotency_key: "k".into(),
            path: "/p".into(),
            body: b"{}".to_vec(),
        })
        .expect("serialises");
        assert!(serde_json::from_str::<StreamRequest>(&perform).is_err());

        let query = serde_json::to_string(&TaskRequestEnvelope {
            operation: "WebFetch".into(),
            target: "model-api".into(),
            justification: "x".into(),
        })
        .expect("serialises");
        assert!(serde_json::from_str::<StreamRequest>(&query).is_err());
    }

    /// A head or end the guest cannot fully read is not a grant: unknown
    /// fields are refused, so a reply shaped for something else fails closed.
    #[test]
    fn stream_replies_refuse_shapes_they_do_not_know() {
        assert!(
            serde_json::from_str::<StreamHead>(r#"{"granted":true,"reason":"","x":1}"#).is_err()
        );
        assert!(serde_json::from_str::<StreamEnd>(r#"{"complete":true}"#).is_err());
        let head: StreamHead =
            serde_json::from_str(r#"{"granted":false,"reason":"not permitted"}"#).expect("refusal");
        assert!(!head.granted);
    }

    /// **The structural guarantee.** No type in this crate has a field that
    /// could hold a secret, so a guest linking it gains no ability to receive
    /// one. Checked against the source so a future field addition trips it.
    #[test]
    fn no_type_here_can_carry_a_credential() {
        let decls = declarations();
        for forbidden in ["Credential", "secret", "token:", "password", "api_key"] {
            assert!(
                !decls.contains(forbidden),
                "a field or type named {forbidden:?} appeared in the protocol crate — \
                 the guest links this, so nothing here may carry credential material"
            );
        }
    }

    /// **No identity claim is expressible.** The guest composes this struct, so
    /// any identity field in it would be an identity the guest chose. Checked
    /// against the declarations so that re-adding one — under any of the
    /// obvious names — trips here rather than silently restoring the confused
    /// deputy this crate was changed to remove.
    #[test]
    fn the_guest_cannot_state_who_it_is() {
        let decls = declarations();
        for forbidden in [
            "pod_identity",
            "identity:",
            "spiffe",
            "pod_id",
            "workload_id",
            "subject",
        ] {
            assert!(
                !decls.contains(forbidden),
                "{forbidden:?} appeared in the wire types — identity must come from \
                 which socket accepted the connection, never from what the guest says"
            );
        }
    }

    /// **The idempotency key is mandatory, and this is what holds that.**
    ///
    /// `broker_client`'s docs promised it before this type existed: a `perform`
    /// has an effect, so a retry the host cannot distinguish from a new request
    /// becomes a duplicate side effect at the upstream. `Option<String>` would
    /// let a caller omit it and would read as "supply one if convenient".
    ///
    /// Scans the DECLARATION rather than constructing a value, because the
    /// property is about the type, and a constructed value proves only that this
    /// test supplied a key.
    #[test]
    fn a_perform_request_cannot_omit_its_idempotency_key() {
        let decls = declarations();
        assert!(
            decls.contains("pub idempotency_key: String"),
            "PerformRequest must carry a mandatory idempotency key"
        );
        assert!(
            !decls.contains("idempotency_key: Option"),
            "an optional idempotency key is not a requirement, it is a suggestion"
        );
    }

    /// A perform reply carries the RESULT of an action, which is the point —
    /// but the fields must still be shaped so a credential has nowhere to go.
    /// `status` and `body` are what an upstream returned; neither names a
    /// secret, and `no_type_here_can_carry_a_credential` scans for those.
    #[test]
    fn a_perform_reply_round_trips_with_its_result() {
        let reply = PerformReply {
            granted: true,
            reason: "granted".into(),
            status: 200,
            body: b"{\"ok\":true}".to_vec(),
        };
        let wire = serde_json::to_string(&reply).expect("serialises");
        let back: PerformReply = serde_json::from_str(&wire).expect("round trips");
        assert_eq!(back, reply);
        assert_eq!(back.status, 200);
    }

    #[test]
    fn the_envelope_round_trips() {
        let e = TaskRequestEnvelope {
            operation: "WebFetch".to_string(),
            target: "api.example.test".to_string(),
            justification: "routine".to_string(),
        };
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(
            serde_json::from_str::<TaskRequestEnvelope>(&json).unwrap(),
            e
        );
    }

    #[test]
    fn a_reply_round_trips() {
        let r = BrokerReply {
            granted: false,
            reason: "not permitted".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<BrokerReply>(&json).unwrap(), r);
    }
}
