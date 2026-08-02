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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Declarations only, with prose stripped: the docs deliberately DISCUSS
    /// the forbidden names to explain why they are absent, and a scanner that
    /// counted prose would fire on the very explanation of the property it
    /// checks.
    fn declarations() -> String {
        let src = include_str!("lib.rs");
        src.split("#[cfg(test)]")
            .next()
            .expect("source before tests")
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("///") && !t.starts_with("//!") && !t.starts_with("//")
            })
            .collect::<Vec<_>>()
            .join("\n")
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
