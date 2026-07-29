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
