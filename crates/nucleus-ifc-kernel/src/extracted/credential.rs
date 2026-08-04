//! Credential delivery — the slice **FM-1**'s noninterference theorem is proven
//! over after Charon→Aeneas→Lean extraction.
//!
//! # The property
//!
//! The CB4A broker exists so that a credential never reaches the guest. Stated
//! as information flow, that is ordinary noninterference: *what the guest can
//! observe must not depend on the credential value*. The standard formulation —
//! two states that agree on low values are indistinguishable to a low observer
//! however their high values differ — is exactly the shape here, with the
//! credential as the high value and the guest as the low observer.
//!
//! # Why this reuses the confidentiality axis rather than inventing one
//!
//! [`super::ifc_confidentiality`] already models the BLP "no write down" axis
//! and already labels the top level `Secret — credentials, keys, private data`.
//! Its [`cflows_to`](super::ifc_confidentiality::cflows_to) is extracted and
//! carries theorems. So FM-1 does not need a new lattice; it needs to say what
//! a *sink* is and prove the guest is not one a credential may reach.
//!
//! # The modelling decision, stated plainly
//!
//! [`CredSink::Guest`] has a ceiling of `Public`. That is the load-bearing
//! choice and it deserves justification rather than assertion: the guest runs
//! the agent the sandbox exists to contain, its `/proc/cmdline` is world
//! readable to every process in it, and — as the vsock work established — an
//! in-guest peer can reach a listener in its own VM. Anything delivered there
//! is observable by untrusted code, so the guest's ceiling is the bottom of the
//! lattice. Treating it as anything higher would prove a weaker statement while
//! looking like the same theorem.
//!
//! Scalar-only, like every other module in `extracted/` — Aeneas emits derived
//! comparisons and collection operations as opaque axioms, and an unspecified
//! axiom on this path would undermine the very claim being made.

use super::ifc_confidentiality::{ConfLevel, cflows_to};

/// Where the broker may be asked to deliver a value.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredSink {
    /// The guest VM — where the agent runs. Untrusted.
    Guest = 0,
    /// An external service the broker calls on the workload's behalf, with the
    /// credential injected host-side and never crossing into the guest.
    ExternalService = 1,
}

/// Numeric rank, so no derived comparison reaches the proof as an opaque axiom.
pub fn sinkrank(s: CredSink) -> u8 {
    match s {
        CredSink::Guest => 0,
        CredSink::ExternalService => 1,
    }
}

/// The confidentiality ceiling of a sink: the most confidential thing it may
/// receive.
///
/// `Guest → Public` is the modelling decision justified in the module docs.
/// `ExternalService → Secret` because that is the destination the credential
/// was issued for — it is the one place a secret is *supposed* to go.
pub fn sink_ceiling(s: CredSink) -> ConfLevel {
    match s {
        CredSink::Guest => ConfLevel::Public,
        CredSink::ExternalService => ConfLevel::Secret,
    }
}

/// May a value at confidentiality `label` be delivered to `sink`?
///
/// The whole decision, and deliberately nothing more: this is
/// [`cflows_to`](super::ifc_confidentiality::cflows_to) against the sink's
/// ceiling. Reusing the proven flows-to relation rather than restating it keeps
/// FM-1 a corollary of the confidentiality axis instead of a parallel model
/// that could drift from it.
pub fn cred_may_deliver(label: ConfLevel, sink: CredSink) -> bool {
    cflows_to(label, sink_ceiling(sink))
}

/// Whether a credential (by definition `Secret`) may reach this sink.
///
/// Exists so the security-relevant instance has a name of its own and can be
/// stated as a theorem without a reader having to know that a credential is
/// labelled `Secret`.
pub fn credential_may_reach(sink: CredSink) -> bool {
    cred_may_deliver(ConfLevel::Secret, sink)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEVELS: [ConfLevel; 3] = [ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];
    const SINKS: [CredSink; 2] = [CredSink::Guest, CredSink::ExternalService];

    /// **THE FM-1 PROPERTY.** A credential may never be delivered to the guest.
    #[test]
    fn a_credential_can_never_reach_the_guest() {
        assert!(
            !credential_may_reach(CredSink::Guest),
            "a Secret credential must not flow to the guest, whose ceiling is Public"
        );
    }

    /// …and the broker is not merely refusing everything: the credential CAN
    /// reach the service it was issued for. Without this the theorem above is
    /// satisfied by a broker that never works.
    #[test]
    fn a_credential_can_still_reach_the_service_it_is_for() {
        assert!(credential_may_reach(CredSink::ExternalService));
    }

    /// Exhaustive over the whole domain — 3 levels x 2 sinks. Small enough to
    /// enumerate, so there is no reason to sample.
    #[test]
    fn the_delivery_relation_is_pinned_over_its_entire_domain() {
        let expected = [
            // (label, sink, may deliver)
            (ConfLevel::Public, CredSink::Guest, true),
            (ConfLevel::Internal, CredSink::Guest, false),
            (ConfLevel::Secret, CredSink::Guest, false),
            (ConfLevel::Public, CredSink::ExternalService, true),
            (ConfLevel::Internal, CredSink::ExternalService, true),
            (ConfLevel::Secret, CredSink::ExternalService, true),
        ];
        for (label, sink, want) in expected {
            assert_eq!(
                cred_may_deliver(label, sink),
                want,
                "{label:?} -> {sink:?} should be {want}"
            );
        }
    }

    /// Only PUBLIC data may reach the guest. Internal is refused too — the
    /// guest's ceiling is the bottom of the lattice, not merely "below secret".
    #[test]
    fn the_guest_receives_public_data_only() {
        for l in LEVELS {
            assert_eq!(
                cred_may_deliver(l, CredSink::Guest),
                l == ConfLevel::Public,
                "the guest may receive {l:?} only if it is Public"
            );
        }
    }

    /// `sinkrank` must be the discriminant, so the Lean side can compare ranks
    /// without an opaque derived `Ord`.
    #[test]
    fn sinkrank_matches_the_discriminant() {
        for s in SINKS {
            assert_eq!(sinkrank(s), s as u8, "rank drift for {s:?}");
        }
    }

    /// The delivery decision is exactly `cflows_to` against the ceiling — not a
    /// second, drifting implementation of the same idea.
    #[test]
    fn delivery_is_exactly_flows_to_against_the_ceiling() {
        for l in LEVELS {
            for s in SINKS {
                assert_eq!(
                    cred_may_deliver(l, s),
                    cflows_to(l, sink_ceiling(s)),
                    "delivery diverged from the confidentiality relation at {l:?} -> {s:?}"
                );
            }
        }
    }
}
