//! Identity-material delivery — the slice **FM-5**'s noninterference theorem is
//! proven over after Charon→Aeneas→Lean extraction.
//!
//! # The property
//!
//! The tool-proxy spawns the agent workload with `env_clear()` and an explicit
//! overlay so that identity material — the SVID and its private key, the task
//! token, the broker capability, the approval and sandbox secrets, the DLC
//! admission credentials — never reaches the one process the sandbox exists to
//! contain. Stated precisely, the property is **direct identity-material
//! non-delivery** at the *intra-VM* boundary: what the workload can observe
//! *through this delivery relation* must not depend on which identity
//! material exists. Full observational noninterference (timing, sizes,
//! errors, proxy responses) is a strictly stronger claim, fenced below. The
//! workload is the low observer; identity material is the high value — and
//! the workload is not credential-free: it holds a deliberately ATTENUATED
//! credential, a local capability for requesting mediated actions, never one
//! that represents the pod to external relying parties.
//!
//! # Why this reuses the confidentiality axis rather than inventing one
//!
//! [`super::ifc_confidentiality`] already models the BLP "no write down" axis
//! and already labels the top level `Secret — credentials, keys, private
//! data`. Its [`cflows_to`](super::ifc_confidentiality::cflows_to) is
//! extracted and carries theorems. FM-5, like FM-1, does not need a new
//! lattice; it needs to say what a *principal* is, what each material kind's
//! label is, and prove the workload's ceiling excludes identity.
//!
//! # The modelling decisions, stated plainly
//!
//! **`Workload → Internal`, not `Public`.** The workload legitimately receives
//! exactly one secret-shaped value: `NUCLEUS_TOOL_PROXY_AUTH_SECRET`, its own
//! credential for reaching the one policed interface. Possession buys a
//! conversation with the kernel-mediated proxy — which then decides — not the
//! ability to impersonate the pod to anything else. That is precisely what the
//! lattice's middle level means, so the auth secret is `Internal` and the
//! workload's ceiling is `Internal`. With that, the delivery relation is
//! *exactly* `cflows_to` against the ceiling — no exception table — and every
//! theorem is a corollary of the proven confidentiality axis.
//!
//! **`SvidCert → Secret`.** The certificate is public-key material to an
//! external TLS peer, but external peers are not a principal here. Within this
//! boundary the cert names the pod's SPIFFE identity, flows only to the guest
//! runtime (`NUCLEUS_IDENTITY_CERT`), and labelling it lower would make the
//! flagship theorem silent about the artifact that literally spells the
//! identity out. A future design that wants workload-side mTLS must relabel it
//! deliberately — and that change is a red theorem first, which is the point.
//!
//! **Two different "guests".** FM-1's `CredSink::Guest` (ceiling `Public`) is
//! the VM as a *host-side credential sink*: nothing the host brokers may cross
//! into the VM at all. FM-5's [`Principal::GuestRuntime`] (ceiling `Secret`)
//! is the trusted runtime *inside* the VM — guest-init and the tool-proxy —
//! which by design holds the pod's identity; [`Principal::Workload`] is the
//! agent process it spawns. The two ceilings do not contradict: they are
//! statements about different boundaries.
//!
//! **`Host` and `GuestRuntime` share ceiling `Secret`**, so this model does
//! not separate host-only material (the CA's signing keys) from
//! guest-deliverable material. That is the host↔guest boundary — FM-1's
//! territory — fenced out of scope here.
//!
//! # What this model does NOT claim
//!
//! The filesystem channel (`/etc/nucleus/identity/*`, mode-0600 uid-0,
//! enforced by uid distinctness and `reject_credential_readable_workload`),
//! the `/proc/cmdline` channel (covered by `snapshot_safety` and the cmdline
//! classification gate), `/proc/<pid>/environ` (uid boundary again), and
//! timing/size channels are all outside this relation. Nor does it claim the
//! spawn path *consults* this relation — the binding tests in
//! `nucleus-tool-proxy/src/workload.rs` pin pointwise agreement with
//! `workload_env`, and a reachability lint is future work.
//!
//! Scalar-only, like every other module in `extracted/` — Aeneas emits derived
//! comparisons and collection operations as opaque axioms, and an unspecified
//! axiom on this path would undermine the very claim being made.

use super::ifc_confidentiality::{ConfLevel, cflows_to};

/// Who may be handed a value at pod-boot and run time.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principal {
    /// The node process on the host. Mints and owns identity material.
    Host = 0,
    /// guest-init and the tool-proxy — the trusted runtime inside the VM,
    /// which holds the pod's identity in order to mediate for the workload.
    GuestRuntime = 1,
    /// The agent process the tool-proxy spawns. Untrusted; the low observer.
    Workload = 2,
}

/// The kinds of value that cross or are withheld at these boundaries.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterialKind {
    /// The SVID certificate (`svid.pem`, `NUCLEUS_IDENTITY_CERT`).
    SvidCert = 0,
    /// The SVID private key (`svid.key`). Possession is impersonation.
    SvidPrivateKey = 1,
    /// The trust bundle (`bundle.pem`) — CA verification material.
    TrustBundle = 2,
    /// The session task token (`NUCLEUS_TASK_TOKEN{,_NONCE,_ISSUER}`).
    TaskToken = 3,
    /// The broker capability (`NUCLEUS_TOOL_PROXY_BROKER_SECRET`) — what
    /// distinguishes the mediating proxy from every other in-guest process.
    BrokerSecret = 4,
    /// The per-pod approval HMAC key (`NUCLEUS_TOOL_PROXY_APPROVAL_SECRET`).
    ApprovalSecret = 5,
    /// The Tier-3 sandbox proof (`NUCLEUS_SANDBOX_TOKEN`).
    SandboxToken = 6,
    /// The DLC admission family (`NUCLEUS_DLC_*`), labelled as a unit.
    DlcCredentials = 7,
    /// The workload's own HMAC for reaching the proxy
    /// (`NUCLEUS_TOOL_PROXY_AUTH_SECRET`). See the module docs for why this
    /// is `Internal`, not `Secret`.
    ProxyAuthSecret = 8,
    /// Egress forwarder names and local URLs (`NUCLEUS_EGRESS_*`) — the
    /// credential stays in the runtime, which is the point.
    EgressEnv = 9,
    /// Everything else: `spec.env`, `PATH`/`HOME`/`LANG`/`TZ`, the proxy URL.
    OrdinaryData = 10,
}

/// Numeric rank, so no derived comparison reaches the proof as an opaque axiom.
pub fn matcode(m: MaterialKind) -> u8 {
    match m {
        MaterialKind::SvidCert => 0,
        MaterialKind::SvidPrivateKey => 1,
        MaterialKind::TrustBundle => 2,
        MaterialKind::TaskToken => 3,
        MaterialKind::BrokerSecret => 4,
        MaterialKind::ApprovalSecret => 5,
        MaterialKind::SandboxToken => 6,
        MaterialKind::DlcCredentials => 7,
        MaterialKind::ProxyAuthSecret => 8,
        MaterialKind::EgressEnv => 9,
        MaterialKind::OrdinaryData => 10,
    }
}

/// Numeric rank for principals, same reason as [`matcode`].
pub fn prinrank(p: Principal) -> u8 {
    match p {
        Principal::Host => 0,
        Principal::GuestRuntime => 1,
        Principal::Workload => 2,
    }
}

/// The confidentiality label carried by each material kind.
///
/// Identity material is `Secret`; the workload's own proxy HMAC is
/// `Internal`; verification material and ordinary data are `Public`. Each
/// choice is justified in the module docs.
pub fn mat_label(m: MaterialKind) -> ConfLevel {
    match m {
        MaterialKind::SvidCert => ConfLevel::Secret,
        MaterialKind::SvidPrivateKey => ConfLevel::Secret,
        MaterialKind::TrustBundle => ConfLevel::Public,
        MaterialKind::TaskToken => ConfLevel::Secret,
        MaterialKind::BrokerSecret => ConfLevel::Secret,
        MaterialKind::ApprovalSecret => ConfLevel::Secret,
        MaterialKind::SandboxToken => ConfLevel::Secret,
        MaterialKind::DlcCredentials => ConfLevel::Secret,
        MaterialKind::ProxyAuthSecret => ConfLevel::Internal,
        MaterialKind::EgressEnv => ConfLevel::Public,
        MaterialKind::OrdinaryData => ConfLevel::Public,
    }
}

/// The confidentiality ceiling of a principal: the most confidential thing it
/// may receive.
///
/// `Workload → Internal` is the modelling decision justified in the module
/// docs. `Host` and `GuestRuntime → Secret` because both hold the pod's
/// identity by design.
pub fn principal_ceiling(p: Principal) -> ConfLevel {
    match p {
        Principal::Host => ConfLevel::Secret,
        Principal::GuestRuntime => ConfLevel::Secret,
        Principal::Workload => ConfLevel::Internal,
    }
}

/// May material `m` be delivered to principal `p`?
///
/// The whole decision, and deliberately nothing more: this is
/// [`cflows_to`](super::ifc_confidentiality::cflows_to) against the
/// principal's ceiling. Reusing the proven flows-to relation rather than
/// restating it keeps FM-5 a corollary of the confidentiality axis instead of
/// a parallel model that could drift from it.
pub fn ident_may_deliver(m: MaterialKind, p: Principal) -> bool {
    cflows_to(mat_label(m), principal_ceiling(p))
}

/// Whether this material kind may reach the workload.
///
/// Exists so the security-relevant instance has a name of its own and can be
/// stated as a theorem without a reader having to unfold the ceiling.
pub fn identity_reaches_workload(m: MaterialKind) -> bool {
    ident_may_deliver(m, Principal::Workload)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MATERIALS: [MaterialKind; 11] = [
        MaterialKind::SvidCert,
        MaterialKind::SvidPrivateKey,
        MaterialKind::TrustBundle,
        MaterialKind::TaskToken,
        MaterialKind::BrokerSecret,
        MaterialKind::ApprovalSecret,
        MaterialKind::SandboxToken,
        MaterialKind::DlcCredentials,
        MaterialKind::ProxyAuthSecret,
        MaterialKind::EgressEnv,
        MaterialKind::OrdinaryData,
    ];
    const PRINCIPALS: [Principal; 3] = [
        Principal::Host,
        Principal::GuestRuntime,
        Principal::Workload,
    ];

    /// **THE FM-5 PROPERTY.** No Secret-labelled material may reach the
    /// workload.
    #[test]
    fn identity_material_never_reaches_the_workload() {
        for m in MATERIALS {
            if mat_label(m) == ConfLevel::Secret {
                assert!(
                    !identity_reaches_workload(m),
                    "{m:?} is identity material and must not flow to the workload, \
                     whose ceiling is Internal"
                );
            }
        }
    }

    /// …and the boundary is not merely refusing everything: the workload CAN
    /// receive its own proxy HMAC — that is how it authenticates at all.
    /// Without this the theorem above is satisfied by a spawn path that hands
    /// the workload nothing.
    #[test]
    fn the_workload_still_authenticates_to_its_proxy() {
        assert!(identity_reaches_workload(MaterialKind::ProxyAuthSecret));
    }

    /// The guest runtime is not the workload: it receives the SVID private
    /// key by design. This is the witness that the model distinguishes the
    /// two in-guest principals rather than collapsing them.
    #[test]
    fn the_guest_runtime_still_receives_its_svid() {
        assert!(ident_may_deliver(
            MaterialKind::SvidPrivateKey,
            Principal::GuestRuntime
        ));
    }

    /// Exhaustive over the whole domain — 11 materials x 3 principals. Small
    /// enough to enumerate, so there is no reason to sample.
    #[test]
    fn the_delivery_relation_is_pinned_over_its_entire_domain() {
        for m in MATERIALS {
            for p in PRINCIPALS {
                let expected = match (mat_label(m), p) {
                    // Public flows everywhere; Internal everywhere; Secret
                    // only to principals whose ceiling is Secret.
                    (ConfLevel::Secret, Principal::Workload) => false,
                    _ => true,
                };
                assert_eq!(
                    ident_may_deliver(m, p),
                    expected,
                    "delivery table changed at ({m:?}, {p:?}) — if this is \
                     deliberate, restate the table AND the Lean theorems"
                );
            }
        }
    }

    /// The 11-entry label table, pinned entry by entry so a single relabel is
    /// a visible diff in exactly one place — and so a relabel *down* cannot
    /// hide inside the quantified flagship test going vacuous.
    #[test]
    fn every_material_label_is_pinned() {
        let expected = [
            (MaterialKind::SvidCert, ConfLevel::Secret),
            (MaterialKind::SvidPrivateKey, ConfLevel::Secret),
            (MaterialKind::TrustBundle, ConfLevel::Public),
            (MaterialKind::TaskToken, ConfLevel::Secret),
            (MaterialKind::BrokerSecret, ConfLevel::Secret),
            (MaterialKind::ApprovalSecret, ConfLevel::Secret),
            (MaterialKind::SandboxToken, ConfLevel::Secret),
            (MaterialKind::DlcCredentials, ConfLevel::Secret),
            (MaterialKind::ProxyAuthSecret, ConfLevel::Internal),
            (MaterialKind::EgressEnv, ConfLevel::Public),
            (MaterialKind::OrdinaryData, ConfLevel::Public),
        ];
        for (m, l) in expected {
            assert_eq!(mat_label(m), l, "label of {m:?} changed");
        }
    }

    /// `as u8` parity with the explicit rank functions, so Lean never sees a
    /// derived `Ord`.
    #[test]
    fn matcode_and_prinrank_match_the_discriminants() {
        for m in MATERIALS {
            assert_eq!(matcode(m), m as u8);
        }
        for p in PRINCIPALS {
            assert_eq!(prinrank(p), p as u8);
        }
    }

    /// The relation is EXACTLY flows-to against the ceiling — no exception
    /// table. If an exception ever appears, this is the test that names it.
    #[test]
    fn delivery_is_exactly_flows_to_against_the_ceiling() {
        for m in MATERIALS {
            for p in PRINCIPALS {
                assert_eq!(
                    ident_may_deliver(m, p),
                    cflows_to(mat_label(m), principal_ceiling(p))
                );
            }
        }
    }
}
