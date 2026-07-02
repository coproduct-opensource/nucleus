//! # Proof-Carrying Authorization (PCA) — one `verify()` surface
//!
//! The PCA fabric answers four authorization questions with four verifiers that
//! all share the same discipline: **recompute the answer from the carried bytes,
//! trust no emitter.** This crate unifies them behind a single entry point.
//!
//! ```text
//! verify(AuthorizationToken, &VerifyCtx) -> Result<Verified, VerifyError>
//!   ├─ PolicyCert   →  nucleus_policy_cert::verify        (decision / governance amendment)
//!   ├─ Delegation   →  portcullis::verify_certificate     (capability chain, projected)
//!   ├─ Flow         →  nucleus_ifc::FlowDeclaration::decide  (model-level information flow)
//!   └─ Isolation    →  portcullis::enforcement::require_isolation  (backend posture)
//! ```
//!
//! ## The public/private boundary (by design)
//!
//! This is the **public** Rust core: every dispatch target lives in a public
//! crate (`nucleus`, `delegation_calc`). Two further subjects — proof-DAG
//! *bundles* and *eval receipts* — are verified by **private** crates, so they
//! cannot be dispatched here without a public→private dependency. The full
//! "verify-all" spanning them lives one layer up, in the wasm/TS/MCP façade
//! (`@coproduct_inc/verify`), which may legally depend on the private crates.
//! The [`Verifiable`] trait lets a downstream (private) consumer register those
//! extra subjects on top of this core.
//!
//! ## What each arm proves
//!
//! - **PolicyCert** — re-runs the verbatim `decide` / `governance_monotone`
//!   against the carried witness and checks the Ed25519 signature + freshness +
//!   context binding. A wrong decision is structurally uncertifiable.
//! - **Delegation** — Ed25519 chain + hash linkage + monotone attenuation
//!   (`child ≤ parent`) + expiry + depth, projected into the same
//!   [`VerifiedAuthority`] a policy cert yields (via the portcullis bridge).
//! - **Flow** — deterministic model-level IFC verdict over a *declared* input
//!   surface; fails closed on exfiltration.
//! - **Isolation** — the posture a backend can actually enforce, clamped **up**
//!   to the nearest enforceable level (never weaker).

use chrono::{TimeZone, Utc};

use nucleus_ifc::decision::{FlowDeclaration, IfcVerdict};
use nucleus_policy_cert::verify as verify_policy_cert;
use portcullis::certificate::{LatticeCertificate, verify_certificate};
use portcullis::enforcement::{BackendCapability, EnforcedIsolation, require_isolation};
use portcullis::isolation::IsolationLattice;

pub use nucleus_policy_cert::{
    AuthorityOutcome, CertError, Certificate, VerifiedAuthority, VerifyCtx,
};

/// The subject to verify — the single input to [`verify`].
pub enum AuthorizationToken {
    /// A recompute-verifiable policy certificate (a decision on a request, or a
    /// non-weakening governance amendment).
    PolicyCert(Box<Certificate>),
    /// A capability **delegation** chain (portcullis `LatticeCertificate`),
    /// verified against a root key with a depth bound.
    Delegation {
        /// The signed delegation chain.
        cert: Box<LatticeCertificate>,
        /// The trusted root public key the chain must anchor to.
        root_pubkey: Vec<u8>,
        /// Maximum permitted chain depth (fail closed beyond it).
        max_depth: usize,
    },
    /// A model-level information-**flow** declaration (inputs → sink).
    Flow(Box<FlowDeclaration>),
    /// An **isolation** posture request against a concrete backend.
    Isolation {
        /// The requested isolation posture.
        requested: IsolationLattice,
        /// The backend that will enforce it.
        backend: &'static BackendCapability,
    },
}

/// The unified result of [`verify`] — a sum reflecting the subject.
pub enum Verified {
    /// A verified authority (from `PolicyCert` or `Delegation`).
    Authority(VerifiedAuthority),
    /// A model-level information-flow verdict (from `Flow`).
    Flow(IfcVerdict),
    /// The enforceable isolation posture (from `Isolation`).
    Isolation(EnforcedIsolation),
}

impl Verified {
    /// **The gate.** The authorization signal where it is well-defined:
    /// `Some(true)` for a positive verdict, `Some(false)` for a negative one,
    /// `None` where the result is not a yes/no authorization on its own.
    ///
    /// Gate on THIS — never on `verify(..).is_ok()`. `Ok` only means "the check
    /// ran and the subject verified", **not** "authorized": a validly-verified
    /// `Deny` decision, and a fail-closed `Flow`, are `Ok(..)` with
    /// `is_positive() == Some(false)`. (The arms are deliberately asymmetric:
    /// PolicyCert/Flow carry a negative verdict *in the payload* as `Ok`, while
    /// Delegation/Isolation surface a hard failure as `Err` — so `is_ok()` is
    /// the wrong gate.)
    ///
    /// - `Decision`   → `Some(allow)`.
    /// - `Governance` → `Some(monotone)` (the amendment is non-weakening).
    /// - `Flow`       → `Some(allow)` (the model-level IFC verdict).
    /// - `Delegation` → `None`: a verified chain proves the leaf holds an
    ///   *attenuated* capability, but the effective permissions + sink scope are
    ///   intentionally not projected into the outcome (see
    ///   [`AuthorityOutcome::Delegation`] — `PermissionLattice` has no canonical
    ///   digest here). Consult the raw `LatticeCertificate` to gate a specific
    ///   action; do not treat a verified delegation as unscoped authorization.
    /// - `Isolation`  → `None`: an enforceable posture, not a yes/no authorization.
    pub fn is_positive(&self) -> Option<bool> {
        match self {
            Verified::Authority(a) => match &a.outcome {
                AuthorityOutcome::Decision { decision, .. } => {
                    Some(*decision == nucleus_policy_kernel::Decision::Allow)
                }
                AuthorityOutcome::Governance { monotone, .. } => Some(*monotone),
                AuthorityOutcome::Delegation { .. } => None,
            },
            Verified::Flow(v) => Some(v.allow),
            Verified::Isolation(_) => None,
        }
    }
}

/// Why a [`verify`] call failed. Wraps each subject's native error.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// A policy-certificate check failed.
    #[error("policy certificate: {0}")]
    Cert(#[from] CertError),
    /// A delegation-chain check failed.
    #[error("delegation chain: {0:?}")]
    Delegation(portcullis::certificate::CertificateError),
    /// An isolation posture could not be enforced by the backend.
    #[error("isolation enforcement: {0:?}")]
    Enforcement(portcullis::enforcement::EnforcementError),
    /// The context timestamp could not be interpreted.
    #[error("invalid now_unix: {0}")]
    Time(u64),
}

/// **The one verify surface.** Dispatch an [`AuthorizationToken`] to its
/// verifier and return a unified [`Verified`] — re-computed from the carried
/// bytes, with zero trust in the emitter.
pub fn verify(token: AuthorizationToken, ctx: &VerifyCtx) -> Result<Verified, VerifyError> {
    match token {
        AuthorizationToken::PolicyCert(cert) => {
            Ok(Verified::Authority(verify_policy_cert(&cert, ctx)?))
        }
        AuthorizationToken::Delegation {
            cert,
            root_pubkey,
            max_depth,
        } => {
            // Fail CLOSED on an out-of-range timestamp: `now_unix as i64` would
            // WRAP for now_unix > i64::MAX into a negative (1969) time that
            // chrono accepts, silently disabling the chain's expiry checks so an
            // expired delegation would verify. `try_from` rejects it instead.
            let secs = i64::try_from(ctx.now_unix).map_err(|_| VerifyError::Time(ctx.now_unix))?;
            let now = Utc
                .timestamp_opt(secs, 0)
                .single()
                .ok_or(VerifyError::Time(ctx.now_unix))?;
            let verified = verify_certificate(&cert, &root_pubkey, now, max_depth)
                .map_err(VerifyError::Delegation)?;
            Ok(Verified::Authority(
                nucleus_policy_cert::portcullis_bridge::verified_authority(&verified, root_pubkey),
            ))
        }
        AuthorizationToken::Flow(decl) => Ok(Verified::Flow(decl.decide())),
        AuthorizationToken::Isolation { requested, backend } => {
            require_isolation(requested, backend)
                .map(Verified::Isolation)
                .map_err(VerifyError::Enforcement)
        }
    }
}

/// An extension point for authorization subjects whose verifiers live in
/// **private** crates (proof-DAG bundles, eval receipts). A downstream consumer
/// implements this to fold them into a broader `verify`, without this public
/// core ever depending on a private crate.
pub trait Verifiable {
    /// The verifier's success type.
    type Output;
    /// The verifier's error type.
    type Error;
    /// Verify `self` in `ctx`.
    fn verify(&self, ctx: &VerifyCtx) -> Result<Self::Output, Self::Error>;
}

/// The certificate envelope + reference-monitor types, re-exported for
/// downstream consumers of the SDK.
pub mod prelude {
    pub use crate::{AuthorizationToken, Verifiable, Verified, VerifyError};
    pub use nucleus_policy_cert::{
        AuthorityOutcome, CertError, Certificate, VerifiedAuthority, VerifyCtx,
    };
    pub use nucleus_policy_kernel::{Decision, Policy, Request, decide, governance_monotone};
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_policy_cert::{Binding, Ed25519Signer, ResidualTrust, issue_decision_cert};
    use nucleus_policy_kernel::{Decision, Effect, Matcher, Policy, Request, Rule};

    fn req() -> Request {
        Request {
            principal: "alice".into(),
            action: "read".into(),
            resource: "doc".into(),
        }
    }

    #[test]
    fn policy_cert_arm_verifies_through_the_unified_surface() {
        let policy = Policy {
            rules: vec![Rule {
                effect: Effect::Permit,
                principal: Matcher::Any,
                action: Matcher::Exact("read".into()),
                resource: Matcher::Any,
            }],
        };
        let signer = Ed25519Signer::from_seed(&[7u8; 32]);
        let cert = issue_decision_cert(
            &policy,
            req(),
            Binding::new([0u8; 32], u64::MAX, None),
            ResidualTrust::recompute(),
            &signer,
        );
        let ctx = VerifyCtx {
            now_unix: 0,
            expected_context_hash: None,
        };
        match verify(AuthorizationToken::PolicyCert(Box::new(cert)), &ctx).unwrap() {
            Verified::Authority(a) => match a.outcome {
                AuthorityOutcome::Decision { decision, .. } => {
                    assert_eq!(decision, Decision::Allow)
                }
                other => panic!("expected a decision outcome, got {other:?}"),
            },
            _ => panic!("expected an Authority result"),
        }
    }

    #[test]
    fn isolation_arm_clamps_through_the_unified_surface() {
        use portcullis::isolation::{FileIsolation, NetworkIsolation, ProcessIsolation};
        let requested = IsolationLattice {
            process: ProcessIsolation::Namespaced,
            file: FileIsolation::Sandboxed,
            network: NetworkIsolation::Filtered,
        };
        let ctx = VerifyCtx {
            now_unix: 0,
            expected_context_hash: None,
        };
        // Apple VZ can't enforce Filtered/Namespaced/Sandboxed → clamps UP.
        let out = verify(
            AuthorizationToken::Isolation {
                requested,
                backend: &BackendCapability::APPLE_VZ,
            },
            &ctx,
        )
        .unwrap();
        match out {
            Verified::Isolation(e) => {
                assert!(
                    e.enforced.at_least(&requested),
                    "enforced must be ≥ requested"
                );
            }
            _ => panic!("expected an Isolation result"),
        }
    }

    #[test]
    fn a_valid_deny_verifies_ok_but_is_not_positive() {
        // The audit trap: a Deny cert validly VERIFIES (Ok), but must NOT read as
        // authorized. `is_positive()` is the correct gate — `is_ok()` is not.
        let policy = Policy { rules: vec![] }; // default-deny
        let signer = Ed25519Signer::from_seed(&[9u8; 32]);
        let cert = issue_decision_cert(
            &policy,
            req(),
            Binding::new([0u8; 32], u64::MAX, None),
            ResidualTrust::recompute(),
            &signer,
        );
        let ctx = VerifyCtx {
            now_unix: 0,
            expected_context_hash: None,
        };
        let out = verify(AuthorizationToken::PolicyCert(Box::new(cert)), &ctx)
            .expect("a validly-signed Deny cert still VERIFIES (Ok)");
        assert_eq!(
            out.is_positive(),
            Some(false),
            "a Deny must gate to Some(false)"
        );
    }
}
