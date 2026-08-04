//! DLC-D verified admission — a cryptographic, proof-carrying admission conjunct.
//!
//! `portcullis-core`'s structural admission (`manifest::check_admission`) validates what a tool
//! *declares*; its own docstring notes a tool that lies in its manifest will pass. This module
//! supplies the conjunct structural rules cannot: an invocation is admitted **iff the issuer
//! really signed a capability for this operation** — a real Ed25519 verify over the operation's
//! domain-separated cap atom, fail-closed — and a positive verdict is backed by DLC-D's
//! machine-checked `admit_joint` theorem (*no false admits* on the admission fragment;
//! `delegation_calc/lean/DLC/AdmitFrag.lean`, axiom footprint `[propext, Classical.choice,
//! Quot.sound]`). Cost is one Ed25519 verify (~19.5 µs measured), far below tool-call timescales.
//!
//! ## Where this sits (the live path)
//!
//! The kernel consults a provisioned [`DlcAdmission`] inside
//! [`Kernel::decide_term_with_flow`](crate::kernel::Kernel::decide_term_with_flow) — the same
//! deny-narrowing, default-inert idiom as the Cedar consult: no provisioning ⇒ no behavior
//! change; provisioned ⇒ every decision additionally requires a valid credential for the
//! operation. See [`Kernel::set_dlc_admission`](crate::kernel::Kernel::set_dlc_admission).
//! A [`PolicyCheck`] impl is also provided for composition-layer use (`AllOf` etc.).
//!
//! ## The credential namespace (a deliberate decision)
//!
//! Credentials bind to **portcullis operation names** (`Operation`'s canonical snake_case
//! `Display` strings: `"web_fetch"`, `"run_bash"`, …) — the kernel's actual enforcement
//! vocabulary — not to transport-level tool names (`"mcp__github__search"`), which the kernel
//! never sees. Credential granularity therefore equals enforcement granularity — including its
//! equivalence relation: `ActionTerm::from_operation` collapses `GrepSearch` into the
//! `GlobSearch` primitive, so at the kernel boundary those are ONE operation identity and a
//! `"glob_search"` credential covers grep invocations (observed live in the Tier 2 harness).
//! Finer, tool-name-level binding is a possible extension via the request context, not silently
//! implied by this module.
//!
//! ## Trust boundary
//!
//! DLC-D proves the *credential↔operation* binding (a credential for operation A provably
//! cannot admit operation B — the signature covers A's cap atom). The **host** supplies: the
//! [`KeyRing`] (which issuer keys are trusted is a host provenance decision), the issuer
//! [`Principal`], and the per-operation credentials presented for this session. Admission
//! authorizes the *invocation*; it does not prove the tool behaves as declared.

use std::collections::BTreeMap;

use dlc_core::judgment::KeyRing;
use dlc_core::principal::Principal;
use dlc_core::syntax::Signature;
use dlc_d::admission::{decide, Decision};

/// Re-exported credential types, so a host crate (e.g. the tool proxy) can
/// provision a [`DlcAdmission`] without depending on `dlc-core` directly.
pub use dlc_core::judgment::KeyRing as DlcKeyRing;
/// Re-export: a keyring row (issuer principal id + public key).
pub use dlc_core::principal::KeyRecord as DlcKeyRecord;
/// Re-export: the issuer principal.
pub use dlc_core::principal::Principal as DlcPrincipal;
/// Re-export: the issuer's stable principal id (32 bytes).
pub use dlc_core::principal::PrincipalId as DlcPrincipalId;
/// Re-export: an issuer-signed capability credential.
pub use dlc_core::syntax::Signature as DlcSignature;

use portcullis_core::combinators::{CheckResult, PolicyCheck, PolicyRequest};

/// The provisioned admission state for a session: the trusted issuer keys, the issuer identity,
/// and the credentials presented for this session (operation name → issuer-signed capability).
///
/// Fail-closed by construction: once provisioned on a kernel, an operation with **no** presented
/// credential — or one whose credential does not verify for exactly that operation's cap atom —
/// is denied.
#[derive(Debug, Clone)]
pub struct DlcAdmission {
    keyring: KeyRing,
    issuer: Principal,
    credentials: BTreeMap<String, Signature>,
}

impl DlcAdmission {
    /// Admission state with the given trust anchors and issuer, and no credentials yet
    /// (which denies every operation until credentials are presented — fail-closed).
    #[must_use]
    pub fn new(keyring: KeyRing, issuer: Principal) -> Self {
        Self {
            keyring,
            issuer,
            credentials: BTreeMap::new(),
        }
    }

    /// Present an issuer-signed credential for one operation (canonical snake_case name,
    /// e.g. `"web_fetch"`). The signature must cover exactly that operation's cap atom.
    #[must_use]
    pub fn with_credential(mut self, operation: &str, sig: Signature) -> Self {
        self.credentials.insert(operation.to_string(), sig);
        self
    }

    /// Decide one operation: [`Decision::Admit`] iff a credential was presented for exactly
    /// this operation name **and** it verifies against the issuer's key in the keyring.
    /// Fail-closed: no credential, unknown issuer, bad signature, or a credential minted for
    /// a different operation all land in [`Decision::Deny`].
    #[must_use]
    pub fn decide_operation(&self, operation: &str) -> Decision {
        match self.credentials.get(operation) {
            Some(sig) => decide(&self.keyring, &self.issuer, operation, sig),
            None => Decision::Deny("no issuer-signed credential presented for this operation"),
        }
    }
}

/// Mint an ephemeral issuer credential for one operation — **harness/host tooling,
/// not a production issuance path** (real issuance belongs to the issuer's own key
/// management). Returns the issuer's public key (which is also its principal id,
/// per dlc-d's `Principal::Atom(PrincipalId(pk))` convention) and the Ed25519
/// credential over the operation's cap atom.
///
/// This function carries a copy of dlc-d's v1 cap-invoke message layout; the
/// round-trip test below (`mint_round_trips_through_admit`) equates it with the
/// rev-pinned verifier, so layout drift surfaces as a RED test at pin-bump, not
/// as silently-invalid credentials.
#[must_use]
pub fn mint_credential(seed: &[u8; 32], operation: &str) -> ([u8; 32], Signature) {
    use ed25519_dalek::Signer as _;
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    let vk = sk.verifying_key().to_bytes();
    let mut msg = b"dlc-d/cap-invoke:".to_vec();
    msg.extend_from_slice(&dlc_d::admission::cap_atom(operation).to_le_bytes());
    let sig = sk.sign(&msg);
    (
        vk,
        Signature {
            alg: 0,
            bytes: sig.to_bytes().to_vec(),
        },
    )
}

impl PolicyCheck for DlcAdmission {
    /// Composition-layer form of the same check. The operation name is taken from the request's
    /// `operation` field (the kernel's canonical vocabulary); a `"tool"` context entry, when
    /// present, overrides it for hosts that bind credentials at tool-name granularity.
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        let name = req
            .context
            .get("tool")
            .map(String::as_str)
            .unwrap_or(&req.operation);
        match self.decide_operation(name) {
            Decision::Admit => CheckResult::Allow,
            Decision::Deny(reason) => CheckResult::Deny(reason.to_string()),
        }
    }

    fn name(&self) -> &str {
        "dlc-d/says-admission"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlc_core::principal::KeyRecord;

    /// The layout guard: what `mint_credential` produces must be exactly what the
    /// rev-pinned dlc-d verifier admits. If dlc-d's cap-invoke layout ever moves,
    /// this REDs at pin-bump instead of credentials silently going invalid.
    #[test]
    fn mint_round_trips_through_admit() {
        let seed = [3u8; 32];
        let (pk, sig) = mint_credential(&seed, "web_fetch");
        let issuer = Principal::Atom(dlc_core::principal::PrincipalId(pk));
        let keyring = KeyRing {
            entries: vec![KeyRecord {
                principal: dlc_core::principal::PrincipalId(pk),
                alg: 0,
                public_key: pk.to_vec(),
            }],
        };
        let admission = DlcAdmission::new(keyring, issuer)
            .with_credential("web_fetch", sig.clone())
            .with_credential("read_files", sig);
        // Admitted for the minted operation…
        assert!(admission.decide_operation("web_fetch").is_admit());
        // …and the SAME signature registered under a different operation is
        // refused by the verifier (tool-binding), not by bookkeeping.
        assert!(!admission.decide_operation("read_files").is_admit());
    }
}
