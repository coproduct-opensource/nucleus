//! **Recompute-verifiable certificates for policy decisions** — the R1 rung of
//! Proof-Carrying Authorization (PCA).
//!
//! Today the substrate *signs assertions* (a `VerifierAttestation` proves *who*
//! emitted a record). This crate proves the record is *correct*. A
//! [`Certificate`] binds, into one self-standing Ed25519-signed object:
//!
//! - a **commitment** to the [`Policy`] in force ([`commit_policy`]),
//! - the **subject** of the authority decision (a [`Request`] + its
//!   [`Decision`], or an `old → new` amendment), and
//! - a **proof** — for R1, the witness ([`Policy`]) needed to *recompute* the
//!   verbatim kernel.
//!
//! Any party can [`verify`] it **without trusting the emitter**: check the
//! signature, check freshness/context [`Binding`], then re-run the verbatim
//! [`nucleus_policy_kernel`] function ([`decide`] / [`governance_monotone`])
//! against the carried witness and confirm the claimed outcome. No trusted
//! setup, no zkVM, O(policy) verification — the transparent-first floor of the
//! ladder. A wrong decision (or a weakening amendment) is structurally
//! *uncertifiable*: [`verify`] rejects it.
//!
//! # Two authority questions, one envelope
//!
//! - [`AuthoritySubject::Decision`] — *may this action run now?* The recompute
//!   re-runs [`decide`] and confirms `Allow`/`Deny`.
//! - [`AuthoritySubject::Governance`] — *was this policy amendment
//!   non-weakening?* The recompute re-runs [`governance_monotone`]; a valid
//!   governance cert exists **iff** `allowed(new) ⊆ allowed(old)`. This makes a
//!   self-amending system a *monotone authority ratchet*: it can only certify
//!   amendments that grant no new privilege.
//!
//! # Honest residual trust
//!
//! A recompute cert binds the *computation given the declared policy*; it does
//! not vouch that the policy itself is the "right" one — that is the relying
//! party's trust root (the signer key). [`ResidualTrust`] records this
//! explicitly, mirroring `nucleus-workflow-snark`'s residual manifest.

use nucleus_policy_kernel::{Decision, Policy, Request, decide, governance_monotone};
use serde::{Deserialize, Serialize};

use codec::{put_b32, put_opt_str, put_str, put_u64, sha256};

/// Canonical, domain-separated, length-prefixed encoding primitives.
///
/// These mirror `nucleus-snark-codec`'s discipline (big-endian widths,
/// length-prefixed strings, presence-byte options) but are kept **local** so
/// this crate stays a leaf — depending on `nucleus-snark-codec` would pull in
/// `nucleus-agent-market`/`-externality` (and ed25519/getrandom), breaking the
/// wasm/zkVM-friendly property. The encoders are pure byte-ops (no hash), so
/// the future SP1 guest can reuse them verbatim and hash with the accelerated
/// `sha2` precompile — host==guest commitments by construction.
mod codec {
    use sha2::{Digest, Sha256};

    /// Append a big-endian `u64`.
    #[inline]
    pub fn put_u64(out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&v.to_be_bytes());
    }

    /// Append a length-prefixed string: `u32_be(len) ‖ utf8`. The prefix means
    /// `("ab","c")` and `("a","bc")` encode distinctly — no separator to escape.
    #[inline]
    pub fn put_str(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    }

    /// Append a raw 32-byte digest (fixed width, no length prefix).
    #[inline]
    pub fn put_b32(out: &mut Vec<u8>, v: &[u8; 32]) {
        out.extend_from_slice(v);
    }

    /// Append an optional string with a presence byte: `0x00` for `None`,
    /// `0x01 ‖ put_str` for `Some` — so `None` is distinct from `Some("")`.
    #[inline]
    pub fn put_opt_str(out: &mut Vec<u8>, s: Option<&str>) {
        match s {
            None => out.push(0x00),
            Some(v) => {
                out.push(0x01);
                put_str(out, v);
            }
        }
    }

    /// 32-byte SHA-256 digest.
    #[inline]
    pub fn sha256(bytes: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }
}

// Re-export the kernel types a caller needs to build/inspect a certificate, so
// downstream crates depend on this one alone.
pub use nucleus_policy_kernel::{
    Decision as PolicyDecision, Policy as PolicyDef, Request as PolicyRequest,
};

// ═══════════════════════════════════════════════════════════════════════════
// COMMITMENTS  (domain-separated, length-prefixed SHA-256 — host==guest)
// ═══════════════════════════════════════════════════════════════════════════

/// Domain tag for a policy commitment.
pub const POLICY_DOMAIN: &[u8] = b"nucleus/pca/policy/v1\0";
/// Domain tag for a request commitment (used to bind a cert to a request).
pub const REQUEST_DOMAIN: &[u8] = b"nucleus/pca/request/v1\0";
/// Domain tag for the certificate signing preimage.
pub const CERT_DOMAIN: &[u8] = b"nucleus/pca/cert/v1\0";

/// Canonical bytes of a policy: `DOMAIN ‖ u64(rule_count) ‖ per-rule(effect ‖
/// matcher×3)`. Order-preserving — the kernel keeps rule order for a stable
/// commitment — so two byte-identical policies commit identically and a
/// reordering changes the commitment.
pub fn canonical_policy_bytes(policy: &Policy) -> Vec<u8> {
    let mut out = Vec::with_capacity(POLICY_DOMAIN.len() + 8 + policy.rules.len() * 16);
    out.extend_from_slice(POLICY_DOMAIN);
    put_u64(&mut out, policy.rules.len() as u64);
    for rule in &policy.rules {
        out.push(effect_byte(rule.effect));
        put_matcher(&mut out, &rule.principal);
        put_matcher(&mut out, &rule.action);
        put_matcher(&mut out, &rule.resource);
    }
    out
}

/// SHA-256 commitment to a [`Policy`].
pub fn commit_policy(policy: &Policy) -> [u8; 32] {
    sha256(&canonical_policy_bytes(policy))
}

/// Canonical bytes of a request: `DOMAIN ‖ str(principal) ‖ str(action) ‖
/// str(resource)`.
pub fn canonical_request_bytes(request: &Request) -> Vec<u8> {
    let mut out = Vec::with_capacity(REQUEST_DOMAIN.len() + 32);
    out.extend_from_slice(REQUEST_DOMAIN);
    put_str(&mut out, &request.principal);
    put_str(&mut out, &request.action);
    put_str(&mut out, &request.resource);
    out
}

/// SHA-256 commitment to a [`Request`] — convenient as a `bound_context_hash`
/// so a decision cert is replay-bound to exactly one request.
pub fn commit_request(request: &Request) -> [u8; 32] {
    sha256(&canonical_request_bytes(request))
}

fn effect_byte(effect: nucleus_policy_kernel::Effect) -> u8 {
    use nucleus_policy_kernel::Effect;
    match effect {
        Effect::Permit => 1,
        Effect::Forbid => 2,
    }
}

fn put_matcher(out: &mut Vec<u8>, matcher: &nucleus_policy_kernel::Matcher) {
    use nucleus_policy_kernel::Matcher;
    match matcher {
        Matcher::Any => out.push(0),
        Matcher::Exact(s) => {
            out.push(1);
            put_str(out, s);
        }
    }
}

fn decision_byte(decision: Decision) -> u8 {
    match decision {
        Decision::Allow => 1,
        Decision::Deny => 2,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CERTIFICATE TYPES
// ═══════════════════════════════════════════════════════════════════════════

/// What a certificate authorizes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthoritySubject {
    /// A reference-monitor verdict: *may this action run now?*
    Decision {
        /// Commitment to the policy that produced the verdict.
        policy_commitment: [u8; 32],
        /// The request that was decided.
        request: Request,
        /// The claimed verdict (verification re-derives and confirms it).
        decision: Decision,
    },
    /// A policy amendment proven non-weakening: *may policy change this way?*
    Governance {
        /// Commitment to the policy before the amendment.
        old_commitment: [u8; 32],
        /// Commitment to the policy after the amendment.
        new_commitment: [u8; 32],
    },
}

/// Freshness + context binding. Defeats replay (`valid_until_unix`) and splice
/// (`bound_context_hash` ties the cert to a specific lineage edge / request).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// Anti-replay nonce, unique per issuance.
    pub nonce: [u8; 32],
    /// Unix seconds after which the cert is stale.
    pub valid_until_unix: u64,
    /// Optional hash this cert is bound to (e.g. an edge `content_hash` or a
    /// [`commit_request`]). When set, [`verify`] requires the caller's expected
    /// context to match.
    pub bound_context_hash: Option<[u8; 32]>,
}

impl Binding {
    /// Construct a binding.
    pub fn new(
        nonce: [u8; 32],
        valid_until_unix: u64,
        bound_context_hash: Option<[u8; 32]>,
    ) -> Self {
        Self {
            nonce,
            valid_until_unix,
            bound_context_hash,
        }
    }
}

/// The recompute witness — what a verifier re-runs the kernel against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Witness {
    /// The full policy behind a [`AuthoritySubject::Decision`].
    Decision {
        /// The policy to re-run [`decide`] against.
        policy: Policy,
    },
    /// Both policies behind a [`AuthoritySubject::Governance`] amendment.
    Governance {
        /// The pre-amendment policy.
        old: Policy,
        /// The post-amendment policy.
        new: Policy,
    },
}

/// The R1 proof: the witness needed to recompute the verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecomputeProof {
    /// The recompute witness (the policy / policies).
    pub witness: Witness,
}

/// The proof carried by a certificate. The variant determines verification
/// cost and trust regime; the *same* [`verify`] surface dispatches on it. R1
/// ships only [`ProofMode::Recompute`]; `Snark` / `Pcd` rungs slot in later
/// without changing carriage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofMode {
    /// Re-run the verbatim kernel against a carried witness (no setup, O(policy)
    /// verify, witness exposed).
    Recompute(RecomputeProof),
}

/// What a proof does **not** close — carried so a relying party can reason
/// about residual trust rather than over-claiming. Mirrors
/// `nucleus-workflow-snark`'s residual manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidualTrust {
    /// Whether the *inputs* (the policy) are vouched for, or taken on faith.
    pub witness_honesty: WitnessClosure,
    /// How verification is performed.
    pub verify_regime: VerifyRegime,
    /// Trusted-setup exposure.
    pub trusted_setup: TrustedSetup,
}

impl ResidualTrust {
    /// The honest residual profile of an R1 recompute certificate: the policy
    /// is taken as the relying party's trust root (unclosed), verification is
    /// by recompute, and there is no trusted setup.
    pub fn recompute() -> Self {
        Self {
            witness_honesty: WitnessClosure::Unclosed,
            verify_regime: VerifyRegime::Recompute,
            trusted_setup: TrustedSetup::None,
        }
    }
}

/// How (if at all) the declared witness/inputs are vouched for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessClosure {
    /// Inputs are taken on faith — the relying party's trust root closes this.
    Unclosed,
    /// Inputs are re-derived at their source.
    RecomputeAtSource,
    /// Inputs are attested via zkTLS.
    ZkTls,
    /// Inputs are attested via a TEE.
    TeeAttestation,
}

/// The verification regime a certificate's proof uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyRegime {
    /// Re-execute the kernel (O(policy)).
    Recompute,
    /// Check a succinct proof (O(1)).
    Snark,
}

/// Trusted-setup exposure of a certificate's proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustedSetup {
    /// No setup (recompute / transparent).
    None,
    /// A transparent STARK (no ceremony).
    TransparentStark,
    /// A circuit-specific Groth16 ceremony.
    Groth16Ceremony,
    /// A universal/updatable setup.
    UniversalSetup,
}

/// A self-standing, signed, independently checkable authorization certificate.
///
/// Integrity comes from `signature` over [`signing_message`]; binding to a
/// decision context comes from [`Binding::bound_context_hash`]. The cert does
/// not need to live inside any host structure to be trustworthy — it can travel
/// alongside a lineage edge (referenced by commitment) and be verified anywhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    /// What is authorized.
    pub subject: AuthoritySubject,
    /// Freshness + context binding.
    pub binding: Binding,
    /// The proof (R1: recompute witness).
    pub proof: ProofMode,
    /// Declared residual trust.
    pub residual: ResidualTrust,
    /// Ed25519 public key of the issuer (32 bytes).
    pub signer_pubkey: Vec<u8>,
    /// Ed25519 signature over [`signing_message`] (64 bytes).
    pub signature: Vec<u8>,
}

/// The result of a successful [`verify`] — only constructible by verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthority {
    /// The issuer key that signed the cert (the relying party decides if it is
    /// trusted).
    pub signer_pubkey: Vec<u8>,
    /// The confirmed authority outcome.
    pub outcome: AuthorityOutcome,
}

/// The confirmed outcome of a verified authority — the unified consumption
/// type spanning all three authority questions. A policy [`Decision`] and a
/// [`Governance`] amendment are produced by this crate's [`verify`]; a
/// capability [`Delegation`] is produced by projecting a verified portcullis
/// chain (the `portcullis` bridge). One enforcement gate consumes all three.
///
/// [`Decision`]: AuthorityOutcome::Decision
/// [`Governance`]: AuthorityOutcome::Governance
/// [`Delegation`]: AuthorityOutcome::Delegation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityOutcome {
    /// A confirmed reference-monitor verdict (*may this action run now?*).
    Decision {
        /// The request that was decided.
        request: Request,
        /// The recompute-confirmed verdict.
        decision: Decision,
    },
    /// A confirmed non-weakening amendment (*may policy change this way?*).
    Governance {
        /// Always `true` on success (a weakening amendment cannot verify).
        monotone: bool,
        /// Commitment to the pre-amendment policy this outcome certifies. Carried
        /// so a consumer of the verified token knows *which* amendment was
        /// approved and cannot apply a different (e.g. weakening) one.
        old_commitment: [u8; 32],
        /// Commitment to the post-amendment policy this outcome certifies.
        new_commitment: [u8; 32],
    },
    /// A confirmed capability delegation (*may this principal hold this?*),
    /// projected from a verified portcullis `LatticeCertificate` chain.
    ///
    /// Carries the deterministic chain facts. A canonical commitment to the
    /// *effective permissions* is intentionally omitted: `PermissionLattice`
    /// has no canonical serialization here (it embeds non-deterministic state),
    /// so binding the exact permissions awaits a portcullis-provided canonical
    /// digest. The verified chain itself remains portcullis's `LatticeCertificate`.
    Delegation {
        /// Number of delegation hops from root authority to leaf.
        chain_depth: u32,
        /// Identity of the root authority.
        root_identity: String,
        /// Identity of the leaf holder.
        leaf_identity: String,
    },
}

/// Verification failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertError {
    /// Signature missing, malformed, or not valid for `signer_pubkey`.
    #[error("certificate signature is invalid")]
    BadSignature,
    /// The certificate's validity window has passed.
    #[error("certificate expired (now={now}, valid_until={valid_until})")]
    Expired {
        /// The current time used for the check.
        now: u64,
        /// The cert's `valid_until_unix`.
        valid_until: u64,
    },
    /// The cert is not bound to the context the verifier expected.
    #[error("certificate not bound to the expected context")]
    ContextMismatch,
    /// The carried witness does not match the committed policy.
    #[error("witness does not match the committed policy")]
    CommitmentMismatch,
    /// The claimed decision differs from the recomputed one.
    #[error("claimed decision {claimed:?} does not match recomputed {recomputed:?}")]
    DecisionMismatch {
        /// The verdict the cert claimed.
        claimed: Decision,
        /// The verdict the kernel actually produces.
        recomputed: Decision,
    },
    /// The amendment is weakening; carries the concrete escalation witness.
    #[error("policy amendment is weakening; escalation witness: {witness:?}")]
    GovernanceViolation {
        /// A request the amendment would newly allow.
        witness: Request,
    },
    /// The subject variant and the witness variant disagree.
    #[error("certificate subject and proof witness are mismatched")]
    SubjectProofMismatch,
    /// A governance witness whose representative-request domain exceeds
    /// [`MAX_GOVERNANCE_DOMAIN`]. Rejected before recompute so an attacker-
    /// supplied witness cannot blow up the Cartesian product (DoS guard).
    #[error("governance witness too large: domain {domain} > max {max}")]
    WitnessTooLarge {
        /// The would-be representative-request domain size.
        domain: u128,
        /// The cap that was exceeded.
        max: u128,
    },
}

/// Upper bound on a governance amendment's representative-request domain that
/// [`check_recompute`] will enumerate. `governance_monotone` builds the full
/// principal×action×resource product of the witness policies' distinct exact
/// values (plus a fresh value per field); a self-signed cert with a large
/// witness would otherwise allocate/iterate ~`domain` `Request`s — a capacity-
/// overflow abort on wasm32 (`usize` = 32-bit). 2²⁰ keeps verification bounded
/// while far exceeding any realistic policy.
pub const MAX_GOVERNANCE_DOMAIN: u128 = 1 << 20;

/// The size of the representative-request domain `governance_monotone` would
/// enumerate for `old → new`: `(|principal exacts|+1) · (|action exacts|+1) ·
/// (|resource exacts|+1)`, computed in `u128` so it cannot overflow. Mirrors
/// the kernel's `representative_requests` shape (one fresh value per field).
fn governance_domain_size(old: &Policy, new: &Policy) -> u128 {
    use nucleus_policy_kernel::Matcher;
    use std::collections::BTreeSet;
    let (mut principals, mut actions, mut resources) =
        (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for rule in old.rules.iter().chain(new.rules.iter()) {
        if let Matcher::Exact(s) = &rule.principal {
            principals.insert(s.as_str());
        }
        if let Matcher::Exact(s) = &rule.action {
            actions.insert(s.as_str());
        }
        if let Matcher::Exact(s) = &rule.resource {
            resources.insert(s.as_str());
        }
    }
    (principals.len() as u128 + 1) * (actions.len() as u128 + 1) * (resources.len() as u128 + 1)
}

// ═══════════════════════════════════════════════════════════════════════════
// SIGNING PREIMAGE
// ═══════════════════════════════════════════════════════════════════════════

/// The exact bytes a certificate's `signature` covers: `DOMAIN ‖ subject ‖
/// binding ‖ proof_commitment ‖ residual`. Excludes `signer_pubkey`/`signature`
/// themselves. The proof is folded in by *commitment* (a hash of the witness),
/// so swapping the witness invalidates the signature — defense in depth on top
/// of the recompute check.
pub fn signing_message(cert: &Certificate) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(CERT_DOMAIN);
    put_subject(&mut out, &cert.subject);
    put_binding(&mut out, &cert.binding);
    put_b32(&mut out, &proof_commitment(&cert.proof));
    put_residual(&mut out, &cert.residual);
    out
}

pub(crate) fn put_subject(out: &mut Vec<u8>, subject: &AuthoritySubject) {
    match subject {
        AuthoritySubject::Decision {
            policy_commitment,
            request,
            decision,
        } => {
            out.push(1);
            put_b32(out, policy_commitment);
            put_str(out, &request.principal);
            put_str(out, &request.action);
            put_str(out, &request.resource);
            out.push(decision_byte(*decision));
        }
        AuthoritySubject::Governance {
            old_commitment,
            new_commitment,
        } => {
            out.push(2);
            put_b32(out, old_commitment);
            put_b32(out, new_commitment);
        }
    }
}

fn put_binding(out: &mut Vec<u8>, binding: &Binding) {
    put_b32(out, &binding.nonce);
    put_u64(out, binding.valid_until_unix);
    match &binding.bound_context_hash {
        None => out.push(0),
        Some(h) => {
            out.push(1);
            put_b32(out, h);
        }
    }
}

fn put_residual(out: &mut Vec<u8>, residual: &ResidualTrust) {
    out.push(match residual.witness_honesty {
        WitnessClosure::Unclosed => 0,
        WitnessClosure::RecomputeAtSource => 1,
        WitnessClosure::ZkTls => 2,
        WitnessClosure::TeeAttestation => 3,
    });
    out.push(match residual.verify_regime {
        VerifyRegime::Recompute => 0,
        VerifyRegime::Snark => 1,
    });
    out.push(match residual.trusted_setup {
        TrustedSetup::None => 0,
        TrustedSetup::TransparentStark => 1,
        TrustedSetup::Groth16Ceremony => 2,
        TrustedSetup::UniversalSetup => 3,
    });
    // A presence-byte-tagged optional, future-proofing the preimage shape.
    put_opt_str(out, None);
}

/// A commitment to the proof's witness, folded into [`signing_message`].
pub fn proof_commitment(proof: &ProofMode) -> [u8; 32] {
    match proof {
        ProofMode::Recompute(rp) => match &rp.witness {
            Witness::Decision { policy } => commit_policy(policy),
            Witness::Governance { old, new } => {
                let mut out = Vec::with_capacity(64);
                put_b32(&mut out, &commit_policy(old));
                put_b32(&mut out, &commit_policy(new));
                sha256(&out)
            }
        },
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SIGNER ABSTRACTION
// ═══════════════════════════════════════════════════════════════════════════

/// A minimal Ed25519 signer. Kept crypto-agnostic so the issuing layer compiles
/// without a crypto backend (the `crypto` feature provides [`Ed25519Signer`]).
pub trait Signer {
    /// The 32-byte Ed25519 public key.
    fn public_key(&self) -> [u8; 32];
    /// Sign `msg`, returning the 64-byte Ed25519 signature.
    fn sign(&self, msg: &[u8]) -> [u8; 64];
}

/// An `ed25519-dalek`-backed [`Signer`].
#[cfg(feature = "crypto")]
pub struct Ed25519Signer {
    key: ed25519_dalek::SigningKey,
}

#[cfg(feature = "crypto")]
impl Ed25519Signer {
    /// Build a signer from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: ed25519_dalek::SigningKey::from_bytes(seed),
        }
    }

    /// The verifying-key bytes a relying party trusts.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

#[cfg(feature = "crypto")]
impl Signer for Ed25519Signer {
    fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer as _;
        self.key.sign(msg).to_bytes()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ISSUANCE  (crypto-agnostic: generic over `Signer`)
// ═══════════════════════════════════════════════════════════════════════════

/// Mint a [`AuthoritySubject::Decision`] certificate: run [`decide`], commit the
/// policy, carry it as the recompute witness, and sign.
pub fn issue_decision_cert<S: Signer>(
    policy: &Policy,
    request: Request,
    binding: Binding,
    residual: ResidualTrust,
    signer: &S,
) -> Certificate {
    let decision = decide(policy, &request);
    let subject = AuthoritySubject::Decision {
        policy_commitment: commit_policy(policy),
        request,
        decision,
    };
    let proof = ProofMode::Recompute(RecomputeProof {
        witness: Witness::Decision {
            policy: policy.clone(),
        },
    });
    finalize(subject, binding, proof, residual, signer)
}

/// Mint a [`AuthoritySubject::Governance`] certificate for the amendment
/// `old → new`. Returns `Err(witness)` — the concrete escalation request — if
/// the amendment is weakening (no valid cert can exist for it). On success the
/// cert proves `allowed(new) ⊆ allowed(old)`.
pub fn issue_governance_cert<S: Signer>(
    old: &Policy,
    new: &Policy,
    binding: Binding,
    residual: ResidualTrust,
    signer: &S,
) -> Result<Certificate, Request> {
    governance_monotone(old, new)?;
    let subject = AuthoritySubject::Governance {
        old_commitment: commit_policy(old),
        new_commitment: commit_policy(new),
    };
    let proof = ProofMode::Recompute(RecomputeProof {
        witness: Witness::Governance {
            old: old.clone(),
            new: new.clone(),
        },
    });
    Ok(finalize(subject, binding, proof, residual, signer))
}

fn finalize<S: Signer>(
    subject: AuthoritySubject,
    binding: Binding,
    proof: ProofMode,
    residual: ResidualTrust,
    signer: &S,
) -> Certificate {
    let mut cert = Certificate {
        subject,
        binding,
        proof,
        residual,
        signer_pubkey: signer.public_key().to_vec(),
        signature: Vec::new(),
    };
    let msg = signing_message(&cert);
    cert.signature = signer.sign(&msg).to_vec();
    cert
}

// ═══════════════════════════════════════════════════════════════════════════
// VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════

/// Context a verifier supplies: the current time, and (optionally) the context
/// hash the cert must be bound to.
#[derive(Debug, Clone, Default)]
pub struct VerifyCtx {
    /// Current Unix seconds, for the freshness check.
    pub now_unix: u64,
    /// If set, the cert's `bound_context_hash` must equal this.
    pub expected_context_hash: Option<[u8; 32]>,
}

/// The signature-free half of verification: freshness, context binding,
/// commitment match, and the recompute of the verbatim kernel. Always
/// compiled (no crypto), so a zkVM guest or a no-crypto build can run it.
///
/// **Does not** check the signature — use [`verify`] for the full check.
pub fn check_recompute(
    cert: &Certificate,
    ctx: &VerifyCtx,
) -> Result<VerifiedAuthority, CertError> {
    if cert.binding.valid_until_unix < ctx.now_unix {
        return Err(CertError::Expired {
            now: ctx.now_unix,
            valid_until: cert.binding.valid_until_unix,
        });
    }
    if let Some(expected) = ctx.expected_context_hash {
        match cert.binding.bound_context_hash {
            Some(h) if h == expected => {}
            _ => return Err(CertError::ContextMismatch),
        }
    }

    let ProofMode::Recompute(rp) = &cert.proof;
    match (&cert.subject, &rp.witness) {
        (
            AuthoritySubject::Decision {
                policy_commitment,
                request,
                decision,
            },
            Witness::Decision { policy },
        ) => {
            if &commit_policy(policy) != policy_commitment {
                return Err(CertError::CommitmentMismatch);
            }
            let recomputed = decide(policy, request);
            if recomputed != *decision {
                return Err(CertError::DecisionMismatch {
                    claimed: *decision,
                    recomputed,
                });
            }
            Ok(VerifiedAuthority {
                signer_pubkey: cert.signer_pubkey.clone(),
                outcome: AuthorityOutcome::Decision {
                    request: request.clone(),
                    decision: *decision,
                },
            })
        }
        (
            AuthoritySubject::Governance {
                old_commitment,
                new_commitment,
            },
            Witness::Governance { old, new },
        ) => {
            if &commit_policy(old) != old_commitment || &commit_policy(new) != new_commitment {
                return Err(CertError::CommitmentMismatch);
            }
            // DoS guard: `governance_monotone` enumerates the principal×action×
            // resource representative domain. A self-signed cert with a large
            // witness would blow that product up (capacity-overflow abort on
            // wasm32). Bound it before recomputing.
            let domain = governance_domain_size(old, new);
            if domain > MAX_GOVERNANCE_DOMAIN {
                return Err(CertError::WitnessTooLarge {
                    domain,
                    max: MAX_GOVERNANCE_DOMAIN,
                });
            }
            match governance_monotone(old, new) {
                Ok(()) => Ok(VerifiedAuthority {
                    signer_pubkey: cert.signer_pubkey.clone(),
                    outcome: AuthorityOutcome::Governance {
                        monotone: true,
                        old_commitment: *old_commitment,
                        new_commitment: *new_commitment,
                    },
                }),
                Err(witness) => Err(CertError::GovernanceViolation { witness }),
            }
        }
        _ => Err(CertError::SubjectProofMismatch),
    }
}

/// Full verification: check the Ed25519 signature over [`signing_message`],
/// then run [`check_recompute`]. Returns the confirmed [`VerifiedAuthority`];
/// the relying party decides whether `signer_pubkey` is a trusted issuer.
#[cfg(feature = "crypto")]
pub fn verify(cert: &Certificate, ctx: &VerifyCtx) -> Result<VerifiedAuthority, CertError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let vk = VerifyingKey::try_from(cert.signer_pubkey.as_slice())
        .map_err(|_| CertError::BadSignature)?;
    let sig =
        Signature::try_from(cert.signature.as_slice()).map_err(|_| CertError::BadSignature)?;
    vk.verify_strict(&signing_message(cert), &sig)
        .map_err(|_| CertError::BadSignature)?;

    check_recompute(cert, ctx)
}

// ═══════════════════════════════════════════════════════════════════════════
// DLC BRIDGE  (feature = "dlc")
// ═══════════════════════════════════════════════════════════════════════════

/// Places a [`Certificate`] inside the **Delegation Logic Calculus** (DLC)
/// proof-term model (`delegation_calc`).
///
/// DLC's `Term::Sign(p, M, σ)` introduces the affirmation `p says φ`
/// (`Prop::Says`). A policy [`Certificate`] is the concrete, recompute-grounded
/// realization of one such affirmation: *the issuer says this request is
/// authorized (this amendment is non-weakening)*. This module maps a cert to
/// the components of that affirmation — the [`Principal`], the affirmed
/// [`Prop`], the [`Signature`], and the [`KeyRecord`] — using DLC's own
/// vocabulary.
///
/// **Why this is the reconciliation, not duplication.** DLC's T2 theorem states
/// that logical validity, cryptographic verifiability, and checkable validity
/// coincide. But DLC's *crypto* side is unbuilt: `dlc-core`'s says-I check is
/// stubbed and `dlc-verifier::verify` returns "not implemented". This crate's
/// [`verify`] **is** a working grounding of the says-I check for the policy
/// fragment — so a cert is exactly a `says` affirmation whose checkable half
/// already runs. When DLC's `dlc-crypto::decide_with_keyring` lands, these
/// affirmations slot straight in.
///
/// Atoms are opaque indices in DLC's global atom table; [`claim_atom_id`]
/// derives a stable one from the cert's subject. The full recoverable meaning
/// (which request/decision) lives in the certificate itself, which is the
/// affirmation's witness.
#[cfg(feature = "dlc")]
pub mod dlc_bridge {
    use super::{AuthoritySubject, Certificate};
    use dlc_core::principal::{KeyRecord, Principal, PrincipalId};
    use dlc_core::syntax::{Prop, Signature};

    /// DLC algorithm identifier for Ed25519 (matches `KeyRecord::alg` /
    /// `Signature::alg` convention, Ed25519 = 0).
    pub const ALG_ED25519: u8 = 0;

    /// The issuer as a DLC atomic principal. Its [`PrincipalId`] is the
    /// SHA-256 of the Ed25519 public key — the same "opaque 32-byte id"
    /// (SPIFFE-hash-style) DLC expects.
    pub fn issuer_principal(cert: &Certificate) -> Principal {
        Principal::Atom(issuer_principal_id(cert))
    }

    /// The issuer's [`PrincipalId`] = SHA-256(pubkey).
    pub fn issuer_principal_id(cert: &Certificate) -> PrincipalId {
        PrincipalId(crate::codec::sha256(&cert.signer_pubkey))
    }

    /// The keyring row binding the issuer principal to its Ed25519 key — what a
    /// DLC `⊢_K` judgment threads to check the `says` signature.
    pub fn issuer_key_record(cert: &Certificate) -> KeyRecord {
        KeyRecord {
            principal: issuer_principal_id(cert),
            alg: ALG_ED25519,
            public_key: cert.signer_pubkey.clone(),
        }
    }

    /// The cert's signature in DLC's [`Signature`] shape.
    pub fn dlc_signature(cert: &Certificate) -> Signature {
        Signature {
            alg: ALG_ED25519,
            bytes: cert.signature.clone(),
        }
    }

    /// A stable DLC atom index for the cert's claim, derived from the subject
    /// (domain-separated SHA-256, first 4 bytes). Same subject ⇒ same atom;
    /// distinct claims ⇒ (overwhelmingly) distinct atoms.
    pub fn claim_atom_id(subject: &AuthoritySubject) -> u32 {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(b"nucleus/pca/dlc-atom/v1\0");
        crate::put_subject(&mut out, subject);
        let d = crate::codec::sha256(&out);
        u32::from_be_bytes([d[0], d[1], d[2], d[3]])
    }

    /// The proposition the cert affirms: `issuer says Atom(claim)`.
    pub fn affirmed_prop(cert: &Certificate) -> Prop {
        Prop::Says(
            issuer_principal(cert),
            Box::new(Prop::Atom(claim_atom_id(&cert.subject))),
        )
    }

    /// The components of the DLC `says-I` affirmation a [`Certificate`]
    /// realizes — everything `Term::Sign` and the `⊢_K` check consume, except
    /// the (intricate, and currently unverifiable) full proof-term tree.
    #[derive(Debug, Clone)]
    pub struct DlcAffirmation {
        /// The affirming principal (the issuer).
        pub principal: Principal,
        /// `issuer says Atom(claim)`.
        pub prop: Prop,
        /// The Ed25519 signature over the cert's signing message.
        pub signature: Signature,
        /// The keyring row needed to check `signature` under `principal`.
        pub key_record: KeyRecord,
    }

    /// Project a [`Certificate`] onto its DLC affirmation.
    pub fn to_dlc_affirmation(cert: &Certificate) -> DlcAffirmation {
        DlcAffirmation {
            principal: issuer_principal(cert),
            prop: affirmed_prop(cert),
            signature: dlc_signature(cert),
            key_record: issuer_key_record(cert),
        }
    }

    #[cfg(all(test, feature = "crypto"))]
    mod tests {
        use super::*;
        use crate::{Binding, Ed25519Signer, ResidualTrust, Signer, issue_decision_cert};
        use nucleus_policy_kernel::Effect::Permit;
        use nucleus_policy_kernel::{Matcher, Policy, Request, Rule};

        fn cert() -> Certificate {
            let policy = Policy {
                rules: vec![Rule {
                    effect: Permit,
                    principal: Matcher::Exact("alice".into()),
                    action: Matcher::Exact("read".into()),
                    resource: Matcher::Any,
                }],
            };
            let request = Request {
                principal: "alice".into(),
                action: "read".into(),
                resource: "doc".into(),
            };
            issue_decision_cert(
                &policy,
                request,
                Binding::new([3u8; 32], 1_000, None),
                ResidualTrust::recompute(),
                &Ed25519Signer::from_seed(&[5u8; 32]),
            )
        }

        #[test]
        fn cert_projects_to_a_says_affirmation() {
            let c = cert();
            let aff = to_dlc_affirmation(&c);

            // Issuer principal id is SHA-256 of the pubkey, and the key record
            // binds that principal to the Ed25519 key.
            let signer = Ed25519Signer::from_seed(&[5u8; 32]);
            assert_eq!(aff.key_record.alg, ALG_ED25519);
            assert_eq!(aff.key_record.public_key, signer.public_key().to_vec());
            match &aff.principal {
                Principal::Atom(id) => assert_eq!(id.0, crate::codec::sha256(&c.signer_pubkey)),
                _ => panic!("issuer must be an atomic principal"),
            }

            // The affirmed proposition is `issuer says Atom(claim)`.
            match aff.prop {
                Prop::Says(_, inner) => assert!(matches!(*inner, Prop::Atom(_))),
                _ => panic!("a certificate affirms a `says` proposition"),
            }

            // The DLC signature carries the cert's Ed25519 bytes verbatim.
            assert_eq!(aff.signature.bytes, c.signature);
        }

        #[test]
        fn claim_atom_is_stable_and_subject_sensitive() {
            let c = cert();
            // Deterministic for the same subject.
            assert_eq!(claim_atom_id(&c.subject), claim_atom_id(&c.subject));
            // A governance subject yields a different atom than a decision one.
            let gov = AuthoritySubject::Governance {
                old_commitment: [1u8; 32],
                new_commitment: [2u8; 32],
            };
            assert_ne!(claim_atom_id(&c.subject), claim_atom_id(&gov));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PORTCULLIS BRIDGE  (feature = "portcullis")
// ═══════════════════════════════════════════════════════════════════════════

/// Bridges a verified portcullis capability **delegation** into the unified
/// [`VerifiedAuthority`] this crate produces for policy decisions and
/// governance amendments — so all three authority questions are consumed by one
/// type and one enforcement gate.
///
/// portcullis's `LatticeCertificate` already answers *who may hold what*: its
/// `verify_certificate` re-runs the lattice `meet` + `leq` chain (a recompute,
/// like ours) and yields a `VerifiedPermissions`. This bridge **projects** that
/// verified result into [`AuthorityOutcome::Delegation`]. It does not re-verify
/// the chain — that is portcullis's job — exactly as the [`dlc_bridge`] projects
/// rather than re-checking DLC's crypto. The delegation certificate stays
/// portcullis's `LatticeCertificate`; what unifies is the *verified outcome*.
///
/// Host-only: portcullis pulls a full dependency tree, so this is behind the
/// `portcullis` feature and never touches the default leaf build.
#[cfg(feature = "portcullis")]
pub mod portcullis_bridge {
    use super::{AuthorityOutcome, VerifiedAuthority};
    use portcullis::certificate::VerifiedPermissions;

    /// Project a verified portcullis delegation into the unified outcome.
    pub fn delegation_outcome(verified: &VerifiedPermissions) -> AuthorityOutcome {
        AuthorityOutcome::Delegation {
            chain_depth: verified.chain_depth as u32,
            root_identity: verified.root_identity.clone(),
            leaf_identity: verified.leaf_identity.clone(),
        }
    }

    /// Project a verified portcullis delegation into a [`VerifiedAuthority`],
    /// tagged with the root authority's key, so it flows through the same
    /// enforcement gate as a PCA policy decision.
    pub fn verified_authority(
        verified: &VerifiedPermissions,
        root_pubkey: Vec<u8>,
    ) -> VerifiedAuthority {
        VerifiedAuthority {
            signer_pubkey: root_pubkey,
            outcome: delegation_outcome(verified),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use portcullis::PermissionLattice;
        use portcullis::certificate::{SinkScope, VerifiedPermissions};

        fn verified(depth: usize) -> VerifiedPermissions {
            VerifiedPermissions::new(
                PermissionLattice::restrictive(),
                depth,
                "spiffe://nucleus.local/human/alice".into(),
                "spiffe://nucleus.local/agent/coder-042".into(),
                SinkScope::default(),
            )
        }

        #[test]
        fn projects_delegation_into_unified_outcome() {
            let v = verified(2);
            match verified_authority(&v, vec![7u8; 32]).outcome {
                AuthorityOutcome::Delegation {
                    chain_depth,
                    root_identity,
                    leaf_identity,
                } => {
                    assert_eq!(chain_depth, 2);
                    assert!(root_identity.contains("alice"));
                    assert!(leaf_identity.contains("coder-042"));
                }
                other => panic!("expected a delegation outcome, got {other:?}"),
            }
        }

        /// The full fabric loop: a verified portcullis **delegation** →
        /// projected into the unified [`VerifiedAuthority`] → through the same
        /// `portcullis::enforcement` act-gate a PCA policy decision would use.
        /// On Apple the secure default's `Filtered` egress is strengthened to
        /// `Airgapped`, never weakened. This is the cross-crate unification
        /// running end-to-end (spiffy `policy-cert` ⇄ nucleus `portcullis`).
        #[test]
        fn delegation_flows_through_enforcement_gate_end_to_end() {
            use portcullis::enforcement::{BackendCapability, require_enforced};
            use portcullis::isolation::{IsolationLattice, NetworkIsolation};

            let authority = verified_authority(&verified(2), vec![7u8; 32]);

            let authorized = require_enforced(
                authority,
                IsolationLattice::sandboxed(),
                &BackendCapability::APPLE_VZ,
            )
            .expect("a verified delegation + an enforceable posture → authorized");

            match authorized.authority.outcome {
                AuthorityOutcome::Delegation { chain_depth, .. } => assert_eq!(chain_depth, 2),
                other => panic!("expected a delegation outcome, got {other:?}"),
            }
            // Filtered → Airgapped, and never weaker than requested.
            assert_eq!(
                authorized.isolation.enforced.network,
                NetworkIsolation::Airgapped
            );
            assert!(
                authorized
                    .isolation
                    .enforced
                    .at_least(&authorized.isolation.requested)
            );
        }
    }
}

#[cfg(all(test, feature = "crypto"))]
mod tests {
    use super::*;
    use nucleus_policy_kernel::{Effect, Matcher, Rule};

    fn signer() -> Ed25519Signer {
        Ed25519Signer::from_seed(&[7u8; 32])
    }

    fn permit(p: Matcher, a: Matcher, r: Matcher) -> Rule {
        Rule {
            effect: Effect::Permit,
            principal: p,
            action: a,
            resource: r,
        }
    }
    fn forbid(p: Matcher, a: Matcher, r: Matcher) -> Rule {
        Rule {
            effect: Effect::Forbid,
            principal: p,
            action: a,
            resource: r,
        }
    }
    fn ex(s: &str) -> Matcher {
        Matcher::Exact(s.into())
    }
    fn req(p: &str, a: &str, r: &str) -> Request {
        Request {
            principal: p.into(),
            action: a.into(),
            resource: r.into(),
        }
    }
    fn binding() -> Binding {
        Binding::new([1u8; 32], 1_000, None)
    }
    fn ctx() -> VerifyCtx {
        VerifyCtx {
            now_unix: 500,
            expected_context_hash: None,
        }
    }

    // ── commitments ──────────────────────────────────────────────────────

    #[test]
    fn commitment_is_deterministic_and_order_sensitive() {
        let p1 = Policy {
            rules: vec![permit(Matcher::Any, ex("read"), Matcher::Any)],
        };
        let p2 = Policy {
            rules: vec![permit(Matcher::Any, ex("read"), Matcher::Any)],
        };
        assert_eq!(commit_policy(&p1), commit_policy(&p2));

        let reordered = Policy {
            rules: vec![
                permit(Matcher::Any, ex("read"), Matcher::Any),
                forbid(Matcher::Any, ex("delete"), Matcher::Any),
            ],
        };
        let swapped = Policy {
            rules: vec![
                forbid(Matcher::Any, ex("delete"), Matcher::Any),
                permit(Matcher::Any, ex("read"), Matcher::Any),
            ],
        };
        assert_ne!(commit_policy(&reordered), commit_policy(&swapped));
    }

    // ── decision certs: happy path + every rejection ─────────────────────

    #[test]
    fn decision_cert_round_trips_and_verifies() {
        let policy = Policy {
            rules: vec![permit(ex("alice"), ex("read"), Matcher::Any)],
        };
        let cert = issue_decision_cert(
            &policy,
            req("alice", "read", "doc"),
            binding(),
            ResidualTrust::recompute(),
            &signer(),
        );
        // serde round-trip (the cert is transported as data).
        let bytes = serde_json::to_vec(&cert).unwrap();
        let back: Certificate = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(cert, back);

        let verified = verify(&back, &ctx()).expect("well-formed cert verifies");
        match verified.outcome {
            AuthorityOutcome::Decision { decision, .. } => assert_eq!(decision, Decision::Allow),
            _ => panic!("expected a decision outcome"),
        }
    }

    #[test]
    fn a_deny_decision_also_certifies() {
        let policy = Policy {
            rules: vec![permit(ex("alice"), ex("read"), Matcher::Any)],
        };
        let cert = issue_decision_cert(
            &policy,
            req("bob", "read", "doc"),
            binding(),
            ResidualTrust::recompute(),
            &signer(),
        );
        let verified = verify(&cert, &ctx()).unwrap();
        assert_eq!(
            verified.outcome,
            AuthorityOutcome::Decision {
                request: req("bob", "read", "doc"),
                decision: Decision::Deny
            }
        );
    }

    #[test]
    fn rejects_flipped_decision() {
        let policy = Policy {
            rules: vec![permit(ex("alice"), ex("read"), Matcher::Any)],
        };
        let mut cert = issue_decision_cert(
            &policy,
            req("alice", "read", "doc"),
            binding(),
            ResidualTrust::recompute(),
            &signer(),
        );
        // Flip the claimed decision Allow → Deny. The signature no longer
        // matches the tampered subject, so the FIRST failure is BadSignature.
        if let AuthoritySubject::Decision { decision, .. } = &mut cert.subject {
            *decision = Decision::Deny;
        }
        assert_eq!(verify(&cert, &ctx()), Err(CertError::BadSignature));
    }

    #[test]
    fn rejects_flipped_decision_even_if_resigned() {
        // A malicious issuer who re-signs a wrong verdict is still caught by
        // the recompute (check_recompute is signature-independent).
        let policy = Policy {
            rules: vec![permit(ex("alice"), ex("read"), Matcher::Any)],
        };
        let mut cert = issue_decision_cert(
            &policy,
            req("alice", "read", "doc"),
            binding(),
            ResidualTrust::recompute(),
            &signer(),
        );
        if let AuthoritySubject::Decision { decision, .. } = &mut cert.subject {
            *decision = Decision::Deny;
        }
        // Re-sign the tampered cert so the signature passes.
        cert.signature = signer().sign(&signing_message(&cert)).to_vec();
        assert_eq!(
            verify(&cert, &ctx()),
            Err(CertError::DecisionMismatch {
                claimed: Decision::Deny,
                recomputed: Decision::Allow
            })
        );
    }

    #[test]
    fn rejects_mutated_policy_commitment() {
        let policy = Policy {
            rules: vec![permit(ex("alice"), ex("read"), Matcher::Any)],
        };
        let mut cert = issue_decision_cert(
            &policy,
            req("alice", "read", "doc"),
            binding(),
            ResidualTrust::recompute(),
            &signer(),
        );
        if let AuthoritySubject::Decision {
            policy_commitment, ..
        } = &mut cert.subject
        {
            policy_commitment[0] ^= 0xff;
        }
        cert.signature = signer().sign(&signing_message(&cert)).to_vec();
        // Commitment no longer matches the witness policy.
        assert_eq!(verify(&cert, &ctx()), Err(CertError::CommitmentMismatch));
    }

    #[test]
    fn rejects_swapped_witness() {
        // Keep the (signed) subject for "alice/read" but swap the witness for a
        // permissive policy that would allow everything. The proof_commitment
        // folded into the signature changes, so BadSignature; and even re-signed
        // the policy_commitment in the subject won't match the new witness.
        let policy = Policy {
            rules: vec![permit(ex("alice"), ex("read"), Matcher::Any)],
        };
        let mut cert = issue_decision_cert(
            &policy,
            req("alice", "read", "doc"),
            binding(),
            ResidualTrust::recompute(),
            &signer(),
        );
        let permissive = Policy {
            rules: vec![permit(Matcher::Any, Matcher::Any, Matcher::Any)],
        };
        cert.proof = ProofMode::Recompute(RecomputeProof {
            witness: Witness::Decision { policy: permissive },
        });
        assert_eq!(verify(&cert, &ctx()), Err(CertError::BadSignature));
        cert.signature = signer().sign(&signing_message(&cert)).to_vec();
        assert_eq!(verify(&cert, &ctx()), Err(CertError::CommitmentMismatch));
    }

    #[test]
    fn rejects_stale_cert() {
        let policy = Policy {
            rules: vec![permit(ex("alice"), ex("read"), Matcher::Any)],
        };
        let cert = issue_decision_cert(
            &policy,
            req("alice", "read", "doc"),
            Binding::new([1u8; 32], 100, None),
            ResidualTrust::recompute(),
            &signer(),
        );
        let late = VerifyCtx {
            now_unix: 101,
            expected_context_hash: None,
        };
        assert_eq!(
            verify(&cert, &late),
            Err(CertError::Expired {
                now: 101,
                valid_until: 100
            })
        );
    }

    #[test]
    fn rejects_wrong_context_binding() {
        let policy = Policy {
            rules: vec![permit(ex("alice"), ex("read"), Matcher::Any)],
        };
        let request = req("alice", "read", "doc");
        let bound = commit_request(&request);
        let cert = issue_decision_cert(
            &policy,
            request,
            Binding::new([1u8; 32], 1_000, Some(bound)),
            ResidualTrust::recompute(),
            &signer(),
        );
        // Verifier expects a different context hash.
        let wrong = VerifyCtx {
            now_unix: 500,
            expected_context_hash: Some([9u8; 32]),
        };
        assert_eq!(verify(&cert, &wrong), Err(CertError::ContextMismatch));
        // The matching context passes.
        let right = VerifyCtx {
            now_unix: 500,
            expected_context_hash: Some(bound),
        };
        assert!(verify(&cert, &right).is_ok());
    }

    #[test]
    fn rejects_bad_signature() {
        let policy = Policy {
            rules: vec![permit(ex("alice"), ex("read"), Matcher::Any)],
        };
        let mut cert = issue_decision_cert(
            &policy,
            req("alice", "read", "doc"),
            binding(),
            ResidualTrust::recompute(),
            &signer(),
        );
        cert.signature[0] ^= 0xff;
        assert_eq!(verify(&cert, &ctx()), Err(CertError::BadSignature));
    }

    #[test]
    fn rejects_other_signers_key() {
        let policy = Policy {
            rules: vec![permit(ex("alice"), ex("read"), Matcher::Any)],
        };
        let mut cert = issue_decision_cert(
            &policy,
            req("alice", "read", "doc"),
            binding(),
            ResidualTrust::recompute(),
            &signer(),
        );
        // Replace the embedded pubkey with an attacker's — signature won't match.
        let attacker = Ed25519Signer::from_seed(&[9u8; 32]);
        cert.signer_pubkey = attacker.public_key().to_vec();
        assert_eq!(verify(&cert, &ctx()), Err(CertError::BadSignature));
    }

    // ── governance certs: the ratchet ────────────────────────────────────

    #[test]
    fn governance_cert_certifies_a_tightening() {
        let old = Policy {
            rules: vec![permit(Matcher::Any, Matcher::Any, Matcher::Any)],
        };
        let new = Policy {
            rules: vec![
                permit(Matcher::Any, Matcher::Any, Matcher::Any),
                forbid(Matcher::Any, ex("delete"), Matcher::Any),
            ],
        };
        let cert =
            issue_governance_cert(&old, &new, binding(), ResidualTrust::recompute(), &signer())
                .expect("a tightening amendment is certifiable");
        let verified = verify(&cert, &ctx()).unwrap();
        assert!(matches!(
            verified.outcome,
            AuthorityOutcome::Governance { monotone: true, .. }
        ));
    }

    #[test]
    fn governance_outcome_carries_the_amendment_commitments() {
        // The verified token names WHICH amendment was approved, so a consumer
        // can't apply a different one.
        let old = Policy {
            rules: vec![permit(Matcher::Any, ex("read"), Matcher::Any)],
        };
        let new = Policy {
            rules: vec![
                permit(Matcher::Any, ex("read"), Matcher::Any),
                forbid(Matcher::Any, ex("delete"), Matcher::Any),
            ],
        };
        let cert =
            issue_governance_cert(&old, &new, binding(), ResidualTrust::recompute(), &signer())
                .unwrap();
        match verify(&cert, &ctx()).unwrap().outcome {
            AuthorityOutcome::Governance {
                monotone,
                old_commitment,
                new_commitment,
            } => {
                assert!(monotone);
                assert_eq!(old_commitment, commit_policy(&old));
                assert_eq!(new_commitment, commit_policy(&new));
            }
            other => panic!("expected a governance outcome, got {other:?}"),
        }
    }

    #[test]
    fn governance_witness_exceeding_the_domain_cap_is_rejected_before_recompute() {
        // A self-signed governance cert with a huge witness must fail closed
        // (WitnessTooLarge) rather than blow up the Cartesian product.
        fn big(n: usize) -> Policy {
            Policy {
                rules: (0..n)
                    .map(|i| {
                        permit(
                            ex(&format!("p{i}")),
                            ex(&format!("a{i}")),
                            ex(&format!("r{i}")),
                        )
                    })
                    .collect(),
            }
        }
        let old = big(110); // domain = 111³ = 1_367_631 > MAX_GOVERNANCE_DOMAIN
        let new = old.clone();
        let subject = AuthoritySubject::Governance {
            old_commitment: commit_policy(&old),
            new_commitment: commit_policy(&new),
        };
        let proof = ProofMode::Recompute(RecomputeProof {
            witness: Witness::Governance { old, new },
        });
        let cert = finalize(
            subject,
            binding(),
            proof,
            ResidualTrust::recompute(),
            &signer(),
        );
        match verify(&cert, &ctx()) {
            Err(CertError::WitnessTooLarge { domain, max }) => {
                assert!(domain > max);
                assert_eq!(max, MAX_GOVERNANCE_DOMAIN);
            }
            other => panic!("expected WitnessTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn governance_cert_refuses_a_weakening_amendment() {
        // old permits only read; new also permits write → escalation.
        let old = Policy {
            rules: vec![permit(Matcher::Any, ex("read"), Matcher::Any)],
        };
        let new = Policy {
            rules: vec![
                permit(Matcher::Any, ex("read"), Matcher::Any),
                permit(Matcher::Any, ex("write"), Matcher::Any),
            ],
        };
        let witness =
            issue_governance_cert(&old, &new, binding(), ResidualTrust::recompute(), &signer())
                .expect_err("a weakening amendment cannot be certified");
        assert_eq!(witness.action, "write");
        assert_eq!(decide(&old, &witness), Decision::Deny);
        assert_eq!(decide(&new, &witness), Decision::Allow);
    }

    #[test]
    fn verify_rejects_a_forged_weakening_governance_cert() {
        // An issuer hand-builds a governance cert for a weakening amendment and
        // signs it. verify must still reject via the recompute.
        let old = Policy {
            rules: vec![permit(Matcher::Any, ex("read"), Matcher::Any)],
        };
        let new = Policy {
            rules: vec![
                permit(Matcher::Any, ex("read"), Matcher::Any),
                permit(Matcher::Any, ex("write"), Matcher::Any),
            ],
        };
        let subject = AuthoritySubject::Governance {
            old_commitment: commit_policy(&old),
            new_commitment: commit_policy(&new),
        };
        let proof = ProofMode::Recompute(RecomputeProof {
            witness: Witness::Governance { old, new },
        });
        let cert = finalize(
            subject,
            binding(),
            proof,
            ResidualTrust::recompute(),
            &signer(),
        );
        match verify(&cert, &ctx()) {
            Err(CertError::GovernanceViolation { witness }) => assert_eq!(witness.action, "write"),
            other => panic!("expected GovernanceViolation, got {other:?}"),
        }
    }

    #[test]
    fn rejects_subject_witness_mismatch() {
        // Decision subject paired with a governance witness.
        let policy = Policy {
            rules: vec![permit(ex("alice"), ex("read"), Matcher::Any)],
        };
        let subject = AuthoritySubject::Decision {
            policy_commitment: commit_policy(&policy),
            request: req("alice", "read", "doc"),
            decision: Decision::Allow,
        };
        let proof = ProofMode::Recompute(RecomputeProof {
            witness: Witness::Governance {
                old: policy.clone(),
                new: policy,
            },
        });
        let cert = finalize(
            subject,
            binding(),
            proof,
            ResidualTrust::recompute(),
            &signer(),
        );
        assert_eq!(verify(&cert, &ctx()), Err(CertError::SubjectProofMismatch));
    }
}
