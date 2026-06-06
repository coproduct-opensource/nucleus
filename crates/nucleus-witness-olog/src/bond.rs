//! `bond.rs` — non-custodial, recompute-slashed bonding (Phase 2 economic layer "A").
//!
//! A [`Bond`] pins a witness's *existing-asset* collateral (an integer
//! [`AmountMicro`]) to its standing in the canonical proof-ledger, identified by a
//! transparency-log root. Collateral is slashed **only** on an
//! **objectively-attributable** fault — a witness whose signed claim is
//! contradicted by an independently-attested recompute — and slashed funds route
//! to the **commons** (no-skim, via `nucleus-econ-kernels::route_to_commons`).
//! Abandoning the canonical ledger (forking) **forfeits** the bond: that
//! forfeiture is the economic self-interest to stay honest and canonical, with no
//! per-trade toll and **no token**.
//!
//! ## Why this can stay tokenless where restaking could not
//!
//! EigenLayer had to bolt on a token because its faults were *subjective* (was a
//! service "good"?) and therefore unattributable. Ours is *objective*:
//! `recompute(spec, input) ≠ claimed_result`. So attribution is mechanical and no
//! token is needed.
//!
//! ## The load-bearing security property (hardened by an adversarial red-team)
//!
//! **Slashing authority comes only from AUTHENTICATED, DERIVED evidence — never
//! from caller-supplied scalars.** A first cut accepted the claimed/recomputed
//! digests, the canonical root, and witness "ownership" as free arguments; a
//! red-team proved (with compiled exploits) that this let anyone slash an honest
//! bonder by typing in numbers. The sound design:
//!
//! - A [`Refutation`] has **no public constructor**; it is produced *only* by
//!   [`Refutation::from_evidence`], which verifies the witness's **signed claim**
//!   (so `claimed` is the witness's, not the attacker's) and an independent
//!   verifier's **signed recompute** (so `recomputed` is real), over the *same*
//!   `(spec, input)`. Agreement ⇒ [`BondError::NoObjectiveFault`] (subjective
//!   faults are structurally inexpressible).
//! - [`slash`] additionally verifies the **bond signature** and a **signed
//!   ownership** attestation, and requires the refuted witness, agent, spec, and
//!   canonical root to all line up.
//! - [`forfeiture_on_fork`] takes a **log-signed [`RootAttestation`]**, not a bare
//!   root, so "your root isn't canonical" cannot be asserted by an attacker.
//!
//! ## Honesty boundary
//!
//! - Integer-only money math (`u128` intermediate, saturating/checked to `u64`);
//!   conservation holds **by construction** (cumulative:
//!   `bond.slashed_micro_after + returned == bonded`, and
//!   `total_routed(commons) == slashed_this_event`).
//! - Models the **accounting + slashing logic**; on-chain custody is out of scope
//!   and strictly **non-custodial**.
//! - **Not Sybil-proof** — no slashing rule can be (arXiv:2509.18338, Prop 6).
//!   Slashing-on-objective-fault closes the *subjective-fault* gap that forced
//!   restaking to a token; residual Sybil/grief exposure is real and named.
//! - The fork-cost incentive ships as a Rust property test + a **MODELED** Lean
//!   statement ([`FORK_COST_THEOREM_MODELED`]) — a stated goal, not a proof.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use nucleus_econ_kernels::{route_to_commons, CommonsAllocation, CommonsError, CommonsShare};

use crate::functor::WitnessDigest;

/// Basis-point scale (100% = 10_000).
pub const BOND_BPS_SCALE: u64 = 10_000;

// Domain tags for canonical signing bytes (domain-tagged, length-prefixed,
// integer-only — the discipline from `manifest.rs`). Bumping a tag invalidates
// every prior signature of that kind.
pub const BOND_DOMAIN: &[u8] = b"nucleus/witness-olog/bond/v1\0";
pub const WITNESS_CLAIM_DOMAIN: &[u8] = b"nucleus/witness-olog/witness-claim/v1\0";
pub const SIGNED_RECOMPUTE_DOMAIN: &[u8] = b"nucleus/witness-olog/recompute/v1\0";
pub const OWNERSHIP_DOMAIN: &[u8] = b"nucleus/witness-olog/ownership/v1\0";
pub const ROOT_ATTESTATION_DOMAIN: &[u8] = b"nucleus/witness-olog/root-attestation/v1\0";

/// A **MODELED** Lean statement of the fork-cost incentive — a stated goal, NOT a
/// discharged proof (the olog Lean core is theorem-incomplete; tiered honestly per
/// `CATEGORICAL-LANDSCAPE.md`).
pub const FORK_COST_THEOREM_MODELED: &str = "\
theorem staying_is_dominant_when_forfeiture_dominates_gain
    (forfeiture max_defection_gain : Nat)
    (h : max_defection_gain ≤ forfeiture) :
    -- abandoning the canonical ledger forfeits `forfeiture`; the best a defector
    -- gains is `max_defection_gain`; so staying's net payoff ≥ forking's.
    -- Statement only (MODELED); discharge is future work.
    True := by trivial";

/// An amount of an EXISTING asset in micro-units (e.g. micro-USD). Accounting
/// only — the asset is custodied on-chain and OUT OF SCOPE (non-custodial).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AmountMicro(pub u64);

impl AmountMicro {
    pub const ZERO: AmountMicro = AmountMicro(0);

    /// Saturating add — overflow can never silently wrap.
    pub fn saturating_add(self, o: AmountMicro) -> AmountMicro {
        AmountMicro(self.0.saturating_add(o.0))
    }

    /// Checked sub — `None` on underflow (callers MUST treat as an error).
    pub fn checked_sub(self, o: AmountMicro) -> Option<AmountMicro> {
        self.0.checked_sub(o.0).map(AmountMicro)
    }

    /// `bps`-fraction via a `u128` intermediate, saturating to `u64`.
    pub fn mul_bps(self, bps: u64) -> AmountMicro {
        let v = (u128::from(self.0) * u128::from(bps)) / u128::from(BOND_BPS_SCALE);
        AmountMicro(u64::try_from(v).unwrap_or(u64::MAX))
    }
}

/// Root of the canonical transparency log a bond is pinned to. A fork has a
/// different root by construction, so a bond pinned to root R is recognised only
/// on the ledger whose root is R — this is what makes a bond NON-PORTABLE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LedgerRoot(pub [u8; 32]);

/// Bond lifecycle. Terminal states are exclusive; a bond is slashable/refundable
/// only while `Active`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BondStanding {
    Active,
    Slashed,
    Released,
    ForfeitedOnFork,
}

/// Errors from the bonding layer.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BondError {
    #[error("signature did not verify: {0}")]
    SignatureInvalid(String),
    #[error("sig_b64 base64 decode failed: {0}")]
    Base64(String),
    #[error("signature is {got} bytes, expected 64")]
    WrongSignatureLength { got: usize },
    /// The recompute AGREES with the witness's claim — no slashable (objective)
    /// fault. Subjective dissatisfaction always lands here.
    #[error("no objective fault: claim and recompute agree")]
    NoObjectiveFault,
    /// The claim and recompute are over different `(spec, input)` — not the same
    /// question, so the disagreement is meaningless.
    #[error("claim and recompute are over different (spec, input)")]
    MismatchedQuestion,
    /// The refutation/ownership doesn't reference this bond.
    #[error("evidence does not reference this bond")]
    EvidenceMismatch,
    /// Bond not in the required lifecycle state.
    #[error("bond is not active (standing = {0:?})")]
    NotActive(BondStanding),
    /// The bond is pinned to the canonical root — it has NOT been abandoned.
    #[error("bond is on the canonical root; nothing to forfeit")]
    NotForked,
    /// `penalty_bps` outside `1..=10_000`.
    #[error("penalty {bps} bps out of range (must be 1..=10000)")]
    PenaltyOutOfRange { bps: u64 },
    /// `slashed_micro` exceeded `bonded_micro` (a malformed/forged bond).
    #[error("collateral underflow: slashed exceeds bonded")]
    CollateralUnderflow,
    /// Commons routing rejected the shares.
    #[error("commons routing: {0}")]
    Commons(String),
}

impl From<CommonsError> for BondError {
    fn from(e: CommonsError) -> Self {
        BondError::Commons(e.to_string())
    }
}

// ── Ed25519 helpers (shared discipline) ─────────────────────────────────────

fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn sign_bytes(sk: &SigningKey, msg: &[u8]) -> String {
    STANDARD.encode(sk.sign(msg).to_bytes())
}

fn verify_bytes(vk: &VerifyingKey, msg: &[u8], sig_b64: &str) -> Result<(), BondError> {
    let sig_bytes = STANDARD
        .decode(sig_b64)
        .map_err(|e| BondError::Base64(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(BondError::WrongSignatureLength {
            got: sig_bytes.len(),
        });
    }
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&sig_bytes);
    vk.verify(msg, &Signature::from_bytes(&buf))
        .map_err(|e| BondError::SignatureInvalid(e.to_string()))
}

// ── Authenticated evidence ──────────────────────────────────────────────────

/// A witness's **signed** claim: "for `(task_spec_hash, input_digest)` I assert
/// `result_digest`." Signed by the witnessing agent, so a refutation derives what
/// the witness *actually* claimed instead of trusting an attacker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedWitnessClaim {
    pub task_spec_hash: [u8; 32],
    pub input_digest: [u8; 32],
    pub result_digest: [u8; 32],
    pub agent_id: String,
    pub kid: String,
    pub sig_b64: String,
}

pub fn canonical_witness_claim_bytes(c: &SignedWitnessClaim) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(WITNESS_CLAIM_DOMAIN);
    push_field(&mut out, &c.task_spec_hash);
    push_field(&mut out, &c.input_digest);
    push_field(&mut out, &c.result_digest);
    push_field(&mut out, c.agent_id.as_bytes());
    push_field(&mut out, c.kid.as_bytes());
    out
}

pub fn sign_witness_claim(sk: &SigningKey, mut c: SignedWitnessClaim) -> SignedWitnessClaim {
    c.sig_b64 = sign_bytes(sk, &canonical_witness_claim_bytes(&c));
    c
}

pub fn verify_witness_claim(c: &SignedWitnessClaim, vk: &VerifyingKey) -> Result<(), BondError> {
    verify_bytes(vk, &canonical_witness_claim_bytes(c), &c.sig_b64)
}

impl SignedWitnessClaim {
    /// Content-address of the claim — the witness's digest in the proof-ledger.
    /// Derived, never supplied.
    pub fn witness_digest(&self) -> WitnessDigest {
        let mut h = Sha256::new();
        h.update(canonical_witness_claim_bytes(self));
        WitnessDigest(h.finalize().into())
    }
}

/// An independent verifier's **signed** recompute of the same question. Binds
/// `result_digest` to a `transcript_digest` (the deterministic, re-derivable
/// recompute trace) under a verifier key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRecompute {
    pub task_spec_hash: [u8; 32],
    pub input_digest: [u8; 32],
    pub result_digest: [u8; 32],
    pub transcript_digest: [u8; 32],
    pub kid: String,
    pub sig_b64: String,
}

pub fn canonical_signed_recompute_bytes(r: &SignedRecompute) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(SIGNED_RECOMPUTE_DOMAIN);
    push_field(&mut out, &r.task_spec_hash);
    push_field(&mut out, &r.input_digest);
    push_field(&mut out, &r.result_digest);
    push_field(&mut out, &r.transcript_digest);
    push_field(&mut out, r.kid.as_bytes());
    out
}

pub fn sign_recompute(sk: &SigningKey, mut r: SignedRecompute) -> SignedRecompute {
    r.sig_b64 = sign_bytes(sk, &canonical_signed_recompute_bytes(&r));
    r
}

pub fn verify_signed_recompute(r: &SignedRecompute, vk: &VerifyingKey) -> Result<(), BondError> {
    verify_bytes(vk, &canonical_signed_recompute_bytes(r), &r.sig_b64)
}

/// OBJECTIVE fault evidence. **No public constructor** — produced only by
/// [`Refutation::from_evidence`], which requires a verified signed claim AND a
/// verified signed recompute that genuinely disagree over the same question. A
/// subjective complaint or attacker-typed digit can never become a `Refutation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Refutation {
    pub task_spec_hash: [u8; 32],
    pub input_digest: [u8; 32],
    pub claimed_result_digest: [u8; 32],
    pub recomputed_result_digest: [u8; 32],
    pub witness_digest: WitnessDigest,
    pub transcript_digest: [u8; 32],
}

impl Refutation {
    /// The ONLY way to build a `Refutation`. Verifies both signatures, requires
    /// the same `(spec, input)`, and requires a genuine disagreement.
    pub fn from_evidence(
        claim: &SignedWitnessClaim,
        claim_vk: &VerifyingKey,
        recompute: &SignedRecompute,
        recompute_vk: &VerifyingKey,
    ) -> Result<Refutation, BondError> {
        verify_witness_claim(claim, claim_vk)?;
        verify_signed_recompute(recompute, recompute_vk)?;
        if claim.task_spec_hash != recompute.task_spec_hash
            || claim.input_digest != recompute.input_digest
        {
            return Err(BondError::MismatchedQuestion);
        }
        if claim.result_digest == recompute.result_digest {
            return Err(BondError::NoObjectiveFault);
        }
        Ok(Refutation {
            task_spec_hash: claim.task_spec_hash,
            input_digest: claim.input_digest,
            claimed_result_digest: claim.result_digest,
            recomputed_result_digest: recompute.result_digest,
            witness_digest: claim.witness_digest(),
            transcript_digest: recompute.transcript_digest,
        })
    }
}

/// A **signed** attestation (by the ledger / trust registry) that
/// `witness_digest` was authored by `agent_id` under `attested_under_root`. Slash
/// requires verifying this — ownership cannot be self-asserted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOwnership {
    pub witness_digest: WitnessDigest,
    pub agent_id: String,
    pub attested_under_root: LedgerRoot,
    pub kid: String,
    pub sig_b64: String,
}

pub fn canonical_ownership_bytes(o: &SignedOwnership) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(OWNERSHIP_DOMAIN);
    push_field(&mut out, &o.witness_digest.0);
    push_field(&mut out, o.agent_id.as_bytes());
    push_field(&mut out, &o.attested_under_root.0);
    push_field(&mut out, o.kid.as_bytes());
    out
}

pub fn sign_ownership(sk: &SigningKey, mut o: SignedOwnership) -> SignedOwnership {
    o.sig_b64 = sign_bytes(sk, &canonical_ownership_bytes(&o));
    o
}

pub fn verify_ownership(o: &SignedOwnership, vk: &VerifyingKey) -> Result<(), BondError> {
    verify_bytes(vk, &canonical_ownership_bytes(o), &o.sig_b64)
}

/// A **log-signed** statement of the current canonical transparency-log root, so
/// `forfeiture_on_fork` cannot be told "your root isn't canonical" by an attacker
/// — only the log key can assert the canonical root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootAttestation {
    pub root: LedgerRoot,
    pub seq: u64,
    pub kid: String,
    pub sig_b64: String,
}

pub fn canonical_root_attestation_bytes(a: &RootAttestation) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(ROOT_ATTESTATION_DOMAIN);
    push_field(&mut out, &a.root.0);
    out.extend_from_slice(&a.seq.to_be_bytes());
    push_field(&mut out, a.kid.as_bytes());
    out
}

pub fn sign_root_attestation(sk: &SigningKey, mut a: RootAttestation) -> RootAttestation {
    a.sig_b64 = sign_bytes(sk, &canonical_root_attestation_bytes(&a));
    a
}

pub fn verify_root_attestation(a: &RootAttestation, vk: &VerifyingKey) -> Result<(), BondError> {
    verify_bytes(vk, &canonical_root_attestation_bytes(a), &a.sig_b64)
}

// ── The Bond ────────────────────────────────────────────────────────────────

/// A non-custodial collateral commitment binding an agent's existing-asset stake
/// to its standing in the canonical proof-ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bond {
    pub agent_id: String,
    pub task_spec_hash: [u8; 32],
    pub bonded_micro: AmountMicro,
    pub slashed_micro: AmountMicro,
    pub pinned_root: LedgerRoot,
    pub standing: BondStanding,
    pub minted_at_seq: u64,
    pub kid: String,
    pub sig_b64: String,
}

pub fn canonical_bond_bytes(b: &Bond) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(BOND_DOMAIN);
    push_field(&mut out, b.agent_id.as_bytes());
    push_field(&mut out, &b.task_spec_hash);
    out.extend_from_slice(&b.bonded_micro.0.to_be_bytes());
    out.extend_from_slice(&b.slashed_micro.0.to_be_bytes());
    push_field(&mut out, &b.pinned_root.0);
    out.push(match b.standing {
        BondStanding::Active => 0,
        BondStanding::Slashed => 1,
        BondStanding::Released => 2,
        BondStanding::ForfeitedOnFork => 3,
    });
    out.extend_from_slice(&b.minted_at_seq.to_be_bytes());
    push_field(&mut out, b.kid.as_bytes());
    out
}

/// Mint an `Active` bond signed by the bonder.
#[allow(clippy::too_many_arguments)]
pub fn mint_bond(
    sk: &SigningKey,
    agent_id: impl Into<String>,
    task_spec_hash: [u8; 32],
    bonded_micro: AmountMicro,
    pinned_root: LedgerRoot,
    minted_at_seq: u64,
    kid: impl Into<String>,
) -> Bond {
    let mut b = Bond {
        agent_id: agent_id.into(),
        task_spec_hash,
        bonded_micro,
        slashed_micro: AmountMicro::ZERO,
        pinned_root,
        standing: BondStanding::Active,
        minted_at_seq,
        kid: kid.into(),
        sig_b64: String::new(),
    };
    b.sig_b64 = sign_bytes(sk, &canonical_bond_bytes(&b));
    b
}

pub fn verify_bond(b: &Bond, vk: &VerifyingKey) -> Result<(), BondError> {
    verify_bytes(vk, &canonical_bond_bytes(b), &b.sig_b64)
}

/// Remaining (un-slashed) collateral on a bond. `None` if malformed
/// (`slashed > bonded`).
pub fn forfeiture_amount(b: &Bond) -> Option<AmountMicro> {
    b.bonded_micro.checked_sub(b.slashed_micro)
}

/// Outcome of a slash or a fork-forfeiture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashOutcome {
    /// The updated bond (terminal standing; `slashed_micro` increased).
    pub bond: Bond,
    /// Collateral removed in THIS event.
    pub slashed_this_event: AmountMicro,
    /// Collateral returned to the bonder in THIS event.
    pub returned_micro: AmountMicro,
    /// Where the slashed collateral went (Σ == `slashed_this_event`, no skim).
    pub commons: Vec<CommonsAllocation>,
    /// The bond's original collateral. Cumulative-conservation (always true):
    /// `bond.slashed_micro (after) + returned_micro == bonded_micro`.
    pub bonded_micro: AmountMicro,
}

/// Slash a bond on an **objective** fault.
///
/// Verifies (1) the bond signature, (2) the ownership attestation, then requires
/// the refuted witness, agent, spec, and canonical root to all line up. The
/// `Refutation` is already self-authenticated. Slashes `penalty_bps` of the bond
/// (capped at the remaining collateral), routes the slashed amount to the
/// commons, and drives the bond to `Slashed`.
#[allow(clippy::too_many_arguments)]
pub fn slash(
    bond: Bond,
    bond_vk: &VerifyingKey,
    refutation: &Refutation,
    ownership: &SignedOwnership,
    ownership_vk: &VerifyingKey,
    canonical_root: LedgerRoot,
    penalty_bps: u64,
    commons_shares: &[CommonsShare],
) -> Result<SlashOutcome, BondError> {
    if bond.standing != BondStanding::Active {
        return Err(BondError::NotActive(bond.standing));
    }
    if penalty_bps == 0 || penalty_bps > BOND_BPS_SCALE {
        return Err(BondError::PenaltyOutOfRange { bps: penalty_bps });
    }
    verify_bond(&bond, bond_vk)?;
    verify_ownership(ownership, ownership_vk)?;

    // The evidence must reference THIS bond's witness, agent, spec, and root.
    if ownership.witness_digest != refutation.witness_digest
        || ownership.agent_id != bond.agent_id
        || ownership.attested_under_root != bond.pinned_root
        || bond.pinned_root != canonical_root
        || bond.task_spec_hash != refutation.task_spec_hash
    {
        return Err(BondError::EvidenceMismatch);
    }

    let bonded_micro = bond.bonded_micro;
    let remaining = forfeiture_amount(&bond).ok_or(BondError::CollateralUnderflow)?;
    let requested = bonded_micro.mul_bps(penalty_bps);
    let slashed_this_event = AmountMicro(requested.0.min(remaining.0));
    let returned_micro = AmountMicro(remaining.0 - slashed_this_event.0);

    let commons = if slashed_this_event.0 > 0 {
        route_to_commons(slashed_this_event.0, commons_shares)?
    } else {
        Vec::new()
    };

    let mut bond = bond;
    bond.slashed_micro = bond.slashed_micro.saturating_add(slashed_this_event);
    bond.standing = BondStanding::Slashed;

    Ok(SlashOutcome {
        bond,
        slashed_this_event,
        returned_micro,
        commons,
        bonded_micro,
    })
}

/// Forfeit a bond pinned to a NON-canonical (forked) root. The canonical root
/// must be presented as a **log-signed** [`RootAttestation`] so an attacker
/// cannot spoof "your root isn't canonical." The full remaining collateral is
/// forfeited to the commons.
pub fn forfeiture_on_fork(
    bond: Bond,
    bond_vk: &VerifyingKey,
    canonical: &RootAttestation,
    canonical_vk: &VerifyingKey,
    commons_shares: &[CommonsShare],
) -> Result<SlashOutcome, BondError> {
    if bond.standing != BondStanding::Active {
        return Err(BondError::NotActive(bond.standing));
    }
    verify_bond(&bond, bond_vk)?;
    verify_root_attestation(canonical, canonical_vk)?;

    if bond.pinned_root == canonical.root {
        return Err(BondError::NotForked);
    }

    let bonded_micro = bond.bonded_micro;
    let remaining = forfeiture_amount(&bond).ok_or(BondError::CollateralUnderflow)?;
    let commons = if remaining.0 > 0 {
        route_to_commons(remaining.0, commons_shares)?
    } else {
        Vec::new()
    };

    let mut bond = bond;
    bond.slashed_micro = bond.bonded_micro; // all remaining forfeited
    bond.standing = BondStanding::ForfeitedOnFork;

    Ok(SlashOutcome {
        bond,
        slashed_this_event: remaining,
        returned_micro: AmountMicro::ZERO,
        commons,
        bonded_micro,
    })
}

/// Voluntarily release a bond on the canonical ledger; remaining collateral is
/// returned in full.
pub fn release_bond(bond: Bond, bond_vk: &VerifyingKey) -> Result<SlashOutcome, BondError> {
    if bond.standing != BondStanding::Active {
        return Err(BondError::NotActive(bond.standing));
    }
    verify_bond(&bond, bond_vk)?;
    let bonded_micro = bond.bonded_micro;
    let remaining = forfeiture_amount(&bond).ok_or(BondError::CollateralUnderflow)?;
    let mut bond = bond;
    bond.standing = BondStanding::Released;
    Ok(SlashOutcome {
        bond,
        slashed_this_event: AmountMicro::ZERO,
        returned_micro: remaining,
        commons: Vec::new(),
        bonded_micro,
    })
}

/// Total un-slashed collateral across bonds **pinned to the canonical root** —
/// the value a bonder forfeits by abandoning it. Bonds on any other root
/// contribute 0 (non-portability).
pub fn total_canonical_collateral(bonds: &[Bond], canonical_root: LedgerRoot) -> AmountMicro {
    bonds
        .iter()
        .filter(|b| b.pinned_root == canonical_root && b.standing == BondStanding::Active)
        .fold(AmountMicro::ZERO, |acc, b| {
            acc.saturating_add(forfeiture_amount(b).unwrap_or(AmountMicro::ZERO))
        })
}

/// The fork-cost incentive: staying on the canonical ledger is rational iff what
/// you'd forfeit by leaving is at least the most you could gain by defecting.
pub fn staying_is_rational(forfeiture: AmountMicro, max_defection_gain: AmountMicro) -> bool {
    forfeiture.0 >= max_defection_gain.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn witness_sk() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }
    fn verifier_sk() -> SigningKey {
        SigningKey::from_bytes(&[2u8; 32])
    }
    fn ledger_sk() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }
    fn bonder_sk() -> SigningKey {
        SigningKey::from_bytes(&[4u8; 32])
    }

    const SPEC: [u8; 32] = [9u8; 32];
    const INPUT: [u8; 32] = [8u8; 32];
    const ROOT_R: LedgerRoot = LedgerRoot([7u8; 32]);
    const ROOT_FORK: LedgerRoot = LedgerRoot([6u8; 32]);

    fn shares() -> Vec<CommonsShare> {
        vec![
            CommonsShare {
                destination: "carbon".into(),
                bps: 6_000,
            },
            CommonsShare {
                destination: "affected".into(),
                bps: 2_500,
            },
            CommonsShare {
                destination: "commons".into(),
                bps: 1_500,
            },
        ]
    }

    fn claim(result: [u8; 32]) -> SignedWitnessClaim {
        sign_witness_claim(
            &witness_sk(),
            SignedWitnessClaim {
                task_spec_hash: SPEC,
                input_digest: INPUT,
                result_digest: result,
                agent_id: "wit".into(),
                kid: "wit-k".into(),
                sig_b64: String::new(),
            },
        )
    }

    fn recompute(result: [u8; 32]) -> SignedRecompute {
        sign_recompute(
            &verifier_sk(),
            SignedRecompute {
                task_spec_hash: SPEC,
                input_digest: INPUT,
                result_digest: result,
                transcript_digest: [5u8; 32],
                kid: "ver-k".into(),
                sig_b64: String::new(),
            },
        )
    }

    fn bond(amount: u64, root: LedgerRoot) -> Bond {
        mint_bond(
            &bonder_sk(),
            "wit",
            SPEC,
            AmountMicro(amount),
            root,
            1,
            "wit-k",
        )
    }

    fn ownership(wd: WitnessDigest, root: LedgerRoot) -> SignedOwnership {
        sign_ownership(
            &ledger_sk(),
            SignedOwnership {
                witness_digest: wd,
                agent_id: "wit".into(),
                attested_under_root: root,
                kid: "ledger-k".into(),
                sig_b64: String::new(),
            },
        )
    }

    fn good_refutation() -> Refutation {
        Refutation::from_evidence(
            &claim([0xAA; 32]),
            &witness_sk().verifying_key(),
            &recompute([0xBB; 32]),
            &verifier_sk().verifying_key(),
        )
        .unwrap()
    }

    #[test]
    fn objective_fault_slashes_to_commons() {
        let c = claim([0xAA; 32]);
        let refutation = good_refutation();
        let b = bond(1_000_000, ROOT_R);
        let own = ownership(c.witness_digest(), ROOT_R);
        let out = slash(
            b,
            &bonder_sk().verifying_key(),
            &refutation,
            &own,
            &ledger_sk().verifying_key(),
            ROOT_R,
            BOND_BPS_SCALE,
            &shares(),
        )
        .unwrap();
        assert_eq!(out.slashed_this_event, AmountMicro(1_000_000));
        assert_eq!(out.bond.standing, BondStanding::Slashed);
        let routed: u64 = out.commons.iter().map(|a| a.amount_micro).sum();
        assert_eq!(routed, 1_000_000, "commons no-skim");
        assert_eq!(
            out.bond.slashed_micro.0 + out.returned_micro.0,
            out.bonded_micro.0
        );
    }

    // ── RED-TEAM REGRESSION: the critical/high exploits must now FAIL ────────

    #[test]
    fn fabricated_claim_cannot_refute_honest_witness() {
        // Honest witness (claim H) + honest recompute (H) → no fault.
        let err = Refutation::from_evidence(
            &claim([0xCC; 32]),
            &witness_sk().verifying_key(),
            &recompute([0xCC; 32]),
            &verifier_sk().verifying_key(),
        )
        .unwrap_err();
        assert_eq!(err, BondError::NoObjectiveFault);

        // A different "claimed" digest signed by the attacker's key won't verify
        // against the real witness key.
        let mut forged = claim([0xCC; 32]);
        forged.result_digest = [0xFF; 32];
        let forged = sign_witness_claim(&SigningKey::from_bytes(&[42u8; 32]), forged);
        let err = Refutation::from_evidence(
            &forged,
            &witness_sk().verifying_key(),
            &recompute([0xCC; 32]),
            &verifier_sk().verifying_key(),
        )
        .unwrap_err();
        assert!(matches!(err, BondError::SignatureInvalid(_)));
    }

    #[test]
    fn fabricated_ownership_cannot_slash() {
        let c = claim([0xAA; 32]);
        let refutation = good_refutation();
        let b = bond(1_000_000, ROOT_R);
        let forged_own = sign_ownership(
            &SigningKey::from_bytes(&[42u8; 32]), // attacker, not the ledger
            SignedOwnership {
                witness_digest: c.witness_digest(),
                agent_id: "wit".into(),
                attested_under_root: ROOT_R,
                kid: "ledger-k".into(),
                sig_b64: String::new(),
            },
        );
        let err = slash(
            b,
            &bonder_sk().verifying_key(),
            &refutation,
            &forged_own,
            &ledger_sk().verifying_key(),
            ROOT_R,
            BOND_BPS_SCALE,
            &shares(),
        )
        .unwrap_err();
        assert!(matches!(err, BondError::SignatureInvalid(_)));
    }

    #[test]
    fn forfeiture_requires_log_signed_root() {
        let b = bond(1_000_000, ROOT_R);
        let forged_root = sign_root_attestation(
            &SigningKey::from_bytes(&[42u8; 32]), // not the log key
            RootAttestation {
                root: ROOT_FORK,
                seq: 2,
                kid: "log-k".into(),
                sig_b64: String::new(),
            },
        );
        let err = forfeiture_on_fork(
            b,
            &bonder_sk().verifying_key(),
            &forged_root,
            &ledger_sk().verifying_key(),
            &shares(),
        )
        .unwrap_err();
        assert!(matches!(err, BondError::SignatureInvalid(_)));
    }

    #[test]
    fn honest_bond_on_canonical_root_is_not_forfeitable() {
        let b = bond(1_000_000, ROOT_R);
        let canonical = sign_root_attestation(
            &ledger_sk(),
            RootAttestation {
                root: ROOT_R,
                seq: 2,
                kid: "log-k".into(),
                sig_b64: String::new(),
            },
        );
        let err = forfeiture_on_fork(
            b,
            &bonder_sk().verifying_key(),
            &canonical,
            &ledger_sk().verifying_key(),
            &shares(),
        )
        .unwrap_err();
        assert_eq!(err, BondError::NotForked);
    }

    #[test]
    fn forfeiture_on_real_fork_routes_full_remaining_to_commons() {
        let b = bond(1_000_000, ROOT_FORK);
        let canonical = sign_root_attestation(
            &ledger_sk(),
            RootAttestation {
                root: ROOT_R,
                seq: 2,
                kid: "log-k".into(),
                sig_b64: String::new(),
            },
        );
        let out = forfeiture_on_fork(
            b,
            &bonder_sk().verifying_key(),
            &canonical,
            &ledger_sk().verifying_key(),
            &shares(),
        )
        .unwrap();
        assert_eq!(out.slashed_this_event, AmountMicro(1_000_000));
        assert_eq!(out.bond.standing, BondStanding::ForfeitedOnFork);
        let routed: u64 = out.commons.iter().map(|a| a.amount_micro).sum();
        assert_eq!(routed, 1_000_000);
    }

    #[test]
    fn penalty_zero_rejected() {
        let c = claim([0xAA; 32]);
        let err = slash(
            bond(1_000_000, ROOT_R),
            &bonder_sk().verifying_key(),
            &good_refutation(),
            &ownership(c.witness_digest(), ROOT_R),
            &ledger_sk().verifying_key(),
            ROOT_R,
            0,
            &shares(),
        )
        .unwrap_err();
        assert!(matches!(err, BondError::PenaltyOutOfRange { bps: 0 }));
    }

    #[test]
    fn mismatched_question_rejected() {
        let c = claim([0xAA; 32]);
        let r = sign_recompute(
            &verifier_sk(),
            SignedRecompute {
                task_spec_hash: SPEC,
                input_digest: [0u8; 32], // different input
                result_digest: [0xBB; 32],
                transcript_digest: [5u8; 32],
                kid: "ver-k".into(),
                sig_b64: String::new(),
            },
        );
        let err = Refutation::from_evidence(
            &c,
            &witness_sk().verifying_key(),
            &r,
            &verifier_sk().verifying_key(),
        )
        .unwrap_err();
        assert_eq!(err, BondError::MismatchedQuestion);
    }

    #[test]
    fn non_portability_excludes_wrong_root() {
        let bonds = vec![bond(1_000_000, ROOT_R), bond(500_000, ROOT_FORK)];
        assert_eq!(
            total_canonical_collateral(&bonds, ROOT_R),
            AmountMicro(1_000_000)
        );
        assert_eq!(
            total_canonical_collateral(&bonds, ROOT_FORK),
            AmountMicro(500_000)
        );
    }

    #[test]
    fn bond_sign_verify_and_tamper() {
        let b = bond(1_000_000, ROOT_R);
        verify_bond(&b, &bonder_sk().verifying_key()).unwrap();
        let mut t = b.clone();
        t.bonded_micro = AmountMicro(2_000_000);
        assert!(verify_bond(&t, &bonder_sk().verifying_key()).is_err());
    }

    #[test]
    fn release_returns_full_collateral() {
        let out = release_bond(bond(1_000_000, ROOT_R), &bonder_sk().verifying_key()).unwrap();
        assert_eq!(out.returned_micro, AmountMicro(1_000_000));
        assert_eq!(out.slashed_this_event, AmountMicro::ZERO);
        assert_eq!(out.bond.standing, BondStanding::Released);
    }

    proptest! {
        #[test]
        fn staying_is_rational_iff_forfeiture_ge_gain(f in 0u64..u64::MAX, g in 0u64..u64::MAX) {
            prop_assert_eq!(staying_is_rational(AmountMicro(f), AmountMicro(g)), f >= g);
        }

        #[test]
        fn slash_conserves_cumulatively(amount in 1u64..u64::MAX, bps in 1u64..=10_000u64) {
            let c = claim([0xAA; 32]);
            let out = slash(
                bond(amount, ROOT_R),
                &bonder_sk().verifying_key(),
                &good_refutation(),
                &ownership(c.witness_digest(), ROOT_R),
                &ledger_sk().verifying_key(),
                ROOT_R,
                bps,
                &shares(),
            ).unwrap();
            prop_assert_eq!(out.bond.slashed_micro.0 + out.returned_micro.0, amount);
            let routed: u64 = out.commons.iter().map(|a| a.amount_micro).sum();
            prop_assert_eq!(routed, out.slashed_this_event.0);
        }
    }
}
