//! The bound on an agent's authority, as an artifact an underwriter can price.
//!
//! # The arbitrage this closes
//!
//! Insurers of autonomous agents underwrite the *blast radius* — how much an
//! agent can do before a human steps in — and the evidence they accept for it
//! today is a governance document: a description of what the agent may do,
//! sampled annually. A description has error bars. It is what the deployer
//! *says* the bound is.
//!
//! Nucleus holds something different. A delegation certificate chain, verified
//! by `portcullis::verify_certificate`, yields an effective permission lattice
//! that is a **bound** on exercised authority — `chain_attenuates_monotone` is
//! the machine-checked statement that no hop in the chain, at any length, can
//! widen it. That does not *estimate* the loss tail; it truncates its support.
//!
//! This crate projects that verified bound into the vocabulary an underwriter
//! uses, and makes the projection a receipt: the certificate chain is the
//! declared input, the radius is the claimed output, and `verify` re-walks the
//! chain and re-derives the radius. A relying party who trusts the root key —
//! and nothing else about us — reaches the same numbers.
//!
//! # Derived, never declared
//!
//! `nucleus-agent-card`'s `RuntimeGuaranteeProfile` is the other kind of
//! artifact: a profile the agent *declares* and signs. Its own documentation
//! says what that proves — "attestation is not enforcement." A [`BlastRadius`]
//! is not declared by anyone. It is a function of a certificate chain that a
//! root authority signed, so the agent cannot claim a narrower radius than it
//! holds, the deployer cannot claim a wider one than was delegated, and a
//! claim whose radius does not match its own chain fails recompute by field
//! name. The two artifacts are complementary: one says what the agent promises
//! to enforce, this one says what it was ever authorised to do.
//!
//! # What this bounds, and what it does not
//!
//! **Authority, not correctness.** An agent can do something wrong inside its
//! bound — send the right kind of request to the right host with the wrong
//! content. The radius truncates the tail of the loss distribution; it does not
//! touch the body. An underwriter will say this first if it is not said here.
//!
//! **The certificate, not the run.** The radius is what the chain *permits*.
//! That enforcement held — that exercised authority stayed inside the bound
//! over N observed actions — is a separate claim, and its evidence is the
//! receipt stream (`nucleus-envelope`, the mediation receipts), not this
//! artifact. Binding the two is the next step; conflating them would make this
//! crate assert something it does not check.
//!
//! **A bound has an expiry.** `valid_until` is part of the radius, and a claim
//! is verified *at* a declared instant, because a certificate that has expired
//! bounds nothing.
//!
//! # Every number is portcullis's own
//!
//! The projection calls `level_for`, `is_uninhabitable_vulnerable`,
//! `is_uninhabitable_enforced`, `requires_approval` and reads `budget`,
//! `time` and the sink scope. It restates no rule (G-1). If portcullis decides
//! an operation is denied, this crate reports it denied; the crate has no
//! opinion of its own about what a lattice means.

#![forbid(unsafe_code)]
// A function whose type says `-> T` and panics is lying about its type, and
// this crate produces the number an insurer prices. Denied for the shipped
// build only: `assert!` IS a panic, so denying inside `#[cfg(test)]` would
// forbid the thing tests are made of.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

use chrono::{DateTime, Utc};
use portcullis::certificate::{LatticeCertificate, VerifiedPermissions, verify_certificate};
use portcullis::{CapabilityLevel, Operation};
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use nucleus_recompute::RecomputeOutcome;

/// Domain separation for the content hash.
const RECEIPT_DOMAIN: &[u8] = b"nucleus-blast-radius/receipt/v1\0";

/// One micro-dollar in `Decimal` terms.
const MICRO_PER_USD: u32 = 1_000_000;

/// The bound, in the vocabulary an underwriter prices.
///
/// Field order is the reading order: money, then what can act without a
/// human, then what a human must approve, then whether the one combination
/// that matters most is reachable, then where side effects may land, then how
/// long any of it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlastRadius {
    /// Spend ceiling in micro-USD, **truncated** toward zero. A ceiling rounded
    /// up would report more authority than was delegated.
    pub max_spend_micro: u64,
    /// Operations the agent may perform with no human in the loop.
    pub autonomous: Vec<Operation>,
    /// Operations permitted at the reduced level.
    pub low_risk: Vec<Operation>,
    /// Operations that require an approval before they run — the human gates.
    pub human_gated: Vec<Operation>,
    /// Operations the certificate denies outright.
    pub denied: Vec<Operation>,
    /// Whether private data, untrusted content and an exfiltration sink are
    /// all reachable — the lethal trifecta. Decided by portcullis's own
    /// constraint, not restated here.
    pub trifecta_reachable: bool,
    /// Whether the constraint that forces approval on that combination is
    /// enforced. `reachable && !gated` is the shape an underwriter declines.
    pub trifecta_gated: bool,
    /// Network hosts side effects may reach. Empty means **unrestricted**, and
    /// that reading is deliberate: an empty allow-list is the widest radius,
    /// not the narrowest.
    pub allowed_hosts: Vec<String>,
    /// File path prefixes side effects may reach. Empty means unrestricted.
    pub allowed_paths: Vec<String>,
    /// Git ref patterns side effects may reach. Empty means unrestricted.
    pub allowed_git_refs: Vec<String>,
    /// When the bound stops holding, RFC 3339.
    pub valid_until: String,
    /// Delegation hops from the root authority to this holder.
    pub chain_depth: u64,
    /// The root authority's identity.
    pub root_identity: String,
    /// The holder's identity.
    pub leaf_identity: String,
}

impl BlastRadius {
    /// Project a verified chain's effective permissions into a radius.
    ///
    /// Takes a [`VerifiedPermissions`], which is sealed and cannot be built by
    /// struct literal — so a radius can only come from a chain that
    /// `verify_certificate` accepted. That is the whole guarantee: the type
    /// of the argument is where "derived, never declared" is enforced.
    #[must_use]
    pub fn of(verified: &VerifiedPermissions) -> Self {
        let lattice = verified.effective();

        let mut autonomous = Vec::new();
        let mut low_risk = Vec::new();
        let mut human_gated = Vec::new();
        let mut denied = Vec::new();
        // `Operation::ALL` is declaration-ordered, so the vectors are
        // deterministic without a sort.
        for op in Operation::ALL {
            match lattice.capabilities.level_for(op) {
                CapabilityLevel::Never => denied.push(op),
                CapabilityLevel::LowRisk => low_risk.push(op),
                CapabilityLevel::Always => autonomous.push(op),
            }
            if lattice.requires_approval(op) {
                human_gated.push(op);
            }
        }

        // `checked_mul` and truncation: a budget too large to represent is
        // reported as ZERO authority, never as a saturated maximum.
        let max_spend_micro = lattice
            .budget
            .max_cost_usd
            .checked_mul(rust_decimal::Decimal::from(MICRO_PER_USD))
            .map(|d| d.trunc())
            .and_then(|d| d.to_u64())
            .unwrap_or(0);

        let scope = verified.sink_scope();
        BlastRadius {
            max_spend_micro,
            autonomous,
            low_risk,
            human_gated,
            denied,
            trifecta_reachable: lattice.is_uninhabitable_vulnerable(),
            trifecta_gated: lattice.is_uninhabitable_enforced(),
            allowed_hosts: scope.allowed_hosts.clone(),
            allowed_paths: scope.allowed_paths.clone(),
            allowed_git_refs: scope.allowed_git_refs.clone(),
            valid_until: lattice.time.valid_until.to_rfc3339(),
            chain_depth: u64::try_from(verified.chain_depth()).unwrap_or(u64::MAX),
            root_identity: verified.root_identity().to_string(),
            leaf_identity: verified.leaf_identity().to_string(),
        }
    }

    /// The single question an underwriter asks first: can this agent be
    /// turned into a confused deputy with no human in the way?
    #[must_use]
    pub fn trifecta_ungated(&self) -> bool {
        self.trifecta_reachable && !self.trifecta_gated
    }
}

/// The receipt: the chain, the key it was verified against, the instant it
/// was verified at, and the radius that verification yields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusClaim {
    /// Declared input: the delegation certificate chain, entire.
    pub certificate: LatticeCertificate,
    /// Declared input: the root authority's Ed25519 public key, hex.
    pub root_public_key_hex: String,
    /// Declared input: the instant the chain was verified at, RFC 3339. A
    /// certificate that has expired bounds nothing, so the verification time
    /// is part of what the claim asserts.
    pub verified_at: String,
    /// Declared input: the chain-depth ceiling the verifier was run with.
    pub max_chain_depth: u64,
    /// Claimed output.
    pub claimed: BlastRadius,
}

/// Why a claim could not be issued.
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    /// The chain did not verify against the given root key at the given time.
    #[error("certificate chain did not verify: {0}")]
    Certificate(#[from] portcullis::certificate::CertificateError),
}

/// Verify the chain and project it, from declared inputs. The one decider —
/// `issue` and `verify` both call it, so they cannot disagree.
fn derive(
    certificate: &LatticeCertificate,
    root_public_key: &[u8],
    verified_at: DateTime<Utc>,
    max_chain_depth: u64,
) -> Result<BlastRadius, portcullis::certificate::CertificateError> {
    let depth = usize::try_from(max_chain_depth).unwrap_or(usize::MAX);
    let verified = verify_certificate(certificate, root_public_key, verified_at, depth)?;
    Ok(BlastRadius::of(&verified))
}

/// Issue a claim over a certificate chain.
///
/// # Errors
///
/// [`IssueError`] if the chain does not verify.
pub fn issue(
    certificate: LatticeCertificate,
    root_public_key: &[u8],
    verified_at: DateTime<Utc>,
    max_chain_depth: u64,
) -> Result<BlastRadiusClaim, IssueError> {
    let claimed = derive(&certificate, root_public_key, verified_at, max_chain_depth)?;
    Ok(BlastRadiusClaim {
        certificate,
        root_public_key_hex: hex::encode(root_public_key),
        verified_at: verified_at.to_rfc3339(),
        max_chain_depth,
        claimed,
    })
}

/// Re-verify the chain and re-derive the radius from the claim's own declared
/// inputs; compare field by field.
///
/// `Invalid` when the declared inputs cannot be assessed — an unparseable key
/// or time, or a chain that does not verify against its own declared root at
/// its own declared instant. That arm is never a pass: a claim whose chain
/// does not verify has no radius to compare.
#[must_use]
pub fn verify(claim: &BlastRadiusClaim) -> RecomputeOutcome {
    let Ok(root) = hex::decode(&claim.root_public_key_hex) else {
        return RecomputeOutcome::Invalid("root_public_key_hex is not hex".to_string());
    };
    let Ok(at) = DateTime::parse_from_rfc3339(&claim.verified_at) else {
        return RecomputeOutcome::Invalid("verified_at is not RFC 3339".to_string());
    };
    let recomputed = match derive(
        &claim.certificate,
        &root,
        at.with_timezone(&Utc),
        claim.max_chain_depth,
    ) {
        Ok(r) => r,
        Err(e) => return RecomputeOutcome::Invalid(format!("chain did not verify: {e}")),
    };
    compare(&claim.claimed, &recomputed)
}

fn compare(c: &BlastRadius, r: &BlastRadius) -> RecomputeOutcome {
    macro_rules! field {
        ($name:ident) => {
            if c.$name != r.$name {
                return RecomputeOutcome::Mismatch {
                    field: stringify!($name),
                    claimed: format!("{:?}", c.$name),
                    recomputed: format!("{:?}", r.$name),
                };
            }
        };
    }
    field!(max_spend_micro);
    field!(autonomous);
    field!(low_risk);
    field!(human_gated);
    field!(denied);
    field!(trifecta_reachable);
    field!(trifecta_gated);
    field!(allowed_hosts);
    field!(allowed_paths);
    field!(allowed_git_refs);
    field!(valid_until);
    field!(chain_depth);
    field!(root_identity);
    field!(leaf_identity);
    RecomputeOutcome::Match
}

/// Canonical, domain-tagged bytes. `None` only if serialization fails, which
/// the type says it can and this crate will not `expect` past.
#[must_use]
pub fn canonical_bytes(claim: &BlastRadiusClaim) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(RECEIPT_DOMAIN.len().saturating_add(1024));
    out.extend_from_slice(RECEIPT_DOMAIN);
    serde_json::to_writer(&mut out, claim).ok()?;
    Some(out)
}

/// SHA-256 over [`canonical_bytes`], hex — what a lineage edge's
/// `content_hash_hex` carries for a blast-radius claim.
#[must_use]
pub fn content_hash_hex(claim: &BlastRadiusClaim) -> Option<String> {
    let bytes = canonical_bytes(claim)?;
    let mut h = Sha256::new();
    h.update(bytes);
    Some(hex::encode(h.finalize()))
}
