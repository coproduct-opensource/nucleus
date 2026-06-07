//! Constitutional Kernel — core types.
//!
//! This crate defines the foundational data structures for proof-carrying
//! constitutional self-amendment:
//!
//! - [`PolicyManifest`]: canonical schema for capabilities, I/O, budgets, proof requirements
//! - [`WitnessBundle`]: canonical evidence schema for amendment admission
//! - [`PatchClass`]: categorization of self-modification danger levels
//! - [`ArtifactDigest`]: content-addressed artifact references
//! - [`AdmissionDecision`]: terminal states of the amendment pipeline

pub mod digest;
pub mod manifest;
pub mod witness;

pub use digest::ArtifactDigest;
pub use manifest::{
    AmendmentRules, BudgetBounds, CapabilitySet, IoSurface, PolicyManifest, ProofRequirements,
};
pub use witness::{AdmissionMode, SignatureVerifier, WitnessBundle};

/// Classification of self-modification by danger level.
///
/// Determines which proof obligations must be satisfied before admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchClass {
    /// Config, thresholds, prompts, eval suite additions.
    Config,
    /// Scheduler, routing, work-state transitions, budget ledger logic.
    Controller,
    /// Proposer, evaluator, search strategy, scoring logic.
    Evaluator,
    /// Constitutional or kernel-adjacent changes. Requires human approval.
    Constitutional,
}

/// Terminal state of the amendment pipeline.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "decision")]
pub enum AdmissionDecision {
    Accepted {
        lineage_digest: ArtifactDigest,
        witness_digest: ArtifactDigest,
    },
    Rejected {
        reasons: Vec<RejectionReason>,
    },
    Quarantined {
        reasons: Vec<String>,
    },
    Expired,
}

/// Why an amendment was rejected.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RejectionReason {
    pub invariant: ConstitutionalInvariant,
    pub message: String,
}

/// The constitutional invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstitutionalInvariant {
    CapabilityNonEscalation,
    IoConfinement,
    ResourceBoundedness,
    GovernanceMonotonicity,
    BoundedTermination,
    /// Anti-self-weakening / anti-coup invariant.
    ///
    /// An ordinary amendment may ENABLE a governance monotonicity flag in its
    /// `amendment_rules`, but may never DISABLE one the parent had set. A flag is
    /// "weakened" iff `parent = true && child = false`.
    ///
    /// This is enforced UNCONDITIONALLY — it is never gated on any flag. That
    /// unconditionality is the crux: if the check were itself gated on a flag,
    /// that gating flag could be disabled (a coup one level up), so the
    /// two-step coup would simply recur. Without this invariant, a passing
    /// amendment can silently disarm a monotonicity flag (this step is legal),
    /// and the NEXT amendment then escalates freely under the relaxed flag — a
    /// two-step constitutional coup that the other (flag-gated) checks miss.
    AmendmentRulesMonotonicity,
}
