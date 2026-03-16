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
pub use witness::{SignatureVerifier, WitnessBundle};

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

/// The five constitutional invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstitutionalInvariant {
    CapabilityNonEscalation,
    IoConfinement,
    ResourceBoundedness,
    GovernanceMonotonicity,
    BoundedTermination,
}
