//! Flow node types, label propagation, and flow policy checking.
//!
//! This module provides the TYPES and PURE FUNCTIONS for information
//! flow control. It does NOT contain a graph data structure — the graph
//! will live in the `portcullis` crate (Phase 3) which can use `alloc`.
//!
//! Labels propagate via Denning's lemma (join of parent labels ⊔ intrinsic).
//! Flow policy checks every outbound action node against 6 enforcement rules.
//!
//! **Current status**: types + pure functions + tests. Not yet wired into
//! `Kernel::decide()` — integration is Phase 3 of the Flow Kernel plan.

use crate::effect::EffectKind;
use crate::storage_lane::StorageLane;
use crate::{
    AuthorityLevel, ConfLevel, DerivationClass, IFCLabel, IntegLevel, Operation, ProvenanceSet,
    SinkClass,
};

// ═══════════════════════════════════════════════════════════════════════════
// Node types
// ═══════════════════════════════════════════════════════════════════════════

/// Node identifier. Currently a plain u64 for Aeneas translatability.
/// The runtime graph (Phase 3) will use content-addressed BLAKE3 hashes.
pub type NodeId = u64;

/// The kind of datum a flow node represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// User prompt — full trust and authority.
    UserPrompt,
    /// MCP tool response — internal confidentiality, untrusted integrity.
    ToolResponse,
    /// Web content — public, adversarial, no authority.
    WebContent,
    /// Memory entry — internal, untrusted, informational authority.
    MemoryRead,
    /// Memory write — outbound action that persists data.
    MemoryWrite,
    /// File read — depends on path (private data exposure).
    FileRead,
    /// Environment variable — system-level, potentially secret.
    EnvVar,
    /// Model plan step — internal reasoning node.
    ModelPlan,
    /// Secret (API key, credential) — secret, no authority.
    Secret,
    /// Outbound action (tool call, git push, PR, shell command).
    OutboundAction,
    /// Context summarization — model compresses prior context.
    /// Inherits taint from summarized content. The summary carries the
    /// join of all labels from the summarized window, preserving the
    /// maximum confidentiality and minimum integrity/authority.
    Summarization,
    /// Retry of a previously denied or failed action.
    /// Carries the same label as the original attempt — retrying does
    /// not launder taint.
    Retry,
    /// Structured API response (distinct from raw WebContent).
    /// Internal confidentiality, untrusted integrity (external service).
    HTTPResponse,
    /// Row fetched from a database.
    /// Internal confidentiality, trusted integrity (local data store).
    DatabaseRow,
    /// Content from a git object (blob, tree).
    /// Internal confidentiality, trusted integrity (version-controlled).
    GitBlob,
    /// Data retrieved from a cache layer.
    /// Public confidentiality, untrusted integrity (cache can be stale/poisoned).
    CachedDatum,
    /// Parser output bound to a schema field without model intermediation.
    /// Parents must be exclusively deterministic (non-model) nodes.
    /// This is the "air gap" that keeps AI-derived taint out of
    /// deterministic data paths (#922).
    DeterministicBind,
    /// Image content — adversarial by default (#961).
    /// Multimodal prompt injection can hide instructions in images.
    ImageContent,
    /// Audio content — adversarial by default (#961).
    AudioContent,
    /// PDF document — adversarial by default (#961).
    /// PDFs can contain hidden text, JavaScript, and form fields.
    PDFContent,
}

impl NodeKind {
    /// Returns `true` if this node kind has an AI-derived intrinsic derivation.
    ///
    /// Used by the `DeterministicBind` invariant (#1230): parents of a
    /// `DeterministicBind` must not be AI-derived, to maintain the "air gap"
    /// between AI-generated and deterministic data paths.
    pub fn is_ai_derived(&self) -> bool {
        matches!(
            self,
            Self::ModelPlan | Self::Summarization | Self::MemoryWrite
        )
    }
}

/// Intrinsic label for a node kind — the base label before propagation.
pub fn intrinsic_label(kind: NodeKind, now: u64) -> IFCLabel {
    match kind {
        NodeKind::UserPrompt => IFCLabel::user_prompt(now),
        NodeKind::ToolResponse => IFCLabel::tool_response(now),
        NodeKind::WebContent => IFCLabel::web_content(now),
        NodeKind::MemoryRead => IFCLabel::memory_entry(now),
        NodeKind::MemoryWrite => IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::MODEL,
            freshness: crate::Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Informational,
            derivation: DerivationClass::AIDerived,
        },
        NodeKind::FileRead => IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::SYSTEM,
            freshness: crate::Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::Deterministic,
        },
        NodeKind::EnvVar => IFCLabel {
            confidentiality: ConfLevel::Secret,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::SYSTEM,
            freshness: crate::Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::NoAuthority,
            derivation: DerivationClass::Deterministic,
        },
        NodeKind::ModelPlan => IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::MODEL,
            freshness: crate::Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::AIDerived,
        },
        NodeKind::Secret => IFCLabel::secret(now),
        NodeKind::OutboundAction => IFCLabel {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::MODEL,
            freshness: crate::Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::Deterministic,
        },
        // Summarization inherits from parents via propagation.
        // The intrinsic label is neutral — the join with parent labels
        // will carry forward any taint from the summarized content.
        NodeKind::Summarization => IFCLabel {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::MODEL,
            freshness: crate::Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::AIDerived,
        },
        // Retry has the same neutral intrinsic as Summarization.
        // The taint comes from parents (the original attempt's data).
        NodeKind::Retry => IFCLabel {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::MODEL,
            freshness: crate::Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::Deterministic,
        },
        // Structured API response — internal, untrusted (external service).
        NodeKind::HTTPResponse => IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Untrusted,
            provenance: ProvenanceSet::TOOL,
            freshness: crate::Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::NoAuthority,
            derivation: DerivationClass::Deterministic,
        },
        // Database row — internal, trusted (local data store).
        NodeKind::DatabaseRow => IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::SYSTEM,
            freshness: crate::Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Informational,
            derivation: DerivationClass::Deterministic,
        },
        // Git blob — internal, trusted (version-controlled content).
        NodeKind::GitBlob => IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::SYSTEM,
            freshness: crate::Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::Deterministic,
        },
        // Cached datum — public, untrusted (cache may be stale or poisoned).
        NodeKind::CachedDatum => IFCLabel {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Untrusted,
            provenance: ProvenanceSet::TOOL,
            freshness: crate::Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::NoAuthority,
            derivation: DerivationClass::Deterministic,
        },
        // DeterministicBind — parser output bound to schema field, no model touch.
        NodeKind::DeterministicBind => IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::TOOL,
            freshness: crate::Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::NoAuthority,
            derivation: DerivationClass::Deterministic,
        },
        // Multimodal content (#961) — all adversarial by default.
        // Prompt injection can hide in images, audio, and PDF documents.
        NodeKind::ImageContent | NodeKind::AudioContent | NodeKind::PDFContent => {
            IFCLabel::web_content(now)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Flow node — a datum in the causal DAG
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum number of parent nodes (causal ancestors) per node.
/// Most nodes have 1-3 parents. 8 covers all practical cases.
pub const MAX_PARENTS: usize = 8;

/// A node in the causal DAG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowNode {
    pub id: NodeId,
    pub kind: NodeKind,
    pub label: IFCLabel,
    pub parent_count: u8,
    pub parents: [NodeId; MAX_PARENTS],
    pub operation: Option<Operation>,
    /// The sink class for this node, if it's an outbound action.
    /// When set, `check_flow` uses sink-class-based authority/integrity
    /// requirements instead of the legacy per-Operation thresholds.
    pub sink_class: Option<SinkClass>,
    /// Computation-step effect classification (#775).
    pub effect_kind: Option<EffectKind>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Label propagation — Denning's lemma
// ═══════════════════════════════════════════════════════════════════════════

/// Propagate labels through the DAG: join all parent labels with intrinsic.
///
/// This is Denning's fundamental lemma generalized to our 6-dimensional
/// product lattice. The result is always ≥ each input (monotone).
pub fn propagate_label(parent_labels: &[IFCLabel], intrinsic: IFCLabel) -> IFCLabel {
    let mut result = intrinsic;
    for parent in parent_labels {
        result = result.join(*parent);
    }
    result
}

// ═══════════════════════════════════════════════════════════════════════════
// Flow policy — the 5 enforcement rules
// ═══════════════════════════════════════════════════════════════════════════

/// Why a flow was blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowDenyReason {
    /// Secret data flowing to an external sink.
    Exfiltration,
    /// Low-authority data trying to steer a privileged action.
    AuthorityEscalation,
    /// Untrusted data used where trusted data is required.
    IntegrityViolation,
    /// Expired data used in a decision.
    FreshnessExpired,
    /// AI-derived or mixed-derivation data flowing to a verified sink.
    ///
    /// Verified sinks (e.g., `GitPush`, `GitCommit`, `PRCommentWrite`)
    /// require data that passes the [`StorageLane::Verified`] gate —
    /// only `Deterministic` and `HumanPromoted` derivations are accepted.
    /// This prevents AI-generated content from reaching publish vectors
    /// without explicit human promotion.
    DerivationViolation,
}

impl FlowDenyReason {
    /// Stable byte tag for deterministic hashing.
    ///
    /// These values are part of the receipt chain's hash commitment and
    /// MUST NOT change once assigned. New variants get the next unused tag.
    ///
    /// | Tag  | Variant              |
    /// |------|----------------------|
    /// | 0x01 | Exfiltration         |
    /// | 0x02 | AuthorityEscalation  |
    /// | 0x03 | IntegrityViolation   |
    /// | 0x04 | FreshnessExpired     |
    /// | 0x05 | DerivationViolation  |
    pub const fn canonical_tag(self) -> u8 {
        match self {
            Self::Exfiltration => 0x01,
            Self::AuthorityEscalation => 0x02,
            Self::IntegrityViolation => 0x03,
            Self::FreshnessExpired => 0x04,
            Self::DerivationViolation => 0x05,
        }
    }
}

/// Result of checking a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowVerdict {
    /// Flow is permitted.
    Allow,
    /// Flow is blocked with a reason.
    Deny(FlowDenyReason),
}

impl FlowVerdict {
    /// Stable byte encoding for deterministic hashing.
    ///
    /// Returns a fixed-length 2-byte tag: `[discriminant, deny_reason]`.
    /// - `Allow`       → `[0x00, 0x00]`
    /// - `Deny(reason)` → `[0x01, reason.canonical_tag()]`
    ///
    /// These values are part of the receipt chain's hash commitment and
    /// MUST NOT change once assigned. See [`FlowDenyReason::canonical_tag`]
    /// for the deny-reason tags.
    pub const fn canonical_bytes(self) -> [u8; 2] {
        match self {
            Self::Allow => [0x00, 0x00],
            Self::Deny(reason) => [0x01, reason.canonical_tag()],
        }
    }
}

/// Verdict from quarantine-aware flow checking.
///
/// Extends `FlowVerdict` with artifact-granular quarantine information.
/// When a node or any of its causal ancestors is quarantined, the action
/// is blocked regardless of its IFC label — the quarantine must be
/// explicitly released before the artifact can flow to sinks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineVerdict {
    /// Flow is permitted and no ancestors are quarantined.
    Clean(FlowVerdict),
    /// Flow is blocked because a causal ancestor is quarantined.
    /// Contains the node IDs of the quarantined ancestors in the causal chain.
    Quarantined {
        /// The quarantined ancestor node IDs that caused the block.
        quarantined_ancestors: Vec<NodeId>,
        /// The underlying flow verdict (what check_flow would have returned
        /// ignoring quarantine). Useful for audit — shows whether the action
        /// would also have been blocked by IFC rules.
        underlying_verdict: FlowVerdict,
    },
}

/// Result of a trusted ancestry check for compartment transitions.
///
/// When transitioning to Execute or Breakglass, data flowing to privileged
/// sinks must have "trusted ancestry" — every causal ancestor must have
/// integrity >= `Untrusted` (i.e., not `Adversarial`). This prevents
/// adversarial web content from reaching execution sinks even if the
/// current session's flow graph was reset on compartment transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustAncestryResult {
    /// All ancestors have integrity >= Untrusted. The node's data
    /// provenance chain is clean for Execute/Breakglass compartments.
    Trusted,
    /// One or more ancestors have Adversarial integrity. The node
    /// cannot flow to privileged sinks in Execute/Breakglass without
    /// explicit declassification.
    Untrusted {
        /// The specific node IDs with Adversarial integrity in the
        /// causal ancestry. Useful for audit trails and error messages.
        tainted_ancestors: Vec<NodeId>,
    },
}

/// Minimum authority required for an operation to proceed.
pub fn required_authority(op: Operation) -> AuthorityLevel {
    match op {
        // Write/exec operations require at least Suggestive authority
        Operation::WriteFiles
        | Operation::EditFiles
        | Operation::RunBash
        | Operation::GitCommit
        | Operation::GitPush
        | Operation::CreatePr
        | Operation::ManagePods
        | Operation::SpawnAgent => AuthorityLevel::Suggestive,
        // Read operations require no authority — pure observation
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => {
            AuthorityLevel::NoAuthority
        }
        // Web operations: WebFetch can exfiltrate via URL params, requires Suggestive
        Operation::WebFetch => AuthorityLevel::Suggestive,
        // WebSearch is read-only observation
        Operation::WebSearch => AuthorityLevel::NoAuthority,
    }
}

/// Minimum integrity required for an operation to proceed.
pub fn required_integrity(op: Operation) -> IntegLevel {
    match op {
        // Exfil operations require trusted integrity
        Operation::GitPush | Operation::CreatePr => IntegLevel::Trusted,
        // Write operations require at least untrusted
        Operation::WriteFiles
        | Operation::EditFiles
        | Operation::RunBash
        | Operation::GitCommit
        | Operation::ManagePods => IntegLevel::Untrusted,
        // Read/web operations have no integrity requirement
        _ => IntegLevel::Adversarial,
    }
}

/// Check whether a flow node's action is permitted by the flow policy.
///
/// Enforces 7 rules:
/// 1. No-exfil: secret data cannot flow to external sinks (incl. WebFetch)
/// 2. No-authority-escalation: NoAuthority data cannot steer privileged actions
/// 3. No-integrity-laundering: untrusted data cannot reach trusted-required sinks
/// 4. No-web-exfil: web-provenance data cannot reach exfil sinks
/// 5. Freshness: expired data cannot be used in decisions
/// 6. Derivation-sink compatibility: AI-derived data cannot reach verified sinks
/// 7. Monotonicity: implicit (enforced by propagate_label's join)
///
/// When a [`SinkClass`] is present on the node, authority and integrity
/// requirements come from the sink class. Otherwise, the legacy per-Operation
/// thresholds are used for backward compatibility.
pub fn check_flow(node: &FlowNode, now: u64) -> FlowVerdict {
    let label = node.label;

    // Non-action nodes (observations, plan steps) are not checked — they
    // don't perform side effects. The check happens when the node is used
    // as a causal ancestor of an OutboundAction node.
    let op = match node.operation {
        Some(op) => op,
        None => {
            // Even without an operation, check freshness — expired data
            // should not be used in any context.
            if label.freshness.is_expired_at(now) {
                return FlowVerdict::Deny(FlowDenyReason::FreshnessExpired);
            }
            return FlowVerdict::Allow;
        }
    };

    // Resolve authority/integrity/exfil requirements from SinkClass when
    // available, otherwise fall back to legacy per-Operation thresholds.
    let (is_exfil, req_auth, req_integ) = match node.sink_class {
        Some(sink) => (
            sink.is_exfil_vector(),
            sink.required_authority(),
            sink.required_integrity(),
        ),
        None => {
            let is_exfil = crate::is_exfil_operation(op) || op == Operation::WebFetch;
            (is_exfil, required_authority(op), required_integrity(op))
        }
    };

    // Rule 1: No-exfil — secret data to external sinks.
    if label.confidentiality >= ConfLevel::Secret && is_exfil {
        return FlowVerdict::Deny(FlowDenyReason::Exfiltration);
    }

    // Rule 2: No-authority-escalation
    if label.authority < req_auth {
        return FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation);
    }

    // Rule 3: No-integrity-laundering
    if label.integrity < req_integ {
        return FlowVerdict::Deny(FlowDenyReason::IntegrityViolation);
    }

    // Rule 4: Provenance check — web-sourced data cannot reach exfil sinks
    if label.provenance.contains(ProvenanceSet::WEB) && is_exfil {
        return FlowVerdict::Deny(FlowDenyReason::Exfiltration);
    }

    // Rule 5: Freshness check
    if label.freshness.is_expired_at(now) {
        return FlowVerdict::Deny(FlowDenyReason::FreshnessExpired);
    }

    // Rule 6: Derivation-sink compatibility — AI-derived data cannot reach
    // verified sinks (GitPush, GitCommit, PRCommentWrite) without human
    // promotion. Uses the StorageLane::Verified gate as the acceptance
    // predicate: only Deterministic and HumanPromoted derivations pass.
    //
    // Fail-closed (#1227): when sink_class is None but the operation
    // unambiguously maps to a verified sink, infer the sink class so Rule 6
    // is never silently skipped. Any FlowNode that sets
    // `operation: Some(Operation::GitPush)` but leaves `sink_class: None`
    // would otherwise bypass this check entirely.
    let effective_sink = node
        .sink_class
        .or_else(|| infer_sink_class_for_derivation(op));
    if let Some(sink) = effective_sink
        && sink.requires_verified_derivation()
        && !StorageLane::Verified.accepts(label.derivation)
    {
        return FlowVerdict::Deny(FlowDenyReason::DerivationViolation);
    }

    FlowVerdict::Allow
}

/// Infer the sink class for derivation checking when `sink_class` is not
/// explicitly set on the [`FlowNode`] (#1227).
///
/// Only operations that unambiguously imply a verified sink are inferred —
/// `GitPush`, `GitCommit`, and `CreatePr`. All other operations return `None`
/// so their derivation is unconstrained (they may or may not be verified sinks
/// depending on context; callers that know the context should set `sink_class`
/// explicitly).
///
/// This is used **only** as a fallback for Rule 6. Rules 1–5 continue to use
/// the legacy per-Operation authority/integrity thresholds when `sink_class`
/// is absent, to preserve backward compatibility.
fn infer_sink_class_for_derivation(op: Operation) -> Option<SinkClass> {
    match op {
        Operation::GitPush => Some(SinkClass::GitPush),
        Operation::GitCommit => Some(SinkClass::GitCommit),
        Operation::CreatePr => Some(SinkClass::PRCommentWrite),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Kani BMC harnesses — bounded model checking of flow enforcement rules
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(kani)]
mod kani_proofs {
    use super::*;
    use crate::*;

    /// Generate a symbolic ConfLevel.
    fn any_conf() -> ConfLevel {
        let v: u8 = kani::any();
        kani::assume(v <= 2);
        match v {
            0 => ConfLevel::Public,
            1 => ConfLevel::Internal,
            _ => ConfLevel::Secret,
        }
    }

    /// Generate a symbolic IntegLevel.
    fn any_integ() -> IntegLevel {
        let v: u8 = kani::any();
        kani::assume(v <= 2);
        match v {
            0 => IntegLevel::Adversarial,
            1 => IntegLevel::Untrusted,
            _ => IntegLevel::Trusted,
        }
    }

    /// Generate a symbolic AuthorityLevel.
    fn any_auth() -> AuthorityLevel {
        let v: u8 = kani::any();
        kani::assume(v <= 3);
        match v {
            0 => AuthorityLevel::NoAuthority,
            1 => AuthorityLevel::Informational,
            2 => AuthorityLevel::Suggestive,
            _ => AuthorityLevel::Directive,
        }
    }

    /// Generate a symbolic DerivationClass.
    fn any_derivation() -> crate::DerivationClass {
        let v: u8 = kani::any();
        kani::assume(v <= 4);
        match v {
            0 => crate::DerivationClass::Deterministic,
            1 => crate::DerivationClass::AIDerived,
            2 => crate::DerivationClass::Mixed,
            3 => crate::DerivationClass::HumanPromoted,
            _ => crate::DerivationClass::OpaqueExternal,
        }
    }

    /// Generate a symbolic Operation.
    fn any_operation() -> Operation {
        let v: u8 = kani::any();
        kani::assume(v < 12);
        Operation::ALL[v as usize]
    }

    /// Generate a symbolic IFCLabel.
    fn any_label() -> IFCLabel {
        IFCLabel {
            confidentiality: any_conf(),
            integrity: any_integ(),
            provenance: ProvenanceSet(kani::any::<u8>() & 0x3F),
            freshness: Freshness {
                observed_at: kani::any(),
                ttl_secs: kani::any(),
            },
            authority: any_auth(),
            derivation: any_derivation(),
        }
    }

    fn any_node(op: Option<Operation>) -> FlowNode {
        FlowNode {
            id: kani::any(),
            kind: NodeKind::OutboundAction,
            label: any_label(),
            parent_count: 0,
            parents: [0; MAX_PARENTS],
            operation: op,
            sink_class: None,
            effect_kind: None,
        }
    }

    /// **F1 — Secret data never reaches exfil sinks.**
    ///
    /// For any symbolic operation and label: if confidentiality is Secret
    /// and the operation is an exfil vector (including WebFetch), check_flow
    /// returns Deny(Exfiltration).
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_no_secret_exfil() {
        let op = any_operation();
        let is_exfil = crate::is_exfil_operation(op) || op == Operation::WebFetch;
        kani::assume(is_exfil);

        let mut label = any_label();
        label.confidentiality = ConfLevel::Secret;

        let node = FlowNode {
            id: 0,
            kind: NodeKind::OutboundAction,
            label,
            parent_count: 0,
            parents: [0; MAX_PARENTS],
            operation: Some(op),
            sink_class: None,
            effect_kind: None,
        };

        let now: u64 = kani::any();
        kani::assume(!label.freshness.is_expired_at(now));

        match check_flow(&node, now) {
            FlowVerdict::Deny(FlowDenyReason::Exfiltration) => {} // expected
            FlowVerdict::Deny(_) => {} // another rule caught it first — also safe
            FlowVerdict::Allow => panic!("Secret data reached exfil sink!"),
        }
    }

    /// **F2 — NoAuthority data cannot steer privileged actions.**
    ///
    /// For any symbolic operation that requires >= Suggestive authority:
    /// if the label has NoAuthority, check_flow never returns Allow.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_authority_confinement() {
        let op = any_operation();
        let required = required_authority(op);
        kani::assume(required >= AuthorityLevel::Suggestive);

        let mut label = any_label();
        label.authority = AuthorityLevel::NoAuthority;

        let node = FlowNode {
            id: 0,
            kind: NodeKind::OutboundAction,
            label,
            parent_count: 0,
            parents: [0; MAX_PARENTS],
            operation: Some(op),
            sink_class: None,
            effect_kind: None,
        };

        let now: u64 = kani::any();
        kani::assume(!label.freshness.is_expired_at(now));

        // Must not be allowed — some deny rule must fire
        assert!(
            !matches!(check_flow(&node, now), FlowVerdict::Allow),
            "NoAuthority data steered a privileged action!"
        );
    }

    /// **F3 — Adversarial data cannot reach trusted-required sinks.**
    ///
    /// For any symbolic operation requiring Trusted integrity: if the label
    /// has Adversarial integrity, check_flow never returns Allow.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_no_integrity_laundering() {
        let op = any_operation();
        let required = required_integrity(op);
        kani::assume(required == IntegLevel::Trusted);

        let mut label = any_label();
        label.integrity = IntegLevel::Adversarial;

        let node = FlowNode {
            id: 0,
            kind: NodeKind::OutboundAction,
            label,
            parent_count: 0,
            parents: [0; MAX_PARENTS],
            operation: Some(op),
            sink_class: None,
            effect_kind: None,
        };

        let now: u64 = kani::any();
        kani::assume(!label.freshness.is_expired_at(now));

        assert!(
            !matches!(check_flow(&node, now), FlowVerdict::Allow),
            "Adversarial data reached trusted-required sink!"
        );
    }

    /// **F4 — Label propagation is monotone.**
    ///
    /// For any two symbolic labels and any intrinsic label:
    /// propagate_label([a, b], intrinsic) >= a and >= b on covariant dims,
    /// and <= a and <= b on contravariant dims.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_propagation_monotone() {
        let a = any_label();
        let b = any_label();
        let intrinsic = any_label();
        let result = propagate_label(&[a, b], intrinsic);

        // Covariant: result >= max of inputs
        assert!(result.confidentiality >= a.confidentiality);
        assert!(result.confidentiality >= b.confidentiality);

        // Contravariant: result <= min of inputs
        assert!(result.integrity <= a.integrity);
        assert!(result.integrity <= b.integrity);
        assert!(result.authority <= a.authority);
        assert!(result.authority <= b.authority);
    }

    /// **F4b — propagate_label is monotone via lattice order.**
    ///
    /// For any parent label, the propagated result is ≥ that parent
    /// in the IFCLabel product lattice ordering. This is the formal
    /// lattice-theoretic version of F4 using IFCLabel::leq.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_propagation_monotone_leq() {
        let parent = any_label();
        let intrinsic = any_label();

        // Fix freshness to make leq tractable (freshness checked separately)
        let parent = IFCLabel {
            freshness: crate::Freshness {
                observed_at: 100,
                ttl_secs: 0,
            },
            ..parent
        };
        let intrinsic = IFCLabel {
            freshness: crate::Freshness {
                observed_at: 100,
                ttl_secs: 0,
            },
            ..intrinsic
        };

        let result = propagate_label(&[parent], intrinsic);

        // The result must be ≥ the parent in the lattice order.
        // join(intrinsic, parent) ≥ parent always holds because join is LUB.
        assert!(parent.leq(result));
        // Also ≥ intrinsic
        assert!(intrinsic.leq(result));
    }

    /// **F5 — Legitimate user actions are allowed.**
    ///
    /// For any operation: a fully trusted, user-sourced, non-expired,
    /// non-secret label with Directive authority is always allowed.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_trusted_user_allowed() {
        let op = any_operation();
        let label = IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::USER,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::Deterministic,
        };

        let node = FlowNode {
            id: 0,
            kind: NodeKind::OutboundAction,
            label,
            parent_count: 0,
            parents: [0; MAX_PARENTS],
            operation: Some(op),
            sink_class: None,
            effect_kind: None,
        };

        assert_eq!(check_flow(&node, 2000), FlowVerdict::Allow);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Freshness;

    fn make_node(kind: NodeKind, label: IFCLabel, op: Option<Operation>) -> FlowNode {
        FlowNode {
            id: 0,
            kind,
            label,
            parent_count: 0,
            parents: [0; MAX_PARENTS],
            operation: op,
            sink_class: None,
            effect_kind: None,
        }
    }

    fn make_node_with_sink(
        kind: NodeKind,
        label: IFCLabel,
        op: Option<Operation>,
        sink: SinkClass,
    ) -> FlowNode {
        FlowNode {
            id: 0,
            kind,
            label,
            parent_count: 0,
            parents: [0; MAX_PARENTS],
            operation: op,
            sink_class: Some(sink),
            effect_kind: None,
        }
    }

    // ── Propagation tests ────────────────────────────────────────────

    #[test]
    fn propagate_no_parents_returns_intrinsic() {
        let intrinsic = IFCLabel::web_content(1000);
        let result = propagate_label(&[], intrinsic);
        assert_eq!(result, intrinsic);
    }

    #[test]
    fn propagate_single_parent_joins() {
        let parent = IFCLabel::user_prompt(1000);
        let intrinsic = IFCLabel::web_content(1000);
        let result = propagate_label(&[parent], intrinsic);
        // Authority should be min (NoAuthority from web)
        assert_eq!(result.authority, AuthorityLevel::NoAuthority);
        // Integrity should be min (Adversarial from web)
        assert_eq!(result.integrity, IntegLevel::Adversarial);
        // Confidentiality should be max (Internal from user)
        assert_eq!(result.confidentiality, ConfLevel::Internal);
    }

    #[test]
    fn propagate_multiple_parents_accumulates() {
        let user = IFCLabel::user_prompt(1000);
        let web = IFCLabel::web_content(1000);
        let secret = IFCLabel::secret(1000);
        let intrinsic = intrinsic_label(NodeKind::OutboundAction, 1000);
        let result = propagate_label(&[user, web, secret], intrinsic);
        assert_eq!(result.confidentiality, ConfLevel::Secret);
        assert_eq!(result.integrity, IntegLevel::Adversarial);
        assert_eq!(result.authority, AuthorityLevel::NoAuthority);
    }

    // ── Flow policy tests ────────────────────────────────────────────

    #[test]
    fn flow_allows_trusted_user_action() {
        let label = IFCLabel::user_prompt(1000);
        let node = make_node(NodeKind::OutboundAction, label, Some(Operation::WriteFiles));
        assert_eq!(check_flow(&node, 2000), FlowVerdict::Allow);
    }

    #[test]
    fn flow_blocks_secret_exfiltration() {
        let label = IFCLabel::secret(1000);
        let node = make_node(NodeKind::OutboundAction, label, Some(Operation::GitPush));
        assert_eq!(
            check_flow(&node, 2000),
            FlowVerdict::Deny(FlowDenyReason::Exfiltration)
        );
    }

    #[test]
    fn flow_blocks_authority_escalation() {
        // Web content (NoAuthority) trying to write files (requires Suggestive)
        let label = IFCLabel::web_content(1000);
        let node = make_node(NodeKind::OutboundAction, label, Some(Operation::WriteFiles));
        assert_eq!(
            check_flow(&node, 2000),
            FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation)
        );
    }

    #[test]
    fn flow_blocks_integrity_laundering() {
        // Adversarial data with sufficient authority, trying to git push (requires Trusted integrity)
        let label = IFCLabel {
            integrity: IntegLevel::Adversarial,
            authority: AuthorityLevel::Directive,
            ..IFCLabel::default()
        };
        let node = make_node(NodeKind::OutboundAction, label, Some(Operation::GitPush));
        assert_eq!(
            check_flow(&node, 2000),
            FlowVerdict::Deny(FlowDenyReason::IntegrityViolation)
        );
    }

    #[test]
    fn flow_blocks_expired_data() {
        let mut label = IFCLabel::user_prompt(1000);
        label.freshness.ttl_secs = 60; // expires at 1060
        let node = make_node(NodeKind::OutboundAction, label, Some(Operation::WriteFiles));
        assert_eq!(
            check_flow(&node, 2000), // now=2000 > 1060
            FlowVerdict::Deny(FlowDenyReason::FreshnessExpired)
        );
    }

    // ── Invariant exploit scenario ───────────────────────────────────

    #[test]
    fn invariant_exploit_end_to_end() {
        // Simulate: malicious GitHub issue → agent reads private repo → tries to exfil
        let now = 1000;

        // Step 1: Agent reads a public GitHub issue (adversarial web content)
        let issue_label = IFCLabel::web_content(now);

        // Step 2: Agent reads private repo file (trusted, internal)
        let repo_label = IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::SYSTEM,
            freshness: crate::Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::Deterministic,
        };

        // Step 3: Agent's plan node combines both (propagation)
        let plan_label = propagate_label(
            &[issue_label, repo_label],
            intrinsic_label(NodeKind::ModelPlan, now),
        );

        // The plan has NoAuthority (from issue) and Adversarial integrity
        assert_eq!(plan_label.authority, AuthorityLevel::NoAuthority);
        assert_eq!(plan_label.integrity, IntegLevel::Adversarial);

        // Step 4: Agent tries to create a PR with the combined data
        let action_label = propagate_label(
            &[plan_label],
            intrinsic_label(NodeKind::OutboundAction, now),
        );
        let action = make_node(
            NodeKind::OutboundAction,
            action_label,
            Some(Operation::CreatePr),
        );

        // BLOCKED: authority escalation (NoAuthority < Suggestive required)
        assert_eq!(
            check_flow(&action, now + 10),
            FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation)
        );
    }

    // ── Unit 42 memory poisoning scenario ────────────────────────────

    #[test]
    fn memory_poisoning_blocked() {
        let now = 1000;

        // Step 1: Malicious web page poisons memory
        let web_label = IFCLabel::web_content(now);

        // Step 2: Memory write inherits web label (adversarial, no authority)
        let memory_write_label =
            propagate_label(&[web_label], intrinsic_label(NodeKind::MemoryWrite, now));

        // Step 3: Later session reads memory (tainted)
        let memory_read_label = propagate_label(
            &[memory_write_label],
            intrinsic_label(NodeKind::MemoryRead, now + 86400),
        );

        // The memory entry is adversarial and has no authority
        assert_eq!(memory_read_label.integrity, IntegLevel::Adversarial);
        assert_eq!(memory_read_label.authority, AuthorityLevel::NoAuthority);

        // Step 4: Agent tries to exfil conversation via the tainted memory
        let exfil_label = propagate_label(
            &[memory_read_label, IFCLabel::user_prompt(now + 86400)],
            intrinsic_label(NodeKind::OutboundAction, now + 86400),
        );
        let exfil = make_node(
            NodeKind::OutboundAction,
            exfil_label,
            Some(Operation::GitPush),
        );

        // BLOCKED: authority escalation AND integrity violation
        assert!(matches!(
            check_flow(&exfil, now + 86400),
            FlowVerdict::Deny(_)
        ));
    }

    // ── SinkClass-based flow policy tests ───────────────────────────

    #[test]
    fn sink_class_allows_trusted_workspace_write() {
        let label = IFCLabel::user_prompt(1000);
        let node = make_node_with_sink(
            NodeKind::OutboundAction,
            label,
            Some(Operation::WriteFiles),
            SinkClass::WorkspaceWrite,
        );
        assert_eq!(check_flow(&node, 2000), FlowVerdict::Allow);
    }

    #[test]
    fn sink_class_blocks_secret_http_egress() {
        let label = IFCLabel::secret(1000);
        let node = make_node_with_sink(
            NodeKind::OutboundAction,
            label,
            Some(Operation::RunBash),
            SinkClass::HTTPEgress,
        );
        assert_eq!(
            check_flow(&node, 2000),
            FlowVerdict::Deny(FlowDenyReason::Exfiltration)
        );
    }

    #[test]
    fn sink_class_blocks_adversarial_git_push() {
        // Adversarial integrity data trying to git push (requires Trusted)
        let label = IFCLabel {
            integrity: IntegLevel::Adversarial,
            authority: AuthorityLevel::Directive,
            ..IFCLabel::default()
        };
        let node = make_node_with_sink(
            NodeKind::OutboundAction,
            label,
            Some(Operation::GitPush),
            SinkClass::GitPush,
        );
        assert_eq!(
            check_flow(&node, 2000),
            FlowVerdict::Deny(FlowDenyReason::IntegrityViolation)
        );
    }

    #[test]
    fn sink_class_secret_read_allows_no_authority() {
        // SecretRead requires NoAuthority — even data with no authority can read secrets
        let label = IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::USER,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::NoAuthority,
            derivation: DerivationClass::Deterministic,
        };
        let node = make_node_with_sink(
            NodeKind::OutboundAction,
            label,
            Some(Operation::ReadFiles),
            SinkClass::SecretRead,
        );
        // SecretRead is not an exfil vector and needs no authority
        assert_eq!(check_flow(&node, 2000), FlowVerdict::Allow);
    }

    #[test]
    fn sink_class_bash_with_url_reclassified_as_egress() {
        // RunBash operation but classified as HTTPEgress (detected curl)
        let label = IFCLabel {
            confidentiality: ConfLevel::Secret,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::SYSTEM,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::Deterministic,
        };
        let node = make_node_with_sink(
            NodeKind::OutboundAction,
            label,
            Some(Operation::RunBash),
            SinkClass::HTTPEgress,
        );
        // HTTPEgress is exfil vector + secret data → blocked
        assert_eq!(
            check_flow(&node, 2000),
            FlowVerdict::Deny(FlowDenyReason::Exfiltration)
        );
    }

    #[test]
    fn sink_class_bash_without_url_allows_trusted() {
        // RunBash classified as BashExec (no network detected)
        let label = IFCLabel::user_prompt(1000);
        let node = make_node_with_sink(
            NodeKind::OutboundAction,
            label,
            Some(Operation::RunBash),
            SinkClass::BashExec,
        );
        // BashExec is NOT an exfil vector, user has authority → allowed
        assert_eq!(check_flow(&node, 2000), FlowVerdict::Allow);
    }

    #[test]
    fn sink_class_web_provenance_blocked_at_pr() {
        // Web-sourced data trying to create a PR (PRCommentWrite is exfil)
        let label = IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::WEB,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::OpaqueExternal,
        };
        let node = make_node_with_sink(
            NodeKind::OutboundAction,
            label,
            Some(Operation::CreatePr),
            SinkClass::PRCommentWrite,
        );
        assert_eq!(
            check_flow(&node, 2000),
            FlowVerdict::Deny(FlowDenyReason::Exfiltration)
        );
    }

    // ── Rule 6 fail-closed: derivation check without sink_class (#1227) ──

    fn ai_derived_label(now: u64) -> IFCLabel {
        IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::MODEL,
            freshness: Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::AIDerived,
        }
    }

    #[test]
    fn rule6_ai_derived_git_push_blocked_without_sink_class() {
        // Before fix: sink_class=None skipped Rule 6; AI-derived content reached GitPush.
        // After fix: infer_sink_class_for_derivation fills in SinkClass::GitPush.
        let label = ai_derived_label(1000);
        let node = make_node(NodeKind::OutboundAction, label, Some(Operation::GitPush));
        assert_eq!(
            node.sink_class, None,
            "precondition: make_node sets sink_class=None"
        );
        assert_eq!(
            check_flow(&node, 2000),
            FlowVerdict::Deny(FlowDenyReason::DerivationViolation),
            "AI-derived content must not reach GitPush even when sink_class is None"
        );
    }

    #[test]
    fn rule6_ai_derived_git_commit_blocked_without_sink_class() {
        let label = ai_derived_label(1000);
        let node = make_node(NodeKind::OutboundAction, label, Some(Operation::GitCommit));
        assert_eq!(
            check_flow(&node, 2000),
            FlowVerdict::Deny(FlowDenyReason::DerivationViolation),
            "AI-derived content must not reach GitCommit even when sink_class is None"
        );
    }

    #[test]
    fn rule6_ai_derived_create_pr_blocked_without_sink_class() {
        let label = ai_derived_label(1000);
        let node = make_node(NodeKind::OutboundAction, label, Some(Operation::CreatePr));
        assert_eq!(
            check_flow(&node, 2000),
            FlowVerdict::Deny(FlowDenyReason::DerivationViolation),
            "AI-derived content must not reach CreatePr even when sink_class is None"
        );
    }

    #[test]
    fn rule6_deterministic_git_push_allowed_without_sink_class() {
        // Regression guard: deterministic content must still pass Rule 6.
        let label = IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::USER,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::Deterministic,
        };
        let node = make_node(NodeKind::OutboundAction, label, Some(Operation::GitPush));
        assert_eq!(check_flow(&node, 2000), FlowVerdict::Allow);
    }

    #[test]
    fn rule6_human_promoted_git_push_allowed_without_sink_class() {
        // HumanPromoted also passes StorageLane::Verified.
        let label = IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::USER,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::HumanPromoted,
        };
        let node = make_node(NodeKind::OutboundAction, label, Some(Operation::GitPush));
        assert_eq!(check_flow(&node, 2000), FlowVerdict::Allow);
    }

    #[test]
    fn rule6_ai_derived_write_files_not_blocked_without_sink_class() {
        // Non-verified-sink operations are NOT inferred — WriteFiles has no
        // derivation constraint when sink_class is absent.
        let label = ai_derived_label(1000);
        let node = make_node(NodeKind::OutboundAction, label, Some(Operation::WriteFiles));
        // WriteFiles is not a verified sink; only integrity/authority/freshness apply.
        // user_prompt has Trusted integrity + Directive authority → allowed.
        assert_eq!(check_flow(&node, 2000), FlowVerdict::Allow);
    }

    // ── canonical_bytes / canonical_tag stability tests (#747) ──────

    #[test]
    fn deny_reason_tags_are_unique() {
        let reasons = [
            FlowDenyReason::Exfiltration,
            FlowDenyReason::AuthorityEscalation,
            FlowDenyReason::IntegrityViolation,
            FlowDenyReason::FreshnessExpired,
            FlowDenyReason::DerivationViolation,
        ];
        let tags: Vec<u8> = reasons.iter().map(|r| r.canonical_tag()).collect();
        for (i, t) in tags.iter().enumerate() {
            for (j, u) in tags.iter().enumerate() {
                if i != j {
                    assert_ne!(t, u, "tags for variants {i} and {j} must differ");
                }
            }
        }
    }

    #[test]
    fn deny_reason_tags_are_nonzero() {
        // 0x00 is reserved for Allow's padding byte
        let reasons = [
            FlowDenyReason::Exfiltration,
            FlowDenyReason::AuthorityEscalation,
            FlowDenyReason::IntegrityViolation,
            FlowDenyReason::FreshnessExpired,
            FlowDenyReason::DerivationViolation,
        ];
        for r in &reasons {
            assert_ne!(r.canonical_tag(), 0x00, "{r:?} tag must be nonzero");
        }
    }

    #[test]
    fn verdict_canonical_bytes_pinned() {
        // Pin the exact byte values so changes are caught at compile time.
        assert_eq!(FlowVerdict::Allow.canonical_bytes(), [0x00, 0x00]);
        assert_eq!(
            FlowVerdict::Deny(FlowDenyReason::Exfiltration).canonical_bytes(),
            [0x01, 0x01]
        );
        assert_eq!(
            FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation).canonical_bytes(),
            [0x01, 0x02]
        );
        assert_eq!(
            FlowVerdict::Deny(FlowDenyReason::IntegrityViolation).canonical_bytes(),
            [0x01, 0x03]
        );
        assert_eq!(
            FlowVerdict::Deny(FlowDenyReason::FreshnessExpired).canonical_bytes(),
            [0x01, 0x04]
        );
        assert_eq!(
            FlowVerdict::Deny(FlowDenyReason::DerivationViolation).canonical_bytes(),
            [0x01, 0x05]
        );
    }

    #[test]
    fn all_verdicts_produce_distinct_canonical_bytes() {
        let verdicts = [
            FlowVerdict::Allow,
            FlowVerdict::Deny(FlowDenyReason::Exfiltration),
            FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation),
            FlowVerdict::Deny(FlowDenyReason::IntegrityViolation),
            FlowVerdict::Deny(FlowDenyReason::FreshnessExpired),
            FlowVerdict::Deny(FlowDenyReason::DerivationViolation),
        ];
        for (i, v) in verdicts.iter().enumerate() {
            for (j, u) in verdicts.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        v.canonical_bytes(),
                        u.canonical_bytes(),
                        "verdicts {i} and {j} must produce distinct bytes"
                    );
                }
            }
        }
    }
}
