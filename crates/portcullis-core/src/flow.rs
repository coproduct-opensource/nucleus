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

use crate::{AuthorityLevel, ConfLevel, IFCLabel, IntegLevel, Operation, ProvenanceSet};

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
        },
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
}

// ═══════════════════════════════════════════════════════════════════════════
// Label propagation — Denning's lemma
// ═══════════════════════════════════════════════════════════════════════════

/// Propagate labels through the DAG: join all parent labels with intrinsic.
///
/// This is Denning's fundamental lemma generalized to our 5-dimensional
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
}

/// Result of checking a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowVerdict {
    /// Flow is permitted.
    Allow,
    /// Flow is blocked with a reason.
    Deny(FlowDenyReason),
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
        | Operation::ManagePods => AuthorityLevel::Suggestive,
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
/// Enforces 6 rules:
/// 1. No-exfil: secret data cannot flow to external sinks (incl. WebFetch)
/// 2. No-authority-escalation: NoAuthority data cannot steer privileged actions
/// 3. No-integrity-laundering: untrusted data cannot reach trusted-required sinks
/// 4. No-web-exfil: web-provenance data cannot reach exfil sinks
/// 5. Freshness: expired data cannot be used in decisions
/// 6. Monotonicity: implicit (enforced by propagate_label's join)
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

    // Rule 1: No-exfil — secret data to external sinks.
    // WebFetch is an exfil vector (URL params can encode secrets) even though
    // the legacy ExposureSet doesn't classify it as such.
    let is_exfil = crate::is_exfil_operation(op) || op == Operation::WebFetch;
    if label.confidentiality >= ConfLevel::Secret && is_exfil {
        return FlowVerdict::Deny(FlowDenyReason::Exfiltration);
    }

    // Rule 2: No-authority-escalation
    let required_auth = required_authority(op);
    if label.authority < required_auth {
        return FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation);
    }

    // Rule 3: No-integrity-laundering
    let required_integ = required_integrity(op);
    if label.integrity < required_integ {
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

    FlowVerdict::Allow
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
        };

        let node = FlowNode {
            id: 0,
            kind: NodeKind::OutboundAction,
            label,
            parent_count: 0,
            parents: [0; MAX_PARENTS],
            operation: Some(op),
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

    fn make_node(kind: NodeKind, label: IFCLabel, op: Option<Operation>) -> FlowNode {
        FlowNode {
            id: 0,
            kind,
            label,
            parent_count: 0,
            parents: [0; MAX_PARENTS],
            operation: op,
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
}
