//! Signed flow receipts — cryptographic evidence of flow decisions.
//!
//! A `FlowReceipt` records:
//! - The action that was blocked or allowed
//! - The labeled observations that were causally sufficient
//! - Which policy rule fired (for blocks)
//! - A signature over the receipt
//!
//! Receipts enable deterministic replay: given a receipt, reconstruct
//! the exact decision and verify the causal chain.
//!
//! ## Honest status
//!
//! Types and serialization only. Not yet wired into `Kernel::decide()`
//! or `check_flow()`. Signatures use a placeholder — real Ed25519
//! signing requires the `ed25519-dalek` crate (in `portcullis`, not here).

use crate::IFCLabel;
use crate::flow::{FlowDenyReason, FlowNode, FlowVerdict, NodeId, NodeKind};

// ═══════════════════════════════════════════════════════════════════════════
// Receipt types
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum number of causal ancestors included in a receipt.
/// Keeps receipts bounded for serialization. Deep causal chains
/// are summarized (the deepest ancestors are included, intermediates elided).
pub const MAX_RECEIPT_ANCESTORS: usize = 16;

/// A signed flow receipt — cryptographic evidence of a flow decision.
///
/// Contains the action node, its causal ancestors with labels, the
/// verdict, and which rule fired. The signature covers the entire
/// receipt so it can be verified independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowReceipt {
    /// The action node that was checked.
    pub action: ReceiptNode,

    /// Causal ancestors that were sufficient for the decision.
    /// Ordered from most recent to oldest (reverse causal order).
    pub ancestors: Vec<ReceiptNode>,

    /// The flow verdict (Allow or Deny with reason).
    pub verdict: FlowVerdict,

    /// Human-readable explanation of which rule fired.
    pub rule_name: &'static str,

    /// Unix timestamp when the receipt was created.
    pub created_at: u64,

    /// Signature over the receipt (placeholder — real signing in portcullis).
    /// 64 bytes for Ed25519 signature, zeroed = unsigned.
    pub signature: [u8; 64],
}

/// A node summary for inclusion in a receipt.
///
/// Lighter than `FlowNode` — includes the label and kind but not
/// the full parent array (the receipt itself encodes the causal chain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptNode {
    pub id: NodeId,
    pub kind: NodeKind,
    pub label: IFCLabel,
}

impl From<&FlowNode> for ReceiptNode {
    fn from(node: &FlowNode) -> Self {
        Self {
            id: node.id,
            kind: node.kind,
            label: node.label,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Receipt construction
// ═══════════════════════════════════════════════════════════════════════════

/// Build a receipt from a flow decision.
///
/// `action` is the node that was checked. `ancestors` are the labeled
/// nodes that were causally sufficient (the caller assembles these from
/// the flow graph). `verdict` is the result of `check_flow()`.
pub fn build_receipt(
    action: &FlowNode,
    ancestors: &[&FlowNode],
    verdict: FlowVerdict,
    now: u64,
) -> FlowReceipt {
    let rule_name = match verdict {
        FlowVerdict::Allow => "allow",
        FlowVerdict::Deny(FlowDenyReason::Exfiltration) => "no-exfil: secret data to external sink",
        FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation) => {
            "no-authority-escalation: low-authority data steering privileged action"
        }
        FlowVerdict::Deny(FlowDenyReason::IntegrityViolation) => {
            "no-integrity-laundering: untrusted data to trusted-required sink"
        }
        FlowVerdict::Deny(FlowDenyReason::FreshnessExpired) => {
            "freshness: expired data in decision"
        }
    };

    let ancestors: Vec<ReceiptNode> = ancestors
        .iter()
        .take(MAX_RECEIPT_ANCESTORS)
        .map(|n| ReceiptNode::from(*n))
        .collect();

    FlowReceipt {
        action: ReceiptNode::from(action),
        ancestors,
        verdict,
        rule_name,
        created_at: now,
        signature: [0; 64], // Unsigned — signing happens in portcullis layer
    }
}

/// Verify that a receipt is internally consistent.
///
/// Checks:
/// 1. If verdict is Deny, rule_name is non-empty
/// 2. If verdict is Allow, rule_name is "allow"
/// 3. Action node exists
///
/// Does NOT verify the signature (requires the signing key).
/// Does NOT re-run check_flow (would require the full graph).
pub fn verify_receipt_consistency(receipt: &FlowReceipt) -> Result<(), ReceiptError> {
    match receipt.verdict {
        FlowVerdict::Deny(_) => {
            if receipt.rule_name == "allow" {
                return Err(ReceiptError::DenyWithAllowRule);
            }
        }
        FlowVerdict::Allow => {
            if receipt.rule_name != "allow" {
                return Err(ReceiptError::AllowWithDenyRule);
            }
        }
    }

    if receipt.ancestors.len() > MAX_RECEIPT_ANCESTORS {
        return Err(ReceiptError::TooManyAncestors);
    }

    Ok(())
}

/// Receipt consistency errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptError {
    /// Verdict is Deny but rule_name says "allow".
    DenyWithAllowRule,
    /// Verdict is Allow but rule_name is a deny rule.
    AllowWithDenyRule,
    /// More ancestors than MAX_RECEIPT_ANCESTORS.
    TooManyAncestors,
}

// ═══════════════════════════════════════════════════════════════════════════
// Display — human-readable receipt rendering
// ═══════════════════════════════════════════════════════════════════════════

impl FlowReceipt {
    /// Render the receipt as a human-readable causal chain.
    ///
    /// Example output for a blocked exfiltration:
    /// ```text
    /// BLOCKED: no-exfil: secret data to external sink
    /// Action: OutboundAction (id=42) label={Secret, Adversarial, NoAuthority}
    /// Causal chain:
    ///   ← WebContent (id=10) label={Public, Adversarial, NoAuthority}
    ///   ← FileRead (id=20) label={Secret, Trusted, Directive}
    ///   ← ModelPlan (id=30) label={Secret, Adversarial, NoAuthority}
    /// ```
    pub fn display_chain(&self) -> String {
        let mut out = String::new();

        match self.verdict {
            FlowVerdict::Allow => out.push_str("ALLOWED"),
            FlowVerdict::Deny(_) => {
                out.push_str("BLOCKED: ");
                out.push_str(self.rule_name);
            }
        }
        out.push('\n');

        out.push_str(&format!(
            "Action: {:?} (id={}) label={{conf={:?}, integ={:?}, auth={:?}}}\n",
            self.action.kind,
            self.action.id,
            self.action.label.confidentiality,
            self.action.label.integrity,
            self.action.label.authority,
        ));

        if !self.ancestors.is_empty() {
            out.push_str("Causal chain:\n");
            for ancestor in &self.ancestors {
                out.push_str(&format!(
                    "  <- {:?} (id={}) label={{conf={:?}, integ={:?}, auth={:?}}}\n",
                    ancestor.kind,
                    ancestor.id,
                    ancestor.label.confidentiality,
                    ancestor.label.integrity,
                    ancestor.label.authority,
                ));
            }
        }

        out
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{MAX_PARENTS, check_flow, intrinsic_label, propagate_label};
    use crate::{AuthorityLevel, ConfLevel, Freshness, IntegLevel, Operation, ProvenanceSet};

    fn make_node(id: NodeId, kind: NodeKind, label: IFCLabel, op: Option<Operation>) -> FlowNode {
        FlowNode {
            id,
            kind,
            label,
            parent_count: 0,
            parents: [0; MAX_PARENTS],
            operation: op,
        }
    }

    #[test]
    fn receipt_for_allowed_action() {
        let label = IFCLabel::user_prompt(1000);
        let action = make_node(
            1,
            NodeKind::OutboundAction,
            label,
            Some(Operation::WriteFiles),
        );
        let verdict = check_flow(&action, 2000);
        let receipt = build_receipt(&action, &[], verdict, 2000);

        assert_eq!(receipt.verdict, FlowVerdict::Allow);
        assert_eq!(receipt.rule_name, "allow");
        assert!(verify_receipt_consistency(&receipt).is_ok());
    }

    #[test]
    fn receipt_for_blocked_exfiltration() {
        let label = IFCLabel::secret(1000);
        let action = make_node(1, NodeKind::OutboundAction, label, Some(Operation::GitPush));
        let verdict = check_flow(&action, 2000);
        let receipt = build_receipt(&action, &[], verdict, 2000);

        assert_eq!(
            receipt.verdict,
            FlowVerdict::Deny(FlowDenyReason::Exfiltration)
        );
        assert!(receipt.rule_name.contains("no-exfil"));
        assert!(verify_receipt_consistency(&receipt).is_ok());
    }

    #[test]
    fn receipt_with_causal_chain() {
        let now = 1000;

        // Build a causal chain: web content → plan → action (blocked)
        let web = make_node(10, NodeKind::WebContent, IFCLabel::web_content(now), None);
        let repo = make_node(
            20,
            NodeKind::FileRead,
            IFCLabel {
                confidentiality: ConfLevel::Internal,
                integrity: IntegLevel::Trusted,
                provenance: ProvenanceSet::SYSTEM,
                freshness: Freshness {
                    observed_at: now,
                    ttl_secs: 0,
                },
                authority: AuthorityLevel::Directive,
            },
            None,
        );

        let plan_label = propagate_label(
            &[web.label, repo.label],
            intrinsic_label(NodeKind::ModelPlan, now),
        );
        let plan = make_node(30, NodeKind::ModelPlan, plan_label, None);

        let action_label = propagate_label(
            &[plan.label],
            intrinsic_label(NodeKind::OutboundAction, now),
        );
        let action = make_node(
            42,
            NodeKind::OutboundAction,
            action_label,
            Some(Operation::CreatePr),
        );

        let verdict = check_flow(&action, now + 10);
        let receipt = build_receipt(&action, &[&web, &repo, &plan], verdict, now + 10);

        // Blocked by authority escalation
        assert!(matches!(
            receipt.verdict,
            FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation)
        ));
        assert_eq!(receipt.ancestors.len(), 3);
        assert!(verify_receipt_consistency(&receipt).is_ok());

        // Display chain is human-readable
        let display = receipt.display_chain();
        assert!(display.contains("BLOCKED"));
        assert!(display.contains("WebContent"));
        assert!(display.contains("FileRead"));
        assert!(display.contains("ModelPlan"));
    }

    #[test]
    fn receipt_consistency_rejects_contradictions() {
        let label = IFCLabel::user_prompt(1000);
        let action = make_node(
            1,
            NodeKind::OutboundAction,
            label,
            Some(Operation::WriteFiles),
        );

        // Manually create an inconsistent receipt
        let bad_receipt = FlowReceipt {
            action: ReceiptNode::from(&action),
            ancestors: vec![],
            verdict: FlowVerdict::Deny(FlowDenyReason::Exfiltration),
            rule_name: "allow", // Contradiction!
            created_at: 2000,
            signature: [0; 64],
        };

        assert_eq!(
            verify_receipt_consistency(&bad_receipt),
            Err(ReceiptError::DenyWithAllowRule)
        );
    }

    #[test]
    fn display_shows_blocked_chain() {
        let label = IFCLabel::web_content(1000);
        let action = make_node(
            1,
            NodeKind::OutboundAction,
            label,
            Some(Operation::WriteFiles),
        );
        let verdict = check_flow(&action, 2000);
        let receipt = build_receipt(&action, &[], verdict, 2000);
        let display = receipt.display_chain();
        assert!(display.contains("BLOCKED"));
        assert!(display.contains("authority"));
    }
}
