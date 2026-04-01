//! Flow receipts — evidence of flow decisions.
//!
//! A `FlowReceipt` records:
//! - The action that was blocked or allowed
//! - The labeled observations that were causally sufficient
//! - Which policy rule fired (for blocks)
//!
//! ## Signing and verification
//!
//! Receipts are unsigned at construction time. The `portcullis` crate
//! provides `sign_receipt()` and `verify_receipt()` using Ed25519 via
//! `ring` (behind the `crypto` feature).
//!
//! This core crate provides `verify_signature()` which accepts a
//! caller-provided verifier function, keeping `portcullis-core`
//! dependency-free for Aeneas verification.
//!
//! ## Trust model
//!
//! Receipts are constructed by `build_receipt()` from trusted inputs
//! (the flow graph). They are NOT tamper-proof without signing.
//!
//! The causal ancestors are assembled by the caller from the flow
//! graph — there is no binding between the receipt and the graph.
//! This is a known limitation until the flow graph (Phase 5+) provides
//! atomic check-and-receipt construction.

use crate::IFCLabel;
use crate::flow::{FlowDenyReason, FlowNode, FlowVerdict, NodeId, NodeKind};

// ═══════════════════════════════════════════════════════════════════════════
// Receipt types
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum causal ancestors in a receipt.
pub const MAX_RECEIPT_ANCESTORS: usize = 16;

/// A flow receipt — evidence of a flow decision.
///
/// Unsigned at construction. Use `portcullis::receipt_sign::sign_receipt()`
/// to sign, and `portcullis::receipt_sign::verify_receipt()` or
/// `verify_signature()` with a custom verifier to verify.
///
/// Fields are `pub(crate)` to prevent external forgery. Use
/// `build_receipt()` to construct.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FlowReceipt {
    pub(crate) action: ReceiptNode,
    pub(crate) ancestors: Vec<ReceiptNode>,
    pub(crate) verdict: FlowVerdict,
    pub(crate) rule_name: &'static str,
    pub(crate) created_at: u64,
    pub(crate) signature: [u8; 64],
    /// SHA-256 hash of the previous receipt in the chain.
    /// All zeros for the first receipt in a session.
    /// Included in the signed content — tampering with chain order
    /// invalidates the signature.
    pub(crate) prev_hash: [u8; 32],
    /// Chain ID — binds the receipt to a specific session.
    /// Prevents cross-session receipt injection (#492).
    /// SHA-256 of the session identifier.
    pub(crate) chain_id: [u8; 32],
}

/// Read-only accessors.
impl FlowReceipt {
    pub fn action(&self) -> &ReceiptNode {
        &self.action
    }
    pub fn ancestors(&self) -> &[ReceiptNode] {
        &self.ancestors
    }
    pub fn verdict(&self) -> FlowVerdict {
        self.verdict
    }
    pub fn rule_name(&self) -> &'static str {
        self.rule_name
    }
    pub fn created_at(&self) -> u64 {
        self.created_at
    }
    pub fn is_signed(&self) -> bool {
        self.signature != [0; 64]
    }
    /// Raw signature bytes (for verification).
    pub fn signature_bytes(&self) -> &[u8; 64] {
        &self.signature
    }
    /// Set the signature (called by signing code in `portcullis` crate).
    pub fn set_signature(&mut self, sig: [u8; 64]) {
        self.signature = sig;
    }
    /// Previous receipt hash (chain link).
    pub fn prev_hash(&self) -> &[u8; 32] {
        &self.prev_hash
    }
    /// Set the previous receipt hash (called before signing).
    pub fn set_prev_hash(&mut self, hash: [u8; 32]) {
        self.prev_hash = hash;
    }
    /// Chain ID (session binding).
    pub fn chain_id(&self) -> &[u8; 32] {
        &self.chain_id
    }
    /// Set the chain ID (called before signing).
    pub fn set_chain_id(&mut self, id: [u8; 32]) {
        self.chain_id = id;
    }
}

/// A node summary for inclusion in a receipt.
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

/// Build an unsigned receipt from a flow decision.
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
        signature: [0; 64], // Unsigned
        prev_hash: [0; 32], // No chain link yet — set via set_prev_hash()
        chain_id: [0; 32],  // No chain ID yet — set via set_chain_id()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Canonical content bytes (for signing/verification)
// ═══════════════════════════════════════════════════════════════════════════

/// Serialize receipt content to canonical bytes for signing/verification.
///
/// The canonical form includes all security-relevant fields in a
/// deterministic order. Changes to any field invalidate the signature.
///
/// This is the same byte sequence signed by `sign_receipt()` in the
/// `portcullis` crate. Verifiers must reconstruct this to check signatures.
pub fn receipt_canonical_bytes(receipt: &FlowReceipt) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // Version tag
    buf.extend_from_slice(b"nucleus-receipt-v3\n");

    // Chain ID — binds this receipt to a specific session (#492).
    buf.extend_from_slice(receipt.chain_id());

    // Chain link — hash of the previous receipt.
    buf.extend_from_slice(receipt.prev_hash());

    // Action node
    append_receipt_node_bytes(&mut buf, receipt.action());

    // Verdict + rule
    buf.extend_from_slice(format!("verdict:{:?}\n", receipt.verdict()).as_bytes());
    buf.extend_from_slice(format!("rule:{}\n", receipt.rule_name()).as_bytes());

    // Timestamp
    buf.extend_from_slice(&receipt.created_at().to_le_bytes());

    // Ancestors (ordered — receipt construction preserves BFS order)
    buf.extend_from_slice(&(receipt.ancestors().len() as u32).to_le_bytes());
    for ancestor in receipt.ancestors() {
        append_receipt_node_bytes(&mut buf, ancestor);
    }

    buf
}

/// Serialize a receipt node to canonical bytes.
fn append_receipt_node_bytes(buf: &mut Vec<u8>, node: &ReceiptNode) {
    buf.extend_from_slice(&node.id.to_le_bytes());
    buf.extend_from_slice(&(node.kind as u8).to_le_bytes());
    buf.extend_from_slice(&(node.label.confidentiality as u8).to_le_bytes());
    buf.extend_from_slice(&(node.label.integrity as u8).to_le_bytes());
    buf.extend_from_slice(&(node.label.authority as u8).to_le_bytes());
    buf.extend_from_slice(&node.label.provenance.bits().to_le_bytes());
    buf.extend_from_slice(&node.label.freshness.observed_at.to_le_bytes());
    buf.extend_from_slice(&node.label.freshness.ttl_secs.to_le_bytes());
}

// ═══════════════════════════════════════════════════════════════════════════
// Signature verification
// ═══════════════════════════════════════════════════════════════════════════

/// Signature verification errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// Receipt has not been signed (signature is all zeros).
    Unsigned,
    /// Ed25519 signature is invalid (wrong key or tampered content).
    InvalidSignature,
}

/// Verify a receipt's signature using a caller-provided verification function.
///
/// The `verifier` receives `(canonical_content_bytes, signature_bytes)` and
/// returns `true` if the signature is valid.
///
/// This design allows `portcullis-core` to remain dependency-free (no `ring`)
/// while still providing signature verification. The `portcullis` crate
/// provides `verify_receipt()` which wraps this with Ed25519 via `ring`.
///
/// Returns `Ok(())` if the signature is valid, `Err(Unsigned)` if the
/// receipt has no signature, or `Err(InvalidSignature)` if the verifier
/// rejects the signature.
pub fn verify_signature(
    receipt: &FlowReceipt,
    verifier: impl FnOnce(&[u8], &[u8; 64]) -> bool,
) -> Result<(), SignatureError> {
    if !receipt.is_signed() {
        return Err(SignatureError::Unsigned);
    }

    let content = receipt_canonical_bytes(receipt);
    if verifier(&content, receipt.signature_bytes()) {
        Ok(())
    } else {
        Err(SignatureError::InvalidSignature)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Display
// ═══════════════════════════════════════════════════════════════════════════

impl FlowReceipt {
    /// Render as a human-readable causal chain.
    ///
    /// **Not a security function.** Output is only as trustworthy as
    /// the receipt data. Do not use for audit without signature verification.
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

        if !self.is_signed() {
            out.push_str("⚠ UNSIGNED — not cryptographically verified\n");
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
            sink_class: None,
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

        assert_eq!(receipt.verdict(), FlowVerdict::Allow);
        assert_eq!(receipt.rule_name(), "allow");
    }

    #[test]
    fn receipt_for_blocked_exfiltration() {
        let label = IFCLabel::secret(1000);
        let action = make_node(1, NodeKind::OutboundAction, label, Some(Operation::GitPush));
        let verdict = check_flow(&action, 2000);
        let receipt = build_receipt(&action, &[], verdict, 2000);

        assert_eq!(
            receipt.verdict(),
            FlowVerdict::Deny(FlowDenyReason::Exfiltration)
        );
        assert!(receipt.rule_name().contains("no-exfil"));
    }

    #[test]
    fn receipt_with_causal_chain() {
        let now = 1000;
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
                derivation: crate::DerivationClass::Deterministic,
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

        assert!(matches!(
            receipt.verdict(),
            FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation)
        ));
        assert_eq!(receipt.ancestors().len(), 3);

        let display = receipt.display_chain();
        assert!(display.contains("BLOCKED"));
        assert!(display.contains("WebContent"));
        assert!(display.contains("UNSIGNED"));
    }

    #[test]
    fn verify_signature_rejects_unsigned() {
        let label = IFCLabel::user_prompt(1000);
        let action = make_node(
            1,
            NodeKind::OutboundAction,
            label,
            Some(Operation::WriteFiles),
        );
        let receipt = build_receipt(&action, &[], FlowVerdict::Allow, 2000);

        // Any verifier should not be called — Unsigned is returned first
        assert_eq!(
            verify_signature(&receipt, |_, _| panic!("should not be called")),
            Err(SignatureError::Unsigned)
        );
        assert!(!receipt.is_signed());
    }

    #[test]
    fn verify_signature_with_verifier_ok() {
        let label = IFCLabel::user_prompt(1000);
        let action = make_node(
            1,
            NodeKind::OutboundAction,
            label,
            Some(Operation::WriteFiles),
        );
        let mut receipt = build_receipt(&action, &[], FlowVerdict::Allow, 2000);
        // Fake a non-zero signature so is_signed() returns true
        receipt.set_signature([0xAA; 64]);

        // Verifier that accepts
        assert_eq!(verify_signature(&receipt, |_, _| true), Ok(()));
        // Verifier that rejects
        assert_eq!(
            verify_signature(&receipt, |_, _| false),
            Err(SignatureError::InvalidSignature)
        );
    }

    #[test]
    fn canonical_bytes_deterministic() {
        let label = IFCLabel::user_prompt(1000);
        let action = make_node(
            1,
            NodeKind::OutboundAction,
            label,
            Some(Operation::WriteFiles),
        );
        let receipt = build_receipt(&action, &[], FlowVerdict::Allow, 2000);
        let bytes1 = receipt_canonical_bytes(&receipt);
        let bytes2 = receipt_canonical_bytes(&receipt);
        assert_eq!(bytes1, bytes2);
        assert!(!bytes1.is_empty());
    }

    #[test]
    fn display_shows_unsigned_warning() {
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
        assert!(display.contains("UNSIGNED"));
    }
}
