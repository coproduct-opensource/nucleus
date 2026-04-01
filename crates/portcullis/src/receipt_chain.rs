//! Append-only receipt chain with hash-chain integrity enforcement.
//!
//! `ReceiptChain` maintains a sequence of `VerdictReceipt`s linked by
//! SHA-256 hashes. Each receipt commits to its predecessor's hash,
//! forming a tamper-evident log. Deletion, reordering, or insertion
//! of receipts is detectable via `verify()`.
//!
//! ## Trust model
//!
//! The chain enforces structural integrity (hash linkage) at write time.
//! Individual receipt authenticity still depends on Ed25519 signatures
//! (see `receipt_sign.rs`). A verified chain with unsigned receipts
//! only guarantees ordering and completeness — not provenance.

use sha2::{Digest, Sha256};

use portcullis_core::flow::{FlowVerdict, NodeId};
use portcullis_core::IFCLabel;

// ═══════════════════════════════════════════════════════════════════════════
// VerdictReceipt — a single chain entry
// ═══════════════════════════════════════════════════════════════════════════

/// A receipt capturing a flow verdict decision and its causal context.
///
/// Each receipt is hash-linked to the previous receipt in the chain,
/// forming an append-only tamper-evident log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictReceipt {
    /// The flow verdict (allow or deny with reason).
    pub verdict: FlowVerdict,
    /// Human-readable operation description (e.g., "write_files", "git_push").
    pub operation: String,
    /// Subject identifier (e.g., agent ID, session ID).
    pub subject: String,
    /// Label at the point of decision.
    pub pre_label: IFCLabel,
    /// Label after the decision was applied (may differ for allow verdicts
    /// that trigger label propagation).
    pub post_label: IFCLabel,
    /// Causal parent node IDs — the flow graph nodes that influenced
    /// this decision.
    pub causal_parents: Vec<NodeId>,
    /// Unix timestamp (seconds since epoch) when the verdict was issued.
    pub timestamp: u64,
    /// SHA-256 hash of the previous receipt in the chain.
    /// All zeros for the first receipt.
    pub prev_hash: [u8; 32],
    /// SHA-256 hash of this receipt's canonical content.
    /// Computed via `compute_hash()` and verified on chain append.
    pub receipt_hash: [u8; 32],
}

impl VerdictReceipt {
    /// Compute the SHA-256 hash of this receipt's canonical fields.
    ///
    /// The hash covers all security-relevant fields in a deterministic
    /// order. The `receipt_hash` field itself is NOT included (it is
    /// the output).
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Version tag for domain separation
        hasher.update(b"nucleus-verdict-receipt-v1\n");

        // Previous chain link
        hasher.update(self.prev_hash);

        // Verdict
        hasher.update(format!("{:?}", self.verdict).as_bytes());

        // Operation + subject
        hasher.update((self.operation.len() as u32).to_le_bytes());
        hasher.update(self.operation.as_bytes());
        hasher.update((self.subject.len() as u32).to_le_bytes());
        hasher.update(self.subject.as_bytes());

        // Labels (pre and post)
        hash_label(&mut hasher, &self.pre_label);
        hash_label(&mut hasher, &self.post_label);

        // Causal parents (count-prefixed for unambiguous parsing)
        hasher.update((self.causal_parents.len() as u32).to_le_bytes());
        for &parent_id in &self.causal_parents {
            hasher.update(parent_id.to_le_bytes());
        }

        // Timestamp
        hasher.update(self.timestamp.to_le_bytes());

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Create a new `VerdictReceipt` from a verdict and context.
    ///
    /// Computes `receipt_hash` automatically from the provided fields.
    /// The caller must supply `prev_hash` from the chain head.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verdict(
        verdict: FlowVerdict,
        operation: impl Into<String>,
        subject: impl Into<String>,
        pre_label: IFCLabel,
        post_label: IFCLabel,
        causal_parents: Vec<NodeId>,
        timestamp: u64,
        prev_hash: [u8; 32],
    ) -> Self {
        let mut receipt = Self {
            verdict,
            operation: operation.into(),
            subject: subject.into(),
            pre_label,
            post_label,
            causal_parents,
            timestamp,
            prev_hash,
            receipt_hash: [0u8; 32], // placeholder
        };
        receipt.receipt_hash = receipt.compute_hash();
        receipt
    }
}

/// Hash an IFCLabel into the hasher in canonical order.
fn hash_label(hasher: &mut Sha256, label: &IFCLabel) {
    hasher.update([label.confidentiality as u8]);
    hasher.update([label.integrity as u8]);
    hasher.update([label.authority as u8]);
    hasher.update(label.provenance.bits().to_le_bytes());
    hasher.update(label.freshness.observed_at.to_le_bytes());
    hasher.update(label.freshness.ttl_secs.to_le_bytes());
}

// ═══════════════════════════════════════════════════════════════════════════
// ReceiptChain — append-only hash-linked sequence
// ═══════════════════════════════════════════════════════════════════════════

/// Error returned when a receipt cannot be appended to the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainAppendError {
    /// The receipt's `prev_hash` does not match the chain's current head hash.
    HashMismatch {
        /// The expected hash (chain head).
        expected: [u8; 32],
        /// The hash the receipt claims as its predecessor.
        actual: [u8; 32],
    },
    /// The receipt's `receipt_hash` does not match `compute_hash()`.
    InvalidReceiptHash,
}

impl std::fmt::Display for ChainAppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HashMismatch { expected, actual } => {
                write!(
                    f,
                    "prev_hash mismatch: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(actual)
                )
            }
            Self::InvalidReceiptHash => {
                write!(f, "receipt_hash does not match computed hash")
            }
        }
    }
}

impl std::error::Error for ChainAppendError {}

/// Error returned when chain verification fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVerifyError {
    /// A receipt's hash does not match its computed hash.
    InvalidHash {
        /// Index of the invalid receipt.
        index: usize,
    },
    /// A receipt's `prev_hash` does not link to the previous receipt.
    BrokenLink {
        /// Index of the receipt with the broken link.
        index: usize,
    },
}

impl std::fmt::Display for ChainVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHash { index } => {
                write!(f, "receipt at index {} has invalid hash", index)
            }
            Self::BrokenLink { index } => {
                write!(f, "receipt at index {} has broken prev_hash link", index)
            }
        }
    }
}

impl std::error::Error for ChainVerifyError {}

/// An append-only chain of verdict receipts with hash-chain integrity.
///
/// Receipts are linked by SHA-256 hashes: each receipt's `prev_hash`
/// must match the preceding receipt's `receipt_hash`. The chain
/// enforces this invariant at append time and can re-verify the
/// entire chain on demand.
///
/// The genesis state has `head_hash` of all zeros.
#[derive(Debug, Clone)]
pub struct ReceiptChain {
    receipts: Vec<VerdictReceipt>,
    head_hash: [u8; 32],
}

impl Default for ReceiptChain {
    fn default() -> Self {
        Self::new()
    }
}

impl ReceiptChain {
    /// Create an empty receipt chain.
    ///
    /// The initial `head_hash` is all zeros (genesis).
    pub fn new() -> Self {
        Self {
            receipts: Vec::new(),
            head_hash: [0u8; 32],
        }
    }

    /// Append a receipt to the chain.
    ///
    /// Verifies that:
    /// 1. `receipt.prev_hash` matches `self.head_hash`
    /// 2. `receipt.receipt_hash` matches `receipt.compute_hash()`
    ///
    /// On success, updates `head_hash` to the appended receipt's hash.
    pub fn append(&mut self, receipt: VerdictReceipt) -> Result<(), ChainAppendError> {
        // Verify chain linkage
        if receipt.prev_hash != self.head_hash {
            return Err(ChainAppendError::HashMismatch {
                expected: self.head_hash,
                actual: receipt.prev_hash,
            });
        }

        // Verify receipt hash integrity
        let computed = receipt.compute_hash();
        if receipt.receipt_hash != computed {
            return Err(ChainAppendError::InvalidReceiptHash);
        }

        self.head_hash = receipt.receipt_hash;
        self.receipts.push(receipt);
        Ok(())
    }

    /// Verify the entire chain's hash integrity.
    ///
    /// Walks from genesis to head, checking:
    /// 1. Each receipt's `receipt_hash` matches `compute_hash()`
    /// 2. Each receipt's `prev_hash` matches the previous receipt's hash
    ///    (or zeros for the first receipt)
    pub fn verify(&self) -> Result<(), ChainVerifyError> {
        let mut expected_prev = [0u8; 32];

        for (i, receipt) in self.receipts.iter().enumerate() {
            // Check prev_hash linkage
            if receipt.prev_hash != expected_prev {
                return Err(ChainVerifyError::BrokenLink { index: i });
            }

            // Check receipt hash
            let computed = receipt.compute_hash();
            if receipt.receipt_hash != computed {
                return Err(ChainVerifyError::InvalidHash { index: i });
            }

            expected_prev = receipt.receipt_hash;
        }

        Ok(())
    }

    /// Export the chain as a JSON string.
    ///
    /// Serializes each receipt into a JSON object with human-readable
    /// fields. Hashes are hex-encoded, labels are serialized as objects
    /// with their component fields.
    #[cfg(feature = "serde")]
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        use serde_json::{json, Value};

        let receipts: Vec<Value> = self
            .receipts
            .iter()
            .map(|r| {
                json!({
                    "verdict": format!("{:?}", r.verdict),
                    "operation": r.operation,
                    "subject": r.subject,
                    "pre_label": label_to_json(&r.pre_label),
                    "post_label": label_to_json(&r.post_label),
                    "causal_parents": r.causal_parents,
                    "timestamp": r.timestamp,
                    "prev_hash": hex::encode(r.prev_hash),
                    "receipt_hash": hex::encode(r.receipt_hash),
                })
            })
            .collect();

        let chain = json!({
            "receipts": receipts,
            "head_hash": hex::encode(self.head_hash),
            "length": self.receipts.len(),
        });

        serde_json::to_string_pretty(&chain)
    }

    /// Number of receipts in the chain.
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    /// The current head hash (hash of the most recent receipt, or zeros if empty).
    pub fn head_hash(&self) -> &[u8; 32] {
        &self.head_hash
    }

    /// Read-only access to the receipts.
    pub fn receipts(&self) -> &[VerdictReceipt] {
        &self.receipts
    }
}

/// Convert an IFCLabel to a serde_json::Value for JSON export.
#[cfg(feature = "serde")]
fn label_to_json(label: &IFCLabel) -> serde_json::Value {
    serde_json::json!({
        "confidentiality": format!("{:?}", label.confidentiality),
        "integrity": format!("{:?}", label.integrity),
        "authority": format!("{:?}", label.authority),
        "provenance_bits": label.provenance.bits(),
        "freshness": {
            "observed_at": label.freshness.observed_at,
            "ttl_secs": label.freshness.ttl_secs,
        },
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_core::flow::FlowDenyReason;

    fn test_label(now: u64) -> IFCLabel {
        IFCLabel::user_prompt(now)
    }

    fn make_receipt(
        chain: &ReceiptChain,
        verdict: FlowVerdict,
        operation: &str,
        timestamp: u64,
    ) -> VerdictReceipt {
        let label = test_label(timestamp);
        VerdictReceipt::from_verdict(
            verdict,
            operation,
            "test-agent",
            label,
            label,
            vec![1, 2],
            timestamp,
            *chain.head_hash(),
        )
    }

    #[test]
    fn append_valid_receipt_and_verify() {
        let mut chain = ReceiptChain::new();
        let receipt = make_receipt(&chain, FlowVerdict::Allow, "read_files", 1000);

        assert!(chain.append(receipt).is_ok());
        assert_eq!(chain.len(), 1);
        assert!(!chain.is_empty());
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn reject_receipt_with_wrong_prev_hash() {
        let mut chain = ReceiptChain::new();

        // First receipt is fine
        let r1 = make_receipt(&chain, FlowVerdict::Allow, "read_files", 1000);
        chain.append(r1).unwrap();

        // Second receipt with wrong prev_hash
        let bad = VerdictReceipt::from_verdict(
            FlowVerdict::Allow,
            "write_files",
            "test-agent",
            test_label(2000),
            test_label(2000),
            vec![3],
            2000,
            [0xff; 32], // wrong prev_hash
        );

        let err = chain.append(bad).unwrap_err();
        assert!(matches!(err, ChainAppendError::HashMismatch { .. }));
        // Chain should still have only 1 receipt
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn empty_chain_is_valid() {
        let chain = ReceiptChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        assert_eq!(chain.head_hash(), &[0u8; 32]);
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn chain_of_five_receipts_verifies() {
        let mut chain = ReceiptChain::new();

        let ops = [
            "read_files",
            "web_fetch",
            "write_files",
            "git_push",
            "create_pr",
        ];
        for (i, op) in ops.iter().enumerate() {
            let verdict = if i == 3 {
                FlowVerdict::Deny(FlowDenyReason::Exfiltration)
            } else {
                FlowVerdict::Allow
            };
            let receipt = make_receipt(&chain, verdict, op, 1000 + i as u64);
            chain.append(receipt).unwrap();
        }

        assert_eq!(chain.len(), 5);
        assert!(chain.verify().is_ok());

        // Head hash should not be zeros after 5 appends
        assert_ne!(chain.head_hash(), &[0u8; 32]);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn export_produces_valid_json() {
        let mut chain = ReceiptChain::new();

        let r1 = make_receipt(&chain, FlowVerdict::Allow, "read_files", 1000);
        chain.append(r1).unwrap();

        let r2 = make_receipt(
            &chain,
            FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation),
            "git_push",
            2000,
        );
        chain.append(r2).unwrap();

        let json = chain.export_json().expect("JSON export should succeed");

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should parse");

        // Check structure
        assert_eq!(parsed["length"], 2);
        assert!(parsed["head_hash"].is_string());
        assert!(parsed["receipts"].is_array());

        let receipts = parsed["receipts"].as_array().unwrap();
        assert_eq!(receipts.len(), 2);

        // First receipt should be Allow
        assert_eq!(receipts[0]["verdict"], "Allow");
        assert_eq!(receipts[0]["operation"], "read_files");
        assert_eq!(receipts[0]["subject"], "test-agent");
        assert!(receipts[0]["prev_hash"].is_string());
        assert!(receipts[0]["receipt_hash"].is_string());
        assert!(receipts[0]["pre_label"].is_object());

        // Second receipt should link to first
        let first_hash = receipts[0]["receipt_hash"].as_str().unwrap();
        let second_prev = receipts[1]["prev_hash"].as_str().unwrap();
        assert_eq!(first_hash, second_prev);
    }

    #[test]
    fn receipt_hash_is_deterministic() {
        let label = test_label(1000);
        let r1 = VerdictReceipt::from_verdict(
            FlowVerdict::Allow,
            "read_files",
            "agent-1",
            label,
            label,
            vec![1, 2, 3],
            1000,
            [0u8; 32],
        );
        let r2 = VerdictReceipt::from_verdict(
            FlowVerdict::Allow,
            "read_files",
            "agent-1",
            label,
            label,
            vec![1, 2, 3],
            1000,
            [0u8; 32],
        );
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn different_operations_produce_different_hashes() {
        let label = test_label(1000);
        let r1 = VerdictReceipt::from_verdict(
            FlowVerdict::Allow,
            "read_files",
            "agent-1",
            label,
            label,
            vec![],
            1000,
            [0u8; 32],
        );
        let r2 = VerdictReceipt::from_verdict(
            FlowVerdict::Allow,
            "write_files",
            "agent-1",
            label,
            label,
            vec![],
            1000,
            [0u8; 32],
        );
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }
}
