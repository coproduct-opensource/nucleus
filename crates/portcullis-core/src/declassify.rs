//! Declassification rules — controlled, auditable label downgrading.
//!
//! Labels are monotone by default: once data is tainted, the taint cannot
//! be removed. Declassification provides a controlled exception: specific
//! label dimensions can be downgraded under explicit, auditable conditions.
//!
//! # Trust model
//!
//! Declassification rules are policy-level declarations, not runtime escapes.
//! They must be declared before the session starts and cannot be added later
//! (monotonicity of the rule set). Each declassification produces an audit
//! entry recording what was downgraded, from what, to what, and why.
//!
//! # Example
//!
//! A web search tool returns public results. The results are web-sourced
//! (Adversarial integrity, NoAuthority) but the tool operator has verified
//! that the search API only returns curated content. A declassification
//! rule can upgrade integrity from Adversarial to Untrusted for output
//! from this specific tool.

use crate::flow::NodeId;
use crate::{AuthorityLevel, ConfLevel, IFCLabel, IntegLevel, Operation};

/// A declassification rule — permits controlled label downgrading.
///
/// Each rule specifies:
/// - Which dimension to modify
/// - What the source level must be (precondition)
/// - What the target level becomes (postcondition)
/// - A human-readable justification (for audit)
///
/// Rules are checked against the CURRENT label. If the precondition
/// matches, the label is modified. If not, the rule has no effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclassificationRule {
    /// What dimension and direction to modify.
    pub action: DeclassifyAction,
    /// Human-readable justification for this declassification.
    /// Included in audit records.
    pub justification: &'static str,
}

/// The specific label modification a declassification performs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclassifyAction {
    /// Lower confidentiality (e.g., Secret → Internal for sanitized output).
    /// Precondition: label.confidentiality >= from.
    LowerConfidentiality { from: ConfLevel, to: ConfLevel },
    /// Raise integrity (e.g., Adversarial → Untrusted for validated input).
    /// Precondition: label.integrity <= from.
    RaiseIntegrity { from: IntegLevel, to: IntegLevel },
    /// Raise authority (e.g., NoAuthority → Informational for curated content).
    /// Precondition: label.authority <= from.
    RaiseAuthority {
        from: AuthorityLevel,
        to: AuthorityLevel,
    },
}

/// Result of applying a declassification rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclassifyResult {
    /// The label after declassification (unchanged if precondition didn't match).
    pub label: IFCLabel,
    /// Whether the rule was actually applied.
    pub applied: bool,
    /// The rule that was checked.
    pub rule: DeclassificationRule,
    /// Label before declassification (for audit).
    pub original: IFCLabel,
}

impl DeclassificationRule {
    /// Apply this rule to a label. Returns the modified label and audit info.
    ///
    /// The rule only fires if the precondition matches. If not, the label
    /// is returned unchanged with `applied: false`.
    pub fn apply(&self, label: IFCLabel) -> DeclassifyResult {
        let original = label;
        let mut modified = label;
        let applied = match &self.action {
            DeclassifyAction::LowerConfidentiality { from, to } => {
                if modified.confidentiality >= *from && to < from {
                    modified.confidentiality = *to;
                    true
                } else {
                    false
                }
            }
            DeclassifyAction::RaiseIntegrity { from, to } => {
                if modified.integrity <= *from && to > from {
                    modified.integrity = *to;
                    true
                } else {
                    false
                }
            }
            DeclassifyAction::RaiseAuthority { from, to } => {
                if modified.authority <= *from && to > from {
                    modified.authority = *to;
                    true
                } else {
                    false
                }
            }
        };

        DeclassifyResult {
            label: modified,
            applied,
            rule: self.clone(),
            original,
        }
    }
}

/// A scoped, time-bounded, signed declassification token.
///
/// Unlike `DeclassificationRule` (which applies to any matching label),
/// a token targets a specific flow graph node and restricts which sinks
/// the declassified data may reach. Tokens are signed with the session's
/// Ed25519 key for tamper detection.
///
/// # Security properties
///
/// - **Artifact-scoped**: Only applies to `target_node_id`, not the whole session
/// - **Time-bounded**: Expires at `valid_until` (unix timestamp)
/// - **Sink-restricted**: Declassified data may only reach `allowed_sinks`
/// - **Signed**: Ed25519 signature over the token's canonical bytes
/// - **Auditable**: Justification string included for receipt chain
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclassificationToken {
    /// The flow graph node this token applies to.
    pub target_node_id: NodeId,
    /// The label transformation to apply.
    pub rule: DeclassificationRule,
    /// Operations that the declassified node may reach.
    /// Empty = no sinks allowed (effectively a no-op).
    pub allowed_sinks: Vec<Operation>,
    /// Unix timestamp after which this token is invalid.
    pub valid_until: u64,
    /// Human-readable justification (included in receipts).
    pub justification: String,
    /// Ed25519 signature over the token's canonical form.
    /// Zero-filled if unsigned (for testing).
    pub signature: [u8; 64],
}

/// Result of attempting to apply a declassification token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenApplyResult {
    /// Token applied successfully — label was modified.
    Applied {
        original_label: IFCLabel,
        new_label: IFCLabel,
    },
    /// Token's target node was not found in the graph.
    NodeNotFound,
    /// Token has expired (now > valid_until).
    Expired { valid_until: u64, now: u64 },
    /// The underlying rule's precondition didn't match the node's label.
    PreconditionUnmet,
    /// Ed25519 signature is missing (all zeros) or failed verification.
    InvalidSignature,
}

impl DeclassificationToken {
    /// Create a new unsigned token (for testing or when signing is deferred).
    pub fn new(
        target_node_id: NodeId,
        rule: DeclassificationRule,
        allowed_sinks: Vec<Operation>,
        valid_until: u64,
        justification: String,
    ) -> Self {
        Self {
            target_node_id,
            rule,
            allowed_sinks,
            valid_until,
            justification,
            signature: [0u8; 64],
        }
    }

    /// Check if the token has been signed (signature is not all zeros).
    pub fn is_signed(&self) -> bool {
        self.signature != [0u8; 64]
    }

    /// Set the signature bytes (called by the signing layer).
    pub fn set_signature(&mut self, sig: [u8; 64]) {
        self.signature = sig;
    }

    /// Check if the token has expired.
    pub fn is_expired(&self, now: u64) -> bool {
        now > self.valid_until
    }

    /// Check if a sink operation is allowed by this token.
    pub fn allows_sink(&self, op: Operation) -> bool {
        self.allowed_sinks.contains(&op)
    }

    /// The canonical bytes for signing: target_node_id ++ valid_until ++ rule fields ++ sinks ++ justification.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.target_node_id.to_le_bytes());
        buf.extend_from_slice(&self.valid_until.to_le_bytes());
        // Encode rule action discriminant + fields
        match &self.rule.action {
            DeclassifyAction::LowerConfidentiality { from, to } => {
                buf.push(0);
                buf.push(*from as u8);
                buf.push(*to as u8);
            }
            DeclassifyAction::RaiseIntegrity { from, to } => {
                buf.push(1);
                buf.push(*from as u8);
                buf.push(*to as u8);
            }
            DeclassifyAction::RaiseAuthority { from, to } => {
                buf.push(2);
                buf.push(*from as u8);
                buf.push(*to as u8);
            }
        }
        // Encode allowed sinks
        for op in &self.allowed_sinks {
            buf.push(*op as u8);
        }
        buf.push(0xFF); // separator
        buf.extend_from_slice(self.justification.as_bytes());
        buf
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Kani BMC harnesses — declassification safety properties
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(kani)]
mod kani_declassify_proofs {
    use super::*;
    use crate::{Freshness, ProvenanceSet};

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

    /// Generate a symbolic IFCLabel.
    fn any_label() -> IFCLabel {
        IFCLabel {
            confidentiality: any_conf(),
            integrity: any_integ(),
            provenance: ProvenanceSet::from_bits(kani::any::<u8>()),
            freshness: Freshness {
                observed_at: kani::any(),
                ttl_secs: kani::any(),
            },
            authority: any_auth(),
            derivation: any_derivation(),
        }
    }

    /// **D1 — Declassification can only lower confidentiality or raise integrity/authority.**
    ///
    /// For any symbolic label and any declassification rule: the resulting label
    /// never has HIGHER confidentiality, LOWER integrity, or LOWER authority
    /// than the original. Provenance and freshness are never modified.
    ///
    /// This is the core safety property: declassification can only weaken
    /// restrictions (lower conf) or strengthen guarantees (raise integ/auth),
    /// never the reverse.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_declassification_only_weakens_restrictions() {
        let label = any_label();
        let from_conf = any_conf();
        let to_conf = any_conf();
        let from_integ = any_integ();
        let to_integ = any_integ();
        let from_auth = any_auth();
        let to_auth = any_auth();

        // Test all three action kinds via symbolic choice
        let action_kind: u8 = kani::any();
        kani::assume(action_kind <= 2);

        let rule = match action_kind {
            0 => DeclassificationRule {
                action: DeclassifyAction::LowerConfidentiality {
                    from: from_conf,
                    to: to_conf,
                },
                justification: "kani",
            },
            1 => DeclassificationRule {
                action: DeclassifyAction::RaiseIntegrity {
                    from: from_integ,
                    to: to_integ,
                },
                justification: "kani",
            },
            _ => DeclassificationRule {
                action: DeclassifyAction::RaiseAuthority {
                    from: from_auth,
                    to: to_auth,
                },
                justification: "kani",
            },
        };

        let result = rule.apply(label);

        // Confidentiality can only decrease or stay the same
        assert!(result.label.confidentiality <= label.confidentiality);
        // Integrity can only increase or stay the same
        assert!(result.label.integrity >= label.integrity);
        // Authority can only increase or stay the same
        assert!(result.label.authority >= label.authority);
        // Provenance is never modified
        assert_eq!(result.label.provenance.bits(), label.provenance.bits());
        // Freshness is never modified
        assert_eq!(
            result.label.freshness.observed_at,
            label.freshness.observed_at
        );
        assert_eq!(result.label.freshness.ttl_secs, label.freshness.ttl_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Freshness, ProvenanceSet};

    fn web_label() -> IFCLabel {
        IFCLabel {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Adversarial,
            provenance: ProvenanceSet::WEB,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::NoAuthority,
            derivation: crate::DerivationClass::OpaqueExternal,
        }
    }

    fn secret_label() -> IFCLabel {
        IFCLabel {
            confidentiality: ConfLevel::Secret,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::SYSTEM,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: crate::DerivationClass::Deterministic,
        }
    }

    #[test]
    fn raise_integrity_for_validated_input() {
        let rule = DeclassificationRule {
            action: DeclassifyAction::RaiseIntegrity {
                from: IntegLevel::Adversarial,
                to: IntegLevel::Untrusted,
            },
            justification: "Search API returns curated content",
        };
        let result = rule.apply(web_label());
        assert!(result.applied);
        assert_eq!(result.label.integrity, IntegLevel::Untrusted);
        // Other dimensions unchanged
        assert_eq!(result.label.authority, AuthorityLevel::NoAuthority);
        assert_eq!(result.label.confidentiality, ConfLevel::Public);
    }

    #[test]
    fn raise_authority_for_curated_content() {
        let rule = DeclassificationRule {
            action: DeclassifyAction::RaiseAuthority {
                from: AuthorityLevel::NoAuthority,
                to: AuthorityLevel::Informational,
            },
            justification: "Tool output is informational only",
        };
        let result = rule.apply(web_label());
        assert!(result.applied);
        assert_eq!(result.label.authority, AuthorityLevel::Informational);
    }

    #[test]
    fn lower_confidentiality_for_sanitized_output() {
        let rule = DeclassificationRule {
            action: DeclassifyAction::LowerConfidentiality {
                from: ConfLevel::Secret,
                to: ConfLevel::Internal,
            },
            justification: "Output sanitized by redaction filter",
        };
        let result = rule.apply(secret_label());
        assert!(result.applied);
        assert_eq!(result.label.confidentiality, ConfLevel::Internal);
    }

    #[test]
    fn rule_does_not_fire_if_precondition_unmet() {
        let rule = DeclassificationRule {
            action: DeclassifyAction::RaiseIntegrity {
                from: IntegLevel::Adversarial,
                to: IntegLevel::Untrusted,
            },
            justification: "N/A",
        };
        // Label already has Trusted integrity — precondition (<=Adversarial) doesn't match
        let result = rule.apply(secret_label());
        assert!(!result.applied);
        assert_eq!(result.label, secret_label());
    }

    #[test]
    fn cannot_raise_beyond_target() {
        // Rule says Adversarial → Untrusted, not Adversarial → Trusted
        let rule = DeclassificationRule {
            action: DeclassifyAction::RaiseIntegrity {
                from: IntegLevel::Adversarial,
                to: IntegLevel::Untrusted,
            },
            justification: "Partial trust",
        };
        let result = rule.apply(web_label());
        assert!(result.applied);
        assert_eq!(
            result.label.integrity,
            IntegLevel::Untrusted,
            "Must not exceed target"
        );
    }

    #[test]
    fn cannot_lower_below_target() {
        let rule = DeclassificationRule {
            action: DeclassifyAction::LowerConfidentiality {
                from: ConfLevel::Secret,
                to: ConfLevel::Internal,
            },
            justification: "Sanitized",
        };
        let result = rule.apply(secret_label());
        assert!(result.applied);
        assert_eq!(
            result.label.confidentiality,
            ConfLevel::Internal,
            "Must not go below target"
        );
    }

    #[test]
    fn audit_trail_preserved() {
        let rule = DeclassificationRule {
            action: DeclassifyAction::RaiseAuthority {
                from: AuthorityLevel::NoAuthority,
                to: AuthorityLevel::Informational,
            },
            justification: "Curated search results",
        };
        let original = web_label();
        let result = rule.apply(original);
        assert_eq!(result.original, original);
        assert_eq!(result.rule.justification, "Curated search results");
    }

    // ── DeclassificationToken tests ──────────────────────────────────

    #[test]
    fn token_expiry() {
        let token = DeclassificationToken::new(
            42,
            DeclassificationRule {
                action: DeclassifyAction::RaiseIntegrity {
                    from: IntegLevel::Adversarial,
                    to: IntegLevel::Untrusted,
                },
                justification: "test",
            },
            vec![Operation::WriteFiles],
            1000,
            "test justification".to_string(),
        );
        assert!(!token.is_expired(999));
        assert!(!token.is_expired(1000));
        assert!(token.is_expired(1001));
    }

    #[test]
    fn token_sink_restriction() {
        let token = DeclassificationToken::new(
            42,
            DeclassificationRule {
                action: DeclassifyAction::RaiseIntegrity {
                    from: IntegLevel::Adversarial,
                    to: IntegLevel::Untrusted,
                },
                justification: "test",
            },
            vec![Operation::WriteFiles, Operation::GitCommit],
            u64::MAX,
            "allow write and commit only".to_string(),
        );
        assert!(token.allows_sink(Operation::WriteFiles));
        assert!(token.allows_sink(Operation::GitCommit));
        assert!(!token.allows_sink(Operation::GitPush));
        assert!(!token.allows_sink(Operation::RunBash));
    }

    #[test]
    fn token_empty_sinks_allows_nothing() {
        let token = DeclassificationToken::new(
            42,
            DeclassificationRule {
                action: DeclassifyAction::RaiseIntegrity {
                    from: IntegLevel::Adversarial,
                    to: IntegLevel::Untrusted,
                },
                justification: "test",
            },
            vec![],
            u64::MAX,
            "no sinks allowed".to_string(),
        );
        assert!(!token.allows_sink(Operation::WriteFiles));
        assert!(!token.allows_sink(Operation::RunBash));
    }

    #[test]
    fn token_canonical_bytes_deterministic() {
        let token = DeclassificationToken::new(
            42,
            DeclassificationRule {
                action: DeclassifyAction::RaiseIntegrity {
                    from: IntegLevel::Adversarial,
                    to: IntegLevel::Untrusted,
                },
                justification: "test",
            },
            vec![Operation::WriteFiles],
            1000,
            "justification".to_string(),
        );
        let bytes1 = token.canonical_bytes();
        let bytes2 = token.canonical_bytes();
        assert_eq!(bytes1, bytes2, "canonical bytes must be deterministic");
        assert!(!bytes1.is_empty());
    }

    #[test]
    fn token_different_params_different_bytes() {
        let token1 = DeclassificationToken::new(
            42,
            DeclassificationRule {
                action: DeclassifyAction::RaiseIntegrity {
                    from: IntegLevel::Adversarial,
                    to: IntegLevel::Untrusted,
                },
                justification: "test",
            },
            vec![Operation::WriteFiles],
            1000,
            "same".to_string(),
        );
        let token2 = DeclassificationToken::new(
            99, // different node
            DeclassificationRule {
                action: DeclassifyAction::RaiseIntegrity {
                    from: IntegLevel::Adversarial,
                    to: IntegLevel::Untrusted,
                },
                justification: "test",
            },
            vec![Operation::WriteFiles],
            1000,
            "same".to_string(),
        );
        assert_ne!(token1.canonical_bytes(), token2.canonical_bytes());
    }

    #[test]
    fn wrong_direction_rejected() {
        // Trying to "lower" confidentiality with to > from — should not apply
        let rule = DeclassificationRule {
            action: DeclassifyAction::LowerConfidentiality {
                from: ConfLevel::Internal,
                to: ConfLevel::Secret, // to > from — wrong direction
            },
            justification: "Invalid",
        };
        let label = IFCLabel {
            confidentiality: ConfLevel::Internal,
            ..web_label()
        };
        let result = rule.apply(label);
        assert!(!result.applied, "Cannot escalate via declassification");
    }
}
