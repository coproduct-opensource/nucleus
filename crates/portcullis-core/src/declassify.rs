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

use crate::{AuthorityLevel, ConfLevel, IFCLabel, IntegLevel};

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
