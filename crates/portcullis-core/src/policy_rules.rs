//! Admissibility rules — declarative source/artifact/sink policy predicates.
//!
//! The policy plane expresses admissibility as rules over
//! source→artifact→sink triples. Each rule specifies:
//! - What source labels are required (min integrity, max confidentiality)
//! - What artifact labels are required (provenance, authority)
//! - Which sink class the rule applies to
//! - What verdict to render (Allow, Deny, RequiresApproval)
//!
//! Rules are evaluated in order (first match wins). If no rule matches,
//! the default verdict is Deny (fail-closed).

use crate::{AuthorityLevel, ConfLevel, IFCLabel, IntegLevel, SinkClass};

/// A predicate over IFC label dimensions.
///
/// Each field is an optional bound. `None` means "any value matches."
/// All specified bounds must be satisfied for the predicate to match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelPredicate {
    /// Minimum integrity required (label.integrity >= this).
    pub min_integrity: Option<IntegLevel>,
    /// Maximum confidentiality allowed (label.confidentiality <= this).
    pub max_confidentiality: Option<ConfLevel>,
    /// Minimum authority required (label.authority >= this).
    pub min_authority: Option<AuthorityLevel>,
}

impl LabelPredicate {
    /// A predicate that matches any label.
    pub fn any() -> Self {
        Self {
            min_integrity: None,
            max_confidentiality: None,
            min_authority: None,
        }
    }

    /// Check whether a label satisfies this predicate.
    pub fn matches(&self, label: &IFCLabel) -> bool {
        if let Some(min_integ) = self.min_integrity
            && label.integrity < min_integ
        {
            return false;
        }
        if let Some(max_conf) = self.max_confidentiality
            && label.confidentiality > max_conf
        {
            return false;
        }
        if let Some(min_auth) = self.min_authority
            && label.authority < min_auth
        {
            return false;
        }
        true
    }
}

impl Default for LabelPredicate {
    fn default() -> Self {
        Self::any()
    }
}

/// The verdict of an admissibility rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleVerdict {
    /// The flow is allowed.
    Allow,
    /// The flow is denied.
    Deny,
    /// The flow requires human approval before proceeding.
    RequiresApproval,
}

/// A single admissibility rule: source predicate × artifact predicate × sink → verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissibilityRule {
    /// Human-readable name for this rule (for audit/diagnostics).
    pub name: String,
    /// Predicate on the source labels (data origin).
    pub source_predicate: LabelPredicate,
    /// Predicate on the artifact labels (data lineage through the graph).
    pub artifact_predicate: LabelPredicate,
    /// Which sink class this rule applies to.
    pub sink_class: SinkClass,
    /// What verdict to render when both predicates match.
    pub verdict: RuleVerdict,
}

/// Result of evaluating a rule set against a proposed flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    /// The verdict (from the first matching rule, or default Deny).
    pub verdict: RuleVerdict,
    /// The index of the matching rule (None if default-deny).
    pub matched_rule: Option<usize>,
    /// The name of the matching rule (empty if default-deny).
    pub rule_name: String,
}

/// An ordered set of admissibility rules. First match wins.
///
/// If no rule matches, the default verdict is `Deny` (fail-closed).
#[derive(Debug, Clone, Default)]
pub struct PolicyRuleSet {
    rules: Vec<AdmissibilityRule>,
}

impl PolicyRuleSet {
    /// Create an empty rule set (default-deny everything).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule to the end of the set (lowest priority).
    pub fn push(&mut self, rule: AdmissibilityRule) {
        self.rules.push(rule);
    }

    /// Number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the rule set is empty.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluate the rule set against a proposed flow.
    ///
    /// `source_labels` — the IFC labels of the data sources (inputs to the artifact).
    /// `artifact_label` — the propagated label of the artifact being written to the sink.
    /// `sink` — the sink class being targeted.
    ///
    /// Returns the first matching rule's verdict, or Deny if no rule matches.
    pub fn evaluate(
        &self,
        source_labels: &[IFCLabel],
        artifact_label: &IFCLabel,
        sink: SinkClass,
    ) -> PolicyEvaluation {
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.sink_class != sink {
                continue;
            }
            // Source predicate: ALL source labels must match.
            let sources_match = source_labels.is_empty()
                || source_labels
                    .iter()
                    .all(|sl| rule.source_predicate.matches(sl));
            if !sources_match {
                continue;
            }
            // Artifact predicate: the propagated artifact label must match.
            if !rule.artifact_predicate.matches(artifact_label) {
                continue;
            }
            return PolicyEvaluation {
                verdict: rule.verdict,
                matched_rule: Some(i),
                rule_name: rule.name.clone(),
            };
        }
        // Default: deny (fail-closed)
        PolicyEvaluation {
            verdict: RuleVerdict::Deny,
            matched_rule: None,
            rule_name: String::new(),
        }
    }

    /// Get a reference to the rules (for inspection/serialization).
    pub fn rules(&self) -> &[AdmissibilityRule] {
        &self.rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Freshness, ProvenanceSet};

    fn trusted_label() -> IFCLabel {
        IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            authority: AuthorityLevel::Directive,
            provenance: ProvenanceSet::SYSTEM,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 0,
            },
        }
    }

    fn adversarial_label() -> IFCLabel {
        IFCLabel {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Adversarial,
            authority: AuthorityLevel::NoAuthority,
            provenance: ProvenanceSet::WEB,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 0,
            },
        }
    }

    fn secret_label() -> IFCLabel {
        IFCLabel {
            confidentiality: ConfLevel::Secret,
            integrity: IntegLevel::Trusted,
            authority: AuthorityLevel::Directive,
            provenance: ProvenanceSet::SYSTEM,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 0,
            },
        }
    }

    // ── LabelPredicate tests ─────────────────────────────────────────

    #[test]
    fn any_predicate_matches_everything() {
        let pred = LabelPredicate::any();
        assert!(pred.matches(&trusted_label()));
        assert!(pred.matches(&adversarial_label()));
        assert!(pred.matches(&secret_label()));
    }

    #[test]
    fn min_integrity_filters() {
        let pred = LabelPredicate {
            min_integrity: Some(IntegLevel::Untrusted),
            ..LabelPredicate::any()
        };
        assert!(pred.matches(&trusted_label())); // Trusted >= Untrusted
        assert!(!pred.matches(&adversarial_label())); // Adversarial < Untrusted
    }

    #[test]
    fn max_confidentiality_filters() {
        let pred = LabelPredicate {
            max_confidentiality: Some(ConfLevel::Internal),
            ..LabelPredicate::any()
        };
        assert!(pred.matches(&trusted_label())); // Internal <= Internal
        assert!(pred.matches(&adversarial_label())); // Public <= Internal
        assert!(!pred.matches(&secret_label())); // Secret > Internal
    }

    #[test]
    fn min_authority_filters() {
        let pred = LabelPredicate {
            min_authority: Some(AuthorityLevel::Informational),
            ..LabelPredicate::any()
        };
        assert!(pred.matches(&trusted_label())); // Directive >= Informational
        assert!(!pred.matches(&adversarial_label())); // NoAuthority < Informational
    }

    #[test]
    fn combined_predicate() {
        let pred = LabelPredicate {
            min_integrity: Some(IntegLevel::Trusted),
            max_confidentiality: Some(ConfLevel::Internal),
            min_authority: None,
        };
        assert!(pred.matches(&trusted_label())); // Trusted + Internal
        assert!(!pred.matches(&adversarial_label())); // fails integrity
        assert!(!pred.matches(&secret_label())); // fails confidentiality
    }

    // ── PolicyRuleSet tests ──────────────────────────────────────────

    #[test]
    fn empty_rule_set_denies_everything() {
        let rules = PolicyRuleSet::new();
        let result = rules.evaluate(&[trusted_label()], &trusted_label(), SinkClass::GitPush);
        assert_eq!(result.verdict, RuleVerdict::Deny);
        assert!(result.matched_rule.is_none());
    }

    #[test]
    fn matching_rule_allows() {
        let mut rules = PolicyRuleSet::new();
        rules.push(AdmissibilityRule {
            name: "trusted code may push".to_string(),
            source_predicate: LabelPredicate {
                min_integrity: Some(IntegLevel::Trusted),
                ..LabelPredicate::any()
            },
            artifact_predicate: LabelPredicate {
                min_integrity: Some(IntegLevel::Trusted),
                ..LabelPredicate::any()
            },
            sink_class: SinkClass::GitPush,
            verdict: RuleVerdict::Allow,
        });

        let result = rules.evaluate(&[trusted_label()], &trusted_label(), SinkClass::GitPush);
        assert_eq!(result.verdict, RuleVerdict::Allow);
        assert_eq!(result.matched_rule, Some(0));
        assert_eq!(result.rule_name, "trusted code may push");
    }

    #[test]
    fn non_matching_rule_falls_through_to_deny() {
        let mut rules = PolicyRuleSet::new();
        rules.push(AdmissibilityRule {
            name: "trusted code may push".to_string(),
            source_predicate: LabelPredicate {
                min_integrity: Some(IntegLevel::Trusted),
                ..LabelPredicate::any()
            },
            artifact_predicate: LabelPredicate::any(),
            sink_class: SinkClass::GitPush,
            verdict: RuleVerdict::Allow,
        });

        // Adversarial source → rule doesn't match → default deny
        let result = rules.evaluate(
            &[adversarial_label()],
            &adversarial_label(),
            SinkClass::GitPush,
        );
        assert_eq!(result.verdict, RuleVerdict::Deny);
        assert!(result.matched_rule.is_none());
    }

    #[test]
    fn first_match_wins() {
        let mut rules = PolicyRuleSet::new();
        // Rule 0: deny web content to GitPush
        rules.push(AdmissibilityRule {
            name: "block web to push".to_string(),
            source_predicate: LabelPredicate::any(),
            artifact_predicate: LabelPredicate {
                min_integrity: None,
                max_confidentiality: None,
                min_authority: None,
            },
            sink_class: SinkClass::GitPush,
            verdict: RuleVerdict::Deny,
        });
        // Rule 1: allow trusted to GitPush (would match, but rule 0 fires first)
        rules.push(AdmissibilityRule {
            name: "allow trusted push".to_string(),
            source_predicate: LabelPredicate {
                min_integrity: Some(IntegLevel::Trusted),
                ..LabelPredicate::any()
            },
            artifact_predicate: LabelPredicate::any(),
            sink_class: SinkClass::GitPush,
            verdict: RuleVerdict::Allow,
        });

        let result = rules.evaluate(&[trusted_label()], &trusted_label(), SinkClass::GitPush);
        assert_eq!(result.verdict, RuleVerdict::Deny, "first match wins");
        assert_eq!(result.matched_rule, Some(0));
    }

    #[test]
    fn sink_class_filters() {
        let mut rules = PolicyRuleSet::new();
        rules.push(AdmissibilityRule {
            name: "allow writes".to_string(),
            source_predicate: LabelPredicate::any(),
            artifact_predicate: LabelPredicate::any(),
            sink_class: SinkClass::WorkspaceWrite,
            verdict: RuleVerdict::Allow,
        });

        // Rule is for WorkspaceWrite, not GitPush → doesn't match
        let result = rules.evaluate(&[trusted_label()], &trusted_label(), SinkClass::GitPush);
        assert_eq!(result.verdict, RuleVerdict::Deny);

        // Correct sink → matches
        let result = rules.evaluate(
            &[trusted_label()],
            &trusted_label(),
            SinkClass::WorkspaceWrite,
        );
        assert_eq!(result.verdict, RuleVerdict::Allow);
    }

    #[test]
    fn requires_approval_verdict() {
        let mut rules = PolicyRuleSet::new();
        rules.push(AdmissibilityRule {
            name: "secret data needs approval for egress".to_string(),
            source_predicate: LabelPredicate::any(),
            artifact_predicate: LabelPredicate {
                max_confidentiality: None, // match anything
                min_integrity: None,
                min_authority: None,
            },
            sink_class: SinkClass::HTTPEgress,
            verdict: RuleVerdict::RequiresApproval,
        });

        let result = rules.evaluate(&[secret_label()], &secret_label(), SinkClass::HTTPEgress);
        assert_eq!(result.verdict, RuleVerdict::RequiresApproval);
    }

    #[test]
    fn all_sources_must_match() {
        let mut rules = PolicyRuleSet::new();
        rules.push(AdmissibilityRule {
            name: "only trusted sources to push".to_string(),
            source_predicate: LabelPredicate {
                min_integrity: Some(IntegLevel::Trusted),
                ..LabelPredicate::any()
            },
            artifact_predicate: LabelPredicate::any(),
            sink_class: SinkClass::GitPush,
            verdict: RuleVerdict::Allow,
        });

        // One trusted + one adversarial → fails (ALL must match)
        let result = rules.evaluate(
            &[trusted_label(), adversarial_label()],
            &trusted_label(),
            SinkClass::GitPush,
        );
        assert_eq!(result.verdict, RuleVerdict::Deny);
    }

    #[test]
    fn no_sources_matches_any_source_predicate() {
        let mut rules = PolicyRuleSet::new();
        rules.push(AdmissibilityRule {
            name: "allow no-source workspace write".to_string(),
            source_predicate: LabelPredicate {
                min_integrity: Some(IntegLevel::Trusted),
                ..LabelPredicate::any()
            },
            artifact_predicate: LabelPredicate::any(),
            sink_class: SinkClass::WorkspaceWrite,
            verdict: RuleVerdict::Allow,
        });

        // No sources → vacuously true
        let result = rules.evaluate(&[], &trusted_label(), SinkClass::WorkspaceWrite);
        assert_eq!(result.verdict, RuleVerdict::Allow);
    }
}
