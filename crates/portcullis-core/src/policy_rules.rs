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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

/// TOML file format for `.nucleus/policy.toml`.
#[cfg(feature = "serde")]
#[derive(Debug, serde::Deserialize)]
struct PolicyToml {
    #[serde(default)]
    admissibility: Vec<AdmissibilityRule>,
}

#[cfg(feature = "serde")]
impl PolicyRuleSet {
    /// Load admissibility rules from `.nucleus/policy.toml` in the given directory.
    ///
    /// Returns `Ok(None)` if no `policy.toml` exists (no policy = no rules).
    /// Returns `Err` if the file exists but is malformed or has contradictory rules.
    pub fn load_from_dir(dir: &std::path::Path) -> Result<Option<Self>, PolicyLoadError> {
        let policy_file = dir.join(".nucleus").join("policy.toml");
        if !policy_file.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&policy_file)
            .map_err(|e| PolicyLoadError::Io(policy_file.display().to_string(), e.to_string()))?;
        Self::from_toml(&content).map(Some)
    }

    /// Parse admissibility rules from a TOML string.
    pub fn from_toml(content: &str) -> Result<Self, PolicyLoadError> {
        let parsed: PolicyToml =
            toml::from_str(content).map_err(|e| PolicyLoadError::Parse(e.to_string()))?;
        let mut rule_set = Self::new();
        for rule in parsed.admissibility {
            rule_set.push(rule);
        }
        rule_set.validate()?;
        Ok(rule_set)
    }

    fn validate(&self) -> Result<(), PolicyLoadError> {
        for i in 0..self.rules.len() {
            for j in (i + 1)..self.rules.len() {
                let a = &self.rules[i];
                let b = &self.rules[j];
                if a.sink_class == b.sink_class
                    && a.source_predicate == b.source_predicate
                    && a.artifact_predicate == b.artifact_predicate
                    && a.verdict != b.verdict
                {
                    return Err(PolicyLoadError::Contradiction {
                        rule_a: a.name.clone(),
                        rule_b: b.name.clone(),
                        sink: a.sink_class,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Errors from loading policy rules.
#[cfg(feature = "serde")]
#[derive(Debug)]
pub enum PolicyLoadError {
    Io(String, String),
    Parse(String),
    Contradiction {
        rule_a: String,
        rule_b: String,
        sink: SinkClass,
    },
}

#[cfg(feature = "serde")]
impl std::fmt::Display for PolicyLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "failed to read {path}: {err}"),
            Self::Parse(err) => write!(f, "TOML parse error: {err}"),
            Self::Contradiction {
                rule_a,
                rule_b,
                sink,
            } => write!(
                f,
                "contradictory rules for {sink:?}: '{rule_a}' and '{rule_b}'"
            ),
        }
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
            derivation: crate::DerivationClass::Deterministic,
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
            derivation: crate::DerivationClass::OpaqueExternal,
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
            derivation: crate::DerivationClass::Deterministic,
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

    // ── TOML loading tests (#656) ────────────────────────────────────

    #[cfg(feature = "serde")]
    mod toml_tests {
        use super::*;

        #[test]
        fn parse_toml_basic() {
            let toml = r#"
[[admissibility]]
name = "trusted code may push"
sink_class = "git_push"
verdict = "allow"

[admissibility.source_predicate]
min_integrity = "trusted"

[admissibility.artifact_predicate]
min_integrity = "trusted"
"#;
            let rules = PolicyRuleSet::from_toml(toml).unwrap();
            assert_eq!(rules.len(), 1);
            assert_eq!(rules.rules()[0].name, "trusted code may push");
            assert_eq!(rules.rules()[0].sink_class, SinkClass::GitPush);
            assert_eq!(rules.rules()[0].verdict, RuleVerdict::Allow);
        }

        #[test]
        fn parse_toml_multiple_rules() {
            let toml = r#"
[[admissibility]]
name = "deny push"
sink_class = "git_push"
verdict = "deny"
[admissibility.source_predicate]
[admissibility.artifact_predicate]

[[admissibility]]
name = "allow writes"
sink_class = "workspace_write"
verdict = "allow"
[admissibility.source_predicate]
[admissibility.artifact_predicate]
"#;
            let rules = PolicyRuleSet::from_toml(toml).unwrap();
            assert_eq!(rules.len(), 2);
        }

        #[test]
        fn parse_toml_requires_approval() {
            let toml = r#"
[[admissibility]]
name = "egress needs approval"
sink_class = "http_egress"
verdict = "requires_approval"
[admissibility.source_predicate]
[admissibility.artifact_predicate]
"#;
            let rules = PolicyRuleSet::from_toml(toml).unwrap();
            assert_eq!(rules.rules()[0].verdict, RuleVerdict::RequiresApproval);
        }

        #[test]
        fn parse_toml_empty() {
            let rules = PolicyRuleSet::from_toml("").unwrap();
            assert!(rules.is_empty());
        }

        #[test]
        fn parse_toml_invalid_rejects() {
            assert!(PolicyRuleSet::from_toml("not valid [[[ toml").is_err());
        }

        #[test]
        fn parse_toml_contradiction_detected() {
            let toml = r#"
[[admissibility]]
name = "allow push"
sink_class = "git_push"
verdict = "allow"
[admissibility.source_predicate]
[admissibility.artifact_predicate]

[[admissibility]]
name = "deny push"
sink_class = "git_push"
verdict = "deny"
[admissibility.source_predicate]
[admissibility.artifact_predicate]
"#;
            let err = PolicyRuleSet::from_toml(toml).unwrap_err();
            assert!(err.to_string().contains("contradictory"));
        }

        #[test]
        fn load_missing_dir_returns_none() {
            let dir = std::env::temp_dir().join("nucleus-test-no-policy");
            std::fs::create_dir_all(&dir).ok();
            assert!(PolicyRuleSet::load_from_dir(&dir).unwrap().is_none());
        }

        #[test]
        fn toml_predicate_fields() {
            let toml = r#"
[[admissibility]]
name = "full predicate"
sink_class = "bash_exec"
verdict = "deny"

[admissibility.source_predicate]
min_integrity = "untrusted"
max_confidentiality = "internal"
min_authority = "informational"

[admissibility.artifact_predicate]
min_integrity = "trusted"
"#;
            let rules = PolicyRuleSet::from_toml(toml).unwrap();
            let rule = &rules.rules()[0];
            assert_eq!(
                rule.source_predicate.min_integrity,
                Some(IntegLevel::Untrusted)
            );
            assert_eq!(
                rule.source_predicate.max_confidentiality,
                Some(ConfLevel::Internal)
            );
            assert_eq!(
                rule.source_predicate.min_authority,
                Some(AuthorityLevel::Informational)
            );
            assert_eq!(
                rule.artifact_predicate.min_integrity,
                Some(IntegLevel::Trusted)
            );
        }
    }
}
