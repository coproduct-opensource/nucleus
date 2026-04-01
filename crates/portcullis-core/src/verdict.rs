//! Unified verdict language for scan, enforce, and audit modes.
//!
//! A single [`StructuredVerdict`] carries the full context of any kernel
//! decision, regardless of whether it was produced during static analysis
//! (scan), runtime enforcement (enforce), or post-hoc audit replay.
//!
//! ## Design principles
//!
//! 1. **One type, three modes** — scan, enforce, and audit produce identical
//!    verdict records. Downstream consumers (dashboards, audit chains, policy
//!    engines) never need to branch on which mode produced the verdict.
//!
//! 2. **Evidence-first** — every verdict carries the IFC labels, causal
//!    ancestry, and declassification tokens that justified the decision.
//!    This makes verdicts self-contained: an auditor can verify a verdict
//!    without access to the original session state.
//!
//! 3. **Minimal dependencies** — this module lives in `portcullis-core`
//!    (the Aeneas verification target). It uses only types already defined
//!    in this crate (`IFCLabel`, `SinkClass`, `Operation`).

use crate::{IFCLabel, Operation, SinkClass};

// ═══════════════════════════════════════════════════════════════════════════
// Decision — the kernel's binary-plus-deferred outcome
// ═══════════════════════════════════════════════════════════════════════════

/// The disposition of a kernel decision.
///
/// Four states form a partial order:
/// ```text
///   Allow ─────────────────── (proceed)
///   RequiresApproval ──────── (proceed after human/policy gate)
///   Quarantined ────────────── (held for inspection, not yet denied)
///   Deny ──────────────────── (rejected)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Decision {
    /// Operation is allowed unconditionally.
    Allow,
    /// Operation is denied. Carries a human-readable reason.
    Deny { reason: String },
    /// Operation requires explicit approval before proceeding.
    RequiresApproval,
    /// Operation is held in quarantine pending inspection.
    ///
    /// Unlike `Deny`, quarantine implies the operation *may* be released
    /// after review. Unlike `RequiresApproval`, the operation cannot
    /// proceed without active intervention.
    Quarantined { reason: String },
}

// ═══════════════════════════════════════════════════════════════════════════
// Mode — when the verdict was produced
// ═══════════════════════════════════════════════════════════════════════════

/// The execution mode under which the verdict was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Mode {
    /// Static analysis of a policy + manifest without executing any hooks.
    Scan,
    /// Runtime enforcement — the kernel made this decision live.
    Enforce,
    /// Post-hoc replay — re-evaluating a recorded operation against policy.
    Audit,
}

// ═══════════════════════════════════════════════════════════════════════════
// RuleSource / RuleRef — which rule triggered the decision
// ═══════════════════════════════════════════════════════════════════════════

/// The category of rule that produced a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RuleSource {
    /// A named rule from the `PolicyRuleSet`.
    PolicyRule,
    /// A capability-level gate from the lattice.
    CapabilityGate,
    /// An information-flow-control check.
    FlowCheck,
    /// An egress-policy check.
    EgressCheck,
    /// A manifest admission check (isolation level, budget, etc.).
    ManifestAdmission,
}

/// Reference to the specific rule that triggered a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RuleRef {
    /// Human-readable rule name (e.g. "no_web_in_airgap", "budget_limit").
    pub name: String,
    /// Which category of rule produced this verdict.
    pub source: RuleSource,
}

// ═══════════════════════════════════════════════════════════════════════════
// Evidence — the IFC context that justified the decision
// ═══════════════════════════════════════════════════════════════════════════

/// Evidence attached to a verdict — the IFC labels, lineage, and
/// declassification tokens that the kernel used when making the decision.
///
/// A verdict without evidence is still valid (e.g., a simple capability
/// gate that doesn't involve IFC). Fields are therefore all optional or
/// default-empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Evidence {
    /// IFC labels on the data sources that participated in this operation.
    pub source_labels: Vec<IFCLabel>,
    /// IFC label on the artifact being written/sent, if applicable.
    pub artifact_label: Option<IFCLabel>,
    /// The sink class of the operation, if applicable.
    pub sink_class: Option<SinkClass>,
    /// Receipt IDs of causal parent operations in the DAG.
    ///
    /// Used for `decide_with_parents()` verdicts where taint flows
    /// through a causal chain.
    pub causal_parents: Vec<u64>,
    /// Declassification tokens that were applied (or attempted) during
    /// this decision. Presence of a token means the label was weakened.
    pub declassification_tokens: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// StructuredVerdict — the unified verdict record
// ═══════════════════════════════════════════════════════════════════════════

/// A fully-qualified verdict record, identical across scan/enforce/audit.
///
/// Every kernel decision — whether produced by static analysis, live
/// enforcement, or audit replay — produces a `StructuredVerdict`. This
/// is the single interchange format for downstream consumers.
///
/// # Construction
///
/// Use [`StructuredVerdict::new`] for explicit construction, or
/// [`StructuredVerdict::allow`] / [`StructuredVerdict::deny`] for
/// common cases.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StructuredVerdict {
    /// The disposition: Allow, Deny, RequiresApproval, or Quarantined.
    pub decision: Decision,
    /// Which rule produced this verdict.
    pub rule: RuleRef,
    /// IFC evidence backing the decision.
    pub evidence: Evidence,
    /// Unix timestamp (seconds since epoch) when the verdict was produced.
    pub timestamp: u64,
    /// Whether this was a scan, enforce, or audit verdict.
    pub mode: Mode,
    /// The operation that was evaluated.
    pub operation: Operation,
    /// The subject (e.g. SPIFFE ID, session ID, agent name) on whose
    /// behalf the operation was evaluated.
    pub subject: String,
}

impl StructuredVerdict {
    /// Construct a new `StructuredVerdict` with all fields explicit.
    pub fn new(
        decision: Decision,
        rule: RuleRef,
        evidence: Evidence,
        timestamp: u64,
        mode: Mode,
        operation: Operation,
        subject: String,
    ) -> Self {
        Self {
            decision,
            rule,
            evidence,
            timestamp,
            mode,
            operation,
            subject,
        }
    }

    /// Convenience: construct an Allow verdict with minimal evidence.
    pub fn allow(
        rule: RuleRef,
        mode: Mode,
        operation: Operation,
        subject: String,
        timestamp: u64,
    ) -> Self {
        Self {
            decision: Decision::Allow,
            rule,
            evidence: Evidence::default(),
            timestamp,
            mode,
            operation,
            subject,
        }
    }

    /// Convenience: construct a Deny verdict with a reason string.
    pub fn deny(
        reason: impl Into<String>,
        rule: RuleRef,
        mode: Mode,
        operation: Operation,
        subject: String,
        timestamp: u64,
    ) -> Self {
        Self {
            decision: Decision::Deny {
                reason: reason.into(),
            },
            rule,
            evidence: Evidence::default(),
            timestamp,
            mode,
            operation,
            subject,
        }
    }

    /// Returns `true` if the decision is `Allow`.
    pub fn is_allowed(&self) -> bool {
        matches!(self.decision, Decision::Allow)
    }

    /// Returns `true` if the decision is `Deny`.
    pub fn is_denied(&self) -> bool {
        matches!(self.decision, Decision::Deny { .. })
    }

    /// Returns `true` if the decision is `RequiresApproval`.
    pub fn requires_approval(&self) -> bool {
        matches!(self.decision, Decision::RequiresApproval)
    }

    /// Returns `true` if the decision is `Quarantined`.
    pub fn is_quarantined(&self) -> bool {
        matches!(self.decision, Decision::Quarantined { .. })
    }

    /// Attach evidence to this verdict (builder pattern).
    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence = evidence;
        self
    }
}

impl std::fmt::Display for StructuredVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let decision_str = match &self.decision {
            Decision::Allow => "ALLOW".to_string(),
            Decision::Deny { reason } => format!("DENY({reason})"),
            Decision::RequiresApproval => "REQUIRES_APPROVAL".to_string(),
            Decision::Quarantined { reason } => format!("QUARANTINED({reason})"),
        };
        write!(
            f,
            "[{mode:?}] {decision} {op} for {subject} (rule: {rule}:{source:?})",
            mode = self.mode,
            decision = decision_str,
            op = self.operation,
            subject = self.subject,
            rule = self.rule.name,
            source = self.rule.source,
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorityLevel, ConfLevel, Freshness, IntegLevel, ProvenanceSet};

    fn sample_rule() -> RuleRef {
        RuleRef {
            name: "no_exfil".to_string(),
            source: RuleSource::FlowCheck,
        }
    }

    #[test]
    fn construct_allow_verdict() {
        let v = StructuredVerdict::allow(
            sample_rule(),
            Mode::Enforce,
            Operation::ReadFiles,
            "spiffe://nucleus/agent/a1".to_string(),
            1_700_000_000,
        );
        assert!(v.is_allowed());
        assert!(!v.is_denied());
        assert!(!v.requires_approval());
        assert!(!v.is_quarantined());
        assert_eq!(v.mode, Mode::Enforce);
        assert_eq!(v.operation, Operation::ReadFiles);
    }

    #[test]
    fn construct_deny_verdict() {
        let v = StructuredVerdict::deny(
            "budget exhausted",
            RuleRef {
                name: "budget_limit".to_string(),
                source: RuleSource::ManifestAdmission,
            },
            Mode::Scan,
            Operation::RunBash,
            "session-42".to_string(),
            1_700_000_001,
        );
        assert!(v.is_denied());
        assert!(!v.is_allowed());
        assert_eq!(
            v.decision,
            Decision::Deny {
                reason: "budget exhausted".to_string()
            }
        );
    }

    #[test]
    fn construct_requires_approval_verdict() {
        let v = StructuredVerdict::new(
            Decision::RequiresApproval,
            RuleRef {
                name: "low_risk_gate".to_string(),
                source: RuleSource::CapabilityGate,
            },
            Evidence::default(),
            1_700_000_002,
            Mode::Enforce,
            Operation::WriteFiles,
            "agent-7".to_string(),
        );
        assert!(v.requires_approval());
    }

    #[test]
    fn construct_quarantined_verdict() {
        let v = StructuredVerdict::new(
            Decision::Quarantined {
                reason: "suspicious egress pattern".to_string(),
            },
            RuleRef {
                name: "egress_anomaly".to_string(),
                source: RuleSource::EgressCheck,
            },
            Evidence::default(),
            1_700_000_003,
            Mode::Audit,
            Operation::WebFetch,
            "agent-9".to_string(),
        );
        assert!(v.is_quarantined());
        assert_eq!(v.mode, Mode::Audit);
    }

    #[test]
    fn evidence_population() {
        let label = IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::EMPTY,
            freshness: Freshness::default(),
            authority: AuthorityLevel::Directive,
        };

        let evidence = Evidence {
            source_labels: vec![label],
            artifact_label: Some(IFCLabel::default()),
            sink_class: Some(SinkClass::HTTPEgress),
            causal_parents: vec![100, 200, 300],
            declassification_tokens: vec!["declass-token-1".to_string()],
        };

        let v = StructuredVerdict::deny(
            "flow violation: exfiltration",
            RuleRef {
                name: "no_exfil".to_string(),
                source: RuleSource::FlowCheck,
            },
            Mode::Enforce,
            Operation::WebFetch,
            "agent-3".to_string(),
            1_700_000_004,
        )
        .with_evidence(evidence.clone());

        assert_eq!(v.evidence.source_labels.len(), 1);
        assert_eq!(
            v.evidence.source_labels[0].confidentiality,
            ConfLevel::Internal
        );
        assert_eq!(v.evidence.sink_class, Some(SinkClass::HTTPEgress));
        assert_eq!(v.evidence.causal_parents, vec![100, 200, 300]);
        assert_eq!(v.evidence.declassification_tokens.len(), 1);
        assert!(v.evidence.artifact_label.is_some());
    }

    #[test]
    fn display_format() {
        let v = StructuredVerdict::allow(
            sample_rule(),
            Mode::Scan,
            Operation::GrepSearch,
            "scanner".to_string(),
            0,
        );
        let s = v.to_string();
        assert!(s.contains("Scan"));
        assert!(s.contains("ALLOW"));
        assert!(s.contains("grep_search"));
        assert!(s.contains("scanner"));
        assert!(s.contains("no_exfil"));
    }

    #[test]
    fn default_evidence_is_empty() {
        let e = Evidence::default();
        assert!(e.source_labels.is_empty());
        assert!(e.artifact_label.is_none());
        assert!(e.sink_class.is_none());
        assert!(e.causal_parents.is_empty());
        assert!(e.declassification_tokens.is_empty());
    }

    #[test]
    fn all_modes() {
        // Ensure all three modes are distinct.
        assert_ne!(Mode::Scan, Mode::Enforce);
        assert_ne!(Mode::Enforce, Mode::Audit);
        assert_ne!(Mode::Scan, Mode::Audit);
    }

    #[test]
    fn all_rule_sources() {
        // Ensure all five rule sources are distinct.
        let sources = [
            RuleSource::PolicyRule,
            RuleSource::CapabilityGate,
            RuleSource::FlowCheck,
            RuleSource::EgressCheck,
            RuleSource::ManifestAdmission,
        ];
        for (i, a) in sources.iter().enumerate() {
            for (j, b) in sources.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }
}
