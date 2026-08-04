//! Gate classification — which *kind* of control decided an operation.
//!
//! EU AI Act Article 12 asks for a queryable record of AI-driven decisions that
//! distinguishes governance interventions by kind: a **hard gate** (the system
//! refused) reads differently to a **soft gate** (the system deferred to a
//! human), and both read differently to "nothing intervened". [`GateClass`]
//! makes that distinction a first-class, machine-queryable field rather than
//! something an auditor infers by string-matching a refusal message.
//!
//! # Why this lives here
//!
//! It is deliberately in `portcullis`, **not** `portcullis-core` and not
//! `kernel.rs`:
//!
//! - `portcullis-core` and `nucleus-ifc-kernel` are inside the Aeneas/Lean
//!   verification fence; adding a derived classifier there would drag a
//!   non-verified convenience type into the extracted core.
//! - `kernel.rs` is under a line ratchet with single-digit headroom, and this
//!   needs none of its internals — [`Verdict`], [`DenyReason`] and
//!   [`ExposureTransition`] are already public.
//!
//! Co-locating it in the same crate as `DenyReason` is intentional: the match
//! below is exhaustive, so adding a refusal reason is a compile error in the
//! crate the author already has open.

use crate::kernel::{DenyReason, ExposureTransition, Verdict};

/// The kind of control that decided an operation.
///
/// Ordering is not meaningful; this is a label, not a lattice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum GateClass {
    /// Allowed with no governance intervention.
    None,
    /// **Soft gate** — deferred to a human because a *static* obligation
    /// (declared in the policy) requires approval for this operation.
    StaticObligation,
    /// **Soft gate** — deferred to a human because *runtime exposure* completed
    /// a risky combination, independent of what the policy statically declared.
    /// This is the distinction `ExposureTransition::dynamic_gate_applied`
    /// carries, and it is the one an auditor most needs: the system escalated
    /// because of what it had already seen, not because of how it was configured.
    DynamicExposure,
    /// **Hard gate** — refused by the capability lattice, path/command
    /// restrictions, budget, time window, or isolation requirements.
    Capability,
    /// **Hard gate** — refused by information-flow control: taint, egress,
    /// sink scope, declassification, or a flow rule.
    InformationFlow,
    /// **Hard gate** — refused by verified admission: no valid issuer-signed
    /// credential for this operation.
    Admission,
    /// **Hard gate** — refused by an external policy engine (Cedar) or an
    /// enterprise/delegation policy layered above the lattice.
    Policy,
    /// **Hard gate** — refused because the action term itself was rejected
    /// before evaluation (malformed or out-of-scope request).
    Validation,
}

impl GateClass {
    /// Whether this class represents a refusal (as opposed to an allow or a
    /// deferral to a human).
    #[must_use]
    pub fn is_hard_gate(self) -> bool {
        matches!(
            self,
            GateClass::Capability
                | GateClass::InformationFlow
                | GateClass::Admission
                | GateClass::Policy
                | GateClass::Validation
        )
    }

    /// Whether this class represents deferral to a human — the Article 14
    /// human-oversight evidence.
    #[must_use]
    pub fn is_soft_gate(self) -> bool {
        matches!(
            self,
            GateClass::StaticObligation | GateClass::DynamicExposure
        )
    }

    /// The stable wire string. Matches the serde rename, and is what an
    /// evidence record carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            GateClass::None => "none",
            GateClass::StaticObligation => "static_obligation",
            GateClass::DynamicExposure => "dynamic_exposure",
            GateClass::Capability => "capability",
            GateClass::InformationFlow => "information_flow",
            GateClass::Admission => "admission",
            GateClass::Policy => "policy",
            GateClass::Validation => "validation",
        }
    }
}

/// Classify a decision.
///
/// `exposure` disambiguates the two soft-gate kinds: an approval requirement
/// raised by runtime exposure is [`GateClass::DynamicExposure`], one raised by
/// a static policy obligation is [`GateClass::StaticObligation`]. The kernel
/// records exactly this in `ExposureTransition::dynamic_gate_applied`.
///
/// The `DenyReason` match is **exhaustive by design** — a new refusal reason
/// must be classified here before it can be recorded, so evidence can never
/// carry an unclassified refusal.
#[must_use]
pub fn classify(verdict: &Verdict, exposure: &ExposureTransition) -> GateClass {
    match verdict {
        Verdict::Allow => GateClass::None,
        Verdict::RequiresApproval => {
            if exposure.dynamic_gate_applied {
                GateClass::DynamicExposure
            } else {
                GateClass::StaticObligation
            }
        }
        Verdict::Deny(reason) => match reason {
            DenyReason::InsufficientCapability
            | DenyReason::BudgetExhausted { .. }
            | DenyReason::TimeExpired { .. }
            | DenyReason::PathBlocked { .. }
            | DenyReason::CommandBlocked { .. }
            | DenyReason::IsolationInsufficient { .. }
            | DenyReason::IsolationGated { .. } => GateClass::Capability,

            DenyReason::EgressBlocked { .. }
            | DenyReason::FlowViolation { .. }
            | DenyReason::InvalidDeclassification { .. }
            | DenyReason::SinkScopeDenied { .. }
            | DenyReason::IfcUnsafe { .. } => GateClass::InformationFlow,

            DenyReason::DlcAdmissionDenied { .. } => GateClass::Admission,

            DenyReason::PolicyDenied { .. }
            | DenyReason::EnterpriseBlocked { .. }
            | DenyReason::DelegationDenied { .. }
            | DenyReason::CedarDenied { .. } => GateClass::Policy,

            DenyReason::ActionTermRejected { .. } => GateClass::Validation,
        },
    }
}

/// The machine-stable code for a refusal — the `DenyReason` serde tag.
///
/// **Never `Debug`.** `format!("{reason:?}")` embeds field values and changes
/// whenever a variant gains a field, so an auditor's query would silently stop
/// matching. These strings mirror `#[serde(rename_all = "snake_case")]` on
/// `DenyReason` and are covered by the round-trip test below.
#[must_use]
pub fn deny_code(reason: &DenyReason) -> &'static str {
    match reason {
        DenyReason::InsufficientCapability => "insufficient_capability",
        DenyReason::BudgetExhausted { .. } => "budget_exhausted",
        DenyReason::TimeExpired { .. } => "time_expired",
        DenyReason::PathBlocked { .. } => "path_blocked",
        DenyReason::CommandBlocked { .. } => "command_blocked",
        DenyReason::IsolationInsufficient { .. } => "isolation_insufficient",
        DenyReason::IsolationGated { .. } => "isolation_gated",
        DenyReason::EgressBlocked { .. } => "egress_blocked",
        DenyReason::DlcAdmissionDenied { .. } => "dlc_admission_denied",
        DenyReason::PolicyDenied { .. } => "policy_denied",
        DenyReason::EnterpriseBlocked { .. } => "enterprise_blocked",
        DenyReason::DelegationDenied { .. } => "delegation_denied",
        DenyReason::FlowViolation { .. } => "flow_violation",
        DenyReason::InvalidDeclassification { .. } => "invalid_declassification",
        DenyReason::SinkScopeDenied { .. } => "sink_scope_denied",
        DenyReason::ActionTermRejected { .. } => "action_term_rejected",
        DenyReason::IfcUnsafe { .. } => "ifc_unsafe",
        DenyReason::CedarDenied { .. } => "cedar_denied",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn exposure(dynamic: bool) -> ExposureTransition {
        ExposureTransition {
            pre_count: 0,
            post_count: 0,
            contributed_label: None,
            state_uninhabitable: false,
            dynamic_gate_applied: dynamic,
        }
    }

    /// Every `DenyReason` variant, constructed. Adding a variant breaks this
    /// list at compile time — which is the point: an unclassified refusal must
    /// never reach an evidence record.
    fn all_deny_reasons() -> Vec<DenyReason> {
        vec![
            DenyReason::InsufficientCapability,
            DenyReason::BudgetExhausted {
                remaining_usd: "0".to_string(),
            },
            DenyReason::TimeExpired {
                expired_at: Utc::now(),
            },
            DenyReason::PathBlocked {
                path: "/x".to_string(),
            },
            DenyReason::CommandBlocked {
                command: "rm".to_string(),
            },
            DenyReason::IsolationInsufficient {
                required: "vm".to_string(),
                actual: "none".to_string(),
            },
            DenyReason::IsolationGated {
                dimension: "network".to_string(),
            },
            DenyReason::EgressBlocked {
                host: "h".to_string(),
                policy_reason: "r".to_string(),
            },
            DenyReason::DlcAdmissionDenied {
                detail: "d".to_string(),
            },
            DenyReason::PolicyDenied {
                rule_name: "r".to_string(),
                sink_class: "s".to_string(),
            },
            DenyReason::EnterpriseBlocked {
                detail: "d".to_string(),
            },
            DenyReason::DelegationDenied {
                detail: "d".to_string(),
            },
            DenyReason::FlowViolation {
                rule: "r".to_string(),
                receipt: None,
            },
            DenyReason::InvalidDeclassification {
                detail: "d".to_string(),
            },
            DenyReason::SinkScopeDenied {
                dimension: "d".to_string(),
                detail: "x".to_string(),
            },
            DenyReason::ActionTermRejected {
                detail: "d".to_string(),
            },
            DenyReason::IfcUnsafe {
                detail: "d".to_string(),
            },
            DenyReason::CedarDenied {
                detail: "d".to_string(),
            },
        ]
    }

    #[test]
    fn every_deny_reason_classifies_as_a_hard_gate() {
        for reason in all_deny_reasons() {
            let class = classify(&Verdict::Deny(reason.clone()), &exposure(false));
            assert!(
                class.is_hard_gate(),
                "{} classified as {:?}, which is not a hard gate",
                deny_code(&reason),
                class
            );
            assert!(!class.is_soft_gate());
        }
    }

    /// ★ The codes must be the SERDE tags, not `Debug`. If `DenyReason`'s serde
    /// rename ever changes, or a variant gains a field that `Debug` would
    /// stringify, this catches it — an auditor's saved query keys on these.
    #[cfg(feature = "serde")]
    #[test]
    fn deny_code_matches_the_serde_tag() {
        for reason in all_deny_reasons() {
            let json = serde_json::to_value(&reason).expect("DenyReason serializes");
            let tag = json
                .get("reason")
                .and_then(|v| v.as_str())
                .expect("tagged representation carries `reason`");
            assert_eq!(
                deny_code(&reason),
                tag,
                "deny_code disagrees with the serde tag"
            );
        }
    }

    #[test]
    fn allow_is_not_a_gate() {
        let c = classify(&Verdict::Allow, &exposure(false));
        assert_eq!(c, GateClass::None);
        assert!(!c.is_hard_gate() && !c.is_soft_gate());
    }

    /// The soft-gate split is the Article 14 evidence: escalated because of what
    /// the session had SEEN, versus because of how it was CONFIGURED.
    #[test]
    fn approval_splits_on_dynamic_gate_applied() {
        assert_eq!(
            classify(&Verdict::RequiresApproval, &exposure(true)),
            GateClass::DynamicExposure
        );
        assert_eq!(
            classify(&Verdict::RequiresApproval, &exposure(false)),
            GateClass::StaticObligation
        );
        for c in [GateClass::DynamicExposure, GateClass::StaticObligation] {
            assert!(c.is_soft_gate() && !c.is_hard_gate());
        }
    }

    #[test]
    fn admission_denial_is_its_own_class() {
        let c = classify(
            &Verdict::Deny(DenyReason::DlcAdmissionDenied {
                detail: "no credential".to_string(),
            }),
            &exposure(false),
        );
        assert_eq!(c, GateClass::Admission);
        assert_eq!(c.as_str(), "admission");
    }

    #[test]
    fn as_str_is_distinct_per_class() {
        let all = [
            GateClass::None,
            GateClass::StaticObligation,
            GateClass::DynamicExposure,
            GateClass::Capability,
            GateClass::InformationFlow,
            GateClass::Admission,
            GateClass::Policy,
            GateClass::Validation,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for c in all {
            assert!(
                seen.insert(c.as_str()),
                "duplicate wire string {}",
                c.as_str()
            );
        }
        assert_eq!(seen.len(), all.len());
    }
}
