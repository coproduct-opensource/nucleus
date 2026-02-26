//! Unified pipeline composing lattice-guard modules into a single analysis flow.
//!
//! Bridges four integration gaps between modules that previously operated in isolation:
//!
//! 1. **Heyting → Weakening**: Algebraic gap computation connected to cost quantification
//! 2. **Graded → Escalation**: Risk accumulation triggers escalation when intervention required
//! 3. **Modal → Obligations**: Necessity computation explains WHY capabilities are stripped
//! 4. **Galois → Weakening**: Domain translation annotated with weakening costs

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::capability::{
    CapabilityLattice, CapabilityLevel, IncompatibilityConstraint, Operation, TrifectaRisk,
};
use crate::escalation::{EscalationRequest, SpiffeTraceChain};
use crate::galois::{BridgeChain, TranslationReport};
use crate::graded::Graded;
use crate::heyting::permission_gap;
use crate::modal::ModalPermissions;
use crate::weakening::{WeakeningCost, WeakeningCostConfig, WeakeningDimension, WeakeningGap};
use crate::PermissionLattice;

use chrono::Utc;
use uuid::Uuid;

// ═══════════════════════════════════════════════════════════════════════════
// PIPELINE TRACE
// ═══════════════════════════════════════════════════════════════════════════

/// Complete trace of a pipeline evaluation across all four bridges.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PipelineTrace {
    /// Bridge 1: Heyting → Weakening algebraic gap analysis
    pub algebraic_gap: Option<AlgebraicWeakeningGap>,
    /// Bridge 2: Graded → Escalation risk evaluation
    pub risk_evaluation: Option<RiskEvaluation>,
    /// Bridge 3: Modal → Obligations justification
    pub modal_justification: Option<ModalJustification>,
    /// Bridge 4: Galois → Weakening cost-annotated translation
    pub translation_cost: Option<CostAnnotatedTranslation>,
}

// ═══════════════════════════════════════════════════════════════════════════
// BRIDGE 1: Heyting → Weakening
// ═══════════════════════════════════════════════════════════════════════════

/// A weakening gap derived through Heyting implication.
///
/// The `algebraic_delta` records `actual.implies(floor)` — fields where this
/// is NOT `Always` indicate dimensions where actual exceeds floor.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AlgebraicWeakeningGap {
    /// Heyting implication `actual → floor` (non-Always = weakening)
    pub algebraic_delta: CapabilityLattice,
    /// Priced gap derived from the algebraic delta
    pub priced_gap: WeakeningGap,
    /// Whether algebraic and manual methods agree on capability request count
    pub consistent: bool,
}

/// Compute the weakening gap algebraically via Heyting implication, then price it.
///
/// Uses `permission_gap(actual, floor)` = `actual.implies(floor)`. Where the
/// result is NOT `Always`, actual exceeds floor — a weakening that needs pricing.
pub fn algebraic_gap(
    floor: &PermissionLattice,
    actual: &PermissionLattice,
    cost_config: &WeakeningCostConfig,
) -> AlgebraicWeakeningGap {
    let delta = permission_gap(&actual.capabilities, &floor.capabilities);

    let constraint = IncompatibilityConstraint::enforcing();
    let floor_trifecta = constraint.trifecta_risk(&floor.capabilities);
    let actual_trifecta = constraint.trifecta_risk(&actual.capabilities);
    let trifecta_mult = cost_config.trifecta_multiplier(floor_trifecta, actual_trifecta);

    let mut gap = WeakeningGap::empty();

    let checks: &[(Operation, CapabilityLevel, CapabilityLevel, CapabilityLevel)] = &[
        (
            Operation::ReadFiles,
            delta.read_files,
            floor.capabilities.read_files,
            actual.capabilities.read_files,
        ),
        (
            Operation::WriteFiles,
            delta.write_files,
            floor.capabilities.write_files,
            actual.capabilities.write_files,
        ),
        (
            Operation::EditFiles,
            delta.edit_files,
            floor.capabilities.edit_files,
            actual.capabilities.edit_files,
        ),
        (
            Operation::RunBash,
            delta.run_bash,
            floor.capabilities.run_bash,
            actual.capabilities.run_bash,
        ),
        (
            Operation::GlobSearch,
            delta.glob_search,
            floor.capabilities.glob_search,
            actual.capabilities.glob_search,
        ),
        (
            Operation::GrepSearch,
            delta.grep_search,
            floor.capabilities.grep_search,
            actual.capabilities.grep_search,
        ),
        (
            Operation::WebSearch,
            delta.web_search,
            floor.capabilities.web_search,
            actual.capabilities.web_search,
        ),
        (
            Operation::WebFetch,
            delta.web_fetch,
            floor.capabilities.web_fetch,
            actual.capabilities.web_fetch,
        ),
        (
            Operation::GitCommit,
            delta.git_commit,
            floor.capabilities.git_commit,
            actual.capabilities.git_commit,
        ),
        (
            Operation::GitPush,
            delta.git_push,
            floor.capabilities.git_push,
            actual.capabilities.git_push,
        ),
        (
            Operation::CreatePr,
            delta.create_pr,
            floor.capabilities.create_pr,
            actual.capabilities.create_pr,
        ),
        (
            Operation::ManagePods,
            delta.manage_pods,
            floor.capabilities.manage_pods,
            actual.capabilities.manage_pods,
        ),
    ];

    for &(op, delta_level, floor_level, actual_level) in checks {
        if delta_level != CapabilityLevel::Always {
            let mut cost = cost_config.capability_cost(floor_level, actual_level);
            cost.trifecta_multiplier = trifecta_mult;
            gap.add(crate::weakening::WeakeningRequest::capability(
                op,
                floor_level,
                actual_level,
                cost,
                actual_trifecta,
            ));
        }
    }

    // Consistency check: compare against compute_gap's 8 tracked operations.
    // The algebraic approach covers all 12 fields; compute_gap covers 8.
    let manual = cost_config.compute_gap(floor, actual);
    let tracked_ops = [
        Operation::ReadFiles,
        Operation::WriteFiles,
        Operation::EditFiles,
        Operation::RunBash,
        Operation::WebSearch,
        Operation::WebFetch,
        Operation::GitPush,
        Operation::CreatePr,
    ];
    let alg_tracked = gap
        .requests
        .iter()
        .filter(|r| match &r.dimension {
            WeakeningDimension::Capability(op) => tracked_ops.contains(op),
            _ => false,
        })
        .count();
    let manual_cap_count = manual
        .requests
        .iter()
        .filter(|r| matches!(r.dimension, WeakeningDimension::Capability(_)))
        .count();

    AlgebraicWeakeningGap {
        algebraic_delta: delta,
        priced_gap: gap,
        consistent: alg_tracked == manual_cap_count,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BRIDGE 2: Graded → Escalation
// ═══════════════════════════════════════════════════════════════════════════

/// Result of evaluating a graded computation's risk and escalation needs.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RiskEvaluation {
    /// The trifecta risk level observed
    pub risk: TrifectaRisk,
    /// Whether intervention is required
    pub requires_intervention: bool,
    /// Escalation trigger details, if intervention is needed
    pub trigger: Option<EscalationTrigger>,
}

/// Context for constructing an `EscalationRequest` (pure, no SPIFFE runtime).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EscalationTrigger {
    /// Risk grade that triggered escalation
    pub risk: TrifectaRisk,
    /// Current permissions being evaluated
    pub current_permissions: PermissionLattice,
    /// Target permissions that require escalation
    pub requested_permissions: PermissionLattice,
    /// Human-readable reason
    pub reason: String,
    /// Suggested TTL for escalated permissions
    pub suggested_ttl_seconds: u64,
}

impl EscalationTrigger {
    /// Convert into a full `EscalationRequest` given the requestor's SPIFFE chain.
    pub fn into_request(self, requestor_chain: SpiffeTraceChain) -> EscalationRequest {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(self.suggested_ttl_seconds as i64);
        EscalationRequest {
            id: Uuid::new_v4(),
            requestor_chain,
            requested: self.requested_permissions,
            reason: self.reason,
            ttl_seconds: self.suggested_ttl_seconds,
            created_at: now,
            expires_at,
        }
    }
}

/// Evaluate a graded computation's risk and produce escalation trigger if needed.
pub fn evaluate_and_escalate<A>(
    graded: &Graded<TrifectaRisk, A>,
    current_perms: &PermissionLattice,
    target_perms: &PermissionLattice,
    reason: impl Into<String>,
) -> RiskEvaluation {
    let requires = graded.grade.requires_intervention();
    let trigger = if requires {
        Some(EscalationTrigger {
            risk: graded.grade,
            current_permissions: current_perms.clone(),
            requested_permissions: target_perms.clone(),
            reason: reason.into(),
            suggested_ttl_seconds: 3600,
        })
    } else {
        None
    };
    RiskEvaluation {
        risk: graded.grade,
        requires_intervention: requires,
        trigger,
    }
}

/// Natural transformation: `Graded<TrifectaRisk, A> → Result<A, Box<EscalationTrigger>>`.
pub fn require_or_escalate<A>(
    graded: Graded<TrifectaRisk, A>,
    current_perms: &PermissionLattice,
    target_perms: &PermissionLattice,
    reason: impl Into<String>,
    suggested_ttl: u64,
) -> Result<A, Box<EscalationTrigger>> {
    if graded.grade.requires_intervention() {
        Err(Box::new(EscalationTrigger {
            risk: graded.grade,
            current_permissions: current_perms.clone(),
            requested_permissions: target_perms.clone(),
            reason: reason.into(),
            suggested_ttl_seconds: suggested_ttl,
        }))
    } else {
        Ok(graded.value)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BRIDGE 3: Modal → Obligation Justification
// ═══════════════════════════════════════════════════════════════════════════

/// Explains WHY necessity stripped specific capabilities.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ModalJustification {
    /// Per-capability justification entries
    pub entries: Vec<ModalJustificationEntry>,
    /// Total capabilities stripped
    pub capabilities_stripped: usize,
    /// Unique obligations causing stripping
    pub obligations_involved: usize,
}

/// Justification for a single capability stripped by necessity.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ModalJustificationEntry {
    /// The operation that was stripped
    pub operation: Operation,
    /// Capability level before stripping
    pub original_level: CapabilityLevel,
    /// Obligations that caused this stripping
    pub caused_by_obligations: Vec<Operation>,
    /// Trifecta risk context
    pub trifecta_context: TrifectaRisk,
}

/// Compute necessity with justification of WHY each capability was stripped.
pub fn justify_necessity(perms: &PermissionLattice) -> (PermissionLattice, ModalJustification) {
    let necessary = perms.necessity();

    let constraint = IncompatibilityConstraint::enforcing();
    let trifecta = constraint.trifecta_risk(&perms.capabilities);
    let trifecta_obligations = constraint.obligations_for(&perms.capabilities);

    let mut entries = Vec::new();
    let mut obligations_set: std::collections::BTreeSet<Operation> =
        std::collections::BTreeSet::new();

    let op_levels: &[(Operation, CapabilityLevel)] = &[
        (Operation::ReadFiles, perms.capabilities.read_files),
        (Operation::WriteFiles, perms.capabilities.write_files),
        (Operation::EditFiles, perms.capabilities.edit_files),
        (Operation::RunBash, perms.capabilities.run_bash),
        (Operation::GlobSearch, perms.capabilities.glob_search),
        (Operation::GrepSearch, perms.capabilities.grep_search),
        (Operation::WebSearch, perms.capabilities.web_search),
        (Operation::WebFetch, perms.capabilities.web_fetch),
        (Operation::GitCommit, perms.capabilities.git_commit),
        (Operation::GitPush, perms.capabilities.git_push),
        (Operation::CreatePr, perms.capabilities.create_pr),
        (Operation::ManagePods, perms.capabilities.manage_pods),
    ];

    for op in &perms.obligations.approvals {
        let original_level = op_levels
            .iter()
            .find(|(o, _)| o == op)
            .map(|(_, l)| *l)
            .unwrap_or(CapabilityLevel::Never);

        if original_level > CapabilityLevel::Never {
            let mut caused_by = Vec::new();
            if perms.obligations.requires(*op) {
                caused_by.push(*op);
            }
            if trifecta_obligations.requires(*op) && !caused_by.contains(op) {
                caused_by.push(*op);
            }
            obligations_set.extend(caused_by.iter());
            entries.push(ModalJustificationEntry {
                operation: *op,
                original_level,
                caused_by_obligations: caused_by,
                trifecta_context: trifecta,
            });
        }
    }

    let justification = ModalJustification {
        capabilities_stripped: entries.len(),
        obligations_involved: obligations_set.len(),
        entries,
    };
    (necessary, justification)
}

// ═══════════════════════════════════════════════════════════════════════════
// BRIDGE 4: Galois → Weakening Cost
// ═══════════════════════════════════════════════════════════════════════════

/// Translation report annotated with weakening costs per hop.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CostAnnotatedTranslation {
    /// The original translation report
    pub translation: TranslationReport,
    /// Final translated permissions
    pub translated_permissions: PermissionLattice,
    /// Per-hop cost analysis
    pub hop_costs: Vec<HopCost>,
    /// Total cost of all narrowings
    pub total_narrowing_cost: WeakeningCost,
}

/// Cost analysis for a single hop in a bridge chain.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HopCost {
    /// Index into TranslationReport::steps
    pub step_index: usize,
    /// Source domain
    pub from_domain: String,
    /// Target domain
    pub to_domain: String,
    /// Whether this hop narrowed permissions
    pub was_narrowed: bool,
    /// Weakening gap for this hop (empty if not narrowed)
    pub gap: WeakeningGap,
}

/// Translate permissions through a bridge chain with cost annotation.
pub fn translate_with_cost(
    chain: &BridgeChain,
    perms: &PermissionLattice,
    cost_config: &WeakeningCostConfig,
) -> CostAnnotatedTranslation {
    let (translated, report) = chain.translate_forward_audited(perms);
    let bridges = chain.bridges();
    let mut current = perms.clone();
    let mut hop_costs = Vec::with_capacity(bridges.len());
    let mut total_cost = WeakeningCost::zero();

    for (i, bridge) in bridges.iter().enumerate() {
        let output = bridge.to_target(&current);
        // Narrowing: output ≤ current AND NOT (current ≤ output), i.e. output < current
        let narrowed = output.leq(&current) && !current.leq(&output);

        let gap = if narrowed {
            cost_config.compute_gap(&output, &current)
        } else {
            WeakeningGap::empty()
        };
        total_cost = total_cost.combine(&gap.total_cost);

        hop_costs.push(HopCost {
            step_index: i,
            from_domain: bridge.source.clone(),
            to_domain: bridge.target.clone(),
            was_narrowed: narrowed,
            gap,
        });
        current = output;
    }

    CostAnnotatedTranslation {
        translation: report,
        translated_permissions: translated,
        hop_costs,
        total_narrowing_cost: total_cost,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// COMPOSED PIPELINE
// ═══════════════════════════════════════════════════════════════════════════

/// Run the full pipeline: Galois → Algebraic gap → Graded risk → Modal justification.
pub fn full_pipeline(
    perms: &PermissionLattice,
    floor: &PermissionLattice,
    target: &PermissionLattice,
    chain: Option<&BridgeChain>,
    cost_config: &WeakeningCostConfig,
) -> PipelineTrace {
    let (effective, translation_cost) = if let Some(c) = chain {
        let cost = translate_with_cost(c, perms, cost_config);
        let eff = cost.translated_permissions.clone();
        (eff, Some(cost))
    } else {
        (perms.clone(), None)
    };

    let alg_gap = algebraic_gap(floor, &effective, cost_config);
    let graded = crate::graded::evaluate_with_risk(&effective, |p| p.clone());
    let risk_eval = evaluate_and_escalate(&graded, &effective, target, "pipeline evaluation");
    let (_, modal_just) = justify_necessity(&effective);

    PipelineTrace {
        algebraic_gap: Some(alg_gap),
        risk_evaluation: Some(risk_eval),
        modal_justification: Some(modal_just),
        translation_cost,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BRIDGE 5: WorkIntent → CodeRegion (Impact Prediction)
// ═══════════════════════════════════════════════════════════════════════════

/// Result of mapping a work intent to a code region via a Galois connection.
///
/// This bridge sits at the **entry** of the pipeline: before any permission
/// analysis, we predict which files the agent will touch. The Galois connection
/// ensures that `alpha(intent) ≤ region ⟺ intent ≤ gamma(region)`.
#[derive(Debug, Clone)]
pub struct IntentRegionMapping {
    /// The work intent (abstracted from a work item).
    pub intent: crate::intent::WorkIntent,
    /// The predicted code region: `alpha(intent)`.
    pub predicted_region: crate::region::CodeRegion,
    /// Round-trip closure: `gamma(alpha(intent))`.
    pub closure_intent: crate::intent::WorkIntent,
    /// Whether the round-trip is faithful (no information loss).
    pub faithful: bool,
}

/// Map a work intent to a code region via a Galois connection (Bridge 5).
///
/// Returns the mapping including round-trip analysis for fidelity checking.
pub fn map_intent_to_region(
    connection: &crate::galois::GaloisConnection<
        crate::intent::WorkIntent,
        crate::region::CodeRegion,
    >,
    intent: &crate::intent::WorkIntent,
) -> IntentRegionMapping {
    let predicted_region = connection.abstract_to(intent);
    let closure_intent = connection.concretize_from(&predicted_region);
    let faithful = intent == &closure_intent;
    IntentRegionMapping {
        intent: intent.clone(),
        predicted_region,
        closure_intent,
        faithful,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graded::Graded;

    // ── Bridge 1: algebraic_gap ──

    #[test]
    fn test_algebraic_gap_identity() {
        let perms = PermissionLattice::default();
        let config = WeakeningCostConfig::default();
        let result = algebraic_gap(&perms, &perms, &config);
        assert!(result.priced_gap.is_empty());
        assert!(result.consistent);
    }

    #[test]
    fn test_algebraic_gap_detects_weakening() {
        let floor = PermissionLattice::read_only();
        let mut actual = floor.clone();
        actual.capabilities.write_files = CapabilityLevel::LowRisk;
        let config = WeakeningCostConfig::default();
        let result = algebraic_gap(&floor, &actual, &config);
        assert!(!result.priced_gap.is_empty());
        assert!(result.consistent);
        assert_ne!(result.algebraic_delta.write_files, CapabilityLevel::Always);
    }

    #[test]
    fn test_algebraic_gap_matches_manual() {
        let floor = PermissionLattice::restrictive();
        let actual = PermissionLattice::codegen();
        let config = WeakeningCostConfig::default();
        let result = algebraic_gap(&floor, &actual, &config);
        assert!(result.consistent, "Algebraic and manual should agree");
    }

    #[test]
    fn test_algebraic_gap_heyting_semantics() {
        let floor = PermissionLattice::restrictive();
        let mut actual = floor.clone();
        actual.capabilities.git_push = CapabilityLevel::Always;
        let config = WeakeningCostConfig::default();
        let result = algebraic_gap(&floor, &actual, &config);
        // actual.git_push=Always > floor.git_push=Never → delta ≠ Always
        assert_ne!(result.algebraic_delta.git_push, CapabilityLevel::Always);
    }

    // ── Bridge 2: evaluate_and_escalate ──

    #[test]
    fn test_no_escalation_for_safe_risk() {
        let graded = Graded::new(TrifectaRisk::None, 42);
        let perms = PermissionLattice::read_only();
        let eval = evaluate_and_escalate(&graded, &perms, &perms, "test");
        assert!(!eval.requires_intervention);
        assert!(eval.trigger.is_none());
    }

    #[test]
    fn test_escalation_for_complete_risk() {
        let graded = Graded::new(TrifectaRisk::Complete, 42);
        let current = PermissionLattice::restrictive();
        let target = PermissionLattice::permissive();
        let eval = evaluate_and_escalate(&graded, &current, &target, "full access");
        assert!(eval.requires_intervention);
        assert!(eval.trigger.is_some());
        assert_eq!(eval.trigger.unwrap().risk, TrifectaRisk::Complete);
    }

    #[test]
    fn test_require_or_escalate_ok() {
        let graded = Graded::new(TrifectaRisk::Low, 42);
        let perms = PermissionLattice::read_only();
        let result = require_or_escalate(graded, &perms, &perms, "test", 3600);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_require_or_escalate_err() {
        let graded = Graded::new(TrifectaRisk::Complete, 42);
        let perms = PermissionLattice::permissive();
        let result = require_or_escalate(graded, &perms, &perms, "dangerous", 3600);
        assert!(result.is_err());
        let trigger = result.unwrap_err();
        assert_eq!(trigger.risk, TrifectaRisk::Complete);
        assert_eq!(trigger.suggested_ttl_seconds, 3600);
    }

    #[test]
    fn test_trigger_into_request() {
        let trigger = EscalationTrigger {
            risk: TrifectaRisk::Complete,
            current_permissions: PermissionLattice::restrictive(),
            requested_permissions: PermissionLattice::permissive(),
            reason: "need write access".into(),
            suggested_ttl_seconds: 7200,
        };
        let chain = SpiffeTraceChain::new_root(
            "spiffe://test/agent/001",
            PermissionLattice::restrictive(),
            12345,
        );
        let request = trigger.into_request(chain);
        assert_eq!(request.ttl_seconds, 7200);
        assert_eq!(request.reason, "need write access");
    }

    // ── Bridge 3: justify_necessity ──

    #[test]
    fn test_justify_necessity_no_obligations() {
        let perms = PermissionLattice::read_only();
        let (necessary, justification) = justify_necessity(&perms);
        assert_eq!(necessary.capabilities, perms.necessity().capabilities);
        assert_eq!(justification.capabilities_stripped, 0);
    }

    #[test]
    fn test_justify_necessity_with_trifecta() {
        let perms = PermissionLattice::fix_issue();
        let (necessary, justification) = justify_necessity(&perms);
        assert_eq!(necessary.capabilities, perms.necessity().capabilities);
        for entry in &justification.entries {
            assert!(entry.original_level > CapabilityLevel::Never);
        }
    }

    #[test]
    fn test_justify_necessity_explains_git_push() {
        let perms = PermissionLattice::fix_issue();
        let (_, justification) = justify_necessity(&perms);
        if perms.obligations.requires(Operation::GitPush)
            && perms.capabilities.git_push > CapabilityLevel::Never
        {
            let entry = justification
                .entries
                .iter()
                .find(|e| e.operation == Operation::GitPush);
            assert!(entry.is_some(), "GitPush should be justified");
            assert_eq!(entry.unwrap().original_level, perms.capabilities.git_push);
        }
    }

    // ── Bridge 4: translate_with_cost ──

    #[test]
    fn test_translate_with_cost_identity() {
        use crate::galois::TrustDomainBridge;
        let mut chain = BridgeChain::new();
        chain.add(TrustDomainBridge::new(
            "spiffe://a",
            "spiffe://b",
            |p: &PermissionLattice| p.clone(),
            |p: &PermissionLattice| p.clone(),
        ));
        let perms = PermissionLattice::restrictive();
        let config = WeakeningCostConfig::default();
        let result = translate_with_cost(&chain, &perms, &config);
        assert_eq!(result.hop_costs.len(), 1);
        assert!(!result.hop_costs[0].was_narrowed);
        assert!(result.total_narrowing_cost.is_zero());
    }

    // ── Full pipeline ──

    #[test]
    fn test_full_pipeline_without_translation() {
        let perms = PermissionLattice::fix_issue();
        let floor = PermissionLattice::restrictive();
        let target = PermissionLattice::permissive();
        let config = WeakeningCostConfig::default();
        let trace = full_pipeline(&perms, &floor, &target, None, &config);
        assert!(trace.algebraic_gap.is_some());
        assert!(trace.risk_evaluation.is_some());
        assert!(trace.modal_justification.is_some());
        assert!(trace.translation_cost.is_none());
    }

    #[test]
    fn test_full_pipeline_produces_gap_and_risk() {
        let perms = PermissionLattice::codegen();
        let floor = PermissionLattice::restrictive();
        let target = PermissionLattice::permissive();
        let config = WeakeningCostConfig::default();
        let trace = full_pipeline(&perms, &floor, &target, None, &config);
        let gap = trace.algebraic_gap.unwrap();
        assert!(!gap.priced_gap.is_empty());
        assert!(gap.consistent);
        assert!(trace.risk_evaluation.unwrap().risk >= TrifectaRisk::None);
    }
}
