//! Lattice dropout for the permission product lattice.
//!
//! For the 6-sublattice product `L = Caps × Obligations × Paths × Budget × Commands × Time`,
//! the canonical projection `π_S: L → ∏_{i∈S} Aᵢ` paired with top-filling injection `ι_S`
//! forms a **Galois connection**:
//!
//! ```text
//! ι_S(π_S(x)) ≥ x   (over-approximation, always sound)
//! ```
//!
//! Three dropout levels:
//!
//! | Level | What's dropped | Fill value | Sound? |
//! |-------|---------------|------------|--------|
//! | Sub-lattice | Paths, Commands, Time, Budget | Most permissive (⊤) | Yes: product projection |
//! | Capability | Individual CapabilityLattice fields | `Always` (⊤) | Yes: product of linear orders |
//! | Pipeline stage | Algebraic Gap, Graded Risk, Modal | Skipped | Yes: explanation-only |
//!
//! ** UninhabitableState caveat**: Dropping capability fields fills them with `Always`, which may
//! trigger uninhabitable_state obligations (conservative = sound).

use crate::capability::{CapabilityLevel, Operation};
use crate::pipeline::PipelineTrace;
use crate::weakening::WeakeningCostConfig;
use crate::{BudgetLattice, CommandLattice, PathLattice, PermissionLattice, TimeLattice};

use chrono::Duration;
use rust_decimal::Decimal;

// ═══════════════════════════════════════════════════════════════════════════
// BITMASK TYPES
// ═══════════════════════════════════════════════════════════════════════════

/// Bitmask for the 6 sub-lattices of PermissionLattice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubLatticeMask(u8);

impl SubLatticeMask {
    /// Capabilities sub-lattice.
    pub const CAPABILITIES: u8 = 0b00_0001;
    /// Obligations sub-lattice.
    pub const OBLIGATIONS: u8 = 0b00_0010;
    /// Paths sub-lattice.
    pub const PATHS: u8 = 0b00_0100;
    /// Budget sub-lattice.
    pub const BUDGET: u8 = 0b00_1000;
    /// Commands sub-lattice.
    pub const COMMANDS: u8 = 0b01_0000;
    /// Time sub-lattice.
    pub const TIME: u8 = 0b10_0000;
    /// All sub-lattices active (no dropout).
    pub const ALL: u8 = 0b11_1111;

    /// Create a mask with all sub-lattices active.
    pub fn all() -> Self {
        Self(Self::ALL)
    }

    /// Create a mask with only the specified sub-lattices active.
    pub fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL)
    }

    /// Check if a sub-lattice is active (not dropped).
    pub fn is_active(&self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// Core-only: capabilities + obligations (fastest evaluation).
    pub fn core_only() -> Self {
        Self(Self::CAPABILITIES | Self::OBLIGATIONS)
    }
}

/// Bitmask for the 12 fields of CapabilityLattice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityMask(u16);

impl CapabilityMask {
    /// All 13 capability fields active.
    pub const ALL: u16 = 0x1FFF;

    // Individual field bits
    const READ_FILES: u16 = 1 << 0;
    const WRITE_FILES: u16 = 1 << 1;
    const EDIT_FILES: u16 = 1 << 2;
    const RUN_BASH: u16 = 1 << 3;
    const GLOB_SEARCH: u16 = 1 << 4;
    const GREP_SEARCH: u16 = 1 << 5;
    const WEB_SEARCH: u16 = 1 << 6;
    const WEB_FETCH: u16 = 1 << 7;
    const GIT_COMMIT: u16 = 1 << 8;
    const GIT_PUSH: u16 = 1 << 9;
    const CREATE_PR: u16 = 1 << 10;
    const MANAGE_PODS: u16 = 1 << 11;
    const SPAWN_AGENT: u16 = 1 << 12;

    //  UninhabitableState groups
    const PRIVATE_ACCESS: u16 = Self::READ_FILES | Self::GLOB_SEARCH | Self::GREP_SEARCH;
    const UNTRUSTED: u16 = Self::WEB_SEARCH | Self::WEB_FETCH;
    const EXFILTRATION: u16 = Self::GIT_PUSH | Self::CREATE_PR | Self::RUN_BASH | Self::SPAWN_AGENT;

    /// Create a mask with all fields active.
    pub fn all() -> Self {
        Self(Self::ALL)
    }

    /// Create from raw bits.
    pub fn from_bits(bits: u16) -> Self {
        Self(bits & Self::ALL)
    }

    /// Check if a field is active.
    pub fn is_active(&self, bit: u16) -> bool {
        self.0 & bit != 0
    }

    /// Create a mask for only the fields relevant to specific operations.
    /// Automatically includes uninhabitable_state peers when any uninhabitable_state member is requested.
    pub fn for_operations(ops: &[Operation]) -> Self {
        let mut bits: u16 = 0;
        let mut needs_uninhabitable_expansion = false;

        for op in ops {
            let bit = Self::operation_to_bit(*op);
            bits |= bit;
            if bit & (Self::PRIVATE_ACCESS | Self::UNTRUSTED | Self::EXFILTRATION) != 0 {
                needs_uninhabitable_expansion = true;
            }
        }

        // If any uninhabitable_state-relevant cap is requested, include all uninhabitable_state caps
        // so the constraint can be properly evaluated
        if needs_uninhabitable_expansion {
            bits |= Self::PRIVATE_ACCESS | Self::UNTRUSTED | Self::EXFILTRATION;
        }

        Self(bits & Self::ALL)
    }

    fn operation_to_bit(op: Operation) -> u16 {
        match op {
            Operation::ReadFiles => Self::READ_FILES,
            Operation::WriteFiles => Self::WRITE_FILES,
            Operation::EditFiles => Self::EDIT_FILES,
            Operation::RunBash => Self::RUN_BASH,
            Operation::GlobSearch => Self::GLOB_SEARCH,
            Operation::GrepSearch => Self::GREP_SEARCH,
            Operation::WebSearch => Self::WEB_SEARCH,
            Operation::WebFetch => Self::WEB_FETCH,
            Operation::GitCommit => Self::GIT_COMMIT,
            Operation::GitPush => Self::GIT_PUSH,
            Operation::CreatePr => Self::CREATE_PR,
            Operation::ManagePods => Self::MANAGE_PODS,
            Operation::SpawnAgent => Self::SPAWN_AGENT,
        }
    }
}

/// Bitmask for pipeline stages (4 stages of `full_pipeline`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineStageMask(u8);

impl PipelineStageMask {
    /// Bridge 4: Galois translation.
    pub const GALOIS: u8 = 0b0001;
    /// Bridge 1: Algebraic gap (Heyting → Weakening).
    pub const ALGEBRAIC_GAP: u8 = 0b0010;
    /// Bridge 2: Graded risk evaluation.
    pub const GRADED_RISK: u8 = 0b0100;
    /// Bridge 3: Modal necessity justification.
    pub const MODAL_JUSTIFICATION: u8 = 0b1000;
    /// All stages active.
    pub const ALL: u8 = 0b1111;

    /// Create with all stages active.
    pub fn all() -> Self {
        Self(Self::ALL)
    }

    /// Create from bits.
    pub fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL)
    }

    /// Check if a stage is active.
    pub fn is_active(&self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// Core stages only: algebraic gap + graded risk.
    pub fn core_only() -> Self {
        Self(Self::ALGEBRAIC_GAP | Self::GRADED_RISK)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DROPOUT CONFIG
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for lattice dropout across all three levels.
#[derive(Debug, Clone)]
pub struct DropoutConfig {
    /// Which sub-lattices to evaluate (dropped = fill with ⊤).
    pub sub_lattices: SubLatticeMask,
    /// Which capability fields to evaluate (dropped = fill with Always).
    pub capabilities: CapabilityMask,
    /// Which pipeline stages to run (dropped = skip computation).
    pub pipeline_stages: PipelineStageMask,
}

impl DropoutConfig {
    /// Full evaluation — no dropout.
    pub fn full() -> Self {
        Self {
            sub_lattices: SubLatticeMask::all(),
            capabilities: CapabilityMask::all(),
            pipeline_stages: PipelineStageMask::all(),
        }
    }

    /// Fast delegation check: only caps + obligations, skip Galois + Modal.
    pub fn fast_delegation() -> Self {
        Self {
            sub_lattices: SubLatticeMask::core_only(),
            capabilities: CapabilityMask::all(),
            pipeline_stages: PipelineStageMask::core_only(),
        }
    }

    /// Check only the capability fields relevant to the given operations.
    pub fn for_operations(ops: &[Operation]) -> Self {
        Self {
            sub_lattices: SubLatticeMask::all(),
            capabilities: CapabilityMask::for_operations(ops),
            pipeline_stages: PipelineStageMask::all(),
        }
    }

    /// Returns true if no dropout is applied.
    pub fn is_full(&self) -> bool {
        self.sub_lattices == SubLatticeMask::all()
            && self.capabilities == CapabilityMask::all()
            && self.pipeline_stages == PipelineStageMask::all()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PROJECTION
// ═══════════════════════════════════════════════════════════════════════════

/// Project a permission lattice by filling dropped dimensions with ⊤.
///
/// **Invariant**: `project(x, config) ≥ x` (inflationary / over-approximation).
///
/// This is sound because replacing a dimension with its top element can only
/// make the permission *more* permissive, never less. Any check that passes
/// on the projected value also passes on the original.
pub fn project(perms: &PermissionLattice, config: &DropoutConfig) -> PermissionLattice {
    let capabilities = project_capabilities(&perms.capabilities, &config.capabilities);

    // Obligations ordering: more obligations = smaller (more constrained).
    // For inflationary projection (project(x) ≥ x), we need projected obligations
    // to be ≤ (fewer than) the original. So we either keep original or drop to empty.
    // We do NOT re-enforce uninhabitable_state on projected capabilities, because filling
    // dropped caps with Always would add spurious obligations, making the result smaller.
    let obligations = if config.sub_lattices.is_active(SubLatticeMask::OBLIGATIONS) {
        perms.obligations.clone()
    } else {
        // Dropped → empty obligations (most permissive = ⊤ for obligations)
        crate::capability::Obligations::default()
    };

    let paths = if config.sub_lattices.is_active(SubLatticeMask::PATHS) {
        perms.paths.clone()
    } else {
        PathLattice::default() // empty allowed + empty blocked = all allowed
    };

    let budget = if config.sub_lattices.is_active(SubLatticeMask::BUDGET) {
        perms.budget.clone()
    } else {
        BudgetLattice {
            max_cost_usd: Decimal::from(1_000_000),
            consumed_usd: Decimal::ZERO,
            max_input_tokens: u64::MAX,
            max_output_tokens: u64::MAX,
        }
    };

    let commands = if config.sub_lattices.is_active(SubLatticeMask::COMMANDS) {
        perms.commands.clone()
    } else {
        CommandLattice::empty()
    };

    let time = if config.sub_lattices.is_active(SubLatticeMask::TIME) {
        perms.time.clone()
    } else {
        // ⊤ for time: widest possible window.
        // valid_from ≤ any original valid_from, valid_until ≥ any original valid_until
        use chrono::Utc;
        TimeLattice::between(
            Utc::now() - Duration::days(365 * 10),
            Utc::now() + Duration::days(365 * 10),
        )
    };

    PermissionLattice {
        capabilities,
        obligations,
        paths,
        budget,
        commands,
        time,
        // Metadata — preserve from original
        uninhabitable_constraint: perms.uninhabitable_constraint,
        ..perms.clone()
    }
}

/// Project capability fields: dropped fields become `Always` (⊤).
fn project_capabilities(
    caps: &crate::capability::CapabilityLattice,
    mask: &CapabilityMask,
) -> crate::capability::CapabilityLattice {
    crate::capability::CapabilityLattice {
        read_files: if mask.is_active(CapabilityMask::READ_FILES) {
            caps.read_files
        } else {
            CapabilityLevel::Always
        },
        write_files: if mask.is_active(CapabilityMask::WRITE_FILES) {
            caps.write_files
        } else {
            CapabilityLevel::Always
        },
        edit_files: if mask.is_active(CapabilityMask::EDIT_FILES) {
            caps.edit_files
        } else {
            CapabilityLevel::Always
        },
        run_bash: if mask.is_active(CapabilityMask::RUN_BASH) {
            caps.run_bash
        } else {
            CapabilityLevel::Always
        },
        glob_search: if mask.is_active(CapabilityMask::GLOB_SEARCH) {
            caps.glob_search
        } else {
            CapabilityLevel::Always
        },
        grep_search: if mask.is_active(CapabilityMask::GREP_SEARCH) {
            caps.grep_search
        } else {
            CapabilityLevel::Always
        },
        web_search: if mask.is_active(CapabilityMask::WEB_SEARCH) {
            caps.web_search
        } else {
            CapabilityLevel::Always
        },
        web_fetch: if mask.is_active(CapabilityMask::WEB_FETCH) {
            caps.web_fetch
        } else {
            CapabilityLevel::Always
        },
        git_commit: if mask.is_active(CapabilityMask::GIT_COMMIT) {
            caps.git_commit
        } else {
            CapabilityLevel::Always
        },
        git_push: if mask.is_active(CapabilityMask::GIT_PUSH) {
            caps.git_push
        } else {
            CapabilityLevel::Always
        },
        create_pr: if mask.is_active(CapabilityMask::CREATE_PR) {
            caps.create_pr
        } else {
            CapabilityLevel::Always
        },
        manage_pods: if mask.is_active(CapabilityMask::MANAGE_PODS) {
            caps.manage_pods
        } else {
            CapabilityLevel::Always
        },
        spawn_agent: if mask.is_active(CapabilityMask::SPAWN_AGENT) {
            caps.spawn_agent
        } else {
            CapabilityLevel::Always
        },
        #[cfg(not(kani))]
        extensions: std::collections::BTreeMap::new(),
    }
}

/// Projected meet: compute the full meet, then project the result.
///
/// **Invariant**: `projected_meet(a, b, config) ≥ a.meet(b)` (over-approximation).
///
/// We project the *result* rather than the *inputs* because projecting inputs
/// before meet can trigger spurious uninhabitable_state obligations (more obligations =
/// smaller in lattice order, violating the over-approximation guarantee).
pub fn projected_meet(
    a: &PermissionLattice,
    b: &PermissionLattice,
    config: &DropoutConfig,
) -> PermissionLattice {
    let full = a.meet(b);
    project(&full, config)
}

// ═══════════════════════════════════════════════════════════════════════════
// PIPELINE WITH DROPOUT
// ═══════════════════════════════════════════════════════════════════════════

/// Run the pipeline with stage dropout.
///
/// Stages masked out produce `None` in the trace. The Galois translation
/// stage is only skipped if both the mask says so AND no chain is provided.
pub fn dropout_pipeline(
    perms: &PermissionLattice,
    floor: &PermissionLattice,
    target: &PermissionLattice,
    chain: Option<&crate::galois::BridgeChain>,
    cost_config: &WeakeningCostConfig,
    config: &DropoutConfig,
) -> (PipelineTrace, DropoutReport) {
    let projected_perms = project(perms, config);
    let projected_floor = project(floor, config);

    let mut stages_skipped = Vec::new();
    let mut trace = PipelineTrace {
        algebraic_gap: None,
        risk_evaluation: None,
        modal_justification: None,
        translation_cost: None,
    };

    // Stage 4 (Galois) — run first if active and chain present
    if config.pipeline_stages.is_active(PipelineStageMask::GALOIS) {
        if let Some(c) = chain {
            let cost = crate::pipeline::translate_with_cost(c, &projected_perms, cost_config);
            trace.translation_cost = Some(cost);
        }
    } else {
        stages_skipped.push(PipelineStage::Galois);
    }

    // Stage 1 (Algebraic gap)
    if config
        .pipeline_stages
        .is_active(PipelineStageMask::ALGEBRAIC_GAP)
    {
        let gap = crate::pipeline::algebraic_gap(&projected_floor, &projected_perms, cost_config);
        trace.algebraic_gap = Some(gap);
    } else {
        stages_skipped.push(PipelineStage::AlgebraicGap);
    }

    // Stage 2 (Graded risk)
    if config
        .pipeline_stages
        .is_active(PipelineStageMask::GRADED_RISK)
    {
        let graded = crate::graded::evaluate_with_risk(&projected_perms, |p| p.clone());
        let eval = crate::pipeline::evaluate_and_escalate(
            &graded,
            &projected_perms,
            target,
            "dropout pipeline",
        );
        trace.risk_evaluation = Some(eval);
    } else {
        stages_skipped.push(PipelineStage::GradedRisk);
    }

    // Stage 3 (Modal justification)
    if config
        .pipeline_stages
        .is_active(PipelineStageMask::MODAL_JUSTIFICATION)
    {
        let (_, justification) = crate::pipeline::justify_necessity(&projected_perms);
        trace.modal_justification = Some(justification);
    } else {
        stages_skipped.push(PipelineStage::ModalJustification);
    }

    // Build report
    let total_stages = 4u32;
    let active_stages = total_stages - stages_skipped.len() as u32;

    // Identify load-bearing vs trivial dimensions
    let (load_bearing, trivial) = classify_dimensions(&projected_perms, &projected_floor);

    let report = DropoutReport {
        config: config.clone(),
        stages_skipped,
        load_bearing_dimensions: load_bearing,
        trivial_dimensions: trivial,
        evaluation_fraction: active_stages as f64 / total_stages as f64,
    };

    (trace, report)
}

/// Classify dimensions into load-bearing (contribute to gap) and trivial (⊤ on both sides).
fn classify_dimensions(
    perms: &PermissionLattice,
    floor: &PermissionLattice,
) -> (Vec<String>, Vec<String>) {
    let mut load_bearing = Vec::new();
    let mut trivial = Vec::new();

    // Check each capability field
    let fields: &[(&str, CapabilityLevel, CapabilityLevel)] = &[
        (
            "read_files",
            perms.capabilities.read_files,
            floor.capabilities.read_files,
        ),
        (
            "write_files",
            perms.capabilities.write_files,
            floor.capabilities.write_files,
        ),
        (
            "edit_files",
            perms.capabilities.edit_files,
            floor.capabilities.edit_files,
        ),
        (
            "run_bash",
            perms.capabilities.run_bash,
            floor.capabilities.run_bash,
        ),
        (
            "glob_search",
            perms.capabilities.glob_search,
            floor.capabilities.glob_search,
        ),
        (
            "grep_search",
            perms.capabilities.grep_search,
            floor.capabilities.grep_search,
        ),
        (
            "web_search",
            perms.capabilities.web_search,
            floor.capabilities.web_search,
        ),
        (
            "web_fetch",
            perms.capabilities.web_fetch,
            floor.capabilities.web_fetch,
        ),
        (
            "git_commit",
            perms.capabilities.git_commit,
            floor.capabilities.git_commit,
        ),
        (
            "git_push",
            perms.capabilities.git_push,
            floor.capabilities.git_push,
        ),
        (
            "create_pr",
            perms.capabilities.create_pr,
            floor.capabilities.create_pr,
        ),
        (
            "manage_pods",
            perms.capabilities.manage_pods,
            floor.capabilities.manage_pods,
        ),
        (
            "spawn_agent",
            perms.capabilities.spawn_agent,
            floor.capabilities.spawn_agent,
        ),
    ];

    for &(name, perm_level, floor_level) in fields {
        if perm_level == CapabilityLevel::Always && floor_level == CapabilityLevel::Always {
            trivial.push(name.to_string());
        } else if perm_level != floor_level {
            load_bearing.push(name.to_string());
        }
    }

    (load_bearing, trivial)
}

// ═══════════════════════════════════════════════════════════════════════════
// REPORT
// ═══════════════════════════════════════════════════════════════════════════

/// Named pipeline stages for reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineStage {
    /// Galois translation (Bridge 4).
    Galois,
    /// Algebraic gap (Bridge 1: Heyting → Weakening).
    AlgebraicGap,
    /// Graded risk evaluation (Bridge 2).
    GradedRisk,
    /// Modal necessity justification (Bridge 3).
    ModalJustification,
}

/// Report describing what dropout was applied and its effects.
#[derive(Debug, Clone)]
pub struct DropoutReport {
    /// The dropout configuration used.
    pub config: DropoutConfig,
    /// Pipeline stages that were skipped.
    pub stages_skipped: Vec<PipelineStage>,
    /// Dimensions that contributed to the permission gap.
    pub load_bearing_dimensions: Vec<String>,
    /// Dimensions at ⊤ on both inputs (no information).
    pub trivial_dimensions: Vec<String>,
    /// Fraction of pipeline that was evaluated (1.0 = no dropout).
    pub evaluation_fraction: f64,
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::IncompatibilityConstraint;
    use proptest::prelude::*;

    // ── Soundness: projection is inflationary ──

    #[test]
    fn test_projection_is_inflationary() {
        let perms = PermissionLattice::restrictive();
        let config = DropoutConfig::fast_delegation();
        let projected = project(&perms, &config);
        assert!(perms.leq(&projected), "project(x) must be ≥ x");
    }

    #[test]
    fn test_projection_full_is_identity() {
        let perms = PermissionLattice::codegen();
        let config = DropoutConfig::full();
        let projected = project(&perms, &config);
        // Full projection should preserve capabilities exactly
        assert_eq!(projected.capabilities, perms.capabilities);
    }

    // ── Soundness: projected meet ≥ full meet ──

    #[test]
    fn test_projected_meet_geq_full_meet() {
        let a = PermissionLattice::fix_issue();
        let b = PermissionLattice::codegen();
        let config = DropoutConfig::fast_delegation();
        let full = a.meet(&b);
        let proj = projected_meet(&a, &b, &config);
        assert!(full.leq(&proj), "projected_meet must be ≥ full meet");
    }

    // ── Full config equals no dropout ──

    #[test]
    fn test_full_config_equals_no_dropout() {
        let perms = PermissionLattice::fix_issue();
        let floor = PermissionLattice::restrictive();
        let target = PermissionLattice::permissive();
        let cost_config = WeakeningCostConfig::default();

        let full_trace =
            crate::pipeline::full_pipeline(&perms, &floor, &target, None, &cost_config);
        let (dropout_trace, report) = dropout_pipeline(
            &perms,
            &floor,
            &target,
            None,
            &cost_config,
            &DropoutConfig::full(),
        );

        // Same stages should be populated
        assert!(full_trace.algebraic_gap.is_some());
        assert!(dropout_trace.algebraic_gap.is_some());
        assert!(full_trace.risk_evaluation.is_some());
        assert!(dropout_trace.risk_evaluation.is_some());
        assert!(full_trace.modal_justification.is_some());
        assert!(dropout_trace.modal_justification.is_some());
        assert_eq!(report.evaluation_fraction, 1.0);
        assert!(report.stages_skipped.is_empty());
    }

    // ── Capability dropout fills with ⊤ ──

    #[test]
    fn test_capability_dropout_fills_with_top() {
        let perms = PermissionLattice::restrictive();
        // Only keep read_files
        let config = DropoutConfig {
            sub_lattices: SubLatticeMask::all(),
            capabilities: CapabilityMask::from_bits(CapabilityMask::READ_FILES),
            pipeline_stages: PipelineStageMask::all(),
        };
        let projected = project(&perms, &config);
        assert_eq!(
            projected.capabilities.read_files,
            perms.capabilities.read_files
        );
        assert_eq!(projected.capabilities.write_files, CapabilityLevel::Always);
        assert_eq!(projected.capabilities.run_bash, CapabilityLevel::Always);
        assert_eq!(projected.capabilities.git_push, CapabilityLevel::Always);
    }

    // ──  UninhabitableState rechecked on capability dropout ──

    #[test]
    fn test_uninhabitable_rechecked_on_capability_dropout() {
        // Start with a safe permission (no uninhabitable_state)
        let perms = PermissionLattice::read_only();
        assert!(!perms.is_uninhabitable_vulnerable());

        // Dropping capabilities fills with Always — the projected capabilities
        // form an uninhabitable_state, but the projection itself does NOT add obligations
        // (that would violate the inflationary invariant).
        let config = DropoutConfig {
            sub_lattices: SubLatticeMask::all(),
            capabilities: CapabilityMask::from_bits(CapabilityMask::READ_FILES),
            pipeline_stages: PipelineStageMask::all(),
        };
        let projected = project(&perms, &config);
        // All dropped fields become Always → uninhabitable_state is detectable on capabilities
        let constraint = IncompatibilityConstraint::enforcing();
        assert!(constraint.is_uninhabitable(&projected.capabilities));
        // But obligations are preserved from original (not inflated), ensuring soundness
        // The pipeline stages will detect the uninhabitable_state risk via graded evaluation
        assert!(perms.leq(&projected), "Projection must remain inflationary");
    }

    // ── Pipeline stage dropout ──

    #[test]
    fn test_pipeline_stage_dropout_skips_stages() {
        let perms = PermissionLattice::fix_issue();
        let floor = PermissionLattice::restrictive();
        let target = PermissionLattice::permissive();
        let cost_config = WeakeningCostConfig::default();

        let config = DropoutConfig {
            sub_lattices: SubLatticeMask::all(),
            capabilities: CapabilityMask::all(),
            pipeline_stages: PipelineStageMask::from_bits(PipelineStageMask::ALGEBRAIC_GAP),
        };

        let (trace, report) =
            dropout_pipeline(&perms, &floor, &target, None, &cost_config, &config);

        assert!(trace.algebraic_gap.is_some());
        assert!(trace.risk_evaluation.is_none());
        assert!(trace.modal_justification.is_none());
        assert!(trace.translation_cost.is_none());
        assert_eq!(report.stages_skipped.len(), 3);
        assert!((report.evaluation_fraction - 0.25).abs() < f64::EPSILON);
    }

    // ── for_operations includes uninhabitable_state ──

    #[test]
    fn test_for_operations_includes_uninhabitable() {
        // Requesting just git_push should auto-include all uninhabitable_state caps
        let mask = CapabilityMask::for_operations(&[Operation::GitPush]);
        // Must include all uninhabitable_state members
        assert!(mask.is_active(CapabilityMask::READ_FILES));
        assert!(mask.is_active(CapabilityMask::GLOB_SEARCH));
        assert!(mask.is_active(CapabilityMask::GREP_SEARCH));
        assert!(mask.is_active(CapabilityMask::WEB_SEARCH));
        assert!(mask.is_active(CapabilityMask::WEB_FETCH));
        assert!(mask.is_active(CapabilityMask::GIT_PUSH));
        assert!(mask.is_active(CapabilityMask::CREATE_PR));
        assert!(mask.is_active(CapabilityMask::RUN_BASH));
    }

    #[test]
    fn test_for_operations_non_uninhabitable() {
        // Requesting git_commit (not uninhabitable_state) should only include git_commit
        let mask = CapabilityMask::for_operations(&[Operation::GitCommit]);
        assert!(mask.is_active(CapabilityMask::GIT_COMMIT));
        assert!(!mask.is_active(CapabilityMask::GIT_PUSH));
        assert!(!mask.is_active(CapabilityMask::WEB_FETCH));
    }

    // ── Dropout report ──

    #[test]
    fn test_dropout_report_load_bearing_dimensions() {
        let perms = PermissionLattice::codegen();
        let floor = PermissionLattice::restrictive();
        let target = PermissionLattice::permissive();
        let cost_config = WeakeningCostConfig::default();

        let (_, report) = dropout_pipeline(
            &perms,
            &floor,
            &target,
            None,
            &cost_config,
            &DropoutConfig::full(),
        );

        // codegen has higher caps than restrictive in several dimensions
        assert!(!report.load_bearing_dimensions.is_empty());
    }

    // ── SubLatticeMask constructors ──

    #[test]
    fn test_sub_lattice_mask_core_only() {
        let mask = SubLatticeMask::core_only();
        assert!(mask.is_active(SubLatticeMask::CAPABILITIES));
        assert!(mask.is_active(SubLatticeMask::OBLIGATIONS));
        assert!(!mask.is_active(SubLatticeMask::PATHS));
        assert!(!mask.is_active(SubLatticeMask::BUDGET));
        assert!(!mask.is_active(SubLatticeMask::COMMANDS));
        assert!(!mask.is_active(SubLatticeMask::TIME));
    }

    // ── Proptest: projection is inflationary ──

    fn arb_capability_level() -> impl Strategy<Value = CapabilityLevel> {
        prop_oneof![
            Just(CapabilityLevel::Never),
            Just(CapabilityLevel::LowRisk),
            Just(CapabilityLevel::Always),
        ]
    }

    fn arb_capability_lattice() -> impl Strategy<Value = crate::capability::CapabilityLattice> {
        (
            (
                arb_capability_level(),
                arb_capability_level(),
                arb_capability_level(),
                arb_capability_level(),
                arb_capability_level(),
                arb_capability_level(),
                arb_capability_level(),
                arb_capability_level(),
                arb_capability_level(),
                arb_capability_level(),
            ),
            (
                arb_capability_level(),
                arb_capability_level(),
                arb_capability_level(),
            ),
        )
            .prop_map(
                |((rf, wf, ef, rb, gs, grs, ws, wf2, gc, gp), (cp, mp, sa))| {
                    crate::capability::CapabilityLattice {
                        read_files: rf,
                        write_files: wf,
                        edit_files: ef,
                        run_bash: rb,
                        glob_search: gs,
                        grep_search: grs,
                        web_search: ws,
                        web_fetch: wf2,
                        git_commit: gc,
                        git_push: gp,
                        create_pr: cp,
                        manage_pods: mp,
                        spawn_agent: sa,
                        extensions: std::collections::BTreeMap::new(),
                    }
                },
            )
    }

    fn arb_sub_lattice_mask() -> impl Strategy<Value = SubLatticeMask> {
        (0u8..=SubLatticeMask::ALL).prop_map(SubLatticeMask::from_bits)
    }

    fn arb_capability_mask() -> impl Strategy<Value = CapabilityMask> {
        (0u16..=CapabilityMask::ALL).prop_map(CapabilityMask::from_bits)
    }

    proptest! {
        #[test]
        fn prop_projection_is_inflationary(
            caps in arb_capability_lattice(),
            sub_mask in arb_sub_lattice_mask(),
            cap_mask in arb_capability_mask(),
        ) {
            let perms = PermissionLattice { capabilities: caps, ..Default::default() };

            let config = DropoutConfig {
                sub_lattices: sub_mask,
                capabilities: cap_mask,
                pipeline_stages: PipelineStageMask::all(),
            };

            let projected = project(&perms, &config);
            prop_assert!(
                perms.leq(&projected),
                "Projection must be inflationary: project(x) ≥ x"
            );
        }

        #[test]
        fn prop_projected_meet_geq_full(
            caps_a in arb_capability_lattice(),
            caps_b in arb_capability_lattice(),
            cap_mask in arb_capability_mask(),
        ) {
            let a = PermissionLattice { capabilities: caps_a, ..Default::default() };
            let b = PermissionLattice { capabilities: caps_b, ..Default::default() };

            let config = DropoutConfig {
                sub_lattices: SubLatticeMask::all(),
                capabilities: cap_mask,
                pipeline_stages: PipelineStageMask::all(),
            };

            let full = a.meet(&b);
            let proj = projected_meet(&a, &b, &config);
            prop_assert!(
                full.leq(&proj),
                "Projected meet must over-approximate: projected_meet(a,b) ≥ a.meet(b)"
            );
        }
    }
}
