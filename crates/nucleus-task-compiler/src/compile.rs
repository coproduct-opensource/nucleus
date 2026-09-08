//! `compile`: proposals → lowered authority → met with the ceiling → grant.

use std::collections::BTreeSet;

use chrono::Utc;
use portcullis::task_grant::{ClippedEffect, CompilerProvenance, GrantLimits, summarise_risk};
use portcullis::{
    BudgetLattice, CapabilityLevel, EffectCatalog, EffectCatalogError, EffectId, PermissionLattice,
    TaskGrant, TimeLattice, WeakeningCostConfig,
};
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::proposer::{EffectProposer, Proposal, ProposerError};
use crate::repo_context::RepoContext;

/// `<crate>/<version>`, recorded in every grant's provenance.
pub const COMPILER_NAME: &str = concat!("nucleus-task-compiler/", env!("CARGO_PKG_VERSION"));

/// Bounds the caller may tighten. Anything not given comes from the ceiling.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LimitOverrides {
    /// Spend ceiling in USD.
    pub max_cost_usd: Option<Decimal>,
    /// Lifetime in hours.
    pub duration_hours: Option<u32>,
}

/// Everything `compile` needs.
pub struct CompileInput<'a> {
    /// The goal as stated.
    pub goal: &'a str,
    /// The repository.
    pub ctx: &'a RepoContext,
    /// The effect vocabulary.
    pub catalog: &'a EffectCatalog,
    /// Name of the ceiling profile (recorded).
    pub ceiling_profile: &'a str,
    /// The ceiling itself; the grant is never wider.
    pub ceiling: &'a PermissionLattice,
    /// Proposers, consulted in order; their proposals are unioned.
    pub proposers: &'a [&'a dyn EffectProposer],
    /// Explicit effects to add to the proposals (e.g. from `--effects`).
    pub explicit: &'a BTreeSet<EffectId>,
    /// Limit overrides.
    pub limits: LimitOverrides,
    /// Cost model for the policy trace.
    pub cost_config: &'a WeakeningCostConfig,
}

/// Compilation failures. None of them falls back to a wider grant.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    /// No rule and no proposer recognised the goal.
    #[error(
        "nothing in the goal was recognised: '{goal}'. Name the effects with --effects <id,...> or pick a profile with --profile."
    )]
    NothingRecognised {
        /// The goal.
        goal: String,
    },
    /// Every proposed effect was clipped by the ceiling.
    #[error("every proposed effect is outside the ceiling profile '{ceiling}': {clipped}")]
    NothingWithinCeiling {
        /// The ceiling.
        ceiling: String,
        /// What was clipped, comma-separated.
        clipped: String,
    },
    /// The catalog rejected something.
    #[error(transparent)]
    Catalog(#[from] EffectCatalogError),
    /// A proposer failed.
    #[error(transparent)]
    Proposer(#[from] ProposerError),
    /// The compiled lattice was not delegable from the ceiling. This is a
    /// bug guard: `meet` makes it impossible, and the check is kept so a
    /// future change cannot make it possible silently.
    #[error("compiled grant is not within its ceiling: {0}")]
    NotWithinCeiling(String),
}

/// Compile a goal into a [`TaskGrant`].
pub fn compile(input: CompileInput<'_>) -> Result<TaskGrant, CompileError> {
    // 1. Propose. Union across proposers; explicit effects are a proposal too.
    let mut proposed: BTreeSet<EffectId> = input.explicit.clone();
    let mut proposers = Vec::new();
    let mut rules_fired = Vec::new();
    if !input.explicit.is_empty() {
        proposers.push("explicit".to_string());
    }
    for p in input.proposers {
        let Proposal {
            proposer,
            effects,
            rules_fired: fired,
        } = p.propose(input.goal, input.ctx, input.catalog)?;
        proposers.push(proposer);
        rules_fired.extend(fired);
        proposed.extend(effects);
    }
    if proposed.is_empty() {
        return Err(CompileError::NothingRecognised {
            goal: input.goal.to_string(),
        });
    }

    // 2. Lower: exactly the union of the proposed effects, nothing else.
    let lowered = input.catalog.lower(&proposed)?;

    // 3. Build the requested lattice around the lowered capabilities. Paths
    //    and commands come from the ceiling (the compiler does not know the
    //    repository's sensitive paths better than the profile author does);
    //    budget and time from the overrides, else the ceiling.
    let max_cost_usd = input
        .limits
        .max_cost_usd
        .unwrap_or(input.ceiling.budget.max_cost_usd);
    let budget = BudgetLattice {
        max_cost_usd,
        consumed_usd: Decimal::ZERO,
        max_input_tokens: input.ceiling.budget.max_input_tokens,
        max_output_tokens: input.ceiling.budget.max_output_tokens,
    };
    let time = match input.limits.duration_hours {
        Some(h) => TimeLattice::hours(i64::from(h)),
        None => input.ceiling.time.clone(),
    };
    let requested = PermissionLattice::builder()
        .description(format!("task: {}", input.goal))
        .capabilities(lowered.capabilities.clone())
        .paths(input.ceiling.paths.clone())
        .commands(input.ceiling.commands.clone())
        .budget(budget)
        .time(time)
        .uninhabitable_constraint(true)
        .created_by(COMPILER_NAME)
        .build();

    // 4. Clamp. `meet` is the whole safety argument: the result is ≤ both.
    let mut lattice = input.ceiling.meet(&requested).normalize();
    lattice.description = format!("task: {}", input.goal);

    // 5. Attribute: an effect whose lowering the ceiling clipped is reported,
    //    never silently granted (it isn't) or silently dropped.
    let mut can = BTreeSet::new();
    let mut cannot = Vec::new();
    for id in &proposed {
        let spec = input
            .catalog
            .get(id)
            .ok_or_else(|| EffectCatalogError::Unknown(id.to_string()))?;
        let clipped: Vec<String> = spec
            .operations
            .iter()
            .filter(|op| lattice.capabilities.level_for(**op) < CapabilityLevel::LowRisk)
            .map(|op| op.to_string())
            .collect();
        if clipped.is_empty() {
            can.insert(id.clone());
        } else {
            cannot.push(ClippedEffect {
                id: id.clone(),
                reason: format!(
                    "outside ceiling {}: {} is never",
                    input.ceiling_profile,
                    clipped.join(", ")
                ),
            });
        }
    }
    if can.is_empty() {
        return Err(CompileError::NothingWithinCeiling {
            ceiling: input.ceiling_profile.to_string(),
            clipped: cannot
                .iter()
                .map(|c| c.id.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        });
    }

    // Hosts: only those of effects that survived the ceiling.
    let granted = input.catalog.lower(&can)?;

    // 6. The guard the whole design rests on.
    input
        .ceiling
        .delegate_to(&lattice, "task grant")
        .map_err(|e| CompileError::NotWithinCeiling(e.to_string()))?;

    let gap = input
        .cost_config
        .compute_gap(&PermissionLattice::restrictive(), &lattice);
    let risk = summarise_risk(&lattice, gap);

    let created_at = Utc::now();
    let not_after = lattice.time.valid_until;
    let duration_secs = (not_after - created_at).num_seconds().max(0) as u64;
    let mut blocked_paths: Vec<String> = lattice.paths.blocked.iter().cloned().collect();
    blocked_paths.sort();

    Ok(TaskGrant {
        version: TaskGrant::VERSION,
        id: Uuid::new_v4(),
        goal: input.goal.to_string(),
        goal_digest: TaskGrant::digest_goal(input.goal),
        ceiling_profile: input.ceiling_profile.to_string(),
        can,
        cannot,
        limits: GrantLimits {
            max_cost_usd: lattice.budget.max_cost_usd,
            duration_secs,
            hosts: granted.hosts.into_iter().collect(),
            blocked_paths,
            commands: granted.commands.into_iter().collect(),
        },
        risk,
        lattice,
        provenance: CompilerProvenance {
            compiler: COMPILER_NAME.to_string(),
            proposers,
            rules_fired,
            repo_context_digest: input.ctx.digest.clone(),
        },
        created_at,
        not_after,
    })
}
