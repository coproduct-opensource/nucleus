//! Every denial is a structured escalation proposal (ADR 0004, milestone 4).
//!
//! A denial used to be a sentence: `egress blocked: api.github.com`. The
//! person reading it had four questions the sentence did not answer: what
//! was the agent trying to do, why exactly was it stopped, what is the
//! *minimum* authority that would have allowed it, and what new risk would
//! granting that create. [`EscalationProposal`] answers all four from the
//! grant, the ceiling and the effect catalog, and names the one command that
//! grants exactly the minimum, still within the ceiling.
//!
//! Three outcomes, and the proposal says which:
//!
//! - **grantable**: an effect in the catalog vouches for the attempt, and the
//!   ceiling admits it. `minimum` names the effect and the per-dimension
//!   weakening it costs, `risk` the delta, `scopes` how to grant it (for the
//!   rest of this run, or always by re-sealing the grant with the effect).
//! - **outside the ceiling**: the effect exists but `--ceiling` clips it.
//!   Nothing is offered; a wider ceiling is a separate, named decision.
//! - **repair, not authority**: information-flow denials, blocked secret
//!   paths, expired or exhausted grants, and layers below the grant
//!   (isolation, enterprise policy, delegation). Widening would not help,
//!   and the proposal says what would.
//!
//! No path here widens anything by itself. A proposal is data; granting is
//! `nucleus grant widen`, which recompiles under the same ceiling and asks
//! for the same single confirmation a new goal would (`C(T) = 1`).

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::effect_catalog::{
    command_matches, host_matches, raise, EffectCatalog, EffectId, EffectSpec,
};
use crate::gate_class::deny_code;
use crate::grant_usage::operation_name;
use crate::kernel::{Decision, DenyReason, Verdict};
use crate::task_grant::{exposure_legs, TaskGrant};
use crate::{
    CapabilityLevel, ExposureLabel, IncompatibilityConstraint, Operation, PermissionLattice,
    StateRisk, WeakeningCostConfig, WeakeningRequest,
};

/// What the agent tried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    /// The operation.
    pub operation: Operation,
    /// Its subject: path, URL, command, ref.
    pub subject: String,
}

/// Why the kernel refused, with its stable code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blocked {
    /// `gate_class::deny_code` of the reason.
    pub code: String,
    /// The kernel's reason, verbatim.
    pub reason: DenyReason,
}

/// One core dimension the minimum raises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Raised {
    /// The dimension.
    pub operation: Operation,
    /// Its level in the grant.
    pub from: CapabilityLevel,
    /// Its level after the minimum, met with the ceiling.
    pub to: CapabilityLevel,
}

/// The least authority that would have allowed the attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Minimum {
    /// The effect that vouches for the attempt (lowest risk first when
    /// several do; the first is what `scopes` grant).
    pub effects: Vec<EffectId>,
    /// Every core dimension the minimum raises, grant → after.
    pub raised: Vec<Raised>,
    /// Per-dimension weakening from the grant's lattice to the lattice the
    /// effect lowers to, met with the ceiling. Empty when only the host or
    /// command vocabulary widens.
    pub requests: Vec<WeakeningRequest>,
    /// Hosts the effect adds to the grant's egress.
    pub hosts: Vec<String>,
    /// Command prefixes the effect vouches for.
    pub commands: Vec<String>,
}

/// What granting the minimum changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskDelta {
    /// Uninhabitable-state risk of the grant as it is.
    pub before: StateRisk,
    /// The same after the minimum is granted.
    pub after: StateRisk,
    /// Exposure legs the minimum adds.
    pub exposure_added: Vec<ExposureLabel>,
    /// After the minimum, all three legs are present: the kernel gates
    /// exfiltration operations on approval.
    pub kernel_will_ask: bool,
}

/// How the minimum can be granted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum Scope {
    /// For the rest of this run: the lattice to request from an approver
    /// (`POST /v1/escalate`), bounded by the ceiling. Not available in
    /// `--local` mode, which has no approver.
    ThisRun {
        /// Seconds the grant has left.
        ttl_seconds: u64,
        /// The grant's lattice with the minimum applied, met with the ceiling.
        requested: Box<PermissionLattice>,
    },
    /// Always: re-seal the grant with the effect, under the same ceiling,
    /// after the same single confirmation.
    Always {
        /// Effects to add.
        effects: Vec<EffectId>,
        /// A raised spend ceiling, when the denial was the budget.
        max_cost_usd: Option<String>,
    },
}

/// A denial, explained, with the least that would change it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationProposal {
    /// Schema version.
    pub version: u8,
    /// The grant the attempt ran under.
    pub grant_id: uuid::Uuid,
    /// What was attempted.
    pub attempted: Attempt,
    /// Why it was refused.
    pub blocked: Blocked,
    /// One sentence a person reads.
    pub plain: String,
    /// The least authority that would allow it, when authority is the answer.
    pub minimum: Option<Minimum>,
    /// What granting it changes.
    pub risk: Option<RiskDelta>,
    /// Ways to grant it. Empty when nothing should be offered.
    pub scopes: Vec<Scope>,
    /// The ceiling profile that clips the minimum, when it does.
    pub outside_ceiling: Option<String>,
    /// What to change instead of widening, when widening would not help.
    pub repair: Option<String>,
}

impl EscalationProposal {
    /// Current schema version.
    pub const VERSION: u8 = 1;
}

/// The host of a URL-ish subject.
fn host_of(subject: &str) -> Option<String> {
    let s = subject.trim();
    let rest = s.split_once("://").map_or(s, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    let host = authority.split(':').next()?.trim().to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn subject_matches(effect: &EffectSpec, op: Operation, subject: &str) -> bool {
    match op {
        Operation::WebFetch | Operation::WebSearch => host_of(subject)
            .map(|h| effect.hosts.iter().any(|p| host_matches(p, &h)))
            .unwrap_or(false),
        Operation::RunBash => effect.commands.iter().any(|p| command_matches(p, subject)),
        _ => false,
    }
}

/// Effects not already granted that would vouch for the attempt: those
/// whose lowering includes the operation, narrowed to the ones whose
/// vocabulary matches the subject when any does. Lowest risk first.
fn candidates<'c>(
    catalog: &'c EffectCatalog,
    grant: &TaskGrant,
    op: Operation,
    subject: &str,
    host: Option<&str>,
) -> Vec<&'c EffectSpec> {
    let mut all: Vec<&EffectSpec> = catalog
        .iter()
        .filter(|e| !grant.can.contains(&e.id))
        .filter(|e| match host {
            // An egress denial: the operation is granted, the host is not.
            Some(h) => e.hosts.iter().any(|p| host_matches(p, h)),
            None => e.operations.contains(&op),
        })
        .collect();
    if host.is_none() {
        let specific: Vec<&EffectSpec> = all
            .iter()
            .copied()
            .filter(|e| subject_matches(e, op, subject))
            .collect();
        if !specific.is_empty() {
            all = specific;
        }
    }
    all.sort_by(|a, b| a.risk.cmp(&b.risk).then_with(|| a.id.cmp(&b.id)));
    all
}

fn describe(reason: &DenyReason, op: Operation) -> String {
    let name = operation_name(op);
    match reason {
        DenyReason::InsufficientCapability => format!("the grant holds {name} at never"),
        DenyReason::BudgetExhausted { remaining_usd } => {
            format!("the grant's budget is exhausted (${remaining_usd} left)")
        }
        DenyReason::TimeExpired { expired_at } => {
            format!(
                "the grant expired at {}",
                expired_at.format("%Y-%m-%d %H:%M UTC")
            )
        }
        DenyReason::PathBlocked { path, denial } => match denial {
            Some(d) => format!("the path {path} is blocked ({d})"),
            None => format!("the path {path} is blocked"),
        },
        DenyReason::CommandBlocked { command } => {
            format!("no granted effect vouches for the command `{command}`")
        }
        DenyReason::IsolationInsufficient { required, actual } => {
            format!("the runtime isolation is {actual}, the policy requires {required}")
        }
        DenyReason::IsolationGated { dimension } => {
            format!("the runtime's {dimension} isolation makes {name} impossible")
        }
        DenyReason::EgressBlocked {
            host,
            policy_reason,
        } => format!("no granted effect admits egress to {host} ({policy_reason})"),
        DenyReason::DlcAdmissionDenied { detail } => {
            format!("no signed admission credential covers it ({detail})")
        }
        DenyReason::PolicyDenied {
            rule_name,
            sink_class,
        } => format!("admissibility rule '{rule_name}' denies sink {sink_class}"),
        DenyReason::EnterpriseBlocked { detail } => format!("enterprise policy: {detail}"),
        DenyReason::DelegationDenied { detail } => format!("delegation constraint: {detail}"),
        DenyReason::FlowViolation { rule, .. } => {
            format!("information-flow rule {rule}: the session's inputs would flow out")
        }
        DenyReason::InvalidDeclassification { detail } => {
            format!("declassification rejected: {detail}")
        }
        DenyReason::DeclassificationReplayed { target_node } => {
            format!("the declassification token for {target_node} was already used")
        }
        DenyReason::SinkScopeDenied { dimension, detail } => {
            format!("the certificate's {dimension} scope excludes it ({detail})")
        }
        DenyReason::ActionTermRejected { detail } => {
            format!("preflight obligation failed: {detail}")
        }
        DenyReason::IfcUnsafe { detail } => {
            format!("information-flow control: {detail}")
        }
        DenyReason::CedarDenied { detail } => format!("no Cedar permit covers it ({detail})"),
    }
}

/// Where the answer is not more authority.
fn repair_for(reason: &DenyReason, grant: &TaskGrant) -> Option<String> {
    Some(match reason {
        DenyReason::PathBlocked { .. } => {
            "blocked paths (.env, .ssh, .aws, credentials) are never granted by an effect; \
             keep the secret out of the workspace or have the credential broker inject it"
                .to_string()
        }
        DenyReason::TimeExpired { .. } => format!(
            "approve the task again: nucleus run --goal \"{}\" (a grant is not extended in place)",
            grant.goal
        ),
        DenyReason::FlowViolation { .. } | DenyReason::IfcUnsafe { .. } => {
            "the session already read untrusted content; widening authority would make the \
             flow worse, not allowed. Start a fresh session for the outbound step, or route \
             the content through human review (a declassification token) first"
                .to_string()
        }
        DenyReason::PolicyDenied { rule_name, .. } => format!(
            "the repository's admissibility rule '{rule_name}' decides this, not the grant; \
             change .nucleus/policy.toml or the inputs the action derives from"
        ),
        DenyReason::SinkScopeDenied { .. } => {
            "the delegation certificate's sink scope decides this; the parent that minted it \
             would have to delegate a wider scope"
                .to_string()
        }
        DenyReason::InvalidDeclassification { .. }
        | DenyReason::DeclassificationReplayed { .. } => {
            "mint a fresh, correctly signed declassification token for this node".to_string()
        }
        DenyReason::ActionTermRejected { detail } => {
            format!("satisfy the preflight obligation: {detail}")
        }
        DenyReason::IsolationInsufficient { required, .. } => {
            format!("run under {required} isolation (a runtime choice, not a grant)")
        }
        DenyReason::IsolationGated { dimension } => {
            format!("the runtime's {dimension} isolation is the decision, not the grant")
        }
        DenyReason::EnterpriseBlocked { .. } => {
            "the enterprise allowlist (.nucleus/enterprise.toml) decides this, not the grant"
                .to_string()
        }
        DenyReason::DelegationDenied { .. } => {
            "the delegation chain decides this, not the grant".to_string()
        }
        DenyReason::DlcAdmissionDenied { .. } => {
            "an issuer-signed admission credential for this operation is required".to_string()
        }
        DenyReason::CedarDenied { .. } => {
            "the Cedar policy decides this; add a permit rule".to_string()
        }
        DenyReason::InsufficientCapability
        | DenyReason::BudgetExhausted { .. }
        | DenyReason::CommandBlocked { .. }
        | DenyReason::EgressBlocked { .. } => return None,
    })
}

/// Build the proposal for one denial under `grant`, whose ceiling profile
/// resolved to `ceiling`.
#[must_use]
pub fn propose(
    grant: &TaskGrant,
    ceiling: &PermissionLattice,
    catalog: &EffectCatalog,
    cost: &WeakeningCostConfig,
    operation: Operation,
    subject: &str,
    reason: &DenyReason,
) -> EscalationProposal {
    let attempted = Attempt {
        operation,
        subject: subject.to_string(),
    };
    let blocked = Blocked {
        code: deny_code(reason).to_string(),
        reason: reason.clone(),
    };
    let plain = format!(
        "{} `{}` was denied: {}",
        operation_name(operation),
        subject,
        describe(reason, operation)
    );
    let mut proposal = EscalationProposal {
        version: EscalationProposal::VERSION,
        grant_id: grant.id,
        attempted,
        blocked,
        plain,
        minimum: None,
        risk: None,
        scopes: Vec::new(),
        outside_ceiling: None,
        repair: repair_for(reason, grant),
    };
    if proposal.repair.is_some() {
        return proposal;
    }

    // The budget is a dimension of its own: the minimum is the spend that
    // was refused, and the scope is a raised --max-cost, still under the
    // ceiling's budget.
    if let DenyReason::BudgetExhausted { .. } = reason {
        let ceiling_max = ceiling.budget.max_cost_usd;
        let current = grant.lattice.budget.max_cost_usd;
        if ceiling_max > current {
            let mut needed = grant.lattice.clone();
            needed.budget.max_cost_usd = ceiling_max;
            let gap = cost.compute_gap(&grant.lattice, &needed);
            proposal.minimum = Some(Minimum {
                effects: Vec::new(),
                raised: Vec::new(),
                requests: gap.requests,
                hosts: Vec::new(),
                commands: Vec::new(),
            });
            proposal.risk = Some(risk_delta(&grant.lattice, &needed));
            proposal.scopes.push(Scope::Always {
                effects: Vec::new(),
                max_cost_usd: Some(ceiling_max.to_string()),
            });
        } else {
            proposal.outside_ceiling = Some(grant.ceiling_profile.clone());
        }
        return proposal;
    }

    let host = match reason {
        DenyReason::EgressBlocked { host, .. } => Some(host.as_str()),
        _ => None,
    };
    let found = candidates(catalog, grant, operation, subject, host);
    let Some(chosen) = found.first().copied() else {
        proposal.repair = Some(match reason {
            DenyReason::CommandBlocked { .. } => format!(
                "no effect in the catalog vouches for this command; declare one under \
                 .nucleus/effects/ (commands = [\"…\"]) and grant it, rather than widening {}",
                operation_name(operation)
            ),
            DenyReason::EgressBlocked { host, .. } => format!(
                "no effect in the catalog names the host {host}; declare one under \
                 .nucleus/effects/ (hosts = [\"{host}\"]) so the grant can say what reaching it means"
            ),
            _ => format!(
                "no effect in the catalog lowers to {}; declare one under .nucleus/effects/",
                operation_name(operation)
            ),
        });
        return proposal;
    };

    // Lower the chosen effect onto the grant and meet with the ceiling.
    let ids: std::collections::BTreeSet<EffectId> = [chosen.id.clone()].into_iter().collect();
    let Ok(lowered) = catalog.lower(&ids) else {
        proposal.repair = Some(format!("the effect {} does not lower cleanly", chosen.id));
        return proposal;
    };
    let mut needed = grant.lattice.clone();
    for op in Operation::ALL {
        let level = lowered.capabilities.level_for(op);
        if level != CapabilityLevel::Never {
            raise(&mut needed.capabilities, op, level);
        }
    }
    let requested = ceiling.meet(&needed).normalize();
    let admitted = requested.capabilities.level_for(operation) != CapabilityLevel::Never;
    let raised: Vec<Raised> = Operation::ALL
        .iter()
        .copied()
        .filter_map(|op| {
            let from = grant.lattice.capabilities.level_for(op);
            let to = requested.capabilities.level_for(op);
            (to > from).then_some(Raised {
                operation: op,
                from,
                to,
            })
        })
        .collect();
    let minimum = Minimum {
        effects: found.iter().map(|e| e.id.clone()).collect(),
        raised,
        requests: cost.compute_gap(&grant.lattice, &requested).requests,
        hosts: lowered.hosts.iter().cloned().collect(),
        commands: lowered.commands.iter().cloned().collect(),
    };
    proposal.risk = Some(risk_delta(&grant.lattice, &requested));
    proposal.minimum = Some(minimum);
    if !admitted {
        proposal.outside_ceiling = Some(grant.ceiling_profile.clone());
        return proposal;
    }
    let ttl_seconds =
        u64::try_from((grant.not_after - chrono::Utc::now()).num_seconds().max(0)).unwrap_or(0);
    proposal.scopes.push(Scope::Always {
        effects: vec![chosen.id.clone()],
        max_cost_usd: None,
    });
    proposal.scopes.push(Scope::ThisRun {
        ttl_seconds,
        requested: Box::new(requested),
    });
    proposal
}

fn risk_delta(before: &PermissionLattice, after: &PermissionLattice) -> RiskDelta {
    let constraint = IncompatibilityConstraint::enforcing();
    let legs_before = exposure_legs(&before.capabilities);
    let legs_after = exposure_legs(&after.capabilities);
    let after_risk = constraint.state_risk(&after.capabilities);
    RiskDelta {
        before: constraint.state_risk(&before.capabilities),
        after: after_risk,
        exposure_added: legs_after
            .into_iter()
            .filter(|l| !legs_before.contains(l))
            .collect(),
        kernel_will_ask: after_risk == StateRisk::Uninhabitable,
    }
}

/// A denial read back from a kernel trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceDenial {
    /// The operation.
    pub operation: Operation,
    /// Its subject.
    pub subject: String,
    /// The kernel's reason.
    pub reason: DenyReason,
}

/// The distinct denials in a kernel trace (`--kernel-trace` JSONL of
/// `Decision`s), in first-seen order. Lines that are not decisions are
/// skipped.
#[must_use]
pub fn denials_in_trace(jsonl: &str) -> Vec<TraceDenial> {
    let mut out: Vec<TraceDenial> = Vec::new();
    for line in jsonl.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(decision) = serde_json::from_str::<Decision>(line) else {
            continue;
        };
        let Verdict::Deny(reason) = decision.verdict else {
            continue;
        };
        let denial = TraceDenial {
            operation: decision.operation,
            subject: decision.subject,
            reason,
        };
        if !out.contains(&denial) {
            out.push(denial);
        }
    }
    out
}

fn level_word(l: CapabilityLevel) -> &'static str {
    match l {
        CapabilityLevel::Never => "never",
        CapabilityLevel::LowRisk => "low_risk",
        CapabilityLevel::Always => "always",
    }
}

fn risk_word(r: StateRisk) -> &'static str {
    match r {
        StateRisk::Safe => "safe",
        StateRisk::Low => "low",
        StateRisk::Medium => "medium",
        StateRisk::Uninhabitable => "uninhabitable",
    }
}

fn leg_word(l: ExposureLabel) -> &'static str {
    match l {
        ExposureLabel::PrivateData => "private data",
        ExposureLabel::UntrustedContent => "untrusted content",
        ExposureLabel::ExfilVector => "an exfiltration vector",
    }
}

/// The lines a person reads. `grant_ref` is how to name the grant in the
/// command offered (a file path, or `<grant>`).
#[must_use]
pub fn render_proposal(p: &EscalationProposal, catalog: &EffectCatalog, grant_ref: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "denied:  {} `{}` — {}",
        operation_name(p.attempted.operation),
        p.attempted.subject,
        describe(&p.blocked.reason, p.attempted.operation)
    );
    if let Some(m) = &p.minimum {
        let mut parts: Vec<String> = Vec::new();
        if let Some(first) = m.effects.first() {
            let title = catalog
                .get(first)
                .map(|e| e.title.to_lowercase())
                .unwrap_or_default();
            parts.push(if title.is_empty() {
                first.to_string()
            } else {
                format!("{first} ({title})")
            });
        }
        for r in &m.raised {
            parts.push(format!(
                "{}: {} → {}",
                operation_name(r.operation),
                level_word(r.from),
                level_word(r.to)
            ));
        }
        if m.raised.is_empty() {
            for r in &m.requests {
                parts.push(format!(
                    "{}: {} → {}",
                    r.dimension, r.from_level, r.to_level
                ));
            }
        }
        if !m.hosts.is_empty() {
            parts.push(format!("hosts {}", m.hosts.join(", ")));
        }
        if parts.is_empty() {
            parts.push("nothing further".into());
        }
        let _ = writeln!(out, "minimum: {}", parts.join(" · "));
        if m.effects.len() > 1 {
            let others: Vec<String> = m.effects[1..].iter().map(|e| e.to_string()).collect();
            let _ = writeln!(out, "         (also possible: {})", others.join(", "));
        }
    }
    if let Some(r) = &p.risk {
        let mut line = format!("risk:    {} → {}", risk_word(r.before), risk_word(r.after));
        if !r.exposure_added.is_empty() {
            let legs: Vec<&str> = r.exposure_added.iter().map(|l| leg_word(*l)).collect();
            let _ = write!(line, ": adds {}", legs.join(" and "));
        }
        if r.kernel_will_ask {
            let _ = write!(
                line,
                "; all three legs present, the kernel will ask before each {}",
                operation_name(p.attempted.operation)
            );
        }
        let _ = writeln!(out, "{line}");
    }
    if let Some(c) = &p.outside_ceiling {
        let what = p
            .minimum
            .as_ref()
            .and_then(|m| m.effects.first())
            .map(|e| e.to_string())
            .unwrap_or_else(|| "the minimum".into());
        let _ = writeln!(
            out,
            "outside: {what} is outside ceiling {c} — a wider ceiling is a separate decision (--ceiling …)"
        );
    }
    for s in &p.scopes {
        match s {
            Scope::Always {
                effects,
                max_cost_usd,
            } => {
                let mut cmd = format!("nucleus grant widen --grant {grant_ref}");
                if !effects.is_empty() {
                    let ids: Vec<String> = effects.iter().map(|e| e.to_string()).collect();
                    let _ = write!(cmd, " --effects {}", ids.join(","));
                }
                if let Some(c) = max_cost_usd {
                    let _ = write!(cmd, " --max-cost {c}");
                }
                let _ = writeln!(out, "grant:   {cmd}   (one confirmation, same ceiling)");
            }
            Scope::ThisRun { ttl_seconds, .. } => {
                let _ = writeln!(
                    out,
                    "         or for this run only: an approver may escalate it for {}m (needs a node with an escalation policy; not in --local)",
                    ttl_seconds / 60
                );
            }
        }
    }
    if let Some(r) = &p.repair {
        let _ = writeln!(out, "repair:  {r}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::Kernel;
    use crate::task_grant::{CompilerProvenance, GrantLimits, RiskSummary};
    use crate::{profile::ProfileRegistry, WeakeningCostConfig};
    use chrono::{Duration, Utc};
    use std::collections::BTreeSet;

    fn catalog() -> EffectCatalog {
        EffectCatalog::builtin().unwrap()
    }

    fn ceiling(name: &str) -> PermissionLattice {
        ProfileRegistry::default().resolve(name).unwrap()
    }

    fn grant(catalog: &EffectCatalog, effects: &[&str], ceiling_name: &str) -> TaskGrant {
        let can: BTreeSet<EffectId> = effects.iter().map(|s| s.parse().unwrap()).collect();
        let lowered = catalog.lower(&can).unwrap();
        let c = ceiling(ceiling_name);
        let mut lattice = c.clone();
        lattice.capabilities = lowered.capabilities;
        let lattice = c.meet(&lattice).normalize();
        let now = Utc::now();
        let not_after = now + Duration::hours(2);
        let gap =
            WeakeningCostConfig::default().compute_gap(&PermissionLattice::restrictive(), &lattice);
        TaskGrant {
            version: TaskGrant::VERSION,
            id: uuid::Uuid::new_v4(),
            goal: "fix the failing CI build".into(),
            goal_digest: TaskGrant::digest_goal("fix the failing CI build"),
            ceiling_profile: ceiling_name.into(),
            can,
            cannot: Vec::new(),
            limits: GrantLimits {
                max_cost_usd: lattice.budget.max_cost_usd,
                duration_secs: 7200,
                hosts: lowered.hosts.into_iter().collect(),
                blocked_paths: Vec::new(),
                commands: Vec::new(),
            },
            lattice,
            risk: RiskSummary {
                before: StateRisk::Safe,
                after: StateRisk::Safe,
                exposure_legs: Vec::new(),
                approval_gated: Vec::new(),
                gap,
            },
            provenance: CompilerProvenance {
                compiler: "test/0".into(),
                proposers: vec![],
                rules_fired: vec![],
                repo_context_digest: "d".into(),
            },
            created_at: now,
            not_after,
        }
    }

    #[test]
    fn a_capability_denial_names_the_effect_the_gap_and_the_one_command() {
        let catalog = catalog();
        let g = grant(
            &catalog,
            &["fs/read-workspace", "shell/run-tests"],
            "codegen",
        );
        let p = propose(
            &g,
            &ceiling("codegen"),
            &catalog,
            &WeakeningCostConfig::default(),
            Operation::GitCommit,
            "-m fix",
            &DenyReason::InsufficientCapability,
        );
        let m = p.minimum.as_ref().expect("a minimum");
        assert_eq!(m.effects[0].to_string(), "git/commit");
        assert!(
            m.raised.iter().any(|r| r.operation == Operation::GitCommit
                && r.from == CapabilityLevel::Never
                && r.to == CapabilityLevel::LowRisk),
            "{:?}",
            m.raised
        );
        assert!(p.outside_ceiling.is_none());
        assert!(p.repair.is_none());
        assert!(
            matches!(&p.scopes[0], Scope::Always { effects, .. } if effects[0].to_string() == "git/commit")
        );
        let text = render_proposal(&p, &catalog, "ci.grant");
        assert!(text.contains("denied:  git_commit `-m fix`"), "{text}");
        assert!(text.contains("minimum: git/commit"), "{text}");
        assert!(text.contains("git_commit: never → low_risk"), "{text}");
        assert!(
            text.contains("nucleus grant widen --grant ci.grant --effects git/commit"),
            "{text}"
        );
    }

    #[test]
    fn a_denial_the_ceiling_clips_offers_nothing_and_names_the_ceiling() {
        let catalog = catalog();
        let g = grant(&catalog, &["fs/read-workspace"], "read-only");
        let p = propose(
            &g,
            &ceiling("read-only"),
            &catalog,
            &WeakeningCostConfig::default(),
            Operation::GitPush,
            "origin main",
            &DenyReason::InsufficientCapability,
        );
        assert_eq!(p.outside_ceiling.as_deref(), Some("read-only"));
        assert!(p.scopes.is_empty());
        assert!(p.minimum.is_some(), "the effect is still named");
        let text = render_proposal(&p, &catalog, "g");
        assert!(text.contains("outside ceiling read-only"), "{text}");
        assert!(!text.contains("nucleus grant widen"), "{text}");
    }

    #[test]
    fn an_egress_denial_is_answered_by_the_effect_that_names_the_host() {
        let catalog = catalog();
        let g = grant(&catalog, &["fs/read-workspace"], "safe-pr-fixer");
        let p = propose(
            &g,
            &ceiling("safe-pr-fixer"),
            &catalog,
            &WeakeningCostConfig::default(),
            Operation::WebFetch,
            "https://api.github.com/repos/o/r/actions/runs",
            &DenyReason::EgressBlocked {
                host: "api.github.com".into(),
                policy_reason: "not in allowlist".into(),
            },
        );
        let m = p.minimum.as_ref().expect("a minimum");
        assert!(
            m.effects
                .iter()
                .all(|e| e.to_string().starts_with("github/")),
            "{:?}",
            m.effects
        );
        assert!(m.hosts.contains(&"api.github.com".to_string()));
        assert!(p.scopes.iter().any(|s| matches!(s, Scope::Always { .. })));
    }

    #[test]
    fn the_risk_delta_says_when_the_kernel_will_start_asking() {
        let catalog = catalog();
        // Private data + untrusted content granted; the exfil leg is the denial.
        let g = grant(
            &catalog,
            &["fs/read-workspace", "github/read-ci-logs"],
            "safe-pr-fixer",
        );
        let p = propose(
            &g,
            &ceiling("safe-pr-fixer"),
            &catalog,
            &WeakeningCostConfig::default(),
            Operation::RunBash,
            "cargo test",
            &DenyReason::InsufficientCapability,
        );
        let r = p.risk.as_ref().unwrap();
        assert_eq!(r.after, StateRisk::Uninhabitable);
        assert!(r.exposure_added.contains(&ExposureLabel::ExfilVector));
        assert!(r.kernel_will_ask);
        let text = render_proposal(&p, &catalog, "g");
        assert!(
            text.contains("the kernel will ask before each run_bash"),
            "{text}"
        );
    }

    #[test]
    fn information_flow_and_secret_path_denials_propose_repair_not_authority() {
        let catalog = catalog();
        let g = grant(
            &catalog,
            &["fs/read-workspace", "git/push-branch"],
            "codegen",
        );
        for reason in [
            DenyReason::IfcUnsafe {
                detail: "web content read".into(),
            },
            DenyReason::FlowViolation {
                rule: "Exfiltration".into(),
                receipt: None,
            },
            DenyReason::PathBlocked {
                path: ".env".into(),
                denial: None,
            },
        ] {
            let p = propose(
                &g,
                &ceiling("codegen"),
                &catalog,
                &WeakeningCostConfig::default(),
                Operation::GitPush,
                "origin main",
                &reason,
            );
            assert!(p.repair.is_some(), "{reason:?}");
            assert!(p.scopes.is_empty(), "{reason:?}");
            assert!(p.minimum.is_none(), "{reason:?}");
        }
    }

    #[test]
    fn a_budget_denial_proposes_the_ceilings_budget_and_nothing_wider() {
        let catalog = catalog();
        let mut g = grant(&catalog, &["fs/read-workspace"], "codegen");
        g.lattice.budget.max_cost_usd = rust_decimal::Decimal::new(100, 2);
        let p = propose(
            &g,
            &ceiling("codegen"),
            &catalog,
            &WeakeningCostConfig::default(),
            Operation::RunBash,
            "cargo test",
            &DenyReason::BudgetExhausted {
                remaining_usd: "0".into(),
            },
        );
        match &p.scopes[0] {
            Scope::Always { max_cost_usd, .. } => {
                assert_eq!(
                    max_cost_usd.as_deref(),
                    Some(ceiling("codegen").budget.max_cost_usd.to_string().as_str())
                );
            }
            other => panic!("{other:?}"),
        }
        let text = render_proposal(&p, &catalog, "g");
        assert!(text.contains("--max-cost"), "{text}");
    }

    #[test]
    #[allow(deprecated)] // `decide` is the shortest way to a real `Decision` line
    fn denials_are_read_back_from_a_kernel_trace() {
        let mut kernel = Kernel::new(PermissionLattice::restrictive());
        let (allowed, _) = kernel.decide(Operation::ReadFiles, "src/main.rs");
        let (denied, _) = kernel.decide(Operation::GitPush, "origin main");
        let (again, _) = kernel.decide(Operation::GitPush, "origin main");
        assert!(matches!(denied.verdict, Verdict::Deny(_)));
        let jsonl = format!(
            "{}\n{}\n{}\n{{\"type\":\"session_summary\"}}\nnot json\n",
            serde_json::to_string(&allowed).unwrap(),
            serde_json::to_string(&denied).unwrap(),
            serde_json::to_string(&again).unwrap()
        );
        let denials = denials_in_trace(&jsonl);
        assert_eq!(denials.len(), 1, "deduplicated: {denials:?}");
        assert_eq!(denials[0].operation, Operation::GitPush);
        assert_eq!(denials[0].subject, "origin main");
        assert_eq!(denials[0].reason, DenyReason::InsufficientCapability);
    }
}
