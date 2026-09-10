//! Attribute a run's observations back to the grant that authorised it, and
//! narrow the grant to what was used (ADR 0004, milestone 3).
//!
//! The loop the ADR opens is `goal → effects → minimum authority → execute →
//! receipts → narrower reusable grant`. This module is the last arrow. Given
//! a [`TaskGrant`] and the observations a run produced (`--kernel-trace`, the
//! same JSONL `nucleus observe` reads), [`attribute`] says which granted
//! effects were exercised and which never were, which operations the lattice
//! admitted that no granted effect explains, and what was denied; it yields
//! the two product metrics the ADR names:
//!
//! - **authority overhead** ρ = authority granted ÷ authority used, over the
//!   13 core dimensions ([`UsageReport::authority_overhead`]) and over
//!   effects ([`UsageReport::effect_overhead`]); ρ → 1 is the goal;
//! - the count of denials, which is what an escalation proposal would have
//!   turned into a decision.
//!
//! [`narrow`] then produces a [`ProfileSpec`] and a [`TaskGrant`] with every
//! unused core dimension at `Never` and every unused effect dropped. The
//! result is `≤` the grant by construction (an operation is either kept at
//! its granted level or set to `Never`), so learning from a run can only
//! narrow: the ceiling the person approved is never exceeded, and the
//! threshold problem observed-usage tools have (encode noise as permission,
//! or refuse the next legitimate run) is bounded on both sides by the grant
//! itself.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::effect_catalog::{command_matches, host_matches, EffectCatalog, EffectId, EffectSpec};
use crate::observe::Observation;
use crate::profile::{
    BudgetSpec, CapabilitiesSpec, ObligationSpec, PathsSpec, ProfileSpec, TimeSpec,
};
use crate::task_grant::{summarise_risk, ClippedEffect, TaskGrant};
use crate::{
    CapabilityLattice, CapabilityLevel, Operation, PermissionLattice, WeakeningCostConfig,
};

/// The 13 core dimensions, in the order the grid renders them.
pub const ALL_OPERATIONS: [Operation; 13] = [
    Operation::ReadFiles,
    Operation::GlobSearch,
    Operation::GrepSearch,
    Operation::WriteFiles,
    Operation::EditFiles,
    Operation::RunBash,
    Operation::WebSearch,
    Operation::WebFetch,
    Operation::GitCommit,
    Operation::GitPush,
    Operation::CreatePr,
    Operation::ManagePods,
    Operation::SpawnAgent,
];

/// Snake-case name of a core operation (the trace vocabulary).
#[must_use]
pub fn operation_name(op: Operation) -> &'static str {
    match op {
        Operation::ReadFiles => "read_files",
        Operation::WriteFiles => "write_files",
        Operation::EditFiles => "edit_files",
        Operation::RunBash => "run_bash",
        Operation::GlobSearch => "glob_search",
        Operation::GrepSearch => "grep_search",
        Operation::WebSearch => "web_search",
        Operation::WebFetch => "web_fetch",
        Operation::GitCommit => "git_commit",
        Operation::GitPush => "git_push",
        Operation::CreatePr => "create_pr",
        Operation::ManagePods => "manage_pods",
        Operation::SpawnAgent => "spawn_agent",
    }
}

fn level_of(caps: &CapabilityLattice, op: Operation) -> CapabilityLevel {
    caps.level_for(op)
}

fn set_level(caps: &mut CapabilityLattice, op: Operation, level: CapabilityLevel) {
    let slot = match op {
        Operation::ReadFiles => &mut caps.read_files,
        Operation::WriteFiles => &mut caps.write_files,
        Operation::EditFiles => &mut caps.edit_files,
        Operation::RunBash => &mut caps.run_bash,
        Operation::GlobSearch => &mut caps.glob_search,
        Operation::GrepSearch => &mut caps.grep_search,
        Operation::WebSearch => &mut caps.web_search,
        Operation::WebFetch => &mut caps.web_fetch,
        Operation::GitCommit => &mut caps.git_commit,
        Operation::GitPush => &mut caps.git_push,
        Operation::CreatePr => &mut caps.create_pr,
        Operation::ManagePods => &mut caps.manage_pods,
        Operation::SpawnAgent => &mut caps.spawn_agent,
    };
    *slot = level;
}

/// An operation seen in the trace, with how often and one example subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationCount {
    /// The operation.
    pub operation: Operation,
    /// How many observations.
    pub count: usize,
    /// One subject, for the report.
    pub example: String,
}

/// What a run exercised of the grant that authorised it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageReport {
    /// The grant the observations were attributed to.
    pub grant_id: Uuid,
    /// Observations read.
    pub observations: usize,
    /// Observations the policy allowed.
    pub allowed: usize,
    /// Observations the policy denied.
    pub denied: usize,
    /// Granted effects that were exercised, with how many observations each
    /// explains (an observation several effects explain counts for each).
    pub used: BTreeMap<EffectId, usize>,
    /// Granted effects no observation exercised.
    pub unused: BTreeSet<EffectId>,
    /// Allowed operations no granted effect explains: admitted by the
    /// lattice (a ceiling profile is wider than its effects), not by a
    /// stated effect. They are kept by [`narrow`], since the run needed them.
    pub unattributed: Vec<OperationCount>,
    /// Core dimensions the grant holds above `Never`.
    pub operations_granted: BTreeSet<Operation>,
    /// Core dimensions at least one allowed observation used.
    pub operations_used: BTreeSet<Operation>,
    /// What was denied (at most [`MAX_DENIALS`] kept).
    pub denials: Vec<OperationCount>,
}

/// How many denial rows a report keeps.
pub const MAX_DENIALS: usize = 20;

impl UsageReport {
    /// ρ over the 13 core dimensions: granted ÷ used. `None` when nothing
    /// was used (the ratio is undefined, not infinite).
    #[must_use]
    pub fn authority_overhead(&self) -> Option<f64> {
        let used = self
            .operations_used
            .iter()
            .filter(|op| self.operations_granted.contains(op))
            .count();
        (used > 0).then(|| ratio(self.operations_granted.len(), used))
    }

    /// ρ over effects: granted ÷ exercised. `None` when none was exercised.
    #[must_use]
    pub fn effect_overhead(&self) -> Option<f64> {
        let used = self.used.len();
        (used > 0).then(|| ratio(self.used.len() + self.unused.len(), used))
    }

    /// Nothing in the trace could be attributed at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observations == 0
    }

    /// Denials on a dimension the grant itself holds above `Never`.
    ///
    /// This is where friction lives. The grant said this *kind* of act was
    /// authorised and the run was refused anyway — because a path was
    /// blocked, a host was off the list, a budget ran out, an approval was
    /// wanted. Every one of them is a place a person's stated intent and the
    /// runtime's behaviour disagreed, and it is exactly the population
    /// `EscalationProposal` turns into a decision somebody can act on.
    ///
    /// Read it as an **upper bound on wrongly-refused work, not a bug count**.
    /// A blocked `.ssh/id_rsa` read under a grant that holds `read_files` is
    /// in here and is a perfectly correct refusal; so is an approval-gated
    /// write, which is a deferral rather than a denial of authority. What the
    /// number is good for is direction: it should fall as effects get more
    /// precise, and a rise means a grant is drifting away from the work it was
    /// compiled for.
    ///
    /// Denials on dimensions the grant does NOT hold are excluded, because
    /// those are the boundary doing its job on work nobody authorised — the
    /// opposite of friction, and counting them here would make a tighter grant
    /// look worse.
    #[must_use]
    pub fn denials_within_grant(&self) -> usize {
        self.denials
            .iter()
            .filter(|d| self.operations_granted.contains(&d.operation))
            .map(|d| d.count)
            .sum()
    }

    /// The denial rows behind [`Self::denials_within_grant`], for a report
    /// that has to say *which* work was refused rather than how much.
    #[must_use]
    pub fn denials_within_grant_rows(&self) -> Vec<&OperationCount> {
        self.denials
            .iter()
            .filter(|d| self.operations_granted.contains(&d.operation))
            .collect()
    }
}

fn ratio(num: usize, den: usize) -> f64 {
    // Counts of at most 13 dimensions or a few dozen effects: exact in f64.
    let num = u32::try_from(num).unwrap_or(u32::MAX);
    let den = u32::try_from(den).unwrap_or(u32::MAX);
    f64::from(num) / f64::from(den)
}

/// The host of a URL-ish subject (`https://api.github.com/repos/x` →
/// `api.github.com`), or the subject itself when it has no scheme.
fn host_of(subject: &str) -> Option<String> {
    let s = subject.trim();
    if s.is_empty() {
        return None;
    }
    let rest = s.split_once("://").map_or(s, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    let host = authority.split(':').next()?.trim().to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// Does the effect's recognition vocabulary match this observation's
/// subject? Only meaningful for operations that carry one (hosts for the
/// web, command prefixes for the shell).
fn subject_matches(effect: &EffectSpec, obs: &Observation) -> bool {
    match obs.operation {
        Operation::WebFetch | Operation::WebSearch => host_of(&obs.subject)
            .map(|h| effect.hosts.iter().any(|p| host_matches(p, &h)))
            .unwrap_or(false),
        Operation::RunBash => effect
            .commands
            .iter()
            .any(|p| command_matches(p, &obs.subject)),
        _ => false,
    }
}

/// Attribute `observations` to the effects `grant` grants.
///
/// An allowed observation is explained by every granted effect whose
/// lowering includes its operation; when some of those also match the
/// subject (host or command prefix) only those count, so `cargo test` is
/// `shell/run-tests` and not also `shell/run-build`. An allowed observation
/// no granted effect explains is `unattributed`. Denied observations are
/// listed, not attributed.
#[must_use]
pub fn attribute(
    grant: &TaskGrant,
    catalog: &EffectCatalog,
    observations: &[Observation],
) -> UsageReport {
    let granted: Vec<&EffectSpec> = grant.can.iter().filter_map(|id| catalog.get(id)).collect();

    let mut used: BTreeMap<EffectId, usize> = BTreeMap::new();
    let mut unattributed: BTreeMap<Operation, OperationCount> = BTreeMap::new();
    let mut denials: Vec<OperationCount> = Vec::new();
    let mut operations_used = BTreeSet::new();
    let mut allowed = 0usize;
    let mut denied = 0usize;

    for obs in observations {
        if !obs.succeeded {
            denied += 1;
            if let Some(d) = denials.iter_mut().find(|d| d.operation == obs.operation) {
                d.count += 1;
            } else if denials.len() < MAX_DENIALS {
                denials.push(OperationCount {
                    operation: obs.operation,
                    count: 1,
                    example: obs.subject.clone(),
                });
            }
            continue;
        }
        allowed += 1;
        operations_used.insert(obs.operation);

        let candidates: Vec<&EffectSpec> = granted
            .iter()
            .copied()
            .filter(|e| e.operations.contains(&obs.operation))
            .collect();
        let specific: Vec<&EffectSpec> = candidates
            .iter()
            .copied()
            .filter(|e| subject_matches(e, obs))
            .collect();
        let explained = if specific.is_empty() {
            candidates
        } else {
            specific
        };
        if explained.is_empty() {
            unattributed
                .entry(obs.operation)
                .and_modify(|c| c.count += 1)
                .or_insert_with(|| OperationCount {
                    operation: obs.operation,
                    count: 1,
                    example: obs.subject.clone(),
                });
        } else {
            for e in explained {
                *used.entry(e.id.clone()).or_insert(0) += 1;
            }
        }
    }

    let unused: BTreeSet<EffectId> = grant
        .can
        .iter()
        .filter(|id| !used.contains_key(*id))
        .cloned()
        .collect();
    let operations_granted: BTreeSet<Operation> = ALL_OPERATIONS
        .iter()
        .copied()
        .filter(|op| level_of(&grant.lattice.capabilities, *op) != CapabilityLevel::Never)
        .collect();

    UsageReport {
        grant_id: grant.id,
        observations: observations.len(),
        allowed,
        denied,
        used,
        unused,
        unattributed: unattributed.into_values().collect(),
        operations_granted,
        operations_used,
        denials,
    }
}

/// A grant narrowed to what a run used.
#[derive(Debug, Clone)]
pub struct Narrowed {
    /// A reusable profile with every unused dimension at `Never`.
    pub profile: ProfileSpec,
    /// The same authority as a grant: the used effects, the narrowed
    /// lattice, a fresh id, provenance naming the grant it came from.
    pub grant: TaskGrant,
    /// Effects the original granted that the run never exercised.
    pub dropped_effects: BTreeSet<EffectId>,
    /// Core dimensions set to `Never` because nothing used them.
    pub dropped_operations: BTreeSet<Operation>,
}

/// Narrow `grant` to what `usage` says was used. The result is `≤ grant`:
/// every core dimension is either kept at its granted level (it was used,
/// whether or not an effect explains it) or set to `Never`; paths, commands,
/// budget and time are unchanged; effects nothing exercised are dropped.
///
/// `name` names the profile (`[a-z0-9-]+`).
#[must_use]
pub fn narrow(grant: &TaskGrant, usage: &UsageReport, name: &str) -> Narrowed {
    let mut lattice = grant.lattice.clone();
    let mut dropped_operations = BTreeSet::new();
    for op in ALL_OPERATIONS {
        if !usage.operations_used.contains(&op)
            && level_of(&lattice.capabilities, op) != CapabilityLevel::Never
        {
            set_level(&mut lattice.capabilities, op, CapabilityLevel::Never);
            dropped_operations.insert(op);
        }
    }
    lattice.id = Uuid::new_v4();
    lattice.description = format!("narrowed from grant {} by observed usage", grant.id);
    lattice.derived_from = Some(grant.lattice.id);
    let lattice = lattice.normalize();
    debug_assert!(lattice.leq(&grant.lattice), "narrowing never widens");

    let kept: BTreeSet<EffectId> = usage.used.keys().cloned().collect();
    let dropped_effects: BTreeSet<EffectId> = grant
        .can
        .iter()
        .filter(|id| !kept.contains(*id))
        .cloned()
        .collect();

    let mut cannot = grant.cannot.clone();
    for id in &dropped_effects {
        cannot.push(ClippedEffect {
            id: id.clone(),
            reason: format!("unused in the observed run of grant {}", grant.id),
        });
    }

    let restrictive = PermissionLattice::restrictive();
    let gap = WeakeningCostConfig::default().compute_gap(&restrictive, &lattice);
    let risk = summarise_risk(&lattice, gap);

    let mut provenance = grant.provenance.clone();
    provenance
        .rules_fired
        .push(format!("narrowed-from:{}", grant.id));

    let narrowed_grant = TaskGrant {
        version: TaskGrant::VERSION,
        id: Uuid::new_v4(),
        goal: grant.goal.clone(),
        goal_digest: grant.goal_digest.clone(),
        ceiling_profile: grant.ceiling_profile.clone(),
        can: kept,
        cannot,
        limits: grant.limits.clone(),
        lattice: lattice.clone(),
        risk,
        provenance,
        created_at: Utc::now(),
        not_after: grant.not_after,
    };

    let profile = profile_from_lattice(
        name,
        format!(
            "Narrowed from goal \"{}\" (grant {}) by observed usage: {} of {} effects used",
            grant.goal,
            grant.id,
            narrowed_grant.can.len(),
            grant.can.len()
        ),
        &lattice,
        grant.limits.duration_secs,
    );

    Narrowed {
        profile,
        grant: narrowed_grant,
        dropped_effects,
        dropped_operations,
    }
}

fn obligation_for(op: Operation) -> ObligationSpec {
    match op {
        Operation::ReadFiles => ObligationSpec::ReadFiles,
        Operation::WriteFiles => ObligationSpec::WriteFiles,
        Operation::EditFiles => ObligationSpec::EditFiles,
        Operation::RunBash => ObligationSpec::RunBash,
        Operation::GlobSearch => ObligationSpec::GlobSearch,
        Operation::GrepSearch => ObligationSpec::GrepSearch,
        Operation::WebSearch => ObligationSpec::WebSearch,
        Operation::WebFetch => ObligationSpec::WebFetch,
        Operation::GitCommit => ObligationSpec::GitCommit,
        Operation::GitPush => ObligationSpec::GitPush,
        Operation::CreatePr => ObligationSpec::CreatePr,
        Operation::ManagePods => ObligationSpec::ManagePods,
        Operation::SpawnAgent => ObligationSpec::SpawnAgent,
    }
}

/// A [`ProfileSpec`] that builds back to `lattice` (capabilities,
/// obligations, paths, budget) with `duration_secs` as its time bound.
#[must_use]
pub fn profile_from_lattice(
    name: &str,
    description: String,
    lattice: &PermissionLattice,
    duration_secs: u64,
) -> ProfileSpec {
    let c = &lattice.capabilities;
    let mut blocked: Vec<String> = lattice.paths.blocked.iter().cloned().collect();
    blocked.sort();
    let mut allowed: Vec<String> = lattice.paths.allowed.iter().cloned().collect();
    allowed.sort();
    ProfileSpec {
        name: name.to_string(),
        description: Some(description),
        capabilities: CapabilitiesSpec {
            read_files: c.read_files,
            write_files: c.write_files,
            edit_files: c.edit_files,
            run_bash: c.run_bash,
            glob_search: c.glob_search,
            grep_search: c.grep_search,
            web_search: c.web_search,
            web_fetch: c.web_fetch,
            git_commit: c.git_commit,
            git_push: c.git_push,
            create_pr: c.create_pr,
            manage_pods: c.manage_pods,
            spawn_agent: c.spawn_agent,
        },
        obligations: lattice
            .obligations
            .approvals
            .iter()
            .map(|op| obligation_for(*op))
            .collect(),
        paths: Some(PathsSpec { allowed, blocked }),
        budget: Some(BudgetSpec {
            max_cost_usd: lattice.budget.max_cost_usd.to_string(),
            max_input_tokens: lattice.budget.max_input_tokens,
            max_output_tokens: lattice.budget.max_output_tokens,
        }),
        time: Some(TimeSpec {
            duration_hours: None,
            duration_minutes: Some((duration_secs / 60).max(1)),
        }),
    }
}

fn title(catalog: &EffectCatalog, id: &EffectId) -> String {
    catalog
        .get(id)
        .map(|e| {
            let t = &e.title;
            let mut chars = t.chars();
            match chars.next() {
                Some(f) if !t.starts_with("CI") && !t.starts_with("GitHub") => {
                    f.to_lowercase().collect::<String>() + chars.as_str()
                }
                _ => t.clone(),
            }
        })
        .unwrap_or_else(|| id.to_string())
}

/// The lines printed after a run.
#[must_use]
pub fn render_usage(report: &UsageReport, catalog: &EffectCatalog) -> String {
    let mut out = String::new();
    let total = report.used.len() + report.unused.len();
    let _ = write!(
        out,
        "authority: used {} of {} effects",
        report.used.len(),
        total
    );
    match report.authority_overhead() {
        Some(rho) => {
            let _ = write!(
                out,
                " · ρ = {rho:.2} ({} of {} granted dimensions used)",
                report
                    .operations_used
                    .iter()
                    .filter(|op| report.operations_granted.contains(op))
                    .count(),
                report.operations_granted.len()
            );
        }
        None => {
            let _ = write!(out, " · nothing used");
        }
    }
    let _ = writeln!(
        out,
        " · {} allowed · {} denied",
        report.allowed, report.denied
    );

    if !report.used.is_empty() {
        let items: Vec<String> = report
            .used
            .iter()
            .map(|(id, n)| format!("{} ({n})", title(catalog, id)))
            .collect();
        let _ = writeln!(out, "  used:    {}", items.join(" · "));
    }
    if !report.unused.is_empty() {
        let items: Vec<String> = report.unused.iter().map(|id| title(catalog, id)).collect();
        let _ = writeln!(out, "  unused:  {}", items.join(" · "));
    }
    if !report.unattributed.is_empty() {
        let items: Vec<String> = report
            .unattributed
            .iter()
            .map(|c| {
                format!(
                    "{} ({}, e.g. {})",
                    operation_name(c.operation),
                    c.count,
                    c.example
                )
            })
            .collect();
        let _ = writeln!(out, "  no effect explains: {}", items.join(" · "));
    }
    if !report.denials.is_empty() {
        let items: Vec<String> = report
            .denials
            .iter()
            .map(|c| {
                format!(
                    "{} {} ({})",
                    operation_name(c.operation),
                    c.example,
                    c.count
                )
            })
            .collect();
        let _ = writeln!(out, "  denied:  {}", items.join(" · "));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effect_catalog::EffectCatalog;
    use crate::task_grant::{CompilerProvenance, GrantLimits, RiskSummary};
    use crate::StateRisk;
    use chrono::Duration;

    fn catalog() -> EffectCatalog {
        EffectCatalog::builtin().unwrap()
    }

    fn id(s: &str) -> EffectId {
        s.parse().unwrap()
    }

    /// A grant of fs/read-workspace + shell/run-tests + shell/run-build +
    /// github/read-ci-logs + git/commit, lowered through the real catalog.
    fn grant(catalog: &EffectCatalog) -> TaskGrant {
        let can: BTreeSet<EffectId> = [
            "fs/read-workspace",
            "shell/run-tests",
            "shell/run-build",
            "github/read-ci-logs",
            "git/commit",
        ]
        .iter()
        .map(|s| id(s))
        .collect();
        let lowered = catalog.lower(&can).unwrap();
        let now = Utc::now();
        let not_after = now + Duration::hours(2);
        let mut lattice = PermissionLattice::restrictive();
        lattice.capabilities = lowered.capabilities;
        lattice.time.valid_until = not_after;
        let gap =
            WeakeningCostConfig::default().compute_gap(&PermissionLattice::restrictive(), &lattice);
        TaskGrant {
            version: TaskGrant::VERSION,
            id: Uuid::new_v4(),
            goal: "fix the failing CI build".into(),
            goal_digest: TaskGrant::digest_goal("fix the failing CI build"),
            ceiling_profile: "codegen".into(),
            can,
            cannot: Vec::new(),
            limits: GrantLimits {
                max_cost_usd: rust_decimal::Decimal::new(500, 2),
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

    fn obs(op: Operation, subject: &str) -> Observation {
        Observation::new(op, subject)
    }

    #[test]
    fn observations_are_attributed_by_operation_then_subject() {
        let catalog = catalog();
        let g = grant(&catalog);
        let trace = [
            obs(Operation::ReadFiles, "src/main.rs"),
            obs(Operation::ReadFiles, "Cargo.toml"),
            obs(Operation::RunBash, "cargo test --workspace"),
            obs(
                Operation::WebFetch,
                "https://api.github.com/repos/o/r/actions/runs",
            ),
            Observation::failed(Operation::GitPush, "origin main"),
        ];
        let r = attribute(&g, &catalog, &trace);
        assert_eq!(r.observations, 5);
        assert_eq!(r.allowed, 4);
        assert_eq!(r.denied, 1);
        assert_eq!(r.used[&id("fs/read-workspace")], 2);
        assert_eq!(
            r.used[&id("shell/run-tests")],
            1,
            "the command prefix picks run-tests over run-build"
        );
        assert!(!r.used.contains_key(&id("shell/run-build")));
        assert_eq!(r.used[&id("github/read-ci-logs")], 1);
        assert!(r.unused.contains(&id("git/commit")));
        assert!(r.unused.contains(&id("shell/run-build")));
        assert!(r.unattributed.is_empty());
        assert_eq!(r.denials.len(), 1);
        assert_eq!(r.denials[0].operation, Operation::GitPush);
        // Granted: read, glob, grep, run_bash, web_fetch, git_commit = 6; used: read, run_bash, web_fetch = 3.
        assert_eq!(r.operations_granted.len(), 6, "{:?}", r.operations_granted);
        assert_eq!(r.operations_used.len(), 3);
        assert!((r.authority_overhead().unwrap() - 2.0).abs() < 1e-9);
        assert!((r.effect_overhead().unwrap() - 5.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn an_operation_the_lattice_admits_but_no_effect_explains_is_reported() {
        let catalog = catalog();
        let mut g = grant(&catalog);
        // Widen the lattice by hand (as a ceiling profile would): git_push
        // admitted, no effect vouches for it.
        g.lattice.capabilities.git_push = CapabilityLevel::LowRisk;
        let trace = [obs(Operation::GitPush, "origin feature")];
        let r = attribute(&g, &catalog, &trace);
        assert_eq!(r.unattributed.len(), 1);
        assert_eq!(r.unattributed[0].operation, Operation::GitPush);
        assert!(r.used.is_empty());
        // Narrowing keeps what the run needed, even unexplained.
        let n = narrow(&g, &r, "pusher");
        assert_eq!(
            n.grant.lattice.capabilities.git_push,
            CapabilityLevel::LowRisk
        );
    }

    #[test]
    fn nothing_used_has_no_overhead_ratio() {
        let catalog = catalog();
        let g = grant(&catalog);
        let r = attribute(&g, &catalog, &[]);
        assert!(r.is_empty());
        assert_eq!(r.authority_overhead(), None);
        assert_eq!(r.effect_overhead(), None);
        assert_eq!(r.unused.len(), 5);
    }

    #[test]
    fn narrowing_never_widens_and_drops_what_was_unused() {
        let catalog = catalog();
        let g = grant(&catalog);
        let trace = [
            obs(Operation::ReadFiles, "src/lib.rs"),
            obs(Operation::RunBash, "cargo test"),
        ];
        let r = attribute(&g, &catalog, &trace);
        let n = narrow(&g, &r, "ci-tests");

        assert!(n.grant.lattice.leq(&g.lattice));
        assert_eq!(n.grant.can.len(), 2);
        assert!(n.grant.can.contains(&id("shell/run-tests")));
        assert_eq!(n.dropped_effects.len(), 3);
        assert!(n.dropped_operations.contains(&Operation::WebFetch));
        assert!(n.dropped_operations.contains(&Operation::GitCommit));
        assert_eq!(
            n.grant.lattice.capabilities.web_fetch,
            CapabilityLevel::Never
        );
        assert_eq!(
            n.grant.lattice.capabilities.git_commit,
            CapabilityLevel::Never
        );
        assert_eq!(
            n.grant.lattice.capabilities.read_files, g.lattice.capabilities.read_files,
            "a used dimension keeps its granted level"
        );
        assert_eq!(
            n.grant.cannot.len(),
            3,
            "dropped effects are listed with a reason"
        );
        assert_ne!(n.grant.id, g.id);
        assert_eq!(n.grant.goal_digest, g.goal_digest);

        // The profile builds back to the narrowed lattice.
        let built = n.profile.build().unwrap();
        assert!(built.capabilities.leq(&g.lattice.capabilities));
        assert_eq!(built.capabilities.web_fetch, CapabilityLevel::Never);
        assert_eq!(
            built.capabilities.run_bash,
            n.grant.lattice.capabilities.run_bash
        );
        assert_eq!(n.profile.name, "ci-tests");
        let yaml = n.profile.to_yaml().unwrap();
        assert!(yaml.contains("name: ci-tests"));
    }

    #[test]
    fn the_usage_lines_read_as_a_person_expects() {
        let catalog = catalog();
        let g = grant(&catalog);
        let trace = [
            obs(Operation::ReadFiles, "src/lib.rs"),
            Observation::failed(Operation::GitPush, "origin main"),
        ];
        let r = attribute(&g, &catalog, &trace);
        let text = render_usage(&r, &catalog);
        assert!(text.starts_with("authority: used 1 of 5 effects"), "{text}");
        assert!(text.contains("ρ = 6.00"), "{text}");
        assert!(
            text.contains("used:    read and search workspace files (1)"),
            "{text}"
        );
        assert!(text.contains("unused:  "), "{text}");
        assert!(text.contains("denied:  git_push origin main (1)"), "{text}");
    }

    #[test]
    fn hosts_are_read_from_url_subjects() {
        assert_eq!(
            host_of("https://API.github.com/x").as_deref(),
            Some("api.github.com")
        );
        assert_eq!(
            host_of("api.github.com:443/x").as_deref(),
            Some("api.github.com")
        );
        assert_eq!(
            host_of("http://u:p@h.example/").as_deref(),
            Some("h.example")
        );
        assert_eq!(host_of(""), None);
    }

    // ── The friction term (ADR 0005) ────────────────────────────────────────
    //
    // ρ says how much authority was held beyond what was used. It says nothing
    // about the other direction — work the grant meant to admit and the runtime
    // refused anyway — and that direction is where a person's stated intent and
    // the runtime's behaviour actually disagree.

    #[test]
    fn a_denial_inside_the_grant_counts_as_friction() {
        let catalog = catalog();
        let grant = grant(&catalog);
        // `read_files` is granted (fs/read-workspace lowers to it), and this
        // read was refused anyway — a blocked path, say.
        let obs = vec![Observation::failed(Operation::ReadFiles, "secrets/.env")];
        let report = attribute(&grant, &catalog, &obs);
        assert!(
            report.operations_granted.contains(&Operation::ReadFiles),
            "precondition: the grant holds read_files"
        );
        assert_eq!(report.denials_within_grant(), 1);
        assert_eq!(report.denied, 1);
    }

    /// The other direction, and the reason the two numbers are separate. A
    /// denial on a dimension nobody granted is the boundary doing its job on
    /// work nobody authorised. Counting it as friction would make a TIGHTER
    /// grant score worse, which is exactly backwards.
    #[test]
    fn a_denial_outside_the_grant_is_not_friction() {
        let catalog = catalog();
        let grant = grant(&catalog);
        let obs = vec![Observation::failed(Operation::GitPush, "origin main")];
        let report = attribute(&grant, &catalog, &obs);
        assert!(
            !report.operations_granted.contains(&Operation::GitPush),
            "precondition: the grant does NOT hold git_push"
        );
        assert_eq!(
            report.denials_within_grant(),
            0,
            "a refusal of unauthorised work is the boundary working, not friction"
        );
        assert_eq!(report.denied, 1, "it is still counted as a denial");
    }

    /// Non-vacuity for the pair above: with both present, the two numbers
    /// differ, so neither is just an alias for `denied`.
    #[test]
    fn friction_and_total_denials_are_different_numbers() {
        let catalog = catalog();
        let grant = grant(&catalog);
        let obs = vec![
            Observation::failed(Operation::ReadFiles, "secrets/.env"),
            Observation::failed(Operation::GitPush, "origin main"),
            Observation::failed(Operation::GitPush, "origin release"),
        ];
        let report = attribute(&grant, &catalog, &obs);
        assert_eq!(report.denials_within_grant(), 1);
        assert_eq!(report.denied, 3);
        let rows = report.denials_within_grant_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].operation, Operation::ReadFiles);
        assert_eq!(rows[0].example, "secrets/.env");
    }
}
