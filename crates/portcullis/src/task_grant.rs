//! The task grant: what a goal compiles to, and how a person reads it.
//!
//! A [`TaskGrant`] is the durable object the `nucleus run --goal` loop is
//! built around. It records the goal (prompt playback), the semantic effects
//! the compiler granted (`can`) and clipped (`cannot`), the lattice they
//! lower to — already met with the ceiling profile, so it is never wider —
//! the limits, and a risk summary derived from the uninhabitable-state
//! analysis. Later milestones seal it into a certificate and attribute
//! receipts back to it; this milestone renders it.
//!
//! Rendering is progressive disclosure. [`Disclosure::Plain`] is the five
//! lines everyone reads (Goal / Can / Cannot / Limits / Risk).
//! [`Disclosure::Technical`] appends the 13-dimension grid in the vocabulary
//! of `docs/permissions.md`. [`Disclosure::PolicyTrace`] appends the
//! per-dimension weakening requests the grant is made of, with their cost.
//! Same object, three depths; the bottom two are why a security engineer
//! trusts the top one.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::effect_catalog::{EffectCatalog, EffectId};
use crate::{
    CapabilityLevel, DelegationError, ExposureLabel, IncompatibilityConstraint, Operation,
    PermissionLattice, StateRisk, WeakeningGap,
};

/// The bounds a grant carries besides its lattice, in the units a person
/// reads them in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantLimits {
    /// Spend ceiling in USD.
    pub max_cost_usd: Decimal,
    /// Lifetime, seconds from `created_at`.
    pub duration_secs: u64,
    /// Hosts the grant admits egress to (empty = none).
    pub hosts: Vec<String>,
    /// Path globs the grant blocks.
    pub blocked_paths: Vec<String>,
    /// Command prefixes the granted effects vouch for (informational in this
    /// milestone; the lattice's own command rules still apply).
    pub commands: Vec<String>,
}

/// The uninhabitable-state analysis of the grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSummary {
    /// Risk with nothing granted.
    pub before: StateRisk,
    /// Risk of the granted lattice.
    pub after: StateRisk,
    /// Exposure legs the granted capabilities provide.
    pub exposure_legs: Vec<ExposureLabel>,
    /// Operations the kernel will gate on human approval.
    pub approval_gated: Vec<Operation>,
    /// Per-dimension weakenings from the restrictive floor, with cost.
    pub gap: WeakeningGap,
}

/// Where the grant came from, for the audit trail and for reuse matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerProvenance {
    /// `<crate>/<version>` of the compiler.
    pub compiler: String,
    /// Names of the proposers consulted, in order.
    pub proposers: Vec<String>,
    /// Ids of the rules that fired.
    pub rules_fired: Vec<String>,
    /// Digest of the repository context the goal was compiled against.
    pub repo_context_digest: String,
}

/// An effect the compiler proposed but the ceiling did not admit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClippedEffect {
    /// The effect.
    pub id: EffectId,
    /// Why it was clipped.
    pub reason: String,
}

/// A compiled grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskGrant {
    /// Schema version.
    pub version: u8,
    /// Unique id.
    pub id: Uuid,
    /// The goal as the person stated it.
    pub goal: String,
    /// `sha256(goal)`, hex; binds a sealed grant to its playback.
    pub goal_digest: String,
    /// The ceiling profile the grant was met with.
    pub ceiling_profile: String,
    /// Effects granted.
    pub can: BTreeSet<EffectId>,
    /// Effects proposed but clipped by the ceiling.
    pub cannot: Vec<ClippedEffect>,
    /// Bounds.
    pub limits: GrantLimits,
    /// The lattice the run executes under; `≤ ceiling` by construction.
    pub lattice: PermissionLattice,
    /// Risk analysis.
    pub risk: RiskSummary,
    /// Provenance.
    pub provenance: CompilerProvenance,
    /// When the grant was compiled.
    pub created_at: DateTime<Utc>,
    /// When it stops being valid.
    pub not_after: DateTime<Utc>,
}

impl TaskGrant {
    /// Current schema version.
    pub const VERSION: u8 = 1;

    /// `sha256(goal)` as lowercase hex.
    pub fn digest_goal(goal: &str) -> String {
        hex_lower(&Sha256::digest(goal.as_bytes()))
    }

    /// The grant's lattice must be delegable from the ceiling: this is the
    /// same check `mint_child` makes, so a grant that passes here is one a
    /// certificate could carry.
    pub fn assert_within(&self, ceiling: &PermissionLattice) -> Result<(), DelegationError> {
        ceiling
            .delegate_to(&self.lattice, "task grant within ceiling")
            .map(|_| ())
    }

    /// Whether the grant has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// How much of the grant to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disclosure {
    /// Goal / Can / Cannot / Limits / Risk.
    Plain,
    /// Plain plus the 13-dimension capability grid.
    Technical,
    /// Technical plus the weakening requests and their cost.
    PolicyTrace,
}

impl std::str::FromStr for Disclosure {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "plain" => Ok(Self::Plain),
            "technical" => Ok(Self::Technical),
            "policy-trace" | "policy_trace" | "trace" => Ok(Self::PolicyTrace),
            other => Err(format!(
                "unknown disclosure level '{other}' (plain | technical | policy-trace)"
            )),
        }
    }
}

/// Render a grant at the given depth.
pub fn render(grant: &TaskGrant, catalog: &EffectCatalog, level: Disclosure) -> String {
    let mut out = String::new();
    render_plain(&mut out, grant, catalog);
    if matches!(level, Disclosure::Technical | Disclosure::PolicyTrace) {
        render_technical(&mut out, grant);
    }
    if level == Disclosure::PolicyTrace {
        render_policy_trace(&mut out, grant);
    }
    out
}

fn render_plain(out: &mut String, grant: &TaskGrant, catalog: &EffectCatalog) {
    let _ = writeln!(out, "Goal:    {}", grant.goal);

    // Can: titles, ordered by risk then id.
    let mut can: Vec<_> = grant
        .can
        .iter()
        .map(|id| {
            let (risk, title) = catalog
                .get(id)
                .map(|e| (e.risk, e.title.clone()))
                .unwrap_or((crate::effect_catalog::EffectRisk::Read, id.to_string()));
            (risk, id.clone(), title)
        })
        .collect();
    can.sort();
    let can_line = join_dot(can.iter().map(|(_, _, t)| lower_first(t)));
    let _ = writeln!(out, "Can:     {can_line}");

    // Cannot: clipped effects first, then structural absences.
    let mut cannot: Vec<String> = grant
        .cannot
        .iter()
        .map(|c| {
            let title = catalog
                .get(&c.id)
                .map(|e| lower_first(&e.title))
                .unwrap_or_else(|| c.id.to_string());
            format!("{title} ({})", c.reason)
        })
        .collect();
    cannot.extend(structural_absences(grant));
    let _ = writeln!(out, "Cannot:  {}", join_dot(cannot));

    // Limits.
    let hours = grant.limits.duration_secs as f64 / 3600.0;
    let mut limits = vec![
        format!("${:.2}", grant.limits.max_cost_usd),
        if hours >= 1.0 {
            format!("{hours:.0}h")
        } else {
            format!("{}m", grant.limits.duration_secs / 60)
        },
    ];
    if grant.limits.hosts.is_empty() {
        limits.push("no network".into());
    } else {
        limits.push(format!("{} only", grant.limits.hosts.join(", ")));
    }
    if !grant.limits.blocked_paths.is_empty() {
        limits.push(format!(
            "no {}",
            summarise_paths(&grant.limits.blocked_paths).join(", ")
        ));
    }
    let _ = writeln!(out, "Limits:  {}", join_dot(limits));

    // Risk.
    let legs = grant.risk.exposure_legs.len();
    let names: Vec<&str> = grant
        .risk
        .exposure_legs
        .iter()
        .map(|l| leg_name(*l))
        .collect();
    let risk_line = if legs == 3 {
        let gated: Vec<String> = grant
            .risk
            .approval_gated
            .iter()
            .map(|o| o.to_string())
            .collect();
        if gated.is_empty() {
            "all 3 exposure legs present (private data + untrusted content + exfiltration)"
                .to_string()
        } else {
            format!(
                "all 3 exposure legs present → the kernel asks for approval before {}",
                gated.join(", ")
            )
        }
    } else {
        let missing: Vec<&str> = [
            ExposureLabel::PrivateData,
            ExposureLabel::UntrustedContent,
            ExposureLabel::ExfilVector,
        ]
        .iter()
        .filter(|l| !grant.risk.exposure_legs.contains(l))
        .map(|l| leg_name(*l))
        .collect();
        let present = if names.is_empty() {
            String::new()
        } else {
            format!(" ({})", names.join(" + "))
        };
        format!(
            "{legs} of 3 exposure legs{present}; {} absent → no approval prompts expected",
            missing.join(" and ")
        )
    };
    let _ = writeln!(out, "Risk:    {risk_line}");
}

fn render_technical(out: &mut String, grant: &TaskGrant) {
    let _ = writeln!(out);
    out.push_str(&render_capabilities(
        &grant.lattice,
        &format!("Capabilities (ceiling: {}):", grant.ceiling_profile),
    ));
    if !grant.limits.commands.is_empty() {
        let _ = writeln!(out, "Commands vouched for by the granted effects:");
        for c in &grant.limits.commands {
            let _ = writeln!(out, "  {c}");
        }
    }
    let _ = writeln!(
        out,
        "Lattice checksum: {}  grant: {}",
        grant.lattice.checksum(),
        grant.id
    );
}

/// The 13-dimension grid in the vocabulary of `docs/permissions.md`, under
/// `heading`. Shared by the grant's technical disclosure and `run --dry-run`.
pub fn render_capabilities(lattice: &PermissionLattice, heading: &str) -> String {
    let caps = &lattice.capabilities;
    let mut out = String::new();
    let _ = writeln!(out, "{heading}");
    let rows: [[Operation; 3]; 4] = [
        [
            Operation::ReadFiles,
            Operation::WebSearch,
            Operation::GitPush,
        ],
        [
            Operation::WriteFiles,
            Operation::WebFetch,
            Operation::CreatePr,
        ],
        [
            Operation::EditFiles,
            Operation::GitCommit,
            Operation::RunBash,
        ],
        [
            Operation::GlobSearch,
            Operation::GrepSearch,
            Operation::SpawnAgent,
        ],
    ];
    for row in &rows {
        let cells: Vec<String> = row
            .iter()
            .map(|op| {
                format!(
                    "{:<13}{}",
                    format!("{op}:"),
                    level_name(caps.level_for(*op))
                )
            })
            .collect();
        let _ = writeln!(out, "  {:<22}{:<22}{}", cells[0], cells[1], cells[2]);
    }
    let _ = writeln!(
        out,
        "  {:<13}{}",
        "manage_pods:",
        level_name(caps.level_for(Operation::ManagePods))
    );
    let gated: Vec<String> = Operation::ALL
        .iter()
        .filter(|op| lattice.obligations.requires(**op))
        .map(|op| op.to_string())
        .collect();
    if !gated.is_empty() {
        let _ = writeln!(out, "  approval required: {}", gated.join(", "));
    }
    out
}

fn render_policy_trace(out: &mut String, grant: &TaskGrant) {
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Policy trace (weakenings from the restrictive floor; risk {:?} → {:?}):",
        grant.risk.before, grant.risk.after
    );
    if grant.risk.gap.is_empty() {
        let _ = writeln!(out, "  none");
    }
    for req in &grant.risk.gap.requests {
        let _ = writeln!(out, "  {req}");
    }
    let _ = writeln!(out, "  total cost: {}", grant.risk.gap.total_cost);
    if !grant.provenance.rules_fired.is_empty() {
        let _ = writeln!(
            out,
            "Rules fired: {}",
            grant.provenance.rules_fired.join(", ")
        );
    }
    let _ = writeln!(
        out,
        "Compiled by {} (proposers: {}) against repo context {}",
        grant.provenance.compiler,
        if grant.provenance.proposers.is_empty() {
            "none".to_string()
        } else {
            grant.provenance.proposers.join(", ")
        },
        &grant.provenance.repo_context_digest[..grant.provenance.repo_context_digest.len().min(12)]
    );
}

/// The "cannot" lines that follow from dimensions the lattice keeps at
/// `Never`, in the order a person expects to see them.
fn structural_absences(grant: &TaskGrant) -> Vec<String> {
    let caps = &grant.lattice.capabilities;
    let never = |op: Operation| caps.level_for(op) == CapabilityLevel::Never;
    let mut v = Vec::new();
    if never(Operation::GitPush) {
        v.push("push to remote branches".to_string());
    }
    if never(Operation::CreatePr) {
        v.push("open or merge pull requests".to_string());
    }
    if never(Operation::WebFetch) && never(Operation::WebSearch) {
        v.push("reach the network".to_string());
    } else if !grant.limits.hosts.is_empty() {
        v.push(format!(
            "reach hosts other than {}",
            grant.limits.hosts.join(", ")
        ));
    }
    if never(Operation::RunBash) {
        v.push("run shell commands".to_string());
    }
    if never(Operation::WriteFiles) && never(Operation::EditFiles) {
        v.push("modify files".to_string());
    }
    if never(Operation::SpawnAgent) && never(Operation::ManagePods) {
        v.push("spawn agents or pods".to_string());
    }
    v
}

fn leg_name(l: ExposureLabel) -> &'static str {
    match l {
        ExposureLabel::PrivateData => "private data",
        ExposureLabel::UntrustedContent => "untrusted content",
        ExposureLabel::ExfilVector => "exfiltration",
    }
}

fn level_name(l: CapabilityLevel) -> &'static str {
    match l {
        CapabilityLevel::Never => "never",
        CapabilityLevel::LowRisk => "low_risk",
        CapabilityLevel::Always => "always",
    }
}

fn lower_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) if !s.starts_with("CI") && !s.starts_with("GitHub") => {
            f.to_lowercase().collect::<String>() + c.as_str()
        }
        _ => s.to_string(),
    }
}

fn join_dot<I: IntoIterator<Item = String>>(items: I) -> String {
    let v: Vec<String> = items.into_iter().collect();
    if v.is_empty() {
        "nothing".to_string()
    } else {
        v.join(" · ")
    }
}

/// `**/.ssh/**` → `.ssh`, `/etc/shadow` → `/etc/shadow`; first three, then "…".
fn summarise_paths(patterns: &[String]) -> Vec<String> {
    let mut out: Vec<String> = patterns
        .iter()
        .map(|p| {
            let t = p.trim_start_matches("**/").trim_end_matches("/**");
            t.trim_end_matches('*').trim_end_matches('.').to_string()
        })
        .filter(|s| !s.is_empty())
        .collect();
    out.sort();
    out.dedup();
    if out.len() > 3 {
        out.truncate(3);
        out.push("…".into());
    }
    out
}

/// Legs a capability lattice provides, using the same thresholds as
/// [`IncompatibilityConstraint::state_risk`].
pub fn exposure_legs(caps: &crate::CapabilityLattice) -> Vec<ExposureLabel> {
    let at_least = |l: CapabilityLevel| l >= CapabilityLevel::LowRisk;
    let mut legs = Vec::new();
    if at_least(caps.read_files) || at_least(caps.glob_search) || at_least(caps.grep_search) {
        legs.push(ExposureLabel::PrivateData);
    }
    if at_least(caps.web_fetch) || at_least(caps.web_search) {
        legs.push(ExposureLabel::UntrustedContent);
    }
    if at_least(caps.git_push) || at_least(caps.create_pr) || at_least(caps.run_bash) {
        legs.push(ExposureLabel::ExfilVector);
    }
    legs
}

/// Build the risk summary for a lattice.
pub fn summarise_risk(lattice: &PermissionLattice, gap: WeakeningGap) -> RiskSummary {
    let constraint = IncompatibilityConstraint::enforcing();
    let approval_gated: Vec<Operation> = Operation::ALL
        .iter()
        .copied()
        .filter(|op| lattice.obligations.requires(*op))
        .collect();
    RiskSummary {
        before: StateRisk::Safe,
        after: constraint.state_risk(&lattice.capabilities),
        exposure_legs: exposure_legs(&lattice.capabilities),
        approval_gated,
        gap,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effect_catalog::EffectCatalog;

    fn grant_for(lattice: PermissionLattice, can: &[&str], hosts: &[&str]) -> TaskGrant {
        let gap = crate::WeakeningCostConfig::default()
            .compute_gap(&PermissionLattice::restrictive(), &lattice);
        TaskGrant {
            version: TaskGrant::VERSION,
            id: Uuid::nil(),
            goal: "fix the failing CI build".into(),
            goal_digest: TaskGrant::digest_goal("fix the failing CI build"),
            ceiling_profile: "safe-pr-fixer".into(),
            can: can.iter().map(|s| s.parse().unwrap()).collect(),
            cannot: vec![ClippedEffect {
                id: "github/open-pr".parse().unwrap(),
                reason: "outside ceiling safe-pr-fixer".into(),
            }],
            limits: GrantLimits {
                max_cost_usd: Decimal::new(500, 2),
                duration_secs: 7200,
                hosts: hosts.iter().map(|s| s.to_string()).collect(),
                blocked_paths: vec!["**/.ssh/**".into(), "**/.aws/**".into(), "**/.env".into()],
                commands: vec!["cargo test".into()],
            },
            risk: summarise_risk(&lattice, gap),
            lattice,
            provenance: CompilerProvenance {
                compiler: "test/0".into(),
                proposers: vec!["rules".into()],
                rules_fired: vec!["ci-logs".into()],
                repo_context_digest: "abcdef0123456789".into(),
            },
            created_at: Utc::now(),
            not_after: Utc::now() + chrono::Duration::hours(2),
        }
    }

    #[test]
    fn plain_render_has_the_five_lines_in_order() {
        let catalog = EffectCatalog::builtin().unwrap();
        let mut lattice = PermissionLattice::safe_pr_fixer();
        lattice.capabilities.web_fetch = CapabilityLevel::LowRisk;
        let grant = grant_for(
            lattice,
            &[
                "fs/read-workspace",
                "github/read-ci-logs",
                "shell/run-tests",
            ],
            &["api.github.com"],
        );
        let text = render(&grant, &catalog, Disclosure::Plain);
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with("Goal:    fix the failing CI build"));
        assert!(lines[1].starts_with("Can:     "));
        assert!(lines[1].contains("read CI logs"));
        assert!(lines[2].starts_with("Cannot:  "));
        assert!(lines[2].contains("open a pull request (outside ceiling safe-pr-fixer)"));
        assert!(lines[2].contains("push to remote branches"));
        assert!(
            lines[3].starts_with("Limits:  $5.00 · 2h · api.github.com only · no .aws, .env, .ssh")
        );
        assert!(lines[4].starts_with("Risk:    "));
        assert_eq!(lines.len(), 5, "plain is exactly five lines");
    }

    #[test]
    fn deeper_disclosure_appends_grid_and_trace() {
        let catalog = EffectCatalog::builtin().unwrap();
        let grant = grant_for(PermissionLattice::read_only(), &["fs/read-workspace"], &[]);
        let technical = render(&grant, &catalog, Disclosure::Technical);
        assert!(technical.contains("Capabilities (ceiling: safe-pr-fixer)"));
        assert!(technical.contains("read_files:"));
        assert!(technical.contains("manage_pods:"));
        let trace = render(&grant, &catalog, Disclosure::PolicyTrace);
        assert!(trace.contains("Policy trace"));
        assert!(trace.contains("Rules fired: ci-logs"));
        assert!(trace.len() > technical.len());
    }

    #[test]
    fn risk_line_names_the_missing_leg() {
        let catalog = EffectCatalog::builtin().unwrap();
        let grant = grant_for(PermissionLattice::read_only(), &["fs/read-workspace"], &[]);
        let text = render(&grant, &catalog, Disclosure::Plain);
        assert!(text.contains("1 of 3 exposure legs (private data)"));
        assert!(text.contains("no approval prompts expected"));
        assert!(text.contains("Limits:  $5.00 · 2h · no network"));
    }

    #[test]
    fn assert_within_rejects_a_grant_above_its_ceiling() {
        let grant = grant_for(PermissionLattice::permissive(), &[], &[]);
        assert!(grant
            .assert_within(&PermissionLattice::read_only())
            .is_err());
        let grant = grant_for(PermissionLattice::read_only(), &[], &[]);
        assert!(grant
            .assert_within(&PermissionLattice::permissive())
            .is_ok());
    }

    #[test]
    fn grant_serde_roundtrip() {
        let grant = grant_for(PermissionLattice::read_only(), &["fs/read-workspace"], &[]);
        let json = serde_json::to_string(&grant).unwrap();
        let back: TaskGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(back.can, grant.can);
        assert_eq!(back.goal_digest, grant.goal_digest);
        assert_eq!(back.lattice.capabilities, grant.lattice.capabilities);
    }
}
