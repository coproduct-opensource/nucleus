//! The two numbers ADR 0004 asks every run to report (milestone 5).
//!
//! - **Authority overhead** ρ = authority granted ÷ authority used, over the
//!   13 core dimensions. ρ → 1 is the goal: a grant that holds nothing the
//!   run did not use. It is undefined, not infinite, when nothing was used.
//! - **Delegation clicks** C(T) = the confirmations a person gave before the
//!   run plus the approvals the kernel asked for during it. One for a new
//!   task, zero for a previously sealed grant, and every extra one is a
//!   prompt that was ceremony or a boundary the task needed moved.
//!
//! Both are computed from what the kernel already keeps: its effective
//! lattice and its append-only decision trace. The tool-proxy folds the
//! result into the exit report, the MCP server into its session summary,
//! and the CLI prints it after a run. This module is feature-free so every
//! one of them can use it; only reading a trace back from JSONL needs
//! `serde`.

use std::collections::BTreeSet;

use crate::kernel::{Decision, Verdict};
use crate::{CapabilityLevel, Operation, PermissionLattice};

/// Snake-case name of a core operation (the trace vocabulary).
fn operation_name(op: Operation) -> &'static str {
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

/// What a session was granted and what it used, in the two ADR metrics.
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthoritySummary {
    /// Core dimensions the effective lattice holds above `Never`.
    pub granted_dimensions: Vec<String>,
    /// Core dimensions at least one allowed decision used.
    pub used_dimensions: Vec<String>,
    /// ρ = granted ÷ used over dimensions; `None` when nothing was used.
    pub overhead: Option<f64>,
    /// Decisions the kernel allowed.
    pub allowed: u64,
    /// Decisions the kernel denied.
    pub denied: u64,
    /// Decisions the kernel gated on approval.
    pub approvals_requested: u64,
    /// Confirmations a person gave before the run (1 for a new goal, 0 for
    /// a sealed grant). Set by whoever asked.
    #[cfg_attr(feature = "serde", serde(default))]
    pub confirmations: u64,
    /// The task grant the session ran under, when it ran under one.
    #[cfg_attr(feature = "serde", serde(default))]
    pub task_grant_id: Option<String>,
}

impl AuthoritySummary {
    /// C(T): confirmations before the run plus approvals during it.
    #[must_use]
    pub fn delegation_clicks(&self) -> u64 {
        self.confirmations.saturating_add(self.approvals_requested)
    }

    /// One line for a run summary.
    #[must_use]
    pub fn render(&self) -> String {
        let rho = match self.overhead {
            Some(r) => format!("ρ = {r:.2}"),
            None => "ρ undefined (nothing used)".to_string(),
        };
        format!(
            "authority: {} of {} granted dimensions used · {rho} · C(T) = {} ({} confirmation{}, {} approval{} during the run) · {} allowed · {} denied",
            self.used_dimensions.len(),
            self.granted_dimensions.len(),
            self.delegation_clicks(),
            self.confirmations,
            if self.confirmations == 1 { "" } else { "s" },
            self.approvals_requested,
            if self.approvals_requested == 1 { "" } else { "s" },
            self.allowed,
            self.denied
        )
    }
}

/// Summarise `trace` against `effective`.
#[must_use]
pub fn summarise_authority(effective: &PermissionLattice, trace: &[Decision]) -> AuthoritySummary {
    let granted: BTreeSet<Operation> = Operation::ALL
        .iter()
        .copied()
        .filter(|op| effective.capabilities.level_for(*op) != CapabilityLevel::Never)
        .collect();
    let mut used: BTreeSet<Operation> = BTreeSet::new();
    let (mut allowed, mut denied, mut approvals) = (0u64, 0u64, 0u64);
    for d in trace {
        match &d.verdict {
            Verdict::Allow => {
                allowed += 1;
                used.insert(d.operation);
            }
            Verdict::RequiresApproval => {
                approvals += 1;
                used.insert(d.operation);
            }
            Verdict::Deny(_) => denied += 1,
        }
    }
    let used_granted = used.iter().filter(|op| granted.contains(op)).count();
    let overhead = (used_granted > 0).then(|| {
        // At most 13 of each: exact in f64.
        f64::from(u32::try_from(granted.len()).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(used_granted).unwrap_or(u32::MAX))
    });
    AuthoritySummary {
        granted_dimensions: granted
            .iter()
            .map(|op| operation_name(*op).to_string())
            .collect(),
        used_dimensions: used
            .iter()
            .map(|op| operation_name(*op).to_string())
            .collect(),
        overhead,
        allowed,
        denied,
        approvals_requested: approvals,
        confirmations: 0,
        task_grant_id: None,
    }
}

/// Every `Decision` line in a kernel trace (`--kernel-trace` JSONL), in
/// order. Lines that are not decisions (the session summary, garbage) are
/// skipped.
#[cfg(feature = "serde")]
#[must_use]
pub fn decisions_in_trace(jsonl: &str) -> Vec<Decision> {
    jsonl
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Decision>(l).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::Kernel;

    #[test]
    #[allow(deprecated)] // `decide` is the shortest way to a real trace
    fn overhead_and_clicks_come_from_the_kernel_trace() {
        let mut lattice = PermissionLattice::restrictive();
        lattice.capabilities.run_bash = CapabilityLevel::LowRisk;
        let mut kernel = Kernel::new(lattice);
        kernel.decide(Operation::ReadFiles, "src/main.rs");
        kernel.decide(Operation::ReadFiles, "Cargo.toml");
        kernel.decide(Operation::GitPush, "origin main"); // denied: never

        let mut s = summarise_authority(kernel.effective(), kernel.trace());
        // restrictive: read, glob, grep at Always; plus run_bash = 4 granted.
        assert_eq!(s.granted_dimensions.len(), 4, "{:?}", s.granted_dimensions);
        assert_eq!(s.used_dimensions, vec!["read_files"]);
        assert!((s.overhead.unwrap() - 4.0).abs() < 1e-9);
        assert_eq!(s.allowed, 2);
        assert_eq!(s.denied, 1);
        assert_eq!(s.approvals_requested, 0);
        assert_eq!(s.delegation_clicks(), 0);
        s.confirmations = 1;
        assert_eq!(s.delegation_clicks(), 1);
        let line = s.render();
        assert!(line.contains("1 of 4 granted dimensions used"), "{line}");
        assert!(line.contains("ρ = 4.00"), "{line}");
        assert!(
            line.contains("C(T) = 1 (1 confirmation, 0 approvals"),
            "{line}"
        );
    }

    #[test]
    fn nothing_used_has_no_overhead() {
        let s = summarise_authority(&PermissionLattice::restrictive(), &[]);
        assert_eq!(s.overhead, None);
        assert!(s.render().contains("ρ undefined"));
    }

    #[cfg(feature = "serde")]
    #[test]
    #[allow(deprecated)]
    fn a_trace_reads_back_and_the_summary_round_trips() {
        let mut kernel = Kernel::new(PermissionLattice::restrictive());
        kernel.decide(Operation::ReadFiles, "a");
        kernel.decide(Operation::GitPush, "b");
        let jsonl = kernel
            .trace()
            .iter()
            .map(|d| serde_json::to_string(d).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n{\"type\":\"session_summary\"}\n";
        let decisions = decisions_in_trace(&jsonl);
        assert_eq!(decisions.len(), 2);
        let s = summarise_authority(kernel.effective(), &decisions);
        assert_eq!(s.allowed, 1);
        assert_eq!(s.denied, 1);
        let json = serde_json::to_string(&s).unwrap();
        let back: AuthoritySummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}
