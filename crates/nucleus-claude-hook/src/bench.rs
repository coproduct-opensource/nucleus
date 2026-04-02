//! Hook latency benchmarking (#522).
//!
//! Simulates PreToolUse events through the full decision pipeline and reports
//! p50/p95/p99 latency. Runs in dry-run mode — no real tool execution, no
//! session state written to disk.
//!
//! Usage:
//!   nucleus-claude-hook --benchmark
//!   nucleus-claude-hook --benchmark --iterations 500

use std::time::{Duration, Instant};

use portcullis::kernel::Kernel;
use portcullis::PermissionLattice;
use portcullis_core::flow::NodeKind;

use crate::classify::{map_tool, operation_to_node_kind, LeafTracker};

/// Benchmark configuration.
pub(crate) struct BenchConfig {
    pub(crate) iterations: usize,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self { iterations: 100 }
    }
}

/// Timing breakdown for a single decide() call.
#[derive(Debug, Clone)]
struct TimingBreakdown {
    total: Duration,
    kernel_build: Duration,
    flow_replay: Duration,
    decide: Duration,
    receipt_build: Duration,
}

/// Benchmark results for a single scenario.
struct ScenarioResult {
    name: String,
    timings: Vec<TimingBreakdown>,
}

impl ScenarioResult {
    fn total_durations(&self) -> Vec<Duration> {
        let mut ds: Vec<Duration> = self.timings.iter().map(|t| t.total).collect();
        ds.sort();
        ds
    }

    fn percentile(sorted: &[Duration], p: f64) -> Duration {
        if sorted.is_empty() {
            return Duration::ZERO;
        }
        let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    fn mean(durations: &[Duration]) -> Duration {
        if durations.is_empty() {
            return Duration::ZERO;
        }
        let total: Duration = durations.iter().sum();
        total / durations.len() as u32
    }

    fn report(&self) {
        let sorted = self.total_durations();
        let p50 = Self::percentile(&sorted, 50.0);
        let p95 = Self::percentile(&sorted, 95.0);
        let p99 = Self::percentile(&sorted, 99.0);
        let mean = Self::mean(&sorted);
        let min = sorted.first().copied().unwrap_or(Duration::ZERO);
        let max = sorted.last().copied().unwrap_or(Duration::ZERO);

        eprintln!("  {}", self.name);
        eprintln!(
            "    p50={:.2}ms  p95={:.2}ms  p99={:.2}ms  mean={:.2}ms  min={:.2}ms  max={:.2}ms",
            p50.as_secs_f64() * 1000.0,
            p95.as_secs_f64() * 1000.0,
            p99.as_secs_f64() * 1000.0,
            mean.as_secs_f64() * 1000.0,
            min.as_secs_f64() * 1000.0,
            max.as_secs_f64() * 1000.0,
        );

        // Phase breakdown (averages)
        let n = self.timings.len() as f64;
        let avg_build: f64 = self
            .timings
            .iter()
            .map(|t| t.kernel_build.as_secs_f64())
            .sum::<f64>()
            / n;
        let avg_replay: f64 = self
            .timings
            .iter()
            .map(|t| t.flow_replay.as_secs_f64())
            .sum::<f64>()
            / n;
        let avg_decide: f64 = self
            .timings
            .iter()
            .map(|t| t.decide.as_secs_f64())
            .sum::<f64>()
            / n;
        let avg_receipt: f64 = self
            .timings
            .iter()
            .map(|t| t.receipt_build.as_secs_f64())
            .sum::<f64>()
            / n;

        eprintln!(
            "    breakdown (avg): kernel_build={:.3}ms  flow_replay={:.3}ms  decide={:.3}ms  receipt={:.3}ms",
            avg_build * 1000.0,
            avg_replay * 1000.0,
            avg_decide * 1000.0,
            avg_receipt * 1000.0,
        );

        // Target check
        let target_us = 50_000.0; // 50ms in microseconds
        let p99_us = p99.as_secs_f64() * 1_000_000.0;
        if p99_us < target_us {
            eprintln!("    -> PASS: p99 < 50ms target");
        } else {
            eprintln!(
                "    -> WARN: p99 {:.2}ms exceeds 50ms target",
                p99.as_secs_f64() * 1000.0
            );
        }
        eprintln!();
    }
}

/// Simulated tool types that exercise different decision paths.
const TOOL_NAMES: &[&str] = &[
    "Read",
    "Write",
    "Edit",
    "Bash",
    "Glob",
    "Grep",
    "WebFetch",
    "WebSearch",
    "mcp__github__get_issue",
    "mcp__fs__write_file",
];

/// Run a single benchmarked decide() through the full pipeline.
fn bench_single_decide(
    perms: &PermissionLattice,
    tool_name: &str,
    flow_observations: &[(u8, String, String)],
    allowed_ops: &[(String, String)],
) -> TimingBreakdown {
    let total_start = Instant::now();

    // Phase 1: Kernel build
    let build_start = Instant::now();
    let operation = map_tool(tool_name);
    let mut kernel = Kernel::new(perms.clone());
    let kernel_build = build_start.elapsed();

    // Phase 2: Replay flow observations
    let replay_start = Instant::now();
    let mut leaves = LeafTracker::default();
    for (op_str, subj) in allowed_ops {
        if let Ok(op) = portcullis::Operation::try_from(op_str.as_str()) {
            kernel.decide(op, subj);
        }
    }
    for &(kind_u8, ref _op_str, ref _subj) in flow_observations {
        let kind = crate::classify::u8_to_node_kind(kind_u8);
        let parents = leaves.parents_for(kind);
        if let Ok(id) = kernel.observe(kind, &parents) {
            leaves.record(kind, id);
        }
    }
    let flow_replay = replay_start.elapsed();

    // Phase 3: Actual decide
    let decide_start = Instant::now();
    let obs_kind = operation_to_node_kind(operation);
    let parents = leaves.parents_for(obs_kind);
    let (decision, _token) = kernel.decide_with_parents(operation, "/bench/subject", &parents);
    let decide = decide_start.elapsed();

    // Phase 4: Receipt build (simulate the signing overhead)
    let receipt_start = Instant::now();
    if let Some(node_id) = decision.flow_node_id {
        {
            let graph = kernel.flow_graph();
            if let Some(action_node) = graph.get(node_id) {
                let ancestor_refs: Vec<&_> =
                    parents.iter().filter_map(|&pid| graph.get(pid)).collect();
                let flow_verdict = if decision.verdict.is_denied() {
                    portcullis_core::flow::FlowVerdict::Deny(
                        portcullis_core::flow::FlowDenyReason::AuthorityEscalation,
                    )
                } else {
                    portcullis_core::flow::FlowVerdict::Allow
                };
                let _receipt = portcullis_core::receipt::build_receipt(
                    action_node,
                    &ancestor_refs,
                    flow_verdict,
                    0, // timestamp=0 for benchmark
                );
            }
        }
    }
    let receipt_build = receipt_start.elapsed();

    TimingBreakdown {
        total: total_start.elapsed(),
        kernel_build,
        flow_replay,
        decide,
        receipt_build,
    }
}

/// Build synthetic flow observations simulating a session with N prior operations.
fn build_observations(count: usize) -> (Vec<(u8, String, String)>, Vec<(String, String)>) {
    let tools = [
        "ReadFiles",
        "EditFiles",
        "GlobSearch",
        "GrepSearch",
        "RunBash",
    ];
    let mut flow_obs = Vec::with_capacity(count);
    let mut allowed_ops = Vec::with_capacity(count);

    for i in 0..count {
        let tool = tools[i % tools.len()];
        let subject = format!("/workspace/file_{i}.rs");
        let kind = match tool {
            "ReadFiles" | "GlobSearch" | "GrepSearch" => NodeKind::FileRead,
            _ => NodeKind::OutboundAction,
        };
        flow_obs.push((
            crate::classify::node_kind_to_u8(kind),
            tool.to_string(),
            subject.clone(),
        ));
        allowed_ops.push((tool.to_string(), subject));
    }
    (flow_obs, allowed_ops)
}

/// Main benchmark entry point.
pub(crate) fn run_benchmark(config: BenchConfig) {
    eprintln!(
        "nucleus benchmark — {} iterations per scenario",
        config.iterations
    );
    eprintln!("target: <50ms p99 per tool call");
    eprintln!();

    let perms = PermissionLattice::safe_pr_fixer();

    // Scenario 1: Cold start (empty session, no flow observations)
    {
        let mut timings = Vec::with_capacity(config.iterations);
        for i in 0..config.iterations {
            let tool = TOOL_NAMES[i % TOOL_NAMES.len()];
            let t = bench_single_decide(&perms, tool, &[], &[]);
            timings.push(t);
        }
        ScenarioResult {
            name: "cold-start (empty session)".to_string(),
            timings,
        }
        .report();
    }

    // Scenario 2: Warm session (50 prior operations)
    {
        let (flow_obs, allowed_ops) = build_observations(50);
        let mut timings = Vec::with_capacity(config.iterations);
        for i in 0..config.iterations {
            let tool = TOOL_NAMES[i % TOOL_NAMES.len()];
            let t = bench_single_decide(&perms, tool, &flow_obs, &allowed_ops);
            timings.push(t);
        }
        ScenarioResult {
            name: "warm-session (50 prior ops)".to_string(),
            timings,
        }
        .report();
    }

    // Scenario 3: Heavy session (500 prior operations)
    {
        let (flow_obs, allowed_ops) = build_observations(500);
        let mut timings = Vec::with_capacity(config.iterations);
        for i in 0..config.iterations {
            let tool = TOOL_NAMES[i % TOOL_NAMES.len()];
            let t = bench_single_decide(&perms, tool, &flow_obs, &allowed_ops);
            timings.push(t);
        }
        ScenarioResult {
            name: "heavy-session (500 prior ops)".to_string(),
            timings,
        }
        .report();
    }

    // Scenario 4: Stress test (1000 prior operations — target boundary)
    {
        let (flow_obs, allowed_ops) = build_observations(1000);
        let mut timings = Vec::with_capacity(config.iterations);
        for i in 0..config.iterations {
            let tool = TOOL_NAMES[i % TOOL_NAMES.len()];
            let t = bench_single_decide(&perms, tool, &flow_obs, &allowed_ops);
            timings.push(t);
        }
        ScenarioResult {
            name: "stress-test (1000 prior ops — target boundary)".to_string(),
            timings,
        }
        .report();
    }

    // Scenario 5: Without flow graph (capability-only mode)
    {
        let mut timings = Vec::with_capacity(config.iterations);
        for i in 0..config.iterations {
            let tool_name = TOOL_NAMES[i % TOOL_NAMES.len()];
            let total_start = Instant::now();

            let build_start = Instant::now();
            let operation = map_tool(tool_name);
            let mut kernel = Kernel::capability_only(perms.clone());
            let kernel_build = build_start.elapsed();

            let decide_start = Instant::now();
            let (_decision, _token) = kernel.decide(operation, "/bench/subject");
            let decide = decide_start.elapsed();

            timings.push(TimingBreakdown {
                total: total_start.elapsed(),
                kernel_build,
                flow_replay: Duration::ZERO,
                decide,
                receipt_build: Duration::ZERO,
            });
        }
        ScenarioResult {
            name: "capability-only (no flow graph)".to_string(),
            timings,
        }
        .report();
    }

    // Scenario 6: Web-tainted session (tests denial path performance)
    {
        let mut flow_obs: Vec<(u8, String, String)> = Vec::new();
        let mut allowed_ops: Vec<(String, String)> = Vec::new();

        // Add some file reads
        for i in 0..10 {
            flow_obs.push((
                crate::classify::node_kind_to_u8(NodeKind::FileRead),
                "ReadFiles".to_string(),
                format!("/workspace/file_{i}.rs"),
            ));
            allowed_ops.push(("ReadFiles".to_string(), format!("/workspace/file_{i}.rs")));
        }
        // Add web content (causes taint)
        flow_obs.push((
            crate::classify::node_kind_to_u8(NodeKind::WebContent),
            "WebFetch".to_string(),
            "https://example.com".to_string(),
        ));
        allowed_ops.push(("WebFetch".to_string(), "https://example.com".to_string()));

        let mut timings = Vec::with_capacity(config.iterations);
        // Try writes after taint — these should be denied
        for _i in 0..config.iterations {
            let t = bench_single_decide(&perms, "Write", &flow_obs, &allowed_ops);
            timings.push(t);
        }
        ScenarioResult {
            name: "web-tainted-write (denial path)".to_string(),
            timings,
        }
        .report();
    }

    // Summary: quick-win identification
    eprintln!("--- Quick Win Analysis ---");
    eprintln!();

    // Measure individual phases in isolation
    let profile_start = Instant::now();
    for _ in 0..100 {
        let _perms = PermissionLattice::safe_pr_fixer();
    }
    let profile_avg = profile_start.elapsed() / 100;
    eprintln!(
        "  Profile resolution: {:.3}ms avg (100 iterations)",
        profile_avg.as_secs_f64() * 1000.0
    );

    let kernel_start = Instant::now();
    for _ in 0..100 {
        let p = PermissionLattice::safe_pr_fixer();
        let _k = Kernel::new(p);
    }
    let kernel_avg = kernel_start.elapsed() / 100;
    eprintln!(
        "  Kernel+flow build: {:.3}ms avg (100 iterations)",
        kernel_avg.as_secs_f64() * 1000.0
    );

    // Measure replay cost scaling
    eprintln!();
    eprintln!("  Replay cost scaling:");
    for &n in &[0, 10, 50, 100, 250, 500, 1000] {
        let (obs, ops) = build_observations(n);
        let start = Instant::now();
        for _ in 0..10 {
            let mut k = Kernel::new(perms.clone());
            let mut lv = LeafTracker::default();
            for (op_str, subj) in &ops {
                if let Ok(op) = portcullis::Operation::try_from(op_str.as_str()) {
                    k.decide(op, subj);
                }
            }
            for &(kind_u8, ref _op_str, ref _subj) in &obs {
                let kind = crate::classify::u8_to_node_kind(kind_u8);
                let parents = lv.parents_for(kind);
                if let Ok(id) = k.observe(kind, &parents) {
                    lv.record(kind, id);
                }
            }
        }
        let avg = start.elapsed() / 10;
        eprintln!(
            "    {n:>5} observations: {:.3}ms replay",
            avg.as_secs_f64() * 1000.0
        );
    }

    eprintln!();
    eprintln!("  Recommendations:");
    eprintln!("    - If replay dominates: consider session state daemon (persistent kernel)");
    eprintln!("    - If kernel build dominates: profile PermissionLattice construction");
    eprintln!("    - If receipt build dominates: consider deferred/async signing");
    eprintln!("    - Target: <50ms p99 for sessions with <1000 operations");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_observations() {
        let (obs, ops) = build_observations(10);
        assert_eq!(obs.len(), 10);
        assert_eq!(ops.len(), 10);
    }

    #[test]
    fn test_bench_single_decide_completes() {
        let perms = PermissionLattice::safe_pr_fixer();
        let t = bench_single_decide(&perms, "Read", &[], &[]);
        assert!(t.total > Duration::ZERO);
    }

    #[test]
    fn test_bench_with_observations() {
        let perms = PermissionLattice::safe_pr_fixer();
        let (obs, ops) = build_observations(20);
        let t = bench_single_decide(&perms, "Write", &obs, &ops);
        assert!(t.total >= t.decide);
    }

    #[test]
    fn test_percentile_calculation() {
        let durations = vec![
            Duration::from_micros(100),
            Duration::from_micros(200),
            Duration::from_micros(300),
            Duration::from_micros(400),
            Duration::from_micros(500),
        ];
        let p50 = ScenarioResult::percentile(&durations, 50.0);
        assert_eq!(p50, Duration::from_micros(300));

        let p0 = ScenarioResult::percentile(&durations, 0.0);
        assert_eq!(p0, Duration::from_micros(100));
    }
}
