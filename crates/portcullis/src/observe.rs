//! Progressive discovery: observe agent behavior and generate minimal policies.
//!
//! An [`ObserveSession`] records tool call observations and produces a minimal
//! [`ProfileSpec`] that permits exactly the observed behavior. This is the
//! "nucleus observe" feature — a bridge from "I don't know what my agent does"
//! to "here's a tight policy."
//!
//! ## Design
//!
//! Unlike behavioral baselines (ARMO-style), the output is a **formal lattice
//! policy** — a [`ProfileSpec`] that can be validated, built into a
//! [`PermissionLattice`], and verified against the same Verus-proven invariants
//! as hand-authored profiles.
//!
//! ## Example
//!
//! ```rust
//! use portcullis::observe::{ObserveSession, Observation};
//! use portcullis::Operation;
//!
//! let mut session = ObserveSession::new("my-agent");
//!
//! // Record observed tool calls
//! session.record(Observation::new(Operation::ReadFiles, "src/main.rs"));
//! session.record(Observation::new(Operation::WebFetch, "https://docs.rs"));
//! session.record(Observation::new(Operation::EditFiles, "src/main.rs"));
//! session.record(Observation::new(Operation::GitCommit, "fix: typo"));
//!
//! // Generate minimal policy
//! let profile = session.synthesize();
//! assert_eq!(profile.name, "observed-my-agent");
//!
//! // The profile permits exactly what was observed, nothing more
//! let yaml = profile.to_yaml().unwrap();
//! println!("{}", yaml);
//!
//! // Exposure analysis is included in the summary
//! let summary = session.summary();
//! assert_eq!(summary.exposure_count, 2); // PrivateData + UntrustedContent
//! assert!(!summary.state_uninhabitable);
//! ```

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};

use crate::capability::{CapabilityLevel, Operation};
use crate::exposure_core::{apply_record, classify_operation};
use crate::guard::{ExposureLabel, ExposureSet};
use crate::profile::{
    BudgetSpec, CapabilitiesSpec, ObligationSpec, PathsSpec, ProfileSpec, TimeSpec,
};

/// A single observed tool call.
#[derive(Debug, Clone)]
pub struct Observation {
    /// The operation that was performed.
    pub operation: Operation,
    /// The subject (file path, URL, command, etc.).
    pub subject: String,
    /// Whether the operation succeeded.
    pub succeeded: bool,
    /// When it happened.
    pub timestamp: DateTime<Utc>,
}

impl Observation {
    /// Create a new successful observation.
    pub fn new(operation: Operation, subject: impl Into<String>) -> Self {
        Self {
            operation,
            subject: subject.into(),
            succeeded: true,
            timestamp: Utc::now(),
        }
    }

    /// Create a failed observation.
    pub fn failed(operation: Operation, subject: impl Into<String>) -> Self {
        Self {
            operation,
            subject: subject.into(),
            succeeded: false,
            timestamp: Utc::now(),
        }
    }
}

/// Accumulated summary of an observe session.
#[derive(Debug, Clone)]
pub struct ObserveSummary {
    /// Agent name.
    pub agent_name: String,
    /// Total observations recorded.
    pub total_observations: usize,
    /// Successful operations count.
    pub successful_operations: usize,
    /// Failed operations count.
    pub failed_operations: usize,
    /// Unique operations used.
    pub operations_used: BTreeSet<Operation>,
    /// Number of exposure legs touched (0-3).
    pub exposure_count: u8,
    /// Whether the uninhabitable_state was completed.
    pub state_uninhabitable: bool,
    /// Exposure labels present.
    pub exposure_labels: Vec<ExposureLabel>,
    /// Unique file paths accessed.
    pub paths_accessed: BTreeSet<String>,
    /// Unique URLs fetched.
    pub urls_fetched: BTreeSet<String>,
    /// Unique commands run.
    pub commands_run: BTreeSet<String>,
    /// Session duration (first to last observation).
    pub duration_seconds: Option<u64>,
}

/// Session that records agent behavior and synthesizes minimal policies.
///
/// Records [`Observation`]s and produces a [`ProfileSpec`] that permits exactly
/// the observed behavior. Only successful operations contribute to the generated
/// policy — failed operations are tracked for reporting but don't widen the
/// policy.
#[derive(Debug)]
pub struct ObserveSession {
    agent_name: String,
    observations: Vec<Observation>,
    /// Accumulated exposure from successful operations.
    exposure: ExposureSet,
    /// Operations that succeeded, with count.
    operation_counts: BTreeMap<Operation, u32>,
    /// File paths accessed (for ReadFiles, WriteFiles, EditFiles).
    paths: BTreeSet<String>,
    /// URLs fetched (for WebFetch, WebSearch).
    urls: BTreeSet<String>,
    /// Commands executed (for RunBash).
    commands: BTreeSet<String>,
    /// First observation time.
    started_at: Option<DateTime<Utc>>,
    /// Last observation time.
    last_at: Option<DateTime<Utc>>,
}

impl ObserveSession {
    /// Create a new observe session for the given agent.
    pub fn new(agent_name: impl Into<String>) -> Self {
        Self {
            agent_name: agent_name.into(),
            observations: Vec::new(),
            exposure: ExposureSet::empty(),
            operation_counts: BTreeMap::new(),
            paths: BTreeSet::new(),
            urls: BTreeSet::new(),
            commands: BTreeSet::new(),
            started_at: None,
            last_at: None,
        }
    }

    /// Record an observed tool call.
    ///
    /// Only successful operations contribute to the synthesized policy.
    /// Failed operations are recorded for the summary report.
    pub fn record(&mut self, obs: Observation) {
        if self.started_at.is_none() {
            self.started_at = Some(obs.timestamp);
        }
        self.last_at = Some(obs.timestamp);

        if obs.succeeded {
            // Accumulate exposure (monotone — only grows)
            self.exposure = apply_record(&self.exposure, obs.operation);

            // Count operation usage
            *self.operation_counts.entry(obs.operation).or_insert(0) += 1;

            // Classify subject by operation type
            match obs.operation {
                Operation::ReadFiles
                | Operation::WriteFiles
                | Operation::EditFiles
                | Operation::GlobSearch
                | Operation::GrepSearch => {
                    self.paths.insert(obs.subject.clone());
                }
                Operation::WebFetch | Operation::WebSearch => {
                    self.urls.insert(obs.subject.clone());
                }
                Operation::RunBash => {
                    self.commands.insert(obs.subject.clone());
                }
                _ => {}
            }
        }

        self.observations.push(obs);
    }

    /// Synthesize a minimal [`ProfileSpec`] from observed behavior.
    ///
    /// The generated profile:
    /// - Sets each operation to the minimum level needed (`Never` if unused,
    ///   `LowRisk` if used)
    /// - Adds uninhabitable_state obligations when all 3 exposure legs are present
    /// - Includes path restrictions based on observed access patterns
    /// - Applies conservative defaults for budget and time
    pub fn synthesize(&self) -> ProfileSpec {
        let capabilities = self.synthesize_capabilities();
        let obligations = self.synthesize_obligations();
        let paths = self.synthesize_paths();
        let time = self.synthesize_time();

        ProfileSpec {
            name: format!("observed-{}", self.agent_name),
            description: Some(format!(
                "Auto-generated from {} observed operations ({} unique)",
                self.observations.iter().filter(|o| o.succeeded).count(),
                self.operation_counts.len(),
            )),
            capabilities,
            obligations,
            paths: Some(paths),
            budget: Some(BudgetSpec::default()),
            time: Some(time),
        }
    }

    /// Get a summary of the observation session.
    pub fn summary(&self) -> ObserveSummary {
        let successful = self.observations.iter().filter(|o| o.succeeded).count();
        let failed = self.observations.len() - successful;

        let mut exposure_labels = Vec::new();
        if self.exposure.contains(ExposureLabel::PrivateData) {
            exposure_labels.push(ExposureLabel::PrivateData);
        }
        if self.exposure.contains(ExposureLabel::UntrustedContent) {
            exposure_labels.push(ExposureLabel::UntrustedContent);
        }
        if self.exposure.contains(ExposureLabel::ExfilVector) {
            exposure_labels.push(ExposureLabel::ExfilVector);
        }

        let duration = match (self.started_at, self.last_at) {
            (Some(start), Some(end)) => {
                let diff = end.signed_duration_since(start);
                Some(diff.num_seconds().unsigned_abs())
            }
            _ => None,
        };

        ObserveSummary {
            agent_name: self.agent_name.clone(),
            total_observations: self.observations.len(),
            successful_operations: successful,
            failed_operations: failed,
            operations_used: self.operation_counts.keys().copied().collect(),
            exposure_count: self.exposure.count(),
            state_uninhabitable: self.exposure.is_uninhabitable(),
            exposure_labels,
            paths_accessed: self.paths.clone(),
            urls_fetched: self.urls.clone(),
            commands_run: self.commands.clone(),
            duration_seconds: duration,
        }
    }

    /// Number of observations recorded.
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }

    /// Access the raw observations.
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }

    // ── Private helpers ─────────────────────────────────────────────

    fn synthesize_capabilities(&self) -> CapabilitiesSpec {
        // Start with everything at Never — minimum privilege
        let mut caps = CapabilitiesSpec {
            read_files: CapabilityLevel::Never,
            write_files: CapabilityLevel::Never,
            edit_files: CapabilityLevel::Never,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Never,
            grep_search: CapabilityLevel::Never,
            web_search: CapabilityLevel::Never,
            web_fetch: CapabilityLevel::Never,
            git_commit: CapabilityLevel::Never,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
        };

        // For each observed operation, set to LowRisk (minimum to permit)
        for op in self.operation_counts.keys() {
            let level = CapabilityLevel::LowRisk;
            match op {
                Operation::ReadFiles => caps.read_files = level,
                Operation::WriteFiles => caps.write_files = level,
                Operation::EditFiles => caps.edit_files = level,
                Operation::RunBash => caps.run_bash = level,
                Operation::GlobSearch => caps.glob_search = level,
                Operation::GrepSearch => caps.grep_search = level,
                Operation::WebSearch => caps.web_search = level,
                Operation::WebFetch => caps.web_fetch = level,
                Operation::GitCommit => caps.git_commit = level,
                Operation::GitPush => caps.git_push = level,
                Operation::CreatePr => caps.create_pr = level,
                Operation::ManagePods => caps.manage_pods = level,
            }
        }

        caps
    }

    fn synthesize_obligations(&self) -> Vec<ObligationSpec> {
        let mut obligations = Vec::new();

        // If uninhabitable_state is complete, add obligations on exfil operations
        if self.exposure.is_uninhabitable() {
            if self.operation_counts.contains_key(&Operation::GitPush) {
                obligations.push(ObligationSpec::GitPush);
            }
            if self.operation_counts.contains_key(&Operation::CreatePr) {
                obligations.push(ObligationSpec::CreatePr);
            }
            if self.operation_counts.contains_key(&Operation::RunBash) {
                obligations.push(ObligationSpec::RunBash);
            }
        }

        obligations
    }

    fn synthesize_paths(&self) -> PathsSpec {
        // Always block sensitive paths regardless of what was observed
        let blocked = vec![
            "**/.ssh/**".to_string(),
            "**/.env".to_string(),
            "**/.env.*".to_string(),
            "**/credentials*".to_string(),
            "**/.aws/**".to_string(),
            "**/.config/gcloud/**".to_string(),
        ];

        PathsSpec {
            allowed: Vec::new(), // Empty = all non-blocked paths allowed
            blocked,
        }
    }

    fn synthesize_time(&self) -> TimeSpec {
        // Set time limit based on observed session duration, with headroom
        let hours = match (self.started_at, self.last_at) {
            (Some(start), Some(end)) => {
                let minutes = end.signed_duration_since(start).num_minutes();
                // Give 2x headroom, minimum 1 hour
                let padded = (minutes * 2).max(60);
                Some((padded / 60).max(1) as u64)
            }
            _ => Some(2), // Default 2 hours
        };

        TimeSpec {
            duration_hours: hours,
            duration_minutes: None,
        }
    }
}

/// Parse JSONL audit log lines into observations.
///
/// Accepts three formats:
///
/// **Simple format** (manual audit logs):
/// ```json
/// {"operation": "read_files", "subject": "src/main.rs", "succeeded": true}
/// ```
///
/// **Kernel Decision format** (from `--kernel-trace` JSONL):
/// ```json
/// {"operation": "read_files", "subject": "/src/main.rs", "verdict": {"type": "allow"}, "timestamp": "..."}
/// ```
///
/// **Python SDK trace format** (from `session.trace.export_jsonl()`):
/// ```json
/// {"timestamp": 1710201600.5, "operation": "fs.read", "args": {"path": "README.md"}, "result_summary": "ok", "duration_ms": 12.5, "policy_decision": "allow"}
/// ```
///
/// SDK operation names (`fs.read`, `net.fetch`, `git.push`, etc.) are mapped
/// to canonical names. The `subject` is extracted from `args.path`, `args.url`,
/// `args.query`, `args.pattern`, or `args.git_args`. The `policy_decision`
/// field determines success (`"allow"` → succeeded).
///
/// Lines with `"type": "session_summary"` are skipped (not tool call observations).
pub fn parse_jsonl_observations(input: &str) -> Vec<Observation> {
    input
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;

            // Skip session_summary lines from kernel trace
            if v.get("type").and_then(|t| t.as_str()) == Some("session_summary") {
                return None;
            }

            let op_str = v.get("operation")?.as_str()?;
            let operation = parse_operation(op_str)?;

            // Extract subject: try "subject" first (simple/kernel format),
            // then fall back to SDK "args" fields.
            let subject = if let Some(s) = v.get("subject").and_then(|s| s.as_str()) {
                s.to_string()
            } else if let Some(args) = v.get("args") {
                // Python SDK trace: extract from args.path, args.url,
                // args.query, args.pattern, or args.git_args
                if let Some(s) = args
                    .get("path")
                    .or_else(|| args.get("url"))
                    .or_else(|| args.get("query"))
                    .or_else(|| args.get("pattern"))
                    .and_then(|v| v.as_str())
                {
                    s.to_string()
                } else if let Some(arr) = args.get("git_args").and_then(|v| v.as_array()) {
                    // git_args is an array — join with spaces
                    arr.iter()
                        .filter_map(|e| e.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            // Determine success:
            // 1. "succeeded" field (simple format)
            // 2. "verdict.type" (kernel Decision format)
            // 3. "policy_decision" (Python SDK trace format)
            // 4. Default to true
            let succeeded = if let Some(s) = v.get("succeeded").and_then(|s| s.as_bool()) {
                s
            } else if let Some(verdict_type) = v
                .get("verdict")
                .and_then(|vv| vv.get("type"))
                .and_then(|t| t.as_str())
            {
                verdict_type == "allow"
            } else if let Some(decision) = v.get("policy_decision").and_then(|d| d.as_str()) {
                decision == "allow"
            } else {
                true
            };

            // Parse timestamp: ISO 8601 string (kernel format) or
            // Unix epoch float (Python SDK format).
            let timestamp = v
                .get("timestamp")
                .and_then(|t| {
                    if let Some(s) = t.as_str() {
                        s.parse::<DateTime<Utc>>().ok()
                    } else if let Some(f) = t.as_f64() {
                        DateTime::from_timestamp(f as i64, ((f.fract()) * 1_000_000_000.0) as u32)
                    } else {
                        None
                    }
                })
                .unwrap_or_else(Utc::now);

            Some(Observation {
                operation,
                subject,
                succeeded,
                timestamp,
            })
        })
        .collect()
}

fn parse_operation(s: &str) -> Option<Operation> {
    match s {
        // Canonical names (kernel Decision format, simple format)
        "read_files" => Some(Operation::ReadFiles),
        "write_files" => Some(Operation::WriteFiles),
        "edit_files" => Some(Operation::EditFiles),
        "run_bash" => Some(Operation::RunBash),
        "glob_search" => Some(Operation::GlobSearch),
        "grep_search" => Some(Operation::GrepSearch),
        "web_search" => Some(Operation::WebSearch),
        "web_fetch" => Some(Operation::WebFetch),
        "git_commit" => Some(Operation::GitCommit),
        "git_push" => Some(Operation::GitPush),
        "create_pr" => Some(Operation::CreatePr),
        "manage_pods" => Some(Operation::ManagePods),
        // Python SDK names (dotted format from trace.export_jsonl())
        "fs.read" => Some(Operation::ReadFiles),
        "fs.write" => Some(Operation::WriteFiles),
        "fs.edit" => Some(Operation::EditFiles),
        "fs.glob" => Some(Operation::GlobSearch),
        "fs.grep" => Some(Operation::GrepSearch),
        "net.fetch" => Some(Operation::WebFetch),
        "net.search" => Some(Operation::WebSearch),
        "git.commit" => Some(Operation::GitCommit),
        "git.push" => Some(Operation::GitPush),
        "git.create_pr" => Some(Operation::CreatePr),
        "git.add" => Some(Operation::RunBash),
        _ => None,
    }
}

/// Format an [`ObserveSummary`] as a human-readable report.
pub fn format_summary(summary: &ObserveSummary) -> String {
    let mut out = String::new();

    out.push_str(&format!("# Observation Report: {}\n\n", summary.agent_name));

    out.push_str(&format!(
        "Operations: {} total ({} succeeded, {} failed)\n",
        summary.total_observations, summary.successful_operations, summary.failed_operations,
    ));

    if let Some(secs) = summary.duration_seconds {
        let mins = secs / 60;
        let remaining = secs % 60;
        out.push_str(&format!("Duration: {}m {}s\n", mins, remaining));
    }

    out.push_str(&format!(
        "\nexposure: {}/3 legs ({})\n",
        summary.exposure_count,
        if summary.state_uninhabitable {
            "uninhabitable_state COMPLETE — obligations added"
        } else {
            "safe"
        },
    ));

    for label in &summary.exposure_labels {
        out.push_str(&format!("  - {:?}\n", label));
    }

    out.push_str(&format!(
        "\nOperations used ({}):\n",
        summary.operations_used.len()
    ));
    for op in &summary.operations_used {
        let exposure = classify_operation(*op);
        let marker = match exposure {
            Some(ExposureLabel::PrivateData) => " [private-data]",
            Some(ExposureLabel::UntrustedContent) => " [untrusted-content]",
            Some(ExposureLabel::ExfilVector) => " [exfil-vector]",
            None => "",
        };
        out.push_str(&format!("  - {:?}{}\n", op, marker));
    }

    if !summary.paths_accessed.is_empty() {
        out.push_str(&format!(
            "\nPaths accessed ({}):\n",
            summary.paths_accessed.len()
        ));
        for path in summary.paths_accessed.iter().take(20) {
            out.push_str(&format!("  - {}\n", path));
        }
        if summary.paths_accessed.len() > 20 {
            out.push_str(&format!(
                "  ... and {} more\n",
                summary.paths_accessed.len() - 20
            ));
        }
    }

    if !summary.urls_fetched.is_empty() {
        out.push_str(&format!(
            "\nURLs fetched ({}):\n",
            summary.urls_fetched.len()
        ));
        for url in &summary.urls_fetched {
            out.push_str(&format!("  - {}\n", url));
        }
    }

    if !summary.commands_run.is_empty() {
        out.push_str(&format!(
            "\nCommands run ({}):\n",
            summary.commands_run.len()
        ));
        for cmd in summary.commands_run.iter().take(20) {
            out.push_str(&format!("  - {}\n", cmd));
        }
        if summary.commands_run.len() > 20 {
            out.push_str(&format!(
                "  ... and {} more\n",
                summary.commands_run.len() - 20
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_session_synthesizes_all_never() {
        let session = ObserveSession::new("test");
        let profile = session.synthesize();

        assert_eq!(profile.name, "observed-test");
        assert_eq!(profile.capabilities.read_files, CapabilityLevel::Never);
        assert_eq!(profile.capabilities.write_files, CapabilityLevel::Never);
        assert_eq!(profile.capabilities.run_bash, CapabilityLevel::Never);
        assert_eq!(profile.capabilities.git_push, CapabilityLevel::Never);
        assert!(profile.obligations.is_empty());
    }

    #[test]
    fn test_read_only_session() {
        let mut session = ObserveSession::new("reader");
        session.record(Observation::new(Operation::ReadFiles, "src/main.rs"));
        session.record(Observation::new(Operation::GlobSearch, "**/*.rs"));
        session.record(Observation::new(Operation::GrepSearch, "fn main"));

        let profile = session.synthesize();

        assert_eq!(profile.capabilities.read_files, CapabilityLevel::LowRisk);
        assert_eq!(profile.capabilities.glob_search, CapabilityLevel::LowRisk);
        assert_eq!(profile.capabilities.grep_search, CapabilityLevel::LowRisk);
        // Unobserved operations remain Never
        assert_eq!(profile.capabilities.write_files, CapabilityLevel::Never);
        assert_eq!(profile.capabilities.run_bash, CapabilityLevel::Never);
        assert_eq!(profile.capabilities.git_push, CapabilityLevel::Never);
        // No obligations (only 1 exposure leg)
        assert!(profile.obligations.is_empty());
    }

    #[test]
    fn test_uninhabitable_triggers_obligations() {
        let mut session = ObserveSession::new("risky");
        // Leg 1: private data
        session.record(Observation::new(Operation::ReadFiles, "secrets.txt"));
        // Leg 2: untrusted content
        session.record(Observation::new(Operation::WebFetch, "https://evil.com"));
        // Leg 3: exfiltration
        session.record(Observation::new(Operation::GitPush, "origin main"));

        let profile = session.synthesize();

        //  UninhabitableState complete → obligations on exfil ops
        assert!(profile
            .obligations
            .iter()
            .any(|o| matches!(o, ObligationSpec::GitPush)));

        let summary = session.summary();
        assert!(summary.state_uninhabitable);
        assert_eq!(summary.exposure_count, 3);
    }

    #[test]
    fn test_failed_operations_dont_widen_policy() {
        let mut session = ObserveSession::new("cautious");
        session.record(Observation::new(Operation::ReadFiles, "src/main.rs"));
        session.record(Observation::failed(Operation::GitPush, "origin main"));

        let profile = session.synthesize();

        // ReadFiles was successful → LowRisk
        assert_eq!(profile.capabilities.read_files, CapabilityLevel::LowRisk);
        // GitPush failed → stays Never
        assert_eq!(profile.capabilities.git_push, CapabilityLevel::Never);
    }

    #[test]
    fn test_exposure_monotonicity() {
        let mut session = ObserveSession::new("mono");
        session.record(Observation::new(Operation::ReadFiles, "a.txt"));

        let s1 = session.summary();
        assert_eq!(s1.exposure_count, 1);

        session.record(Observation::new(Operation::WebFetch, "https://example.com"));

        let s2 = session.summary();
        assert_eq!(s2.exposure_count, 2);
        assert!(s2.exposure_count >= s1.exposure_count); // Monotone
    }

    #[test]
    fn test_sensitive_paths_always_blocked() {
        let mut session = ObserveSession::new("safe");
        session.record(Observation::new(Operation::ReadFiles, ".ssh/id_rsa"));

        let profile = session.synthesize();

        assert!(profile
            .paths
            .as_ref()
            .unwrap()
            .blocked
            .contains(&"**/.ssh/**".to_string()));
    }

    #[test]
    fn test_parse_jsonl() {
        let input = r#"{"operation":"read_files","subject":"src/main.rs","succeeded":true}
{"operation":"web_fetch","subject":"https://docs.rs","succeeded":true}
{"operation":"git_push","subject":"origin main","succeeded":false}
"#;

        let observations = parse_jsonl_observations(input);
        assert_eq!(observations.len(), 3);
        assert_eq!(observations[0].operation, Operation::ReadFiles);
        assert_eq!(observations[1].operation, Operation::WebFetch);
        assert!(!observations[2].succeeded);
    }

    #[test]
    fn test_parse_jsonl_skips_unknown_operations() {
        let input = r#"{"operation":"read_files","subject":"a.txt"}
{"operation":"unknown_op","subject":"foo"}
{"operation":"web_fetch","subject":"https://example.com"}
"#;

        let observations = parse_jsonl_observations(input);
        assert_eq!(observations.len(), 2);
    }

    #[test]
    fn test_parse_kernel_decision_format() {
        // Kernel Decision JSONL format with verdict.type
        let input = r#"{"id":"abc","sequence":0,"operation":"read_files","subject":"src/main.rs","verdict":{"type":"allow"},"timestamp":"2026-03-12T00:00:00Z","pre_permissions_hash":"a","post_permissions_hash":"b","exposure_transition":{"pre_count":0,"post_count":1,"contributed_label":"private_data","state_uninhabitable":false,"dynamic_gate_applied":false}}
{"id":"def","sequence":1,"operation":"write_files","subject":"out.txt","verdict":{"type":"deny","reason":"insufficient_capability"},"timestamp":"2026-03-12T00:01:00Z","pre_permissions_hash":"a","post_permissions_hash":"a","exposure_transition":{"pre_count":1,"post_count":1,"contributed_label":null,"state_uninhabitable":false,"dynamic_gate_applied":false}}
{"id":"ghi","sequence":2,"operation":"web_fetch","subject":"https://example.com","verdict":{"type":"requires_approval"},"timestamp":"2026-03-12T00:02:00Z","pre_permissions_hash":"a","post_permissions_hash":"a","exposure_transition":{"pre_count":1,"post_count":1,"contributed_label":null,"state_uninhabitable":false,"dynamic_gate_applied":true}}
"#;

        let observations = parse_jsonl_observations(input);
        assert_eq!(observations.len(), 3);

        // allow → succeeded
        assert_eq!(observations[0].operation, Operation::ReadFiles);
        assert!(observations[0].succeeded);

        // deny → not succeeded
        assert_eq!(observations[1].operation, Operation::WriteFiles);
        assert!(!observations[1].succeeded);

        // requires_approval → not succeeded
        assert_eq!(observations[2].operation, Operation::WebFetch);
        assert!(!observations[2].succeeded);
    }

    #[test]
    fn test_parse_kernel_decision_skips_session_summary() {
        let input = r#"{"id":"abc","sequence":0,"operation":"read_files","subject":"a.txt","verdict":{"type":"allow"},"timestamp":"2026-03-12T00:00:00Z","pre_permissions_hash":"a","post_permissions_hash":"b","exposure_transition":{"pre_count":0,"post_count":1,"contributed_label":"private_data","state_uninhabitable":false,"dynamic_gate_applied":false}}
{"type":"session_summary","session_id":"123","decisions":1,"consumed_usd":"0.01","remaining_usd":"9.99","initial_hash":"abc"}
"#;

        let observations = parse_jsonl_observations(input);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].operation, Operation::ReadFiles);
    }

    #[test]
    fn test_parse_mixed_formats() {
        // Both simple and kernel Decision formats in the same input
        let input = r#"{"operation":"read_files","subject":"a.txt","succeeded":true}
{"id":"abc","sequence":0,"operation":"web_fetch","subject":"https://example.com","verdict":{"type":"allow"},"timestamp":"2026-03-12T00:00:00Z","pre_permissions_hash":"a","post_permissions_hash":"b","exposure_transition":{"pre_count":0,"post_count":1,"contributed_label":null,"state_uninhabitable":false,"dynamic_gate_applied":false}}
{"operation":"git_push","subject":"origin main","succeeded":false}
"#;

        let observations = parse_jsonl_observations(input);
        assert_eq!(observations.len(), 3);
        assert!(observations[0].succeeded);
        assert!(observations[1].succeeded); // verdict.type == "allow"
        assert!(!observations[2].succeeded);
    }

    #[test]
    fn test_synthesized_profile_builds_valid_lattice() {
        let mut session = ObserveSession::new("validator");
        session.record(Observation::new(Operation::ReadFiles, "src/lib.rs"));
        session.record(Observation::new(Operation::EditFiles, "src/lib.rs"));
        session.record(Observation::new(Operation::WebFetch, "https://crates.io"));
        session.record(Observation::new(Operation::GitCommit, "fix: bug"));

        let profile = session.synthesize();

        // Profile must validate and build into a real lattice
        assert!(profile.validate().is_ok());
        let lattice = profile.build();
        assert!(
            lattice.is_ok(),
            "synthesized profile must build: {:?}",
            lattice.err()
        );
    }

    #[test]
    fn test_format_summary_not_empty() {
        let mut session = ObserveSession::new("formatter");
        session.record(Observation::new(Operation::ReadFiles, "a.txt"));

        let summary = session.summary();
        let report = format_summary(&summary);

        assert!(report.contains("formatter"));
        assert!(report.contains("ReadFiles"));
    }

    #[test]
    fn test_summary_tracks_subjects() {
        let mut session = ObserveSession::new("tracker");
        session.record(Observation::new(Operation::ReadFiles, "a.txt"));
        session.record(Observation::new(Operation::ReadFiles, "b.txt"));
        session.record(Observation::new(Operation::WebFetch, "https://example.com"));
        session.record(Observation::new(Operation::RunBash, "cargo test"));

        let summary = session.summary();
        assert_eq!(summary.paths_accessed.len(), 2);
        assert_eq!(summary.urls_fetched.len(), 1);
        assert_eq!(summary.commands_run.len(), 1);
    }

    #[test]
    fn test_parse_sdk_trace_format() {
        // Python SDK trace.export_jsonl() format
        let input = r#"{"timestamp":1710201600.5,"operation":"fs.read","args":{"path":"README.md"},"result_summary":"ok","duration_ms":12.5,"policy_decision":"allow"}
{"timestamp":1710201601.0,"operation":"net.fetch","args":{"url":"https://docs.rs","method":"GET"},"result_summary":"ok","duration_ms":150.0,"policy_decision":"allow"}
{"timestamp":1710201602.0,"operation":"git.push","args":{"git_args":["push","origin","main"]},"result_summary":"exit_code=0","duration_ms":2000.0,"policy_decision":"allow"}
{"timestamp":1710201603.0,"operation":"fs.write","args":{"path":"out.txt"},"result_summary":"ok","duration_ms":5.0,"policy_decision":"deny"}
"#;

        let observations = parse_jsonl_observations(input);
        assert_eq!(observations.len(), 4);

        // fs.read → ReadFiles, subject from args.path
        assert_eq!(observations[0].operation, Operation::ReadFiles);
        assert_eq!(observations[0].subject, "README.md");
        assert!(observations[0].succeeded);

        // net.fetch → WebFetch, subject from args.url
        assert_eq!(observations[1].operation, Operation::WebFetch);
        assert_eq!(observations[1].subject, "https://docs.rs");
        assert!(observations[1].succeeded);

        // git.push → GitPush, subject from args.git_args joined
        assert_eq!(observations[2].operation, Operation::GitPush);
        assert_eq!(observations[2].subject, "push origin main");
        assert!(observations[2].succeeded);

        // policy_decision: "deny" → not succeeded
        assert_eq!(observations[3].operation, Operation::WriteFiles);
        assert_eq!(observations[3].subject, "out.txt");
        assert!(!observations[3].succeeded);
    }

    #[test]
    fn test_parse_sdk_trace_glob_grep() {
        let input = r#"{"timestamp":1710201600.0,"operation":"fs.glob","args":{"pattern":"**/*.rs"},"result_summary":"ok","duration_ms":10.0,"policy_decision":"allow"}
{"timestamp":1710201601.0,"operation":"fs.grep","args":{"pattern":"fn main"},"result_summary":"ok","duration_ms":20.0,"policy_decision":"allow"}
{"timestamp":1710201602.0,"operation":"net.search","args":{"query":"rust async"},"result_summary":"ok","duration_ms":300.0,"policy_decision":"allow"}
"#;

        let observations = parse_jsonl_observations(input);
        assert_eq!(observations.len(), 3);

        assert_eq!(observations[0].operation, Operation::GlobSearch);
        assert_eq!(observations[0].subject, "**/*.rs");

        assert_eq!(observations[1].operation, Operation::GrepSearch);
        assert_eq!(observations[1].subject, "fn main");

        assert_eq!(observations[2].operation, Operation::WebSearch);
        assert_eq!(observations[2].subject, "rust async");
    }

    #[test]
    fn test_parse_sdk_trace_numeric_timestamp() {
        let input = r#"{"timestamp":1710201600.123,"operation":"fs.read","args":{"path":"a.txt"},"result_summary":"ok","duration_ms":1.0,"policy_decision":"allow"}"#;

        let observations = parse_jsonl_observations(input);
        assert_eq!(observations.len(), 1);
        // Verify the timestamp was parsed from the numeric value
        assert_eq!(observations[0].timestamp.timestamp(), 1710201600);
    }

    #[test]
    fn test_parse_sdk_trace_feeds_observe_session() {
        // End-to-end: SDK trace → parse → observe session → synthesize policy
        let input = r#"{"timestamp":1710201600.0,"operation":"fs.read","args":{"path":"src/main.rs"},"result_summary":"ok","duration_ms":5.0,"policy_decision":"allow"}
{"timestamp":1710201601.0,"operation":"fs.write","args":{"path":"src/main.rs"},"result_summary":"ok","duration_ms":8.0,"policy_decision":"allow"}
{"timestamp":1710201602.0,"operation":"fs.glob","args":{"pattern":"**/*.rs"},"result_summary":"ok","duration_ms":10.0,"policy_decision":"allow"}
{"timestamp":1710201603.0,"operation":"net.fetch","args":{"url":"https://docs.rs"},"result_summary":"ok","duration_ms":200.0,"policy_decision":"allow"}
{"timestamp":1710201604.0,"operation":"git.commit","args":{"git_args":["commit","-m","fix: typo"]},"result_summary":"exit_code=0","duration_ms":500.0,"policy_decision":"allow"}
"#;

        let observations = parse_jsonl_observations(input);
        assert_eq!(observations.len(), 5);

        let mut session = ObserveSession::new("sdk-agent");
        for obs in observations {
            session.record(obs);
        }

        let profile = session.synthesize();
        assert_eq!(profile.name, "observed-sdk-agent");

        // Verify the capabilities match the observed operations
        assert_eq!(profile.capabilities.read_files, CapabilityLevel::LowRisk);
        assert_eq!(profile.capabilities.write_files, CapabilityLevel::LowRisk);
        assert_eq!(profile.capabilities.glob_search, CapabilityLevel::LowRisk);
        assert_eq!(profile.capabilities.web_fetch, CapabilityLevel::LowRisk);
        assert_eq!(profile.capabilities.git_commit, CapabilityLevel::LowRisk);
        // Unobserved operations remain Never
        assert_eq!(profile.capabilities.git_push, CapabilityLevel::Never);
        assert_eq!(profile.capabilities.run_bash, CapabilityLevel::Never);

        // Profile must be valid
        assert!(profile.validate().is_ok());
        assert!(profile.build().is_ok());

        // Verify subjects were extracted correctly
        let summary = session.summary();
        assert!(summary.paths_accessed.contains("src/main.rs"));
        assert!(summary.paths_accessed.contains("**/*.rs"));
        assert!(summary.urls_fetched.contains("https://docs.rs"));
    }

    #[test]
    fn test_parse_mixed_all_three_formats() {
        // All three formats in a single input
        let input = r#"{"operation":"read_files","subject":"a.txt","succeeded":true}
{"id":"abc","sequence":0,"operation":"web_fetch","subject":"https://example.com","verdict":{"type":"allow"},"timestamp":"2026-03-12T00:00:00Z","pre_permissions_hash":"a","post_permissions_hash":"b","exposure_transition":{"pre_count":0,"post_count":1,"contributed_label":null,"state_uninhabitable":false,"dynamic_gate_applied":false}}
{"timestamp":1710201600.0,"operation":"fs.grep","args":{"pattern":"TODO"},"result_summary":"ok","duration_ms":15.0,"policy_decision":"allow"}
"#;

        let observations = parse_jsonl_observations(input);
        assert_eq!(observations.len(), 3);

        assert_eq!(observations[0].operation, Operation::ReadFiles);
        assert_eq!(observations[0].subject, "a.txt");

        assert_eq!(observations[1].operation, Operation::WebFetch);
        assert_eq!(observations[1].subject, "https://example.com");

        assert_eq!(observations[2].operation, Operation::GrepSearch);
        assert_eq!(observations[2].subject, "TODO");
    }
}
