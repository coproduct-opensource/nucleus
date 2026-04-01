//! `nucleus-claude-hook --status` — rich, parseable session & config summary.
//!
//! Replaces the minimal status output with structured information about
//! active sessions, loaded configuration, and security posture.
//!
//! Two output modes:
//! - **Human** (default): coloured, formatted text on stderr.
//! - **JSON** (`--status --json`): machine-parseable JSON on stdout.

use serde::Serialize;
use std::path::Path;

use crate::session::{self, SessionState};

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

/// Full status payload — serializable to JSON.
#[derive(Debug, Serialize)]
pub(crate) struct NucleusStatus {
    /// Package version from Cargo.toml.
    pub version: String,
    /// Resolved profile name (env > config > default).
    pub profile: String,
    /// Active compartment (if set via env or config).
    pub compartment: Option<String>,
    /// Number of active sessions found on disk.
    pub active_sessions: usize,
    /// Per-session details.
    pub sessions: Vec<SessionSummary>,
    /// Number of tool manifests loaded from `.nucleus/manifests/`.
    pub manifests_loaded: usize,
    /// Whether `.nucleus/egress.toml` exists.
    pub egress_policy: bool,
    /// Number of admissibility rules in `.nucleus/policy.toml`.
    pub policy_rules: usize,
    /// Whether `.nucleus/managed.toml` exists (enterprise managed mode).
    pub enterprise_managed: bool,
    /// Whether `.nucleus/Compartmentfile` exists.
    pub compartmentfile: bool,
    /// Project `.nucleus/` directory path (if found).
    pub nucleus_dir: Option<String>,
}

/// Per-session status summary.
#[derive(Debug, Serialize)]
pub(crate) struct SessionSummary {
    /// Session identifier (filename stem).
    pub session_id: String,
    /// Profile used for this session.
    pub profile: String,
    /// Active compartment.
    pub compartment: Option<String>,
    /// Number of allowed operations.
    pub allowed_ops: usize,
    /// Number of denied operations (from receipt chain).
    pub denied_ops: usize,
    /// Receipt chain length.
    pub receipt_chain_length: usize,
    /// Whether the chain has any unsigned entries.
    pub receipt_chain_intact: bool,
    /// Taint status: "CLEAN" or "TAINTED".
    pub taint: String,
    /// Flow graph observations count.
    pub flow_observations: usize,
}

// ═══════════════════════════════════════════════════════════════════════════
// Collection
// ═══════════════════════════════════════════════════════════════════════════

/// Collect all status information.
pub(crate) fn collect_status() -> NucleusStatus {
    let cwd = std::env::current_dir().unwrap_or_default();
    let nucleus_dir = cwd.join(".nucleus");

    // Profile resolution (mirrors main.rs logic).
    let profile = resolve_profile_name();
    let compartment = std::env::var("NUCLEUS_COMPARTMENT").ok();

    // Discover sessions.
    let session_dir = session::session_dir();
    let sessions = collect_sessions(&session_dir);
    let active_sessions = sessions.len();

    // Manifest count.
    let registry = portcullis::manifest_registry::ManifestRegistry::load_from_dir(&cwd);
    let manifests_loaded = registry.admitted_count();

    // Egress policy.
    let egress_policy = nucleus_dir.join("egress.toml").exists();

    // Admissibility rules.
    let policy_rules = match portcullis::PolicyRuleSet::load_from_dir(&cwd) {
        Ok(Some(rules)) => rules.len(),
        _ => 0,
    };

    // Enterprise managed mode.
    let enterprise_managed = nucleus_dir.join("managed.toml").exists();

    // Compartmentfile.
    let compartmentfile = nucleus_dir.join("Compartmentfile").exists();

    let nucleus_dir_display = if nucleus_dir.exists() {
        Some(nucleus_dir.display().to_string())
    } else {
        None
    };

    NucleusStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        profile,
        compartment,
        active_sessions,
        sessions,
        manifests_loaded,
        egress_policy,
        policy_rules,
        enterprise_managed,
        compartmentfile,
        nucleus_dir: nucleus_dir_display,
    }
}

/// Resolve profile name: env > config > default.
fn resolve_profile_name() -> String {
    if let Ok(p) = std::env::var("NUCLEUS_PROFILE") {
        return p;
    }
    let config = crate::load_config_file();
    if let Some(p) = config.get("profile") {
        return p.clone();
    }
    "safe_pr_fixer".to_string()
}

/// Scan the session directory for active sessions and build summaries.
fn collect_sessions(session_dir: &Path) -> Vec<SessionSummary> {
    let mut summaries = Vec::new();

    let entries: Vec<_> = match std::fs::read_dir(session_dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
            .collect(),
        Err(_) => return summaries,
    };

    for entry in &entries {
        if let Ok(content) = std::fs::read_to_string(entry.path()) {
            if let Ok(state) = serde_json::from_str::<SessionState>(&content) {
                let session_id = entry
                    .path()
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();

                // Count receipts from the receipt chain file.
                let (receipt_chain_length, denied_ops, receipt_chain_intact) =
                    count_receipts(session_dir, &session_id);

                // Taint detection: check if any flow observation involves
                // web/fetch content (NodeKind::Source with fetch-like ops).
                let taint = detect_taint(&state);

                summaries.push(SessionSummary {
                    session_id,
                    profile: state.profile.clone(),
                    compartment: state.active_compartment.clone(),
                    allowed_ops: state.allowed_ops.len(),
                    denied_ops,
                    receipt_chain_length,
                    receipt_chain_intact,
                    taint,
                    flow_observations: state.flow_observations.len(),
                });
            }
        }
    }

    summaries
}

/// Count receipt entries and check chain integrity from the JSONL file.
fn count_receipts(session_dir: &Path, session_id: &str) -> (usize, usize, bool) {
    let receipts_dir = session_dir.join("receipts");
    let safe_id = session::sanitize_session_id(session_id);
    let path = receipts_dir.join(format!("{safe_id}.jsonl"));

    if !path.exists() {
        return (0, 0, true);
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return (0, 0, false),
    };

    let mut total = 0usize;
    let mut denied = 0usize;
    let mut all_signed = true;

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        total += 1;
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
            // Check verdict.
            if let Some(v) = entry["verdict"].as_str() {
                if v.contains("Deny") || v.contains("deny") {
                    denied += 1;
                }
            }
            // Check signature presence.
            if let Some(sig) = entry["signature"].as_str() {
                if sig.is_empty() {
                    all_signed = false;
                }
            } else {
                all_signed = false;
            }
        }
    }

    (total, denied, all_signed)
}

/// Detect taint: look for web-content flow observations.
///
/// NodeKind discriminants: 0=Source, 1=Action, 2=Sink.
/// Sources involving web content (WebFetch, curl, etc.) indicate taint.
fn detect_taint(state: &SessionState) -> String {
    for (kind, op, _subject) in &state.flow_observations {
        // NodeKind::Source = 0
        if *kind == 0 {
            let op_lower = op.to_lowercase();
            if op_lower.contains("fetch")
                || op_lower.contains("curl")
                || op_lower.contains("http")
                || op_lower.contains("web")
                || op_lower.contains("url")
            {
                return "TAINTED".to_string();
            }
        }
    }
    "CLEAN".to_string()
}

// ═══════════════════════════════════════════════════════════════════════════
// Output
// ═══════════════════════════════════════════════════════════════════════════

/// Entry point: collect status and print in the requested format.
pub(crate) fn run_status(json: bool) {
    let status = collect_status();

    if json {
        // Machine-parseable JSON on stdout.
        let out = serde_json::to_string_pretty(&status).unwrap_or_else(|e| {
            eprintln!("nucleus: failed to serialize status: {e}");
            crate::exit_codes::ExitCode::Error.exit();
        });
        println!("{out}");
    } else {
        // Human-readable on stderr.
        print_human(&status);
    }
}

/// Print coloured, human-readable status to stderr.
fn print_human(s: &NucleusStatus) {
    let bold = "\x1b[1m";
    let reset = "\x1b[0m";
    let green = "\x1b[32m";
    let red = "\x1b[31m";
    let yellow = "\x1b[33m";
    let dim = "\x1b[2m";

    eprintln!("{bold}nucleus-claude-hook{reset} v{}", s.version);
    eprintln!();

    // Configuration summary.
    eprintln!("{bold}Configuration:{reset}");
    eprintln!("  Profile:          {}", s.profile);
    if let Some(ref c) = s.compartment {
        eprintln!("  Compartment:      {c}");
    }
    if let Some(ref dir) = s.nucleus_dir {
        eprintln!("  .nucleus/ dir:    {dir}");
    } else {
        eprintln!("  .nucleus/ dir:    {yellow}not found{reset} (run --init to create)");
    }
    eprintln!("  Manifests:        {}", s.manifests_loaded);
    eprintln!(
        "  Egress policy:    {}",
        if s.egress_policy {
            format!("{green}active{reset}")
        } else {
            format!("{dim}none{reset}")
        }
    );
    eprintln!(
        "  Policy rules:     {}",
        if s.policy_rules > 0 {
            format!("{} rules", s.policy_rules)
        } else {
            format!("{dim}none{reset}")
        }
    );
    eprintln!(
        "  Enterprise:       {}",
        if s.enterprise_managed {
            format!("{yellow}managed{reset}")
        } else {
            format!("{dim}no{reset}")
        }
    );
    eprintln!(
        "  Compartmentfile:  {}",
        if s.compartmentfile {
            format!("{green}present{reset}")
        } else {
            format!("{dim}absent{reset}")
        }
    );

    // Sessions.
    eprintln!();
    if s.sessions.is_empty() {
        eprintln!("{bold}Sessions:{reset} {dim}none active{reset}");
    } else {
        eprintln!("{bold}Sessions:{reset} {} active", s.active_sessions);
        for sess in &s.sessions {
            eprintln!();
            eprintln!("  {bold}Session:{reset} {}", sess.session_id);
            eprintln!("    Profile:      {}", sess.profile);
            if let Some(ref c) = sess.compartment {
                eprintln!("    Compartment:  {c}");
            }

            // Taint status with colour.
            let taint_display = if sess.taint == "CLEAN" {
                format!("{green}CLEAN{reset}")
            } else {
                format!("{red}TAINTED{reset} (web content in flow graph)")
            };
            eprintln!("    Taint:        {taint_display}");

            eprintln!(
                "    Operations:   {} allowed, {} denied",
                sess.allowed_ops, sess.denied_ops
            );

            // Receipt chain with integrity indicator.
            let chain_display = if sess.receipt_chain_intact {
                format!(
                    "{} {dim}(chain intact, signed){reset}",
                    sess.receipt_chain_length
                )
            } else {
                format!(
                    "{} {red}(unsigned entries detected){reset}",
                    sess.receipt_chain_length
                )
            };
            eprintln!("    Receipts:     {chain_display}");
            eprintln!("    Flow nodes:   {}", sess.flow_observations);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state(flow_observations: Vec<(u8, String, String)>) -> SessionState {
        SessionState {
            schema_version: 1,
            profile: "safe_pr_fixer".into(),
            high_water_mark: 0,
            allowed_ops: vec![("Read".into(), "foo.rs".into())],
            flow_observations,
            chain_head_hash: [0u8; 32],
            signing_key_pkcs8: vec![],
            active_compartment: None,
            compartment_token: String::new(),
            parent_session_id: None,
            parent_chain_hash: None,
            last_pre_tool_obs_index: None,
            flagged_tools: Default::default(),
        }
    }

    #[test]
    fn detect_taint_clean() {
        let state = test_state(vec![(1, "Read".into(), "foo.rs".into())]);
        assert_eq!(detect_taint(&state), "CLEAN");
    }

    #[test]
    fn detect_taint_web_content() {
        let state = test_state(vec![(0, "WebFetch".into(), "https://example.com".into())]);
        assert_eq!(detect_taint(&state), "TAINTED");
    }

    #[test]
    fn status_serializes_to_json() {
        let status = NucleusStatus {
            version: "0.1.0".into(),
            profile: "safe_pr_fixer".into(),
            compartment: Some("draft".into()),
            active_sessions: 0,
            sessions: vec![],
            manifests_loaded: 3,
            egress_policy: true,
            policy_rules: 2,
            enterprise_managed: false,
            compartmentfile: true,
            nucleus_dir: Some("/tmp/test/.nucleus".into()),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"version\":\"0.1.0\""));
        assert!(json.contains("\"manifests_loaded\":3"));
        assert!(json.contains("\"egress_policy\":true"));
        assert!(json.contains("\"enterprise_managed\":false"));
    }

    #[test]
    fn session_summary_includes_taint() {
        let summary = SessionSummary {
            session_id: "test-123".into(),
            profile: "read_only".into(),
            compartment: None,
            allowed_ops: 5,
            denied_ops: 1,
            receipt_chain_length: 6,
            receipt_chain_intact: true,
            taint: "CLEAN".into(),
            flow_observations: 3,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"taint\":\"CLEAN\""));
        assert!(json.contains("\"receipt_chain_intact\":true"));
    }
}
