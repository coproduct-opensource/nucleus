//! Text and JSON report rendering for scan results.

use crate::finding::{ScanReport, Severity};

pub fn print_scan_report(report: &ScanReport) {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║               NUCLEUS SECURITY SCAN REPORT                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // --- Overview ---
    if let Some(name) = &report.pod_name {
        println!("  Pod:            {}", name);
    }
    if let Some(profile) = &report.policy_profile {
        println!("  Policy:         {}", profile);
    }
    println!("  Trifecta risk:  {}", report.trifecta_risk);
    println!(
        "  Trifecta guard: {}",
        if report.trifecta_enforced {
            "ENFORCED"
        } else {
            "DISABLED"
        }
    );
    println!("  Network:        {}", report.network_posture);
    println!("  Isolation:      {}", report.isolation_level);
    println!(
        "  Credentials:    {}",
        if report.has_credentials {
            "present"
        } else {
            "none"
        }
    );
    println!();

    // --- Permission surface ---
    println!("── Permission Surface ──────────────────────────────────────────");
    if !report.permission_surface.always_allowed.is_empty() {
        println!(
            "  Always allowed:    {}",
            report.permission_surface.always_allowed.join(", ")
        );
    }
    if !report.permission_surface.low_risk.is_empty() {
        println!(
            "  Low-risk auto:     {}",
            report.permission_surface.low_risk.join(", ")
        );
    }
    if !report.permission_surface.never.is_empty() {
        println!(
            "  Never allowed:     {}",
            report.permission_surface.never.join(", ")
        );
    }
    if !report.permission_surface.approval_required.is_empty() {
        println!(
            "  Approval required: {}",
            report.permission_surface.approval_required.join(", ")
        );
    }
    println!();

    // --- Claude settings summary ---
    if let Some(cs) = &report.claude_settings_summary {
        println!("── Claude Code Settings ────────────────────────────────────────");
        println!("  Allow rules:       {}", cs.total_allow_rules);
        println!("  Deny rules:        {}", cs.total_deny_rules);
        println!("  Ask rules:         {}", cs.total_ask_rules);
        println!("  MCP servers:       {}", cs.mcp_server_count);
        if let Some(sandbox) = cs.sandbox_enabled {
            println!(
                "  Sandbox:           {}",
                if sandbox { "enabled" } else { "DISABLED" }
            );
        }
        if !cs.safety_bypasses.is_empty() {
            println!("  Safety bypasses:   {}", cs.safety_bypasses.join(", "));
        }
        println!();
    }

    // --- MCP config summary ---
    if let Some(mc) = &report.mcp_config_summary {
        println!("── MCP Configuration ──────────────────────────────────────────");
        println!("  Total servers:     {}", mc.server_count);
        println!("  Command servers:   {}", mc.command_servers);
        println!("  HTTP servers:      {}", mc.http_servers);
        println!("  With credentials:  {}", mc.servers_with_credentials);
        println!();
    }

    // --- Runtime metrics ---
    if let Some(metrics) = &report.runtime_metrics {
        println!("── Runtime Analysis ────────────────────────────────────────────");
        println!("  Audit entries:     {}", metrics.total_entries);
        println!(
            "  Chain integrity:   {}",
            if metrics.chain_valid {
                "VALID"
            } else {
                "BROKEN"
            }
        );
        println!("  Identities:        {}", metrics.identities);
        println!("  Deviations:        {}", metrics.deviations);
        println!("  Trifecta events:   {}", metrics.trifecta_completions);
        println!("  Blocked:           {}", metrics.blocks);
        println!();
    }

    // --- Findings ---
    let critical_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low_count = report
        .findings
        .iter()
        .filter(|f| f.severity <= Severity::Low)
        .count();

    println!(
        "── Findings ({} critical, {} high, {} medium, {} low) ──────────",
        critical_count, high_count, medium_count, low_count
    );
    println!();

    for finding in &report.findings {
        let marker = match finding.severity {
            Severity::Critical => "!!",
            Severity::High => "! ",
            Severity::Medium => "~ ",
            Severity::Low => "- ",
            Severity::Info => "  ",
        };
        println!("  {} [{}] {}", marker, finding.severity, finding.title);
        for line in textwrap(&finding.description, 58) {
            println!("       {}", line);
        }
        println!();
    }

    if report.findings.is_empty() {
        println!("  No findings. Configuration follows security best practices.");
        println!();
    }

    // --- Verdict ---
    let verdict = if critical_count > 0 {
        "FAIL — critical issues must be resolved"
    } else if high_count > 0 {
        "WARN — high-severity issues should be addressed"
    } else if medium_count > 0 {
        "PASS with advisories"
    } else {
        "PASS"
    };
    println!("══ Verdict: {} ══", verdict);
}

pub fn textwrap(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in s.split_whitespace() {
        if current.len() + word.len() + 1 > width && !current.is_empty() {
            lines.push(current.clone());
            current.clear();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}
