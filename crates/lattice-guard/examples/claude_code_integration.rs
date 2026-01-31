//! Example showing how to integrate with Claude Code CLI.
//!
//! This example demonstrates converting a PermissionLattice to
//! Claude Code CLI flags for the `--allowedTools` argument.

use lattice_guard::{CapabilityLevel, PermissionLattice};

/// Convert a PermissionLattice to Claude Code CLI `--allowedTools` flags.
fn build_allowed_tools(perms: &PermissionLattice) -> Vec<String> {
    let mut tools = Vec::new();
    let caps = &perms.capabilities;

    // File operations
    if caps.read_files >= CapabilityLevel::LowRisk {
        tools.push("Read".to_string());
    }
    if caps.write_files >= CapabilityLevel::LowRisk {
        tools.push("Write".to_string());
    }
    if caps.edit_files >= CapabilityLevel::LowRisk {
        tools.push("Edit".to_string());
    }

    // Search operations
    if caps.glob_search >= CapabilityLevel::LowRisk {
        tools.push("Glob".to_string());
    }
    if caps.grep_search >= CapabilityLevel::LowRisk {
        tools.push("Grep".to_string());
    }

    // Web operations
    if caps.web_search >= CapabilityLevel::LowRisk {
        tools.push("WebSearch".to_string());
    }
    if caps.web_fetch >= CapabilityLevel::LowRisk {
        tools.push("WebFetch".to_string());
    }

    // Bash (only if explicitly allowed)
    if caps.run_bash >= CapabilityLevel::LowRisk {
        tools.push("Bash".to_string());
    }

    tools
}

/// Get the permission mode for Claude Code CLI.
fn get_permission_mode(perms: &PermissionLattice) -> &'static str {
    let caps = &perms.capabilities;

    // If any capability requires asking first, use plan mode
    let needs_ask = [
        caps.write_files,
        caps.edit_files,
        caps.run_bash,
        caps.git_commit,
        caps.git_push,
        caps.create_pr,
    ]
    .iter()
    .any(|&level| level == CapabilityLevel::AskFirst);

    if needs_ask {
        "plan"
    } else if caps.write_files >= CapabilityLevel::LowRisk {
        "bypassPermissions"
    } else {
        "default"
    }
}

fn main() {
    println!("=== Claude Code CLI Integration Example ===\n");

    // Example 1: Code review (read-only)
    println!("1. Code Review Task:");
    let review_perms = PermissionLattice::code_review();
    let tools = build_allowed_tools(&review_perms);
    let mode = get_permission_mode(&review_perms);

    println!("   Allowed tools: {:?}", tools);
    println!("   Permission mode: {}", mode);
    println!(
        "   CLI: claude --allowedTools {} --permission-mode {}",
        tools.join(","),
        mode
    );

    // Example 2: Fix issue (write access)
    println!("\n2. Fix Issue Task:");
    let fix_perms = PermissionLattice::fix_issue();
    let tools = build_allowed_tools(&fix_perms);
    let mode = get_permission_mode(&fix_perms);

    println!("   Allowed tools: {:?}", tools);
    println!("   Permission mode: {}", mode);
    println!(
        "   CLI: claude --allowedTools {} --permission-mode {} --max-cost-usd {:.2}",
        tools.join(","),
        mode,
        fix_perms.budget.max_cost_usd
    );

    // Example 3: Dangerous config (trifecta blocked)
    println!("\n3. Dangerous Config (auto-corrected):");
    let mut dangerous = PermissionLattice::permissive();
    dangerous.capabilities.web_fetch = CapabilityLevel::LowRisk;
    dangerous.capabilities.git_push = CapabilityLevel::LowRisk;

    // Meet enforces trifecta constraint
    let safe = dangerous.meet(&dangerous);

    println!(
        "   Requested git_push: {:?}",
        dangerous.capabilities.git_push
    );
    println!("   Effective git_push: {:?}", safe.capabilities.git_push);
    println!("   Trifecta prevented: exfiltration demoted to AskFirst");

    let tools = build_allowed_tools(&safe);
    let mode = get_permission_mode(&safe);
    println!(
        "   CLI: claude --allowedTools {} --permission-mode {}",
        tools.join(","),
        mode
    );

    // Example 4: Budget enforcement
    println!("\n4. Budget Enforcement:");
    let perms = PermissionLattice::fix_issue();
    println!("   Max cost: ${:.2}", perms.budget.max_cost_usd);
    println!("   Max input tokens: {}", perms.budget.max_input_tokens);
    println!("   Max output tokens: {}", perms.budget.max_output_tokens);

    // Simulate charging
    let mut budget = perms.budget.clone();
    let charge_ok = budget.charge_f64(0.50);
    println!("\n   Charged $0.50: {}", if charge_ok { "OK" } else { "DENIED" });
    println!("   Remaining: ${:.2}", budget.remaining_usd());

    println!("\n=== Done ===");
}
