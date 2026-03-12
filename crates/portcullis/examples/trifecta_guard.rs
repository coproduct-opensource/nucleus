//! Trifecta guard example — demonstrates how the lethal trifecta
//! (private data + untrusted content + exfiltration) is detected and mitigated.
//!
//! Run with: `cargo run --example trifecta_guard -p portcullis`
//!
//! The "lethal trifecta" is:
//! 1. Access to private data (read_files, read credentials)
//! 2. Exposure to untrusted content (web_fetch, web_search)
//! 3. External communication (git_push, run_bash, create_pr)
//!
//! When all three are present, prompt injection attacks can exfiltrate
//! private data. The trifecta guard adds approval obligations to
//! exfiltration operations when the trifecta is complete.

use portcullis::{
    BoundedLattice, CapabilityLattice, CapabilityLevel, IncompatibilityConstraint, Operation,
    PermissionLattice, TrifectaRisk,
};

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║         Trifecta Guard: Lethal Combination Detection            ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    let constraint = IncompatibilityConstraint::enforcing();

    // Scenario 1: Safe — read + search (no untrusted content, no exfil)
    println!("Scenario 1: Read + Search (SAFE)");
    let safe = CapabilityLattice {
        read_files: CapabilityLevel::Always,
        glob_search: CapabilityLevel::Always,
        grep_search: CapabilityLevel::Always,
        ..CapabilityLattice::bottom()
    };
    let risk = constraint.trifecta_risk(&safe);
    println!("   Capabilities: read_files, glob_search, grep_search");
    println!("   Risk: {:?}", risk);
    println!(
        "   Trifecta complete: {}\n",
        constraint.is_trifecta_complete(&safe)
    );

    // Scenario 2: Partial — read + web (no exfil vector)
    println!("Scenario 2: Read + Web (PARTIAL — missing exfil)");
    let partial = CapabilityLattice {
        read_files: CapabilityLevel::Always,
        web_fetch: CapabilityLevel::LowRisk,
        web_search: CapabilityLevel::LowRisk,
        ..CapabilityLattice::bottom()
    };
    let risk = constraint.trifecta_risk(&partial);
    println!("   Capabilities: read_files, web_fetch, web_search");
    println!("   Risk: {:?}", risk);
    println!(
        "   Trifecta complete: {}\n",
        constraint.is_trifecta_complete(&partial)
    );

    // Scenario 3: Complete trifecta — read + web + bash
    println!("Scenario 3: Read + Web + Bash (COMPLETE TRIFECTA)");
    let dangerous = CapabilityLattice {
        read_files: CapabilityLevel::Always,
        web_fetch: CapabilityLevel::LowRisk,
        run_bash: CapabilityLevel::LowRisk,
        ..CapabilityLattice::bottom()
    };
    let risk = constraint.trifecta_risk(&dangerous);
    println!("   Capabilities: read_files, web_fetch, run_bash");
    println!("   Risk: {:?}", risk);
    println!(
        "   Trifecta complete: {}",
        constraint.is_trifecta_complete(&dangerous)
    );

    // Show obligations
    let obligations = constraint.obligations_for(&dangerous);
    println!("   Obligations added:");
    for op in [
        Operation::RunBash,
        Operation::GitPush,
        Operation::CreatePr,
        Operation::WebFetch,
    ] {
        if obligations.requires(op) {
            println!("   - {:?} now requires approval", op);
        }
    }

    // Scenario 4: Automatic trifecta enforcement via PermissionLattice
    println!("\nScenario 4: Automatic enforcement via meet()");
    let perms = PermissionLattice {
        capabilities: dangerous.clone(),
        trifecta_constraint: true,
        ..Default::default()
    };
    let enforced = perms.meet(&perms);
    println!(
        "   Before meet: git_push requires approval = {}",
        perms.requires_approval(Operation::GitPush)
    );
    println!(
        "   After meet:  git_push requires approval = {}",
        enforced.requires_approval(Operation::GitPush)
    );

    // Scenario 5: Risk grades across profiles
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Risk grades across built-in profiles:\n");
    let profiles = [
        ("read_only", PermissionLattice::read_only()),
        ("code_review", PermissionLattice::code_review()),
        ("codegen", PermissionLattice::codegen()),
        ("fix_issue", PermissionLattice::fix_issue()),
        ("permissive", PermissionLattice::permissive()),
    ];

    for (name, profile) in &profiles {
        let risk = constraint.trifecta_risk(&profile.capabilities);
        let vulnerable = constraint.is_trifecta_complete(&profile.capabilities);
        let risk_str = match risk {
            TrifectaRisk::None => "None    ",
            TrifectaRisk::Low => "Low     ",
            TrifectaRisk::Medium => "Medium  ",
            TrifectaRisk::Complete => "Complete",
        };
        println!("   {:<14} risk={} trifecta={}", name, risk_str, vulnerable);
    }

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("The trifecta guard ensures that when an agent has access to private");
    println!("data AND untrusted content, any exfiltration path requires human");
    println!("approval — even if each capability was individually authorized.");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}
