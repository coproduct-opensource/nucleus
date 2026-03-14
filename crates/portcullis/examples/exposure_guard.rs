//!  UninhabitableState guard example — demonstrates how the uninhabitable_state
//! (private data + untrusted content + exfiltration) is detected and mitigated.
//!
//! Run with: `cargo run --example exposure_guard -p portcullis`
//!
//! The "uninhabitable_state" is:
//! 1. Access to private data (read_files, read credentials)
//! 2. Exposure to untrusted content (web_fetch, web_search)
//! 3. External communication (git_push, run_bash, create_pr)
//!
//! When all three are present, prompt injection attacks can exfiltrate
//! private data. The uninhabitable_state guard adds approval obligations to
//! exfiltration operations when the uninhabitable_state is complete.

use portcullis::{
    BoundedLattice, CapabilityLattice, CapabilityLevel, IncompatibilityConstraint, Operation,
    PermissionLattice, StateRisk,
};

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║          UninhabitableState Guard: Lethal Combination Detection            ║");
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
    let risk = constraint.state_risk(&safe);
    println!("   Capabilities: read_files, glob_search, grep_search");
    println!("   Risk: {:?}", risk);
    println!(
        "    UninhabitableState complete: {}\n",
        constraint.is_uninhabitable(&safe)
    );

    // Scenario 2: Partial — read + web (no exfil vector)
    println!("Scenario 2: Read + Web (PARTIAL — missing exfil)");
    let partial = CapabilityLattice {
        read_files: CapabilityLevel::Always,
        web_fetch: CapabilityLevel::LowRisk,
        web_search: CapabilityLevel::LowRisk,
        ..CapabilityLattice::bottom()
    };
    let risk = constraint.state_risk(&partial);
    println!("   Capabilities: read_files, web_fetch, web_search");
    println!("   Risk: {:?}", risk);
    println!(
        "    UninhabitableState complete: {}\n",
        constraint.is_uninhabitable(&partial)
    );

    // Scenario 3: Complete uninhabitable_state — read + web + bash
    println!("Scenario 3: Read + Web + Bash (COMPLETE uninhabitable_state)");
    let dangerous = CapabilityLattice {
        read_files: CapabilityLevel::Always,
        web_fetch: CapabilityLevel::LowRisk,
        run_bash: CapabilityLevel::LowRisk,
        ..CapabilityLattice::bottom()
    };
    let risk = constraint.state_risk(&dangerous);
    println!("   Capabilities: read_files, web_fetch, run_bash");
    println!("   Risk: {:?}", risk);
    println!(
        "    UninhabitableState complete: {}",
        constraint.is_uninhabitable(&dangerous)
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

    // Scenario 4: Automatic uninhabitable_state enforcement via PermissionLattice
    println!("\nScenario 4: Automatic enforcement via meet()");
    let perms = PermissionLattice {
        capabilities: dangerous.clone(),
        uninhabitable_constraint: true,
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
        let risk = constraint.state_risk(&profile.capabilities);
        let vulnerable = constraint.is_uninhabitable(&profile.capabilities);
        let risk_str = match risk {
            StateRisk::Safe => "None    ",
            StateRisk::Low => "Low     ",
            StateRisk::Medium => "Medium  ",
            StateRisk::Uninhabitable => "Complete",
        };
        println!(
            "   {:<14} risk={} uninhabitable_state={}",
            name, risk_str, vulnerable
        );
    }

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("The uninhabitable_state guard ensures that when an agent has access to private");
    println!("data AND untrusted content, any exfiltration path requires human");
    println!("approval — even if each capability was individually authorized.");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}
