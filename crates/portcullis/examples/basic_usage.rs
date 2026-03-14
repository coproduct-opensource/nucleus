//! Basic usage example demonstrating uninhabitable_state prevention.

use portcullis::{
    CapabilityLattice, CapabilityLevel, IncompatibilityConstraint, Operation, PermissionLattice,
};

fn main() {
    println!("=== Lattice Guard Basic Usage ===\n");

    // Demonstrate the uninhabitable_state detection
    println!("1. Creating a dangerous capability set with all three uninhabitable_state elements:");
    let dangerous = CapabilityLattice {
        read_files: CapabilityLevel::Always, // Private data access
        web_fetch: CapabilityLevel::LowRisk, // Untrusted content exposure
        git_push: CapabilityLevel::LowRisk,  // Exfiltration vector
        ..Default::default()
    };
    println!("   - read_files: Always (private data access)");
    println!("   - web_fetch: LowRisk (untrusted content)");
    println!("   - git_push: LowRisk (exfiltration vector)");

    // Check if uninhabitable_state is complete
    let constraint = IncompatibilityConstraint::enforcing();
    let is_dangerous = constraint.is_uninhabitable(&dangerous);
    println!("\n    UninhabitableState complete: {}", is_dangerous);

    // Compute obligations
    println!("\n2. Computing uninhabitable_state obligations:");
    let obligations = constraint.obligations_for(&dangerous);
    println!(
        "   - approval required for git_push: {}",
        obligations.requires(Operation::GitPush)
    );
    println!(
        "   - approval required for run_bash: {}",
        obligations.requires(Operation::RunBash)
    );

    // Using the full permission lattice
    println!("\n3. Using PermissionLattice with automatic uninhabitable_state enforcement:");
    let perms = PermissionLattice {
        capabilities: dangerous.clone(),
        obligations: Default::default(),
        uninhabitable_constraint: true,
        ..Default::default()
    };

    // Meet operation automatically applies constraint
    let combined = perms.meet(&perms);
    println!("   After meet operation:");
    println!(
        "   - git_push requires approval: {}",
        combined.requires_approval(Operation::GitPush)
    );
    println!(
        "   - create_pr requires approval: {}",
        combined.requires_approval(Operation::CreatePr)
    );

    // Preset configurations
    println!("\n4. Preset configurations:");
    let readonly = PermissionLattice::read_only();
    println!(
        "   read_only - can write files: {:?}",
        readonly.capabilities.write_files
    );

    let fix = PermissionLattice::fix_issue();
    println!(
        "   fix_issue - can git push: {:?}",
        fix.capabilities.git_push
    );

    let review = PermissionLattice::code_review();
    println!(
        "   code_review - can web search: {:?}",
        review.capabilities.web_search
    );

    // Delegation
    println!("\n5. Safe delegation:");
    let parent = PermissionLattice::permissive();
    let requested = PermissionLattice::fix_issue();

    match parent.delegate_to(&requested, "fix bug #123") {
        Ok(child) => {
            println!("   Delegation successful!");
            println!("   Child ≤ Parent: {}", child.leq(&parent));
        }
        Err(e) => {
            println!("   Delegation failed: {}", e);
        }
    }

    println!("\n=== Done ===");
}
