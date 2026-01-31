//! Basic usage example demonstrating trifecta prevention.

use lattice_guard::{
    CapabilityLattice, CapabilityLevel, IncompatibilityConstraint, PermissionLattice,
};

fn main() {
    println!("=== Lattice Guard Basic Usage ===\n");

    // Demonstrate the lethal trifecta detection
    println!("1. Creating a dangerous capability set with all three trifecta elements:");
    let dangerous = CapabilityLattice {
        read_files: CapabilityLevel::Always,   // Private data access
        web_fetch: CapabilityLevel::LowRisk,   // Untrusted content exposure
        git_push: CapabilityLevel::LowRisk,    // Exfiltration vector
        ..Default::default()
    };
    println!("   - read_files: Always (private data access)");
    println!("   - web_fetch: LowRisk (untrusted content)");
    println!("   - git_push: LowRisk (exfiltration vector)");

    // Check if trifecta is complete
    let constraint = IncompatibilityConstraint::enforcing();
    let is_dangerous = constraint.is_trifecta_complete(&dangerous);
    println!("\n   Trifecta complete: {}", is_dangerous);

    // Apply the constraint
    println!("\n2. Applying trifecta constraint:");
    let safe = constraint.apply(&dangerous);
    println!("   - read_files: {:?} (unchanged)", safe.read_files);
    println!("   - web_fetch: {:?} (unchanged)", safe.web_fetch);
    println!("   - git_push: {:?} (demoted!)", safe.git_push);

    // Now trifecta is broken
    let still_dangerous = constraint.is_trifecta_complete(&safe);
    println!("\n   Trifecta still complete: {}", still_dangerous);

    // Using the full permission lattice
    println!("\n3. Using PermissionLattice with automatic trifecta enforcement:");
    let perms = PermissionLattice {
        capabilities: dangerous.clone(),
        trifecta_constraint: true,
        ..Default::default()
    };

    // Meet operation automatically applies constraint
    let combined = perms.meet(&perms);
    println!("   After meet operation:");
    println!("   - git_push: {:?}", combined.capabilities.git_push);
    println!("   - create_pr: {:?}", combined.capabilities.create_pr);

    // Preset configurations
    println!("\n4. Preset configurations:");
    let readonly = PermissionLattice::read_only();
    println!("   read_only - can write files: {:?}", readonly.capabilities.write_files);

    let fix = PermissionLattice::fix_issue();
    println!("   fix_issue - can git push: {:?}", fix.capabilities.git_push);

    let review = PermissionLattice::code_review();
    println!("   code_review - can web search: {:?}", review.capabilities.web_search);

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
