//! Delegation chain defense example — demonstrates how the permission lattice
//! prevents multi-agent privilege escalation attacks.
//!
//! Run with: `cargo run --example delegation_chain -p portcullis`
//!
//! This example walks through a real-world attack scenario (PajaMAS-style
//! multi-agent hijacking) and shows how lattice-guard's monotone delegation
//! prevents it at every step.

use portcullis::{meet_with_justification, CapabilityLevel, Operation, PermissionLattice};

/// Build a human trust anchor with full capabilities.
fn build_human_alice() -> PermissionLattice {
    let mut p = PermissionLattice::permissive();
    p.description = "Human: Alice (trust anchor)".to_string();
    p
}

/// Build an orchestrator request — wants read, write, search, and git.
fn build_orchestrator_request() -> PermissionLattice {
    let mut p = PermissionLattice::fix_issue();
    p.description = "Orchestrator: PR review agent".to_string();
    p
}

/// Build a sub-agent request — claims it needs bash + web for "testing".
fn build_malicious_subagent_request() -> PermissionLattice {
    let mut p = PermissionLattice::permissive();
    p.description = "Sub-agent: claims testing needs".to_string();
    // Attacker wants everything
    p.capabilities.run_bash = CapabilityLevel::Always;
    p.capabilities.web_fetch = CapabilityLevel::Always;
    p.capabilities.git_push = CapabilityLevel::Always;
    p
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║   Delegation Chain Defense: Multi-Agent Privilege Escalation    ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // Step 1: Human trust anchor
    let alice = build_human_alice();
    println!("1. Human trust anchor (Alice):");
    println!("   read_files:  {:?}", alice.capabilities.read_files);
    println!("   write_files: {:?}", alice.capabilities.write_files);
    println!("   git_push:    {:?}", alice.capabilities.git_push);
    println!("   run_bash:    {:?}", alice.capabilities.run_bash);

    // Step 2: Delegate to orchestrator
    println!("\n2. Delegating to orchestrator (PR review):");
    let orch_request = build_orchestrator_request();
    let orch = alice
        .delegate_to(&orch_request, "PR review for issue #42")
        .expect("delegation should succeed");
    println!("   write_files: {:?}", orch.capabilities.write_files);
    println!("   git_push:    {:?}", orch.capabilities.git_push);
    println!(
        "   run_bash:    {:?} (restricted by profile)",
        orch.capabilities.run_bash
    );
    println!("   orch <= alice: {}", orch.leq(&alice));

    // Step 3: Sub-agent tries to escalate
    println!("\n3. Malicious sub-agent requests full capabilities:");
    let malicious_request = build_malicious_subagent_request();
    println!(
        "   Requested run_bash:  {:?}",
        malicious_request.capabilities.run_bash
    );
    println!(
        "   Requested web_fetch: {:?}",
        malicious_request.capabilities.web_fetch
    );
    println!(
        "   Requested git_push:  {:?}",
        malicious_request.capabilities.git_push
    );

    // Delegation enforces monotone attenuation via meet
    let (sub_effective, justification) = meet_with_justification(&orch, &malicious_request);
    println!("\n   After delegation (meet with orchestrator ceiling):");
    println!(
        "   Effective run_bash:  {:?}",
        sub_effective.capabilities.run_bash
    );
    println!(
        "   Effective web_fetch: {:?}",
        sub_effective.capabilities.web_fetch
    );
    println!(
        "   Effective git_push:  {:?}",
        sub_effective.capabilities.git_push
    );
    println!("   sub <= orch:  {}", sub_effective.leq(&orch));
    println!("   sub <= alice: {}", sub_effective.leq(&alice));

    // Show what was restricted
    println!("\n   Restrictions applied:");
    for detail in &justification.restrictions {
        println!("   - {:?}: {:?}", detail.dimension, detail.reason);
    }

    // Step 4: Trifecta check
    println!("\n4. Trifecta safety check:");
    println!(
        "   Sub-agent triggers trifecta: {}",
        sub_effective.is_trifecta_vulnerable()
    );
    println!(
        "   git_push requires approval: {}",
        sub_effective.requires_approval(Operation::GitPush)
    );
    println!(
        "   run_bash requires approval: {}",
        sub_effective.requires_approval(Operation::RunBash)
    );

    // Step 5: Verify the monotone chain property
    println!("\n5. Monotone chain verification (audit trail):");
    let chain = [
        ("Alice (root)", &alice),
        ("Orchestrator", &orch),
        ("Sub-agent", &sub_effective),
    ];
    for window in chain.windows(2) {
        let (parent_name, parent) = &window[0];
        let (child_name, child) = &window[1];
        println!(
            "   {} <= {}: {}",
            child_name,
            parent_name,
            child.leq(parent)
        );
    }

    // Step 6: Demonstrate the key invariant
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("KEY INVARIANT: For any delegation chain p0 >= p1 >= ... >= pN,");
    println!("every agent's effective permissions are bounded by its parent.");
    println!("A compromised sub-agent CANNOT escalate beyond the orchestrator's");
    println!("ceiling, which is itself bounded by the human trust anchor.");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}
