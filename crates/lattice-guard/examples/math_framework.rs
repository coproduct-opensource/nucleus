//! Mathematical framework examples demonstrating category-theoretic permission modeling.
//!
//! This example showcases the five mathematical extensions to lattice-guard:
//! 1. Frame/Nucleus - Type-safe quotient lattices
//! 2. Heyting Algebra - Conditional permissions via implication
//! 3. Galois Connections - Trust domain translation
//! 4. Modal Operators - Necessity vs possibility
//! 5. Graded Monad - Composable risk tracking

use lattice_guard::{
    frame::{BoundedLattice, Nucleus, SafePermissionLattice, TrifectaQuotient},
    galois::presets,
    graded::{evaluate_with_risk, Graded, RiskGrade},
    heyting::{entails, permission_gap, ConditionalPermission},
    modal::{all_capability_modals, ModalContext, ModalPermissions},
    CapabilityLattice, CapabilityLevel, Operation, PermissionLattice, TrifectaRisk,
};

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║     Mathematical Framework for AI Agent Permissions              ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    example_frame_and_nucleus();
    example_heyting_implication();
    example_galois_connections();
    example_modal_operators();
    example_graded_monad();
}

/// Example 1: Frame Theory and Nucleus Operators
fn example_frame_and_nucleus() {
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("1. FRAME THEORY AND NUCLEUS OPERATORS");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    println!("A nucleus j: L → L on a frame L satisfies:");
    println!("  • j(j(x)) = j(x)     (idempotent)");
    println!("  • j(x) ≤ x           (deflationary)");
    println!("  • j(x ∧ y) = j(x) ∧ j(y)  (preserves meets)\n");

    // Create the trifecta quotient nucleus
    let nucleus = TrifectaQuotient::new();

    // A dangerous permission set (has all three trifecta components)
    let dangerous = PermissionLattice::permissive();
    println!("Original permissions: {}", dangerous.description);
    println!("  - Has trifecta: {}", dangerous.is_trifecta_vulnerable());

    // Project through the nucleus
    let projected = nucleus.apply(&dangerous);
    println!("\nAfter nucleus projection:");
    println!(
        "  - Requires approval for GitPush: {}",
        projected.requires_approval(Operation::GitPush)
    );
    println!("  - Is fixed point: {}", nucleus.is_fixed_point(&projected));

    // Create a SafePermissionLattice (compile-time guarantee)
    let safe = SafePermissionLattice::from_nucleus(&nucleus, dangerous);
    println!("\nSafePermissionLattice created (type-level safety guarantee)");
    println!(
        "  - Inner lattice is trifecta-safe: {}",
        nucleus.is_fixed_point(safe.inner())
    );

    // Demonstrate idempotence (compare capabilities, not UUIDs)
    let twice = nucleus.apply(&nucleus.apply(&PermissionLattice::default()));
    let once = nucleus.apply(&PermissionLattice::default());
    println!(
        "\nIdempotence verified: j(j(x)) = j(x): {}",
        once.capabilities == twice.capabilities && once.obligations == twice.obligations
    );

    println!();
}

/// Example 2: Heyting Algebra and Intuitionistic Implication
fn example_heyting_implication() {
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("2. HEYTING ALGEBRA (INTUITIONISTIC IMPLICATION)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    println!("The Heyting adjunction: (c ∧ a) ≤ b  ⟺  c ≤ (a → b)\n");

    // Define capability sets
    let read_only = CapabilityLattice {
        read_files: CapabilityLevel::Always,
        glob_search: CapabilityLevel::Always,
        grep_search: CapabilityLevel::Always,
        ..CapabilityLattice::bottom()
    };

    let with_web = CapabilityLattice {
        read_files: CapabilityLevel::Always,
        glob_search: CapabilityLevel::Always,
        grep_search: CapabilityLevel::Always,
        web_search: CapabilityLevel::LowRisk,
        web_fetch: CapabilityLevel::LowRisk,
        ..CapabilityLattice::bottom()
    };

    // Check entailment
    println!("Entailment (a → b = ⊤ means a ≤ b):");
    println!(
        "  - read_only entails with_web: {}",
        entails(&read_only, &with_web)
    );
    println!(
        "  - with_web entails read_only: {}",
        entails(&with_web, &read_only)
    );
    println!(
        "  - bottom entails anything: {}",
        entails(&CapabilityLattice::bottom(), &with_web)
    );

    // Compute the permission gap
    println!("\nPermission gap (what's needed to go from current to target):");
    let gap = permission_gap(&read_only, &with_web);
    println!("  - Gap for web_search: {:?}", gap.web_search);
    println!("  - Gap for web_fetch: {:?}", gap.web_fetch);
    println!(
        "  - Gap for read_files: {:?} (already satisfied)",
        gap.read_files
    );

    // Conditional permission rules
    println!("\nConditional permissions (if-then rules):");
    let rule = ConditionalPermission::new(
        CapabilityLattice {
            read_files: CapabilityLevel::LowRisk,
            ..CapabilityLattice::bottom()
        },
        CapabilityLattice {
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            ..CapabilityLattice::bottom()
        },
        "Read access implies search access",
    );
    println!("  Rule: {}", rule.description);
    println!(
        "  Applies to read_only: {}",
        rule.apply(&read_only).is_some()
    );
    println!(
        "  Does NOT apply to bottom (condition not met): {}",
        rule.apply(&CapabilityLattice::bottom()).is_none()
    );

    println!();
}

/// Example 3: Galois Connections for Trust Domain Translation
fn example_galois_connections() {
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("3. GALOIS CONNECTIONS (TRUST DOMAIN TRANSLATION)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    println!("A Galois connection (α, γ) satisfies: α(l) ≤ r  ⟺  l ≤ γ(r)\n");

    // Create bridges for different trust domains
    let internal_external =
        presets::internal_external("spiffe://internal.corp", "spiffe://partner.org");

    let human_agent =
        presets::human_agent("spiffe://corp/human/alice", "spiffe://corp/agent/coder-001");

    // Internal to external translation
    println!("Internal → External domain translation:");
    let internal_perms = PermissionLattice::permissive();
    let external_perms = internal_external.to_target(&internal_perms);
    println!("  Internal: full capabilities");
    println!(
        "  External: read_files={:?}, web_fetch={:?}",
        external_perms.capabilities.read_files, external_perms.capabilities.web_fetch
    );

    // Human to agent delegation
    println!("\nHuman → Agent delegation:");
    let human_perms = PermissionLattice::permissive();
    let agent_perms = human_agent.to_target(&human_perms);
    println!("  Human capabilities: full");
    println!("  Agent capabilities: restricted to defaults");
    println!("  Agent ≤ Human: {}", agent_perms.leq(&human_perms));

    // Round-trip (closure operator)
    println!("\nRound-trip (γ ∘ α) shows information loss:");
    let round_trip = internal_external.round_trip(&internal_perms);
    println!(
        "  Original read_files: {:?}",
        internal_perms.capabilities.read_files
    );
    println!(
        "  After round-trip: {:?}",
        round_trip.capabilities.read_files
    );
    println!(
        "  Information preserved: {}",
        round_trip.capabilities.leq(&internal_perms.capabilities)
    );

    println!();
}

/// Example 4: Modal Operators (Necessity and Possibility)
fn example_modal_operators() {
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("4. MODAL OPERATORS (NECESSITY □ AND POSSIBILITY ◇)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    println!("Modal logic distinguishes:");
    println!("  □A (necessity): what is GUARANTEED (no approval needed)");
    println!("  ◇A (possibility): what is ACHIEVABLE (with escalation)\n");

    // Use fix_issue which has trifecta obligations
    let perms = PermissionLattice::fix_issue();
    println!("Permission profile: {}", perms.description);

    // Compute necessity (what's guaranteed without approval)
    let necessary = perms.necessity();
    println!("\nNecessity (□) - what's guaranteed:");
    println!("  - git_push: {:?}", necessary.capabilities.git_push);
    println!("  - read_files: {:?}", necessary.capabilities.read_files);

    // Compute possibility (what's achievable with escalation)
    let ceiling = PermissionLattice::permissive();
    let possible = perms.possibility(&ceiling);
    println!("\nPossibility (◇) - what's achievable:");
    println!("  - git_push: {:?}", possible.capabilities.git_push);
    println!(
        "  - All capabilities: {:?}",
        possible.capabilities == ceiling.capabilities
    );

    // Modal context for comprehensive analysis
    let context = ModalContext::new(perms.clone());
    println!("\nModal Context Analysis:");
    println!("  - Requires escalation: {}", context.requires_escalation());
    println!(
        "  - Operations needing approval: {:?}",
        context.escalation_required_for()
    );
    println!("  - Is tight (no gap): {}", context.is_tight());

    // Per-capability modal analysis
    println!("\nPer-capability modal breakdown:");
    let modals = all_capability_modals(&perms);
    for modal in modals.iter().filter(|m| m.requires_approval) {
        println!(
            "  - {:?}: level={:?}, needs_approval={}",
            modal.operation, modal.level, modal.requires_approval
        );
    }

    println!();
}

/// Example 5: Graded Monad for Risk Tracking
fn example_graded_monad() {
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("5. GRADED MONAD (COMPOSABLE RISK TRACKING)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    println!("A graded monad M indexed by monoid (G, *, 1):");
    println!("  pure: A -> M_1(A)                    (no risk)");
    println!("  bind: M_g(A) -> (A -> M_h(B)) -> M_{{g*h}}(B)  (risk composes)\n");

    // Pure computation (no risk)
    let safe: Graded<TrifectaRisk, i32> = Graded::pure(42);
    println!("Pure computation:");
    println!("  - Value: {}", safe.value);
    println!("  - Risk: {:?}", safe.grade);

    // Chain computations, accumulating risk
    println!("\nChained computation (risk accumulates via max):");
    let result = safe
        .and_then(|x| {
            println!("  Step 1: multiply by 2 (Low risk)");
            Graded::new(TrifectaRisk::Low, x * 2)
        })
        .and_then(|x| {
            println!("  Step 2: add 10 (Medium risk)");
            Graded::new(TrifectaRisk::Medium, x + 10)
        })
        .and_then(|x| {
            println!("  Step 3: divide by 2 (Low risk)");
            Graded::new(TrifectaRisk::Low, x / 2)
        });

    println!("\nFinal result:");
    println!("  - Value: {}", result.value);
    println!("  - Accumulated risk: {:?}", result.grade);
    println!(
        "  - Requires intervention: {}",
        result.requires_intervention()
    );

    // Evaluate permission with risk grading
    println!("\nEvaluating permission profiles with risk:");
    for profile in [
        PermissionLattice::read_only(),
        PermissionLattice::codegen(),
        PermissionLattice::fix_issue(),
        PermissionLattice::permissive(),
    ] {
        let graded = evaluate_with_risk(&profile, |p| p.description.clone());
        println!("  - {}: {:?}", graded.value, graded.grade);
    }

    // Demonstrate monoid laws
    println!("\nRisk grade monoid laws:");
    let a = TrifectaRisk::Low;
    let b = TrifectaRisk::Medium;
    println!(
        "  - identity * a = a: {}",
        TrifectaRisk::identity().compose(&a) == a
    );
    println!(
        "  - a * identity = a: {}",
        a.compose(&TrifectaRisk::identity()) == a
    );
    println!("  - Low.compose(Medium) = {:?}", a.compose(&b));

    println!();
    println!("═══════════════════════════════════════════════════════════════════════");
    println!("                    Framework demonstration complete                    ");
    println!("═══════════════════════════════════════════════════════════════════════");
}
