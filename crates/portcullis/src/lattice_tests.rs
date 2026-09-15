//! Tests for `lattice.rs`, in their own file so the lattice module stays
//! under the line ratchet's sweep ceiling. The module is 30 lines under it
//! on main, so a new method plus the tests that defend it does not fit —
//! the same remedy `certificate_tests.rs` already uses in this crate.

// ── The laws PermissionLattice actually satisfies ─────────────────
//
// `verify_lattice_laws` is all-or-nothing, and this type does not pass it:
// absorption fails, for a reason worth naming rather than papering over.
// These pin the four laws that DO hold, so the equality fix below cannot
// regress silently, and `absorption_fails_because_meet_applies_a_closure`
// records the one that does not.

fn law_samples() -> Vec<PermissionLattice> {
    vec![
        PermissionLattice::permissive(),
        PermissionLattice::restrictive(),
        PermissionLattice::default(),
    ]
}

#[test]
fn meet_and_join_are_idempotent() {
    for a in law_samples() {
        assert_eq!(a.meet(&a), a, "a ∧ a = a");
        assert_eq!(a.join(&a), a, "a ∨ a = a");
    }
}

#[test]
fn meet_and_join_are_commutative() {
    for a in law_samples() {
        for b in law_samples() {
            assert_eq!(a.meet(&b), b.meet(&a), "a ∧ b = b ∧ a");
            assert_eq!(a.join(&b), b.join(&a), "a ∨ b = b ∨ a");
        }
    }
}

#[test]
fn meet_and_join_are_associative() {
    for a in law_samples() {
        for b in law_samples() {
            for c in law_samples() {
                assert_eq!(a.meet(&b.meet(&c)), a.meet(&b).meet(&c));
                assert_eq!(a.join(&b.join(&c)), a.join(&b).join(&c));
            }
        }
    }
}

#[test]
fn leq_agrees_with_meet() {
    // `a ≤ b ⟺ a ∧ b = a`. This was FALSE for every pair before the
    // equality fix, because `meet` mints a fresh `id` so `a.meet(&b) == a`
    // could never hold.
    for a in law_samples() {
        for b in law_samples() {
            assert_eq!(
                a.leq(&b),
                a.meet(&b) == a,
                "leq and meet must agree on {} ≤ {}",
                a.description,
                b.description
            );
        }
    }
}

#[test]
fn every_policy_field_reaches_the_digest() {
    // The mutation-killing test. `cargo mutants` replaced `digest_parts`
    // with constants and every one survived, because the variant it mutated
    // was `cfg`-ed out under `--all-features`. With one function there is
    // nowhere to hide — but a constant projection would still satisfy
    // `checksum_agrees_with_equality`, which only compares digests to each
    // other. This pins the stronger property: perturbing ANY of the eight
    // fields moves the digest, so a field cannot silently drop out of it.
    //
    // That silent drop is #747's defect class, and the one this checksum was
    // rewritten to avoid.
    let base = PermissionLattice::restrictive();
    let d = base.checksum();

    let mut caps = base.clone();
    caps.capabilities = PermissionLattice::permissive().capabilities;
    assert_ne!(caps.checksum(), d, "capabilities");

    let mut obl = base.clone();
    obl.obligations = PermissionLattice::permissive().obligations;
    assert_ne!(obl.checksum(), d, "obligations");

    // A distinct value, not `permissive()`'s — the two constructors share
    // their `paths`, so borrowing one perturbs nothing and the assertion
    // would pass for the wrong reason. This test caught that on its first
    // run, which is the argument for writing it field by field.
    let mut paths = base.clone();
    paths.paths.allowed.insert("src/only-here/**".to_string());
    assert_ne!(paths.checksum(), d, "paths");

    let mut budget = base.clone();
    budget.budget = PermissionLattice::permissive().budget;
    assert_ne!(budget.checksum(), d, "budget");

    let mut commands = base.clone();
    // Both constructors have the same command policy. Random HashSet wire
    // order used to make their checksums differ and hide this inert probe.
    commands
        .commands
        .blocked
        .insert("newly-blocked-command".into());
    assert_ne!(commands.commands, base.commands);
    assert_ne!(commands.checksum(), d, "commands");

    let mut time = base.clone();
    time.time = PermissionLattice::permissive().time;
    assert_ne!(time.checksum(), d, "time");

    let mut iso = base.clone();
    iso.minimum_isolation = Some(IsolationLattice::localhost());
    assert_ne!(iso.checksum(), d, "minimum_isolation");

    // `uninhabitable_constraint` is private; `normalize` is the supported
    // way it differs, and a normalized policy must not hash as its input
    // when normalization changed it.
    let normalized = base.clone().normalize();
    if normalized != base {
        assert_ne!(normalized.checksum(), d, "uninhabitable/normalize");
    }
}

#[test]
fn checksum_agrees_with_equality() {
    // The `Hash`/`Eq` coherence law, which the old checksum broke: it
    // serialized the whole struct, so a `meet` producing the same policy
    // under a new label produced a different digest and the audit chain
    // recorded `pre_permissions_hash != post_permissions_hash` — a
    // permission change that had not happened.
    let a = PermissionLattice::restrictive();
    let mut b = a.clone();
    b.id = Uuid::new_v4();
    b.description = "a different label".to_string();
    b.derived_from = Some(Uuid::new_v4());
    assert_eq!(a, b, "same policy");
    assert_eq!(a.checksum(), b.checksum(), "so the same checksum");

    // …and it still separates policies that differ.
    let c = PermissionLattice::permissive();
    assert_ne!(a, c);
    assert_ne!(a.checksum(), c.checksum());
}

#[test]
fn the_seal_asks_a_different_question_from_the_checksum() {
    // Relabelling does not change what is permitted, so the checksum holds;
    // it DOES change the sealed value, so integrity fails. Two questions,
    // two digests — collapsing them is what made the checksum incoherent
    // with equality in the first place.
    let sealed = EffectivePermissions::new(PermissionLattice::restrictive());
    assert!(sealed.verify_integrity());

    let mut tampered = sealed.clone();
    tampered.lattice.description = "tampered".to_string();
    assert_eq!(
        tampered.lattice.checksum(),
        sealed.lattice.checksum(),
        "relabelling permits nothing new"
    );
    assert!(
        !tampered.verify_integrity(),
        "but the seal covers the label a reviewer reads"
    );
}

#[test]
fn equality_is_over_what_is_permitted_not_over_provenance() {
    let a = PermissionLattice::restrictive();
    let mut b = a.clone();
    b.id = Uuid::new_v4();
    b.description = "a different label".to_string();
    b.derived_from = Some(Uuid::new_v4());
    assert_eq!(a, b, "provenance is an audit handle, not identity");
}

#[test]
fn absorption_fails_because_meet_applies_a_closure() {
    // `a ∧ (a ∨ b) = a` is the law a closure operator breaks, and `meet`
    // applies one: `IncompatibilityConstraint::enforcing()` adds approval
    // obligations for the capabilities the meet produces. So the composite
    // is `j(a ∧ b)` for a closure `j`, which is a NUCLEUS on a lattice and
    // not a lattice meet.
    //
    // Recorded rather than fixed: the obligations it adds are the
    // uninhabitable-state constraint doing its job, so "make absorption
    // hold" would mean weakening it. The type nonetheless implements
    // `Lattice`, `BoundedLattice` and `DistributiveLattice`, three traits
    // whose laws it does not satisfy — and this repo already has the right
    // vocabulary for what it IS: `frame::Nucleus`, and the
    // `ConstraintNucleus` that `scripts/law-mechanisms-manifest.txt` records
    // as declared-dead, with production using "hardcoded ifs" instead.
    //
    // This test exists so that stops being invisible. If absorption ever
    // starts holding, something changed about the constraint and this test
    // says so.
    let a = PermissionLattice::restrictive();
    let b = PermissionLattice::permissive();
    let absorbed = a.meet(&a.join(&b));
    assert_ne!(
        absorbed, a,
        "if this now passes, meet stopped applying the uninhabitable closure"
    );
    assert_eq!(
        absorbed.capabilities, a.capabilities,
        "the break is in obligations, not capabilities"
    );
    assert!(
        absorbed.obligations != a.obligations,
        "the closure added approval obligations the operand did not carry"
    );
}

use super::*;

/// Regression: a non-ASCII `id` used to PANIC uuid's error formatter
/// (slice at a non-char-boundary) while deserializing `PermissionLattice`
/// — a libFuzzer-reachable crash via `permission_serde`. It must now
/// return a clean `Err`, never panic. Exercises the exact fuzz path
/// (`serde_json::from_str::<PermissionLattice>`).
#[cfg(feature = "serde")]
#[test]
fn deserialize_rejects_hostile_uuid_without_panicking() {
    let base = serde_json::to_value(PermissionLattice::default()).unwrap();

    // Non-ASCII id (the crashing class): U+2028 is multi-byte.
    let mut bad = base.clone();
    bad["id"] = serde_json::Value::String("\u{2028}-not-a-uuid".to_string());
    let s = serde_json::to_string(&bad).unwrap();
    assert!(
        serde_json::from_str::<PermissionLattice>(&s).is_err(),
        "non-ASCII id must error cleanly, not panic"
    );

    // ASCII-but-invalid id: still a clean error.
    let mut bad2 = base.clone();
    bad2["id"] = serde_json::Value::String("definitely-not-a-uuid".to_string());
    assert!(
        serde_json::from_str::<PermissionLattice>(&serde_json::to_string(&bad2).unwrap()).is_err()
    );

    // A non-ASCII derived_from is also rejected cleanly (Option path).
    let mut bad3 = base.clone();
    bad3["derived_from"] = serde_json::Value::String("é-bad".to_string());
    assert!(
        serde_json::from_str::<PermissionLattice>(&serde_json::to_string(&bad3).unwrap()).is_err()
    );

    // A valid uuid still round-trips successfully.
    let mut good = base;
    good["id"] = serde_json::Value::String("00000000-0000-0000-0000-000000000001".to_string());
    assert!(
        serde_json::from_str::<PermissionLattice>(&serde_json::to_string(&good).unwrap()).is_ok()
    );
}

/// LOAD-BEARING (live-path mint brick, acceptance (a)): for EVERY policy
/// profile, `granted_operations()` is exactly the set of operations whose
/// capability level is strictly above `Never`. Concretely:
///
/// 1. no granted op is `Never` (a minted scope never grants a denied op);
/// 2. every op with `level_for(op) == Never` is excluded;
/// 3. the granted set == the `> Never` set (nothing dropped either way);
/// 4. ordering is deterministic (follows `Operation::ALL`).
///
/// This is the by-construction guarantee that a token scope minted from
/// `granted_operations()` is a subset of the policy.
#[test]
fn granted_operations_excludes_every_never_op_for_all_profiles() {
    let profiles: Vec<(&str, PermissionLattice)> = vec![
        ("default", PermissionLattice::default()),
        ("permissive", PermissionLattice::permissive()),
        ("restrictive", PermissionLattice::restrictive()),
        ("read_only", PermissionLattice::read_only()),
        (
            "filesystem_readonly",
            PermissionLattice::filesystem_readonly(),
        ),
        ("network_only", PermissionLattice::network_only()),
        ("web_research", PermissionLattice::web_research()),
        ("code_review", PermissionLattice::code_review()),
        ("edit_only", PermissionLattice::edit_only()),
        ("local_dev", PermissionLattice::local_dev()),
        ("fix_issue", PermissionLattice::fix_issue()),
        ("safe_pr_fixer", PermissionLattice::safe_pr_fixer()),
        ("release", PermissionLattice::release()),
        ("database_client", PermissionLattice::database_client()),
        ("demo", PermissionLattice::demo()),
        ("pr_review", PermissionLattice::pr_review()),
        ("codegen", PermissionLattice::codegen()),
        ("pr_approve", PermissionLattice::pr_approve()),
        ("orchestrator", PermissionLattice::orchestrator()),
    ];

    for (name, policy) in &profiles {
        let granted = policy.granted_operations();

        // (1)+(2)+(3): granted == { op | level_for(op) > Never }.
        let expected: Vec<Operation> = Operation::ALL
            .into_iter()
            .filter(|&op| policy.capabilities.level_for(op) > CapabilityLevel::Never)
            .collect();
        assert_eq!(
            granted, expected,
            "profile {name}: granted_operations must equal the >Never set"
        );

        // (1) restated as a direct denial check: no granted op is Never.
        for op in &granted {
            assert_ne!(
                policy.capabilities.level_for(*op),
                CapabilityLevel::Never,
                "profile {name}: granted op {op:?} must not be Never"
            );
        }
        // (2) restated: every Never op is absent from the granted set.
        for op in Operation::ALL {
            if policy.capabilities.level_for(op) == CapabilityLevel::Never {
                assert!(
                    !granted.contains(&op),
                    "profile {name}: denied (Never) op {op:?} leaked into granted set"
                );
            }
        }

        // (4) deterministic ordering: granted is a subsequence of ALL.
        let mut all_iter = Operation::ALL.into_iter();
        for op in &granted {
            assert!(
                all_iter.by_ref().any(|a| a == *op),
                "profile {name}: granted ops must follow Operation::ALL order"
            );
        }
    }
}

/// A fully-locked-down policy (every capability `Never`) grants NO
/// operations — an empty scope, not a wildcard. In particular `RunBash` is
/// absent, so a token minted from it later DENIES bash (acceptance (b)).
#[test]
fn granted_operations_empty_for_all_never_policy() {
    // read_only already has run_bash = Never; build a stricter one where
    // every capability is Never to prove the empty-scope case exactly.
    let mut locked = PermissionLattice::read_only();
    locked.capabilities = CapabilityLattice {
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
        spawn_agent: CapabilityLevel::Never,
        #[cfg(not(kani))]
        extensions: std::collections::BTreeMap::new(),
    };
    let granted = locked.granted_operations();
    assert!(
        granted.is_empty(),
        "an all-Never policy must grant an EMPTY operation set, got {granted:?}"
    );
    assert!(
        !granted.contains(&Operation::RunBash),
        "RunBash must never appear in an all-Never policy's granted ops"
    );
}

#[test]
fn test_meet_is_commutative() {
    let a = PermissionLattice::permissive();
    let b = PermissionLattice::restrictive();

    let ab = a.meet(&b);
    let ba = b.meet(&a);

    assert_eq!(ab.capabilities, ba.capabilities);
    assert_eq!(ab.paths, ba.paths);
    assert_eq!(ab.budget.max_cost_usd, ba.budget.max_cost_usd);
}

#[test]
fn test_meet_is_idempotent() {
    let a = PermissionLattice::default();
    let aa = a.meet(&a);

    assert_eq!(a.capabilities, aa.capabilities);
    assert_eq!(a.paths, aa.paths);
    assert_eq!(a.budget.max_cost_usd, aa.budget.max_cost_usd);
}

#[test]
fn test_meet_is_associative() {
    let a = PermissionLattice::permissive();
    let b = PermissionLattice::default();
    let c = PermissionLattice::restrictive();

    let ab_c = a.meet(&b).meet(&c);
    let a_bc = a.meet(&b.meet(&c));

    assert_eq!(ab_c.capabilities, a_bc.capabilities);
    assert_eq!(ab_c.budget.max_cost_usd, a_bc.budget.max_cost_usd);
}

#[test]
fn test_delegation_monotonicity() {
    let parent = PermissionLattice::permissive();
    let requested = PermissionLattice {
        capabilities: CapabilityLattice {
            write_files: CapabilityLevel::Always,
            git_push: CapabilityLevel::Always,
            ..Default::default()
        },
        obligations: Obligations::default(),
        ..Default::default()
    };

    let result = parent.delegate_to(&requested, "test delegation").unwrap();

    assert!(result.capabilities.leq(&parent.capabilities));
    assert!(result.requires_approval(Operation::GitPush));
}

#[test]
fn test_delegation_fails_when_parent_expired() {
    let mut parent = PermissionLattice::default();
    parent.time.valid_until = Utc::now() - Duration::hours(1);

    let result = parent.delegate_to(&PermissionLattice::default(), "test");
    assert!(matches!(result, Err(DelegationError::ParentExpired)));
}

#[test]
fn test_effective_permissions_integrity() {
    let perms = EffectivePermissions::new(PermissionLattice::default());
    assert!(perms.verify_integrity());
}

#[test]
fn test_builder_pattern() {
    let lattice = PermissionLattice::builder()
        .description("Test permissions")
        .capabilities(CapabilityLattice::restrictive())
        .budget(BudgetLattice::with_cost_limit(1.0))
        .uninhabitable_constraint(true)
        .created_by("test")
        .build();

    assert_eq!(lattice.description, "Test permissions");
    assert_eq!(lattice.budget.max_cost_usd, Decimal::ONE);
    assert!(lattice.uninhabitable_constraint);
}

#[test]
fn test_uninhabitable_is_enforced_in_meet() {
    let dangerous = PermissionLattice {
        capabilities: CapabilityLattice {
            read_files: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::LowRisk,
            git_push: CapabilityLevel::LowRisk,
            create_pr: CapabilityLevel::LowRisk,
            ..Default::default()
        },
        obligations: Obligations::default(),
        uninhabitable_constraint: true,
        ..Default::default()
    };

    let combined = dangerous.meet(&dangerous);

    // Exfiltration should require approval
    assert!(combined.requires_approval(Operation::GitPush));
    assert!(combined.requires_approval(Operation::CreatePr));
}

#[test]
fn test_join_operation() {
    let a = PermissionLattice::restrictive();
    let b = PermissionLattice::permissive();

    let result = a.join(&b);

    // Join should take the more permissive values
    assert!(result.budget.max_cost_usd >= a.budget.max_cost_usd);
    assert!(result.budget.max_cost_usd >= b.budget.max_cost_usd);
}

#[test]
fn test_join_preserves_uninhabitable_constraint_or_semantics() {
    // Regression: join() previously used AND for uninhabitable_constraint,
    // meaning an attacker who controlled one input could disable the safety
    // check by providing uninhabitable_constraint=false.
    let constrained = PermissionLattice {
        uninhabitable_constraint: true,
        ..Default::default()
    };

    // Simulate attacker-controlled input with constraint disabled.
    // In practice this is only reachable via programmatic construction
    // (deserialization always forces true), but join must be safe regardless.
    let unconstrained = PermissionLattice {
        uninhabitable_constraint: false,
        ..Default::default()
    };

    // join(true, false) must be true (OR-semantics)
    let result = constrained.join(&unconstrained);
    assert!(
        result.uninhabitable_constraint,
        "join must preserve uninhabitable_constraint via OR-semantics"
    );

    // Commutative: join(false, true) must also be true
    let result_rev = unconstrained.join(&constrained);
    assert!(
        result_rev.uninhabitable_constraint,
        "join must be commutative for uninhabitable_constraint"
    );

    // join(true, true) = true
    let both = constrained.join(&constrained);
    assert!(both.uninhabitable_constraint);

    // join(false, false) = false (both inputs opted out — no constraint to preserve)
    let neither = unconstrained.join(&unconstrained);
    assert!(!neither.uninhabitable_constraint);
}

#[cfg(feature = "serde")]
#[test]
fn test_uninhabitable_bypass_via_deserialization_blocked() {
    // Attempt to bypass uninhabitable_state constraint via JSON
    let json = r#"{
        "id": "00000000-0000-0000-0000-000000000001",
        "description": "malicious",
        "derived_from": null,
        "capabilities": {
            "read_files": "always",
            "write_files": "low_risk",
            "edit_files": "low_risk",
            "run_bash": "never",
            "glob_search": "always",
            "grep_search": "always",
            "web_search": "low_risk",
            "web_fetch": "low_risk",
            "git_commit": "low_risk",
            "git_push": "never",
            "create_pr": "low_risk"
        },
        "obligations": {"approvals": []},
        "paths": {"allowed": [], "blocked": [], "work_dir": null},
        "budget": {"max_cost_usd": "5", "consumed_usd": "0", "max_input_tokens": 100000, "max_output_tokens": 10000},
        "commands": {"allowed": [], "blocked": []},
        "time": {"valid_from": "2024-01-01T00:00:00Z", "valid_until": "2025-01-01T00:00:00Z"},
        "uninhabitable_constraint": false,
        "created_at": "2024-01-01T00:00:00Z",
        "created_by": "attacker"
    }"#;

    let perms: PermissionLattice = serde_json::from_str(json).unwrap();

    // Despite the JSON saying false, the constraint should be enforced
    assert!(
        perms.uninhabitable_constraint,
        " UninhabitableState constraint should always be true after deserialization"
    );
}

// ========================================================================
// Workflow Profile Tests (pr_review, codegen, pr_approve)
// ========================================================================

#[test]
fn test_pr_review_no_uninhabitable() {
    // pr_review has read + web access, but NO exfiltration capability
    // (git_push=Never, create_pr=Never, run_bash=Never), so uninhabitable_state is not complete
    let perms = PermissionLattice::pr_review();

    // Verify capabilities match expected profile
    assert_eq!(perms.capabilities.read_files, CapabilityLevel::Always);
    assert_eq!(perms.capabilities.web_fetch, CapabilityLevel::LowRisk);
    assert_eq!(perms.capabilities.web_search, CapabilityLevel::LowRisk);
    assert_eq!(perms.capabilities.git_push, CapabilityLevel::Never);
    assert_eq!(perms.capabilities.create_pr, CapabilityLevel::Never);
    assert_eq!(perms.capabilities.run_bash, CapabilityLevel::Never);
    assert_eq!(perms.capabilities.write_files, CapabilityLevel::Never);
    assert_eq!(perms.capabilities.edit_files, CapabilityLevel::Never);

    //  UninhabitableState should NOT be detected (no exfil capability)
    assert!(
        !perms.is_uninhabitable_vulnerable(),
        "pr_review should NOT trigger uninhabitable_state (no exfiltration capability)"
    );

    // No approvals should be required
    assert!(
        !perms.requires_approval(Operation::GitPush),
        "git_push is Never, so no approval needed"
    );
}

#[test]
fn test_codegen_no_uninhabitable() {
    // codegen has read + write + bash, but NO untrusted content exposure
    // (web_fetch=Never, web_search=Never), so uninhabitable_state is not complete
    let perms = PermissionLattice::codegen();

    // Verify capabilities match expected profile
    assert_eq!(perms.capabilities.read_files, CapabilityLevel::Always);
    assert_eq!(perms.capabilities.write_files, CapabilityLevel::LowRisk);
    assert_eq!(perms.capabilities.edit_files, CapabilityLevel::LowRisk);
    assert_eq!(perms.capabilities.run_bash, CapabilityLevel::LowRisk);
    assert_eq!(perms.capabilities.git_commit, CapabilityLevel::LowRisk);
    assert_eq!(perms.capabilities.web_fetch, CapabilityLevel::Never);
    assert_eq!(perms.capabilities.web_search, CapabilityLevel::Never);
    assert_eq!(perms.capabilities.git_push, CapabilityLevel::Never);
    assert_eq!(perms.capabilities.create_pr, CapabilityLevel::Never);

    //  UninhabitableState should NOT be detected (no untrusted content)
    assert!(
        !perms.is_uninhabitable_vulnerable(),
        "codegen should NOT trigger uninhabitable_state (no untrusted content exposure)"
    );

    // No approvals should be required for bash since no uninhabitable_state
    assert!(
        !perms.requires_approval(Operation::RunBash),
        "run_bash should not require approval (no uninhabitable_state)"
    );
}

#[test]
fn test_pr_approve_has_uninhabitable() {
    // pr_approve has all three: read + web + git_push
    // This SHOULD trigger uninhabitable_state protection
    let perms = PermissionLattice::pr_approve();

    // Verify capabilities match expected profile
    assert_eq!(perms.capabilities.read_files, CapabilityLevel::Always);
    assert_eq!(perms.capabilities.web_fetch, CapabilityLevel::LowRisk);
    assert_eq!(perms.capabilities.web_search, CapabilityLevel::LowRisk);
    assert_eq!(perms.capabilities.git_push, CapabilityLevel::LowRisk);
    assert_eq!(perms.capabilities.write_files, CapabilityLevel::Never);
    assert_eq!(perms.capabilities.edit_files, CapabilityLevel::Never);
    assert_eq!(perms.capabilities.create_pr, CapabilityLevel::Never);

    //  UninhabitableState SHOULD be detected
    assert!(
        perms.is_uninhabitable_vulnerable(),
        "pr_approve SHOULD trigger uninhabitable_state (has read + web + git_push)"
    );

    // git_push should require approval due to uninhabitable_state
    assert!(
        perms.requires_approval(Operation::GitPush),
        "git_push should require approval in pr_approve (CI-gated)"
    );

    // run_bash also requires approval since it's an exfil vector
    assert!(
        perms.requires_approval(Operation::RunBash),
        "run_bash should require approval in pr_approve (uninhabitable_state active)"
    );
}

#[test]
fn test_workflow_profiles_block_sensitive_paths() {
    // All workflow profiles should block sensitive paths by default
    let profiles = [
        PermissionLattice::pr_review(),
        PermissionLattice::codegen(),
        PermissionLattice::pr_approve(),
        PermissionLattice::safe_pr_fixer(),
    ];

    for perms in &profiles {
        // Should block common sensitive patterns
        assert!(
            !perms.paths.blocked.is_empty(),
            "Workflow profile '{}' should have blocked paths",
            perms.description
        );
    }
}

#[test]
fn test_codegen_is_fully_network_isolated() {
    let perms = PermissionLattice::codegen();

    // Verify complete network isolation
    assert_eq!(
        perms.capabilities.web_fetch,
        CapabilityLevel::Never,
        "codegen must be network-isolated (web_fetch=Never)"
    );
    assert_eq!(
        perms.capabilities.web_search,
        CapabilityLevel::Never,
        "codegen must be network-isolated (web_search=Never)"
    );
    assert_eq!(
        perms.capabilities.git_push,
        CapabilityLevel::Never,
        "codegen cannot push (git_push=Never)"
    );
    assert_eq!(
        perms.capabilities.create_pr,
        CapabilityLevel::Never,
        "codegen cannot create PRs (create_pr=Never)"
    );
}

#[test]
fn test_safe_pr_fixer_no_push_no_pr() {
    let perms = PermissionLattice::safe_pr_fixer();

    // Key security invariant: cannot push or create PRs
    assert_eq!(
        perms.capabilities.git_push,
        CapabilityLevel::Never,
        "safe_pr_fixer cannot push (CI script does that)"
    );
    assert_eq!(
        perms.capabilities.create_pr,
        CapabilityLevel::Never,
        "safe_pr_fixer cannot create PRs (CI script does that)"
    );

    // Can read, write, edit, commit, run bash
    assert_eq!(perms.capabilities.read_files, CapabilityLevel::Always);
    assert_eq!(perms.capabilities.write_files, CapabilityLevel::LowRisk);
    assert_eq!(perms.capabilities.edit_files, CapabilityLevel::LowRisk);
    assert_eq!(perms.capabilities.run_bash, CapabilityLevel::LowRisk);
    assert_eq!(perms.capabilities.git_commit, CapabilityLevel::LowRisk);

    // Web fetch allowed (docs lookup) but no broad search
    assert_eq!(perms.capabilities.web_fetch, CapabilityLevel::LowRisk);
    assert_eq!(perms.capabilities.web_search, CapabilityLevel::Never);

    // No pod management
    assert_eq!(perms.capabilities.manage_pods, CapabilityLevel::Never);

    //  UninhabitableState IS triggered (read + web_fetch + run_bash), and normalize()
    // correctly adds approval obligations on bash. This is the right behavior:
    // bash requires human approval, while git_push/create_pr are fully blocked.
    assert!(
        perms.is_uninhabitable_vulnerable(),
        "safe_pr_fixer has uninhabitable_state (bash is exfil vector), obligations mitigate"
    );
    assert!(
        perms.requires_approval(Operation::RunBash),
        "run_bash should require approval (uninhabitable_state mitigation)"
    );
}

#[test]
fn test_pr_review_cannot_modify_code() {
    let perms = PermissionLattice::pr_review();

    // Verify read-only for code
    assert_eq!(
        perms.capabilities.write_files,
        CapabilityLevel::Never,
        "pr_review cannot write files"
    );
    assert_eq!(
        perms.capabilities.edit_files,
        CapabilityLevel::Never,
        "pr_review cannot edit files"
    );
    assert_eq!(
        perms.capabilities.git_commit,
        CapabilityLevel::Never,
        "pr_review cannot commit"
    );
    assert_eq!(
        perms.capabilities.git_push,
        CapabilityLevel::Never,
        "pr_review cannot push"
    );
    assert_eq!(
        perms.capabilities.run_bash,
        CapabilityLevel::Never,
        "pr_review cannot run bash (exfil vector)"
    );
}

#[test]
fn test_pr_approve_cannot_modify_code() {
    let perms = PermissionLattice::pr_approve();

    // Verify read-only for code (only git_push is allowed for merging)
    assert_eq!(
        perms.capabilities.write_files,
        CapabilityLevel::Never,
        "pr_approve cannot write files"
    );
    assert_eq!(
        perms.capabilities.edit_files,
        CapabilityLevel::Never,
        "pr_approve cannot edit files"
    );
    assert_eq!(
        perms.capabilities.git_commit,
        CapabilityLevel::Never,
        "pr_approve cannot commit"
    );
    // But CAN push (for merging)
    assert_eq!(
        perms.capabilities.git_push,
        CapabilityLevel::LowRisk,
        "pr_approve CAN push (for merging)"
    );
}

// ========================================================================
// Orchestrator Profile Tests
// ========================================================================

#[test]
fn test_orchestrator_no_uninhabitable() {
    let perms = PermissionLattice::orchestrator();

    // Verify core capability: manage_pods is Always
    assert_eq!(
        perms.capabilities.manage_pods,
        CapabilityLevel::Always,
        "orchestrator must have manage_pods: Always"
    );

    // Verify no direct tool access
    assert_eq!(perms.capabilities.write_files, CapabilityLevel::Never);
    assert_eq!(perms.capabilities.edit_files, CapabilityLevel::Never);
    assert_eq!(perms.capabilities.run_bash, CapabilityLevel::Never);
    assert_eq!(perms.capabilities.web_search, CapabilityLevel::Never);
    assert_eq!(perms.capabilities.web_fetch, CapabilityLevel::Never);
    assert_eq!(perms.capabilities.git_commit, CapabilityLevel::Never);
    assert_eq!(perms.capabilities.git_push, CapabilityLevel::Never);
    assert_eq!(perms.capabilities.create_pr, CapabilityLevel::Never);

    // Read-only access for orchestration configs
    assert_eq!(perms.capabilities.read_files, CapabilityLevel::LowRisk);
    assert_eq!(perms.capabilities.glob_search, CapabilityLevel::LowRisk);
    assert_eq!(perms.capabilities.grep_search, CapabilityLevel::LowRisk);

    // UninhabitableState: only 1/3 components (private access), no untrusted or exfil
    assert!(
        !perms.is_uninhabitable_vulnerable(),
        "orchestrator should NOT trigger uninhabitable_state"
    );

    // No approval obligations required
    assert!(
        !perms.requires_approval(Operation::ManagePods),
        "manage_pods should not require approval"
    );
}

#[test]
fn test_orchestrator_delegation_strips_manage_pods() {
    let orchestrator = PermissionLattice::orchestrator();
    let codegen = PermissionLattice::codegen();

    // Delegate from orchestrator to codegen sub-pod
    let delegated = orchestrator
        .delegate_to(&codegen, "spawn codegen sub-pod")
        .unwrap();

    // Sub-pod should NOT get manage_pods (codegen doesn't request it,
    // and meet of Always with Never = Never)
    assert_eq!(
        delegated.capabilities.manage_pods,
        CapabilityLevel::Never,
        "codegen sub-pod must not get manage_pods"
    );
}

#[test]
fn test_orchestrator_budget() {
    let perms = PermissionLattice::orchestrator();
    assert_eq!(
        perms.budget.max_cost_usd,
        Decimal::from(50),
        "orchestrator should have $50 budget"
    );
}

/// `program_checksum` drops the validity window and nothing else.
///
/// Three mutants survived this function when it landed untested: returning
/// `String::new()`, returning a constant, and flipping the `tag == "time"` skip
/// to `!=` — which hashes ONLY the window and inverts the whole point. The two
/// tests below kill all three, because together they pin both directions: the
/// window must not matter, and everything else must.
mod program_checksum_tests {
    use super::*;

    /// Two policies alike but for WHEN they are valid are the same program.
    /// This is the property the cross-execution cache needs: a window minted per
    /// launch must not make every run a different program.
    #[test]
    fn a_differing_window_is_the_same_program() {
        let base = PermissionLattice::demo();
        let mut later = base.clone();
        later.time = TimeLattice {
            valid_from: base.time.valid_from + chrono::Duration::hours(3),
            valid_until: base.time.valid_until + chrono::Duration::hours(3),
        };

        assert_ne!(
            base.checksum(),
            later.checksum(),
            "checksum answers 'same certificate', and a different window IS a \
             different grant — if this stops holding, the window has left the \
             certificate identity too and that is a separate defect"
        );
        assert_eq!(
            base.program_checksum(),
            later.program_checksum(),
            "a window says WHEN a pod runs, never WHAT it computes"
        );
    }

    /// And a policy that permits something different is a different program, so
    /// the checksum is not a constant and the skip is not swallowing the rest.
    #[test]
    fn a_differing_permission_is_a_different_program() {
        let base = PermissionLattice::demo();
        let mut narrowed = base.clone();
        narrowed
            .commands
            .blocked
            .insert("newly-blocked-command".into());

        assert_ne!(
            base.commands, narrowed.commands,
            "the probe must actually differ, or what follows proves nothing"
        );
        assert_ne!(
            base.program_checksum(),
            narrowed.program_checksum(),
            "every field but the window still enters: a constant return, or a \
             skip that swallowed the other fields, would collapse these"
        );
    }
}
