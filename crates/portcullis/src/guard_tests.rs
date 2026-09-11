//! Tests for `guard.rs`.
//!
//! Split out under `#[path]` — the same shape `kernel.rs` uses — when the
//! module's tests carried the file past the 2500-line default ratchet
//! ceiling. The alternative was a `[[files]]` entry raising the ceiling for
//! `guard.rs`, which buys silence rather than a smaller file.

use super::*;
use std::path::PathBuf;

// ── the proof names what was checked (ADR 0006, C2.2) ───────────────

/// A proof answers "a read of *what*?".
///
/// Before, it could not: `check` was told only the verb, so the target
/// travelled beside the proof as a separate string and the audit record
/// was built from that string. Nothing connected the two, and nothing
/// would have noticed a handler that checked one path and audited another.
#[test]
fn a_proof_names_what_was_checked() {
    let guard = GradedExposureGuard::new(PermissionLattice::default(), "schema");
    let act = Act::Read {
        path: FilePath::new("/etc/shadow"),
        sink: ReadSink::AuditLog,
    };
    let proof = guard.check(&act).expect("reads are allowed by default");

    assert_eq!(proof.act(), &act, "the proof carries the act it was given");
    assert_eq!(
        proof.subject(),
        "/etc/shadow",
        "the audit subject is derived from the decision, not carried beside it"
    );
    assert_eq!(
        proof.operation(),
        Operation::ReadFiles,
        "and the verb is still reachable, derived from the act"
    );
}

/// Two reads of different files are now distinguishable at the guard.
///
/// This is the precondition for anything downstream refusing one and
/// allowing the other. It is deliberately not itself a policy change —
/// both still pass — but before this the guard could not have told them
/// apart even in principle.
#[test]
fn reads_of_different_files_are_distinguishable() {
    let guard = GradedExposureGuard::new(PermissionLattice::default(), "schema");
    let secret = guard
        .check(&Act::Read {
            path: FilePath::new("/etc/shadow"),
            sink: ReadSink::AuditLog,
        })
        .expect("allowed");
    let ordinary = guard
        .check(&Act::Read {
            path: FilePath::new("/workspace/main.rs"),
            sink: ReadSink::AuditLog,
        })
        .expect("allowed");

    assert_eq!(secret.operation(), ordinary.operation(), "same verb");
    assert_ne!(
        secret.subject(),
        ordinary.subject(),
        "different target, and the guard can now see the difference"
    );
}

/// C2.2 changed the vocabulary, not the policy.
///
/// The decision still turns on the verb and the accumulated exposure; a
/// capability set to `Never` still denies, and the target does not rescue
/// it. Without this, "the guard now sees the target" could have been a
/// silent loosening.
#[test]
fn the_decision_still_turns_on_the_verb() {
    use crate::CapabilityLevel;

    let mut perms = PermissionLattice::default();
    perms.capabilities.web_fetch = CapabilityLevel::Never;
    let guard = GradedExposureGuard::new(perms, "schema");

    for host in ["example.com", "127.0.0.1", "internal.corp"] {
        let act = Act::Fetch {
            endpoint: Endpoint::new("GET", "https", host, 443, "/", "https://x/"),
        };
        assert!(
            guard.check(&act).is_err(),
            "{host}: a Never capability denies regardless of target"
        );
    }

    let guard = GradedExposureGuard::new(PermissionLattice::default(), "schema");
    assert!(
        guard
            .check(&Act::Fetch {
                endpoint: Endpoint::new("GET", "https", "example.com", 443, "/", "https://x/"),
            })
            .is_ok(),
        "non-vacuity: the same act is allowed when the capability is not Never"
    );
}

// ── the TOCTOU re-check (found by cargo mutants) ────────────────────

/// Capabilities that ARE uninhabitable, normalised the way production
/// builds them — so `normalize` really does attach the approval
/// obligations, and this is not a hand-made lattice that could not occur.
fn toctou_perms() -> PermissionLattice {
    use crate::CapabilityLevel;
    let mut perms = PermissionLattice::default();
    perms.capabilities.read_files = CapabilityLevel::Always;
    perms.capabilities.web_fetch = CapabilityLevel::LowRisk;
    perms.capabilities.run_bash = CapabilityLevel::LowRisk;
    perms.capabilities.spawn_agent = CapabilityLevel::Always;
    perms.uninhabitable_constraint = true;
    perms.normalize()
}

/// Grow the exposure to {PrivateData, UntrustedContent} from inside a
/// closure — the only place it can grow, because `execute_and_record` runs
/// the closure before it takes the record lock.
fn grow_two_legs(guard: &impl ToolCallGuard) {
    for op in [Operation::ReadFiles, Operation::WebFetch] {
        let p = guard
            .check(&Act::untargeted(op))
            .expect("each leg is allowed on its own");
        guard
            .execute_and_record(p, || Ok::<_, String>(()))
            .expect("and records");
    }
}

/// **The TOCTOU re-check denies on BOTH conditions, not either.**
///
/// When the exposure grew between `check` and the record,
/// `execute_and_record` re-projects and denies only if the projection is
/// uninhabitable **and** the operation requires approval. That conjunction
/// is not incidental: `exposure_core::should_deny` is literally
/// `projected.is_uninhabitable() && requires_approval`, so the re-check
/// mirrors check-time policy. One that denied on *either* would refuse an
/// operation the check itself had just allowed.
///
/// Nothing covered this branch — it is reachable only when a closure grows
/// the exposure — and `cargo mutants --in-diff` is what found it: `replace
/// && with ||` survived at both `execute_and_record` sites.
///
/// The two sides are told apart by the operation. `obligations_for` attaches
/// approval to `GitPush`, `CreatePr` and `RunBash`, and
/// `PermissionLattice::default` pre-loads `WriteFiles`, `EditFiles`,
/// `WebSearch`, `WebFetch`, `GitCommit` and `CreatePr` — while
/// `classify_operation` makes `SpawnAgent` an `ExfilVector` that appears in
/// neither list. So a normalised, uninhabitable lattice still has an exfil
/// operation needing no approval, and the mutant is killable rather than
/// equivalent. Finding that took reading both sources of obligations: the
/// first two operations tried were in one list each.
#[test]
fn a_toctou_recheck_denies_on_both_conditions_not_either() {
    let perms = toctou_perms();
    assert!(
        !perms.requires_approval(Operation::SpawnAgent),
        "non-vacuity: this side of the conjunction must be false, or `&&` \
         and `||` agree here and the test proves nothing"
    );
    assert!(
        perms.requires_approval(Operation::RunBash),
        "and normalize really did attach obligations — otherwise the \
         lattice is not the uninhabitable one this is about"
    );

    let guard = GradedExposureGuard::new(perms, "[]");
    let proof = guard
        .check(&Act::untargeted(Operation::SpawnAgent))
        .expect("a clean session allows it");

    let out = guard.execute_and_record(proof, || {
        grow_two_legs(&guard);
        Ok::<_, String>(())
    });

    assert!(
        out.is_ok(),
        "the projection is uninhabitable but SpawnAgent needs no approval, \
         so the re-check must allow — the answer `should_deny` gives at \
         check time. Denying here would refuse what the guard just approved."
    );
    assert!(
        guard.exposure().is_uninhabitable(),
        "and the exposure IS recorded: allowing the act is not forgetting it"
    );
}

/// The other direction, and the reason the test above is not just "always
/// allow": with an operation that DOES require approval, the same grown
/// exposure denies. Without this, a re-check that had been deleted outright
/// would pass the test above.
#[test]
fn a_toctou_recheck_does_deny_when_approval_is_required() {
    let guard = GradedExposureGuard::new(toctou_perms(), "[]");
    let proof = guard
        .check(&Act::untargeted(Operation::RunBash))
        .expect("a clean session allows it");

    let out = guard.execute_and_record(proof, || {
        grow_two_legs(&guard);
        Ok::<_, String>(())
    });

    assert!(
        matches!(out, Err(ExecuteError::TocTouDenied { .. })),
        "RunBash carries the approval obligation, so the grown exposure \
         must deny it: {out:?}",
        out = out.as_ref().map(|_| ())
    );
}

/// The deprecated guard carries its own copy of the re-check, and its own
/// mutant survived. One test would have killed one.
#[test]
#[allow(deprecated)]
fn the_deprecated_guard_recheck_also_denies_on_both() {
    // Allowed: the projection is uninhabitable, SpawnAgent needs no approval.
    let guard = RuntimeStateGuard::new(toctou_perms(), "[]");
    let allowed = guard
        .check(&Act::untargeted(Operation::SpawnAgent))
        .expect("allowed when clean");
    let out = guard.execute_and_record(allowed, || {
        grow_two_legs(&guard);
        Ok::<_, String>(())
    });
    assert!(out.is_ok(), "same conjunction, same answer");

    // Denied: a FRESH guard, because once the session above went
    // uninhabitable `check` itself refuses and the re-check is never
    // reached — which is the guard working, not the test failing.
    let guard = RuntimeStateGuard::new(toctou_perms(), "[]");
    let needs_approval = guard
        .check(&Act::untargeted(Operation::RunBash))
        .expect("allowed when clean");
    let denied = guard.execute_and_record(needs_approval, || {
        grow_two_legs(&guard);
        Ok::<_, String>(())
    });
    assert!(
        matches!(denied, Err(ExecuteError::TocTouDenied { .. })),
        "RunBash carries the approval obligation, so the grown exposure \
         must deny it"
    );
}

/// Test helper: check and record an operation in one call.
/// Panics if check or execute_and_record fails.
fn check_and_record(guard: &impl ToolCallGuard, op: Operation) {
    let proof = guard.check(&Act::untargeted(op)).expect("check failed");
    guard
        .execute_and_record(proof, || Ok::<_, String>(()))
        .expect("execute_and_record failed");
}

struct TestPathGuard {
    blocked: Vec<String>,
}

impl PermissionGuard for TestPathGuard {
    type Action = PathBuf;
    type Error = String;

    fn guard(&self, path: PathBuf) -> Result<GuardedAction<PathBuf>, GuardError<String>> {
        let path_str = path.to_string_lossy();
        for blocked in &self.blocked {
            if path_str.contains(blocked) {
                return Err(GuardError::Blocked {
                    blocker: blocked.clone(),
                });
            }
        }
        Ok(GuardedAction::new(path))
    }
}

#[test]
fn test_guard_allows_valid_path() {
    let guard = TestPathGuard {
        blocked: vec![".env".to_string()],
    };

    let result = guard.guard(PathBuf::from("src/main.rs"));
    assert!(result.is_ok());

    let guarded = result.unwrap();
    assert_eq!(guarded.action(), &PathBuf::from("src/main.rs"));
}

#[test]
fn test_guard_blocks_sensitive_path() {
    let guard = TestPathGuard {
        blocked: vec![".env".to_string()],
    };

    let result = guard.guard(PathBuf::from(".env"));
    assert!(result.is_err());

    match result {
        Err(GuardError::Blocked { blocker }) => {
            assert_eq!(blocker, ".env");
        }
        _ => panic!("Expected Blocked error"),
    }
}

#[test]
fn test_guarded_action_cannot_be_constructed_externally() {
    // This test documents that GuardedAction cannot be constructed
    // outside this module due to the private field.
    //
    // If you uncomment the following line, it will fail to compile:
    // let _action = GuardedAction { action: 42, _private: () };
}

#[test]
fn test_composite_guard() {
    let guard = CompositeGuard::<i32, String>::new()
        .with_guard(|n| {
            if *n < 0 {
                Err(GuardError::Denied {
                    reason: "negative".to_string(),
                })
            } else {
                Ok(())
            }
        })
        .with_guard(|n| {
            if *n > 100 {
                Err(GuardError::Denied {
                    reason: "too large".to_string(),
                })
            } else {
                Ok(())
            }
        });

    // Valid value passes all guards
    assert!(guard.guard(50).is_ok());

    // Negative fails first guard
    assert!(matches!(
        guard.guard(-5),
        Err(GuardError::Denied { reason }) if reason == "negative"
    ));

    // Too large fails second guard
    assert!(matches!(
        guard.guard(150),
        Err(GuardError::Denied { reason }) if reason == "too large"
    ));
}

#[test]
fn test_guarded_action_map() {
    let guard = TestPathGuard { blocked: vec![] };

    let result = guard.guard(PathBuf::from("test.txt"));
    let guarded = result.unwrap();

    // Map to string
    let string_action = guarded.map(|p| p.to_string_lossy().to_string());
    assert_eq!(string_action.into_action(), "test.txt");
}

#[test]
fn test_guarded_action_and_then() {
    let guard = TestPathGuard {
        blocked: vec![".env".to_string()],
    };

    // Successful chain: read src, then read lib
    let result = guard
        .guard(PathBuf::from("src/main.rs"))
        .and_then(|_| guard.guard(PathBuf::from("lib/utils.rs")));
    assert!(result.is_ok());

    // Chain fails on second guard
    let result = guard
        .guard(PathBuf::from("src/main.rs"))
        .and_then(|_| guard.guard(PathBuf::from(".env")));
    assert!(result.is_err());

    // Chain fails on first guard (second never runs)
    let result = guard
        .guard(PathBuf::from(".env"))
        .and_then(|_| guard.guard(PathBuf::from("src/main.rs")));
    assert!(result.is_err());
}

#[test]
fn test_guarded_action_try_map() {
    let guard = TestPathGuard { blocked: vec![] };

    // Successful try_map
    let result: Result<GuardedAction<String>, GuardError<String>> = guard
        .guard(PathBuf::from("test.txt"))
        .unwrap()
        .try_map(|p| Ok::<_, String>(p.to_string_lossy().to_string()));
    assert!(result.is_ok());
    assert_eq!(result.unwrap().into_action(), "test.txt");

    // Failed try_map
    let result: Result<GuardedAction<String>, GuardError<String>> = guard
        .guard(PathBuf::from("test.txt"))
        .unwrap()
        .try_map(|_| Err::<String, _>("io error".to_string()));
    assert!(matches!(result, Err(GuardError::CheckFailed { .. })));
}

#[test]
fn test_graded_guard_safe_profile() {
    let perms = PermissionLattice::read_only();
    let guard = GradedGuard::new(perms);

    // read_only has only private data access (read_files: Always)
    // so risk should be Low (1 uninhabitable_state component)
    assert_eq!(guard.risk(), StateRisk::Low);

    // ReadFile operation should be allowed
    let result = guard.check_operation(Operation::ReadFiles);
    assert!(result.value.is_ok());
    assert_eq!(result.grade, StateRisk::Low);
}

#[test]
fn test_graded_guard_permissive_denies_uninhabitable_exfiltration() {
    let perms = PermissionLattice::permissive();
    let guard = GradedGuard::new(perms);

    // Permissive has complete uninhabitable_state
    assert_eq!(guard.risk(), StateRisk::Uninhabitable);

    // Exfiltration operations that require approval should be denied
    let result = guard.check_operation(Operation::GitPush);
    assert_eq!(result.grade, StateRisk::Uninhabitable);
    // GitPush requires approval under uninhabitable_state, so it should be denied
    assert!(result.value.is_err());
}

#[test]
fn test_graded_guard_path_check() {
    use crate::PathLattice;
    use std::collections::HashSet;

    let perms = PermissionLattice {
        paths: PathLattice {
            allowed: HashSet::from(["**/*.rs".to_string()]),
            blocked: HashSet::from([".env*".to_string()]),
            work_dir: None,
        },
        ..Default::default()
    };
    let guard = GradedGuard::new(perms);

    // .rs files should be allowed
    let result = guard.check_path("src/lib.rs");
    assert!(result.value.is_ok());

    // .env files should be denied
    let result = guard.check_path(".env");
    assert!(result.value.is_err());
}

#[test]
fn test_graded_guard_permission_gap() {
    use crate::CapabilityLevel;

    let floor = PermissionLattice::read_only();
    let mut target = PermissionLattice::read_only();
    target.capabilities.git_push = CapabilityLevel::Always;
    target.capabilities.web_fetch = CapabilityLevel::LowRisk;

    let guard = GradedGuard::new(floor);
    let gap = guard.permission_gap_to(&target);

    // Target has more uninhabitable_state components, so risk is higher
    assert!(gap.grade >= StateRisk::Medium);

    // The gap should show what's needed for the capabilities
    // that the floor doesn't have
    assert_eq!(gap.value.git_push, CapabilityLevel::Always);
    assert_eq!(gap.value.web_fetch, CapabilityLevel::Always);
}

#[test]
fn test_graded_guard_compose_checks() {
    let perms = PermissionLattice::read_only();
    let guard = GradedGuard::new(perms);

    // Compose two graded checks using and_then
    let result = guard
        .check_path("/workspace/src/lib.rs")
        .and_then(|first_result| {
            // Only proceed if first check passed
            match first_result {
                Ok(_) => guard.check_operation(Operation::ReadFiles),
                Err(e) => Graded::new(guard.risk(), Err(e)),
            }
        });

    // Risk should be composed (max of both checks)
    assert_eq!(result.grade, StateRisk::Low);
    assert!(result.value.is_ok());
}

// -----------------------------------------------------------------------
// RuntimeStateGuard tests
// -----------------------------------------------------------------------

fn uninhabitable_perms() -> PermissionLattice {
    use crate::CapabilityLevel;
    let mut perms = PermissionLattice::default();
    perms.capabilities.read_files = CapabilityLevel::Always;
    perms.capabilities.web_fetch = CapabilityLevel::LowRisk;
    perms.capabilities.run_bash = CapabilityLevel::LowRisk;
    perms.uninhabitable_constraint = true;
    perms.normalize()
}

#[test]
#[allow(deprecated)]
fn test_session_risk_accumulates() {
    let guard = RuntimeStateGuard::new(uninhabitable_perms(), "[]");

    // Start at None
    assert_eq!(guard.accumulated_risk(), StateRisk::Safe);

    // Read (private data leg)
    check_and_record(&guard, Operation::ReadFiles);
    assert_eq!(guard.accumulated_risk(), StateRisk::Low);

    // Fetch (untrusted content leg)
    check_and_record(&guard, Operation::WebFetch);
    assert_eq!(guard.accumulated_risk(), StateRisk::Medium);

    // RunBash (exfil leg) — should be BLOCKED because it completes uninhabitable_state
    let result = guard.check(&Act::untargeted(Operation::RunBash));
    assert!(
        result.is_err(),
        "RunBash should be blocked when completing uninhabitable_state"
    );

    // Risk stays at Medium (RunBash was not recorded)
    assert_eq!(guard.accumulated_risk(), StateRisk::Medium);
}

#[test]
#[allow(deprecated)]
fn test_no_phantom_risk() {
    let guard = RuntimeStateGuard::new(uninhabitable_perms(), "[]");

    // check() alone does NOT increase risk (proof is dropped, not consumed)
    let _proof1 = guard.check(&Act::untargeted(Operation::ReadFiles)).unwrap();
    let _proof2 = guard.check(&Act::untargeted(Operation::WebFetch)).unwrap();
    assert_eq!(guard.accumulated_risk(), StateRisk::Safe);

    // Only execute_and_record increases risk
    check_and_record(&guard, Operation::ReadFiles);
    assert_eq!(guard.accumulated_risk(), StateRisk::Low);
}

#[test]
#[allow(deprecated)]
fn test_benign_sequence_allowed() {
    let guard = RuntimeStateGuard::new(uninhabitable_perms(), "[]");

    // Read, glob, grep — all private data, only 1 uninhabitable_state component
    check_and_record(&guard, Operation::ReadFiles);
    check_and_record(&guard, Operation::GlobSearch);
    check_and_record(&guard, Operation::GrepSearch);
    assert_eq!(guard.accumulated_risk(), StateRisk::Low);

    // More reads are always fine
    assert!(guard.check(&Act::untargeted(Operation::ReadFiles)).is_ok());
}

#[test]
#[allow(deprecated)]
fn test_schema_pinning_detects_mutation() {
    let guard = RuntimeStateGuard::new(uninhabitable_perms(), r#"[{"name":"read"}]"#);

    // Same schema: OK
    let mut hasher = Sha256::new();
    hasher.update(r#"[{"name":"read"}]"#.as_bytes());
    let same_hash = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert!(guard.verify_schema(&same_hash).is_ok());

    // Different schema: rug-pull detected
    let mut hasher = Sha256::new();
    hasher.update(r#"[{"name":"read"},{"name":"evil"}]"#.as_bytes());
    let different_hash = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert!(guard.verify_schema(&different_hash).is_err());
}

#[test]
#[allow(deprecated)]
fn test_two_leg_uninhabitable_allows_exfil() {
    // If only 2 of 3 exposure legs are present in permissions,
    // exfil should be allowed (no uninhabitable_state constraint fires)
    use crate::CapabilityLevel;
    let mut perms = PermissionLattice::default();
    perms.capabilities.read_files = CapabilityLevel::Always;
    perms.capabilities.run_bash = CapabilityLevel::LowRisk;
    // No web_fetch — only 2 legs
    perms.uninhabitable_constraint = true;
    let perms = perms.normalize();

    let guard = RuntimeStateGuard::new(perms, "[]");

    check_and_record(&guard, Operation::ReadFiles);
    // RunBash should be allowed — no untrusted content present
    check_and_record(&guard, Operation::RunBash);
    assert_eq!(guard.accumulated_risk(), StateRisk::Medium);
}

// -----------------------------------------------------------------------
// ExposureSet monoid laws
// -----------------------------------------------------------------------

#[test]
fn test_exposure_set_identity() {
    let empty = ExposureSet::empty();
    let s = ExposureSet::singleton(ExposureLabel::PrivateData);

    // Left identity: empty ∪ s = s
    assert_eq!(empty.union(&s), s);
    // Right identity: s ∪ empty = s
    assert_eq!(s.union(&empty), s);
}

#[test]
fn test_exposure_set_associativity() {
    let a = ExposureSet::singleton(ExposureLabel::PrivateData);
    let b = ExposureSet::singleton(ExposureLabel::UntrustedContent);
    let c = ExposureSet::singleton(ExposureLabel::ExfilVector);

    // (a ∪ b) ∪ c = a ∪ (b ∪ c)
    assert_eq!(a.union(&b).union(&c), a.union(&b.union(&c)));
}

#[test]
fn test_exposure_set_idempotent() {
    let s = ExposureSet::singleton(ExposureLabel::PrivateData);
    // s ∪ s = s (semilattice: join is idempotent)
    assert_eq!(s.union(&s), s);
}

#[test]
fn test_exposure_set_commutative() {
    let a = ExposureSet::singleton(ExposureLabel::PrivateData);
    let b = ExposureSet::singleton(ExposureLabel::UntrustedContent);
    // a ∪ b = b ∪ a
    assert_eq!(a.union(&b), b.union(&a));
}

#[test]
fn test_exposure_set_uninhabitable_detection() {
    let mut exposure = ExposureSet::empty();
    assert!(!exposure.is_uninhabitable());
    assert_eq!(exposure.to_risk(), StateRisk::Safe);

    exposure = exposure.union(&ExposureSet::singleton(ExposureLabel::PrivateData));
    assert!(!exposure.is_uninhabitable());
    assert_eq!(exposure.to_risk(), StateRisk::Low);

    exposure = exposure.union(&ExposureSet::singleton(ExposureLabel::UntrustedContent));
    assert!(!exposure.is_uninhabitable());
    assert_eq!(exposure.to_risk(), StateRisk::Medium);

    exposure = exposure.union(&ExposureSet::singleton(ExposureLabel::ExfilVector));
    assert!(exposure.is_uninhabitable());
    assert_eq!(exposure.to_risk(), StateRisk::Uninhabitable);
}

#[test]
fn test_exposure_set_risk_grade_impl() {
    use crate::graded::RiskGrade;

    // Identity
    assert_eq!(ExposureSet::identity(), ExposureSet::empty());

    // Compose = union
    let a = ExposureSet::singleton(ExposureLabel::PrivateData);
    let b = ExposureSet::singleton(ExposureLabel::ExfilVector);
    let composed = a.compose(&b);
    assert!(composed.contains(ExposureLabel::PrivateData));
    assert!(composed.contains(ExposureLabel::ExfilVector));
    assert!(!composed.contains(ExposureLabel::UntrustedContent));

    // requires_intervention only at Complete
    assert!(!a.requires_intervention());
    assert!(!composed.requires_intervention());
    let full = composed.compose(&ExposureSet::singleton(ExposureLabel::UntrustedContent));
    assert!(full.requires_intervention());
}

#[test]
fn test_exposure_set_display() {
    assert_eq!(format!("{}", ExposureSet::empty()), "{}");
    assert_eq!(
        format!("{}", ExposureSet::singleton(ExposureLabel::PrivateData)),
        "{PrivateData}"
    );
    let full = ExposureSet::singleton(ExposureLabel::PrivateData)
        .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent))
        .union(&ExposureSet::singleton(ExposureLabel::ExfilVector));
    assert_eq!(
        format!("{}", full),
        "{PrivateData, UntrustedContent, ExfilVector}"
    );
}

#[test]
fn test_operation_exposure_classification() {
    // Private data leg
    assert_eq!(
        operation_exposure(Operation::ReadFiles),
        Some(ExposureLabel::PrivateData)
    );
    assert_eq!(
        operation_exposure(Operation::GlobSearch),
        Some(ExposureLabel::PrivateData)
    );
    assert_eq!(
        operation_exposure(Operation::GrepSearch),
        Some(ExposureLabel::PrivateData)
    );

    // Untrusted content leg
    assert_eq!(
        operation_exposure(Operation::WebFetch),
        Some(ExposureLabel::UntrustedContent)
    );
    assert_eq!(
        operation_exposure(Operation::WebSearch),
        Some(ExposureLabel::UntrustedContent)
    );

    // Exfil vector leg
    assert_eq!(
        operation_exposure(Operation::RunBash),
        Some(ExposureLabel::ExfilVector)
    );
    assert_eq!(
        operation_exposure(Operation::GitPush),
        Some(ExposureLabel::ExfilVector)
    );
    assert_eq!(
        operation_exposure(Operation::CreatePr),
        Some(ExposureLabel::ExfilVector)
    );

    // Local sinks are exfil legs too (most-paranoid #4).
    assert_eq!(
        operation_exposure(Operation::WriteFiles),
        Some(ExposureLabel::ExfilVector)
    );
    assert_eq!(
        operation_exposure(Operation::EditFiles),
        Some(ExposureLabel::ExfilVector)
    );
    assert_eq!(
        operation_exposure(Operation::GitCommit),
        Some(ExposureLabel::ExfilVector)
    );
    assert_eq!(
        operation_exposure(Operation::ManagePods),
        Some(ExposureLabel::ExfilVector)
    );
}

// -----------------------------------------------------------------------
// GradedExposureGuard tests
// -----------------------------------------------------------------------

#[test]
fn test_graded_exposure_guard_risk_accumulates() {
    let guard = GradedExposureGuard::new(uninhabitable_perms(), "[]");

    // Start at empty exposure
    assert_eq!(guard.exposure(), ExposureSet::empty());
    assert_eq!(guard.accumulated_risk(), StateRisk::Safe);

    // Read (private data)
    check_and_record(&guard, Operation::ReadFiles);
    assert!(guard.exposure().contains(ExposureLabel::PrivateData));
    assert_eq!(guard.accumulated_risk(), StateRisk::Low);

    // Fetch (untrusted content)
    check_and_record(&guard, Operation::WebFetch);
    assert!(guard.exposure().contains(ExposureLabel::UntrustedContent));
    assert_eq!(guard.accumulated_risk(), StateRisk::Medium);

    // RunBash (exfil) — BLOCKED: would uninhabitable_state
    let result = guard.check(&Act::untargeted(Operation::RunBash));
    assert!(
        result.is_err(),
        "RunBash should be blocked when completing uninhabitable_state"
    );
    assert_eq!(guard.accumulated_risk(), StateRisk::Medium);
}

#[test]
fn test_graded_exposure_guard_no_phantom_exposure() {
    let guard = GradedExposureGuard::new(uninhabitable_perms(), "[]");

    // check() alone does NOT expose the session (proofs are dropped)
    let _proof1 = guard.check(&Act::untargeted(Operation::ReadFiles)).unwrap();
    let _proof2 = guard.check(&Act::untargeted(Operation::WebFetch)).unwrap();
    assert_eq!(guard.exposure(), ExposureSet::empty());

    // Only execute_and_record exposures
    check_and_record(&guard, Operation::ReadFiles);
    assert!(guard.exposure().contains(ExposureLabel::PrivateData));
}

#[test]
fn test_graded_exposure_guard_local_sinks_are_exfil() {
    let guard = GradedExposureGuard::new(uninhabitable_perms(), "[]");

    // Local sinks now contribute the ExfilVector leg (most-paranoid #4):
    // writing/editing/committing is an exfiltration channel.
    check_and_record(&guard, Operation::WriteFiles);
    assert!(guard.exposure().contains(ExposureLabel::ExfilVector));
    check_and_record(&guard, Operation::EditFiles);
    check_and_record(&guard, Operation::GitCommit);
    assert!(guard.exposure().contains(ExposureLabel::ExfilVector));
}

#[test]
fn test_graded_exposure_guard_schema_pinning() {
    let guard = GradedExposureGuard::new(uninhabitable_perms(), r#"[{"name":"read"}]"#);

    // Same schema: OK
    let same_hash = {
        let mut h = Sha256::new();
        h.update(r#"[{"name":"read"}]"#.as_bytes());
        h.finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    assert!(guard.verify_schema(&same_hash).is_ok());

    // Mutated schema: rug-pull detected
    let evil_hash = {
        let mut h = Sha256::new();
        h.update(r#"[{"name":"read"},{"name":"evil_tool"}]"#.as_bytes());
        h.finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let result = guard.verify_schema(&evil_hash);
    assert!(result.is_err());
    if let Err(GuardError::Denied { reason }) = result {
        assert!(
            reason.contains("rug-pull"),
            "error should mention rug-pull: {reason}"
        );
    }
}

#[test]
#[allow(deprecated)]
fn test_graded_exposure_guard_agrees_with_runtime_guard() {
    // Both guards should make identical decisions
    let perms = uninhabitable_perms();
    let runtime = RuntimeStateGuard::new(perms.clone(), "[]");
    let graded = GradedExposureGuard::new(perms, "[]");

    let ops = vec![
        Operation::ReadFiles,
        Operation::GlobSearch,
        Operation::WebFetch,
    ];

    for op in &ops {
        let r1 = runtime.check(&Act::untargeted(*op));
        let r2 = graded.check(&Act::untargeted(*op));
        assert_eq!(r1.is_ok(), r2.is_ok(), "disagreement on {:?}", op);

        if let (Ok(p1), Ok(p2)) = (r1, r2) {
            runtime
                .execute_and_record(p1, || Ok::<_, String>(()))
                .unwrap();
            graded
                .execute_and_record(p2, || Ok::<_, String>(()))
                .unwrap();
        }
    }

    // Both should block RunBash now (uninhabitable_state complete)
    assert!(runtime.check(&Act::untargeted(Operation::RunBash)).is_err());
    assert!(graded.check(&Act::untargeted(Operation::RunBash)).is_err());

    // Both report same risk
    assert_eq!(runtime.accumulated_risk(), graded.accumulated_risk());
}

#[test]
fn test_graded_exposure_guard_as_graded_monad() {
    // Demonstrate the graded monad composition explicitly
    use crate::graded::{Graded, RiskGrade};

    let guard = GradedExposureGuard::new(uninhabitable_perms(), "[]");

    // Model each tool call as Graded<ExposureSet, Operation>
    let read_call = Graded::new(
        ExposureSet::singleton(ExposureLabel::PrivateData),
        Operation::ReadFiles,
    );
    let fetch_call = Graded::new(
        ExposureSet::singleton(ExposureLabel::UntrustedContent),
        Operation::WebFetch,
    );

    // Compose via >>= (and_then): exposure accumulates through the monoid
    let composed = read_call.and_then(|_| fetch_call);

    // The composed grade is the union of both exposure sets
    assert!(composed.grade.contains(ExposureLabel::PrivateData));
    assert!(composed.grade.contains(ExposureLabel::UntrustedContent));
    assert!(!composed.grade.contains(ExposureLabel::ExfilVector));
    assert_eq!(composed.grade.to_risk(), StateRisk::Medium);

    // Adding an exfil call would complete the uninhabitable_state
    let exfil_call = Graded::new(
        ExposureSet::singleton(ExposureLabel::ExfilVector),
        Operation::RunBash,
    );
    let full = composed.and_then(|_| exfil_call);
    assert!(full.grade.is_uninhabitable());
    assert!(full.grade.requires_intervention());

    // This is exactly what the guard does internally, but with
    // RwLock state instead of pure functional composition
    check_and_record(&guard, Operation::ReadFiles);
    check_and_record(&guard, Operation::WebFetch);
    assert!(guard.check(&Act::untargeted(Operation::RunBash)).is_err());
}

/// Clinejection attack (Feb 2026): prompt injection in a GitHub issue
/// triggers `npm install` via an AI coding assistant. The preinstall
/// hook exfiltrates credentials.
///
/// Portcullis must block this even WITHOUT a prior ReadFiles:
///   WebFetch(UntrustedContent) → RunBash(projected: PrivateData+ExfilVector)
///   = all 3 exposure legs → DENIED.
#[test]
fn test_clinejection_blocked() {
    let guard = GradedExposureGuard::new(uninhabitable_perms(), "[]");

    // Step 1: Read untrusted content (GitHub issue via WebFetch)
    check_and_record(&guard, Operation::WebFetch);

    // Step 2: Attempt RunBash (npm install from attacker).
    // RunBash projects PrivateData + ExfilVector (omnibus),
    // completing the uninhabitable_state with UntrustedContent.
    let result = guard.check(&Act::untargeted(Operation::RunBash));
    assert!(
        result.is_err(),
        "Clinejection: RunBash after WebFetch must be denied (omnibus projection)"
    );

    // The exposure should NOT have changed (check doesn't exposure)
    assert!(!guard.exposure().contains(ExposureLabel::PrivateData));
    assert!(!guard.exposure().contains(ExposureLabel::ExfilVector));
}

/// Verify that RunBash also triggers uninhabitable_state in the RuntimeStateGuard.
#[test]
#[allow(deprecated)]
fn test_clinejection_runtime_guard() {
    let perms = uninhabitable_perms();
    let guard = RuntimeStateGuard::new(perms, "[]");

    // WebFetch then RunBash — should uninhabitable_state
    check_and_record(&guard, Operation::WebFetch);

    let result = guard.check(&Act::untargeted(Operation::RunBash));
    assert!(
        result.is_err(),
        "Clinejection: RuntimeStateGuard must also block WebFetch → RunBash"
    );
}

/// Verify that execute_and_record does NOT record on closure failure
/// (no phantom exposure from failed operations).
#[test]
fn test_execute_and_record_no_phantom_on_failure() {
    let guard = GradedExposureGuard::new(uninhabitable_perms(), "[]");

    let proof = guard.check(&Act::untargeted(Operation::ReadFiles)).unwrap();
    let result = guard.execute_and_record(proof, || Err::<(), _>("io error"));
    assert!(result.is_err());

    // Exposure should be empty — failed operation not recorded
    assert_eq!(guard.exposure(), ExposureSet::empty());
    assert_eq!(guard.accumulated_risk(), StateRisk::Safe);
}

// -----------------------------------------------------------------------
// Audit H-3 — decision-lock poison ⇒ fail CLOSED (adversarial corpus)
//
// A stray panic while a thread holds the exposure write guard durably
// poisons the RwLock. The exposure accumulator is monotone-union (taint is
// only ever added), so recovering the torn guard via into_inner() could
// UNDER-COUNT taint and turn a required DENY into an ALLOW — a fail-open
// strictly worse than the original crash. These tests pin the fail-CLOSED
// contract: a poisoned DECISION lock ⇒ deny, never allow, never panic.
//
// NOTE: this fault-injection scenario cannot be expressed in the IFC-flow
// JSON attack corpus (tests/attack_corpus.json is source→sink flows only),
// so it lives here as the H-3 adversarial regression.
// -----------------------------------------------------------------------

/// Poison a lock by panicking while holding its write guard, in a way that
/// does not abort the test process. Returns once the lock is poisoned.
fn poison_write_lock<T>(lock: &RwLock<T>) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = lock.write().expect("first write should not be poisoned");
        panic!("intentional panic while holding write lock (H-3 fault injection)");
    }));
    assert!(result.is_err(), "the fault-injection closure must panic");
    assert!(lock.is_poisoned(), "the lock must now be poisoned");
}

#[test]
fn test_decision_lock_poison_denies_graded_check() {
    let guard = GradedExposureGuard::new(uninhabitable_perms(), "[]");

    // Adversary: poison the exposure DECISION lock.
    poison_write_lock(&guard.exposure);

    // check() MUST fail CLOSED: a Denied error — NOT a panic, NOT an allow,
    // NOT a torn-state allow. This assertion FAILS if someone swaps in
    // `into_inner()` on the decision lock (which would return Ok).
    match guard.check(&Act::untargeted(Operation::ReadFiles)) {
        Err(GuardError::Denied { reason }) => {
            assert!(
                reason.contains("poisoned"),
                "denial must cite the poisoned lock, got: {reason}"
            );
        }
        Err(other) => panic!("expected a fail-closed Denied, got {other:?}"),
        Ok(_) => panic!(
            "FAIL-OPEN REGRESSION: check() returned an ALLOW on a poisoned \
             decision lock — someone likely swapped in into_inner()"
        ),
    }

    // accumulated_risk() must also fail closed → MAXIMUM risk.
    assert_eq!(
        guard.accumulated_risk(),
        StateRisk::Uninhabitable,
        "poisoned decision lock must report maximum risk, never under-report"
    );

    // exposure() must fail closed → maximal (fully uninhabitable) set.
    assert!(
        guard.exposure().is_uninhabitable(),
        "poisoned exposure accessor must report maximal exposure"
    );
}

#[test]
#[allow(deprecated)]
fn test_decision_lock_poison_denies_runtime_check() {
    let guard = RuntimeStateGuard::new(uninhabitable_perms(), "[]");

    poison_write_lock(&guard.exposure);

    match guard.check(&Act::untargeted(Operation::ReadFiles)) {
        Err(GuardError::Denied { reason }) => {
            assert!(reason.contains("poisoned"), "got: {reason}");
        }
        Err(other) => panic!("expected fail-closed Denied, got {other:?}"),
        Ok(_) => panic!(
            "FAIL-OPEN REGRESSION: RuntimeStateGuard::check() allowed on a \
             poisoned decision lock (into_inner() must NOT be used here)"
        ),
    }

    assert_eq!(guard.accumulated_risk(), StateRisk::Uninhabitable);
}

#[test]
fn test_decision_lock_poison_execute_and_record_fails_closed() {
    let guard = GradedExposureGuard::new(uninhabitable_perms(), "[]");

    // Obtain a valid proof BEFORE poisoning (check reads the lock).
    let proof = guard
        .check(&Act::untargeted(Operation::ReadFiles))
        .expect("check should pass");

    // Now poison the exposure decision lock.
    poison_write_lock(&guard.exposure);

    // The closure runs, but recording cannot be proven consistent, so
    // execute_and_record must fail CLOSED with TocTouDenied — the caller
    // must treat the executed op as denied, never Ok.
    let result = guard.execute_and_record(proof, || Ok::<_, String>(()));
    match result {
        Err(ExecuteError::TocTouDenied { reason }) => {
            assert!(reason.contains("poisoned"), "got: {reason}");
        }
        Err(ExecuteError::OperationFailed(_)) => {
            panic!("closure succeeded; must not report OperationFailed")
        }
        Ok(_) => panic!(
            "FAIL-OPEN REGRESSION: execute_and_record returned Ok on a \
             poisoned decision lock (into_inner() must NOT be used here)"
        ),
    }
}

// -----------------------------------------------------------------------
// Exhaustive equivalence: RuntimeStateGuard ≡ GradedExposureGuard
//
// Now that RuntimeStateGuard delegates to exposure_core, both guards
// MUST produce identical check/deny/risk decisions for ALL operation
// permutations. This test checks every permutation of all 12 operations.
// -----------------------------------------------------------------------

/// All Operation variants for exhaustive testing.
const ALL_OPS: [Operation; 13] = [
    Operation::ReadFiles,
    Operation::WriteFiles,
    Operation::EditFiles,
    Operation::RunBash,
    Operation::GlobSearch,
    Operation::GrepSearch,
    Operation::WebSearch,
    Operation::WebFetch,
    Operation::GitCommit,
    Operation::GitPush,
    Operation::CreatePr,
    Operation::ManagePods,
    Operation::SpawnAgent,
];

/// Exhaustive equivalence test: for every possible operation sequence
/// (up to length 4), both guards produce identical decisions.
#[test]
#[allow(deprecated)]
fn test_guard_equivalence_exhaustive() {
    // Test all single-operation sequences
    for &op in &ALL_OPS {
        assert_guards_agree(&[op], &format!("[{:?}]", op));
    }

    // Test all 2-operation sequences (12 × 12 = 144)
    for &op1 in &ALL_OPS {
        for &op2 in &ALL_OPS {
            assert_guards_agree(&[op1, op2], &format!("[{:?}, {:?}]", op1, op2));
        }
    }

    // Test critical 3-operation sequences (uninhabitable-state-completing paths)
    let exposure_legs: [Operation; 6] = [
        Operation::ReadFiles,
        Operation::WebFetch,
        Operation::RunBash,
        Operation::GlobSearch,
        Operation::WebSearch,
        Operation::GitPush,
    ];
    for &op1 in &exposure_legs {
        for &op2 in &exposure_legs {
            for &op3 in &exposure_legs {
                assert_guards_agree(
                    &[op1, op2, op3],
                    &format!("[{:?}, {:?}, {:?}]", op1, op2, op3),
                );
            }
        }
    }
}

/// Helper: create both guards with uninhabitable_perms, feed the same
/// operations, and assert every observable produces identical results.
#[allow(deprecated)]
fn assert_guards_agree(ops: &[Operation], label: &str) {
    let perms = uninhabitable_perms();
    let runtime = RuntimeStateGuard::new(perms.clone(), "[]");
    let graded = GradedExposureGuard::new(perms, "[]");

    for (i, &op) in ops.iter().enumerate() {
        let r1 = runtime.check(&Act::untargeted(op));
        let r2 = graded.check(&Act::untargeted(op));

        assert_eq!(
            r1.is_ok(),
            r2.is_ok(),
            "Guard disagreement on check({:?}) at step {} of {}: runtime={}, graded={}",
            op,
            i,
            label,
            if r1.is_ok() { "allow" } else { "deny" },
            if r2.is_ok() { "allow" } else { "deny" },
        );

        // If both allow, record the operation in both
        if let (Ok(p1), Ok(p2)) = (r1, r2) {
            let e1 = runtime.execute_and_record(p1, || Ok::<_, String>(()));
            let e2 = graded.execute_and_record(p2, || Ok::<_, String>(()));
            assert_eq!(
                e1.is_ok(),
                e2.is_ok(),
                "Guard disagreement on execute({:?}) at step {} of {}",
                op,
                i,
                label,
            );
        }

        // Risk must always agree
        assert_eq!(
            runtime.accumulated_risk(),
            graded.accumulated_risk(),
            "Risk disagreement after step {} of {}: runtime={:?}, graded={:?}",
            i,
            label,
            runtime.accumulated_risk(),
            graded.accumulated_risk(),
        );
    }
}
