//! Two things named `release` must not grant different permissions.
//!
//! # The debt this closes
//!
//! Nucleus resolves a profile name two ways, and they are different code:
//!
//!   * the **YAML registry** — ten files under `portcullis/profiles/`, which is
//!     what a pod spec's `policy: {type: profile, name: …}` actually hits;
//!   * **`PermissionLattice` constructors** — about twenty associated functions,
//!     reached from Rust and used by the CTF engine and the test suite.
//!
//! Six names exist in both. `nucleus-spec`'s resolver tries the registry first
//! and calls the constructors a "legacy fallback", so for those six the
//! constructor arm is unreachable — and nothing checked that the two agreed.
//!
//! They did not. `spawn_agent`, the most escalation-prone capability there is:
//!
//! ```text
//!                    YAML     hardcoded
//!   release          Never    Always
//!   safe-pr-fixer    Never    LowRisk
//! ```
//!
//! `PermissionLattice::release()` granted **unrestricted agent spawning** while
//! `profile: release` in a pod spec forbade it entirely. Same name, opposite
//! answer, five months apart: #391 (2026-03-31) added `spawn_agent` to the
//! hardcoded lattices and never touched the YAML, which kept the field's
//! `Never` default.
//!
//! Neither profile's own documentation mentions spawning agents —
//! `safe-pr-fixer` says the agent "CANNOT push or create PRs", a constraint a
//! spawned sub-agent could route around — so `Never` was the documented intent
//! and the constructors were corrected to match, not the other way round.
//!
//! # Why a test rather than one source of truth
//!
//! Deriving the constructors from the YAML would be better and is not what this
//! does: the constructors are `fn`s that predate the registry and are called
//! directly across the workspace. This pins the agreement so the two cannot
//! drift again, which is the property that was actually missing.

use portcullis::profile::ProfileRegistry;
use portcullis::PermissionLattice;

/// Every name that exists in BOTH namespaces, with its constructor.
fn overlapping() -> Vec<(&'static str, PermissionLattice)> {
    vec![
        ("codegen", PermissionLattice::codegen()),
        ("read-only", PermissionLattice::read_only()),
        ("local-dev", PermissionLattice::local_dev()),
        ("code-review", PermissionLattice::code_review()),
        ("release", PermissionLattice::release()),
        ("safe-pr-fixer", PermissionLattice::safe_pr_fixer()),
    ]
}

/// The property: a name means one thing.
#[test]
fn a_name_grants_the_same_capabilities_from_yaml_and_from_rust() {
    let registry = ProfileRegistry::default();
    let mut disagree = Vec::new();

    for (name, hardcoded) in overlapping() {
        let from_yaml = registry
            .resolve(name)
            .unwrap_or_else(|e| panic!("`{name}` is expected in the YAML registry: {e}"));
        let y = format!("{:?}", from_yaml.capabilities);
        let h = format!("{:?}", hardcoded.capabilities);
        if y != h {
            disagree.push(format!("{name}\n     yaml: {y}\n     rust: {h}"));
        }
    }

    assert!(
        disagree.is_empty(),
        "these names grant different capabilities depending on which resolver \
         you reach them through — a pod spec gets the YAML, Rust callers get the \
         constructor:\n  {}",
        disagree.join("\n  ")
    );
}

/// Non-vacuity: the check must actually be comparing something. An empty
/// `overlapping()` or a registry that resolved nothing would make the test above
/// pass while checking no names at all.
#[test]
fn the_parity_check_covers_every_shared_name() {
    let registry = ProfileRegistry::default();
    let names: Vec<String> = registry.names().iter().map(|s| s.to_string()).collect();
    let covered: Vec<&str> = overlapping().iter().map(|(n, _)| *n).collect();

    assert!(
        covered.len() >= 6,
        "expected at least the six known shared names, got {}",
        covered.len()
    );
    for n in &covered {
        assert!(
            names.iter().any(|r| r == n),
            "`{n}` is in the parity list but not in the registry — the list has \
             gone stale and the check is weaker than it looks"
        );
    }
}

/// The specific regression, pinned by name so a future edit to either side
/// fails with the reason rather than a diff of two long Debug strings.
#[test]
fn neither_release_nor_safe_pr_fixer_grants_agent_spawning() {
    use portcullis::CapabilityLevel;
    let registry = ProfileRegistry::default();
    for name in ["release", "safe-pr-fixer"] {
        assert_eq!(
            registry.resolve(name).unwrap().capabilities.spawn_agent,
            CapabilityLevel::Never,
            "`{name}` must not permit spawning a sub-agent: its own documentation \
             enumerates what the agent may do and spawning is not in it, and a \
             sub-agent is a route around the constraints that are"
        );
    }
    assert_eq!(
        PermissionLattice::release().capabilities.spawn_agent,
        CapabilityLevel::Never
    );
    assert_eq!(
        PermissionLattice::safe_pr_fixer().capabilities.spawn_agent,
        CapabilityLevel::Never
    );
}
