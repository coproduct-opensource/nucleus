//! The two properties the compiler exists for, over a goal corpus and every
//! canonical ceiling:
//!
//! 1. **Clamped**: the compiled lattice is ≤ the ceiling, always.
//! 2. **Fail-closed**: unrecognised goals and out-of-ceiling proposals are
//!    reported, never granted.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use nucleus_task_compiler::{
    CompileError, CompileInput, EffectProposer, ExternalCommandProposer, LimitOverrides,
    RuleProposer, compile,
};
use portcullis::profile::ProfileRegistry;
use portcullis::{CapabilityLevel, EffectCatalog, EffectId, Operation, WeakeningCostConfig};

const GOALS: &[&str] = &[
    "fix the failing CI build",
    "fix the flaky test in the keystore",
    "upgrade axum and fix the tests",
    "add a --json flag to the status command",
    "refactor the parser into a separate module",
    "run the tests and report what fails",
    "make clippy happy",
    "update the README for the new CLI",
    "investigate why the build is slow",
    "review the open pull requests",
    "open a PR with the fix",
    "merge the dependency PR",
    "comment on issue 42 with the root cause",
    "explain what the kernel does",
    "implement the feature described in issue 17",
];

fn repo_with_ci_and_github() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='x'\nversion='0.1.0'\n",
    )
    .unwrap();
    fs::create_dir_all(root.join(".github/workflows")).unwrap();
    fs::write(root.join(".github/workflows/ci.yml"), "on: push\n").unwrap();
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::write(
        root.join(".git/config"),
        "[remote \"origin\"]\n\turl = https://github.com/acme/widgets.git\n",
    )
    .unwrap();
    dir
}

fn ceilings() -> Vec<(String, portcullis::PermissionLattice)> {
    let registry = ProfileRegistry::canonical().unwrap();
    let mut names: Vec<String> = registry.names().iter().map(|s| s.to_string()).collect();
    names.sort();
    names
        .into_iter()
        .map(|n| {
            let l = registry.resolve(&n).unwrap();
            (n, l)
        })
        .collect()
}

#[test]
fn every_goal_under_every_ceiling_is_clamped_and_attributed() {
    let dir = repo_with_ci_and_github();
    let ctx = nucleus_task_compiler::probe(dir.path()).unwrap();
    let catalog = EffectCatalog::builtin().unwrap();
    let cost = WeakeningCostConfig::default();
    let rules = RuleProposer;
    let proposers: [&dyn EffectProposer; 1] = [&rules];
    let explicit = BTreeSet::new();

    for goal in GOALS {
        for (name, ceiling) in ceilings() {
            let result = compile(CompileInput {
                goal,
                ctx: &ctx,
                catalog: &catalog,
                ceiling_profile: &name,
                ceiling: &ceiling,
                proposers: &proposers,
                explicit: &explicit,
                limits: LimitOverrides::default(),
                cost_config: &cost,
            });
            let grant = match result {
                Ok(g) => g,
                Err(CompileError::NothingWithinCeiling { .. }) => continue,
                Err(e) => panic!("{goal:?} under {name}: {e}"),
            };
            assert!(
                grant.lattice.leq(&ceiling),
                "{goal:?} under {name}: grant is not ≤ ceiling"
            );
            assert!(grant.assert_within(&ceiling).is_ok());
            for id in &grant.can {
                assert!(catalog.get(id).is_some(), "granted unknown effect {id}");
            }
            // Everything proposed is either in `can` or in `cannot`, never lost.
            let proposed = nucleus_task_compiler::apply(goal, &ctx).effects;
            for id in &proposed {
                let in_can = grant.can.contains(id);
                let in_cannot = grant.cannot.iter().any(|c| &c.id == id);
                assert!(
                    in_can ^ in_cannot,
                    "{id} under {name}: must be in exactly one of can/cannot"
                );
            }
            // Hosts come only from granted effects.
            for h in &grant.limits.hosts {
                assert!(
                    grant
                        .can
                        .iter()
                        .any(|id| catalog.get(id).unwrap().hosts.contains(h)),
                    "host {h} not vouched for by a granted effect"
                );
            }
            assert_eq!(grant.goal_digest, portcullis::TaskGrant::digest_goal(goal));
        }
    }
}

#[test]
fn fix_ci_under_safe_pr_fixer_reads_logs_but_cannot_publish() {
    let dir = repo_with_ci_and_github();
    let ctx = nucleus_task_compiler::probe(dir.path()).unwrap();
    let catalog = EffectCatalog::builtin().unwrap();
    let registry = ProfileRegistry::canonical().unwrap();
    let ceiling = registry.resolve("safe-pr-fixer").unwrap();
    let rules = RuleProposer;
    let proposers: [&dyn EffectProposer; 1] = [&rules];
    let grant = compile(CompileInput {
        goal: "fix the failing CI build",
        ctx: &ctx,
        catalog: &catalog,
        ceiling_profile: "safe-pr-fixer",
        ceiling: &ceiling,
        proposers: &proposers,
        explicit: &BTreeSet::new(),
        limits: LimitOverrides::default(),
        cost_config: &WeakeningCostConfig::default(),
    })
    .unwrap();
    let id = |s: &str| s.parse::<EffectId>().unwrap();
    assert!(grant.can.contains(&id("github/read-ci-logs")));
    assert!(grant.can.contains(&id("shell/run-tests")));
    assert!(grant.can.contains(&id("fs/edit-workspace")));
    assert!(!grant.can.contains(&id("github/open-pr")));
    assert_eq!(
        grant.lattice.capabilities.level_for(Operation::GitPush),
        CapabilityLevel::Never
    );
    assert_eq!(
        grant.lattice.capabilities.level_for(Operation::CreatePr),
        CapabilityLevel::Never
    );
    assert_eq!(grant.limits.hosts, vec!["api.github.com".to_string()]);
    assert!(
        grant
            .provenance
            .rules_fired
            .contains(&"ci-logs".to_string())
    );
    let text = portcullis::render_grant(&grant, &catalog, portcullis::Disclosure::Plain);
    assert!(text.contains("read CI logs"), "{text}");
    assert!(text.contains("push to remote branches"), "{text}");
}

#[test]
fn unrecognised_goal_fails_closed() {
    let dir = repo_with_ci_and_github();
    let ctx = nucleus_task_compiler::probe(dir.path()).unwrap();
    let catalog = EffectCatalog::builtin().unwrap();
    let registry = ProfileRegistry::canonical().unwrap();
    let ceiling = registry.resolve("codegen").unwrap();
    let rules = RuleProposer;
    let proposers: [&dyn EffectProposer; 1] = [&rules];
    let err = compile(CompileInput {
        goal: "hello there",
        ctx: &ctx,
        catalog: &catalog,
        ceiling_profile: "codegen",
        ceiling: &ceiling,
        proposers: &proposers,
        explicit: &BTreeSet::new(),
        limits: LimitOverrides::default(),
        cost_config: &WeakeningCostConfig::default(),
    })
    .unwrap_err();
    assert!(
        matches!(err, CompileError::NothingRecognised { .. }),
        "{err}"
    );
}

#[test]
fn a_greedy_external_proposer_is_clamped_and_unknown_effects_dropped() {
    let dir = repo_with_ci_and_github();
    let ctx = nucleus_task_compiler::probe(dir.path()).unwrap();
    let catalog = EffectCatalog::builtin().unwrap();
    let registry = ProfileRegistry::canonical().unwrap();
    let ceiling = registry.resolve("safe-pr-fixer").unwrap();
    let fixture: PathBuf =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/greedy-proposer.sh");
    let greedy = ExternalCommandProposer { program: fixture };
    let proposers: [&dyn EffectProposer; 1] = [&greedy];
    let grant = compile(CompileInput {
        goal: "anything at all",
        ctx: &ctx,
        catalog: &catalog,
        ceiling_profile: "safe-pr-fixer",
        ceiling: &ceiling,
        proposers: &proposers,
        explicit: &BTreeSet::new(),
        limits: LimitOverrides::default(),
        cost_config: &WeakeningCostConfig::default(),
    })
    .unwrap();
    let id = |s: &str| s.parse::<EffectId>().unwrap();
    assert!(grant.can.contains(&id("fs/read-workspace")));
    for wide in ["github/merge-pr", "github/open-pr", "git/push-branch"] {
        assert!(!grant.can.contains(&id(wide)), "{wide} must be clipped");
        assert!(
            grant.cannot.iter().any(|c| c.id == id(wide)),
            "{wide} must be reported"
        );
    }
    assert!(grant.lattice.leq(&ceiling));
    assert!(grant.provenance.proposers[0].starts_with("external:"));
    assert!(
        grant
            .provenance
            .rules_fired
            .iter()
            .any(|r| r.contains("github/delete-repo"))
    );
}

#[test]
fn limit_overrides_only_tighten() {
    let dir = repo_with_ci_and_github();
    let ctx = nucleus_task_compiler::probe(dir.path()).unwrap();
    let catalog = EffectCatalog::builtin().unwrap();
    let registry = ProfileRegistry::canonical().unwrap();
    let ceiling = registry.resolve("codegen").unwrap();
    let rules = RuleProposer;
    let proposers: [&dyn EffectProposer; 1] = [&rules];
    let grant = compile(CompileInput {
        goal: "fix the tests",
        ctx: &ctx,
        catalog: &catalog,
        ceiling_profile: "codegen",
        ceiling: &ceiling,
        proposers: &proposers,
        explicit: &BTreeSet::new(),
        limits: LimitOverrides {
            max_cost_usd: Some(rust_decimal::Decimal::new(100_000, 2)),
            duration_hours: Some(1000),
        },
        cost_config: &WeakeningCostConfig::default(),
    })
    .unwrap();
    assert!(grant.limits.max_cost_usd <= ceiling.budget.max_cost_usd);
    assert!(grant.not_after <= ceiling.time.valid_until);
}
