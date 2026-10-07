//! Exercise the real probe table and the engine's effects in isolated trees.
use super::*;

fn write(root: &Path, name: &str, text: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn harness(root: &Path, mode: Mode) -> Harness {
    Harness {
        root: root.into(),
        opts: Opts {
            mode,
            scope: ScopeKind::Full,
            base: String::new(),
            changed_files: None,
            plan: false,
        },
        scope: fixture_scope(ScopeKind::Full, "fixture", &[]),
        index: None,
        failures: 0,
        covered: 0,
        selected: 0,
        skipped: 0,
        baseline_seen: BTreeSet::new(),
        base_tree: None,
        base_cache: BTreeMap::new(),
        base_seconds: 0.0,
        main_red: BTreeMap::new(),
        stop: Arc::new(AtomicBool::new(false)),
    }
}

/// Copy the working tree's tracked inputs, not HEAD: a new perturbation must
/// be tested against the file it will actually change. No edits reach the source.
fn copy_tree() -> tempfile::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let files = git_ok(root, &["ls-files"]).unwrap();
    for name in files.lines() {
        let from = root.join(name);
        if from.is_file() {
            let to = dir.path().join(name);
            fs::create_dir_all(to.parent().unwrap()).unwrap();
            fs::copy(from, to).unwrap();
        }
    }
    assert!(git_ok(dir.path(), &["init", "-q"]).is_some());
    assert!(git_ok(dir.path(), &["add", "."]).is_some());
    dir
}

#[test]
fn every_real_probe_changes_its_subject_restores_it_and_is_accounted_for() {
    let tree = copy_tree();
    let root = tree.path();
    let index = Index::new(root).unwrap();
    assert!(
        selftest::run(root, &index),
        "input derivation must select the right probes"
    );
    let probes = table::probes();
    let mut h = harness(root, Mode::VacuityOnly);
    for probe in &probes {
        let before = fs::read(root.join(probe.target)).unwrap();
        let covered = h.covered;
        h.probe(probe);
        assert_eq!(h.failures, 0, "{}", probe.label());
        assert_eq!(h.covered, covered + 1, "{} must execute", probe.label());
        assert_eq!(
            fs::read(root.join(probe.target)).unwrap(),
            before,
            "{} must restore",
            probe.label()
        );
    }
    assert_eq!(account(&mut h, &probes), 0);
    // The domain is an observed set, not a hand-maintained count. A new gate
    // must fail accounting until a probe or explicit exemption accounts for it.
    write(root, "scripts/check-unaccounted-fixture.sh", "exit 0\n");
    write(
        root,
        ".github/workflows/unaccounted-fixture.yml",
        "steps:\n  - run: bash scripts/check-unaccounted-fixture.sh\n",
    );
    assert_eq!(account(&mut harness(root, Mode::Probe), &probes), 1);
    fs::remove_file(root.join("scripts/check-unaccounted-fixture.sh")).unwrap();
    fs::remove_file(root.join(".github/workflows/unaccounted-fixture.yml")).unwrap();
    assert_eq!(account(&mut harness(root, Mode::Probe), &probes), 0);
    // A SELF_FALSIFIED xtask row is a checked claim: with no workflow running its
    // `--self-test`, the row exempts a gate whose falsifier is gone, and accounting fails.
    let mut saved = Vec::new();
    for entry in fs::read_dir(root.join(".github/workflows")).unwrap() {
        let path = entry.unwrap().path();
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        if text.contains("lean-replay --self-test") {
            let gone = text.replace("lean-replay --self-test", "lean-replay --self-test-gone");
            fs::write(&path, gone).unwrap();
            saved.push((path, text));
        }
    }
    assert!(
        !saved.is_empty(),
        "no workflow runs lean-replay --self-test"
    );
    assert_eq!(account(&mut harness(root, Mode::Probe), &probes), 1);
    for (path, text) in saved {
        fs::write(path, text).unwrap();
    }
    assert_eq!(account(&mut harness(root, Mode::Probe), &probes), 0);
}

fn defect(_: &Path, _: &str) -> perturb::Perturbed {
    perturb::Perturbed {
        text: "red\n".into(),
        complaint: None,
    }
}

fn noop(_: &Path, text: &str) -> perturb::Perturbed {
    perturb::Perturbed {
        text: text.into(),
        complaint: None,
    }
}

fn fixture_probe(apply: perturb::PerturbFn) -> Probe {
    Probe {
        family: Family::Script {
            gate: "check-fixture.sh",
            flags: "--fixture",
        },
        target: "subject",
        desc: "a real changed subject",
        perturb: table::Perturbation {
            name: "fixture",
            apply,
        },
    }
}

#[test]
fn red_green_cycle_rejects_vacuous_always_green_and_already_red_gates() {
    let tree = tempfile::tempdir().unwrap();
    let root = tree.path();
    write(
        root,
        ".github/workflows/fixture.yml",
        "steps:\n  - run: bash scripts/check-fixture.sh --fixture\n",
    );
    write(root, "subject", "green\n");
    for (script, apply, failures, covered) in [
        (
            "test \"$(cat subject)\" = green\n",
            defect as perturb::PerturbFn,
            0,
            1,
        ),
        (
            "test \"$(cat subject)\" = green\n",
            noop as perturb::PerturbFn,
            1,
            0,
        ),
        ("exit 0\n", defect as perturb::PerturbFn, 1, 1),
        ("exit 1\n", defect as perturb::PerturbFn, 1, 0),
    ] {
        write(root, "scripts/check-fixture.sh", script);
        let mut h = harness(root, Mode::Probe);
        h.probe(&fixture_probe(apply));
        assert_eq!((h.failures, h.covered), (failures, covered), "{script}");
        assert_eq!(fs::read_to_string(root.join("subject")).unwrap(), "green\n");
    }
    write(root, "scripts/check-fixture.sh", "exit 0\n");
    let mut h = harness(root, Mode::BaselineOnly);
    h.probe(&fixture_probe(defect));
    h.probe(&fixture_probe(defect));
    assert_eq!(
        (h.failures, h.covered),
        (0, 1),
        "baseline runs each command once"
    );
    assert_eq!(fs::read_to_string(root.join("subject")).unwrap(), "green\n");
    fs::remove_file(root.join(".github/workflows/fixture.yml")).unwrap();
    let mut h = harness(root, Mode::Probe);
    h.probe(&fixture_probe(defect));
    assert_eq!(h.failures, 1, "a local gate absent from CI proves nothing");
}

#[test]
fn only_the_same_measured_red_on_a_real_base_tree_is_exempted() {
    for (base_script, expected_failures, expected_exemptions) in [
        (Some("exit 1\n"), 0, 1),
        (Some("exit 0\n"), 1, 0),
        (Some("exit 2\n"), 1, 0),
        (Some("exit 127\n"), 1, 0),
        (None, 1, 0),
    ] {
        let tree = tempfile::tempdir().unwrap();
        let root = tree.path();
        write(root, "subject", "green\n");
        write(
            root,
            ".github/workflows/fixture.yml",
            "steps:\n  - run: bash scripts/check-fixture.sh --fixture\n",
        );
        if let Some(script) = base_script {
            write(root, "scripts/check-fixture.sh", script);
        }
        assert!(git_ok(root, &["init", "-q"]).is_some());
        assert!(git_ok(root, &["add", "."]).is_some());
        assert!(
            git_ok(
                root,
                &[
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-qm",
                    "base"
                ]
            )
            .is_some()
        );
        let sha = git_ok(root, &["rev-parse", "HEAD"]).unwrap();
        write(root, "scripts/check-fixture.sh", "exit 1\n");
        let mut h = harness(root, Mode::Probe);
        h.scope.main = MainRef::Known(sha.trim().into());
        h.probe(&fixture_probe(defect));
        assert_eq!(h.failures, expected_failures, "base={base_script:?}");
        assert_eq!(
            h.main_red.len(),
            expected_exemptions,
            "base={base_script:?}"
        );
        assert_eq!(h.covered, 0, "an already-red gate has not been proved");
        assert_eq!(h.base_cache.len(), 1);
        h.probe(&fixture_probe(defect));
        assert_eq!(h.failures, 2 * expected_failures);
        assert_eq!(
            h.main_red.len(),
            expected_exemptions,
            "one annotation per base gate"
        );
        assert_eq!(fs::read_to_string(root.join("subject")).unwrap(), "green\n");
        drop(h);
        let worktrees = git_ok(root, &["worktree", "list", "--porcelain"]).unwrap();
        assert_eq!(
            worktrees
                .lines()
                .filter(|l| l.starts_with("worktree "))
                .count(),
            1,
            "the temporary base checkout must be removed on every verdict"
        );
    }
}

#[test]
fn every_probe_family_refuses_absent_ci_wiring_before_touching_the_subject() {
    let tree = tempfile::tempdir().unwrap();
    let root = tree.path();
    write(root, "subject", "green\n");
    for family in [
        Family::Script {
            gate: "check-fixture.sh",
            flags: "--fixture",
        },
        Family::Xtask { sub: "fixture" },
        Family::XtaskFlagged {
            sub: "fixture",
            flags: "--strict",
        },
        Family::XtaskPartial {
            sub: "fixture",
            ci_flags: "--strict",
            marker: "defect",
        },
        Family::XtaskGenerated {
            sub: "fixture",
            ci_flags: "--input generated",
            generated: &[],
        },
    ] {
        let mut probe = fixture_probe(defect);
        probe.family = family;
        let mut h = harness(root, Mode::VacuityOnly);
        h.probe(&probe);
        assert_eq!((h.failures, h.covered), (1, 0), "{}", probe.label());
        assert_eq!(fs::read_to_string(root.join("subject")).unwrap(), "green\n");
    }
}
