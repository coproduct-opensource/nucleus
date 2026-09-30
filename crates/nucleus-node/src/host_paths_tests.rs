use super::*;

/// A node state dir laid out as provisioning makes it: the CA under the state
/// dir beside the per-node roots, and an installed artifacts dir elsewhere.
struct Node {
    state: tempfile::TempDir,
    roots: Roots,
    ca_key: PathBuf,
}

impl Node {
    fn artifacts(&self) -> &Path {
        &self.roots.artifacts
    }
}

fn node() -> Node {
    let state = tempfile::tempdir().expect("state dir");
    let artifacts = state.path().join("installed-artifacts");
    std::fs::create_dir_all(&artifacts).expect("artifacts dir");
    let roots = HostPathArgs {
        scratch_root: None,
        artifacts_root: artifacts,
        data_root: None,
        workspace_root: None,
        image_root: None,
    }
    .ensure(state.path())
    .expect("roots");
    let ca = state.path().join("ca");
    std::fs::create_dir_all(&ca).expect("ca dir");
    let ca_key = ca.join("ca.key");
    std::fs::write(&ca_key, b"-----BEGIN PRIVATE KEY-----").expect("ca key");
    Node {
        state,
        roots,
        ca_key,
    }
}

fn put(dir: &Path, name: &str) -> PathBuf {
    std::fs::create_dir_all(dir).expect("dir");
    let p = dir.join(name);
    std::fs::write(&p, name.as_bytes()).expect("file");
    p
}

/// A spec whose kernel and rootfs are legitimate installed artifacts, so each
/// test varies exactly one path.
fn pod(n: &Node) -> PodSpec {
    let mut spec: PodSpec = serde_json::from_str(
        r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"image":{
            "kernel_path":"/k","rootfs_path":"/r"}}}"#,
    )
    .expect("minimal spec");
    let image = spec.spec.image.as_mut().expect("image");
    image.kernel_path = put(n.artifacts(), "vmlinux");
    image.rootfs = RootfsSource::Path(put(n.artifacts(), "rootfs.ext4"));
    spec
}

fn image(spec: &PodSpec) -> &ImageSpec {
    spec.spec.image.as_ref().expect("image")
}

const FC: DriverKind = DriverKind::Firecracker;

/// THE defect, red on the parent commit: the node's CA key named as a pod's
/// read-only data disk — attached to the guest as a readable drive — was admitted
/// (so was `/etc/shadow` as kernel and rootfs).
#[test]
fn a_node_ca_key_is_refused_as_data() {
    let n = node();
    let mut spec = pod(&n);
    spec.spec.image.as_mut().expect("image").data_path = Some(n.ca_key.clone());
    let err = admit(&mut spec, &FC, &n.roots).expect_err("the CA key must never be a guest disk");
    assert!(matches!(err, ApiError::InvalidSpec(_)), "{err:?}");
    assert!(err.to_string().contains("image.data_path"), "{err}");
    assert!(err.to_string().contains("--data-root"), "{err}");
}

#[test]
fn a_node_ca_key_is_refused_as_scratch() {
    let n = node();
    let mut spec = pod(&n);
    spec.spec.image.as_mut().expect("image").scratch_path = Some(n.ca_key.clone());
    let err = admit(&mut spec, &FC, &n.roots).expect_err("refused");
    assert!(err.to_string().contains("--scratch-root"), "{err}");
}

#[test]
fn a_kernel_outside_the_artifacts_root_is_refused() {
    let n = node();
    for outside in [n.ca_key.clone(), put(n.state.path(), "vmlinux")] {
        let mut spec = pod(&n);
        spec.spec.image.as_mut().expect("image").kernel_path = outside;
        let err = admit(&mut spec, &FC, &n.roots).expect_err("refused");
        assert!(err.to_string().contains("--artifacts-root"), "{err}");
    }
}

#[test]
fn a_rootfs_symlink_escaping_the_artifacts_root_is_refused() {
    let n = node();
    let link = n.artifacts().join("innocent.ext4");
    std::os::unix::fs::symlink(&n.ca_key, &link).expect("symlink");
    let refusal = confine(&link, Role::Rootfs, &n.roots).expect_err("a symlink out must not pass");
    assert!(
        matches!(refusal.reason, Reason::Outside { .. }),
        "{refusal:?}"
    );
    // The same symlink as data: a different root, the same answer.
    let refusal = confine(&link, Role::Data, &n.roots).expect_err("refused");
    assert!(
        matches!(refusal.reason, Reason::Outside { .. }),
        "{refusal:?}"
    );
}

/// Every role, so a role added without this check is visible here.
const ALL_ROLES: [Role; 8] = [
    Role::Kernel,
    Role::Rootfs,
    Role::ImportedRootfs,
    Role::Scratch,
    Role::Data,
    Role::SeccompFilter,
    Role::ContainerWorkDir,
    Role::Cgroup,
];

#[test]
fn every_role_refuses_a_parent_component_even_landing_inside() {
    // Exhaustive: a new role fails to compile until it is listed above.
    let _listed = |r: Role| match r {
        Role::Kernel
        | Role::Rootfs
        | Role::ImportedRootfs
        | Role::Scratch
        | Role::Data
        | Role::SeccompFilter
        | Role::ContainerWorkDir
        | Role::Cgroup => (),
    };
    let n = node();
    for role in ALL_ROLES {
        let root = n.roots.get(role.root());
        let dotted = root.join("sub").join("..").join("x");
        let escaping = root.join("..").join("ca").join("ca.key");
        for p in [dotted, escaping] {
            let refusal = confine(&p, role, &n.roots).expect_err("`..` refused");
            assert!(
                matches!(refusal.reason, Reason::ParentComponent(_)),
                "{role:?}: {refusal:?}"
            );
        }
    }
}

/// Non-vacuity: legitimate paths in each root are admitted, the spec then names
/// the resolved paths, and `image_identity`'s digest pins still hold against those
/// rewritten paths — and still refuse a mismatch.
#[tokio::test]
async fn legitimate_paths_are_admitted_resolved_and_still_digest_checked() {
    let n = node();
    let mut spec = pod(&n);
    let scratch = put(&n.roots.scratch, "workspace.ext4");
    let data = put(&n.roots.data, "corpus.img");
    {
        let image = spec.spec.image.as_mut().expect("image");
        image.scratch_path = Some(scratch.clone());
        image.data_path = Some(data.clone());
    }
    admit(&mut spec, &FC, &n.roots).expect("all four are inside their roots");
    let admitted = image(&spec);
    let canon = |p: &Path| p.canonicalize().expect("canonical");
    assert_eq!(admitted.kernel_path, canon(&n.artifacts().join("vmlinux")));
    assert_eq!(
        admitted.rootfs,
        RootfsSource::Path(canon(&n.artifacts().join("rootfs.ext4")))
    );
    assert_eq!(admitted.scratch_path, Some(canon(&scratch)));
    assert_eq!(admitted.data_path, Some(canon(&data)));

    let pin = |p: &Path, bytes: &[u8]| {
        std::fs::write(p, bytes).expect("rewrite");
        let hex = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes));
        nucleus_spec::ArtifactDigest::parse(&format!("sha-256:{hex}")).expect("digest")
    };
    let mut pinned = admitted.clone();
    pinned.kernel_digest = Some(pin(&pinned.kernel_path, b"kernel"));
    pinned.data_digest = Some(pin(pinned.data_path.as_ref().expect("data"), b"corpus"));
    let host = |i: &ImageSpec| crate::rootfs_source::HostImage::resolve(i).expect("a path rootfs");
    crate::image_identity::verify(&host(&pinned), None)
        .await
        .expect("pins hold against the admitted paths");
    pinned.data_digest = Some(pin(&n.state.path().join("other"), b"another corpus"));
    let err = crate::image_identity::verify(&host(&pinned), None)
        .await
        .expect_err("a mismatched data pin is still refused");
    assert!(err.contains("data"), "{err}");
}

#[test]
fn a_container_work_dir_must_be_a_directory_inside_the_workspace_root() {
    let n = node();
    let container = DriverKind::Container;
    // The state dir (which holds the CA), the host root, and the old default.
    for outside in [
        n.state.path().to_path_buf(),
        PathBuf::from("/"),
        PathBuf::from("."),
    ] {
        let mut spec = pod(&n);
        spec.spec.work_dir = outside.clone();
        let err = admit(&mut spec, &container, &n.roots).expect_err("refused");
        assert!(
            err.to_string().contains("--workspace-root"),
            "{outside:?}: {err}"
        );
    }
    let mut spec = pod(&n);
    spec.spec.work_dir = put(&n.roots.workspace, "a-file");
    let err = admit(&mut spec, &container, &n.roots).expect_err("a file is not a workspace");
    assert!(err.to_string().contains("not a directory"), "{err}");

    let ws = n.roots.workspace.join("pod-a");
    std::fs::create_dir_all(&ws).expect("ws");
    let mut spec = pod(&n);
    spec.spec.work_dir = ws.clone();
    admit(&mut spec, &container, &n.roots).expect("a workspace directory is admitted");
    assert_eq!(spec.spec.work_dir, ws.canonicalize().expect("canonical"));

    // Under Firecracker, work_dir is a guest path and is left alone.
    let mut spec = pod(&n);
    spec.spec.work_dir = PathBuf::from("/work");
    admit(&mut spec, &FC, &n.roots).expect("guest path");
    assert_eq!(spec.spec.work_dir, PathBuf::from("/work"));
}

#[test]
fn a_custom_seccomp_filter_comes_from_the_artifacts_root() {
    let n = node();
    let mut spec = pod(&n);
    spec.spec.seccomp = Some(SeccompSpec::Custom {
        filter_path: n.ca_key.clone(),
    });
    let err = admit(&mut spec, &FC, &n.roots).expect_err("refused");
    assert!(err.to_string().contains("seccomp.filter_path"), "{err}");
    let filter = put(n.artifacts(), "filter.bpf");
    spec.spec.seccomp = Some(SeccompSpec::Custom {
        filter_path: filter.clone(),
    });
    admit(&mut spec, &FC, &n.roots).expect("inside the artifacts root");
}

#[test]
fn cgroup_placement_stays_under_the_cgroup_filesystem() {
    let n = node();
    let cg = |path: &str, file: &str| CgroupSpec {
        path: PathBuf::from(path),
        settings: vec![nucleus_spec::CgroupSetting {
            file: file.to_string(),
            value: "1".to_string(),
        }],
    };
    for (bad, file) in [
        ("/etc", "cpu.max"),
        ("/sys/fs/cgroup", "cpu.max"),
        ("sys/fs/cgroup/x", "cpu.max"),
        ("/sys/fs/cgroup/nucleus/../../../etc", "cpu.max"),
        ("/sys/fs/cgroup/nucleus/pod-1", "../../../etc/passwd"),
        ("/sys/fs/cgroup/nucleus/pod-1", "a/b"),
        ("/sys/fs/cgroup/nucleus/pod-1", "/etc/passwd"),
    ] {
        let mut spec = pod(&n);
        spec.spec.cgroup = Some(cg(bad, file));
        admit(&mut spec, &FC, &n.roots).expect_err(&format!("{bad} / {file} refused"));
    }
    let mut spec = pod(&n);
    spec.spec.cgroup = Some(cg("/sys/fs/cgroup/nucleus/pod-1", "cpu.max"));
    admit(&mut spec, &FC, &n.roots).expect("a cgroup under the cgroup fs is admitted");
}

#[test]
fn an_absent_artifacts_root_admits_no_microvm() {
    let mut n = node();
    let mut spec = pod(&n);
    n.roots.artifacts = n.state.path().join("never-installed");
    let err = admit(&mut spec, &FC, &n.roots).expect_err("nothing can be inside a missing root");
    assert!(err.to_string().contains("--artifacts-root"), "{err}");
}

#[test]
fn the_root_itself_a_directory_and_a_missing_file_are_refused() {
    let n = node();
    let r = |p: &Path| confine(p, Role::Kernel, &n.roots).map_err(|e| e.reason);
    assert!(matches!(r(n.artifacts()), Err(Reason::Outside { .. })));
    std::fs::create_dir_all(n.artifacts().join("dir")).expect("dir");
    assert!(matches!(
        r(&n.artifacts().join("dir")),
        Err(Reason::WrongShape(_))
    ));
    assert!(matches!(
        r(&n.artifacts().join("missing")),
        Err(Reason::Unresolvable { .. })
    ));
}

#[test]
fn a_spec_without_host_paths_is_untouched() {
    let n = node();
    let mut spec: PodSpec =
        serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#)
            .expect("minimal spec");
    admit(&mut spec, &FC, &n.roots).expect("nothing to confine");
    assert!(spec.spec.image.is_none());
}

/// The default artifacts root IS the directory `nucleus setup` installs into —
/// the same constant, not a copy of it.
#[test]
fn the_default_artifacts_root_is_the_provisioned_one() {
    use clap::Parser;
    let args = crate::Args::try_parse_from([
        "nucleus-node",
        "--proxy-auth-secret=test",
        "--proxy-approval-secret=test",
    ])
    .expect("defaults parse");
    assert_eq!(
        args.host_paths.artifacts_root,
        Path::new(nucleus_spec::tier2_artifacts::HOST_ARTIFACTS_DIR)
    );
}

/// Every example pod spec with an image is admitted under the flags its docs
/// give: `./build/firecracker/...` under `--artifacts-root ./build/firecracker
/// --scratch-root ./build/firecracker`, an absolute path under the provisioned
/// layout. Each tree is rebuilt under a temp dir, since the node's own working
/// directory is ambient state a test must not move.
#[test]
fn the_repositorys_example_specs_are_admitted_under_their_documented_flags() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let mut yamls = Vec::new();
    let mut dirs = vec![examples];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("examples dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                yamls.push(path);
            }
        }
    }
    let mut admitted = 0;
    for yaml in yamls {
        let text = std::fs::read_to_string(&yaml).expect("read");
        let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&text) else {
            continue;
        };
        let Some(img) = doc.get("spec").and_then(|s| s.get("image")) else {
            continue;
        };
        let field = |k: &str| img.get(k).and_then(|v| v.as_str()).map(PathBuf::from);
        let t = tempfile::tempdir().expect("tree");
        let host = |p: &Path| {
            let rel = p.strip_prefix("/").unwrap_or(p);
            let h = t.path().join(rel);
            std::fs::create_dir_all(h.parent().expect("parent")).expect("dirs");
            std::fs::write(&h, b"x").expect("file");
            h
        };
        let kernel = field("kernel_path").expect("an image names a kernel");
        let (artifacts, scratch) = if kernel.is_relative() {
            let dev = t.path().join("build/firecracker");
            (dev.clone(), Some(dev))
        } else {
            let installed = nucleus_spec::tier2_artifacts::HOST_ARTIFACTS_DIR;
            (t.path().join(installed.trim_start_matches('/')), None)
        };
        let roots = HostPathArgs {
            scratch_root: scratch,
            artifacts_root: artifacts,
            data_root: None,
            workspace_root: None,
            image_root: None,
        }
        .ensure(&t.path().join("state"))
        .expect("roots");
        let mut spec: PodSpec = serde_json::from_str(
            r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"image":{
                "kernel_path":"/k","rootfs_path":"/r"}}}"#,
        )
        .expect("spec");
        let image = spec.spec.image.as_mut().expect("image");
        image.kernel_path = host(&kernel);
        image.rootfs = RootfsSource::Path(host(&field("rootfs_path").expect("rootfs")));
        image.scratch_path = field("scratch_path").map(|p| host(&p));
        image.data_path = field("data_path").map(|p| host(&p));
        admit(&mut spec, &FC, &roots).unwrap_or_else(|e| {
            panic!(
                "{} is refused under its documented flags: {e}",
                yaml.display()
            )
        });
        admitted += 1;
    }
    assert!(
        admitted >= 5,
        "found only {admitted} example specs with an image"
    );
}

/// Wired: `create_pod_internal` calls `admit` at function-body level, before
/// the posture gate measures the rootfs and before any driver spawns (and so
/// before any jail placement hard-links a file).
#[test]
fn create_pod_internal_confines_host_paths_before_reading_them() {
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
    let call = at("let image = host_paths::admit(&mut spec, &state.driver, &state.host_roots)?;");
    assert!(
        call < at("posture::admit_posture("),
        "confined before the rootfs is measured"
    );
    assert!(
        call < at("let spawned = match state.driver"),
        "confined before any driver runs"
    );
    let indent = main[..call].rsplit('\n').next().unwrap_or("");
    assert_eq!(
        indent, "    ",
        "at function-body level, not under a condition"
    );
}

// ── The image store: an `image.rootfs_oci` rootfs ──────────────────────────

const REF_HEX: &str = "a";
const MANIFEST_HEX: &str = "b";
const GUEST_HEX: &str = "c";

fn oci_json(reference: &str, manifest: &str, guest: &str) -> String {
    format!(
        r#"{{"reference":"registry.example/app@sha256:{}",
            "manifest_digest":"sha256:{}","guest_layer_digest":"sha-256:{}"}}"#,
        reference.repeat(64),
        manifest.repeat(64),
        guest.repeat(64)
    )
}

fn digest_of(bytes: &[u8]) -> ArtifactDigest {
    let hex = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes));
    ArtifactDigest::parse(&format!("sha-256:{hex}")).expect("digest")
}

/// A store entry as `nucleus-hostctl image build` files it: the ext4 under its
/// own digest, and the record of which image it was built from.
fn store_entry(n: &Node, bytes: &[u8], manifest: &str, guest: &str) -> ArtifactDigest {
    let digest = digest_of(bytes);
    let dir = image_store::entry_dir(&n.roots.images, &digest);
    std::fs::create_dir_all(&dir).expect("entry");
    std::fs::write(dir.join(image_store::ROOTFS_FILE), bytes).expect("ext4");
    let d = |c: &str| format!("sha256:{}", c.repeat(64));
    let record = format!(
        r#"{{"format":"nucleus-image-store/v1",
            "import":{{"crate_version":"9.9.9-test","pinned":"{pinned}","index_digest":null,
              "manifest_digest":"{manifest}","config_digest":"{cfg}",
              "platform":{{"os":"linux","architecture":"arm64"}},"layers":[],
              "report":{{"dropped":[],"stripped_setid":[],"stripped_capabilities":[],
                        "dropped_xattrs":[]}},
              "limits":{limits},
              "rootfs":{{"digest":"{tar}","bytes":1,"entries":1}},
              "workload":{{"entrypoint":[],"cmd":[],"env":[],"working_dir":null,
                          "user":{{"status":"root","user":""}}}}}},
            "guest_layer_digest":"sha-256:{guest}",
            "mke2fs":{{"major":1,"minor":47,"patch":2}},
            "builder_version":"test"}}"#,
        pinned = d(REF_HEX),
        manifest = d(manifest),
        cfg = d("e"),
        tar = d("f"),
        guest = guest.repeat(64),
        limits =
            serde_json::to_string(&nucleus_oci_rootfs::ImportLimits::standard()).expect("limits"),
    );
    std::fs::write(dir.join(image_store::RECORD_FILE), record).expect("record");
    digest
}

fn oci_pod(n: &Node, oci: &str, rootfs_digest: &ArtifactDigest) -> PodSpec {
    let kernel = put(n.artifacts(), "vmlinux");
    serde_json::from_str(&format!(
        r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{{"image":{{
            "kernel_path":{kernel:?},"rootfs_digest":"{}","rootfs_oci":{oci}}}}}}}"#,
        rootfs_digest.as_str()
    ))
    .expect("an OCI spec")
}

fn refusal_of(spec: &mut PodSpec, n: &Node) -> String {
    match admit(spec, &FC, &n.roots) {
        Err(ApiError::InvalidSpec(msg)) => msg,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn an_imported_oci_rootfs_is_admitted_from_the_store_with_its_provenance() {
    let n = node();
    let digest = store_entry(&n, b"ext4 A", MANIFEST_HEX, GUEST_HEX);
    let mut spec = oci_pod(&n, &oci_json(REF_HEX, MANIFEST_HEX, GUEST_HEX), &digest);
    let admitted = admit(&mut spec, &FC, &n.roots)
        .expect("the stored image is the one named")
        .expect("an image");
    let expected = image_store::rootfs_path(&n.roots.images, &digest)
        .canonicalize()
        .expect("canonical");
    assert_eq!(admitted.rootfs_path(), expected);
    let p = admitted
        .provenance()
        .expect("an OCI rootfs carries provenance");
    assert_eq!(p.importer_version(), "9.9.9-test");
    assert_eq!(p.mke2fs(), "1.47.2");
    assert_eq!(
        p.oci().manifest_digest.as_str(),
        format!("sha256:{}", MANIFEST_HEX.repeat(64))
    );
    assert!(
        matches!(image(&spec).rootfs, RootfsSource::Oci(_)),
        "the spec still names the image, not a path"
    );
}

/// THE consistency defect: image B's digest under image A's name. The derived
/// path exists and B's bytes measure as B's digest, so integrity alone admits
/// it — and boots B while the spec, the attestation's config hash and the
/// receipt all say A. Red with the record check neutralised.
#[test]
fn a_rootfs_digest_naming_another_images_rootfs_is_refused() {
    let n = node();
    let a = store_entry(&n, b"ext4 A", MANIFEST_HEX, GUEST_HEX);
    let b = store_entry(&n, b"ext4 B", "d", GUEST_HEX);
    let mut spec = oci_pod(&n, &oci_json(REF_HEX, MANIFEST_HEX, GUEST_HEX), &b);
    let msg = refusal_of(&mut spec, &n);
    assert!(msg.contains("manifest_digest"), "{msg}");
    assert!(msg.contains("another image"), "{msg}");

    // Each field is compared, not only the manifest.
    let c = store_entry(&n, b"ext4 C", MANIFEST_HEX, "d");
    let mut spec = oci_pod(&n, &oci_json(REF_HEX, MANIFEST_HEX, GUEST_HEX), &c);
    assert!(refusal_of(&mut spec, &n).contains("guest_layer_digest"));
    let mut spec = oci_pod(&n, &oci_json("9", MANIFEST_HEX, GUEST_HEX), &a);
    assert!(refusal_of(&mut spec, &n).contains("reference digest"));
}

#[test]
fn an_oci_rootfs_not_in_the_store_is_refused_with_the_remedy() {
    let n = node();
    let absent = digest_of(b"never imported");
    let mut spec = oci_pod(&n, &oci_json(REF_HEX, MANIFEST_HEX, GUEST_HEX), &absent);
    let msg = refusal_of(&mut spec, &n);
    assert!(msg.contains("is not imported on this node"), "{msg}");
    assert!(
        msg.contains("nucleus image import registry.example/app@sha256:"),
        "{msg}"
    );
    assert!(msg.contains("--image-root"), "{msg}");
}

/// A store entry directory that is a symlink out of the image root — at the
/// node's CA dir, holding a file named like an image — is refused.
#[test]
fn a_store_entry_symlinked_out_of_the_image_root_is_refused() {
    let n = node();
    let outside = n.state.path().join("ca");
    std::fs::write(outside.join(image_store::ROOTFS_FILE), b"ext4 A").expect("bait");
    let digest = digest_of(b"ext4 A");
    let entry = image_store::entry_dir(&n.roots.images, &digest);
    std::fs::create_dir_all(entry.parent().expect("sha256 dir")).expect("sha256 dir");
    std::os::unix::fs::symlink(&outside, &entry).expect("symlink");
    let mut spec = oci_pod(&n, &oci_json(REF_HEX, MANIFEST_HEX, GUEST_HEX), &digest);
    let msg = refusal_of(&mut spec, &n);
    assert!(msg.contains("not inside the node's root"), "{msg}");
    assert!(msg.contains("--image-root"), "{msg}");
}

/// The record may not be a symlink out of the root either: it is what vouches
/// for the image, so it must be the store's own.
#[test]
fn a_store_record_symlinked_out_of_the_image_root_is_refused() {
    let n = node();
    let digest = store_entry(&n, b"ext4 A", MANIFEST_HEX, GUEST_HEX);
    let dir = image_store::entry_dir(&n.roots.images, &digest);
    let record = dir.join(image_store::RECORD_FILE);
    let elsewhere = n.state.path().join("forged.json");
    std::fs::rename(&record, &elsewhere).expect("move record");
    std::os::unix::fs::symlink(&elsewhere, &record).expect("symlink");
    let mut spec = oci_pod(&n, &oci_json(REF_HEX, MANIFEST_HEX, GUEST_HEX), &digest);
    assert!(refusal_of(&mut spec, &n).contains("not inside the node's root"));
}

/// Path specs are unaffected: admitted as before, with no provenance.
#[test]
fn a_path_rootfs_is_admitted_without_provenance() {
    let n = node();
    let mut spec = pod(&n);
    let admitted = admit(&mut spec, &FC, &n.roots)
        .expect("admitted")
        .expect("an image");
    assert!(admitted.provenance().is_none());
    assert_eq!(
        RootfsSource::Path(admitted.rootfs_path().to_path_buf()),
        image(&spec).rootfs
    );
}

/// `AdmittedImage` is evidence (C-1): admission is its only constructor. Its
/// fields are private, so no other module can write a literal; this pins that
/// every literal that does exist is in `host_paths.rs`, so a second minting
/// site (or a public constructor beside the type) is a red test.
#[test]
fn an_admitted_image_is_minted_only_by_admission() {
    // Built at run time so this file does not contain the needle it counts.
    let needle = ["Admitted", "Image {"].concat();
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut minted: Vec<String> = Vec::new();
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source");
            let literals = text
                .match_indices(&needle)
                .filter(|(i, _)| {
                    let after = text[i + needle.len()..].trim_start();
                    after.starts_with("rootfs") || after.starts_with("provenance")
                })
                .count();
            for _ in 0..literals {
                minted.push(path.file_name().expect("name").to_string_lossy().into());
            }
        }
    }
    assert!(!minted.is_empty(), "the census found no literal at all");
    assert!(
        minted.iter().all(|f| f == "host_paths.rs"),
        "AdmittedImage minted outside admission: {minted:?}"
    );
}
