use super::*;
use base64::Engine as _;
use nucleus_spec::guest_release::UnknownGuest;
use std::path::PathBuf;

const TENANT: &str = "github~example~repo";

fn pem() -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(key.verifying_key().as_bytes());
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n")
}

struct Node {
    dir: tempfile::TempDir,
    workspace: PathBuf,
    roots: PathBuf,
    bundles: PathBuf,
}

fn node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    let bundles = dir.path().join("bundles");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&bundles).unwrap();
    let roots = dir.path().join("roots.json");
    let p = pem();
    let file = serde_json::json!([{
        "kid": nucleus_signed_decision::kid_for(&p), "public_key": p, "who": "owner"
    }]);
    std::fs::write(&roots, file.to_string()).unwrap();
    Node {
        dir,
        workspace,
        roots,
        bundles,
    }
}

fn args(roots: Option<&Path>, tenant: Option<&str>, bundles: Option<&Path>) -> DecisionArgs {
    DecisionArgs {
        decision_trust_roots: roots.map(Path::to_path_buf),
        decision_tenant: tenant.map(str::to_string),
        decision_bundles: bundles.map(Path::to_path_buf),
    }
}

fn loaded(n: &Node) -> NodeDecisions {
    args(Some(&n.roots), Some(TENANT), Some(&n.bundles))
        .load(&n.workspace)
        .unwrap()
        .expect("configured")
}

fn message(e: ApiError) -> String {
    e.to_string()
}

/// Red before: the node took no decision flags at all, so a pod could only be told about
/// owner decisions by hand. Now bad configuration refuses the node's start, by the flag's name.
#[test]
fn bad_decision_configuration_refuses_the_node_start_by_name() {
    let n = node();
    assert!(args(None, None, None).load(&n.workspace).unwrap().is_none());
    assert_eq!(loaded(&n).tenant, TENANT);

    let partial = args(Some(&n.roots), None, Some(&n.bundles)).load(&n.workspace);
    assert!(message(partial.unwrap_err()).contains("--decision-trust-roots"));

    let empty_tenant = args(Some(&n.roots), Some(""), Some(&n.bundles)).load(&n.workspace);
    assert!(message(empty_tenant.unwrap_err()).contains("--decision-tenant"));

    let bad = n.dir.path().join("bad.json");
    std::fs::write(&bad, "[]").unwrap();
    let malformed = args(Some(&bad), Some(TENANT), Some(&n.bundles)).load(&n.workspace);
    let msg = message(malformed.unwrap_err());
    assert!(
        msg.contains("--decision-trust-roots") && msg.contains("empty"),
        "{msg}"
    );

    let inside = n.workspace.join("roots.json");
    std::fs::copy(&n.roots, &inside).unwrap();
    let in_workspace = args(Some(&inside), Some(TENANT), Some(&n.bundles)).load(&n.workspace);
    assert!(message(in_workspace.unwrap_err()).contains("outside the workspace"));

    let not_dir = args(Some(&n.roots), Some(TENANT), Some(&n.roots)).load(&n.workspace);
    assert!(message(not_dir.unwrap_err()).contains("--decision-bundles"));
}

/// The material carries the roots, the tenant and every `<id>.json` within the cap, and
/// nothing else; it verifies none of them.
#[test]
fn the_material_carries_only_bundle_files_named_for_a_decision() {
    let n = node();
    let id = "ab".repeat(32);
    std::fs::write(
        n.bundles.join(format!("{id}.json")),
        "{\"unverified\":true}",
    )
    .unwrap();
    std::fs::write(n.bundles.join("notes.txt"), "the owner said yes").unwrap();
    std::fs::write(
        n.bundles.join(format!("{}.json", "cd".repeat(32))),
        "x".repeat(usize::try_from(MAX_BUNDLE_BYTES).unwrap() + 1),
    )
    .unwrap();
    let material = loaded(&n).material().unwrap();
    assert_eq!(material.tenant, TENANT);
    assert!(material.trust_roots.contains("BEGIN PUBLIC KEY"));
    assert_eq!(material.bundles.len(), 1, "{:?}", material.bundles);
    assert_eq!(material.bundles[0].id, id);
    assert_eq!(material.check(), Ok(()));
}

/// The `FETCH_POD_SPEC` reply carries the material beside the spec, and a pod with none gets
/// the reply an older guest-init has always read.
#[test]
fn the_spec_reply_carries_the_material_beside_the_spec() {
    let n = node();
    let material = loaded(&n).material().unwrap();
    let with = crate::workload_api_vsock::handle_fetch_pod_spec(Some("kind: Pod"), Some(&material))
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&with).unwrap();
    assert_eq!(parsed["spec"], "kind: Pod");
    let back: DecisionMaterial = serde_json::from_value(parsed["decisions"].clone()).unwrap();
    assert_eq!(back, material);
    let without =
        crate::workload_api_vsock::handle_fetch_pod_spec(Some("kind: Pod"), None).unwrap();
    assert_eq!(
        without,
        serde_json::json!({ "spec": "kind: Pod" }).to_string()
    );
}

#[test]
fn each_driver_names_where_its_tool_proxy_reads_the_material() {
    let n = node();
    let d = loaded(&n);
    let local = d.local_env();
    assert_eq!(local[0].0, TRUST_ROOTS_ENV);
    assert_eq!(PathBuf::from(&local[0].1), n.roots.canonicalize().unwrap());
    let env: Vec<String> = d.container_env().collect();
    assert!(env.contains(&format!(
        "{TRUST_ROOTS_ENV}={}",
        decision_gate::GUEST_TRUST_ROOTS
    )));
    assert!(env.contains(&format!("{TENANT_ENV}={TENANT}")));
    for bind in d.container_binds() {
        assert!(
            bind.ends_with(":ro"),
            "{bind}: the pod must not write the material"
        );
    }
}

fn spec(requires: &str, rootfs: &str) -> PodSpec {
    serde_json::from_str(&format!(
        r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{{
            "policy":{{"type":"profile","name":"codegen"}},
            "image":{{"kernel_path":"/k","rootfs_path":"{rootfs}","read_only":true}},
            "credentialed_egress":[{{"name":"forge","upstream":"https://forge.invalid/api",
                "credential_env":"FORGE_TOKEN","header":"authorization","value_prefix":"Bearer "}}],
            "requires_decision":{requires}}}}}"#
    ))
    .unwrap()
}

fn known(version: &str, rootfs: &str) -> NodeGuestReport {
    NodeGuestReport::Known {
        origin: GuestOrigin::Release {
            version: version.into(),
        },
        rootfs_path: rootfs.into(),
        rootfs_sha256: "00".repeat(32),
    }
}

/// Red before: `requires_decision` did not exist, so a spec could not ask for a decision and a
/// node had nothing to refuse. Every arm refuses by name; none admits silently.
#[test]
fn a_pod_requiring_a_decision_is_refused_where_none_could_be_enforced() {
    let n = node();
    let d = loaded(&n);
    let fc = DriverKind::Firecracker;
    let mediated = ContainerMediation::ToolProxy;
    let unknown = NodeGuestReport::Unknown {
        rootfs_path: "/var/lib/nucleus/artifacts/rootfs.ext4".into(),
        reason: UnknownGuest::NoRecord,
    };
    let gated = spec(r#"["create_pr:forge"]"#, "/r");

    // No requirement: nothing to judge, whatever the node holds.
    assert!(admit_with(None, &spec("[]", "/r"), &fc, mediated, &unknown).is_ok());
    // A requirement with no roots to verify against.
    let msg = message(admit_with(None, &gated, &fc, mediated, &unknown).unwrap_err());
    assert!(
        msg.contains("create_pr:forge") && msg.contains("--decision-trust-roots"),
        "{msg}"
    );
    // A requirement naming an upstream the spec does not declare could never fire.
    let typo = spec(r#"["create_pr:frge"]"#, "/r");
    let msg = message(admit_with(Some(&d), &typo, &fc, mediated, &unknown).unwrap_err());
    assert!(
        msg.contains("frge") && msg.contains("could never apply"),
        "{msg}"
    );
    // An unmediated container runs nothing that would enforce it.
    let msg = message(
        admit_with(
            Some(&d),
            &gated,
            &DriverKind::Container,
            ContainerMediation::Unmediated,
            &unknown,
        )
        .unwrap_err(),
    );
    assert!(msg.contains("unmediated"), "{msg}");
    assert!(admit_with(Some(&d), &gated, &DriverKind::Container, mediated, &unknown).is_ok());
    // A guest the node cannot tell is decided at boot, not here.
    assert!(admit_with(Some(&d), &gated, &fc, mediated, &unknown).is_ok());
}

/// The pinned 2.7.0 guest predates decision gating. A pod that requires a decision on it is
/// refused at create, by the capability's name, and a pod that does not is admitted unchanged.
#[test]
fn the_pinned_guest_is_refused_for_a_pod_that_requires_a_decision() {
    let n = node();
    let d = loaded(&n);
    let fc = DriverKind::Firecracker;
    let mediated = ContainerMediation::ToolProxy;
    let rootfs = "/var/lib/nucleus/artifacts/rootfs.ext4";
    let pinned = known(tier2_artifacts::GUEST_RELEASE, rootfs);
    let gated = spec(r#"["create_pr:forge"]"#, rootfs);

    let msg = message(admit_with(Some(&d), &gated, &fc, mediated, &pinned).unwrap_err());
    assert!(msg.contains("DecisionGatedSinks"), "{msg}");
    assert!(
        msg.contains(&format!("v{}", tier2_artifacts::GUEST_RELEASE)),
        "{msg}"
    );
    // The node does not require the row of an ordinary pod on the same guest.
    assert!(admit_with(Some(&d), &spec("[]", rootfs), &fc, mediated, &pinned).is_ok());
    // A pod booting another rootfs is not judged by the default's record: the boot gate is.
    let other = spec(r#"["create_pr:forge"]"#, "/elsewhere/rootfs.ext4");
    assert!(admit_with(Some(&d), &other, &fc, mediated, &pinned).is_ok());
    // A local build carries what its tree carries.
    let local = NodeGuestReport::Known {
        origin: GuestOrigin::LocalBuild,
        rootfs_path: rootfs.into(),
        rootfs_sha256: "00".repeat(32),
    };
    assert!(admit_with(Some(&d), &gated, &fc, mediated, &local).is_ok());

    // The same table judges a container image by its release label.
    let msg =
        message(admit_image("img", Some(tier2_artifacts::GUEST_RELEASE), &gated).unwrap_err());
    assert!(msg.contains("DecisionGatedSinks"), "{msg}");
    assert!(
        admit_image(
            "img",
            Some(tier2_artifacts::GUEST_RELEASE),
            &spec("[]", rootfs)
        )
        .is_ok()
    );
    assert!(
        admit_image("img", None, &gated).is_ok(),
        "cannot tell: decided at startup"
    );
}

/// A guest the node could not judge at create is handed out only once its tool-proxy says it
/// armed every requirement; an older guest's console has no such line.
#[test]
fn a_firecracker_pod_is_handed_out_only_once_its_gate_is_armed() {
    let gated = spec(r#"["create_pr:forge"]"#, "/r");
    let caps = &gated.spec.requires_decision;
    let older = "NUCLEUS_HOST_SPEC: READY\nNUCLEUS_EGRESS_PROBE: PASS\n";
    let msg = message(require_armed_in(&gated, older).unwrap_err());
    assert!(msg.contains("DecisionGatedSinks") && msg.contains(decision_gate::ARMED_PREFIX));
    let armed = format!("{older}{}\n", decision_gate::armed_line(caps));
    assert!(require_armed_in(&gated, &armed).is_ok());
    assert!(require_armed_in(&spec("[]", "/r"), older).is_ok());
    let named = name_skew(
        &gated,
        ApiError::Driver("proxy never became healthy".into()),
    );
    assert!(message(named).contains("DecisionGatedSinks"));
}
