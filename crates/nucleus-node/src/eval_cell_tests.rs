//! ADR 0013: every eval-cell requirement refuses by name, and none of them
//! touches a standard pod (the non-vacuity half of each test).

use super::*;
use crate::broker_rollout::EnforcementDisabled;
use nucleus_spec::isolation_profile::PROFILE_LABEL;

fn spec_json(profile: Option<&str>, inner: &str) -> PodSpec {
    let labels = profile.map_or_else(String::new, |p| {
        format!(r#","metadata":{{"labels":{{"{PROFILE_LABEL}":"{p}"}}}}"#)
    });
    serde_json::from_str(&format!(
        r#"{{"apiVersion":"nucleus/v1","kind":"Pod"{labels},"spec":{inner}}}"#
    ))
    .expect("test spec parses")
}

/// A policy granting no network capability, so the egress rule turns only on
/// what the spec lists.
fn no_network_policy() -> String {
    let mut lattice = nucleus_spec::PolicySpec::Profile {
        name: "codegen".into(),
    }
    .resolve()
    .expect("codegen resolves");
    lattice.capabilities.web_fetch = CapabilityLevel::Never;
    lattice.capabilities.web_search = CapabilityLevel::Never;
    serde_json::to_string(&nucleus_spec::PolicySpec::Inline {
        lattice: Box::new(lattice),
    })
    .expect("serializes")
}

fn eval_cell(network: &str) -> PodSpec {
    let policy = no_network_policy();
    spec_json(
        Some("eval-cell"),
        &format!(r#"{{"policy":{policy}{network}}}"#),
    )
}

fn standard(network: &str) -> PodSpec {
    let policy = no_network_policy();
    spec_json(None, &format!(r#"{{"policy":{policy}{network}}}"#))
}

/// A platform whose appraisal is fixed, whatever the time it is asked at.
struct Fixed(nucleus_federation::NodeAttestation);

impl PlatformAttestation for Fixed {
    fn attestation_now(&self, _now: u64) -> nucleus_federation::NodeAttestation {
        self.0.clone()
    }
}

/// The live run's epoch-4 evidence (#2706), appraised at its own mint time
/// against its reference and AK pin: `attested`, through the same
/// `NodeAttestation::of_current_evidence` the node runs.
static ATTESTED: std::sync::LazyLock<Fixed> = std::sync::LazyLock::new(|| {
    let fixture = |name: &str| {
        std::fs::read(format!(
            "{}/../nucleus-node-evidence/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("fixture")
    };
    let evidence = fixture("live-node-epoch4-evidence.json");
    let doc: serde_json::Value = serde_json::from_slice(&evidence).expect("evidence parses");
    let binding = nucleus_node_evidence::KeyBinding {
        executor_key: nucleus_node_evidence::ExecutorKey::Ed25519(
            hex::decode(doc["binding"]["executor_key"]["ed25519"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        federation: nucleus_node_evidence::Federation::NotFederated,
    };
    let reference: nucleus_node_evidence::ReferenceManifest =
        serde_json::from_slice(&fixture("live-node-reference-exact.json")).unwrap();
    let anchors = nucleus_node_evidence::AnchorPolicy {
        software_tpm_pins: vec![],
        trust_roots: vec![],
        operator_pins: vec![nucleus_node_evidence::OperatorPin {
            source: doc["ak_anchor"]["operator_fetched"]["source"]
                .as_str()
                .unwrap()
                .into(),
            ak_spki_sha256: "beced81752041938278acd53c5df51df98652f58bb76bdf722e8965d25bd2366"
                .into(),
        }],
    };
    let attestation = nucleus_federation::NodeAttestation::of_current_evidence(
        &evidence,
        Some(&nucleus_federation::SelfAppraisal {
            binding: &binding,
            reference: &reference,
            anchors: &anchors,
            max_age_secs: nucleus_federation::SelfAppraisal::max_age_for_epoch(300),
        }),
        1_791_247_262,
    );
    assert_eq!(
        attestation.tier(),
        ClaimedTier::Attested,
        "{}",
        attestation.note()
    );
    Fixed(attestation)
});

/// A Firecracker node with every posture an eval cell needs.
fn holding(driver: &DriverKind) -> NodePosture<'_> {
    NodePosture {
        driver,
        seccomp_verify: true,
        jailer: true,
        landlock: nucleus::LandlockWaiver::Absent,
        host_spec: HostSpecEnforcement::Required,
        platform: &*ATTESTED,
    }
}

/// ADR 0016 D3: an eval cell runs only on a node whose own evidence appraises
/// `attested` now. Every other tier refuses it by name, the tier and the
/// appraisal's note in the message; a standard pod on the same node is admitted,
/// and the same cell on an attested node is admitted (non-vacuous).
#[test]
fn an_eval_cell_is_refused_on_a_node_whose_evidence_is_not_attested() {
    let fc = DriverKind::Firecracker;
    let evidence = std::fs::read(format!(
        "{}/../nucleus-node-evidence/tests/fixtures/live-node-epoch4-evidence.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("fixture");
    let cases = [
        (
            Fixed(nucleus_federation::NodeAttestation::without_evidence(
                "no TPM configured",
            )),
            "no TPM configured",
        ),
        // Real evidence the node did not appraise (no reference configured).
        (
            Fixed(nucleus_federation::NodeAttestation::of_current_evidence(
                &evidence,
                None,
                1_791_247_262,
            )),
            "no reference manifest",
        ),
    ];
    for (platform, note) in &cases {
        let node = NodePosture {
            platform,
            ..holding(&fc)
        };
        let refused = admit(&eval_cell(""), &node, None).expect_err("not attested");
        assert!(
            matches!(
                refused,
                EvalCellRefused::NodeNotAttested {
                    tier: "unattested",
                    ..
                }
            ),
            "{refused:?}"
        );
        assert!(refused.to_string().contains(note), "{refused}");
        assert_eq!(
            admit(&standard(""), &node, None),
            Ok(IsolationProfile::Standard)
        );
    }
    assert_eq!(
        admit(&eval_cell(""), &holding(&fc), None),
        Ok(IsolationProfile::EvalCell)
    );
}

/// An attested launch for `measured` from `ca`, as the leaf DER the node serves.
async fn attested_leaf(
    ca: &nucleus_identity::SelfSignedCa,
    measured: &nucleus_identity::LaunchAttestation,
) -> Vec<u8> {
    use nucleus_identity::CaClient;
    let identity = nucleus_identity::Identity::for_pod("test.local", "cell");
    let cs = nucleus_identity::CsrOptions::new(identity.to_spiffe_uri())
        .generate()
        .unwrap();
    ca.sign_attested_csr(
        cs.csr(),
        cs.private_key(),
        &identity,
        std::time::Duration::from_secs(3600),
        measured,
    )
    .await
    .unwrap()
    .leaf()
    .der()
    .to_vec()
}

/// ADR 0016 D3, the decider: an eval cell's launch verifies only when its leaf
/// chains to the node's CA and carries exactly the measurement the node took.
/// Each failure is refused by name; a standard pod is never checked.
#[tokio::test]
async fn an_eval_cell_launch_verifies_only_as_the_node_measured_it() {
    use nucleus_identity::{CaClient, LaunchAttestation, SelfSignedCa};
    let ca = SelfSignedCa::new("test.local").unwrap();
    let measured = LaunchAttestation::from_hashes([1; 32], [2; 32], [3; 32]);
    let leaf = attested_leaf(&ca, &measured).await;
    let issued = |leaf: &[u8], ca: &SelfSignedCa, m: &LaunchAttestation| {
        let launch = LaunchIdentity::Issued {
            measured: m,
            leaf_der: leaf,
            trust_bundle: ca.trust_bundle(),
        };
        require_verified_launch(IsolationProfile::EvalCell, launch)
    };

    // Non-vacuous: the node's own launch verifies.
    assert_eq!(issued(&leaf, &ca, &measured), Ok(()));

    // Another launch's measurement.
    let other = LaunchAttestation::from_hashes([1; 32], [2; 32], [4; 32]);
    let e = issued(&leaf, &ca, &other).expect_err("measurement differs");
    assert!(e.to_string().contains("but the node measured"), "{e}");

    // A leaf from a CA that is not this node's, carrying the right measurement.
    let foreign = SelfSignedCa::new("test.local").unwrap();
    let forged = attested_leaf(&foreign, &measured).await;
    let e = issued(&forged, &ca, &measured).expect_err("foreign issuer");
    assert!(e.to_string().contains("not issued by a trusted CA"), "{e}");

    // Each fallback a standard pod keeps.
    for launch in [
        LaunchIdentity::NoIdentity,
        LaunchIdentity::NotMeasured("io".into()),
        LaunchIdentity::NotIssued("ca".into()),
    ] {
        let e = require_verified_launch(IsolationProfile::EvalCell, launch)
            .expect_err("an eval cell is refused");
        assert!(matches!(e, EvalCellRefused::LaunchUnverified(_)), "{e:?}");
    }

    // A standard pod is not checked at all, even with a forged leaf.
    let launch = LaunchIdentity::Issued {
        measured: &other,
        leaf_der: &forged,
        trust_bundle: ca.trust_bundle(),
    };
    assert_eq!(
        require_verified_launch(IsolationProfile::Standard, launch),
        Ok(())
    );
    assert_eq!(
        require_verified_launch(IsolationProfile::Standard, LaunchIdentity::NoIdentity),
        Ok(())
    );
}

fn every_driver() -> Vec<DriverKind> {
    vec![
        DriverKind::Firecracker,
        DriverKind::Container,
        DriverKind::AppleVz,
        #[cfg(feature = "local-driver")]
        DriverKind::Local,
    ]
}

/// The tier clamp. Each refused tier is refused BY NAME, the name the isolation
/// clamp writes into the pod's labels, and the same pod on Firecracker is
/// admitted. A standard pod is admitted on every tier, so the refusal is the
/// profile's, not the tier's.
#[test]
fn an_eval_cell_is_refused_on_every_tier_but_firecracker_by_name() {
    let pod = eval_cell("");
    let mut refused = Vec::new();
    for driver in every_driver() {
        let tier = isolation_backend(&driver).name;
        match admit(&pod, &holding(&driver), None) {
            Ok(profile) => {
                assert_eq!(tier, "firecracker", "only Firecracker hosts an eval cell");
                assert_eq!(profile, IsolationProfile::EvalCell);
            }
            Err(e) => {
                assert!(
                    matches!(e, EvalCellRefused::Tier { tier: t, .. } if t == tier),
                    "{tier}: {e:?}"
                );
                let msg = ApiError::from(e).to_string();
                assert!(msg.contains(&format!("`{tier}` tier")), "{msg}");
                refused.push(tier);
            }
        }
        assert_eq!(
            admit(&standard(""), &holding(&driver), None),
            Ok(IsolationProfile::Standard),
            "{tier}: a standard pod is admitted as before"
        );
    }
    let mut expected = vec!["container", "apple-vz"];
    if cfg!(feature = "local-driver") {
        expected.push("local");
    }
    assert_eq!(refused, expected);
}

/// Each node posture an eval cell relies on, turned off one at a time, refuses
/// it by name; a standard pod on the same node is admitted.
#[test]
fn a_node_that_weakens_any_host_control_refuses_an_eval_cell_by_name() {
    let fc = DriverKind::Firecracker;
    let cases: [(NodePosture<'_>, &str); 4] = [
        (
            NodePosture {
                seccomp_verify: false,
                ..holding(&fc)
            },
            "--firecracker-seccomp-verify=false",
        ),
        (
            NodePosture {
                jailer: false,
                ..holding(&fc)
            },
            "--firecracker-jailer=false",
        ),
        (
            NodePosture {
                landlock: nucleus::LandlockWaiver::Explicit,
                ..holding(&fc)
            },
            "--allow-workload-without-landlock",
        ),
        (
            NodePosture {
                host_spec: HostSpecEnforcement::Disabled(EnforcementDisabled::OperatorOptOut),
                ..holding(&fc)
            },
            "host-spec credential delivery",
        ),
    ];
    for (node, names) in cases {
        let msg = admit(&eval_cell(""), &node, None)
            .expect_err("an eval cell needs every host control")
            .to_string();
        assert!(msg.contains(names), "{names}: {msg}");
        assert_eq!(
            admit(&standard(""), &node, None),
            Ok(IsolationProfile::Standard)
        );
    }
}

#[test]
fn an_eval_cell_runs_the_vmm_under_the_default_seccomp_filter_only() {
    let fc = DriverKind::Firecracker;
    let node = holding(&fc);
    for (seccomp, mode) in [
        (r#"{"mode":"disabled"}"#, "disabled"),
        (r#"{"mode":"custom","filter_path":"/f"}"#, "custom"),
    ] {
        let policy = no_network_policy();
        let pod = spec_json(
            Some("eval-cell"),
            &format!(r#"{{"policy":{policy},"seccomp":{seccomp}}}"#),
        );
        assert_eq!(
            admit(&pod, &node, None),
            Err(EvalCellRefused::SpecSeccomp { mode })
        );
    }
    let policy = no_network_policy();
    let pod = spec_json(
        Some("eval-cell"),
        &format!(r#"{{"policy":{policy},"seccomp":{{"mode":"default"}}}}"#),
    );
    assert_eq!(admit(&pod, &node, None), Ok(IsolationProfile::EvalCell));
}

/// The audit uploader's credential is the one bearer credential the workload API
/// serves a guest (`FETCH_AUDIT_CREDENTIALS`), and guest root holds whatever the
/// guest is served. An eval cell naming an audit sink is refused by the sink's
/// name; the same spec as a standard pod is admitted, and an eval cell without a
/// sink is admitted, so the refusal is the sink's under this profile alone.
#[test]
fn an_eval_cell_is_never_served_an_audit_uploader_credential() {
    let fc = DriverKind::Firecracker;
    let node = holding(&fc);
    let sink = r#","audit_sink":{"sink":"trail","prefix":"run-7"}"#;
    assert_eq!(
        admit(&eval_cell(sink), &node, None),
        Err(EvalCellRefused::GuestHeldAuditCredential {
            sink: "trail".into()
        })
    );
    let msg = admit(&eval_cell(sink), &node, None)
        .expect_err("refused")
        .to_string();
    assert!(msg.contains("audit_sink.sink `trail`"), "{msg}");
    assert_eq!(
        admit(&standard(sink), &node, None),
        Ok(IsolationProfile::Standard)
    );
    assert_eq!(
        admit(&eval_cell(""), &node, None),
        Ok(IsolationProfile::EvalCell)
    );
}

/// Egress is what the cell lists, one host at a time. A range — public or
/// private — is refused naming the entry; the same entry is admitted for a
/// standard pod, and a single host is admitted for an eval cell.
#[test]
fn an_eval_cell_refuses_any_allow_entry_that_is_not_one_host() {
    let fc = DriverKind::Firecracker;
    let node = holding(&fc);
    for entry in [
        "0.0.0.0/0",
        "10.0.0.0/8:443",
        "203.0.113.0/24:443",
        "::/0",
        "nonsense",
    ] {
        let network = format!(r#","network":{{"allow":["{entry}"]}}"#);
        assert_eq!(
            admit(&eval_cell(&network), &node, None),
            Err(EvalCellRefused::UnlistedRange {
                entry: entry.to_string()
            }),
            "{entry}"
        );
        assert_eq!(
            admit(&standard(&network), &node, None),
            Ok(IsolationProfile::Standard),
            "{entry}: the standard profile is unchanged"
        );
    }
    for entry in ["203.0.113.5", "203.0.113.5/32:443", "[2001:db8::1]:443"] {
        let network = format!(r#","network":{{"allow":["{entry}"]}}"#);
        assert_eq!(
            admit(&eval_cell(&network), &node, None),
            Ok(IsolationProfile::EvalCell),
            "{entry}"
        );
    }
}

/// A policy that asks for network egress while the spec lists no destination is
/// refused, naming the capability. Listing a host, or granting `never`, admits.
#[test]
fn an_eval_cell_requesting_egress_it_does_not_list_is_refused() {
    let fc = DriverKind::Firecracker;
    let node = holding(&fc);
    for (field, capability) in [("web_fetch", "web_fetch"), ("web_search", "web_search")] {
        let mut lattice = nucleus_spec::PolicySpec::Profile {
            name: "codegen".into(),
        }
        .resolve()
        .expect("codegen resolves");
        lattice.capabilities.web_fetch = CapabilityLevel::Never;
        lattice.capabilities.web_search = CapabilityLevel::Never;
        match field {
            "web_fetch" => lattice.capabilities.web_fetch = CapabilityLevel::Always,
            "web_search" => lattice.capabilities.web_search = CapabilityLevel::LowRisk,
            other => panic!("no such field {other}"),
        }
        let policy = serde_json::to_string(&nucleus_spec::PolicySpec::Inline {
            lattice: Box::new(lattice),
        })
        .expect("serializes");
        let unlisted = spec_json(Some("eval-cell"), &format!(r#"{{"policy":{policy}}}"#));
        assert_eq!(
            admit(&unlisted, &node, None),
            Err(EvalCellRefused::UnlistedEgress { capability }),
        );
        let listed = spec_json(
            Some("eval-cell"),
            &format!(r#"{{"policy":{policy},"network":{{"allow":["203.0.113.5:443"]}}}}"#),
        );
        assert_eq!(admit(&listed, &node, None), Ok(IsolationProfile::EvalCell));
        let as_standard = spec_json(None, &format!(r#"{{"policy":{policy}}}"#));
        assert_eq!(
            admit(&as_standard, &node, None),
            Ok(IsolationProfile::Standard)
        );
    }
    // With no network capability and nothing listed: nothing to reach, admitted.
    assert_eq!(
        admit(&eval_cell(""), &node, None),
        Ok(IsolationProfile::EvalCell)
    );
}

/// A pod an eval cell creates is an eval cell: omitting the label is refused,
/// never read as standard. A standard parent may create an eval cell.
#[test]
fn a_child_cannot_shed_its_parents_eval_cell() {
    let fc = DriverKind::Firecracker;
    let node = holding(&fc);
    let parent = Uuid::new_v4();
    assert_eq!(
        admit(
            &standard(""),
            &node,
            Some((parent, IsolationProfile::EvalCell))
        ),
        Err(EvalCellRefused::ShedByChild { parent })
    );
    assert_eq!(
        admit(
            &eval_cell(""),
            &node,
            Some((parent, IsolationProfile::EvalCell))
        ),
        Ok(IsolationProfile::EvalCell)
    );
    assert_eq!(
        admit(
            &eval_cell(""),
            &node,
            Some((parent, IsolationProfile::Standard))
        ),
        Ok(IsolationProfile::EvalCell)
    );
    assert_eq!(
        admit(
            &standard(""),
            &node,
            Some((parent, IsolationProfile::Standard))
        ),
        Ok(IsolationProfile::Standard)
    );
}

/// ADR 0007 B-3: an unknown profile denies, on every tier.
#[test]
fn an_unknown_profile_is_refused_never_read_as_standard() {
    for driver in every_driver() {
        let pod = spec_json(Some("eval_cell"), "{}");
        let e = admit(&pod, &holding(&driver), None).expect_err("an unknown profile denies");
        assert!(matches!(e, EvalCellRefused::UnknownProfile(_)), "{e:?}");
    }
}

/// At boot, an eval cell whose guest did not report Landlock enforced is not
/// started; a standard pod with the same silent guest is.
#[test]
fn an_eval_cell_guest_that_does_not_confine_its_children_fails_the_boot() {
    use crate::net::confinement::WorkloadFilesystem;
    use nucleus_spec::guest_layout::WorkloadLandlockVerdict as V;
    let enforced = WorkloadFilesystem::Reported(V::Enforced { abi: 2 });
    for unconfined in [
        WorkloadFilesystem::Unreported,
        WorkloadFilesystem::Reported(V::NotApplied),
    ] {
        let err = require_confined_children(&eval_cell(""), &unconfined)
            .expect_err("an eval cell requires its children confined")
            .to_string();
        assert!(err.contains("landlock NOT enforced"), "{err}");
        assert!(require_confined_children(&standard(""), &unconfined).is_ok());
    }
    assert!(require_confined_children(&eval_cell(""), &enforced).is_ok());
}

/// The decider is wired into create: an eval-cell spec on this fixture's local
/// node is refused by name and nothing is registered, while the wiring sits
/// before the backend clamp and admission.
#[cfg(feature = "local-driver")]
#[tokio::test]
async fn create_refuses_an_eval_cell_on_the_local_tier_by_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = crate::pod_api::handler_tests::state(&dir);
    let root = crate::pod_authority::Admission {
        caller_spiffe_id: st.authority.root_minter().to_string(),
        caller_pod: None,
        header_cert: None,
    };
    let Err(ApiError::InvalidSpec(msg)) =
        crate::create_pod_internal(&st, eval_cell(""), None, None, root).await
    else {
        panic!("an eval cell on the local tier must be refused at create");
    };
    assert!(msg.contains("`local` tier"), "{msg}");
    assert!(st.pods.lock().await.is_empty(), "nothing was registered");
}

#[test]
fn the_eval_cell_decider_runs_at_create_before_the_clamp_and_admission() {
    let main = include_str!("main.rs");
    let body = main
        .split("async fn create_pod_internal(")
        .nth(1)
        .expect("create_pod_internal exists");
    let decide = body
        .find("let profile = eval_cell::admit_on(state, &spec, parent_pod_id, id)?;")
        .expect("create calls the eval-cell decider and propagates its refusal");
    let clamp = body
        .find("driver::clamp_isolation_to_backend(")
        .expect("the clamp is called");
    assert!(
        decide < clamp,
        "the profile is decided before anything is clamped"
    );
    let indent = body[..decide].rsplit('\n').next().unwrap_or("");
    assert_eq!(indent, "    ", "unconditional, at function-body level");
}

/// The live decider records each eval cell it admits, before the guest exists,
/// and holds that pod's children to the profile: a child that omits the label
/// is refused by name. A standard parent's standard child is admitted. This
/// fixture's node is not attested, so it refuses the cell itself (ADR 0016) and
/// the parent's record is written as admission writes it.
#[cfg(feature = "local-driver")]
#[test]
fn the_node_holds_a_child_to_the_profile_it_admitted_its_parent_under() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut st = crate::pod_api::handler_tests::state(&dir);
    st.driver = DriverKind::Firecracker;
    st.firecracker_seccomp_verify = true;
    st.firecracker_jailer = true;
    st.workload_landlock = nucleus::LandlockWaiver::Absent;
    st.broker_enforcing = HostSpecEnforcement::Required;
    let cell = Uuid::new_v4();
    // Wired through the live state (ADR 0016 D3): this fixture's node has no TPM,
    // so its own evidence appraises `unattested` and the eval cell is refused by
    // name, and a refused cell is not recorded.
    let msg = admit_on(&st, &eval_cell(""), None, cell)
        .expect_err("an eval cell on a node with no attested evidence")
        .to_string();
    assert!(msg.contains("appraises `unattested`"), "{msg}");
    assert!(msg.contains("test node"), "{msg}");
    assert_eq!(st.eval_cells.profile_of(cell), IsolationProfile::Standard);
    // What admit_on records for a cell it admits on an attested node.
    st.eval_cells.record(cell);
    let msg = admit_on(&st, &standard(""), Some(cell), Uuid::new_v4())
        .expect_err("a child cannot shed its parent's profile")
        .to_string();
    assert!(msg.contains(&cell.to_string()), "{msg}");
    let msg = admit_on(&st, &eval_cell(""), Some(cell), Uuid::new_v4())
        .expect_err("an eval-cell child is held to the attested-node rule too")
        .to_string();
    assert!(msg.contains("appraises `unattested`"), "{msg}");
    let plain = Uuid::new_v4();
    assert_eq!(
        admit_on(&st, &standard(""), None, plain).expect("a standard pod"),
        IsolationProfile::Standard
    );
    assert_eq!(
        admit_on(&st, &standard(""), Some(plain), Uuid::new_v4()).expect("its standard child"),
        IsolationProfile::Standard
    );
}
