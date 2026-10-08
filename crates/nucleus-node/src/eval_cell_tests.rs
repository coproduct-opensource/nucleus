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

/// A Firecracker node with every posture an eval cell needs.
fn holding(driver: &DriverKind) -> NodePosture<'_> {
    NodePosture {
        driver,
        seccomp_verify: true,
        jailer: true,
        landlock: nucleus::LandlockWaiver::Absent,
        host_spec: HostSpecEnforcement::Required,
    }
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
/// is refused by name. A standard parent's standard child is admitted.
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
    assert_eq!(
        admit_on(&st, &eval_cell(""), None, cell).expect("an eval cell on a holding node"),
        IsolationProfile::EvalCell
    );
    let msg = admit_on(&st, &standard(""), Some(cell), Uuid::new_v4())
        .expect_err("a child cannot shed its parent's profile")
        .to_string();
    assert!(msg.contains(&cell.to_string()), "{msg}");
    assert_eq!(
        admit_on(&st, &eval_cell(""), Some(cell), Uuid::new_v4()).expect("an eval-cell child"),
        IsolationProfile::EvalCell
    );
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
