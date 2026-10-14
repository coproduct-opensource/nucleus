use super::*;
use crate::pod_authority::{Admission, AuthorityArgs, PodAuthority};
use nucleus_spec::PolicySpec;

fn authority(dir: &std::path::Path) -> PodAuthority {
    PodAuthority::new(
        &AuthorityArgs {
            root_minter_spiffe_id: None,
            cert_trust_anchors: Vec::new(),
            max_children_per_pod: 8,
            upstreams: None,
            upstreams_poll_secs: 0,
            federation_issuer: None,
            ingress: Default::default(),
            approvals: crate::host_decide::effects::ApprovalTimingArgs::HUMAN,
        },
        "nucleus.local",
        dir,
        &crate::pod_authority::NO_TPM,
    )
    .expect("no registry to fail to load")
}

/// The caller's request, as it arrives on the wire: a profile policy, a host checkout, and a
/// credential value. Each is something a delivery rewrites.
const REQUEST: &str = r#"apiVersion: nucleus/v1
kind: Pod
metadata:
  name: hash-probe
  labels:
    team: review
spec:
  work_dir: /srv/workspaces/project
  timeout_seconds: 600
  policy:
    type: profile
    name: default
  credentials:
    env:
      LLM_API_TOKEN: test-token-123
"#;

/// Every delivery a node makes, with its name for the failure message.
fn deliveries() -> [(&'static str, Delivery<'static>); 6] {
    [
        ("local", Delivery::AsAdmitted),
        (
            "firecracker, enforcing",
            Delivery::Firecracker { withhold: true },
        ),
        (
            "firecracker, not enforcing",
            Delivery::Firecracker { withhold: false },
        ),
        (
            "container, mediated, HTTP create",
            Delivery::Container {
                mediation: ContainerMediation::ToolProxy,
                raw: Some(REQUEST),
            },
        ),
        (
            "container, mediated, gRPC create",
            Delivery::Container {
                mediation: ContainerMediation::ToolProxy,
                raw: None,
            },
        ),
        (
            "container, unmediated",
            Delivery::Container {
                mediation: ContainerMediation::Unmediated,
                raw: None,
            },
        ),
    ]
}

/// Admit `REQUEST` through the node's authority gate, as `create_pod_internal` does, under
/// `delivery`.
async fn admitted(
    auth: &PodAuthority,
    delivery: Delivery<'_>,
) -> crate::pod_authority::AdmittedPodPlan {
    let root = Admission {
        caller_spiffe_id: auth.root_minter().to_string(),
        caller_pod: None,
        header_cert: None,
    };
    let request: PodSpec = nucleus_yaml::from_str(REQUEST).expect("the request parses");
    let (plan, reservation) = auth
        .admit_pod(
            &root,
            request,
            uuid::Uuid::new_v4(),
            crate::host_decide::StartingLabel::Clean,
            delivery,
        )
        .await
        .expect("the root minter admits a bare policy");
    reservation.commit();
    plan
}

/// What the pod's tool-proxy binds an approval to: `PodSpec::manifest_hash` of the spec file
/// it reads, parsed as it parses it (`nucleus-tool-proxy`'s `verify_and_load_approval_bundle`).
fn guest_hash(file: &str) -> ManifestHash {
    nucleus_yaml::from_str::<PodSpec>(file)
        .expect("the guest parses the spec it is handed")
        .manifest_hash()
        .expect("the guest hashes it")
}

/// **THE PROPERTY (#3395 follow-up).** For one pod, the approval hash and the receipt hash are
/// the same: the hash a guest's tool-proxy computes from the spec it is handed equals the
/// `manifest_hash` the pod's receipt carries (the plan's, which `create_pod_internal` stores on
/// the handle and `pod_receipt::build` reads).
///
/// Red before: the receipt hashed the admitted host spec. The Firecracker enforcing guest was
/// served that spec with its credential value withheld, and the container guest got
/// `work_dir: /workspace`. On the HTTP path the container also got the caller's raw request,
/// with the requested profile policy where the issued lattice belongs. An approval minted for
/// the receipt's hash could not verify in either guest.
#[tokio::test]
async fn the_guest_hashes_the_spec_the_receipt_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path());
    for (name, delivery) in deliveries() {
        let plan = admitted(&auth, delivery).await;
        let delivered = plan.delivered();
        assert_eq!(
            &guest_hash(delivered.yaml()),
            delivered.manifest_hash(),
            "{name}: the guest's approval hash is not the receipt's manifest hash"
        );
    }
}

/// An unmediated container's file keeps the caller's extension fields for its runner. Nothing in
/// it binds an approval. The hash is still the typed admitted spec under the container mount,
/// never the raw request, and it equals the mediated delivery of the same pod.
#[tokio::test]
async fn an_unmediated_containers_extension_fields_do_not_reach_the_hash() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path());
    let with_task = format!("{REQUEST}  task: run the standard tests\n");
    let raw = with_task.as_str();
    let unmediated = admitted(
        &auth,
        Delivery::Container {
            mediation: ContainerMediation::Unmediated,
            raw: Some(raw),
        },
    )
    .await;
    assert!(
        unmediated
            .delivered()
            .yaml()
            .contains("run the standard tests"),
        "the runner's task survives delivery"
    );
    let mediated = admitted(
        &auth,
        Delivery::Container {
            mediation: ContainerMediation::ToolProxy,
            raw: Some(raw),
        },
    )
    .await;
    assert!(
        !mediated
            .delivered()
            .yaml()
            .contains("run the standard tests"),
        "the proxy is handed the admitted spec, which has no extension fields"
    );
    // Two admissions differ only in what admission stamps per pod, so compare the hash input.
    let typed = |plan: &crate::pod_authority::AdmittedPodPlan| {
        crate::container_mediation::pod_yaml(plan.spec(), None).unwrap()
    };
    assert_eq!(
        unmediated.delivered().manifest_hash(),
        &guest_hash(&typed(&unmediated))
    );
    assert_eq!(
        mediated.delivered().manifest_hash(),
        &guest_hash(&typed(&mediated))
    );
}

/// A mediated container's proxy reads the ISSUED spec. It used to read the caller's request
/// (the HTTP path wrote the raw body), so the requested policy and upstreams sat in the file its
/// own comment called "the node's own copy (policy already replaced)".
#[tokio::test]
async fn a_mediated_container_is_handed_the_admitted_spec_not_the_request() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path());
    let plan = admitted(
        &auth,
        Delivery::Container {
            mediation: ContainerMediation::ToolProxy,
            raw: Some(REQUEST),
        },
    )
    .await;
    let read: PodSpec = nucleus_yaml::from_str(plan.delivered().yaml()).unwrap();
    assert!(
        matches!(read.spec.policy, PolicySpec::Inline { .. }),
        "the issued lattice, not the requested profile: {:?}",
        read.spec.policy
    );
    assert_eq!(read.spec.work_dir, std::path::Path::new("/workspace"));
}

/// The enforcing Firecracker guest is served no credential value, and so the receipt's hash no
/// longer covers one: a receipt is distributed, and a hash over a low-entropy secret can be
/// searched for it offline.
#[tokio::test]
async fn a_withheld_credential_value_is_in_neither_the_guest_spec_nor_the_hash_input() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path());
    let plan = admitted(&auth, Delivery::Firecracker { withhold: true }).await;
    assert!(plan.delivered().withheld().is_some());
    assert!(!plan.delivered().yaml().contains("test-token-123"));
    assert_ne!(
        plan.delivered().manifest_hash(),
        &plan.spec().manifest_hash().unwrap(),
        "the host record keeps the value; the canonical spec does not"
    );
}

/// The driver selects the delivery, exhaustively: a Firecracker node withholds exactly when
/// enforcing, and a container node passes its mediation and the request through.
#[test]
fn each_driver_selects_its_delivery() {
    use crate::broker_rollout::{EnforcementDisabled, HostSpecEnforcement};
    let off = HostSpecEnforcement::Disabled(EnforcementDisabled::OperatorOptOut);
    assert!(matches!(
        Delivery::for_driver(
            &crate::DriverKind::Firecracker,
            HostSpecEnforcement::Required,
            ContainerMediation::ToolProxy,
            None
        ),
        Delivery::Firecracker { withhold: true }
    ));
    assert!(matches!(
        Delivery::for_driver(
            &crate::DriverKind::Firecracker,
            off,
            ContainerMediation::ToolProxy,
            None
        ),
        Delivery::Firecracker { withhold: false }
    ));
    assert!(matches!(
        Delivery::for_driver(
            &crate::DriverKind::Container,
            off,
            ContainerMediation::Unmediated,
            Some(REQUEST)
        ),
        Delivery::Container {
            mediation: ContainerMediation::Unmediated,
            raw: Some(_)
        }
    ));
}
