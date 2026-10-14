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

// ADR 0016 S3: an eval cell's launch must be rooted in the node's TPM. These run
// against the quote a software TPM really took (`nucleus-identity`'s
// `tests/fixtures/launch-quote/`; the capture recipe is in that crate's
// `launch_quote_tests.rs`): the fixture's leaf key, its measurement
// (kernel `0x11…`, rootfs `0x22…`, config `0x33…`), its executor key `0x5e…`
// (not federated), its AK pin and the source it was pinned under.

const LAUNCH_QUOTE_LEAF_KEY: &str =
    include_str!("../../nucleus-identity/tests/fixtures/launch-quote/leaf-key.pem");
const LAUNCH_QUOTE: &[u8] =
    include_bytes!("../../nucleus-identity/tests/fixtures/launch-quote/quote.json");
/// SHA-256 of the fixture swtpm AK's SubjectPublicKeyInfo.
const LAUNCH_QUOTE_AK_PIN: &str =
    "c973a42e47c26d950b76f3930f8abcdb5f3915ae2c1d1df767f776f7d1025b9a";
/// A time inside the fixture's validity, Unix seconds.
const LAUNCH_QUOTE_NOW: i64 = 1_791_000_000;

fn quoted_measurement() -> nucleus_identity::LaunchAttestation {
    nucleus_identity::LaunchAttestation::from_hashes([0x11; 32], [0x22; 32], [0x33; 32])
}

/// The fixture swtpm's node: its reference, its AK pinned as a software TPM,
/// its binding, and the one launch quote it stored.
struct FixtureTpmNode {
    reference: nucleus_node_evidence::ReferenceManifest,
    anchors: nucleus_node_evidence::AnchorPolicy,
}

impl FixtureTpmNode {
    fn new() -> Self {
        use nucleus_node_evidence::{Expect, REFERENCE_PROFILE, ReferenceValues};
        fn none<T>() -> Expect<T> {
            Expect::NotChecked("software TPM: no firmware, no IMA".into())
        }
        Self {
            reference: nucleus_node_evidence::ReferenceManifest {
                profile: REFERENCE_PROFILE.into(),
                tag_id: "swtpm-fixture".into(),
                reference_values: ReferenceValues {
                    pcrs: Default::default(),
                    secure_boot: none(),
                    efi_applications: none(),
                    boot_files: none(),
                    kernel_cmdline: none(),
                    ima: none(),
                },
            },
            anchors: nucleus_node_evidence::AnchorPolicy {
                trust_roots: Vec::new(),
                operator_pins: Vec::new(),
                software_tpm_pins: vec![nucleus_node_evidence::OperatorPin {
                    source: "swtpm-fixture".into(),
                    ak_spki_sha256: LAUNCH_QUOTE_AK_PIN.into(),
                }],
            },
        }
    }
}

impl OwnLaunchQuotes for FixtureTpmNode {
    fn appraisal(&self) -> Result<OwnQuoteAppraisal<'_>, String> {
        Ok(OwnQuoteAppraisal {
            binding: nucleus_node_evidence::KeyBinding {
                executor_key: nucleus_node_evidence::ExecutorKey::Ed25519([0x5e; 32]),
                federation: nucleus_node_evidence::Federation::NotFederated,
            },
            reference: &self.reference,
            anchors: &self.anchors,
            now: LAUNCH_QUOTE_NOW,
        })
    }

    fn document(&self, digest: &[u8; 32]) -> Result<Vec<u8>, String> {
        if nucleus_node_evidence::evidence_digest(LAUNCH_QUOTE) == *digest {
            Ok(LAUNCH_QUOTE.to_vec())
        } else {
            Err(format!(
                "this node holds no launch quote {}",
                hex::encode(digest)
            ))
        }
    }
}

/// A leaf `ca` signs over `key_pem` for `measured`, naming the launch quote
/// `quote` (OID `.1.7`) when given, as the node serves it.
async fn launch_leaf(
    ca: &nucleus_identity::SelfSignedCa,
    key_pem: &str,
    measured: &nucleus_identity::LaunchAttestation,
    quote: Option<&[u8; 32]>,
) -> Vec<u8> {
    use nucleus_identity::CaClient;
    let identity = nucleus_identity::Identity::for_pod("test.local", "cell");
    let key = rcgen::KeyPair::from_pem(key_pem).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::URI(
        rcgen::string::Ia5String::try_from(identity.to_spiffe_uri()).unwrap(),
    )];
    let csr = params.serialize_request(&key).unwrap().pem().unwrap();
    ca.sign_measured_csr(
        &csr,
        key_pem,
        &identity,
        std::time::Duration::from_secs(3600),
        &nucleus_identity::MeasuredClaims {
            attestation: measured,
            mediator_key_sha256: None,
            launch_quote_sha256: quote,
            isolation_profile: nucleus_identity::SvidProfile::EvalCell,
        },
    )
    .await
    .unwrap()
    .leaf()
    .der()
    .to_vec()
}

fn fixture_quote_digest() -> [u8; 32] {
    nucleus_node_evidence::evidence_digest(LAUNCH_QUOTE)
}

/// ADR 0016 D3 and S3, the decider, positive: an eval cell whose leaf chains to
/// the node's CA, names the launch quote the node's TPM took over its key and
/// measurement, and carries exactly the measurement the node took, verifies.
/// Every other launch is refused by name, and a standard pod is never checked.
#[tokio::test]
async fn an_eval_cell_launch_verifies_only_when_the_nodes_tpm_quoted_it() {
    use nucleus_identity::{CaClient, LaunchAttestation, SelfSignedCa};
    let node = FixtureTpmNode::new();
    let ca = SelfSignedCa::new("test.local").unwrap();
    let measured = quoted_measurement();
    let digest = fixture_quote_digest();
    let leaf = launch_leaf(&ca, LAUNCH_QUOTE_LEAF_KEY, &measured, Some(&digest)).await;
    let issued = |leaf: &[u8], ca: &SelfSignedCa, m: &LaunchAttestation| {
        require_verified_launch(
            IsolationProfile::EvalCell,
            LaunchIdentity::Issued {
                measured: m,
                leaf_der: leaf,
                trust_bundle: ca.trust_bundle(),
                quotes: &node,
            },
        )
    };

    // Non-vacuous: the launch the TPM quoted verifies, rooted in the TPM.
    assert_eq!(issued(&leaf, &ca, &measured), Ok(()));

    // The node measured another launch than the one the leaf carries and the TPM quoted.
    let other = LaunchAttestation::from_hashes([0x11; 32], [0x22; 32], [0x34; 32]);
    let e = issued(&leaf, &ca, &other).expect_err("measurement differs");
    assert!(matches!(e, EvalCellRefused::LaunchUnverified(_)), "{e:?}");
    assert!(e.to_string().contains("but the node measured"), "{e}");

    // A leaf from a CA that is not this node's, over the quoted key, measurement and quote.
    let foreign = SelfSignedCa::new("test.local").unwrap();
    let forged = launch_leaf(&foreign, LAUNCH_QUOTE_LEAF_KEY, &measured, Some(&digest)).await;
    let e = issued(&forged, &ca, &measured).expect_err("foreign issuer");
    assert!(matches!(e, EvalCellRefused::LaunchUnverified(_)), "{e:?}");
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

    // A standard pod is not checked at all, even with a forged leaf on a node with no TPM.
    let no_tpm = crate::node_evidence::NodePlatformSource::Unattested("no TPM".into());
    let launch = LaunchIdentity::Issued {
        measured: &other,
        leaf_der: &forged,
        trust_bundle: ca.trust_bundle(),
        quotes: &no_tpm,
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

/// ADR 0016 S3: a launch only the node CA vouches for is refused by name. On a
/// node with no TPM (the node's own `NodePlatformSource`, so the production arm),
/// with the very leaf that verifies on the TPM node; and on the TPM node, a leaf
/// that names no launch quote (`.1.7` missing), and one naming a quote the node
/// does not hold. Each of these leaves passes the CA-only check.
#[tokio::test]
async fn an_eval_cell_launch_rooted_in_the_ca_alone_is_refused() {
    use nucleus_identity::{SelfSignedCa, VerifiedLaunch};
    let ca = SelfSignedCa::new("test.local").unwrap();
    let measured = quoted_measurement();
    let digest = fixture_quote_digest();
    let quoted = launch_leaf(&ca, LAUNCH_QUOTE_LEAF_KEY, &measured, Some(&digest)).await;
    let unquoted = launch_leaf(&ca, LAUNCH_QUOTE_LEAF_KEY, &measured, None).await;
    let mut elsewhere = digest;
    elsewhere[0] ^= 0x01;
    let unheld = launch_leaf(&ca, LAUNCH_QUOTE_LEAF_KEY, &measured, Some(&elsewhere)).await;
    let ca_bundle = nucleus_identity::CaClient::trust_bundle(&ca);
    for leaf in [&quoted, &unquoted, &unheld] {
        VerifiedLaunch::verify(leaf, ca_bundle).expect("the node CA alone vouches for each");
    }

    let tpm = FixtureTpmNode::new();
    let no_tpm = crate::node_evidence::NodePlatformSource::Unattested(
        "no TPM attester configured (--node-evidence-tpm is unset)".into(),
    );
    let cases: [(&[u8], &dyn OwnLaunchQuotes, &str); 3] = [
        (&quoted, &no_tpm, "this node has no TPM"),
        (&unquoted, &tpm, "names no launch quote"),
        (&unheld, &tpm, "holds no launch quote"),
    ];
    for (leaf, quotes, why) in cases {
        let e = require_verified_launch(
            IsolationProfile::EvalCell,
            LaunchIdentity::Issued {
                measured: &measured,
                leaf_der: leaf,
                trust_bundle: ca_bundle,
                quotes,
            },
        )
        .expect_err("a launch the CA alone roots");
        assert!(matches!(e, EvalCellRefused::LaunchNotTpmRooted(_)), "{e:?}");
        assert!(
            e.to_string().contains("not rooted in this node's TPM"),
            "{e}"
        );
        assert!(e.to_string().contains(why), "{why}: {e}");
    }
}

/// ADR 0016 S3, the certificate swap: the same CA, measurement and `.1.7`, but
/// another key. The node CA cannot tell it from the real leaf; the quote, taken
/// over the real leaf's key, refuses it.
#[tokio::test]
async fn an_eval_cell_launch_quoted_over_another_key_is_refused() {
    use nucleus_identity::{SelfSignedCa, VerifiedLaunch};
    let ca = SelfSignedCa::new("test.local").unwrap();
    let measured = quoted_measurement();
    let other_key = rcgen::KeyPair::generate().unwrap().serialize_pem();
    let swapped = launch_leaf(&ca, &other_key, &measured, Some(&fixture_quote_digest())).await;
    let ca_bundle = nucleus_identity::CaClient::trust_bundle(&ca);
    VerifiedLaunch::verify(&swapped, ca_bundle).expect("the CA-only root cannot see the swap");

    let e = require_verified_launch(
        IsolationProfile::EvalCell,
        LaunchIdentity::Issued {
            measured: &measured,
            leaf_der: &swapped,
            trust_bundle: ca_bundle,
            quotes: &FixtureTpmNode::new(),
        },
    )
    .expect_err("a quote over another key does not root this leaf");
    assert!(matches!(e, EvalCellRefused::LaunchNotTpmRooted(_)), "{e:?}");
    assert!(
        e.to_string()
            .contains("not taken over this leaf's key and measurement"),
        "{e}"
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

/// ADR 0013 rule 8 (A-19 row 1): an eval cell given a governor key is refused by the key's name,
/// for each name the guest reads; the same spec as a standard pod passes this decider, and an
/// eval cell with an unrelated credential is admitted, so the refusal is the key's under this
/// profile alone.
#[test]
fn an_eval_cell_is_never_given_a_governor_key() {
    let fc = DriverKind::Firecracker;
    let node = holding(&fc);
    for key in nucleus_spec::isolation_profile::GOVERNOR_KEY_ENV {
        let creds = format!(r#","credentials":{{"env":{{"{key}":"aa"}}}}"#);
        assert_eq!(
            admit(&eval_cell(&creds), &node, None),
            Err(EvalCellRefused::GuestHeldGovernorKey { key: key.into() })
        );
        let msg = admit(&eval_cell(&creds), &node, None)
            .expect_err("refused")
            .to_string();
        assert!(msg.contains(key) && msg.contains("rule 8"), "{msg}");
        assert_eq!(
            admit(&standard(&creds), &node, None),
            Ok(IsolationProfile::Standard)
        );
    }
    let unrelated = r#","credentials":{"env":{"LLM_API_TOKEN":"test-token-123"}}"#;
    assert_eq!(
        admit(&eval_cell(unrelated), &node, None),
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
        let pod = spec_json(
            Some("eval_cell"),
            r#"{"policy":{"type":"profile","name":"default"}}"#,
        );
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
