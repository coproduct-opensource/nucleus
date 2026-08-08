use super::*;

#[test]
fn label_selector_empty_matches_all() {
    let labels = BTreeMap::from([("team".into(), "backend".into())]);
    assert!(matches_label_selector(&labels, ""));
}

#[test]
fn label_selector_empty_labels_no_match() {
    let labels = BTreeMap::new();
    assert!(!matches_label_selector(&labels, "team=backend"));
}

#[test]
fn label_selector_single_match() {
    let labels = BTreeMap::from([("team".into(), "backend".into())]);
    assert!(matches_label_selector(&labels, "team=backend"));
}

#[test]
fn label_selector_single_no_match() {
    let labels = BTreeMap::from([("team".into(), "backend".into())]);
    assert!(!matches_label_selector(&labels, "team=frontend"));
}

#[test]
fn label_selector_multiple_and_semantics() {
    let labels = BTreeMap::from([
        ("team".into(), "backend".into()),
        ("env".into(), "prod".into()),
    ]);
    assert!(matches_label_selector(&labels, "team=backend,env=prod"));
    assert!(!matches_label_selector(&labels, "team=backend,env=staging"));
}

#[test]
fn label_selector_whitespace_trimmed() {
    let labels = BTreeMap::from([("team".into(), "backend".into())]);
    assert!(matches_label_selector(&labels, " team = backend "));
}

#[test]
fn label_selector_missing_value_no_match() {
    let labels = BTreeMap::from([("team".into(), "backend".into())]);
    assert!(!matches_label_selector(&labels, "team"));
}

#[test]
fn label_selector_missing_key_in_labels() {
    let labels = BTreeMap::from([("team".into(), "backend".into())]);
    assert!(!matches_label_selector(&labels, "env=prod"));
}

#[test]
fn label_selector_value_with_equals_sign() {
    // key=val=ue should parse as key="val=ue" thanks to splitn(2, '=')
    let labels = BTreeMap::from([("expr".into(), "a=b".into())]);
    assert!(matches_label_selector(&labels, "expr=a=b"));
}

#[test]
fn label_selector_empty_value() {
    let labels = BTreeMap::from([("tag".into(), "".into())]);
    assert!(matches_label_selector(&labels, "tag="));
}

/// Fail-closed parity: the container driver cannot enforce a structured network
/// egress policy, so it must REJECT one rather than silently ignore it (which
/// would run the pod with unrestricted egress). RED on main — `spawn_container_pod`
/// had no such rejection at all.
#[test]
fn container_driver_rejects_network_policy_fail_closed() {
    use nucleus_spec::{PodSpecInner, PolicySpec};
    use std::path::PathBuf;
    let mk = |network| {
        PodSpec::new(PodSpecInner {
            work_dir: PathBuf::from("/workspace"),
            timeout_seconds: 3600,
            policy: PolicySpec::Profile {
                name: "default".to_string(),
            },
            budget_model: None,
            resources: None,
            network,
            credentialed_egress: Vec::new(),
            workload: None,
            image: None,
            vsock: None,
            seccomp: None,
            cgroup: None,
            audit_sink: None,
            credentials: None,
        })
    };
    let with_policy = mk(Some(
        serde_json::from_str::<nucleus_spec::NetworkSpec>("{}").unwrap(),
    ));
    assert!(
        container_driver_reject_unsupported_network_policy(&with_policy).is_err(),
        "container driver must reject a network egress policy it cannot enforce (fail-closed parity)"
    );
    let without = mk(None);
    assert!(container_driver_reject_unsupported_network_policy(&without).is_ok());
}

// ── VMM version floor: the launch path must fail closed ───────────────────

/// A Firecracker binary that does not exist must REFUSE, not pass.
///
/// This is the direction that matters. If an unrunnable or unreadable VMM
/// returned "acceptable", the floor would be defeated by anything that broke
/// the version probe — which is a far easier condition for an attacker to
/// arrange than shipping a specific vulnerable build.
#[tokio::test]
async fn vmm_preflight_refuses_a_binary_it_cannot_run() {
    let verdict = vmm_preflight(Path::new("/nonexistent/firecracker")).await;
    assert!(
        !verdict.is_acceptable(),
        "an unrunnable VMM must be refused, got {verdict:?}"
    );
}

/// A binary that runs but prints no recognisable version is also refused.
/// `/bin/echo --version` prints something, but not a Firecracker banner.
#[tokio::test]
async fn vmm_preflight_refuses_output_without_a_version() {
    let verdict = vmm_preflight(Path::new("/usr/bin/true")).await;
    assert!(
        !verdict.is_acceptable(),
        "output with no version triple must be refused, got {verdict:?}"
    );
}
// ── Egress chain: correspondence with the Lean confinement theorem ────────

use crate::net::{egress_chain, model_chain, ResolvedDnsEntry, RuleKind};
use nucleus_ifc_kernel::extracted::egress as eg;

fn spec_from(deny: &[&str], allow: &[&str]) -> nucleus_spec::NetworkSpec {
    serde_json::from_str(&format!(
        r#"{{"deny":{},"allow":{},"dns_allow":[]}}"#,
        serde_json::to_string(deny).unwrap(),
        serde_json::to_string(allow).unwrap()
    ))
    .expect("network spec")
}

/// Mirrors `EgressConfinement.verdict` in
/// crates/portcullis-core/lean/EgressConfinementExtracted.lean: first match
/// wins, and an unmatched packet falls through to the chain's DROP policy.
///
/// Written against the SAME extracted matcher the theorem is stated over, so
/// this is not a second implementation of the matching logic — only of the fold.
fn verdict(chain: &[eg::Rule], d: eg::Dest) -> bool {
    for r in chain {
        if eg::rule_matches(*r, d) {
            return r.allow;
        }
    }
    false
}

fn dest(a: u8, b: u8, c: u8, dd: u8, port: u16) -> eg::Dest {
    eg::Dest {
        addr: u32::from(std::net::Ipv4Addr::new(a, b, c, dd)),
        port,
    }
}

/// The ordering the theorem `deny_before_allow_wins` relies on. Reverse the two
/// extends in `egress_chain` and this fails.
#[test]
fn deny_precedes_allow_in_the_chain() {
    let spec = spec_from(&["10.0.0.7/32"], &["10.0.0.0/8", "192.168.0.0/16"]);
    let chain = egress_chain(&spec, None).expect("chain");
    let first_allow = chain
        .iter()
        .position(|r| r.kind == RuleKind::Allow)
        .expect("an allow exists");
    let last_deny = chain
        .iter()
        .rposition(|r| r.kind == RuleKind::Deny)
        .expect("a deny exists");
    assert!(
        last_deny < first_allow,
        "every deny must precede every allow: {chain:?}"
    );
}

/// A deny inside a broader allow still wins — the confused-deputy of firewalls.
/// This is `deny_before_allow_wins` instantiated on a real policy.
#[test]
fn a_specific_deny_beats_a_broader_allow() {
    let spec = spec_from(&["10.0.0.7/32"], &["10.0.0.0/8"]);
    let chain = egress_chain(&spec, None).expect("chain");
    let model = model_chain(&chain).expect("ipv4 chain is inside the model");

    assert!(
        !verdict(&model, dest(10, 0, 0, 7, 443)),
        "the denied host must not be reachable through the broader allow"
    );
    assert!(
        verdict(&model, dest(10, 0, 0, 8, 443)),
        "its neighbour in the allowed range must still be reachable"
    );
}

/// `unmatched_is_dropped`, on a real policy: anything no rule admits is dropped.
#[test]
fn a_destination_no_rule_admits_is_dropped() {
    let spec = spec_from(&[], &["10.0.0.0/8:443"]);
    let chain = egress_chain(&spec, None).expect("chain");
    let model = model_chain(&chain).expect("ipv4 chain is inside the model");

    for d in [
        dest(93, 184, 216, 34, 443), // outside the allowed network
        dest(10, 0, 0, 5, 80),       // inside the network, wrong port
        dest(11, 0, 0, 5, 443),      // adjacent network
    ] {
        assert!(!verdict(&model, d), "{d:?} must be dropped");
    }
    assert!(
        verdict(&model, dest(10, 0, 0, 5, 443)),
        "the allowed (network, port) must pass, or the test proves nothing"
    );
}

/// DNS-resolved allowlist entries are allows like any other, and must not
/// outrank a deny. If they were appended before the denies, a resolver handing
/// back a denied address would re-open it.
#[test]
fn dns_resolved_entries_do_not_outrank_a_deny() {
    let spec = spec_from(&["10.0.0.7/32"], &[]);
    let resolved = [ResolvedDnsEntry {
        host: "example.test".to_string(),
        port: Some(443),
        ips: vec![std::net::Ipv4Addr::new(10, 0, 0, 7)],
    }];
    let chain = egress_chain(&spec, Some(&resolved)).expect("chain");
    let model = model_chain(&chain).expect("ipv4 chain is inside the model");
    assert!(
        !verdict(&model, dest(10, 0, 0, 7, 443)),
        "a resolved name must not re-open a denied address"
    );
}

/// The model is IPv4-only, and says so rather than guessing. An IPv6 rule makes
/// `model_chain` return None — "not covered", never "covered and fine".
#[test]
fn an_ipv6_rule_falls_outside_the_model_rather_than_being_assumed_safe() {
    let spec = spec_from(&[], &["2001:db8::/32"]);
    let chain = egress_chain(&spec, None).expect("chain");
    assert!(
        model_chain(&chain).is_none(),
        "an IPv6 chain must be reported as outside the model"
    );
}

// ── Identity is gated on egress confinement ───────────────────────────────

use crate::net::{decide_identity_grant, IdentityGrant};

fn net_spec(allow: &[&str]) -> nucleus_spec::NetworkSpec {
    serde_json::from_str(&format!(
        r#"{{"allow":{},"deny":[],"dns_allow":[]}}"#,
        serde_json::to_string(allow).unwrap()
    ))
    .expect("network spec")
}

/// The headline trade: you may have the open internet, or a workload identity,
/// not both.
#[test]
fn a_wide_open_allowlist_forfeits_the_workload_identity() {
    assert!(!decide_identity_grant(Some(&net_spec(&["0.0.0.0/0"]))).is_granted());
}

/// Absence of a policy is the MOST confined state, not the least: `NetnsPlan`
/// still creates the netns and applies default-deny with no allow rules. If this
/// denied, the gate would push operators toward writing a policy in order to
/// keep an identity — inverting the incentive it exists to create.
#[test]
fn no_policy_at_all_still_gets_an_identity() {
    assert!(decide_identity_grant(None).is_granted());
}

/// Private space is fine at any breadth — reaching "some internal network"
/// cannot present a credential to the internet.
#[test]
fn broad_private_ranges_do_not_forfeit_the_identity() {
    for allow in [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
    ] {
        assert!(
            decide_identity_grant(Some(&net_spec(&[allow]))).is_granted(),
            "{allow} is non-routable and must not forfeit the identity"
        );
    }
}

/// A named public host keeps the identity: the destination set is enumerable,
/// which is the whole property. This is also what `dns_allow` resolves to, so
/// the ordinary "let me reach this API" case is unaffected.
#[test]
fn a_named_public_host_keeps_the_identity() {
    assert!(decide_identity_grant(Some(&net_spec(&["93.184.216.34/32"]))).is_granted());
    assert!(decide_identity_grant(Some(&net_spec(&["93.184.216.34/32:443"]))).is_granted());
}

/// …but a public RANGE does not, however small. /31 is two hosts and still
/// forfeits, because the rule is "name the host", not "keep it small" — a
/// size threshold would be an arbitrary line to argue about.
#[test]
fn a_public_range_forfeits_even_when_small() {
    for allow in ["93.184.216.0/24", "93.184.216.34/31", "128.0.0.0/1"] {
        assert!(
            !decide_identity_grant(Some(&net_spec(&[allow]))).is_granted(),
            "{allow} reaches unnamed public hosts and must forfeit the identity"
        );
    }
}

/// One bad entry forfeits, even alongside good ones — the check is over the
/// whole allow set, not a majority of it.
#[test]
fn one_unconfined_entry_forfeits_despite_confined_siblings() {
    let spec = net_spec(&["10.0.0.0/8", "93.184.216.34/32", "0.0.0.0/0"]);
    match decide_identity_grant(Some(&spec)) {
        IdentityGrant::Denied { offending } => assert_eq!(offending, "0.0.0.0/0"),
        IdentityGrant::Granted => panic!("a wide-open entry must forfeit the identity"),
    }
}

/// The refusal explains the trade rather than just saying no — an operator
/// reading it should be able to act on it.
#[test]
fn the_refusal_names_the_entry_and_the_remedy() {
    let msg = decide_identity_grant(Some(&net_spec(&["0.0.0.0/0"]))).to_string();
    assert!(msg.contains("0.0.0.0/0"), "names the entry: {msg}");
    assert!(
        msg.contains("dns_allow") || msg.contains("/32"),
        "names a remedy: {msg}"
    );
}

/// The wiring, not just the decision: a denied grant must withhold the port
/// even when identity management is fully enabled on the node.
#[test]
fn a_denied_grant_withholds_the_workload_api_port() {
    use crate::net::workload_api_port_for;
    let denied = IdentityGrant::Denied {
        offending: "0.0.0.0/0".to_string(),
    };
    assert_eq!(workload_api_port_for(true, &denied, 9000), None);
    assert_eq!(
        workload_api_port_for(true, &IdentityGrant::Granted, 9000),
        Some(9000)
    );
    // And identity being off on the node still wins regardless of the grant.
    assert_eq!(
        workload_api_port_for(false, &IdentityGrant::Granted, 9000),
        None
    );
}

/// The serving-side half of the gate: a denied pod is never registered, so
/// there is no identity to issue even if the guest reaches the listener.
#[test]
fn a_denied_grant_is_never_registered_with_the_workload_api() {
    use crate::net::identity_registration;
    let manager = "stand-in for IdentityManager";
    let denied = IdentityGrant::Denied {
        offending: "0.0.0.0/0".to_string(),
    };
    assert!(identity_registration(Some(&manager), &denied).is_none());
    assert!(identity_registration(Some(&manager), &IdentityGrant::Granted).is_some());
    // Identity disabled on the node still wins.
    assert!(identity_registration(None::<&&str>, &IdentityGrant::Granted).is_none());
}

// ── The DNS proxy is a static map, not a resolver ─────────────────────────

fn dns_entry(host: &str, a: u8, b: u8, c: u8, d: u8) -> ResolvedDnsEntry {
    ResolvedDnsEntry {
        host: host.to_string(),
        port: None,
        ips: vec![std::net::Ipv4Addr::new(a, b, c, d)],
    }
}

/// THE PROPERTY THAT CLOSES DNS TUNNELLING, and the reason it closes it.
///
/// A DNS tunnel needs a forwarder: the agent encodes data in query labels and
/// the resolver carries them to the attacker's authoritative server. Nothing in
/// the egress allowlist notices, because the query went to the allowed resolver.
///
/// nucleus's proxy has no upstream at all — `no-resolv` and not one `server=` —
/// so an unlisted name fails locally instead of travelling. That is currently
/// true by accident of how the config string was built; this test makes it a
/// property, so adding a forwarder is a test failure rather than a silent
/// re-opening of the channel.
#[test]
fn the_dns_proxy_has_no_upstream_and_cannot_forward() {
    use crate::net::{dnsmasq_config, DNS_FORWARDING_DIRECTIVES};
    let config = dnsmasq_config(
        std::net::Ipv4Addr::new(10, 200, 0, 2),
        &[dns_entry("api.example.test", 93, 184, 216, 34)],
    );
    assert!(
        config.lines().any(|l| l.trim() == "no-resolv"),
        "without no-resolv the proxy inherits the host's nameservers: {config}"
    );
    for directive in DNS_FORWARDING_DIRECTIVES {
        assert!(
            !config.contains(directive),
            "{directive} would give the proxy an upstream and re-open DNS tunnelling: {config}"
        );
    }
}

/// Answers come only from the allowlist. An entry that was never allowed has no
/// `address=` line, so it cannot even be resolved locally.
#[test]
fn only_allowlisted_names_get_an_answer() {
    use crate::net::dnsmasq_config;
    let config = dnsmasq_config(
        std::net::Ipv4Addr::new(10, 200, 0, 2),
        &[dns_entry("api.example.test", 93, 184, 216, 34)],
    );
    let addresses: Vec<&str> = config
        .lines()
        .filter(|l| l.starts_with("address=/"))
        .collect();
    assert_eq!(addresses, vec!["address=/api.example.test/93.184.216.34"]);
    assert!(!config.contains("evil.test"));
}

/// An empty allowlist yields a proxy that answers nothing — not one that falls
/// back to forwarding. The degenerate case is the one most likely to be got
/// wrong, and it is the one where getting it wrong is a wide-open resolver.
#[test]
fn an_empty_allowlist_answers_nothing_rather_than_forwarding() {
    use crate::net::{dnsmasq_config, DNS_FORWARDING_DIRECTIVES};
    let config = dnsmasq_config(std::net::Ipv4Addr::new(10, 200, 0, 2), &[]);
    assert!(!config.lines().any(|l| l.starts_with("address=/")));
    for directive in DNS_FORWARDING_DIRECTIVES {
        assert!(!config.contains(directive), "{directive} in empty config");
    }
    assert!(config.lines().any(|l| l.trim() == "no-resolv"));
}

// ── Secretless guest: the HMAC key is off the kernel command line ─────────

/// THE NEGATIVE TEST FOR PHASE 1. `nucleus.auth_secret` must not appear on any
/// guest kernel command line, for any spec.
///
/// /proc/cmdline is world-readable inside the guest, so a key there is a key
/// the agent can read and sign with. The vsock listener now establishes origin
/// from a peer CID the guest kernel sets, so the key is deleted rather than
/// relocated.
#[test]
fn the_auth_secret_never_reaches_the_guest_command_line() {
    use crate::snapshot::snapshot_safety;
    // The exact string the builder used to emit.
    let emitted = include_str!("firecracker_config.rs");
    let emits_auth_secret = emitted
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .any(|l| l.contains("nucleus.auth_secret={") || l.contains("nucleus.auth_secret="));
    assert!(
        !emits_auth_secret,
        "firecracker_config still emits nucleus.auth_secret onto the guest command line"
    );
    // And a command line carrying it would still be refused as a snapshot base,
    // which is the independent guard from the snapshot work.
    assert!(!snapshot_safety("console=ttyS0 nucleus.auth_secret=abc").is_safe_to_clone());
}

/// THE NEGATIVE TEST FOR SIGNED APPROVALS. The approval secret was the last
/// real secret on the guest command line — and it was worse than a leak: HMAC
/// is symmetric, so the guest's verification key was also a signing key, and
/// any workload reading /proc/cmdline could FORGE approvals. What rides now is
/// `nucleus.approval_pubkeys`, the Ed25519 PUBLIC half of the node's approval
/// key: verification only, no forging power. (This test previously pinned the
/// OPPOSITE — "still emitted and tracked" — and failed the moment the emission
/// was removed, exactly as intended.)
#[test]
fn the_approval_secret_never_reaches_the_guest_command_line() {
    use crate::snapshot::snapshot_safety;
    let src = include_str!("firecracker_config.rs");
    let emits_approval_secret = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .any(|l| l.contains("nucleus.approval_secret="));
    assert!(
        !emits_approval_secret,
        "firecracker_config emits nucleus.approval_secret again — that key lets any \
         /proc/cmdline reader forge approvals; approvals are Ed25519-verified against \
         nucleus.approval_pubkeys now"
    );
    // The pods must still be given the VERIFICATION key, or approvals brick.
    assert!(
        src.contains("nucleus.approval_pubkeys={approval_pubkeys}"),
        "the approval public key is no longer delivered — pods cannot verify approvals"
    );
    // And a command line carrying the old secret is still refused as a
    // snapshot base — the denylist is categorical, not tied to emission.
    assert!(!snapshot_safety("console=ttyS0 nucleus.approval_secret=abc").is_safe_to_clone());
}

// ── Proof-carrying admission: the posture gate on a real rootfs ───────────
//
// posture.rs unit-tests the pure parse/registry/verify logic. These exercise
// `admit_posture` end to end: it must MEASURE a real on-disk rootfs and compare
// the claim against that measurement, fail-closed, before any driver is spawned.

/// Build a minimal PodSpec with an optional `dlc_posture` label and a rootfs
/// path pointing at `rootfs`.
fn posture_spec(label: Option<&str>, rootfs: Option<&std::path::Path>) -> PodSpec {
    use nucleus_spec::{ImageSpec, PodSpecInner, PolicySpec};
    use std::path::PathBuf;
    let mut spec = PodSpec::new(PodSpecInner {
        work_dir: PathBuf::from("/work"),
        timeout_seconds: 60,
        policy: PolicySpec::Profile {
            name: "demo".to_string(),
        },
        budget_model: None,
        resources: None,
        network: None,
        credentialed_egress: Vec::new(),
        workload: None,
        image: rootfs.map(|p| ImageSpec {
            kernel_path: PathBuf::from("/does/not/matter"),
            rootfs_path: p.to_path_buf(),
            boot_args: None,
            read_only: true,
            scratch_path: None,
        }),
        vsock: None,
        seccomp: None,
        cgroup: None,
        audit_sink: None,
        credentials: None,
    });
    if let Some(l) = label {
        spec.metadata
            .labels
            .insert(posture::POSTURE_LABEL.to_string(), l.to_string());
    }
    spec
}

/// Write bytes to a temp file and return (dir keepalive, path, hex digest the
/// node will measure over it).
async fn rootfs_fixture(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rootfs.ext4");
    tokio::fs::write(&path, bytes).await.unwrap();
    let digest = hex::encode(
        nucleus_identity::attestation::measure_artifact(&path)
            .await
            .unwrap(),
    );
    (dir, path, digest)
}

#[tokio::test]
async fn admit_posture_inert_without_a_claim() {
    let (_dir, path, _digest) = rootfs_fixture(b"an artifact").await;
    let spec = posture_spec(None, Some(&path));
    let reg = posture::PostureRegistry::default();
    // No claim: inert, even with an empty registry and no image measured.
    assert_eq!(
        posture::admit_posture(&spec, Uuid::new_v4(), &reg)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn admit_posture_admits_a_matching_trusted_claim() {
    let (_dir, path, digest) = rootfs_fixture(b"the proven artifact").await;
    let label = format!("identity_nondelivery@{digest}");
    let spec = posture_spec(Some(&label), Some(&path));
    let reg =
        posture::PostureRegistry::from_operator_str(&format!("identity_nondelivery@{digest}"));
    assert_eq!(
        posture::admit_posture(&spec, Uuid::new_v4(), &reg)
            .await
            .unwrap(),
        Some("identity_nondelivery:verified".to_string())
    );
}

#[tokio::test]
async fn admit_posture_refuses_a_lying_digest() {
    // The pod claims a digest that is NOT the rootfs the node measures.
    let (_dir, path, real_digest) = rootfs_fixture(b"the real artifact").await;
    let lie = "0".repeat(64);
    assert_ne!(lie, real_digest);
    let label = format!("identity_nondelivery@{lie}");
    let spec = posture_spec(Some(&label), Some(&path));
    // Even trusting the LIE, the measurement mismatch must refuse.
    let reg = posture::PostureRegistry::from_operator_str(&format!("identity_nondelivery@{lie}"));
    assert!(posture::admit_posture(&spec, Uuid::new_v4(), &reg)
        .await
        .is_err());
}

#[tokio::test]
async fn admit_posture_refuses_an_untrusted_artifact() {
    // Digest matches the measurement, but no trusted builder proved this posture
    // for it (empty registry) — fail-closed.
    let (_dir, path, digest) = rootfs_fixture(b"an unregistered artifact").await;
    let label = format!("identity_nondelivery@{digest}");
    let spec = posture_spec(Some(&label), Some(&path));
    let reg = posture::PostureRegistry::default();
    assert!(posture::admit_posture(&spec, Uuid::new_v4(), &reg)
        .await
        .is_err());
}

#[tokio::test]
async fn admit_posture_refuses_a_claim_with_no_image_to_measure() {
    // A claim names a rootfs digest; without an image there is nothing to
    // measure, so it cannot be verified and must be refused.
    let label = format!("identity_nondelivery@{}", "a".repeat(64));
    let spec = posture_spec(Some(&label), None);
    let reg = posture::PostureRegistry::from_operator_str(&label);
    assert!(posture::admit_posture(&spec, Uuid::new_v4(), &reg)
        .await
        .is_err());
}

/// The perturbation the plan calls for: flipping one byte of the artifact
/// changes the measured digest, so a claim minted for the original REDs. This is
/// the property that makes the gate bind to the artifact, not to the pod's word.
#[tokio::test]
async fn admit_posture_one_byte_of_drift_reds_the_gate() {
    let (_dir, path, digest) = rootfs_fixture(b"artifact v1").await;
    let label = format!("identity_nondelivery@{digest}");
    let reg = posture::PostureRegistry::from_operator_str(&label);
    // As built, admitted.
    let spec = posture_spec(Some(&label), Some(&path));
    assert!(posture::admit_posture(&spec, Uuid::new_v4(), &reg)
        .await
        .is_ok());
    // Rewrite the rootfs with one byte changed: same claim, same registry, but
    // the measurement no longer matches.
    tokio::fs::write(&path, b"artifact v2").await.unwrap();
    let spec2 = posture_spec(Some(&label), Some(&path));
    assert!(
        posture::admit_posture(&spec2, Uuid::new_v4(), &reg)
            .await
            .is_err(),
        "a changed artifact must fail a claim minted for the original"
    );
}
