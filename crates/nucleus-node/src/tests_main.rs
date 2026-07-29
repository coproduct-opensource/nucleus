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
