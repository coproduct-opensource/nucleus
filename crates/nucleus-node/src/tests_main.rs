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
    let verdict = vmm_preflight(
        Path::new("/nonexistent/firecracker"),
        tokio::time::Instant::now() + Duration::from_secs(1),
    )
    .await;
    assert!(
        !verdict.is_acceptable(),
        "an unrunnable VMM must be refused, got {verdict:?}"
    );
}

/// A binary that runs but prints no recognisable version is also refused.
/// `/bin/echo --version` prints something, but not a Firecracker banner.
#[tokio::test]
async fn vmm_preflight_refuses_output_without_a_version() {
    let verdict = vmm_preflight(
        Path::new("/usr/bin/true"),
        tokio::time::Instant::now() + Duration::from_secs(1),
    )
    .await;
    assert!(
        !verdict.is_acceptable(),
        "output with no version triple must be refused, got {verdict:?}"
    );
}
#[tokio::test]
async fn vmm_preflight_bounds_a_stalled_probe_and_skips_expired_launches() {
    use std::os::unix::fs::PermissionsExt;
    let executable = std::env::current_exe().unwrap();
    let dir = tempfile::tempdir_in(executable.parent().unwrap()).unwrap();
    let probe = dir.path().join("probe");
    std::fs::write(
        &probe,
        "#!/bin/sh\necho started > \"$0.started\"\nexec sleep 30\n",
    )
    .unwrap();
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).unwrap();
    let expired = vmm_preflight(&probe, tokio::time::Instant::now()).await;
    assert!(!expired.is_acceptable());
    assert!(!dir.path().join("probe.started").exists());
    let verdict = tokio::time::timeout(
        Duration::from_secs(5),
        vmm_preflight(&probe, tokio::time::Instant::now() + Duration::from_secs(1)),
    )
    .await
    .expect("stalled probe did not obey its deadline");
    assert!(dir.path().join("probe.started").exists());
    assert!(
        matches!(verdict, nucleus_spec::vmm_version::VmmVerdict::Unparseable { raw } if raw.contains("timed out"))
    );
    let ready = dir.path().join("ready");
    std::fs::write(
        &ready,
        format!(
            "#!/bin/sh\nprintf 'Firecracker v{}\\n'\n",
            nucleus_spec::vmm_version::PINNED_STR
        ),
    )
    .unwrap();
    std::fs::set_permissions(&ready, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        vmm_preflight(&ready, tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .is_acceptable()
    );
}

// ── Egress chain: correspondence with the Lean confinement theorem ────────

use crate::net::{ResolvedDnsEntry, RuleKind, egress_chain, model_chain};
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

/// #3120: the node's deny floor leads the chain, so no spec `allow` reaches the cloud metadata
/// service or the host end of a pod's veth link. On main `allow: ["0.0.0.0/0"]` reached both, and
/// `169.254.169.254/32` reached the metadata service while keeping the workload identity.
#[test]
fn no_allow_reopens_the_node_deny_floor() {
    let allows: [&[&str]; 4] = [
        &["0.0.0.0/0"],
        &["169.254.169.254/32"],
        &["169.254.0.0/16:80"],
        &["10.0.0.0/8"],
    ];
    for allow in allows {
        let spec = spec_from(&[], allow);
        let chain = egress_chain(&spec, None).expect("chain");
        let model = model_chain(&chain).expect("ipv4 chain is inside the model");
        for d in [
            dest(169, 254, 169, 254, 80), // instance metadata
            dest(10, 200, 0, 1, 8080),    // the first pod's host-side veth address
        ] {
            assert!(!verdict(&model, d), "{allow:?} reached {d:?}");
        }
    }
    // Non-vacuity: the floor denies only what it names.
    let open = spec_from(&[], &["0.0.0.0/0"]);
    let model = model_chain(&egress_chain(&open, None).expect("chain")).expect("model");
    assert!(
        verdict(&model, dest(93, 184, 216, 34, 443)),
        "the internet is still allowed"
    );
}

// ── The host side of a pod's link (#3134) ────────────────────────────────

use crate::net::host_link::{HostRule, Placement, host_link_rules};

const POD_LINK: &str = "vethpod0001";

/// A packet on the host, described by what netfilter decides it on.
#[derive(Clone, Copy, Debug)]
struct HostPacket {
    /// Arrived on this interface.
    in_iface: &'static str,
    /// Leaves on this interface, when forwarded.
    out_iface: Option<&'static str>,
    /// The destination, before NAT, is an address of the host (`addrtype --dst-type LOCAL`).
    dst_is_host: bool,
    /// After NAT the host delivers it locally (`INPUT`) rather than forwarding it.
    delivered_locally: bool,
    /// Conntrack has seen the other direction.
    established: bool,
}

/// Whether `rule` matches `p`, and the verdict it gives. `Masquerade` rewrites, it does not filter.
fn host_rule_verdict(rule: &HostRule, p: HostPacket) -> Option<bool> {
    match rule {
        HostRule::DropToHostBeforeNat { iface } => {
            (p.in_iface == iface && p.dst_is_host).then_some(false)
        }
        HostRule::DropInput { iface } => (p.in_iface == iface).then_some(false),
        HostRule::Masquerade { source: _ } => None,
        HostRule::ForwardFrom { iface } => (p.in_iface == iface).then_some(true),
        HostRule::ForwardRepliesTo { iface } => {
            (p.out_iface == Some(iface.as_str()) && p.established).then_some(true)
        }
    }
}

/// netfilter over the host's chains, first match wins per chain, with every host policy ACCEPT:
/// the worst host nucleus can land on, and the default of a stock install. `raw PREROUTING`, then
/// `INPUT` for a locally delivered packet or `FORWARD` for a forwarded one.
fn host_admits(rules: &[HostRule], p: HostPacket) -> bool {
    let chain = |name: &str| -> bool {
        rules
            .iter()
            .filter(|r| r.chain() == name)
            .find_map(|r| host_rule_verdict(r, p))
            .unwrap_or(true)
    };
    chain("PREROUTING")
        && chain(if p.delivered_locally {
            "INPUT"
        } else {
            "FORWARD"
        })
}

fn from_pod(dst_is_host: bool, delivered_locally: bool) -> HostPacket {
    HostPacket {
        in_iface: POD_LINK,
        out_iface: (!delivered_locally).then_some("eth0"),
        dst_is_host,
        delivered_locally,
        established: false,
    }
}

/// #3134: a pod whose spec allows `0.0.0.0/0` does not reach the host it runs on. Its own chain
/// admits the host's LAN address (that is the gap: the namespace cannot name it), so the host
/// side of the link is what has to drop it, for every host address and for a host port published
/// with DNAT. On main nothing filtered the link's INPUT and both arrived.
#[test]
fn an_open_allowlist_does_not_reach_the_host() {
    let spec = spec_from(&[], &["0.0.0.0/0"]);
    let model = model_chain(&egress_chain(&spec, None).expect("chain")).expect("model");
    assert!(
        verdict(&model, dest(192, 0, 2, 10, 22)),
        "the pod's own chain admits the host's LAN address; this test is about the host side"
    );

    let rules = host_link_rules(POD_LINK, "10.200.0.0/30".parse().unwrap());
    for (what, p) in [
        ("a host address", from_pod(true, true)),
        (
            "a host port DNAT'd to a local container",
            from_pod(true, false),
        ),
    ] {
        assert!(!host_admits(&rules, p), "the pod reached {what}");
    }

    // What the pod legitimately needs still passes: forwarded egress (the internet, and a public
    // resolver on 53) and the replies to it. Its DNS proxy is inside its own namespace.
    assert!(
        host_admits(&rules, from_pod(false, false)),
        "egress is forwarded"
    );
    let reply = HostPacket {
        in_iface: "eth0",
        out_iface: Some(POD_LINK),
        dst_is_host: false,
        delivered_locally: false,
        established: true,
    };
    assert!(host_admits(&rules, reply), "replies reach the pod");
    // Another interface is not this link's business.
    let other = HostPacket {
        in_iface: "eth0",
        out_iface: None,
        dst_is_host: true,
        delivered_locally: true,
        established: false,
    };
    assert!(
        host_admits(&rules, other),
        "the drops are scoped to the pod's link"
    );
}

/// The node-owned drops are installed first and at the head of their chains, so neither the
/// link's own accepts nor anything the host's firewall put first can precede them.
#[test]
fn the_host_drops_lead_and_are_rendered_at_the_head() {
    let rules = host_link_rules(POD_LINK, "10.200.0.0/30".parse().unwrap());
    let is_drop = |r: &HostRule| r.add_argv().last().map(String::as_str) == Some("DROP");
    let last_drop = rules.iter().rposition(is_drop).expect("a drop exists");
    let first_accept = rules
        .iter()
        .position(|r| !is_drop(r))
        .expect("an accept exists");
    assert!(last_drop < first_accept, "{rules:?}");
    for r in rules.iter().filter(|r| is_drop(r)) {
        assert_eq!(r.placement(), Placement::Head, "{r:?}");
    }
    let argv = |r: &HostRule| r.add_argv().join(" ");
    assert_eq!(
        argv(&rules[0]),
        format!("-t raw -I PREROUTING 1 -i {POD_LINK} -m addrtype --dst-type LOCAL -j DROP")
    );
    assert_eq!(
        argv(&rules[1]),
        format!("-t filter -I INPUT 1 -i {POD_LINK} -j DROP")
    );
    // Teardown names the same rule setup installed.
    for r in &rules {
        let (add, del) = (r.add_argv(), r.delete_argv());
        assert_eq!(del[2], "-D", "{del:?}");
        assert!(add.ends_with(&del[4..]), "{add:?} vs {del:?}");
    }
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

use crate::net::{IdentityGrant, decide_identity_grant};

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
    use crate::net::{DNS_FORWARDING_DIRECTIVES, dnsmasq_config};
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
    use crate::net::{DNS_FORWARDING_DIRECTIVES, dnsmasq_config};
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
            rootfs: nucleus_spec::RootfsSource::Path(p.to_path_buf()),
            boot_args: None,
            read_only: true,
            scratch_path: None,
            kernel_digest: None,
            rootfs_digest: None,
            scratch_digest: None,
            data_path: None,
            data_digest: None,
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
    assert!(
        posture::admit_posture(&spec, Uuid::new_v4(), &reg)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn admit_posture_refuses_an_untrusted_artifact() {
    // Digest matches the measurement, but no trusted builder proved this posture
    // for it (empty registry) — fail-closed.
    let (_dir, path, digest) = rootfs_fixture(b"an unregistered artifact").await;
    let label = format!("identity_nondelivery@{digest}");
    let spec = posture_spec(Some(&label), Some(&path));
    let reg = posture::PostureRegistry::default();
    assert!(
        posture::admit_posture(&spec, Uuid::new_v4(), &reg)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn admit_posture_refuses_a_claim_with_no_image_to_measure() {
    // A claim names a rootfs digest; without an image there is nothing to
    // measure, so it cannot be verified and must be refused.
    let label = format!("identity_nondelivery@{}", "a".repeat(64));
    let spec = posture_spec(Some(&label), None);
    let reg = posture::PostureRegistry::from_operator_str(&label);
    assert!(
        posture::admit_posture(&spec, Uuid::new_v4(), &reg)
            .await
            .is_err()
    );
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
    assert!(
        posture::admit_posture(&spec, Uuid::new_v4(), &reg)
            .await
            .is_ok()
    );
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

// ── Authority gate wiring (pod_authority) ──────────────────────────────────

/// The authority gate cannot be dropped from pod creation without this
/// failing — the `include_str!` idiom `pod_mgmt.rs` uses for the same reason:
/// an unwired security check is the failure shape this repo keeps finding.
/// Both entry points (HTTP and gRPC) funnel into `create_pod_internal`, so
/// this one site is the whole surface.
#[test]
fn create_pod_internal_still_consults_the_authority_gate() {
    let src = include_str!("main.rs");
    let body = src
        .split("async fn create_pod_internal(")
        .nth(1)
        .expect("create_pod_internal exists");
    let body = &body[..body.find("\nasync fn ").unwrap_or(body.len())];
    assert!(
        body.contains("state.authority.admit("),
        "create_pod_internal must consult pod_authority::admit before any driver spawns"
    );
    assert!(
        body.contains("let reservation = issued.apply_to(&mut spec);"),
        "the issued effective lattice and admitted upstreams must replace the requested \
         policy and credentialed_egress before spawn (`IssuedAuthority::apply_to`)"
    );
    assert!(
        body.contains("reservation.release().await;") && body.contains("reservation.commit();"),
        "a failed spawn hands the budget reservation back, and only a registered pod keeps it \
         (a dropped create releases through the guard's Drop, #3032). `Reservation::release` \
         is the unspawned arm: nothing ran, so the spend is zero, where `release_child(_)` \
         would fold the WHOLE allocation into the parent"
    );
    // Both entry points build an Admission — neither bypasses the gate.
    assert!(src.contains("pod_authority::Admission::from_http("));
    assert!(src.contains("pod_authority::Admission::from_grpc("));
}

#[test]
fn pod_listing_reports_root_lineage_explicitly() {
    let mut info = PodInfo {
        id: Uuid::new_v4(),
        name: Some("probe".into()),
        created_at_unix: 1,
        state: PodState::Running,
        proxy_addr: None,
        labels: BTreeMap::new(),
        parent_pod_id: None,
        posture: None,
    };
    let value = serde_json::to_value(&info).unwrap();
    assert_eq!(
        value.get("parent_pod_id"),
        Some(&serde_json::Value::Null),
        "missing lineage is not evidence of a root pod"
    );
    let parent = Uuid::new_v4();
    info.parent_pod_id = Some(parent);
    assert_eq!(
        serde_json::to_value(&info).unwrap()["parent_pod_id"],
        parent.to_string()
    );
}

/// A cancelled container pod reports the state it exited in, not an error.
///
/// Cancel used to remove the container without caching its exit state first
/// (exit cleanup did), so every later `status()` inspected a container that no
/// longer existed and read `Error` — and the reaper audited the exit as "No such
/// container". Needs a real Docker daemon, so it is ignored by default:
/// `NUCLEUS_TEST_DOCKER_IMAGE=<local image> cargo test -p nucleus-node --bin nucleus-node -- --ignored a_cancelled_container`.
#[tokio::test]
#[ignore = "needs a Docker daemon and a local image in NUCLEUS_TEST_DOCKER_IMAGE"]
async fn a_cancelled_container_reports_its_exit_not_an_error() {
    let image = std::env::var("NUCLEUS_TEST_DOCKER_IMAGE")
        .expect("NUCLEUS_TEST_DOCKER_IMAGE names an image already present locally");
    let docker = bollard::Docker::connect_with_local_defaults().expect("a Docker daemon");
    let created = docker
        .create_container(
            None::<bollard::query_parameters::CreateContainerOptions>,
            bollard::models::ContainerCreateBody {
                image: Some(image),
                cmd: Some(vec!["sleep".to_string(), "300".to_string()]),
                ..Default::default()
            },
        )
        .await
        .expect("create container");
    docker
        .start_container(
            &created.id,
            None::<bollard::query_parameters::StartContainerOptions>,
        )
        .await
        .expect("start container");
    let pod = ContainerPod {
        launch_intent: None,
        container_id: created.id.clone(),
        docker,
        signed_proxy: Mutex::new(None),
        permit: Mutex::new(None),
        cached_exit: Mutex::new(None),
    };
    // Non-vacuity: it was running, so the cancel had something to stop.
    assert!(matches!(pod.status().await, PodState::Running));

    let handle = PodHandle {
        id: uuid::Uuid::new_v4(),
        spec: serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#)
            .expect("minimal spec"),
        created_at: 1_757_000_000,
        execution_deadline: tokio::time::Instant::now() + Duration::from_secs(3600),
        log_path: std::env::temp_dir().join("container-cancel-test.log"),
        proxy_addr: Mutex::new(None),
        driver_state: DriverState::Container(Box::new(pod)),
        parent_pod_id: None,
        posture_stamp: None,
        owner: None,
        capacity: tokio::sync::Mutex::new(None),
    };
    handle.cancel().await.expect("cancel");
    let after = handle.status().await;
    assert!(
        matches!(after, PodState::Exited { .. }),
        "a cancelled container reports {after:?}, not the state it exited in"
    );
}

/// clap prints an env-backed arg's CURRENT value in `--help` unless the arg
/// hides it, so a secret sitting in the environment reaches the terminal, shell
/// logs and CI logs (#3026). Walked over the whole command tree, so a new flag
/// or subcommand that forgets `hide_env_values` reds here.
#[test]
fn help_never_prints_an_env_value() {
    fn walk(cmd: &clap::Command, seen: &mut usize, shown: &mut Vec<String>) {
        for arg in cmd.get_arguments().filter(|a| a.get_env().is_some()) {
            *seen += 1;
            if !arg.is_hide_env_values_set() {
                shown.push(format!("{} --{}", cmd.get_name(), arg.get_id()));
            }
        }
        for sub in cmd.get_subcommands() {
            walk(sub, seen, shown);
        }
    }
    let (mut seen, mut shown) = (0, Vec::new());
    walk(
        &<Args as clap::CommandFactory>::command(),
        &mut seen,
        &mut shown,
    );
    assert!(
        seen > 0,
        "no env-backed arg was found; the walk reached nothing"
    );
    assert!(
        shown.is_empty(),
        "--help would print the value of: {shown:?}"
    );
}

/// #2903, the container half. The container driver runs the same tool-proxy as
/// the local driver (proxy mode), and it had no copy of the dlc_* label->env
/// mapping at all: a container pod's labels were accepted, listed by `nucleus
/// node pods`, and never reached the gate. Driven red by deleting the
/// `DlcProvisioning::from_labels` block from `container_env`, which is exactly
/// what main had.
#[cfg(feature = "local-driver")]
#[tokio::test]
async fn a_container_pods_dlc_labels_reach_its_tool_proxy() {
    use nucleus_spec::dlc_admission::{DlcField, ENV_PREFIX};

    let dir = tempfile::tempdir().expect("tempdir");
    let state = crate::pod_api::handler_tests::state(&dir);
    let dlc = DlcProvisioning {
        trusted_keys: "aa".repeat(32),
        issuer: "bb".repeat(32),
        credentials: "read_files=cc".to_string(),
    };
    let mut spec: PodSpec =
        serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#)
            .expect("minimal spec");
    // The labels a spec author writes, through the same declaration.
    spec.metadata.labels = dlc.labels();
    assert!(
        spec.metadata
            .labels
            .contains_key(DlcField::TrustedKeys.label())
    );

    let proxy = container_env(
        &state,
        &spec,
        Uuid::new_v4(),
        "test-token-123",
        "",
        None,
        None,
    )
    .await;
    for (key, value) in dlc.env() {
        let want = format!("{key}={value}");
        assert!(
            proxy.contains(&want),
            "a proxy-mode container must carry {key}; got {:?}",
            proxy
                .iter()
                .map(|e| e.split('=').next())
                .collect::<Vec<_>>()
        );
    }

    // Direct mode runs no tool-proxy, so there is nothing to arm and the
    // credentials stay out of the workload's environment.
    let mut direct_state = state.clone();
    direct_state.container_mediation = crate::container_mediation::ContainerMediation::Unmediated;
    let direct = container_env(
        &direct_state,
        &spec,
        Uuid::new_v4(),
        "test-token-123",
        "",
        None,
        None,
    )
    .await;
    assert!(
        !direct.iter().any(|e| e.starts_with(ENV_PREFIX)),
        "a direct-mode container is the workload itself and must not hold DLC credentials"
    );
}

/// What a child spawned from `command` actually starts with: this process's environment (a
/// `Command` inherits it unless told otherwise), with the command's own sets and removals applied.
#[cfg(feature = "local-driver")]
fn effective_env(command: &Command) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = std::env::vars().collect();
    for (key, value) in command.as_std().get_envs() {
        let key = key.to_string_lossy().into_owned();
        match value {
            Some(value) => {
                env.insert(key, value.to_string_lossy().into_owned());
            }
            None => {
                env.remove(&key);
            }
        }
    }
    env
}

/// #3160, the local driver. The node's own cloud key writes anywhere the operator's account
/// reaches, so it must never be in the local tool-proxy's environment: not forwarded, and not
/// inherited either, because a `Command` inherits the node's whole environment by default. Red on
/// #3155's head, which forwarded the key to every pod with an audit sink and let every other pod
/// inherit it.
#[cfg(feature = "local-driver")]
#[tokio::test]
async fn the_ambient_key_never_reaches_a_local_uploader() {
    use audit_sink::credentials::fake;
    audit_sink::ambient_fixture::plant();
    let grant = fake::grant(fake::target()).await;
    for audit in [None, Some(&grant)] {
        let mut command = Command::new("tool-proxy");
        provision_local_audit_env(&mut command, audit);
        let env = effective_env(&command);
        let leaked: Vec<&String> = env
            .iter()
            .filter(|(_, value)| audit_sink::ambient_fixture::leaks(value))
            .map(|(key, _)| key)
            .collect();
        assert!(
            leaked.is_empty(),
            "the node's ambient key reached the local uploader (sink: {}) under {leaked:?}",
            audit.is_some()
        );
        if audit.is_some() {
            // Non-vacuity: the uploader does hold a credential, and it is the minted one.
            assert_eq!(
                env.get("AWS_ACCESS_KEY_ID").map(String::as_str),
                Some(fake::MINTED_KEY_ID)
            );
            assert_eq!(
                env.get("AWS_SECRET_ACCESS_KEY").map(String::as_str),
                Some(fake::MINTED_SECRET)
            );
            assert_eq!(
                env.get("NUCLEUS_TOOL_PROXY_AUDIT_S3_PREFIX")
                    .map(String::as_str),
                Some("nucleus/team-a")
            );
        }
    }
}

/// #3160, the container driver. Red on #3155's head, which copied the node's ambient key into
/// the container's environment for any pod with an audit sink.
#[cfg(feature = "local-driver")]
#[tokio::test]
async fn the_ambient_key_never_reaches_a_container_uploader() {
    use audit_sink::credentials::fake;
    audit_sink::ambient_fixture::plant();
    let dir = tempfile::tempdir().expect("tempdir");
    let state = crate::pod_api::handler_tests::state(&dir);
    let spec: PodSpec =
        serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#)
            .expect("minimal spec");
    let grant = fake::grant(fake::target()).await;
    let env = container_env(
        &state,
        &spec,
        Uuid::new_v4(),
        "test-token-123",
        "",
        Some(&grant),
        None,
    )
    .await;
    let leaked: Vec<&str> = env
        .iter()
        .filter(|e| audit_sink::ambient_fixture::leaks(e))
        .filter_map(|e| e.split('=').next())
        .collect();
    assert!(
        leaked.is_empty(),
        "the node's ambient key reached the container uploader under {leaked:?}"
    );
    // Non-vacuity: the uploader does hold a credential, and it is the minted one.
    assert!(
        env.contains(&format!("AWS_ACCESS_KEY_ID={}", fake::MINTED_KEY_ID)),
        "the container uploader holds no minted credential"
    );
}

/// #3160: a node with an audit sink configured but no credential minter refuses a spec that names
/// the sink, at create, by the sink's name, before anything is spawned. It does not fall back to
/// the node's own key.
#[cfg(feature = "local-driver")]
#[tokio::test]
async fn a_sink_without_a_minter_is_refused_at_create_by_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut st = crate::pod_api::handler_tests::state(&dir);
    st.audit_sinks = Arc::new(
        audit_sink::AuditSinks::from_toml(
            "[[sink]]\nname = \"audit\"\nbucket = \"operator-audit\"\nprefix = \"nucleus\"\n",
        )
        .expect("loads"),
    );
    assert!(st.audit_minter.is_none(), "the fixture has no minter");
    let spec: PodSpec = serde_json::from_str(
        r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"audit_sink":{"sink":"audit","prefix":"team-a"}}}"#,
    )
    .expect("spec parses");
    let admission = crate::pod_authority::Admission {
        caller_spiffe_id: st.authority.root_minter().to_string(),
        caller_pod: None,
        header_cert: None,
    };
    let refused = create_pod_internal(&st, spec, None, None, admission)
        .await
        .expect_err("no minter: the sink is unavailable");
    let msg = refused.to_string();
    assert!(
        matches!(refused, ApiError::InvalidSpec(_)),
        "a refusal, not a driver failure: {msg}"
    );
    assert!(msg.contains("audit_sink.sink `audit`"), "{msg}");
    assert!(msg.contains("no scoped credential minter"), "{msg}");
    assert!(msg.contains("operator-audit/nucleus/team-a/*"), "{msg}");
    assert!(
        st.pods.lock().await.is_empty(),
        "nothing was registered for a refused create"
    );
}
