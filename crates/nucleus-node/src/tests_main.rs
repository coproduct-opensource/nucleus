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
