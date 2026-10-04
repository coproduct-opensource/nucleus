//! #3120: each posture field a spec could use to weaken its pod is refused at create.
//!
//! Every test names the spec a hostile author would have written on main and asserts the refusal
//! names the field. Each was driven red by making the check it pins admit (see the PR body).

use super::*;

/// The node's default ceilings: these tests are about the other fields.
fn admit(s: &PodSpec) -> Result<(), PostureRefused> {
    super::admit(s, &PodCeilings::defaults())
}

fn spec(inner: &str) -> PodSpec {
    serde_json::from_str(&format!(
        r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{inner}}}"#
    ))
    .expect("test spec parses")
}

fn sink(fields: &str) -> PodSpec {
    spec(&format!(r#"{{"audit_sink":{{{fields}}}}}"#))
}

fn refused(s: &PodSpec) -> PostureRefused {
    admit(s).expect_err("a hostile spec must be refused at create")
}

/// The finding: a bucket was appended verbatim to the guest command line, so it could carry its
/// own `init=` (the kernel takes the last one) or any other token the node did not write.
#[test]
fn an_audit_sink_value_cannot_carry_a_second_kernel_token() {
    for (fields, field) in [
        (r#""s3_bucket":"b init=/bin/sh""#, "s3_bucket"),
        (
            r#""s3_bucket":"bkt","s3_prefix":"p ipv6.disable=0""#,
            "s3_prefix",
        ),
        (
            r#""s3_bucket":"bkt","s3_region":"us-east-1 NUCLEUS_TOOL_PROXY_POLICY=permissive""#,
            "s3_region",
        ),
        (
            r#""s3_bucket":"bkt","s3_endpoint":"https://x \"init=/bin/sh""#,
            "s3_endpoint",
        ),
        (r#""s3_bucket":"bkt","s3_prefix":"a\tb""#, "s3_prefix"),
    ] {
        let e = refused(&sink(fields));
        assert!(
            matches!(&e, PostureRefused::AuditSink { field: f, .. } if *f == field),
            "{fields}: {e}"
        );
        let msg = ApiError::from(e).to_string();
        assert!(msg.contains(field), "the refusal names the field: {msg}");
    }
}

#[test]
fn an_audit_sink_outside_its_grammar_is_refused() {
    for fields in [
        r#""s3_bucket":"UPPER""#,
        r#""s3_bucket":"ab""#,
        r#""s3_bucket":"-leading""#,
        r#""s3_bucket":"bkt","s3_endpoint":"file:///etc/passwd""#,
        r#""s3_bucket":"bkt","s3_prefix":"""#,
        r#""s3_bucket":"bkt","s3_region":"US""#,
    ] {
        assert!(
            matches!(refused(&sink(fields)), PostureRefused::AuditSink { .. }),
            "{fields}"
        );
    }
}

/// The control: an ordinary sink is admitted and renders one token per value, in order.
#[test]
fn an_ordinary_audit_sink_renders_one_token_per_value() {
    let s = sink(
        r#""s3_bucket":"audit.example-1","s3_prefix":"audit/pod-a/","s3_region":"us-east-1",
            "s3_endpoint":"https://minio.internal:9000""#,
    );
    admit(&s).expect("an ordinary sink is admitted");
    let tokens = audit_sink_boot_args(s.spec.audit_sink.as_ref().expect("sink")).expect("renders");
    assert_eq!(
        tokens,
        [
            "nucleus.audit_s3_bucket=audit.example-1",
            "nucleus.audit_s3_prefix=audit/pod-a/",
            "nucleus.audit_s3_region=us-east-1",
            "nucleus.audit_s3_endpoint=https://minio.internal:9000",
        ]
    );
    for t in &tokens {
        assert_eq!(t.split_whitespace().count(), 1, "{t}");
    }
}

/// CID 2 is the host's; the in-guest proxy accepts the host by it. Every other CID panics the
/// guest (#2395). Only the node's CID is admitted.
#[test]
fn the_guest_cid_is_the_nodes() {
    for cid in [0, 1, 2, 4, 100, u32::MAX] {
        let s = spec(&format!(r#"{{"vsock":{{"guest_cid":{cid},"port":5000}}}}"#));
        assert_eq!(refused(&s), PostureRefused::GuestCid { cid });
    }
    let ok = spec(&format!(
        r#"{{"vsock":{{"guest_cid":{GUEST_CID},"port":5000}}}}"#
    ));
    admit(&ok).expect("the node's own CID is admitted");
}

/// On the container driver `credentials.env` is appended after the runtime's own variables, so
/// these names would have replaced the mediator's configuration.
#[test]
fn a_credential_cannot_name_a_runtime_variable() {
    for key in [
        "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET",
        "NUCLEUS_SANDBOX_TOKEN",
        "NUCLEUS_TOOL_PROXY_AUDIT_LOG",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "BAD=NAME",
        "has space",
        "",
        "1LEADING_DIGIT",
    ] {
        let s = spec(&format!(
            r#"{{"credentials":{{"env":{{{}:"x"}}}}}}"#,
            serde_json::to_string(key).expect("json key")
        ));
        assert!(
            matches!(refused(&s), PostureRefused::CredentialName { key: k, .. } if k == key),
            "`{key}` must be refused"
        );
    }
    let ok = spec(
        r#"{"credentials":{"env":{"LLM_API_TOKEN":"test-token-123","NUCLEUS_TASK_CMD":"run"}}}"#,
    );
    admit(&ok).expect("an ordinary credential and the task runner are admitted");
}

/// A value past `TimeDelta`'s range panicked the create handler (`Duration::seconds`); one inside
/// it minted certificates and task tokens for centuries.
#[test]
fn a_timeout_past_the_ceiling_is_refused() {
    for seconds in [MAX_TIMEOUT_SECONDS + 1, i64::MAX as u64, u64::MAX] {
        let s = spec(&format!(r#"{{"timeout_seconds":{seconds}}}"#));
        assert_eq!(refused(&s), PostureRefused::Timeout { seconds });
    }
    admit(&spec(&format!(
        r#"{{"timeout_seconds":{MAX_TIMEOUT_SECONDS}}}"#
    )))
    .expect("the ceiling itself is admitted");
    admit(&spec("{}")).expect("the default timeout is admitted");
}

/// A spec priced its own executions. Zero per-second also removed the time guard requirement.
#[test]
fn a_budget_model_cannot_undercut_the_runtime() {
    for (model, field) in [
        (
            r#"{"base_cost_usd":0.0,"cost_per_second_usd":0.0001}"#,
            "base_cost_usd",
        ),
        (
            r#"{"base_cost_usd":0.5,"cost_per_second_usd":0.0}"#,
            "cost_per_second_usd",
        ),
        (
            r#"{"base_cost_usd":-1.0,"cost_per_second_usd":1.0}"#,
            "base_cost_usd",
        ),
    ] {
        let s = spec(&format!(r#"{{"budget_model":{model}}}"#));
        assert!(
            matches!(refused(&s), PostureRefused::BudgetModel { field: f, .. } if f == field),
            "{model}"
        );
    }
    let mut nan = spec(r#"{"budget_model":{"base_cost_usd":1.0,"cost_per_second_usd":1.0}}"#);
    nan.spec.budget_model.as_mut().expect("model").base_cost_usd = f64::NAN;
    assert!(matches!(refused(&nan), PostureRefused::BudgetModel { .. }));

    admit(&spec(
        r#"{"budget_model":{"base_cost_usd":0.5,"cost_per_second_usd":0.25}}"#,
    ))
    .expect("a dearer price is admitted");
}

/// The container driver's network mode came from a label the spec author sets.
#[test]
fn a_container_pod_cannot_choose_a_wider_network() {
    for label in ["host", "container:other-pod", "bridge"] {
        assert_eq!(
            container_network(Some(label), "none"),
            Err(PostureRefused::ContainerNetwork {
                value: label.into(),
                node: "none".into()
            })
        );
    }
    assert_eq!(container_network(None, "bridge").as_deref(), Ok("bridge"));
    assert_eq!(
        container_network(Some("none"), "bridge").as_deref(),
        Ok("none")
    );
    assert_eq!(
        container_network(Some("bridge"), "bridge").as_deref(),
        Ok("bridge")
    );
}

fn labelled(label: &str, value: &str) -> PodSpec {
    let mut s = spec("{}");
    s.metadata.labels.insert(label.into(), value.into());
    s
}

/// #3133: the container driver read whether to run the tool-proxy, and which image it came from,
/// from these labels. Each is refused by name whatever its value, including the value that asks
/// for mediation: the node no longer reads it, and an ignored label would mislead its author.
#[test]
fn a_spec_cannot_choose_its_own_mediation() {
    for (label, value) in [
        ("nucleus.io/proxy-mode", "false"),
        ("nucleus.io/proxy-mode", "true"),
        ("nucleus.io/proxy-mode", ""),
        (
            "nucleus.io/container-image",
            "attacker.example/mediator:latest",
        ),
        ("nucleus.io/container-image", "nucleus-tool-proxy:latest"),
    ] {
        let err = refused(&labelled(label, value));
        assert!(
            matches!(err, PostureRefused::NodeOwnedLabel { label: l, .. } if l == label),
            "{label}={value}: {err:?}"
        );
        assert!(err.to_string().contains(label), "{err}");
    }
    // Neighbouring labels the node still reads are not swept up.
    admit(&labelled("nucleus.io/network", "none")).expect("network label is admitted here");
}

/// A spec with none of these fields is admitted unchanged: the default is not a refusal.
#[test]
fn a_minimal_spec_is_admitted() {
    admit(&spec("{}")).expect("minimal spec");
}

/// End to end through the real create path: the refusal happens in `create_pod_internal`, before
/// the authority admits anything or a driver spawns. Built on the local driver's fixture, which is
/// the one `NodeState` a test can construct.
#[cfg(feature = "local-driver")]
#[tokio::test]
async fn create_refuses_a_hostile_posture_before_anything_is_spawned() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = crate::pod_api::handler_tests::state(&dir);
    let root = crate::pod_authority::Admission {
        caller_spiffe_id: st.authority.root_minter().to_string(),
        caller_pod: None,
        header_cert: None,
    };
    let hostile = sink(r#""s3_bucket":"b init=/bin/sh""#);
    let Err(ApiError::InvalidSpec(msg)) =
        crate::create_pod_internal(&st, hostile, None, None, root).await
    else {
        panic!("a spec writing the guest command line must be refused at create");
    };
    assert!(msg.contains("audit_sink.s3_bucket"), "{msg}");
    assert!(st.pods.lock().await.is_empty(), "nothing was registered");

    // #3130, through the same create path: a terabyte of guest memory is refused by name.
    let greedy = spec(r#"{"resources":{"memory_mib":1048576}}"#);
    let root = crate::pod_authority::Admission {
        caller_spiffe_id: st.authority.root_minter().to_string(),
        caller_pod: None,
        header_cert: None,
    };
    let Err(ApiError::InvalidSpec(msg)) =
        crate::create_pod_internal(&st, greedy, None, None, root).await
    else {
        panic!("a pod larger than the node's ceiling must be refused at create");
    };
    assert!(msg.contains("resources.memory_mib 1048576"), "{msg}");
    assert!(st.pods.lock().await.is_empty(), "nothing was registered");
}

/// #3130: the size is decided at create by the same one decider, and the refusal reaches the
/// caller as an invalid spec naming the field. On main a terabyte of guest memory was admitted.
#[test]
fn a_size_above_the_node_ceiling_is_refused_at_create() {
    for (inner, field) in [
        (r#"{"resources":{"memory_mib":1048576}}"#, "memory_mib"),
        (r#"{"resources":{"cpu_cores":32}}"#, "cpu_cores"),
        (r#"{"resources":{"huge_pages":"2M"}}"#, "huge_pages"),
        (
            r#"{"cgroup":{"path":"/sys/fs/cgroup/n","settings":[{"file":"memory.max","value":"max"}]}}"#,
            "memory.max",
        ),
    ] {
        let e = refused(&spec(inner));
        assert!(matches!(e, PostureRefused::Resources(_)), "{inner}: {e}");
        let msg = ApiError::from(e).to_string();
        assert!(msg.contains(field), "the refusal names {field}: {msg}");
    }
}

/// #3133 end to end: a child or tenant naming the mediation label is refused by the create path
/// itself, so `create_sub_pod`'s label passthrough cannot reach the container driver with it.
#[cfg(feature = "local-driver")]
#[tokio::test]
async fn create_refuses_a_spec_choosing_its_mediation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = crate::pod_api::handler_tests::state(&dir);
    let root = crate::pod_authority::Admission {
        caller_spiffe_id: st.authority.root_minter().to_string(),
        caller_pod: None,
        header_cert: None,
    };
    let hostile = labelled("nucleus.io/proxy-mode", "false");
    let Err(ApiError::InvalidSpec(msg)) =
        crate::create_pod_internal(&st, hostile, None, None, root).await
    else {
        panic!("a spec choosing its own mediation must be refused at create");
    };
    assert!(msg.contains("nucleus.io/proxy-mode"), "{msg}");
    assert!(st.pods.lock().await.is_empty(), "nothing was registered");
}
