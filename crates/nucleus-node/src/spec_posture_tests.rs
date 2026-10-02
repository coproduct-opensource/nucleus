//! #3120: each posture field a spec could use to weaken its pod is refused at create.
//!
//! Every test names the spec a hostile author would have written on main and asserts the refusal
//! names the field. Each was driven red by making the check it pins admit (see the PR body).

use super::*;

fn spec(inner: &str) -> PodSpec {
    serde_json::from_str(&format!(
        r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{inner}}}"#
    ))
    .expect("test spec parses")
}

/// The operator's audit sinks every test here admits against: one sink, named `audit`.
fn sinks() -> AuditSinks {
    AuditSinks::from_toml(
        r#"
        [[sink]]
        name     = "audit"
        bucket   = "operator-audit"
        prefix   = "nucleus/node-1"
        region   = "us-east-1"
        endpoint = "https://objects.internal:9000"
        "#,
    )
    .expect("the operator's sinks load")
}

fn admitted(s: &PodSpec) -> Result<Option<AuditTarget>, PostureRefused> {
    admit(s, &sinks())
}

fn refused(s: &PodSpec) -> PostureRefused {
    admitted(s).expect_err("a hostile spec must be refused at create")
}

/// #3131, the finding: the spec chose the bucket, region and endpoint, and the node handed the
/// tool-proxy the OPERATOR's cloud credentials to write there. A tenant could write into any
/// bucket that key reaches, or name an endpoint it runs and receive the key ID and session token.
///
/// Red on main: every one of these specs parsed and was admitted. Now the spec type has no field
/// for a destination, so each is refused when the spec is read, naming the field.
#[test]
fn a_spec_cannot_choose_where_the_operators_credentials_write() {
    for (fields, field) in [
        (r#""s3_bucket":"attacker-bucket""#, "s3_bucket"),
        (
            r#""sink":"audit","s3_endpoint":"https://attacker.example""#,
            "s3_endpoint",
        ),
        (
            r#""sink":"audit","s3_bucket":"attacker-bucket""#,
            "s3_bucket",
        ),
        (r#""sink":"audit","s3_region":"us-west-2""#, "s3_region"),
        (r#""sink":"audit","bucket":"attacker-bucket""#, "bucket"),
        (
            r#""sink":"audit","endpoint":"https://attacker.example""#,
            "endpoint",
        ),
    ] {
        let json = format!(
            r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{{"audit_sink":{{{fields}}}}}}}"#
        );
        let refusal = match serde_json::from_str::<PodSpec>(&json) {
            Err(e) => e.to_string(),
            Ok(s) => match admitted(&s) {
                Err(e) => e.to_string(),
                Ok(target) => panic!("{fields}: a spec chose its own destination: {target:?}"),
            },
        };
        assert!(
            refusal.contains(field),
            "{fields}: the refusal names `{field}`: {refusal}"
        );
    }
}

/// A spec naming a sink the operator did not configure is refused at create, by name. With no
/// `--audit-sinks` at all, every name is unconfigured.
#[test]
fn an_unconfigured_audit_sink_is_refused_by_name() {
    let s = spec(r#"{"audit_sink":{"sink":"elsewhere"}}"#);
    let e = refused(&s);
    assert!(
        matches!(&e, PostureRefused::AuditSinkUnknown { name, .. } if name == "elsewhere"),
        "{e}"
    );
    let msg = ApiError::from(e).to_string();
    assert!(msg.contains("audit_sink.sink `elsewhere`"), "{msg}");
    assert!(msg.contains("configures: audit"), "{msg}");

    let configured = spec(r#"{"audit_sink":{"sink":"audit"}}"#);
    let e = admit(&configured, &AuditSinks::none()).expect_err("no sinks: nothing is configured");
    assert!(e.to_string().contains("configures none"), "{e}");
}

/// The control: a configured sink is admitted, and resolves to the operator's destination.
#[test]
fn a_configured_audit_sink_is_admitted() {
    let target = admitted(&spec(r#"{"audit_sink":{"sink":"audit"}}"#))
        .expect("a configured sink is admitted")
        .expect("and resolved");
    assert_eq!(
        crate::audit_sink::audit_sink_boot_args(&target),
        [
            "nucleus.audit_s3_bucket=operator-audit",
            "nucleus.audit_s3_prefix=nucleus/node-1",
            "nucleus.audit_s3_region=us-east-1",
            "nucleus.audit_s3_endpoint=https://objects.internal:9000",
        ]
    );
    assert_eq!(
        admitted(&spec("{}")).expect("no sink"),
        None,
        "a spec without a sink resolves to none"
    );
}

/// A narrowing that would add a kernel token, or climb out of the operator's prefix, is refused.
#[test]
fn an_audit_prefix_cannot_escape_or_add_a_token() {
    for prefix in [
        "p ipv6.disable=0",
        "a\tb",
        "x\" init=/bin/sh",
        "",
        "..",
        "../other-tenant",
        "a/../../b",
        "./a",
        "/absolute",
        "a//b",
    ] {
        let s = spec(&format!(
            r#"{{"audit_sink":{{"sink":"audit","prefix":{}}}}}"#,
            serde_json::to_string(prefix).expect("json")
        ));
        assert!(
            matches!(
                refused(&s),
                PostureRefused::AuditSink {
                    field: "prefix",
                    ..
                }
            ),
            "`{prefix}` must be refused"
        );
    }
}

/// Built on the operator's prefix, never in place of it.
#[test]
fn an_audit_prefix_narrows_the_operators() {
    for (prefix, want) in [
        ("team-a/run-7", "nucleus/node-1/team-a/run-7"),
        ("team-a/", "nucleus/node-1/team-a"),
    ] {
        let s = spec(&format!(
            r#"{{"audit_sink":{{"sink":"audit","prefix":"{prefix}"}}}}"#
        ));
        let target = admitted(&s).expect("admitted").expect("resolved");
        let args = crate::audit_sink::audit_sink_boot_args(&target);
        assert!(
            args.contains(&format!("nucleus.audit_s3_prefix={want}")),
            "{args:?}"
        );
        assert!(
            args.contains(&"nucleus.audit_s3_bucket=operator-audit".to_string()),
            "{args:?}"
        );
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
    admitted(&ok).expect("the node's own CID is admitted");
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
    admitted(&ok).expect("an ordinary credential and the task runner are admitted");
}

/// A value past `TimeDelta`'s range panicked the create handler (`Duration::seconds`); one inside
/// it minted certificates and task tokens for centuries.
#[test]
fn a_timeout_past_the_ceiling_is_refused() {
    for seconds in [MAX_TIMEOUT_SECONDS + 1, i64::MAX as u64, u64::MAX] {
        let s = spec(&format!(r#"{{"timeout_seconds":{seconds}}}"#));
        assert_eq!(refused(&s), PostureRefused::Timeout { seconds });
    }
    admitted(&spec(&format!(
        r#"{{"timeout_seconds":{MAX_TIMEOUT_SECONDS}}}"#
    )))
    .expect("the ceiling itself is admitted");
    admitted(&spec("{}")).expect("the default timeout is admitted");
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

    admitted(&spec(
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

/// A spec with none of these fields is admitted unchanged: the default is not a refusal.
#[test]
fn a_minimal_spec_is_admitted() {
    admitted(&spec("{}")).expect("minimal spec");
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
    // The fixture node configures no audit sink (`--audit-sinks` unset), so any name is foreign.
    let hostile = spec(r#"{"audit_sink":{"sink":"attacker"}}"#);
    let Err(ApiError::InvalidSpec(msg)) =
        crate::create_pod_internal(&st, hostile, None, None, root).await
    else {
        panic!("a spec naming an audit sink the operator did not configure must be refused");
    };
    assert!(msg.contains("audit_sink.sink `attacker`"), "{msg}");
    assert!(st.pods.lock().await.is_empty(), "nothing was registered");
}
