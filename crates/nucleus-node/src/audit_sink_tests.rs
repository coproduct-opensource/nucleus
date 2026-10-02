//! #3131: the operator's audit sink file. What it refuses at load, and what a resolved target
//! hands the tool-proxy.

use super::*;

fn spec(sink: &str) -> PodSpec {
    serde_json::from_str(&format!(
        r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{{"audit_sink":{sink}}}}}"#
    ))
    .expect("test spec parses")
}

/// Every value in the operator's file rides the guest command line, so the file is held to the
/// same one-token grammar a spec is. A bad file stops the node rather than loading the rest.
#[test]
fn an_operator_sink_outside_its_grammar_does_not_load() {
    for (body, needle) in [
        (
            r#"name = "a"
bucket = "b init=/bin/sh""#,
            "bucket",
        ),
        (
            r#"name = "a"
bucket = "UPPER""#,
            "bucket",
        ),
        (
            r#"name = "a"
bucket = "bkt"
endpoint = "file:///etc/passwd""#,
            "endpoint",
        ),
        (
            r#"name = "a"
bucket = "bkt"
region = "us-east-1 init=/bin/sh""#,
            "region",
        ),
        (
            r#"name = "a"
bucket = "bkt"
prefix = "p/../q""#,
            "prefix",
        ),
        (
            r#"name = "A B"
bucket = "bkt""#,
            "sink name",
        ),
        (
            r#"name = "a"
bucket = "bkt"
credential_env = "NODE_SECRET""#,
            "credential_env",
        ),
    ] {
        let err = AuditSinks::from_toml(&format!("[[sink]]\n{body}\n"))
            .expect_err("a bad sink must not load");
        assert!(err.contains(needle), "{body}: {err}");
    }
}

#[test]
fn a_sink_name_is_defined_once() {
    let err = AuditSinks::from_toml(
        "[[sink]]\nname = \"a\"\nbucket = \"one\"\n[[sink]]\nname = \"a\"\nbucket = \"two\"\n",
    )
    .expect_err("a duplicate name is ambiguous");
    assert!(err.contains("defined twice"), "{err}");
}

/// No file, no sink: the flag unset is an empty set, and an empty file is too.
#[test]
fn no_file_configures_no_sink() {
    let unset = AuditSinkArgs { audit_sinks: None }
        .load()
        .expect("unset loads");
    assert!(matches!(
        unset.resolve_for(&spec(r#"{"sink":"audit"}"#)),
        Err(PostureRefused::AuditSinkUnknown { .. })
    ));
    let empty = AuditSinks::from_toml("").expect("an empty file loads");
    assert!(empty.resolve_for(&spec(r#"{"sink":"audit"}"#)).is_err());
}

/// What the local and container drivers set: the operator's values, with the spec's narrowing.
/// An operator sink without a prefix leaves the spec's prefix as the whole of it (still in the
/// operator's bucket, at the operator's endpoint).
#[test]
fn a_resolved_target_sets_the_operators_destination() {
    let sinks = AuditSinks::from_toml(
        "[[sink]]\nname = \"audit\"\nbucket = \"operator-audit\"\nendpoint = \"https://objects.internal\"\n",
    )
    .expect("loads");
    let target = sinks
        .resolve_for(&spec(r#"{"sink":"audit","prefix":"team-a"}"#))
        .expect("admitted")
        .expect("resolved");
    assert_eq!(
        target.proxy_env(),
        [
            ("NUCLEUS_TOOL_PROXY_AUDIT_S3_BUCKET", "operator-audit"),
            ("NUCLEUS_TOOL_PROXY_AUDIT_S3_PREFIX", "team-a"),
            (
                "NUCLEUS_TOOL_PROXY_AUDIT_S3_ENDPOINT",
                "https://objects.internal"
            ),
        ]
    );
    let bare = sinks
        .resolve_for(&spec(r#"{"sink":"audit"}"#))
        .expect("admitted")
        .expect("resolved");
    assert_eq!(
        bare.proxy_env(),
        [
            ("NUCLEUS_TOOL_PROXY_AUDIT_S3_BUCKET", "operator-audit"),
            (
                "NUCLEUS_TOOL_PROXY_AUDIT_S3_ENDPOINT",
                "https://objects.internal"
            ),
        ]
    );
}

/// The operator's prefix plus the narrowing may not exceed the per-value ceiling.
#[test]
fn a_narrowing_cannot_overflow_the_prefix() {
    let long = "a".repeat(300);
    let sinks = AuditSinks::from_toml(&format!(
        "[[sink]]\nname = \"audit\"\nbucket = \"bkt\"\nprefix = \"{long}\"\n"
    ))
    .expect("loads");
    let refused = sinks
        .resolve_for(&spec(&format!(r#"{{"sink":"audit","prefix":"{long}"}}"#)))
        .expect_err("611 characters is past the ceiling");
    assert!(
        matches!(
            refused,
            PostureRefused::AuditSink {
                field: "prefix",
                ..
            }
        ),
        "{refused}"
    );
}
