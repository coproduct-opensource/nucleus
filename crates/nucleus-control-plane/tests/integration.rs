//! End-to-end: execute a mock job through a [`JsonlSink`], then verify
//! the resulting bundle by serializing it to JSON and re-parsing — same
//! path a customer/verifier would follow.

use nucleus_control_plane::{
    execute_job, AgentDriverRef, Destination, InputRef, JobSpec, MockJobRunner,
};
use nucleus_envelope::{verify_bundle, Bundle, TrustAnchor};
use nucleus_lineage::{CallSpiffeId, JsonlSink, Jwks, LocalIssuer};
use tempfile::tempdir;

#[test]
fn mock_job_through_jsonl_sink_round_trips_and_verifies() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("lineage.jsonl");
    let sink = JsonlSink::open(&log_path).unwrap();
    let issuer = LocalIssuer::random().unwrap();
    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
    let runner = MockJobRunner;

    let spec = JobSpec {
        input_ref: InputRef::Inline {
            content: serde_json::json!({"raw": "hello"}),
        },
        task: "summarize the input".to_string(),
        destination: Destination::InResponse,
        policy_profile: "report-extraction".to_string(),
        agent_driver: AgentDriverRef {
            name: "mock".to_string(),
            version: None,
            config: serde_json::json!({}),
        },
    };
    let session_root = CallSpiffeId::pod("test.nucleus.local", "agents", "summarizer").unwrap();

    let bundle = execute_job(
        &spec,
        &session_root,
        &runner,
        &sink,
        &issuer,
        jwks.clone(),
        Vec::new(),
        None,
    )
    .expect("mock job must succeed");

    // Serialize → deserialize — the round-trip a customer would do.
    let on_wire = serde_json::to_vec(&bundle).unwrap();
    let restored: Bundle = serde_json::from_slice(&on_wire).unwrap();

    // Verify against a trusted JWKS (production path).
    let trusted = TrustAnchor::from_jwks(jwks);
    let report = verify_bundle(&restored, &trusted).expect("must verify against trusted JWKS");
    assert_eq!(report.edge_count, 5);
    assert_eq!(report.trust_domain, "test.nucleus.local");
    assert!(!report.trust_mode_self_check_only);
}

#[test]
fn local_path_input_is_read_into_the_lineage() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.txt");
    std::fs::write(&input_path, b"hello from disk").unwrap();
    let sink = nucleus_lineage::InMemorySink::new();
    let issuer = LocalIssuer::random().unwrap();
    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();

    let spec = JobSpec {
        input_ref: InputRef::LocalPath {
            path: input_path.clone(),
        },
        task: "describe".to_string(),
        destination: Destination::InResponse,
        policy_profile: "report-extraction".to_string(),
        agent_driver: AgentDriverRef {
            name: "mock".to_string(),
            version: None,
            config: serde_json::json!({}),
        },
    };
    let root = CallSpiffeId::pod("test.nucleus.local", "agents", "summarizer").unwrap();
    let bundle = execute_job(
        &spec,
        &root,
        &MockJobRunner,
        &sink,
        &issuer,
        jwks,
        Vec::new(),
        None,
    )
    .unwrap();

    // The mock runner records the input byte count in attrs.
    let read_edge = bundle
        .envelope
        .edges
        .iter()
        .find(|e| matches!(e.kind, nucleus_lineage::EdgeKind::ToolCall { .. }))
        .expect("expected a tool-call edge");
    assert_eq!(
        read_edge.attrs.get("input_bytes").map(String::as_str),
        Some("15") // "hello from disk".len()
    );
}
