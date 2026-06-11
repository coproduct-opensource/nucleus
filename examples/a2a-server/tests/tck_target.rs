//! Pins the scope of the transport-conformance app (`tck-target`): the SDK
//! bindings answer WITHOUT the gate header, and — because the gate is what
//! issues receipts — no receipt header appears. The gated path keeps its own
//! coverage in `e2e.rs`; nothing here weakens it.

use nucleus_a2a_server_example::{
    build_transport_conformance_app, serve_normalized, ServerIdentity, RECEIPT_HEADER,
};

async fn spawn() -> String {
    let identity = ServerIdentity::generate_demo("http://test.invalid").unwrap();
    let app = build_transport_conformance_app(identity);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { serve_normalized(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn serves_bindings_without_gate_and_without_receipts() {
    let base = spawn().await;
    let http = reqwest::Client::new();

    // Discovery is identical to the gated server: the signed card.
    let card: serde_json::Value = http
        .get(format!("{base}/.well-known/agent-card.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        card["signatures"].as_array().is_some_and(|s| !s.is_empty()),
        "card stays signed even on the conformance target"
    );

    // JSON-RPC binding answers with NO X-Agent-Card header — at the
    // trailing-slash spelling that base-URL-joining clients (httpx: the
    // A2A TCK, the official Python client) actually request...
    let resp = http
        .post(format!("{base}/jsonrpc/"))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "SendMessage",
            "params": {
                "message": {
                    "role": "ROLE_USER",
                    "messageId": "tck-m1",
                    "parts": [{ "text": "Agents need receipts. Trust needs proofs." }]
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "no gate on the conformance target");

    // ...and therefore carries NO receipt: receipts are issued by the gate,
    // and this target must not look like it provides them.
    assert!(
        resp.headers().get(RECEIPT_HEADER).is_none(),
        "ungated target must not emit receipt headers"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED",
        "{body}"
    );
}

/// §3.6.2: an unsupported `A2A-Version` MUST be rejected with
/// `VersionNotSupportedError`, mapped per §5.4 — JSON-RPC `-32009`,
/// HTTP+JSON `400`/`FAILED_PRECONDITION`. A supported version is served.
#[tokio::test]
async fn unsupported_a2a_version_is_rejected_per_binding() {
    let base = spawn().await;
    let http = reqwest::Client::new();
    let send = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "SendMessage",
        "params": {
            "message": {
                "role": "ROLE_USER",
                "messageId": "ver-m1",
                "parts": [{ "text": "version check" }]
            }
        }
    });

    // JSON-RPC: error envelope, code -32009, id echoed.
    let resp = http
        .post(format!("{base}/jsonrpc"))
        .header("A2A-Version", "99.0")
        .json(&send)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], -32009, "{body}");
    assert_eq!(body["id"], 7, "request id echoed: {body}");

    // HTTP+JSON: 400 with an AIP-193 error object.
    let resp = http
        .post(format!("{base}/rest/message:send"))
        .header("A2A-Version", "99.0")
        .json(&serde_json::json!({
            "message": {
                "role": "ROLE_USER",
                "messageId": "ver-m2",
                "parts": [{ "text": "version check" }]
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["status"], "FAILED_PRECONDITION", "{body}");

    // The supported version is served normally (header present and valid).
    let resp = http
        .post(format!("{base}/jsonrpc"))
        .header("A2A-Version", "1.0")
        .json(&send)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.get("error").is_none(), "{body}");
}
