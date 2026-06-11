//! End-to-end over a real TCP socket: discover the signed card, get gated,
//! get served, verify the receipt offline. Also a shape-interop check:
//! the nucleus-signed card deserializes into the OFFICIAL SDK's `AgentCard`
//! type and back without loss.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use nucleus_a2a_server_example::{build_app, ServerIdentity, RECEIPT_HEADER};
use nucleus_agent_card::{
    sign_card, verify_card, AgentCapabilities, AgentCard, AgentInterface, JsonWebKey,
    NucleusClaims, A2A_PROTOCOL_VERSION,
};
use nucleus_envelope::{Bundle, TrustAnchor};
use nucleus_lineage::{Jwks, LocalIssuer};
use nucleus_verify_commerce::verify_receipt_bundle;

struct Caller {
    header: String,
    jwk: JsonWebKey,
}

fn p256() -> (Vec<u8>, JsonWebKey) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let der = pkcs8.as_ref().to_vec();
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng).unwrap();
    let pk = kp.public_key().as_ref();
    (
        der,
        JsonWebKey::ec_p256(
            URL_SAFE_NO_PAD.encode(&pk[1..33]),
            URL_SAFE_NO_PAD.encode(&pk[33..65]),
        ),
    )
}

fn caller() -> Caller {
    let (der, jwk) = p256();
    let trust_jwks: Jwks =
        serde_json::from_value(LocalIssuer::random().unwrap().publish_jwks()).unwrap();
    let card = AgentCard {
        name: "E2E Caller".to_string(),
        description: "test caller".to_string(),
        supported_interfaces: vec![AgentInterface {
            url: "https://caller.test/a2a/v1".to_string(),
            protocol_binding: "JSONRPC".to_string(),
            tenant: None,
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        }],
        provider: None,
        version: "0.0.1".to_string(),
        documentation_url: None,
        capabilities: AgentCapabilities::default(),
        security_schemes: serde_json::Map::new(),
        security_requirements: vec![],
        default_input_modes: vec!["text/plain".to_string()],
        default_output_modes: vec!["text/plain".to_string()],
        skills: vec![],
        signatures: vec![],
        icon_url: None,
    }
    .with_nucleus_claims(&NucleusClaims {
        spiffe_id: "spiffe://caller.test/ns/agents/sa/e2e".to_string(),
        did: "did:web:caller.test".to_string(),
        supported_envelope_schema_versions: vec!["1".to_string()],
        jwks_uri: None,
        trust_jwks,
        runtime_guarantees: None,
    })
    .unwrap();
    let signed = sign_card(card, &der, "e2e-caller-key-1").unwrap();
    Caller {
        header: serde_json::to_string(&signed).unwrap(),
        jwk,
    }
}

/// Spawn the app on an ephemeral port; returns (base_url, server identity
/// public parts we asserted on).
async fn spawn() -> (String, JsonWebKey, Jwks, Caller) {
    let identity = ServerIdentity::generate_demo("http://test.invalid").unwrap();
    let card_jwk = identity.card_verify_jwk.clone();
    let receipt_jwks = identity.receipt_jwks.clone();
    let c = caller();
    let app = build_app(identity, c.jwk.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), card_jwk, receipt_jwks, c)
}

fn jsonrpc_send_message(text: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "SendMessage",
        "params": {
            "message": {
                "role": "ROLE_USER",
                "messageId": "e2e-m1",
                "parts": [{ "text": text }]
            }
        }
    })
}

#[tokio::test]
async fn discover_gate_serve_receipt() {
    let (base, card_jwk, receipt_jwks, caller) = spawn().await;
    let http = reqwest::Client::new();

    // ── 1. Discovery: the well-known card is a SIGNED v1.0 card that
    //       verifies against the server's out-of-band key and carries the
    //       nucleus extension.
    let card_json: serde_json::Value = http
        .get(format!("{base}/.well-known/agent-card.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let server_card: AgentCard = serde_json::from_value(card_json.clone()).unwrap();
    let verified = verify_card(&server_card, &card_jwk).expect("server card verifies");
    assert_eq!(
        verified.claims.spiffe_id,
        "spiffe://summarizer.example.com/ns/agents/sa/summarizer"
    );
    assert!(verified.claims.runtime_guarantees.is_some());

    // ── 2. Gate: no card → 401; tampered card → 401.
    let resp = http
        .post(format!("{base}/jsonrpc"))
        .json(&jsonrpc_send_message("hi"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "no X-Agent-Card must be rejected");

    let tampered = caller.header.replace("E2E Caller", "Mallory");
    let resp = http
        .post(format!("{base}/jsonrpc"))
        .header("x-agent-card", tampered)
        .json(&jsonrpc_send_message("hi"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "tampered card must be rejected");

    // ── 3. Serve: verified caller gets a completed task from the official
    //       SDK's JSON-RPC binding.
    let resp = http
        .post(format!("{base}/jsonrpc"))
        .header("x-agent-card", &caller.header)
        .json(&jsonrpc_send_message(
            "Agents need receipts. Trust needs proofs.",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let receipt_b64 = resp
        .headers()
        .get(RECEIPT_HEADER)
        .expect("every non-streaming response carries a receipt")
        .to_str()
        .unwrap()
        .to_owned();
    let body_bytes = resp.bytes().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let result = &body["result"]["task"];
    assert_eq!(result["status"]["state"], "TASK_STATE_COMPLETED", "{body}");
    let summary = result["status"]["message"]["parts"][0]["text"]
        .as_str()
        .unwrap();
    assert_eq!(summary, "Agents need receipts (6 words)");

    // ── 4. Receipt: decodes to an envelope bundle that verifies OFFLINE
    //       against the server's published JWKS and binds caller + body.
    let bundle: Bundle =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(receipt_b64).unwrap()).unwrap();
    let verified_receipt =
        verify_receipt_bundle(&bundle, &TrustAnchor::from_jwks(receipt_jwks)).unwrap();
    assert_eq!(
        verified_receipt.caller_spiffe_id,
        "spiffe://caller.test/ns/agents/sa/e2e"
    );
    assert_eq!(verified_receipt.resource, "/jsonrpc");
    let sha = ring::digest::digest(&ring::digest::SHA256, &body_bytes);
    assert_eq!(
        verified_receipt.body_sha256,
        hex(sha.as_ref()),
        "receipt binds exactly the bytes the caller received"
    );
}

/// Shape interop: a nucleus-signed card round-trips through the OFFICIAL
/// SDK's `AgentCard` type without loss — and the signature still verifies
/// on the other side of the round-trip.
#[tokio::test]
async fn signed_card_round_trips_through_official_sdk_type() {
    let identity = ServerIdentity::generate_demo("http://test.invalid").unwrap();
    let sdk_card: a2a::AgentCard = serde_json::from_value(identity.signed_card.clone())
        .expect("nucleus card parses as the official SDK AgentCard");
    let back = serde_json::to_value(&sdk_card).unwrap();
    let reparsed: AgentCard = serde_json::from_value(back).expect("and back");
    verify_card(&reparsed, &identity.card_verify_jwk)
        .expect("signature survives the SDK round-trip");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
