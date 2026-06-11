//! End-to-end over a real TCP socket: discover the signed card (including
//! the auth scheme it declares, §7.3), get gated, negotiate `A2A-Version`
//! (§3.6), get served, and verify receipts offline — from the response
//! header, from the §4.6.2 extension metadata, and per SSE event. Also a
//! shape-interop check: the nucleus-signed card deserializes into the
//! OFFICIAL SDK's `AgentCard` type.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use nucleus_a2a_server_example::{
    build_app, receipt_preimage, ServerIdentity, RECEIPT_EXTENSION_URI, RECEIPT_HEADER,
    SECURITY_SCHEME_NAME,
};
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

fn jsonrpc_request(method: &str, text: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": {
            "message": {
                "role": "ROLE_USER",
                "messageId": "e2e-m1",
                "parts": [{ "text": text }]
            }
        }
    })
}

fn jsonrpc_send_message(text: &str) -> serde_json::Value {
    jsonrpc_request("SendMessage", text)
}

/// Verify one receipt bundle against the published JWKS and check it
/// binds `payload`'s pre-image (JCS bytes with the receipt stripped).
fn verify_bound(
    bundle: &Bundle,
    jwks: &Jwks,
    payload: &serde_json::Value,
) -> nucleus_verify_commerce::VerifiedReceipt {
    let verified = verify_receipt_bundle(bundle, &TrustAnchor::from_jwks(jwks.clone())).unwrap();
    let preimage = receipt_preimage(payload).unwrap();
    let sha = ring::digest::digest(&ring::digest::SHA256, &preimage);
    assert_eq!(
        verified.body_sha256,
        hex(sha.as_ref()),
        "receipt must bind the payload's pre-image bytes"
    );
    verified
}

#[tokio::test]
async fn discover_gate_serve_receipt() {
    let (base, card_jwk, receipt_jwks, caller) = spawn().await;
    let http = reqwest::Client::new();

    // ── 1. Discovery: the well-known card is a SIGNED v1.0 card that
    //       verifies against the server's out-of-band key and carries the
    //       nucleus extension, the receipt extension, and the declared
    //       auth scheme.
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
    // §4.6.1: the receipt extension is declared, optional.
    let receipt_ext = server_card
        .capabilities
        .extensions
        .iter()
        .find(|e| e.uri == RECEIPT_EXTENSION_URI)
        .expect("receipt extension declared in capabilities.extensions");
    assert!(!receipt_ext.required);

    // ── 2. Gate: no card → 401 with a WWW-Authenticate hint pointing at
    //       the card's securitySchemes (§7.4); tampered card → 401.
    let resp = http
        .post(format!("{base}/jsonrpc"))
        .header("A2A-Version", "1.0")
        .json(&jsonrpc_send_message("hi"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "no X-Agent-Card must be rejected");
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .expect("401 carries an auth challenge (§7.4)")
        .to_str()
        .unwrap();
    assert!(challenge.contains("X-Agent-Card"), "{challenge}");
    assert!(challenge.contains("securitySchemes"), "{challenge}");

    let tampered = caller.header.replace("E2E Caller", "Mallory");
    let resp = http
        .post(format!("{base}/jsonrpc"))
        .header("A2A-Version", "1.0")
        .header("x-agent-card", tampered)
        .json(&jsonrpc_send_message("hi"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "tampered card must be rejected");
    assert!(resp.headers().contains_key("www-authenticate"));

    // ── 3. Serve: verified caller (speaking 1.0) gets a completed task
    //       from the official SDK's JSON-RPC binding.
    let resp = http
        .post(format!("{base}/jsonrpc"))
        .header("A2A-Version", "1.0")
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
        .expect("every non-streaming response carries a receipt header")
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

    // ── 4. Receipts, both carriages. The header decodes to an envelope
    //       bundle; the SAME bundle rides in the Task's metadata under the
    //       extension URI (§4.6.2). Both verify OFFLINE against the
    //       published JWKS and bind caller + payload pre-image.
    let header_bundle: Bundle =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(receipt_b64).unwrap()).unwrap();
    let metadata_bundle_json = result["metadata"][RECEIPT_EXTENSION_URI].clone();
    assert!(
        metadata_bundle_json.is_object(),
        "receipt must ride in the Task's metadata keyed by the extension URI: {body}"
    );
    let metadata_bundle: Bundle = serde_json::from_value(metadata_bundle_json).unwrap();
    assert_eq!(
        serde_json::to_value(&header_bundle).unwrap(),
        serde_json::to_value(&metadata_bundle).unwrap(),
        "header and metadata carry the SAME receipt"
    );

    let verified_receipt = verify_bound(&metadata_bundle, &receipt_jwks, &body);
    assert_eq!(
        verified_receipt.caller_spiffe_id,
        "spiffe://caller.test/ns/agents/sa/e2e"
    );
    assert_eq!(verified_receipt.resource, "/jsonrpc");

    // The pre-image is reconstructible WITHOUT this crate: strip the
    // receipt entry from the Task's metadata (drop `metadata` if that
    // empties it) and canonicalize per RFC 8785. Pin that the documented
    // procedure matches `receipt_preimage`.
    let mut stripped = body.clone();
    let meta = stripped["result"]["task"]["metadata"]
        .as_object_mut()
        .unwrap();
    meta.remove(RECEIPT_EXTENSION_URI);
    let meta_emptied = meta.is_empty();
    if meta_emptied {
        stripped["result"]["task"]
            .as_object_mut()
            .unwrap()
            .remove("metadata");
    }
    assert_eq!(
        serde_jcs::to_vec(&stripped).unwrap(),
        receipt_preimage(&body).unwrap(),
        "documented manual stripping must reproduce the library pre-image"
    );
}

/// §7.3 end-to-end: a client that knows NOTHING out-of-band except the
/// card-trust key discovers from the served card itself where to put its
/// credential — securityRequirements names the scheme, securitySchemes
/// describes an API-key-in-header carrying the signed AgentCard.
#[tokio::test]
async fn auth_is_discoverable_from_the_card_alone() {
    let (base, _card_jwk, _receipt_jwks, caller) = spawn().await;
    let http = reqwest::Client::new();

    let card: serde_json::Value = http
        .get(format!("{base}/.well-known/agent-card.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // §7.3 step 1: discover the required scheme from the card.
    let required_scheme = card["securityRequirements"][0]["schemes"]
        .as_object()
        .expect("securityRequirements declares a scheme")
        .keys()
        .next()
        .expect("at least one required scheme")
        .clone();
    assert_eq!(required_scheme, SECURITY_SCHEME_NAME);
    let scheme = &card["securitySchemes"][&required_scheme]["apiKeySecurityScheme"];
    assert!(
        scheme.is_object(),
        "scheme is the proto APIKeySecurityScheme oneof variant: {card}"
    );
    assert_eq!(scheme["location"], "header");
    let header_name = scheme["name"].as_str().unwrap();
    assert!(
        scheme["description"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("signed"),
        "description says the credential is the SIGNED AgentCard"
    );

    // §7.3 step 3: put the credential exactly where the card said.
    let resp = http
        .post(format!("{base}/jsonrpc"))
        .header("A2A-Version", "1.0")
        .header(header_name, &caller.header)
        .json(&jsonrpc_send_message("Discovered auth. From the card."))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED",
        "{body}"
    );
}

/// §3.6: this interface speaks 1.0 only. Missing header (⇒ 0.3 per
/// §3.6.2), explicit 0.3, and garbage are all rejected with
/// VersionNotSupportedError in each binding's representation; 1.0 (and a
/// patch-suffixed 1.0.x, which MUST not be considered) pass.
#[tokio::test]
async fn version_negotiation() {
    let (base, _card_jwk, _receipt_jwks, caller) = spawn().await;
    let http = reqwest::Client::new();

    // JSON-RPC binding: -32009 in a proper error envelope, id echoed.
    for bad in [None, Some("0.3"), Some("not-a-version"), Some("1.1")] {
        let mut req = http
            .post(format!("{base}/jsonrpc"))
            .header("x-agent-card", &caller.header)
            .json(&jsonrpc_send_message("hi"));
        if let Some(v) = bad {
            req = req.header("A2A-Version", v);
        }
        let resp = req.send().await.unwrap();
        assert_eq!(resp.status(), 200, "JSON-RPC errors ride a 200 envelope");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["jsonrpc"], "2.0", "case {bad:?}: {body}");
        assert_eq!(body["id"], 1, "id echoed from the request: {body}");
        assert_eq!(body["error"]["code"], -32009, "case {bad:?}: {body}");
        assert_eq!(
            body["error"]["data"][0]["reason"], "VERSION_NOT_SUPPORTED",
            "{body}"
        );
        assert_eq!(body["error"]["data"][0]["domain"], "a2a-protocol.org");
    }

    // REST binding: HTTP 400, google.rpc.Status shape, same ErrorInfo.
    let resp = http
        .post(format!("{base}/rest/message:send"))
        .header("x-agent-card", &caller.header)
        .header("A2A-Version", "0.3")
        .json(&serde_json::json!({
            "message": {
                "role": "ROLE_USER",
                "messageId": "e2e-rest-1",
                "parts": [{ "text": "hi" }]
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], 400, "{body}");
    assert_eq!(body["error"]["status"], "FAILED_PRECONDITION", "{body}");
    assert_eq!(
        body["error"]["details"][0]["reason"], "VERSION_NOT_SUPPORTED",
        "{body}"
    );

    // Accepted forms: 1.0; 1.0 with a numeric patch (§3.6: patch MUST not
    // be considered); the §3.6.1 query-parameter form.
    for (header, query) in [
        (Some("1.0"), ""),
        (Some("1.0.9"), ""),
        (None, "?A2A-Version=1.0"),
    ] {
        let mut req = http
            .post(format!("{base}/jsonrpc{query}"))
            .header("x-agent-card", &caller.header)
            .json(&jsonrpc_send_message("version ok"));
        if let Some(v) = header {
            req = req.header("A2A-Version", v);
        }
        let body: serde_json::Value = req.send().await.unwrap().json().await.unwrap();
        assert_eq!(
            body["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED",
            "case ({header:?}, {query:?}): {body}"
        );
    }

    // Authentication is checked before version negotiation (§7.4: every
    // request): no card + bad version → 401, not -32009.
    let resp = http
        .post(format!("{base}/jsonrpc"))
        .header("A2A-Version", "0.3")
        .json(&jsonrpc_send_message("hi"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

/// §4.6.2 streaming: every SSE event carries its own receipt in the event
/// object's metadata; each verifies offline and binds that event's
/// pre-image AND its position in the stream (`#sse-<n>`).
#[tokio::test]
async fn streaming_events_carry_verifiable_receipts() {
    let (base, _card_jwk, receipt_jwks, caller) = spawn().await;
    let http = reqwest::Client::new();

    let resp = http
        .post(format!("{base}/jsonrpc"))
        .header("A2A-Version", "1.0")
        .header("x-agent-card", &caller.header)
        .json(&jsonrpc_request(
            "SendStreamingMessage",
            "Agents need receipts. Trust needs proofs.",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/event-stream"));
    assert_eq!(
        resp.headers().get(RECEIPT_HEADER).unwrap(),
        "per-event",
        "streaming responses signal per-event receipts"
    );

    let wire = String::from_utf8(resp.bytes().await.unwrap().to_vec()).unwrap();
    let events: Vec<serde_json::Value> = wire
        .split("\n\n")
        .filter(|f| !f.trim().is_empty())
        .map(|f| {
            serde_json::from_str(
                f.strip_prefix("data: ")
                    .unwrap_or_else(|| panic!("unexpected SSE frame: {f:?}")),
            )
            .unwrap()
        })
        .collect();
    assert_eq!(
        events.len(),
        2,
        "executor emits working + completed: {wire}"
    );

    // Event 0: TaskStatusUpdateEvent (working). Event 1: Task (completed).
    let carriers = [
        &events[0]["result"]["statusUpdate"],
        &events[1]["result"]["task"],
    ];
    assert_eq!(carriers[0]["status"]["state"], "TASK_STATE_WORKING");
    assert_eq!(carriers[1]["status"]["state"], "TASK_STATE_COMPLETED");
    for (i, carrier) in carriers.iter().enumerate() {
        let bundle_json = carrier["metadata"][RECEIPT_EXTENSION_URI].clone();
        assert!(
            bundle_json.is_object(),
            "event {i} must carry a receipt in its metadata: {}",
            events[i]
        );
        let bundle: Bundle = serde_json::from_value(bundle_json).unwrap();
        let verified = verify_bound(&bundle, &receipt_jwks, &events[i]);
        assert_eq!(
            verified.caller_spiffe_id,
            "spiffe://caller.test/ns/agents/sa/e2e"
        );
        assert_eq!(
            verified.resource,
            format!("/jsonrpc#sse-{i}"),
            "receipt attests the event's position in the stream"
        );
    }

    // The REST binding streams with the same per-event carriage.
    let resp = http
        .post(format!("{base}/rest/message:stream"))
        .header("A2A-Version", "1.0")
        .header("x-agent-card", &caller.header)
        .json(&serde_json::json!({
            "message": {
                "role": "ROLE_USER",
                "messageId": "e2e-rest-stream-1",
                "parts": [{ "text": "Streams get receipts too. Honest." }]
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let wire = String::from_utf8(resp.bytes().await.unwrap().to_vec()).unwrap();
    let events: Vec<serde_json::Value> = wire
        .split("\n\n")
        .filter(|f| !f.trim().is_empty())
        .map(|f| serde_json::from_str(f.strip_prefix("data: ").unwrap()).unwrap())
        .collect();
    assert_eq!(events.len(), 2, "{wire}");
    let final_task = &events[1]["task"];
    assert_eq!(final_task["status"]["state"], "TASK_STATE_COMPLETED");
    let bundle: Bundle =
        serde_json::from_value(final_task["metadata"][RECEIPT_EXTENSION_URI].clone()).unwrap();
    let verified = verify_bound(&bundle, &receipt_jwks, &events[1]);
    assert_eq!(verified.resource, "/rest/message:stream#sse-1");
}

/// Shape interop: a nucleus-signed card round-trips through the OFFICIAL
/// SDK's `AgentCard` type — with ONE pinned deviation: a2a-lf 0.3
/// re-serializes `securityRequirements` as the flat OpenAPI map
/// (`{"scheme": ["roles"]}`) instead of the normative ProtoJSON
/// `SecurityRequirement` shape (`{"schemes": {"scheme": {"list": […]}}}`,
/// a2a.proto — normative per §1.4). The SDK *accepts* the ProtoJSON shape
/// on input; only its output shape deviates. This test pins that the
/// deviation is confined to exactly that field — everything else,
/// including the detached JWS, survives the round-trip.
#[tokio::test]
async fn signed_card_round_trips_through_official_sdk_type() {
    let identity = ServerIdentity::generate_demo("http://test.invalid").unwrap();
    let sdk_card: a2a::AgentCard = serde_json::from_value(identity.signed_card.clone())
        .expect("nucleus card parses as the official SDK AgentCard");
    let mut back = serde_json::to_value(&sdk_card).unwrap();

    // Pin the deviation: the SDK flattened the ProtoJSON shape.
    assert_eq!(
        back["securityRequirements"],
        serde_json::json!([{ "signedAgentCard": ["verified-caller"] }]),
        "SDK 0.3 emits the flat OpenAPI map for securityRequirements"
    );
    assert_ne!(
        back["securityRequirements"],
        identity.signed_card["securityRequirements"]
    );
    // …and that it is confined: restoring that one field makes the
    // round-tripped card verify against the original signature again.
    back["securityRequirements"] = identity.signed_card["securityRequirements"].clone();
    let reparsed: AgentCard = serde_json::from_value(back).expect("and back");
    verify_card(&reparsed, &identity.card_verify_jwk)
        .expect("signature survives the SDK round-trip (modulo the pinned field)");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
