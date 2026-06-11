//! An A2A v1.0 server on the **official Rust SDK** (`a2a-lf`), guarded by
//! nucleus *verify-before-you-act* and emitting a **signed provenance
//! receipt for every response**.
//!
//! Wire path:
//!
//! ```text
//! caller ──(A2A JSON-RPC / REST  +  X-Agent-Card header)──▶ axum
//!   1. gate: verify the caller's SIGNED A2A v1.0 Agent Card against a key
//!      resolved OUT-OF-BAND (never the card's own material) — §8.4.3
//!      trusted-key-store mode, nucleus trust model
//!   2. official SDK routers serve the task (DefaultRequestHandler)
//!   3. gate: sign a nucleus-envelope receipt binding
//!      caller ⨯ resource ⨯ sha256(response bytes), attach it as the
//!      `X-Nucleus-Receipt` response header (base64url of the bundle JSON)
//! ```
//!
//! The receipt verifies OFFLINE against the server's published JWKS
//! (`verify_receipt_bundle`, or `verify_receipt_js` in a browser). Streaming
//! (SSE) responses are verified but not receipted — a live stream has no
//! final byte string to bind; the header says `skipped-streaming`.
//!
//! Everything secret here is demo-grade on purpose: the receipt signer is
//! the TEST-ONLY `insecure-local-issuer` and keys are generated per run. A
//! production deployment injects a real `EdgeSigner` and publishes JWKS
//! out-of-band.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use nucleus_agent_card::{
    sign_card, AgentCapabilities, AgentCard, AgentInterface, AgentSkill, EnforcementRule,
    JsonWebKey, NucleusClaims, RuntimeGuaranteeProfile, A2A_PROTOCOL_VERSION,
};
use nucleus_lineage::{CallSpiffeId, Jwks, LocalIssuer};
use nucleus_verify_commerce::{
    AgentCardVerifier, CallerClaims, CallerVerifier as _, CommerceRequest, EnvelopeReceiptIssuer,
    PaymentProof, ReceiptContext, ReceiptIssuer as _,
};

mod executor;
pub use executor::SummarizeExecutor;

/// Largest response body the gate will buffer to receipt (16 MiB).
const RECEIPT_BODY_LIMIT: usize = 16 * 1024 * 1024;

/// The caller-facing receipt header.
pub const RECEIPT_HEADER: &str = "x-nucleus-receipt";

/// This server's identity: a signed A2A v1.0 Agent Card (nucleus claims in
/// the registered extension) plus the receipt-signing materials.
pub struct ServerIdentity {
    /// The signed card served at `/.well-known/agent-card.json`.
    pub signed_card: serde_json::Value,
    /// Public key the card's signature verifies against — what a caller
    /// resolves out-of-band.
    pub card_verify_jwk: JsonWebKey,
    /// Published JWKS the receipts verify against.
    pub receipt_jwks: Jwks,
    /// Receipt signer (TEST-ONLY local issuer; production: real EdgeSigner).
    pub receipt_signer: LocalIssuer,
    /// Session-root SPIFFE id stamped into receipt lineage.
    pub session_root: CallSpiffeId,
}

impl ServerIdentity {
    /// Generate a fresh demo identity advertising `base_url` interfaces.
    pub fn generate_demo(base_url: &str) -> anyhow::Result<Self> {
        // Card-signing key (P-256; verification side is pure-Rust p256).
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| anyhow::anyhow!("generate card key: {e}"))?;
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .map_err(|e| anyhow::anyhow!("load card key: {e}"))?;
        let pk = kp.public_key().as_ref();
        let card_verify_jwk = JsonWebKey::ec_p256(
            URL_SAFE_NO_PAD.encode(&pk[1..33]),
            URL_SAFE_NO_PAD.encode(&pk[33..65]),
        );

        // Receipt signer + its published JWKS — also the card's trustJwks
        // claim: "bundles from me verify against THESE keys".
        let receipt_signer =
            LocalIssuer::random().map_err(|e| anyhow::anyhow!("generate receipt signer: {e}"))?;
        let receipt_jwks: Jwks = serde_json::from_value(receipt_signer.publish_jwks())?;
        let session_root = CallSpiffeId::pod("summarizer.example.com", "agents", "summarizer")
            .map_err(|e| anyhow::anyhow!("session root: {e}"))?;

        let card = AgentCard {
            name: "Summarizer Agent (nucleus-guarded)".to_string(),
            description: "Summarizes text over A2A; every response carries an offline-verifiable signed receipt.".to_string(),
            supported_interfaces: vec![
                AgentInterface {
                    url: format!("{base_url}/jsonrpc"),
                    protocol_binding: "JSONRPC".to_string(),
                    tenant: None,
                    protocol_version: A2A_PROTOCOL_VERSION.to_string(),
                },
                AgentInterface {
                    url: format!("{base_url}/rest"),
                    protocol_binding: "HTTP+JSON".to_string(),
                    tenant: None,
                    protocol_version: A2A_PROTOCOL_VERSION.to_string(),
                },
            ],
            provider: None,
            version: env!("CARGO_PKG_VERSION").to_string(),
            documentation_url: None,
            capabilities: AgentCapabilities {
                streaming: Some(true),
                push_notifications: Some(false),
                extensions: vec![],
                extended_agent_card: None,
            },
            security_schemes: serde_json::Map::new(),
            security_requirements: vec![],
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
            skills: vec![AgentSkill {
                id: "summarize".to_string(),
                name: "Summarize".to_string(),
                description: "Returns a deterministic summary of the input text.".to_string(),
                tags: vec!["summarize".to_string()],
                examples: vec![],
                input_modes: vec![],
                output_modes: vec![],
                security_requirements: vec![],
            }],
            signatures: vec![],
            icon_url: None,
        }
        .with_nucleus_claims(&NucleusClaims {
            spiffe_id: "spiffe://summarizer.example.com/ns/agents/sa/summarizer".to_string(),
            did: "did:web:summarizer.example.com".to_string(),
            supported_envelope_schema_versions: vec!["1".to_string()],
            jwks_uri: None,
            trust_jwks: receipt_jwks.clone(),
            runtime_guarantees: Some(RuntimeGuaranteeProfile {
                profile_version: "1.0".to_string(),
                tracked_sources: vec!["web_content".to_string()],
                enforcement_rules: vec![EnforcementRule {
                    name: "verified_caller_only".to_string(),
                    description: "Tasks are served only to callers whose signed agent card verified against an out-of-band key.".to_string(),
                }],
                attestation_reference: None,
            }),
        })?;
        let signed = sign_card(card, pkcs8.as_ref(), "summarizer-card-key-1")?;
        Ok(Self {
            signed_card: serde_json::to_value(&signed)?,
            card_verify_jwk,
            receipt_jwks,
            receipt_signer,
            session_root,
        })
    }
}

/// Per-request state for the verify→serve→receipt middleware.
pub struct Gate {
    verifier: AgentCardVerifier,
    signer: LocalIssuer,
    jwks: Jwks,
    session_root: CallSpiffeId,
}

/// Verify the caller's signed card, let the SDK serve, then sign a receipt
/// over the response bytes. Mirrors `nucleus_verify_commerce::serve_verified`
/// at the transport layer (the manual split exists so verified SSE streams
/// can pass through without being buffered into a receipt).
async fn guard(State(gate): State<Arc<Gate>>, req: Request, next: Next) -> Response {
    // 1) Verify-before-you-act: the signed A2A v1.0 card travels in a
    //    header; the verification key is the gate's, resolved out-of-band.
    let Some(card_json) = req
        .headers()
        .get("x-agent-card")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    else {
        return (
            StatusCode::UNAUTHORIZED,
            "missing X-Agent-Card: present your signed A2A v1.0 agent card\n",
        )
            .into_response();
    };
    let claims = CallerClaims {
        agent_id: "x-agent-card".to_string(),
        credential: card_json,
    };
    let caller = match gate.verifier.verify(&claims).await {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                format!("agent card verification failed: {e}\n"),
            )
                .into_response()
        }
    };
    let resource = req.uri().path().to_string();

    // 2) Serve via the official SDK routers.
    let resp = next.run(req).await;
    let (mut parts, body) = resp.into_parts();

    // SSE: verified, but a live stream has no final byte string to bind.
    let is_stream = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/event-stream"));
    if is_stream {
        parts.headers.insert(
            RECEIPT_HEADER,
            HeaderValue::from_static("skipped-streaming"),
        );
        return Response::from_parts(parts, body);
    }

    // 3) Receipt: sign caller ⨯ resource ⨯ sha256(body) into an envelope
    //    bundle anyone can verify offline against the published JWKS.
    let bytes = match axum::body::to_bytes(body, RECEIPT_BODY_LIMIT).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("buffering response for receipt: {e}\n"),
            )
                .into_response()
        }
    };
    let commerce_req = CommerceRequest::new(
        resource,
        claims,
        PaymentProof {
            scheme: "none".to_string(),
            reference: "a2a-demo".to_string(),
        },
    );
    let issuer =
        EnvelopeReceiptIssuer::new(gate.session_root.clone(), &gate.signer, gate.jwks.clone());
    let receipt = match issuer.issue(&ReceiptContext {
        caller: &caller,
        request: &commerce_req,
        body: &bytes,
        ifc_verdict: None,
    }) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("receipt issuance failed: {e}\n"),
            )
                .into_response()
        }
    };
    let Some(bundle) = receipt.bundle else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "receipt issuer returned no bundle\n",
        )
            .into_response();
    };
    let header_value = URL_SAFE_NO_PAD.encode(bundle.to_string());
    match HeaderValue::from_str(&header_value) {
        Ok(v) => {
            parts.headers.insert(RECEIPT_HEADER, v);
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("receipt header encoding failed: {e}\n"),
            )
                .into_response()
        }
    }
    Response::from_parts(parts, Body::from(bytes))
}

/// Build the full router: well-known signed card (public) + SDK transports
/// (JSON-RPC + REST) behind the verify→serve→receipt gate.
///
/// `caller_verify_jwk` is the public key callers' cards must verify against
/// — the out-of-band trust decision, made by the operator, not the wire.
pub fn build_app(identity: ServerIdentity, caller_verify_jwk: JsonWebKey) -> axum::Router {
    use a2a_server::{DefaultRequestHandler, InMemoryTaskStore};

    let handler = Arc::new(DefaultRequestHandler::new(
        SummarizeExecutor,
        InMemoryTaskStore::new(),
    ));
    let gate = Arc::new(Gate {
        verifier: AgentCardVerifier::new(caller_verify_jwk),
        signer: identity.receipt_signer,
        jwks: identity.receipt_jwks,
        session_root: identity.session_root,
    });

    let protected = axum::Router::new()
        .nest(
            "/jsonrpc",
            a2a_server::jsonrpc::jsonrpc_router(handler.clone()),
        )
        .nest("/rest", a2a_server::rest::rest_router(handler))
        .layer(axum::middleware::from_fn_with_state(gate, guard));

    let card = identity.signed_card;
    axum::Router::new()
        .route(
            "/.well-known/agent-card.json",
            axum::routing::get(move || {
                let card = card.clone();
                async move { axum::Json(card) }
            }),
        )
        .merge(protected)
}
