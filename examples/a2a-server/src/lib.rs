//! An A2A v1.0 server on the **official Rust SDK** (`a2a-lf`), guarded by
//! nucleus *verify-before-you-act* and emitting a **signed provenance
//! receipt for every response — streaming included**.
//!
//! Wire path:
//!
//! ```text
//! caller ──(A2A JSON-RPC / REST  +  X-Agent-Card  +  A2A-Version: 1.0)──▶ axum
//!   1. gate: verify the caller's SIGNED A2A v1.0 Agent Card against a key
//!      resolved OUT-OF-BAND (never the card's own material) — §8.4.3
//!      trusted-key-store mode, nucleus trust model. The scheme is
//!      DECLARED in the served card's `securitySchemes` (§7.3), and 401s
//!      carry a `WWW-Authenticate` hint pointing back at it (§7.4).
//!   2. negotiate `A2A-Version` (§3.6): this interface speaks 1.0 only;
//!      anything else — including the absent-header 0.3 default — gets
//!      `VersionNotSupportedError` (-32009 / HTTP 400, §5.4).
//!   3. official SDK routers serve the task (DefaultRequestHandler)
//!   4. gate: sign a nucleus-envelope receipt binding caller ⨯ resource ⨯
//!      sha256(payload pre-image) and carry it BOTH ways:
//!        - in the response object's `metadata` under the extension URI
//!          `https://coproduct.one/a2a/ext/receipt/v1` (§4.6.2 — the
//!          spec's own extension-data carriage), per SSE event when
//!          streaming;
//!        - as the `X-Nucleus-Receipt` response header (base64url of the
//!          bundle JSON) for curl ergonomics on non-streaming responses.
//! ```
//!
//! The receipt verifies OFFLINE against the server's published JWKS
//! (`verify_receipt_bundle`, or `verify_receipt_js` in a browser). The
//! exact bytes a receipt binds are defined in [`receipt`] (a receipt
//! cannot bind bytes that contain itself); see
//! `docs/a2a-receipt-extension.md`.
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
    sign_card, AgentCapabilities, AgentCard, AgentExtension, AgentInterface, AgentSkill,
    EnforcementRule, JsonWebKey, NucleusClaims, RuntimeGuaranteeProfile, SecurityRequirement,
    StringList, A2A_PROTOCOL_VERSION,
};
use nucleus_lineage::{CallSpiffeId, Jwks, LocalIssuer};
use nucleus_verify_commerce::{
    AgentCardVerifier, CallerClaims, CallerVerifier as _, CommerceRequest, EnvelopeReceiptIssuer,
    PaymentProof, ReceiptContext, ReceiptIssuer as _, VerifiedCaller,
};

mod executor;
pub mod receipt;
pub mod version;

pub use executor::SummarizeExecutor;
pub use receipt::{receipt_preimage, RECEIPT_EXTENSION_URI};
pub use version::{A2A_VERSION_HEADER, VERSION_NOT_SUPPORTED};

/// Largest response body the gate will buffer to receipt (16 MiB).
const RECEIPT_BODY_LIMIT: usize = 16 * 1024 * 1024;

/// The caller-facing receipt header (curl ergonomics; the spec-idiomatic
/// carriage is the §4.6.2 metadata entry under [`RECEIPT_EXTENSION_URI`]).
pub const RECEIPT_HEADER: &str = "x-nucleus-receipt";

/// The request header carrying the caller's signed A2A v1.0 AgentCard —
/// declared in the served card's `securitySchemes` under
/// [`SECURITY_SCHEME_NAME`] so clients discover it per §7.3 step 1.
pub const AGENT_CARD_HEADER: &str = "x-agent-card";

/// Name of the security scheme in the card's `securitySchemes` map.
pub const SECURITY_SCHEME_NAME: &str = "signedAgentCard";

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

        // §7.3 step 1: DECLARE the authentication the gate enforces, so a
        // client that only reads the card knows where the credential goes.
        // `security_schemes` is an opaque ProtoJSON map for now (a typed
        // model is coming separately), so the proto's
        // `APIKeySecurityScheme` oneof variant is built as raw JSON here:
        // oneof key `apiKeySecurityScheme`, fields per `a2a.proto`.
        let mut security_schemes = serde_json::Map::new();
        security_schemes.insert(
            SECURITY_SCHEME_NAME.to_string(),
            serde_json::json!({
                "apiKeySecurityScheme": {
                    "description": "The value is the caller's SIGNED A2A v1.0 AgentCard JSON \
                                    (detached JWS per §8.4). It is verified against a key the \
                                    operator resolved out-of-band — never the card's own material.",
                    "location": "header",
                    "name": "X-Agent-Card",
                }
            }),
        );
        // The matching requirement (§7.3): this scheme on every request.
        // "verified-caller" is a role name (OpenAPI 3.2 allows role names
        // for non-OAuth schemes): the gate grants exactly one role —
        // being a caller whose signed card verified.
        let security_requirements = vec![SecurityRequirement {
            schemes: [(
                SECURITY_SCHEME_NAME.to_string(),
                StringList {
                    list: vec!["verified-caller".to_string()],
                },
            )]
            .into_iter()
            .collect(),
        }];

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
                // §4.6.1 declaration: receipts are an ordinary, optional
                // A2A extension — clients that ignore it interoperate
                // untouched. The nucleus runtime-guarantees extension is
                // added below by `with_nucleus_claims`.
                extensions: vec![AgentExtension {
                    uri: receipt::RECEIPT_EXTENSION_URI.to_string(),
                    description: "Signed provenance receipts: each response object's metadata \
                                  carries a nucleus-envelope bundle (per SSE event when \
                                  streaming) binding caller, resource, and payload bytes; \
                                  verifies offline against the card's trustJwks."
                        .to_string(),
                    required: false,
                    params: Some(serde_json::json!({
                        "responseHeader": "X-Nucleus-Receipt",
                    })),
                }],
                extended_agent_card: None,
            },
            security_schemes,
            security_requirements,
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

/// §7.4: authentication rejections SHOULD carry challenge information —
/// point the caller back at the card's `securitySchemes` (§7.3 step 1).
fn unauthorized(message: String) -> Response {
    let mut resp = (StatusCode::UNAUTHORIZED, message).into_response();
    resp.headers_mut().insert(
        http::header::WWW_AUTHENTICATE,
        HeaderValue::from_static(
            "SignedAgentCard header=\"X-Agent-Card\", \
             schemes=\"/.well-known/agent-card.json#/securitySchemes/signedAgentCard\"",
        ),
    );
    resp
}

/// Verify the caller's signed card, let the SDK serve, then sign a receipt
/// over the response payload — per SSE event for streams, whole body
/// otherwise — carried in the §4.6.2 extension metadata (and, for
/// non-streaming, the [`RECEIPT_HEADER`] too).
async fn guard(State(gate): State<Arc<Gate>>, req: Request, next: Next) -> Response {
    // 1) Verify-before-you-act: the signed A2A v1.0 card travels in a
    //    header; the verification key is the gate's, resolved out-of-band.
    let Some(card_json) = req
        .headers()
        .get(AGENT_CARD_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    else {
        return unauthorized(
            "missing X-Agent-Card: present your signed A2A v1.0 agent card \
             (see the card's securitySchemes.signedAgentCard)\n"
                .to_string(),
        );
    };
    let claims = CallerClaims {
        agent_id: AGENT_CARD_HEADER.to_string(),
        credential: card_json,
    };
    let caller = match gate.verifier.verify(&claims).await {
        Ok(c) => c,
        Err(e) => return unauthorized(format!("agent card verification failed: {e}\n")),
    };
    let resource = req.uri().path().to_string();

    // 2) Serve via the official SDK routers (the version middleware runs
    //    between this gate and the SDK; its -32009 envelopes get
    //    receipted like any other response).
    let resp = next.run(req).await;
    let (mut parts, body) = resp.into_parts();

    // 3a) SSE: a live stream has no final byte string, so each event is
    //     receipted individually in its own §4.6.2 metadata.
    let is_stream = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/event-stream"));
    if is_stream {
        parts
            .headers
            .insert(RECEIPT_HEADER, HeaderValue::from_static("per-event"));
        let issue = sse_issuer(gate, caller, claims, resource);
        return Response::from_parts(parts, receipt::per_event_receipts(body, issue));
    }

    // 3b) Non-streaming: receipt the whole payload. The signed pre-image
    //     is the JCS form of the body with the receipt entry excluded
    //     (`receipt::receipt_preimage`) — a receipt cannot bind bytes
    //     that contain itself — then the bundle rides both in the
    //     response object's metadata (§4.6.2) and the header.
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
    // These routes only produce JSON; a non-JSON body (defensive) gets a
    // raw-bytes header-only receipt.
    let parsed: Option<serde_json::Value> = serde_json::from_slice(&bytes).ok();
    let preimage: Vec<u8> = match &parsed {
        Some(payload) => match receipt::receipt_preimage(payload) {
            Ok(p) => p,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("receipt pre-image failed: {e}\n"),
                )
                    .into_response()
            }
        },
        None => bytes.to_vec(),
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
        body: &preimage,
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
    // §4.6.2 carriage: the same bundle in the response object's metadata.
    // Payloads with no carrier (error envelopes, lists) keep header-only.
    let final_bytes: Vec<u8> = match parsed {
        Some(mut payload) => {
            if receipt::inject_receipt(&mut payload, &bundle) {
                match serde_json::to_vec(&payload) {
                    Ok(b) => b,
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("receipt injection re-serialization failed: {e}\n"),
                        )
                            .into_response()
                    }
                }
            } else {
                bytes.to_vec()
            }
        }
        None => bytes.to_vec(),
    };
    // The body may have grown; let hyper restate the length.
    parts.headers.remove(http::header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(final_bytes))
}

/// Build the per-event receipt issuer for a verified SSE response: each
/// event's receipt binds caller ⨯ `"<path>#sse-<n>"` ⨯ that event's
/// pre-image bytes.
fn sse_issuer(
    gate: Arc<Gate>,
    caller: VerifiedCaller,
    claims: CallerClaims,
    resource: String,
) -> Arc<receipt::IssueReceipt> {
    Arc::new(move |preimage: &[u8], index: u64| {
        let request = CommerceRequest::new(
            format!("{resource}#sse-{index}"),
            claims.clone(),
            PaymentProof {
                scheme: "none".to_string(),
                reference: "a2a-demo".to_string(),
            },
        );
        let issuer =
            EnvelopeReceiptIssuer::new(gate.session_root.clone(), &gate.signer, gate.jwks.clone());
        let receipt = issuer
            .issue(&ReceiptContext {
                caller: &caller,
                request: &request,
                body: preimage,
                ifc_verdict: None,
            })
            .map_err(|e| anyhow::anyhow!("receipt issuance: {e}"))?;
        receipt
            .bundle
            .ok_or_else(|| anyhow::anyhow!("receipt issuer returned no bundle"))
    })
}

/// Build the full router: well-known signed card (public) + SDK transports
/// (JSON-RPC + REST) behind verify (§7) → version negotiation (§3.6) →
/// serve → receipt (§4.6.2).
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

    // Layer order (outermost first): authenticate (§7.4 says EVERY
    // request) → negotiate A2A-Version (§3.6) → SDK. Responses flow back
    // through the gate, which receipts them — version errors included.
    let protected = axum::Router::new()
        .nest(
            "/jsonrpc",
            a2a_server::jsonrpc::jsonrpc_router(handler.clone()),
        )
        .nest("/rest", a2a_server::rest::rest_router(handler))
        .layer(axum::middleware::from_fn(version::negotiate))
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
