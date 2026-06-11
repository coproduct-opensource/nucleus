//! `nucleus-verify-commerce` — seller-side **verify → serve → receipt**
//! middleware for verified agent commerce on x402 / A2A.
//!
//! The payment rail (x402 / A2A / AP2) is already commoditized. The open gap is
//! *trust*: a seller cannot rely on its own telemetry to verify a buyer-agent it
//! did not build, and after serving has no portable proof of *what was delivered
//! for what payment*. This crate is the thin seller-side layer that closes that
//! gap around an existing paid endpoint:
//!
//! 1. **Verify the caller** before serving — [`CallerVerifier`] turns the
//!    request's identity material into a [`VerifiedCaller`] (a SPIFFE id), or
//!    rejects it.
//! 2. **Serve** the paid work (your handler).
//! 3. **Issue a receipt** — [`ReceiptIssuer`] emits a portable [`Receipt`]
//!    binding caller + payment + a hash of what was delivered, so the buyer can
//!    verify-then-settle and the seller has a dispute-defence artifact.
//!
//! See `docs/rfcs/verified-agent-commerce-quickstart.md`.
//!
//! # Implementations
//!
//! Two flavours of each trait, both real and tested:
//!
//! - [`AllowlistVerifier`] / [`HashingReceiptIssuer`] — in-memory, dependency-
//!   light; for tests, local dev, and minimal deployments.
//! - [`AgentCardVerifier`] — verifies a signed [A2A v1.0 Agent
//!   Card](nucleus_agent_card) against an **out-of-band-resolved** key.
//! - [`EnvelopeReceiptIssuer`] — emits a real [`nucleus_envelope`] provenance
//!   `Bundle` (signed by a seller-provided [`EdgeSigner`](nucleus_lineage::EdgeSigner))
//!   that any party can check with `nucleus_envelope::verify_bundle` or the
//!   public verifier — the verify-then-pay artifact.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod card_verifier;
mod envelope_receipt;
pub mod ifc;
pub mod x402;

pub use card_verifier::AgentCardVerifier;
pub use envelope_receipt::{verify_receipt_bundle, EnvelopeReceiptIssuer, VerifiedReceipt};
pub use ifc::{DeclaredInput, FlowDeclaration, IfcVerdict};

/// Identity material lifted from the incoming x402 / A2A request (e.g. a signed
/// Agent Card or an OIDC token). Opaque here; a [`CallerVerifier`] interprets it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerClaims {
    /// Caller-asserted agent identifier (unverified until checked).
    pub agent_id: String,
    /// The bearer material to verify (card JWS, OIDC token, …).
    pub credential: String,
}

/// A reference to the x402 / A2A settlement for this request. Verifying the
/// payment itself is the rail's job and out of scope here; the reference is
/// carried into the [`Receipt`] so the receipt binds delivery to payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentProof {
    /// Payment scheme (e.g. `"x402"`).
    pub scheme: String,
    /// Settlement reference / tx id supplied by the rail.
    pub reference: String,
}

/// An incoming request to a paid endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommerceRequest {
    /// The resource/tool being purchased (e.g. an API route).
    pub resource: String,
    /// Caller identity material to verify.
    pub caller: CallerClaims,
    /// Reference to the payment for this request.
    pub payment: PaymentProof,
}

impl CommerceRequest {
    /// Construct directly from parts.
    pub fn new(resource: impl Into<String>, caller: CallerClaims, payment: PaymentProof) -> Self {
        Self {
            resource: resource.into(),
            caller,
            payment,
        }
    }

    /// Deserialize a request from JSON bytes (the crate's own wire form). A
    /// deployment maps its transport (x402 `X-PAYMENT` header + an identity
    /// header) onto this type; see the [`x402`] module for the payment-header
    /// helper.
    pub fn from_json(bytes: &[u8]) -> Result<Self, CommerceError> {
        serde_json::from_slice(bytes)
            .map_err(|e| CommerceError::Backend(format!("malformed commerce request: {e}")))
    }
}

/// A caller whose identity material passed verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedCaller {
    /// The SPIFFE id the caller verified to.
    pub spiffe_id: String,
}

/// A portable, independently-checkable record that a verified caller paid for,
/// and was delivered, a specific result.
///
/// The flat fields are the human-readable binding. When produced by
/// [`EnvelopeReceiptIssuer`], `bundle` carries a full signed
/// [`nucleus_envelope`] provenance bundle that any party can verify
/// out-of-band (e.g. `nucleus_envelope::verify_bundle` or the public verifier);
/// [`HashingReceiptIssuer`] leaves it `None`.
///
/// Timestamps are intentionally absent — the issuer / transparency log stamps
/// time; the binding here is deterministic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    /// Resource that was delivered.
    pub resource: String,
    /// SPIFFE id of the verified caller.
    pub caller_spiffe_id: String,
    /// Payment settlement reference this delivery is bound to.
    pub payment_reference: String,
    /// SHA-256 (hex) of the delivered response bytes.
    pub body_sha256: String,
    /// Optional full signed provenance bundle (set by [`EnvelopeReceiptIssuer`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<serde_json::Value>,
}

/// Errors surfaced by the verify→serve→receipt pipeline.
#[derive(Debug, thiserror::Error)]
pub enum CommerceError {
    /// The caller's identity material did not verify.
    #[error("caller not verified: {0}")]
    Unverified(String),
    /// The handler (paid work) failed.
    #[error("handler failed: {0}")]
    Handler(String),
    /// The IFC gate denied the paid action — the handler was never invoked.
    #[error("ifc denied: {}", .verdict.reason)]
    IfcDenied {
        /// The denying verdict (carries the declared inputs for coverage audit).
        verdict: IfcVerdict,
    },
    /// A backend/transport error (signing, serialization, bundle build).
    #[error("backend error: {0}")]
    Backend(String),
}

/// Verifies a caller's identity material into a [`VerifiedCaller`].
#[async_trait]
pub trait CallerVerifier: Send + Sync {
    /// Verify the claims, or reject with [`CommerceError::Unverified`].
    async fn verify(&self, claims: &CallerClaims) -> Result<VerifiedCaller, CommerceError>;
}

/// Context handed to a [`ReceiptIssuer`] after the work has been served.
pub struct ReceiptContext<'a> {
    /// The verified caller.
    pub caller: &'a VerifiedCaller,
    /// The originating request.
    pub request: &'a CommerceRequest,
    /// The delivered response bytes.
    pub body: &'a [u8],
    /// The IFC verdict for this call, when served through [`serve_verified_ifc`].
    /// `None` for the plain [`serve_verified`] path (no IFC gate). When `Some`,
    /// [`EnvelopeReceiptIssuer`] folds it into the signed receipt binding.
    pub ifc_verdict: Option<&'a IfcVerdict>,
}

/// Issues a [`Receipt`] for a served request.
pub trait ReceiptIssuer: Send + Sync {
    /// Produce a receipt binding caller + payment + delivered bytes.
    fn issue(&self, ctx: &ReceiptContext<'_>) -> Result<Receipt, CommerceError>;
}

/// The middleware: verify the caller, run the paid `handler`, then issue a
/// receipt. The handler is only invoked **after** verification succeeds, so an
/// unverified caller never reaches the paid work.
///
/// Returns the delivered body together with its receipt.
pub async fn serve_verified<V, I, H, F>(
    request: &CommerceRequest,
    verifier: &V,
    issuer: &I,
    handler: H,
) -> Result<(Vec<u8>, Receipt), CommerceError>
where
    V: CallerVerifier,
    I: ReceiptIssuer,
    H: FnOnce(&VerifiedCaller, &CommerceRequest) -> F,
    F: std::future::Future<Output = Result<Vec<u8>, CommerceError>>,
{
    let caller = verifier.verify(&request.caller).await?;
    let body = handler(&caller, request).await?;
    let receipt = issuer.issue(&ReceiptContext {
        caller: &caller,
        request,
        body: &body,
        ifc_verdict: None,
    })?;
    Ok((body, receipt))
}

/// The IFC-gated middleware: verify the caller, run the **model-level IFC
/// decision** over `flow`, and only then serve — folding the verdict into the
/// signed receipt.
///
/// Ordering is the guarantee: the IFC gate runs strictly between caller
/// verification and the handler. If [`FlowDeclaration::decide`] denies, the
/// `handler` is **never invoked** and this returns [`CommerceError::IfcDenied`]
/// carrying the verdict (no receipt is issued — nothing was served).
///
/// On allow, the handler runs once and the [`IfcVerdict`] is passed to the
/// issuer; [`EnvelopeReceiptIssuer`] binds it into the signed content hash so
/// the in-bounds decision is independently re-derivable via
/// [`verify_receipt_bundle`].
///
/// See [`ifc`] for the honesty boundary: this enforces the model-level decision
/// over the caller's *declared* inputs (coverage-limited), per call.
pub async fn serve_verified_ifc<V, I, H, F>(
    request: &CommerceRequest,
    flow: &FlowDeclaration,
    verifier: &V,
    issuer: &I,
    handler: H,
) -> Result<(Vec<u8>, Receipt), CommerceError>
where
    V: CallerVerifier,
    I: ReceiptIssuer,
    H: FnOnce(&VerifiedCaller, &CommerceRequest) -> F,
    F: std::future::Future<Output = Result<Vec<u8>, CommerceError>>,
{
    let caller = verifier.verify(&request.caller).await?;

    // IFC gate — strictly before the handler. Deny ⇒ handler never runs.
    let verdict = flow.decide();
    if !verdict.is_allow() {
        return Err(CommerceError::IfcDenied { verdict });
    }

    let body = handler(&caller, request).await?;
    let receipt = issuer.issue(&ReceiptContext {
        caller: &caller,
        request,
        body: &body,
        ifc_verdict: Some(&verdict),
    })?;
    Ok((body, receipt))
}

/// SHA-256 of `bytes` as a lowercase hex string.
pub fn body_sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ── In-memory implementations (real, tested) ─────────────────────────────────

/// A [`CallerVerifier`] that accepts an explicit allowlist of
/// `agent_id → spiffe_id`. For tests and local development — it does **not**
/// check the credential cryptographically (that is [`AgentCardVerifier`]'s job).
#[derive(Default)]
pub struct AllowlistVerifier {
    allow: std::collections::BTreeMap<String, String>,
}

impl AllowlistVerifier {
    /// Empty allowlist.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow `agent_id`, verifying it to `spiffe_id`.
    pub fn allow(mut self, agent_id: impl Into<String>, spiffe_id: impl Into<String>) -> Self {
        self.allow.insert(agent_id.into(), spiffe_id.into());
        self
    }
}

#[async_trait]
impl CallerVerifier for AllowlistVerifier {
    async fn verify(&self, claims: &CallerClaims) -> Result<VerifiedCaller, CommerceError> {
        match self.allow.get(&claims.agent_id) {
            Some(spiffe_id) => Ok(VerifiedCaller {
                spiffe_id: spiffe_id.clone(),
            }),
            None => Err(CommerceError::Unverified(format!(
                "agent_id `{}` not in allowlist",
                claims.agent_id
            ))),
        }
    }
}

/// A [`ReceiptIssuer`] that binds caller + payment + a SHA-256 of the delivered
/// bytes. Real and deterministic, but minimal — the production issuer emits a
/// full signed provenance bundle (see [`EnvelopeReceiptIssuer`]).
pub struct HashingReceiptIssuer;

impl ReceiptIssuer for HashingReceiptIssuer {
    fn issue(&self, ctx: &ReceiptContext<'_>) -> Result<Receipt, CommerceError> {
        Ok(Receipt {
            resource: ctx.request.resource.clone(),
            caller_spiffe_id: ctx.caller.spiffe_id.clone(),
            payment_reference: ctx.request.payment.reference.clone(),
            body_sha256: body_sha256_hex(ctx.body),
            bundle: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(agent_id: &str) -> CommerceRequest {
        CommerceRequest {
            resource: "/v1/summarize".into(),
            caller: CallerClaims {
                agent_id: agent_id.into(),
                credential: "opaque-token".into(),
            },
            payment: PaymentProof {
                scheme: "x402".into(),
                reference: "0xpay123".into(),
            },
        }
    }

    #[test]
    fn sha256_known_vector() {
        // SHA-256("") = e3b0c442...
        assert_eq!(
            body_sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn request_round_trips_through_json() {
        let req = request("buyer-agent");
        let bytes = serde_json::to_vec(&req).unwrap();
        let back = CommerceRequest::from_json(&bytes).unwrap();
        assert_eq!(back.resource, req.resource);
        assert_eq!(back.caller.agent_id, "buyer-agent");
        assert_eq!(back.payment.reference, "0xpay123");
    }

    #[tokio::test]
    async fn verified_caller_is_served_and_gets_a_bound_receipt() {
        let verifier = AllowlistVerifier::new().allow("buyer-agent", "spiffe://nucleus.io/buyer");
        let issuer = HashingReceiptIssuer;
        let req = request("buyer-agent");

        let (body, receipt) = serve_verified(&req, &verifier, &issuer, |caller, r| {
            let resource = r.resource.clone();
            let who = caller.spiffe_id.clone();
            async move { Ok(format!("served {resource} for {who}").into_bytes()) }
        })
        .await
        .unwrap();

        assert_eq!(receipt.caller_spiffe_id, "spiffe://nucleus.io/buyer");
        assert_eq!(receipt.resource, "/v1/summarize");
        assert_eq!(receipt.payment_reference, "0xpay123");
        assert_eq!(receipt.body_sha256, body_sha256_hex(&body));
        assert!(receipt.bundle.is_none());
    }

    #[tokio::test]
    async fn unverified_caller_never_reaches_the_handler() {
        let verifier = AllowlistVerifier::new(); // empty
        let issuer = HashingReceiptIssuer;
        let req = request("stranger");

        let handler_ran = std::cell::Cell::new(false);
        let result = serve_verified(&req, &verifier, &issuer, |_, _| {
            handler_ran.set(true);
            async { Ok(Vec::new()) }
        })
        .await;

        assert!(matches!(result, Err(CommerceError::Unverified(_))));
        assert!(
            !handler_ran.get(),
            "handler must not run for an unverified caller"
        );
    }

    #[tokio::test]
    async fn handler_error_propagates() {
        let verifier = AllowlistVerifier::new().allow("buyer-agent", "spiffe://nucleus.io/buyer");
        let issuer = HashingReceiptIssuer;
        let req = request("buyer-agent");

        let result = serve_verified(&req, &verifier, &issuer, |_, _| async {
            Err(CommerceError::Handler("downstream 500".into()))
        })
        .await;

        assert!(matches!(result, Err(CommerceError::Handler(_))));
    }

    #[tokio::test]
    async fn ifc_denied_request_never_reaches_the_handler() {
        let verifier = AllowlistVerifier::new().allow("buyer-agent", "spiffe://nucleus.io/buyer");
        let issuer = HashingReceiptIssuer;
        let req = request("buyer-agent");
        // Untrusted web content reaching the paid (outbound) action → IFC deny.
        let flow = FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::WebContent]);

        let handler_ran = std::cell::Cell::new(false);
        let result = serve_verified_ifc(&req, &flow, &verifier, &issuer, |_, _| {
            handler_ran.set(true);
            async { Ok(Vec::new()) }
        })
        .await;

        match result {
            Err(CommerceError::IfcDenied { verdict }) => assert!(!verdict.is_allow()),
            other => panic!("expected IfcDenied, got {other:?}"),
        }
        assert!(
            !handler_ran.get(),
            "handler must NOT run when the IFC gate denies"
        );
    }

    #[tokio::test]
    async fn ifc_allowed_request_serves_and_binds_the_verdict() {
        let verifier = AllowlistVerifier::new().allow("buyer-agent", "spiffe://nucleus.io/buyer");
        let issuer = HashingReceiptIssuer; // verdict binding is exercised in envelope_receipt tests
        let req = request("buyer-agent");
        let flow = FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow]);

        let (body, receipt) = serve_verified_ifc(&req, &flow, &verifier, &issuer, |_, r| {
            let res = r.resource.clone();
            async move { Ok(format!("served {res}").into_bytes()) }
        })
        .await
        .expect("clean flow must be served");

        assert_eq!(receipt.body_sha256, body_sha256_hex(&body));
        assert_eq!(receipt.caller_spiffe_id, "spiffe://nucleus.io/buyer");
    }
}
