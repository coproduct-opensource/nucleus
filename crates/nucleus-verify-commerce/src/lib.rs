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
//! # Status: scaffold (honest)
//!
//! The orchestration ([`serve_verified`]) and in-memory implementations
//! ([`AllowlistVerifier`], [`HashingReceiptIssuer`]) are implemented and tested,
//! so the seam and control flow are real. The production implementations that
//! wire the existing nucleus crates are **documented skeletons** that return
//! [`CommerceError::NotWired`] rather than faking a result:
//!
//! - [`AgentCardVerifier`] — will verify a signed Agent Card / OIDC token via
//!   `nucleus-agent-card` + `nucleus-fly-oidc` / `nucleus-github-oidc` and derive
//!   the trust anchor.
//! - [`EnvelopeReceiptIssuer`] — will emit a `nucleus-envelope` provenance
//!   `Bundle` and append it to `nucleus-verifier-service`'s transparency log.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

/// A caller whose identity material passed verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedCaller {
    /// The SPIFFE id the caller verified to.
    pub spiffe_id: String,
}

/// A portable, independently-checkable record that a verified caller paid for,
/// and was delivered, a specific result.
///
/// This scaffold's receipt is a minimal binding; the production
/// [`EnvelopeReceiptIssuer`] will emit a full `nucleus-envelope` bundle with a
/// signed lineage envelope. Timestamps are intentionally absent — the issuer (or
/// the transparency log) stamps time; the binding here is deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Resource that was delivered.
    pub resource: String,
    /// SPIFFE id of the verified caller.
    pub caller_spiffe_id: String,
    /// Payment settlement reference this delivery is bound to.
    pub payment_reference: String,
    /// SHA-256 (hex) of the delivered response bytes.
    pub body_sha256: String,
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
    /// A production implementation whose backing crate is not wired yet.
    #[error("not wired: {0}")]
    NotWired(&'static str),
    /// A backend/transport error.
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
        })
    }
}

// ── Production skeletons (honest: NotWired) ───────────────────────────────────

const AGENT_CARD_TODO: &str =
    "AgentCardVerifier: wire nucleus-agent-card::verify_card + OIDC key resolution \
     (see docs/rfcs/verified-agent-commerce-quickstart.md)";

const ENVELOPE_TODO: &str = "EnvelopeReceiptIssuer: emit a nucleus-envelope Bundle + append to \
     nucleus-verifier-service transparency log";

/// Production [`CallerVerifier`] skeleton: will verify a signed Agent Card or
/// OIDC token and derive the trust anchor via `nucleus-agent-card` +
/// `nucleus-fly-oidc` / `nucleus-github-oidc`. Not wired yet — returns
/// [`CommerceError::NotWired`] rather than faking verification.
pub struct AgentCardVerifier {
    _private: (),
}

impl AgentCardVerifier {
    /// Construct the (not-yet-wired) production verifier.
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for AgentCardVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CallerVerifier for AgentCardVerifier {
    async fn verify(&self, _claims: &CallerClaims) -> Result<VerifiedCaller, CommerceError> {
        Err(CommerceError::NotWired(AGENT_CARD_TODO))
    }
}

/// Production [`ReceiptIssuer`] skeleton: will emit a `nucleus-envelope` bundle
/// and append it to the transparency log. Not wired yet — returns
/// [`CommerceError::NotWired`] rather than faking a receipt.
pub struct EnvelopeReceiptIssuer {
    _private: (),
}

impl EnvelopeReceiptIssuer {
    /// Construct the (not-yet-wired) production issuer.
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for EnvelopeReceiptIssuer {
    fn default() -> Self {
        Self::new()
    }
}

impl ReceiptIssuer for EnvelopeReceiptIssuer {
    fn issue(&self, _ctx: &ReceiptContext<'_>) -> Result<Receipt, CommerceError> {
        Err(CommerceError::NotWired(ENVELOPE_TODO))
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
    async fn production_skeletons_are_honestly_unwired() {
        let v = AgentCardVerifier::new();
        assert!(matches!(
            v.verify(&request("x").caller).await,
            Err(CommerceError::NotWired(_))
        ));

        let i = EnvelopeReceiptIssuer::new();
        let req = request("x");
        let caller = VerifiedCaller {
            spiffe_id: "spiffe://nucleus.io/x".into(),
        };
        let ctx = ReceiptContext {
            caller: &caller,
            request: &req,
            body: b"hi",
        };
        assert!(matches!(i.issue(&ctx), Err(CommerceError::NotWired(_))));
    }
}
