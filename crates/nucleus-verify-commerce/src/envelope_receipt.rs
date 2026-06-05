//! [`EnvelopeReceiptIssuer`] — emit a real, independently-verifiable
//! [`nucleus_envelope`] provenance bundle as the commerce receipt, plus
//! [`verify_receipt_bundle`] to check it.
//!
//! # What is cryptographically bound
//!
//! `nucleus_lineage::canonical_edge_bytes` signs an edge's `child`, `kind`,
//! `parents`, **`content_hash_hex`**, `ts`, and `prev_hash` — but **not** the
//! edge's free-form `attrs` nor the bundle's `payload`. So the commerce binding
//! (resource + caller + payment + body hash) is folded into the delivery edge's
//! **content hash**, which is signed. The human-readable copy in `payload` is a
//! convenience that [`verify_receipt_bundle`] re-derives and checks against the
//! signed content hash — tampering any field is therefore detected.

use nucleus_envelope::{verify_bundle, Bundle, BundleBuilder, TrustAnchor};
use nucleus_lineage::{
    canonical_edge_bytes, edge_content_hash, CallSpiffeId, EdgeKind, EdgeSigner, InMemorySink,
    Jwks, LineageEdge, LineageSink, Proof,
};

use crate::{body_sha256_hex, CommerceError, Receipt, ReceiptContext, ReceiptIssuer};

/// Deterministic canonical bytes of the commerce binding. NUL-separated; the
/// fields never contain NUL. This is what the delivery edge's signed content
/// hash commits to.
fn binding_bytes(
    resource: &str,
    caller_spiffe_id: &str,
    payment_scheme: &str,
    payment_reference: &str,
    body_sha256: &str,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(256);
    for f in [
        resource,
        caller_spiffe_id,
        payment_scheme,
        payment_reference,
        body_sha256,
    ] {
        v.extend_from_slice(f.as_bytes());
        v.push(0);
    }
    v
}

/// A [`ReceiptIssuer`] that emits a signed `nucleus-envelope` provenance bundle
/// whose **signed content hash** commits to the full commerce binding.
///
/// Signed with a seller-provided [`EdgeSigner`] (the seller's real signing
/// identity — **never** the test-only `insecure-local-issuer`); `jwks` is the
/// matching public JWKS the seller publishes out-of-band. A buyer verifies with
/// [`verify_receipt_bundle`] (which wraps `nucleus_envelope::verify_bundle` and
/// adds the binding check) — the verify-then-pay artifact.
pub struct EnvelopeReceiptIssuer<'a> {
    session_root: CallSpiffeId,
    issuer: &'a dyn EdgeSigner,
    jwks: Jwks,
}

impl<'a> EnvelopeReceiptIssuer<'a> {
    /// Construct with the seller's session-root SPIFFE id, signing identity, and
    /// the matching published JWKS.
    pub fn new(session_root: CallSpiffeId, issuer: &'a dyn EdgeSigner, jwks: Jwks) -> Self {
        Self {
            session_root,
            issuer,
            jwks,
        }
    }

    /// Sign `edge` into `sink` in hash-chain order, returning the new chain head.
    /// Mirrors the canonical chain bookkeeping without depending on the
    /// control-plane's `SessionWriter`.
    fn emit_signed(
        &self,
        sink: &dyn LineageSink,
        edge: LineageEdge,
        prev: Option<[u8; 32]>,
    ) -> Result<[u8; 32], CommerceError> {
        let bytes = canonical_edge_bytes(&edge, prev.as_ref());
        let sig = self
            .issuer
            .sign(&bytes)
            .map_err(|e| CommerceError::Backend(format!("edge signing failed: {e}")))?;
        let mut proof = Proof::new(self.issuer.kid(), self.issuer.alg(), sig);
        if let Some(h) = prev {
            proof = proof.with_prev_hash(h);
        }
        let signed = edge.with_proof(proof);
        let new_hash = edge_content_hash(&signed, prev.as_ref());
        sink.emit(signed)
            .map_err(|e| CommerceError::Backend(format!("sink emit failed: {e}")))?;
        Ok(new_hash)
    }
}

impl ReceiptIssuer for EnvelopeReceiptIssuer<'_> {
    fn issue(&self, ctx: &ReceiptContext<'_>) -> Result<Receipt, CommerceError> {
        let body_hash = body_sha256_hex(ctx.body);
        // The signed commitment: hash of the full canonical binding.
        let binding = binding_bytes(
            &ctx.request.resource,
            &ctx.caller.spiffe_id,
            &ctx.request.payment.scheme,
            &ctx.request.payment.reference,
            &body_hash,
        );
        let binding_hash = body_sha256_hex(&binding);

        let sink = InMemorySink::new();

        // 1) pod-admit anchors the chain at the seller's session root.
        let h0 = self.emit_signed(
            &sink,
            LineageEdge::pod_admit(self.session_root.clone()),
            None,
        )?;

        // 2) the delivery edge: content-addressed by the *binding* hash, so the
        //    signature commits to caller + payment + resource + body together.
        let child = self
            .session_root
            .derive_tool("verify-commerce-deliver", Some(&binding))
            .map_err(|e| CommerceError::Backend(format!("deriving delivery id failed: {e}")))?;
        let delivery =
            LineageEdge::from_parent(child, self.session_root.clone(), EdgeKind::ArtifactProduced)
                .with_content_hash(binding_hash.clone());
        self.emit_signed(&sink, delivery, Some(h0))?;

        // 3) payload = the human-readable binding (re-derived + checked by the
        //    verifier against the signed content hash).
        let payload = serde_json::json!({
            "kind": "verify-commerce-receipt",
            "resource": ctx.request.resource,
            "caller_spiffe_id": ctx.caller.spiffe_id,
            "payment_scheme": ctx.request.payment.scheme,
            "payment_reference": ctx.request.payment.reference,
            "body_sha256": body_hash,
        });

        // 4) build a signed bundle and self-verify it before handing it back.
        let bundle = BundleBuilder::new(self.session_root.clone())
            .payload(payload)
            .sink(&sink)
            .jwks(self.jwks.clone())
            .require_signed()
            .build()
            .map_err(|e| CommerceError::Backend(format!("bundle build failed: {e}")))?;
        verify_bundle(&bundle, &TrustAnchor::self_check_only())
            .map_err(|e| CommerceError::Backend(format!("bundle self-check failed: {e}")))?;

        let bundle_value = serde_json::to_value(&bundle)
            .map_err(|e| CommerceError::Backend(format!("serializing bundle failed: {e}")))?;

        Ok(Receipt {
            resource: ctx.request.resource.clone(),
            caller_spiffe_id: ctx.caller.spiffe_id.clone(),
            payment_reference: ctx.request.payment.reference.clone(),
            body_sha256: body_hash,
            bundle: Some(bundle_value),
        })
    }
}

/// The commerce binding recovered from a receipt bundle after full verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReceipt {
    /// Resource delivered.
    pub resource: String,
    /// Verified caller SPIFFE id.
    pub caller_spiffe_id: String,
    /// Payment scheme.
    pub payment_scheme: String,
    /// Payment settlement reference.
    pub payment_reference: String,
    /// SHA-256 (hex) of the delivered bytes.
    pub body_sha256: String,
}

/// Verify a receipt bundle and return its trusted commerce binding.
///
/// Two checks, both required:
/// 1. `nucleus_envelope::verify_bundle` against `anchor` — every edge's
///    signature, the hash chain, and the JWKS.
/// 2. The signed delivery edge's `content_hash_hex` equals the SHA-256 of the
///    binding re-derived from the bundle's `payload`. Because the content hash
///    is covered by the edge signature but the payload is not, this is what
///    actually binds caller + payment + resource + body to the seller's
///    signature; without it the payload would be free to tamper.
pub fn verify_receipt_bundle(
    bundle: &Bundle,
    anchor: &TrustAnchor,
) -> Result<VerifiedReceipt, CommerceError> {
    verify_bundle(bundle, anchor)
        .map_err(|e| CommerceError::Unverified(format!("bundle did not verify: {e}")))?;

    let p = &bundle.payload;
    let field = |k: &str| -> Result<String, CommerceError> {
        p.get(k)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| CommerceError::Unverified(format!("receipt payload missing `{k}`")))
    };
    let resource = field("resource")?;
    let caller_spiffe_id = field("caller_spiffe_id")?;
    let payment_scheme = field("payment_scheme")?;
    let payment_reference = field("payment_reference")?;
    let body_sha256 = field("body_sha256")?;

    let expected = body_sha256_hex(&binding_bytes(
        &resource,
        &caller_spiffe_id,
        &payment_scheme,
        &payment_reference,
        &body_sha256,
    ));

    let signed_binding = bundle
        .envelope
        .edges
        .iter()
        .find(|e| matches!(e.kind, EdgeKind::ArtifactProduced) && e.content_hash_hex.is_some())
        .and_then(|e| e.content_hash_hex.clone())
        .ok_or_else(|| {
            CommerceError::Unverified("no signed delivery edge in receipt".to_string())
        })?;

    if signed_binding != expected {
        return Err(CommerceError::Unverified(
            "payload binding does not match the signed content hash (tampered receipt)".to_string(),
        ));
    }

    Ok(VerifiedReceipt {
        resource,
        caller_spiffe_id,
        payment_scheme,
        payment_reference,
        body_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CallerClaims, CommerceRequest, PaymentProof, VerifiedCaller};
    use nucleus_lineage::LocalIssuer;

    fn seller_root() -> CallSpiffeId {
        CallSpiffeId::pod("seller.example.com", "agents", "commerce").unwrap()
    }

    fn req() -> CommerceRequest {
        CommerceRequest {
            resource: "/v1/summarize".into(),
            caller: CallerClaims {
                agent_id: "buyer".into(),
                credential: "…".into(),
            },
            payment: PaymentProof {
                scheme: "x402".into(),
                reference: "0xpay123".into(),
            },
        }
    }

    fn caller() -> VerifiedCaller {
        VerifiedCaller {
            spiffe_id: "spiffe://nucleus.io/buyer".into(),
        }
    }

    fn issue_receipt(body: &[u8], jwks: &Jwks, signer: &dyn EdgeSigner) -> Receipt {
        let issuer = EnvelopeReceiptIssuer::new(seller_root(), signer, jwks.clone());
        let request = req();
        let caller = caller();
        issuer
            .issue(&ReceiptContext {
                caller: &caller,
                request: &request,
                body,
            })
            .unwrap()
    }

    #[test]
    fn untampered_receipt_verifies_and_recovers_the_binding() {
        let signer = LocalIssuer::random().unwrap(); // TEST-ONLY signer
        let jwks: Jwks = serde_json::from_value(signer.publish_jwks()).unwrap();
        let body = b"summary: ...";
        let receipt = issue_receipt(body, &jwks, &signer);

        let bundle: Bundle = serde_json::from_value(receipt.bundle.clone().unwrap()).unwrap();
        let verified = verify_receipt_bundle(&bundle, &TrustAnchor::from_jwks(jwks)).unwrap();

        assert_eq!(verified.caller_spiffe_id, "spiffe://nucleus.io/buyer");
        assert_eq!(verified.payment_reference, "0xpay123");
        assert_eq!(verified.body_sha256, body_sha256_hex(body));
        assert_eq!(verified.resource, "/v1/summarize");
    }

    #[test]
    fn tampering_any_binding_field_is_detected() {
        let signer = LocalIssuer::random().unwrap();
        let jwks: Jwks = serde_json::from_value(signer.publish_jwks()).unwrap();
        let receipt = issue_receipt(b"original", &jwks, &signer);
        let anchor = TrustAnchor::from_jwks(jwks);

        // Each of these payload edits must be caught by verify_receipt_bundle,
        // because the signed content hash commits to the original binding.
        for field in [
            "payment_reference",
            "caller_spiffe_id",
            "resource",
            "body_sha256",
        ] {
            let mut bundle: Bundle =
                serde_json::from_value(receipt.bundle.clone().unwrap()).unwrap();
            bundle.payload[field] = serde_json::json!("ATTACKER");
            let result = verify_receipt_bundle(&bundle, &anchor);
            assert!(
                matches!(result, Err(CommerceError::Unverified(_))),
                "tampering `{field}` must be detected, got {result:?}"
            );
        }
    }

    #[test]
    fn a_receipt_signed_by_a_different_key_does_not_verify() {
        let signer = LocalIssuer::random().unwrap();
        let jwks: Jwks = serde_json::from_value(signer.publish_jwks()).unwrap();
        let receipt = issue_receipt(b"x", &jwks, &signer);

        // Verify against an UNRELATED issuer's JWKS → signature check fails.
        let other = LocalIssuer::random().unwrap();
        let other_jwks: Jwks = serde_json::from_value(other.publish_jwks()).unwrap();
        let bundle: Bundle = serde_json::from_value(receipt.bundle.clone().unwrap()).unwrap();
        assert!(matches!(
            verify_receipt_bundle(&bundle, &TrustAnchor::from_jwks(other_jwks)),
            Err(CommerceError::Unverified(_))
        ));
    }
}
