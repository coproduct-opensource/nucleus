//! This pod's certificate of authority, and request-borne delegation
//! certificates — certificate convergence, tool-proxy half (#2424, #2427,
//! #2440).
//!
//! # The pod's own certificate
//!
//! The node mints every pod a `LatticeCertificate` chain (`pod_authority` on
//! the node) and delivers the PUBLIC token plus the pinned root key on the
//! boot channel (`NUCLEUS_POD_CERT` / `NUCLEUS_CERT_ROOT_PUBKEY`). This module
//! verifies it ONCE at startup, against the pinned anchor — never against the
//! key the token itself embeds, which is self-asserted — and hands back:
//!
//! - the sealed [`VerifiedPermissions`] the kernel is built from
//!   (`Kernel::from_certificate`, so every decision carries provenance), and
//! - a [`PodCertificate`] summary the rest of the proxy reads: the effective
//!   lattice IS this pod's ceiling for everything it delegates.
//!
//! Present-but-invalid is fatal at boot (`EX_CONFIG`, like a missing sandbox
//! proof). Absent is not: a pod created before its node grew an authority
//! falls back to its resolved policy as its own ceiling.
//!
//! # Request-borne certificates and auth tiers (#2427, #2431)
//!
//! A caller may present `x-nucleus-delegation-cert` to act under a delegated
//! authority. Before this module, the certificate's leaf identity was
//! cross-checked against the caller only inside `if let Some(spiffe_id)`, and
//! only the mTLS tier ever set one — so on every other tier a validly-signed
//! certificate for ANY leaf was honoured, and a verification failure quietly
//! fell through to the unsigned permission-bid header. Now:
//!
//! - [`delegation_authority`] says which tiers bind an identity. Only
//!   `SpiffeMtls` does. A certificate presented on any other tier is refused
//!   outright — there is nobody to bind it to.
//! - Every failure (malformed, unverifiable, leaf ≠ caller, no anchor
//!   configured) is an error, never a downgrade.

use axum::http::HeaderMap;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use portcullis::PermissionLattice;
use portcullis::certificate::{
    DEFAULT_MAX_CHAIN_DEPTH, LatticeCertificate, VerifiedPermissions, verify_certificate,
};
use portcullis::token::AttenuationToken;

use crate::auth::AuthMethod;
use crate::{ApiError, AppState, PermissionGrant, cert_bridge, identity_fusion};

/// Header a caller presents a delegation certificate in (base64 JSON
/// `LatticeCertificate`). Same spelling the node accepts an
/// `AttenuationToken` in; the node re-roots, the proxy narrows.
pub(crate) const HEADER_DELEGATION_CERT: &str = "x-nucleus-delegation-cert";

/// What the proxy keeps of its own certificate after the one-time verify.
#[derive(Debug, Clone)]
pub(crate) struct PodCertificate {
    /// The chain's effective permissions: this pod's true ceiling.
    pub effective: PermissionLattice,
    /// `LatticeCertificate::fingerprint`, recorded as kernel provenance.
    pub fingerprint: [u8; 32],
    /// Hops from the node's root to this pod.
    pub chain_depth: usize,
    /// The identity the chain was issued to (this pod's SPIFFE ID).
    pub leaf_identity: String,
    /// The identity at the root of the chain (the creator's).
    pub root_identity: String,
}

/// Why the pod's own certificate could not be accepted at boot.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PodCertError {
    #[error(
        "NUCLEUS_POD_CERT is set but NUCLEUS_CERT_ROOT_PUBKEY is not: no anchor to verify against"
    )]
    MissingAnchor,
    #[error("NUCLEUS_CERT_ROOT_PUBKEY is not a 32-byte hex Ed25519 public key")]
    MalformedAnchor,
    #[error("the certificate's embedded root key is not the pinned anchor")]
    AnchorMismatch,
    #[error("malformed pod certificate: {0}")]
    Malformed(String),
    #[error("pod certificate does not verify: {0}")]
    Verify(String),
}

/// Verify this pod's certificate against the pinned anchor.
///
/// `Ok(None)` when no certificate was delivered. `Err` when one was and it
/// does not hold up — the caller treats that as fatal.
pub(crate) fn resolve_pod_certificate(
    cert_b64: Option<&str>,
    root_hex: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Option<(VerifiedPermissions, PodCertificate)>, PodCertError> {
    let Some(cert_b64) = cert_b64.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let anchor = parse_anchor(root_hex)?;
    let token = AttenuationToken::from_base64(cert_b64)
        .map_err(|e| PodCertError::Malformed(e.to_string()))?;
    // The token carries a root key of its own; it is NOT the trust decision.
    if token.root_public_key() != anchor.as_slice() {
        return Err(PodCertError::AnchorMismatch);
    }
    let verified = verify_certificate(token.certificate(), &anchor, now, DEFAULT_MAX_CHAIN_DEPTH)
        .map_err(|e| PodCertError::Verify(e.to_string()))?;
    let summary = PodCertificate {
        effective: verified.effective().clone(),
        fingerprint: token.fingerprint(),
        chain_depth: verified.chain_depth(),
        leaf_identity: verified.leaf_identity().to_string(),
        root_identity: verified.root_identity().to_string(),
    };
    Ok(Some((verified, summary)))
}

fn parse_anchor(root_hex: Option<&str>) -> Result<Vec<u8>, PodCertError> {
    let hex_str = root_hex.map(str::trim).filter(|s| !s.is_empty());
    let Some(hex_str) = hex_str else {
        return Err(PodCertError::MissingAnchor);
    };
    match hex::decode(hex_str) {
        Ok(k) if k.len() == 32 => Ok(k),
        _ => Err(PodCertError::MalformedAnchor),
    }
}

/// Whether an authentication tier binds an identity a delegation
/// certificate's leaf can be checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DelegationAuthority {
    /// The tier proved WHO the caller is; a certificate for that leaf may act.
    Bound,
    /// The tier proved at most that the caller holds a secret or arrived on
    /// a trusted transport — nobody to bind a certificate to. Zero delegated
    /// authority (#2427).
    Unbound,
}

/// The delegation authority of an authentication method. Only SPIFFE mTLS
/// binds an identity; the shared-secret, approval, and host-vsock tiers do
/// not, and a certificate on any of them is refused.
pub(crate) fn delegation_authority(method: &AuthMethod) -> DelegationAuthority {
    match method {
        AuthMethod::SpiffeMtls => DelegationAuthority::Bound,
        _ => DelegationAuthority::Unbound,
    }
}

/// A verified delegation certificate and the market-intersected effective
/// permissions derived from it.
#[derive(Clone)]
#[allow(dead_code)] // Fields consumed by downstream handlers
pub(crate) struct CertifiedPermissions {
    pub(crate) verified: VerifiedPermissions,
    pub(crate) effective: PermissionLattice,
}

/// Evaluate a request-borne delegation certificate, fail-closed.
///
/// `Ok(None)`: no certificate presented — the caller proceeds under its
/// policy / permission bid exactly as before. `Ok(Some(..))`: a certificate
/// verified against the pinned root, whose leaf IS the authenticated caller.
/// `Err`: a certificate was presented and cannot be honoured — on a tier
/// with no identity binding, malformed, unverifiable, for another leaf, or
/// with no anchor configured. Never a silent downgrade.
pub(crate) fn evaluate_request_cert(
    headers: &HeaderMap,
    state: &AppState,
    method: &AuthMethod,
    authenticated_spiffe_id: Option<&str>,
    client_cert_der: Option<&[u8]>,
) -> Result<
    Option<(
        PermissionGrant,
        CertifiedPermissions,
        Option<identity_fusion::FusedIdentity>,
    )>,
    ApiError,
> {
    let Some(cert_header) = headers.get(HEADER_DELEGATION_CERT) else {
        return Ok(None);
    };
    if delegation_authority(method) == DelegationAuthority::Unbound {
        tracing::warn!(
            method = ?method,
            event = "delegation_cert_unbound_tier",
            "delegation cert presented on an auth tier with no identity binding"
        );
        return Err(ApiError::DelegationCert(format!(
            "a delegation certificate cannot be honoured on the {method:?} tier: no identity to bind it to"
        )));
    }
    let Some(spiffe_id) = authenticated_spiffe_id else {
        return Err(ApiError::DelegationCert(
            "bound tier without an authenticated identity".into(),
        ));
    };
    let Some(root_pubkey) = state.cert_root_pubkey.as_ref() else {
        return Err(ApiError::DelegationCert(
            "no root delegation authority is configured on this pod".into(),
        ));
    };
    let cert_b64 = cert_header
        .to_str()
        .map_err(|_| ApiError::DelegationCert("header is not ASCII".into()))?;
    let cert_bytes = base64::engine::general_purpose::STANDARD
        .decode(cert_b64)
        .map_err(|e| ApiError::DelegationCert(format!("invalid base64: {e}")))?;
    let cert: LatticeCertificate = serde_json::from_slice(&cert_bytes)
        .map_err(|e| ApiError::DelegationCert(format!("invalid certificate JSON: {e}")))?;
    let verified = verify_certificate(&cert, root_pubkey, Utc::now(), DEFAULT_MAX_CHAIN_DEPTH)
        .map_err(|e| ApiError::DelegationCert(format!("verification failed: {e}")))?;

    // The certificate's leaf must BE the authenticated caller: agent-A may not
    // act under agent-B's certificate.
    if verified.leaf_identity() != spiffe_id {
        tracing::warn!(
            authenticated_id = %spiffe_id,
            cert_leaf_id = %verified.leaf_identity(),
            event = "identity_mismatch_rejected",
            "delegation cert leaf_identity does not match authenticated SPIFFE ID"
        );
        return Err(ApiError::DelegationCert(format!(
            "certificate leaf {} is not the authenticated caller",
            verified.leaf_identity()
        )));
    }

    // Layer 3: fused identity from the X.509 permission-fingerprint extension.
    let mut fused =
        client_cert_der.and_then(|der| identity_fusion::extract_fused_identity(der, spiffe_id));

    let bid = cert_bridge::certificate_to_bid(&verified);
    let market = state.permission_market.lock().unwrap();
    let mut grant = market.evaluate_bid(&bid);
    if let Some(ref mut fi) = fused
        && identity_fusion::verify_delegation_against_fingerprint(fi, &cert, &verified)
    {
        grant = identity_fusion::elevate_grant_trust(&grant);
    }
    let effective = cert_bridge::intersect_grant_with_certificate(&grant, &verified);

    tracing::info!(
        leaf_identity = %verified.leaf_identity(),
        chain_depth = verified.chain_depth(),
        trust_tier = ?bid.trust_tier,
        granted = grant.granted.len(),
        denied = grant.denied.len(),
        total_cost = grant.total_cost,
        fused_verified = fused.as_ref().is_some_and(|f| f.fingerprint_verified),
        event = "delegation_cert_evaluated",
        "delegation certificate verified and evaluated against market"
    );

    Ok(Some((
        grant,
        CertifiedPermissions {
            verified,
            effective,
        },
        fused,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn key() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap()
    }

    fn issued() -> (String, String, Ed25519KeyPair) {
        let rng = ring::rand::SystemRandom::new();
        let root = key();
        let (cert, _holder) = LatticeCertificate::mint(
            PermissionLattice::restrictive(),
            "spiffe://test/ns/pods/sa/p1".into(),
            Utc::now() + Duration::hours(1),
            &root,
            &rng,
        );
        let token = AttenuationToken::seal(cert, root.public_key().as_ref().to_vec());
        (
            token.to_base64().unwrap(),
            hex::encode(root.public_key().as_ref()),
            root,
        )
    }

    #[test]
    fn absent_is_none_and_a_valid_certificate_verifies() {
        assert!(matches!(
            resolve_pod_certificate(None, None, Utc::now()),
            Ok(None)
        ));
        assert!(matches!(
            resolve_pod_certificate(Some("  "), Some("aa"), Utc::now()),
            Ok(None)
        ));
        let (b64, anchor, _) = issued();
        let (verified, summary) = resolve_pod_certificate(Some(&b64), Some(&anchor), Utc::now())
            .unwrap()
            .expect("issued");
        assert_eq!(summary.leaf_identity, "spiffe://test/ns/pods/sa/p1");
        assert_eq!(summary.chain_depth, 0);
        assert!(summary.effective.leq(verified.effective()));
    }

    /// The trust decision is the pinned anchor, never the token's own key.
    #[test]
    fn the_embedded_root_key_is_not_the_trust_decision() {
        let (b64, _anchor, _) = issued();
        let other = hex::encode(key().public_key().as_ref());
        assert!(matches!(
            resolve_pod_certificate(Some(&b64), Some(&other), Utc::now()),
            Err(PodCertError::AnchorMismatch)
        ));
        // And a token whose embedded key we deliberately re-seal to the pinned
        // anchor still fails the actual signature check.
        let (b64, _, _) = issued();
        let token = AttenuationToken::from_base64(&b64).unwrap();
        let stranger = key();
        let resealed = AttenuationToken::seal(
            token.certificate().clone(),
            stranger.public_key().as_ref().to_vec(),
        );
        let anchor = hex::encode(stranger.public_key().as_ref());
        assert!(matches!(
            resolve_pod_certificate(
                Some(&resealed.to_base64().unwrap()),
                Some(&anchor),
                Utc::now()
            ),
            Err(PodCertError::Verify(_))
        ));
    }

    #[test]
    fn a_certificate_without_an_anchor_is_fatal_not_ignored() {
        let (b64, _, _) = issued();
        assert!(matches!(
            resolve_pod_certificate(Some(&b64), None, Utc::now()),
            Err(PodCertError::MissingAnchor)
        ));
        assert!(matches!(
            resolve_pod_certificate(Some(&b64), Some("not-hex"), Utc::now()),
            Err(PodCertError::MalformedAnchor)
        ));
        assert!(matches!(
            resolve_pod_certificate(Some("!!not base64!!"), Some(&"ab".repeat(32)), Utc::now()),
            Err(PodCertError::Malformed(_))
        ));
    }

    #[test]
    fn an_expired_certificate_does_not_verify() {
        let (b64, anchor, _) = issued();
        assert!(matches!(
            resolve_pod_certificate(Some(&b64), Some(&anchor), Utc::now() + Duration::hours(2)),
            Err(PodCertError::Verify(_))
        ));
    }

    /// #2427: exactly one tier binds an identity.
    #[test]
    fn only_spiffe_mtls_carries_delegation_authority() {
        assert_eq!(
            delegation_authority(&AuthMethod::SpiffeMtls),
            DelegationAuthority::Bound
        );
        for m in [
            AuthMethod::Hmac,
            AuthMethod::HmacDrand,
            AuthMethod::HostVsock,
            AuthMethod::Ed25519Drand,
        ] {
            assert_eq!(
                delegation_authority(&m),
                DelegationAuthority::Unbound,
                "{m:?}"
            );
        }
    }
}
