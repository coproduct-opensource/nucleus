//! SPIFFE Identity Fusion: binding LatticeCertificate to WorkloadCertificate.
//!
//! When a pod's X.509 certificate contains a permission fingerprint extension
//! (OID 1.3.6.1.4.1.57212.1.2), the pod's SPIFFE identity IS its permission
//! attestation. The CA has cryptographically bound "who you are" to "what you can do".
//!
//! # Trust Elevation
//!
//! - No fingerprint: trust from policy engine or delegation cert (standard path)
//! - Fingerprint + matching delegation cert: Platform trust tier (CA-attested binding)
//! - Fingerprint + mismatched delegation cert: logged warning, no elevation

use nucleus_permission_market::PermissionGrant;
use portcullis::certificate::VerifiedPermissions;

/// Result of fused identity verification.
///
/// When an mTLS client certificate contains a permission fingerprint extension,
/// this struct tracks whether the delegation certificate matches.
#[derive(Clone, Debug)]
pub struct FusedIdentity {
    /// The SPIFFE ID from the X.509 certificate.
    pub spiffe_id: String,
    /// The SHA-256 permission fingerprint from the X.509 extension.
    pub permission_fingerprint: [u8; 32],
    /// The verified permissions (set when delegation cert matches fingerprint).
    #[allow(dead_code)]
    pub verified_permissions: Option<VerifiedPermissions>,
    /// Whether the fingerprint matched the delegation cert (elevated trust).
    pub fingerprint_verified: bool,
}

/// Attempt to extract a fused identity from the mTLS client certificate.
///
/// Returns `Some(FusedIdentity)` if the client cert has a permission fingerprint extension.
pub fn extract_fused_identity(client_cert_der: &[u8], spiffe_id: &str) -> Option<FusedIdentity> {
    let fingerprint =
        nucleus_identity::attestation::extract_permission_fingerprint(client_cert_der)?;

    Some(FusedIdentity {
        spiffe_id: spiffe_id.to_string(),
        permission_fingerprint: fingerprint,
        verified_permissions: None,
        fingerprint_verified: false,
    })
}

/// Verify that a delegation certificate's fingerprint matches the one embedded in X.509.
///
/// If they match, the trust tier is elevated to Platform (CA-attested binding)
/// and the market cost drops to zero.
pub fn verify_delegation_against_fingerprint(
    fused: &mut FusedIdentity,
    cert: &portcullis::LatticeCertificate,
    verified: &VerifiedPermissions,
) -> bool {
    let cert_fingerprint = cert.fingerprint();

    if cert_fingerprint == fused.permission_fingerprint {
        fused.verified_permissions = Some(verified.clone());
        fused.fingerprint_verified = true;
        tracing::info!(
            spiffe_id = %fused.spiffe_id,
            fingerprint = %hex::encode(&fused.permission_fingerprint[..8]),
            event = "fused_identity_verified",
            "delegation cert fingerprint matches X.509 extension — elevated to Platform trust"
        );
        true
    } else {
        tracing::warn!(
            spiffe_id = %fused.spiffe_id,
            x509_fp = %hex::encode(&fused.permission_fingerprint[..8]),
            cert_fp = %hex::encode(&cert_fingerprint[..8]),
            event = "fused_identity_mismatch",
            "delegation cert fingerprint does NOT match X.509 extension"
        );
        false
    }
}

/// Override a permission grant for CA-attested bindings: zero market cost.
///
/// When the CA has cryptographically bound identity to permissions, the market
/// cost is waived — the CA's signature is the ultimate authority.
pub fn elevate_grant_trust(grant: &PermissionGrant) -> PermissionGrant {
    PermissionGrant {
        granted: grant.granted.clone(),
        denied: grant.denied.clone(),
        total_cost: 0.0,
        expires_at: grant.expires_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elevate_grant_trust_zeroes_cost() {
        let grant = PermissionGrant {
            granted: vec![],
            denied: vec![],
            total_cost: 42.0,
            expires_at: None,
        };
        let elevated = elevate_grant_trust(&grant);
        assert_eq!(elevated.total_cost, 0.0);
    }

    #[test]
    fn test_extract_fused_identity_returns_none_without_extension() {
        // Any DER that isn't a valid X.509 cert should return None
        let fake_der = b"not a certificate";
        assert!(extract_fused_identity(fake_der, "spiffe://test/agent").is_none());
    }

    #[test]
    fn test_verify_delegation_matching_fingerprint() {
        use portcullis::{LatticeCertificate, PermissionLattice};
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = SystemRandom::new();
        let root_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let root_key = Ed25519KeyPair::from_pkcs8(root_pkcs8.as_ref()).unwrap();
        let not_after = chrono::Utc::now() + chrono::Duration::hours(8);

        let (cert, _holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/root".into(),
            not_after,
            &root_key,
            &rng,
        );

        let root_pub = root_key.public_key().as_ref().to_vec();
        let verified = portcullis::verify_certificate(
            &cert,
            &root_pub,
            chrono::Utc::now(),
            portcullis::certificate::DEFAULT_MAX_CHAIN_DEPTH,
        )
        .unwrap();

        let fp = cert.fingerprint();
        let mut fused = FusedIdentity {
            spiffe_id: "spiffe://test/root".into(),
            permission_fingerprint: fp,
            verified_permissions: None,
            fingerprint_verified: false,
        };

        assert!(verify_delegation_against_fingerprint(
            &mut fused, &cert, &verified
        ));
        assert!(fused.fingerprint_verified);
        assert!(fused.verified_permissions.is_some());
    }

    #[test]
    fn test_verify_delegation_mismatched_fingerprint() {
        use portcullis::{LatticeCertificate, PermissionLattice};
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = SystemRandom::new();
        let root_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let root_key = Ed25519KeyPair::from_pkcs8(root_pkcs8.as_ref()).unwrap();
        let not_after = chrono::Utc::now() + chrono::Duration::hours(8);

        let (cert, _holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/root".into(),
            not_after,
            &root_key,
            &rng,
        );

        let root_pub = root_key.public_key().as_ref().to_vec();
        let verified = portcullis::verify_certificate(
            &cert,
            &root_pub,
            chrono::Utc::now(),
            portcullis::certificate::DEFAULT_MAX_CHAIN_DEPTH,
        )
        .unwrap();

        // Use a bogus fingerprint
        let mut fused = FusedIdentity {
            spiffe_id: "spiffe://test/root".into(),
            permission_fingerprint: [0x00; 32],
            verified_permissions: None,
            fingerprint_verified: false,
        };

        assert!(!verify_delegation_against_fingerprint(
            &mut fused, &cert, &verified
        ));
        assert!(!fused.fingerprint_verified);
        assert!(fused.verified_permissions.is_none());
    }
}
