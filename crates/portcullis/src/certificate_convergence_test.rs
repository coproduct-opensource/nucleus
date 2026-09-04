//! Certificate-convergence tests: signature coverage of every attenuating
//! dimension, strict Ed25519 verification, and the caller-owned-key
//! constructors an issuer needs to persist per-pod authority.
//!
//! Lives beside `certificate.rs` (like `kernel_tests.rs`) rather than inside
//! it so the module stays under the line ratchet; it uses the same
//! `pub(crate)` test-only accessors.

use crate::certificate::*;
use crate::{CapabilityLevel, PermissionLattice};
use chrono::{Duration, Utc};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn generate_key(rng: &dyn SecureRandom) -> Ed25519KeyPair {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(rng).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn minted() -> (LatticeCertificate, Ed25519KeyPair, Vec<u8>, SystemRandom) {
    let rng = SystemRandom::new();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();
    let mut perms = PermissionLattice::restrictive();
    perms.capabilities.spawn_agent = CapabilityLevel::Never;
    perms.budget.max_cost_usd = rust_decimal::Decimal::from(5);
    let (cert, holder) = LatticeCertificate::mint(
        perms,
        "spiffe://test/human/alice".into(),
        Utc::now() + Duration::hours(8),
        &root_key,
        &rng,
    );
    (cert, holder, root_pub, rng)
}

/// The signature-coverage hole: `spawn_agent` was inside the signed struct
/// but outside the signed bytes, so raising it on the serialized
/// certificate invalidated nothing. It is exactly the dimension that gates
/// sub-pod creation.
#[test]
fn spawn_agent_is_signature_covered() {
    let (mut cert, _holder, root_pub, _rng) = minted();
    assert!(verify_certificate(&cert, &root_pub, Utc::now(), DEFAULT_MAX_CHAIN_DEPTH).is_ok());

    cert.authority_mut()
        .root_permissions
        .capabilities
        .spawn_agent = CapabilityLevel::Always;
    let result = verify_certificate(&cert, &root_pub, Utc::now(), DEFAULT_MAX_CHAIN_DEPTH);
    assert!(
        matches!(
            result,
            Err(CertificateError::InvalidSignature { block_index: 0 })
        ),
        "raising spawn_agent must break the authority signature, got {result:?}"
    );
}

#[test]
fn extension_capabilities_are_signature_covered() {
    let (mut cert, _holder, root_pub, _rng) = minted();
    cert.authority_mut()
        .root_permissions
        .capabilities
        .extensions
        .insert(
            crate::capability::ExtensionOperation::new("deploy"),
            CapabilityLevel::Always,
        );
    assert!(matches!(
        verify_certificate(&cert, &root_pub, Utc::now(), DEFAULT_MAX_CHAIN_DEPTH),
        Err(CertificateError::InvalidSignature { block_index: 0 })
    ));
}

/// Resetting `consumed_usd` grants back everything already spent.
#[test]
fn consumed_usd_is_signature_covered_and_monotone() {
    let (cert, holder, root_pub, rng) = minted();
    let mut spent = cert.effective_permissions().clone();
    spent.budget.charge(rust_decimal::Decimal::from(2));
    let (mut child, _k) = cert
        .delegate(
            &spent,
            "spiffe://test/agent/a".into(),
            Utc::now() + Duration::hours(1),
            &holder,
            &rng,
        )
        .unwrap();
    assert!(verify_certificate(&child, &root_pub, Utc::now(), DEFAULT_MAX_CHAIN_DEPTH).is_ok());

    // Tamper: pretend nothing was spent. Signature breaks first.
    child.blocks_mut()[0]
        .effective_permissions
        .budget
        .consumed_usd = rust_decimal::Decimal::ZERO;
    assert!(matches!(
        verify_certificate(&child, &root_pub, Utc::now(), DEFAULT_MAX_CHAIN_DEPTH),
        Err(CertificateError::InvalidSignature { block_index: 1 })
    ));

    // And independently of the signature, the lattice order refuses it.
    let mut reset = spent.clone();
    reset.budget.consumed_usd = rust_decimal::Decimal::ZERO;
    assert!(!reset.leq(&spent), "a consumed_usd reset is an escalation");
}

#[test]
fn provenance_is_signature_covered_and_fingerprinted() {
    let rng = SystemRandom::new();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();
    let holder = generate_key(&rng);
    let fp = [7u8; 32];
    let cert = LatticeCertificate::mint_with_holder_key(
        PermissionLattice::restrictive(),
        "spiffe://test/agent/rerooted".into(),
        Utc::now() + Duration::hours(1),
        Some(fp),
        &root_key,
        &holder,
    );
    assert_eq!(cert.authority().provenance, Some(fp));
    assert!(verify_certificate(&cert, &root_pub, Utc::now(), DEFAULT_MAX_CHAIN_DEPTH).is_ok());
    let fingerprint_with = cert.fingerprint();

    let mut stripped = cert.clone();
    stripped.authority_mut().provenance = None;
    assert!(matches!(
        verify_certificate(&stripped, &root_pub, Utc::now(), DEFAULT_MAX_CHAIN_DEPTH),
        Err(CertificateError::InvalidSignature { block_index: 0 })
    ));
    assert_ne!(stripped.fingerprint(), fingerprint_with);
}

/// The point of the caller-owned-key constructors: a key the issuer
/// generated itself (and can therefore persist) is the key the chain
/// expects at the next hop.
#[test]
fn issuer_owned_keys_delegate_across_hops() {
    let rng = SystemRandom::new();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();

    let holder_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let holder = Ed25519KeyPair::from_pkcs8(holder_pkcs8.as_ref()).unwrap();
    let cert = LatticeCertificate::mint_with_holder_key(
        PermissionLattice::permissive(),
        "spiffe://test/root".into(),
        Utc::now() + Duration::hours(8),
        None,
        &root_key,
        &holder,
    );

    // "Restart": re-parse the persisted document and delegate with it.
    let holder_again = Ed25519KeyPair::from_pkcs8(holder_pkcs8.as_ref()).unwrap();
    let child_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let child_key = Ed25519KeyPair::from_pkcs8(child_pkcs8.as_ref()).unwrap();
    // One expiry for every hop: a second `Utc::now()` is already later and
    // `delegate_with_scope` checks expiry before anything else of interest.
    let hop_expiry = Utc::now() + Duration::hours(1);
    let child = cert
        .mint_child_with_scope_using_key(
            &PermissionLattice::restrictive(),
            "spiffe://test/pod/1".into(),
            hop_expiry,
            "spawn",
            SinkScope::unrestricted(),
            &holder_again,
            &child_key,
        )
        .expect("persisted holder key must match next_key");
    assert_eq!(
        child.delegation_blocks()[0].next_key,
        child_key.public_key().as_ref()
    );

    let grandchild_key = generate_key(&rng);
    let grandchild = child
        .mint_child_with_scope_using_key(
            &PermissionLattice::restrictive(),
            "spiffe://test/pod/2".into(),
            hop_expiry,
            "spawn",
            SinkScope::unrestricted(),
            &child_key,
            &grandchild_key,
        )
        .expect("the child key the issuer kept delegates again");
    let verified =
        verify_certificate(&grandchild, &root_pub, Utc::now(), DEFAULT_MAX_CHAIN_DEPTH).unwrap();
    assert_eq!(verified.chain_depth(), 2);
    assert_eq!(verified.leaf_identity(), "spiffe://test/pod/2");

    // A key the issuer did NOT mint the hop with is still refused.
    let stranger = generate_key(&rng);
    assert!(matches!(
        child.mint_child_with_scope_using_key(
            &PermissionLattice::restrictive(),
            "spiffe://test/pod/3".into(),
            hop_expiry,
            "spawn",
            SinkScope::unrestricted(),
            &stranger,
            &grandchild_key,
        ),
        Err(CertificateMintChildError::Chain(
            CertificateDelegationError::KeyMismatch
        ))
    ));
}

#[test]
fn mint_child_with_scope_narrows_scope_and_budget() {
    let (cert, holder, root_pub, rng) = minted();
    let scope = SinkScope {
        allowed_paths: vec!["src/**".into()],
        ..SinkScope::unrestricted()
    };
    let hop_expiry = Utc::now() + Duration::hours(1);
    let (child, child_key) = cert
        .mint_child_with_scope(
            &PermissionLattice::restrictive(),
            "spiffe://test/pod/1".into(),
            hop_expiry,
            "spawn",
            scope.clone(),
            &holder,
            &rng,
        )
        .unwrap();
    let verified =
        verify_certificate(&child, &root_pub, Utc::now(), DEFAULT_MAX_CHAIN_DEPTH).unwrap();
    assert_eq!(verified.sink_scope().allowed_paths, scope.allowed_paths);

    // Widening the scope at the next hop is refused at mint time.
    let widened = child.mint_child_with_scope(
        &PermissionLattice::restrictive(),
        "spiffe://test/pod/2".into(),
        hop_expiry,
        "spawn",
        SinkScope::unrestricted(),
        &child_key,
        &rng,
    );
    assert!(
        matches!(
            widened,
            Err(CertificateMintChildError::Chain(
                CertificateDelegationError::SinkScopeExceedsParent
            ))
        ),
        "expected SinkScopeExceedsParent, got {widened:?}"
    );

    // And so is a budget past the parent's.
    let mut greedy = PermissionLattice::restrictive();
    greedy.budget.max_cost_usd = rust_decimal::Decimal::from(1_000);
    let over = child.mint_child_with_scope(
        &greedy,
        "spiffe://test/pod/2".into(),
        hop_expiry,
        "spawn",
        scope,
        &child_key,
        &rng,
    );
    assert!(
        matches!(
            over,
            Err(CertificateMintChildError::Lattice(
                crate::DelegationError::InsufficientBudget { .. }
            ))
        ),
        "expected InsufficientBudget, got {over:?}"
    );
}

/// SECURITY_TODO #16: the chain verify must reject the small-order
/// identity-key forgery that `ring`'s cofactored verify accepts. Under the
/// identity key A = R the cofactored equation `[s]B == R + [k]A` reduces to
/// `identity == identity` for EVERY message.
#[test]
fn small_order_root_key_forgery_rejected() {
    let (mut cert, _holder, _root_pub, _rng) = minted();
    let mut identity_vk = [0u8; 32];
    identity_vk[0] = 1; // compressed Edwards identity: y = 1
    let mut identity_sig = [0u8; 64];
    identity_sig[..32].copy_from_slice(&identity_vk); // R = identity, s = 0

    let payload = cert.authority().signing_payload();
    // Non-vacuity: this IS a forgery ring accepts.
    let ring_verifier =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, identity_vk);
    assert!(
        ring_verifier.verify(&payload, &identity_sig).is_ok(),
        "ring's cofactored verify accepts the identity triple; if this ever fails the \
         test no longer distinguishes strict from cofactored verification"
    );

    cert.authority_mut().signature = identity_sig.to_vec();
    assert!(matches!(
        verify_certificate(&cert, &identity_vk, Utc::now(), DEFAULT_MAX_CHAIN_DEPTH),
        Err(CertificateError::InvalidSignature { block_index: 0 })
    ));
}

#[test]
fn authority_block_without_provenance_field_still_deserializes() {
    // Older serialized certificates carry no `provenance`; serde(default)
    // reads them as None (they will then fail signature verification under
    // the v2 payload, by design — but they must parse).
    let (cert, _h, _p, _r) = minted();
    let mut json: serde_json::Value = serde_json::from_slice(&cert.to_bytes().unwrap()).unwrap();
    json["authority"]
        .as_object_mut()
        .unwrap()
        .remove("provenance");
    let parsed = LatticeCertificate::from_bytes(&serde_json::to_vec(&json).unwrap()).unwrap();
    assert_eq!(parsed.authority().provenance, None);
}
