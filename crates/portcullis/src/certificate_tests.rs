//! Tests for `certificate.rs`, in their own file so the certificate module
//! stays under the line ratchet's sweep ceiling as the chain checks and their
//! regression tests grow (#2474, #2485, #2484, #2451 each added some).

use super::*;
use crate::CapabilityLevel;
use chrono::Duration;

fn test_rng() -> ring::rand::SystemRandom {
    ring::rand::SystemRandom::new()
}

fn generate_key(rng: &dyn SecureRandom) -> Ed25519KeyPair {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(rng).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

#[test]
fn test_mint_and_verify() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + Duration::hours(8);

    let (cert, _holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    assert_eq!(cert.chain_depth(), 0);
    assert_eq!(cert.root_identity(), "spiffe://test/human/alice");
    assert_eq!(cert.leaf_identity(), "spiffe://test/human/alice");

    let verified = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();
    assert_eq!(verified.chain_depth, 0);
    assert_eq!(verified.root_identity, "spiffe://test/human/alice");
    assert_eq!(verified.leaf_identity, "spiffe://test/human/alice");
}

#[test]
fn test_single_delegation() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + Duration::hours(8);

    let root_perms = PermissionLattice::permissive();
    let (cert, holder_key) = LatticeCertificate::mint(
        root_perms.clone(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    let requested = PermissionLattice::restrictive();
    let (cert, _delegatee_key) = cert
        .delegate(
            &requested,
            "spiffe://test/agent/coder-042".into(),
            not_after,
            &holder_key,
            &rng,
        )
        .unwrap();

    assert_eq!(cert.chain_depth(), 1);
    assert_eq!(cert.leaf_identity(), "spiffe://test/agent/coder-042");

    let verified = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();
    assert_eq!(verified.chain_depth, 1);
    assert_eq!(verified.leaf_identity, "spiffe://test/agent/coder-042");

    // Effective permissions should be ≤ root (compare against same root, not fresh one)
    assert!(verified.effective.leq(&root_perms));
}

#[test]
fn test_three_hop_chain() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + Duration::hours(8);

    // Alice → Orchestrator
    let (cert, holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    let mut orch_request = PermissionLattice::permissive();
    orch_request.capabilities.git_push = CapabilityLevel::Never;

    let (cert, orch_key) = cert
        .delegate(
            &orch_request,
            "spiffe://test/agent/orch-001".into(),
            not_after,
            &holder_key,
            &rng,
        )
        .unwrap();

    // Orchestrator → Coder
    let mut coder_request = PermissionLattice::permissive();
    coder_request.capabilities.web_fetch = CapabilityLevel::Never;

    let (cert, coder_key) = cert
        .delegate(
            &coder_request,
            "spiffe://test/agent/coder-042".into(),
            not_after,
            &orch_key,
            &rng,
        )
        .unwrap();

    // Coder → TestRunner
    let (cert, _test_key) = cert
        .delegate(
            &PermissionLattice::read_only(),
            "spiffe://test/agent/test-007".into(),
            not_after,
            &coder_key,
            &rng,
        )
        .unwrap();

    assert_eq!(cert.chain_depth(), 3);

    let verified = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();
    assert_eq!(verified.chain_depth, 3);
    assert_eq!(verified.root_identity, "spiffe://test/human/alice");
    assert_eq!(verified.leaf_identity, "spiffe://test/agent/test-007");

    // TestRunner permissions must be ≤ all ancestors
    let root_perms = &cert.authority.root_permissions;
    assert!(verified.effective.leq(root_perms));
}

#[test]
fn test_wrong_root_key_rejected() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let wrong_key = generate_key(&rng);
    let wrong_pub = wrong_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + Duration::hours(8);

    let (cert, _holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    let result = verify_certificate(&cert, &wrong_pub, Utc::now(), 10);
    assert!(matches!(
        result,
        Err(CertificateError::InvalidSignature { block_index: 0 })
    ));
}

#[test]
fn test_tampered_authority_signature_rejected() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + Duration::hours(8);

    let (mut cert, _holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    // Flip a bit in the authority signature
    cert.authority_mut().signature[0] ^= 0x01;

    let result = verify_certificate(&cert, &root_pub, Utc::now(), 10);
    assert!(matches!(
        result,
        Err(CertificateError::InvalidSignature { block_index: 0 })
    ));
}

#[test]
fn test_tampered_delegation_signature_rejected() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + Duration::hours(8);

    let (cert, holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    let (mut cert, _delegatee_key) = cert
        .delegate(
            &PermissionLattice::restrictive(),
            "spiffe://test/agent/coder".into(),
            not_after,
            &holder_key,
            &rng,
        )
        .unwrap();

    // Flip a bit in the delegation signature
    cert.blocks_mut()[0].signature[0] ^= 0x01;

    let result = verify_certificate(&cert, &root_pub, Utc::now(), 10);
    assert!(matches!(
        result,
        Err(CertificateError::InvalidSignature { block_index: 1 })
    ));
}

#[test]
fn test_expired_authority_rejected() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();

    // Expired 1 hour ago
    let not_after = Utc::now() - Duration::hours(1);

    let (cert, _holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    let result = verify_certificate(&cert, &root_pub, Utc::now(), 10);
    assert!(matches!(
        result,
        Err(CertificateError::Expired { block_index: 0 })
    ));
}

#[test]
fn test_chain_too_deep_rejected() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + Duration::hours(8);

    let (cert, _holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    // Verify with max_chain_depth = 0 (no delegations allowed)
    let result = verify_certificate(&cert, &root_pub, Utc::now(), 0);
    // Should pass (0 blocks, max 0)
    assert!(result.is_ok());

    // Now delegate once
    let (cert, holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    let (cert, _delegatee_key) = cert
        .delegate(
            &PermissionLattice::restrictive(),
            "spiffe://test/agent/coder".into(),
            not_after,
            &holder_key,
            &rng,
        )
        .unwrap();

    // max_chain_depth = 0 should reject 1 block
    let result = verify_certificate(&cert, &root_pub, Utc::now(), 0);
    assert!(matches!(
        result,
        Err(CertificateError::ChainTooDeep { depth: 1, max: 0 })
    ));
}

#[test]
fn test_expiry_exceeds_parent_rejected() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let not_after = Utc::now() + Duration::hours(1);

    let (cert, holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    // Try to delegate with longer expiry
    let result = cert.delegate(
        &PermissionLattice::restrictive(),
        "spiffe://test/agent/coder".into(),
        not_after + Duration::hours(1), // exceeds parent
        &holder_key,
        &rng,
    );

    assert!(matches!(
        result,
        Err(CertificateDelegationError::ExpiryExceedsParent)
    ));
}

#[test]
fn test_key_mismatch_rejected() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let wrong_key = generate_key(&rng);
    let not_after = Utc::now() + Duration::hours(8);

    let (cert, _holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    // Try to delegate with the wrong key
    let result = cert.delegate(
        &PermissionLattice::restrictive(),
        "spiffe://test/agent/coder".into(),
        not_after,
        &wrong_key,
        &rng,
    );

    assert!(matches!(
        result,
        Err(CertificateDelegationError::KeyMismatch)
    ));
}

#[test]
fn test_invalid_proof_of_possession() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + Duration::hours(8);

    let (mut cert, _holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    // Tamper with the proof-of-possession
    cert.final_signature_mut()[0] ^= 0x01;

    let result = verify_certificate(&cert, &root_pub, Utc::now(), 10);
    assert!(matches!(
        result,
        Err(CertificateError::InvalidProofOfPossession)
    ));
}

#[cfg(feature = "serde")]
#[test]
fn test_serde_roundtrip() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + Duration::hours(8);

    let (cert, holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    let (cert, _delegatee_key) = cert
        .delegate(
            &PermissionLattice::restrictive(),
            "spiffe://test/agent/coder".into(),
            not_after,
            &holder_key,
            &rng,
        )
        .unwrap();

    // Serialize → deserialize → verify
    let bytes = cert.to_bytes().unwrap();
    let restored = LatticeCertificate::from_bytes(&bytes).unwrap();
    let verified = verify_certificate(&restored, &root_pub, Utc::now(), 10).unwrap();
    assert_eq!(verified.chain_depth, 1);
}

/// #2485: the tool surface rides the certificate as extension keys, so a
/// hop can only narrow it — the child's effective surface is the meet of
/// what the parent approved and what the child asked for, inside the
/// signed permissions and therefore the fingerprint.
#[test]
fn a_delegated_certificate_narrows_the_tool_surface() {
    use crate::tool_surface::{approve_tool, approved_tools};

    let rng = test_rng();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + Duration::hours(8);

    let mut root_perms = PermissionLattice::permissive();
    approve_tool(&mut root_perms.capabilities, "read_file", "11");
    approve_tool(&mut root_perms.capabilities, "list_dir", "22");
    let (cert, holder) = LatticeCertificate::mint(
        root_perms,
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    let mut requested = PermissionLattice::permissive();
    approve_tool(&mut requested.capabilities, "read_file", "11");
    approve_tool(&mut requested.capabilities, "exfiltrate", "33");
    let (child, _) = cert
        .delegate(
            &requested,
            "spiffe://test/agent/a".into(),
            not_after,
            &holder,
            &rng,
        )
        .unwrap();

    let verified = verify_certificate(&child, &root_pub, Utc::now(), 10).unwrap();
    assert_eq!(
        approved_tools(&verified.effective().capabilities).unwrap(),
        std::collections::BTreeMap::from([("read_file".to_string(), "11".to_string())]),
        "list_dir dropped by the child, exfiltrate never approved by the parent"
    );
    assert_ne!(
        child.fingerprint(),
        cert.fingerprint(),
        "the surface is under the fingerprint"
    );

    // A request that says nothing about tools keeps the parent's surface.
    let (silent, _) = cert
        .delegate(
            &PermissionLattice::permissive(),
            "spiffe://test/agent/b".into(),
            not_after,
            &holder,
            &rng,
        )
        .unwrap();
    let verified = verify_certificate(&silent, &root_pub, Utc::now(), 10).unwrap();
    assert_eq!(
        approved_tools(&verified.effective().capabilities).unwrap(),
        std::collections::BTreeMap::from([
            ("list_dir".to_string(), "22".to_string()),
            ("read_file".to_string(), "11".to_string()),
        ])
    );

    // Asking for the marker at Never cannot shed the dimension either: a
    // request with no surface above Never counts as silent and inherits
    // the parent's whole surface. No request shape escapes.
    let mut shed = PermissionLattice::permissive();
    shed.capabilities.extensions.insert(
        crate::ExtensionOperation::new(crate::tool_surface::TOOL_SURFACE_MARKER),
        crate::CapabilityLevel::Never,
    );
    let (kept, _) = cert
        .delegate(
            &shed,
            "spiffe://test/agent/c".into(),
            not_after,
            &holder,
            &rng,
        )
        .unwrap();
    let verified = verify_certificate(&kept, &root_pub, Utc::now(), 10).unwrap();
    assert_eq!(
        approved_tools(&verified.effective().capabilities)
            .unwrap()
            .len(),
        2,
        "the shedding request inherited the parent's surface instead"
    );
}

/// #2484: the compartment rides the certificate; a root in `execute` is
/// clamped to its ceiling, a child may go down to `draft` (and is clamped
/// again), a silent child inherits, and a child asking for `breakglass`
/// is refused rather than clamped.
#[test]
fn a_certificate_carries_a_compartment_that_only_goes_down() {
    use crate::cert_compartment::{
        compartment_of, set_compartment, Compartment, CompartmentHopError,
    };

    let rng = test_rng();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + Duration::hours(8);

    let mut root_perms = PermissionLattice::permissive();
    set_compartment(&mut root_perms.capabilities, Compartment::Execute);
    let (cert, holder) = LatticeCertificate::mint(
        root_perms,
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );
    let root_eff = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();
    assert_eq!(
        compartment_of(&root_eff.effective().capabilities),
        Some(Compartment::Execute)
    );
    assert_eq!(
        root_eff.effective().capabilities.git_push,
        CapabilityLevel::Never,
        "execute cannot push"
    );

    let mut lower = PermissionLattice::permissive();
    set_compartment(&mut lower.capabilities, Compartment::Draft);
    let (child, child_key) = cert
        .delegate(
            &lower,
            "spiffe://test/agent/a".into(),
            not_after,
            &holder,
            &rng,
        )
        .unwrap();
    let eff = verify_certificate(&child, &root_pub, Utc::now(), 10).unwrap();
    assert_eq!(
        compartment_of(&eff.effective().capabilities),
        Some(Compartment::Draft)
    );
    assert_eq!(
        eff.effective().capabilities.run_bash,
        CapabilityLevel::Never,
        "draft cannot execute"
    );

    let (silent, _) = child
        .delegate(
            &PermissionLattice::permissive(),
            "spiffe://test/agent/b".into(),
            not_after,
            &child_key,
            &rng,
        )
        .unwrap();
    let eff = verify_certificate(&silent, &root_pub, Utc::now(), 10).unwrap();
    assert_eq!(
        compartment_of(&eff.effective().capabilities),
        Some(Compartment::Draft)
    );

    let mut higher = PermissionLattice::permissive();
    set_compartment(&mut higher.capabilities, Compartment::Breakglass);
    assert!(matches!(
        cert.delegate(
            &higher,
            "spiffe://test/agent/c".into(),
            not_after,
            &holder,
            &rng
        ),
        Err(CertificateDelegationError::Compartment(
            CompartmentHopError::Escalated {
                from: Compartment::Execute,
                to: Compartment::Breakglass
            }
        ))
    ));
}

#[test]
fn test_monotone_attenuation_holds() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let not_after = Utc::now() + Duration::hours(8);

    let root_perms = PermissionLattice::permissive();
    let (cert, holder_key) = LatticeCertificate::mint(
        root_perms.clone(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    let (cert, _key) = cert
        .delegate(
            &PermissionLattice::restrictive(),
            "spiffe://test/agent/a".into(),
            not_after,
            &holder_key,
            &rng,
        )
        .unwrap();

    // Effective permissions must be ≤ root
    assert!(cert.effective_permissions().leq(&root_perms));
}

// ═══════════════════════════════════════════════════════════════════════
// FINGERPRINT TESTS
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_fingerprint_deterministic() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let not_after = Utc::now() + Duration::hours(8);

    let (cert, _) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/root".into(),
        not_after,
        &root_key,
        &rng,
    );

    let fp1 = cert.fingerprint();
    let fp2 = cert.fingerprint();
    assert_eq!(fp1, fp2, "same certificate must produce same fingerprint");
}

#[test]
fn test_fingerprint_different_for_different_permissions() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let not_after = Utc::now() + Duration::hours(8);

    let (cert1, _) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/root".into(),
        not_after,
        &root_key,
        &rng,
    );
    let (cert2, _) = LatticeCertificate::mint(
        PermissionLattice::restrictive(),
        "spiffe://test/root".into(),
        not_after,
        &root_key,
        &rng,
    );

    assert_ne!(
        cert1.fingerprint(),
        cert2.fingerprint(),
        "different permissions must produce different fingerprints"
    );
}

#[test]
fn test_fingerprint_different_for_different_identities() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let not_after = Utc::now() + Duration::hours(8);

    let (cert1, _) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/alice".into(),
        not_after,
        &root_key,
        &rng,
    );
    let (cert2, _) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/bob".into(),
        not_after,
        &root_key,
        &rng,
    );

    assert_ne!(
        cert1.fingerprint(),
        cert2.fingerprint(),
        "different identities must produce different fingerprints"
    );
}

#[test]
fn test_fingerprint_changes_with_delegation() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let not_after = Utc::now() + Duration::hours(8);

    let (cert, holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/root".into(),
        not_after,
        &root_key,
        &rng,
    );
    let fp_before = cert.fingerprint();

    let (delegated, _) = cert
        .delegate(
            &PermissionLattice::restrictive(),
            "spiffe://test/agent".into(),
            not_after,
            &holder_key,
            &rng,
        )
        .unwrap();
    let fp_after = delegated.fingerprint();

    assert_ne!(
        fp_before, fp_after,
        "delegation must change the fingerprint"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Sink scope tests (#594)
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_sink_scope_subset_check() {
    let parent = SinkScope {
        allowed_paths: vec!["/workspace/".into(), "/tmp/".into()],
        allowed_hosts: vec!["api.example.com".into()],
        allowed_git_refs: vec![],
    };
    // Child is a subset
    let child = SinkScope {
        allowed_paths: vec!["/workspace/".into()],
        allowed_hosts: vec!["api.example.com".into()],
        allowed_git_refs: vec![],
    };
    assert!(parent.contains(&child));

    // Child tries to widen — NOT a subset
    let wider = SinkScope {
        allowed_paths: vec!["/workspace/".into(), "/etc/".into()],
        allowed_hosts: vec!["api.example.com".into()],
        allowed_git_refs: vec![],
    };
    assert!(!parent.contains(&wider));
}

#[test]
fn test_sink_scope_unrestricted_parent() {
    let unrestricted = SinkScope::unrestricted();
    let restricted = SinkScope {
        allowed_paths: vec!["/workspace/".into()],
        ..Default::default()
    };
    // Unrestricted parent allows any child
    assert!(unrestricted.contains(&restricted));
    assert!(unrestricted.contains(&unrestricted));
}

#[test]
fn test_sink_scope_restricted_parent_rejects_unrestricted_child() {
    let restricted = SinkScope {
        allowed_paths: vec!["/workspace/".into()],
        ..Default::default()
    };
    let unrestricted = SinkScope::unrestricted();
    // Restricted parent REJECTS unrestricted child (widening)
    assert!(!restricted.contains(&unrestricted));
}

#[test]
fn test_delegate_with_sink_scope() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let not_after = Utc::now() + Duration::hours(8);

    let (cert, holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "root".into(),
        not_after,
        &root_key,
        &rng,
    );

    // Delegate with path restrictions
    let scope = SinkScope {
        allowed_paths: vec!["/workspace/output/".into()],
        allowed_hosts: vec!["api.example.com".into()],
        ..Default::default()
    };

    let (cert, _delegatee_key) = cert
        .delegate_with_scope(
            &PermissionLattice::restrictive(),
            "agent-1".into(),
            not_after,
            scope.clone(),
            &holder_key,
            &rng,
        )
        .unwrap();

    // Verify — should see the sink scope
    let root_pub = root_key.public_key().as_ref();
    let verified = verify_certificate(&cert, root_pub, Utc::now(), 10).unwrap();
    assert_eq!(verified.sink_scope, scope);
}

#[test]
fn test_delegate_rejects_scope_widening() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let not_after = Utc::now() + Duration::hours(8);

    let (cert, holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "root".into(),
        not_after,
        &root_key,
        &rng,
    );

    // First delegation: restrict to /workspace/
    let narrow_scope = SinkScope {
        allowed_paths: vec!["/workspace/".into()],
        ..Default::default()
    };
    let (cert, delegatee_key) = cert
        .delegate_with_scope(
            &PermissionLattice::permissive(),
            "agent-1".into(),
            not_after,
            narrow_scope,
            &holder_key,
            &rng,
        )
        .unwrap();

    // Second delegation: try to WIDEN to /workspace/ + /etc/
    let wider_scope = SinkScope {
        allowed_paths: vec!["/workspace/".into(), "/etc/".into()],
        ..Default::default()
    };
    let result = cert.delegate_with_scope(
        &PermissionLattice::permissive(),
        "agent-2".into(),
        not_after,
        wider_scope,
        &delegatee_key,
        &rng,
    );

    assert!(matches!(
        result,
        Err(CertificateDelegationError::SinkScopeExceedsParent)
    ));
}

// ── mint_child (#2432) ───────────────────────────────────────────────

#[test]
fn mint_child_succeeds_and_matches_delegate() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let not_after = Utc::now() + Duration::hours(8);
    let (cert, holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    let (child, _delegatee_key) = cert
        .mint_child(
            &PermissionLattice::restrictive(),
            "spiffe://test/agent/coder".into(),
            not_after,
            "spawn coder agent",
            &holder_key,
            &rng,
        )
        .expect("a well-formed request within budget/depth must mint");

    assert_eq!(child.chain_depth(), 1);
    assert_eq!(child.leaf_identity(), "spiffe://test/agent/coder");
}

/// The load-bearing case: `delegate`/`delegate_with_scope` alone would
/// silently CLAMP a request for more budget than the parent has
/// remaining — the plain lattice meet just narrows, it never rejects.
/// `mint_child` must refuse instead, via `PermissionLattice::delegate_to`.
#[test]
fn mint_child_rejects_budget_exceeding_parent() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let not_after = Utc::now() + Duration::hours(8);

    let mut parent_perms = PermissionLattice::restrictive();
    parent_perms.budget.max_cost_usd = rust_decimal::Decimal::from(1);
    let (cert, holder_key) = LatticeCertificate::mint(
        parent_perms,
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    let mut over_budget = PermissionLattice::restrictive();
    over_budget.budget.max_cost_usd = rust_decimal::Decimal::from(1_000);

    let result = cert.mint_child(
        &over_budget,
        "spiffe://test/agent/coder".into(),
        not_after,
        "spawn coder agent",
        &holder_key,
        &rng,
    );

    assert!(
        matches!(
            result,
            Err(CertificateMintChildError::Lattice(
                crate::DelegationError::InsufficientBudget { .. }
            ))
        ),
        "expected InsufficientBudget, got {result:?}"
    );

    // Non-vacuity: `delegate` (the primitive `mint_child` wraps for the
    // chain-level half) does NOT reject this — it silently clamps. If it
    // also rejected, this test wouldn't be distinguishing mint_child's
    // added check from the pre-existing one.
    let plain_delegate_result = cert.delegate(
        &over_budget,
        "spiffe://test/agent/coder".into(),
        not_after,
        &holder_key,
        &rng,
    );
    assert!(
        plain_delegate_result.is_ok(),
        "the pre-existing gap: delegate() must still silently clamp, not reject — \
         otherwise this test no longer demonstrates what mint_child adds"
    );
}

/// The other half of the lattice-level check: an already-expired parent
/// lattice. Distinct from `test_expired_authority_rejected` (which tests
/// the certificate's own `not_after`, checked at *verification* time) —
/// this is the lattice's own `TimeLattice`, checked at *mint* time.
#[test]
fn mint_child_rejects_expired_parent_lattice() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let not_after = Utc::now() + Duration::hours(8);

    let mut parent_perms = PermissionLattice::permissive();
    parent_perms.time = crate::TimeLattice::between(
        Utc::now() - Duration::hours(2),
        Utc::now() - Duration::hours(1),
    );
    let (cert, holder_key) = LatticeCertificate::mint(
        parent_perms,
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    let result = cert.mint_child(
        &PermissionLattice::restrictive(),
        "spiffe://test/agent/coder".into(),
        not_after,
        "spawn coder agent",
        &holder_key,
        &rng,
    );

    assert!(
        matches!(
            result,
            Err(CertificateMintChildError::Lattice(
                crate::DelegationError::ParentExpired
            ))
        ),
        "expected ParentExpired, got {result:?}"
    );
}

/// Depth-exceeded: `mint_child` must surface the SAME `ChainTooDeep`
/// the chain-level check already gives `delegate`/`delegate_with_scope`
/// — the lattice-level check ahead of it must not shadow this one.
#[test]
fn mint_child_rejects_depth_exceeded() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let not_after = Utc::now() + Duration::hours(8);
    let (mut cert, mut holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    // Walk the chain to exactly DEFAULT_MAX_CHAIN_DEPTH.
    for i in 0..DEFAULT_MAX_CHAIN_DEPTH {
        let (next_cert, next_key) = cert
            .mint_child(
                &PermissionLattice::permissive(),
                format!("spiffe://test/agent/hop-{i}"),
                not_after,
                "hop",
                &holder_key,
                &rng,
            )
            .expect("within depth so far");
        cert = next_cert;
        holder_key = next_key;
    }
    assert_eq!(cert.chain_depth(), DEFAULT_MAX_CHAIN_DEPTH);

    // One more must be refused as ChainTooDeep, not silently minted.
    let result = cert.mint_child(
        &PermissionLattice::permissive(),
        "spiffe://test/agent/one-too-many".into(),
        not_after,
        "hop",
        &holder_key,
        &rng,
    );
    assert!(
        matches!(
            result,
            Err(CertificateMintChildError::Chain(
                CertificateDelegationError::ChainTooDeep { .. }
            ))
        ),
        "expected ChainTooDeep, got {result:?}"
    );
}

/// #2451 parity: the Aeneas-extracted walk (`portcullis_core::certchain::
/// chain_attenuates`, proven monotone in `CertChainMonotoneExtracted.lean`)
/// agrees with `verify_certificate`'s step 4c on REAL, fully signed
/// certificates — on an honest two-hop chain, and on a chain whose second
/// hop is validly signed by its parent but WIDENS its permissions (built by
/// hand: `delegate` refuses to mint one). Everything else in the walk
/// (signatures, hash linkage, expiry, proof of possession) holds, so the
/// monotone check is the only thing deciding.
#[test]
fn chain_attenuates_agrees_with_verify_certificate() {
    use portcullis_core::certchain::chain_attenuates;

    let rng = test_rng();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + Duration::hours(8);
    let root_perms = PermissionLattice::permissive();

    let (cert, holder) = LatticeCertificate::mint(
        root_perms.clone(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );
    let (cert, child) = cert
        .delegate(
            &PermissionLattice::restrictive(),
            "spiffe://test/agent/a".into(),
            not_after,
            &holder,
            &rng,
        )
        .unwrap();

    // Honest: both accept.
    let effective: Vec<PermissionLattice> = cert
        .blocks
        .iter()
        .map(|b| b.effective_permissions.clone())
        .collect();
    assert!(verify_certificate(&cert, &root_pub, Utc::now(), 10).is_ok());
    assert!(chain_attenuates(&root_perms, &effective));

    // A second hop, correctly signed by the first hop's holder, that
    // claims MORE than its parent: permissive under a restrictive parent.
    let grandchild = generate_key(&rng);
    let parent = cert.blocks.last().unwrap();
    let (_, justification) = meet_with_justification(
        &parent.effective_permissions,
        &PermissionLattice::permissive(),
    );
    let mut widened = DelegationBlock {
        effective_permissions: PermissionLattice::permissive(),
        justification,
        from_identity: parent.to_identity.clone(),
        to_identity: "spiffe://test/agent/b".into(),
        not_after,
        sink_scope: SinkScope::unrestricted(),
        prev_block_hash: parent.block_hash(),
        signature: Vec::new(),
        next_key: grandchild.public_key().as_ref().to_vec(),
    };
    widened.signature = child.sign(&widened.signing_payload()).as_ref().to_vec();
    let pop = LatticeCertificate::pop_payload_for_block_hash(&widened.block_hash());
    let mut blocks = cert.blocks.clone();
    blocks.push(widened);
    let escalated = LatticeCertificate {
        authority: cert.authority.clone(),
        blocks,
        final_signature: grandchild.sign(&pop).as_ref().to_vec(),
    };

    let effective: Vec<PermissionLattice> = escalated
        .blocks
        .iter()
        .map(|b| b.effective_permissions.clone())
        .collect();
    assert!(
        matches!(
            verify_certificate(&escalated, &root_pub, Utc::now(), 10),
            Err(CertificateError::MonotoneViolation { block_index: 2 })
        ),
        "the production walk refuses the widened hop for the monotone reason and no other"
    );
    assert!(
        !chain_attenuates(&root_perms, &effective),
        "the extracted walk refuses the same chain"
    );
}

/// #2474 regression: a validly signed child block whose paths and commands
/// are UNRESTRICTED (empty allow sets) under a parent restricted to
/// `src/**` / `cargo test` used to pass the monotone check, because an
/// empty set is vacuously a subset of anything. `verify_certificate` must
/// refuse it as `MonotoneViolation`, and an honest narrower child must
/// still verify.
#[test]
fn a_child_claiming_unrestricted_paths_or_commands_is_refused() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + Duration::hours(8);

    let mut root_perms = PermissionLattice::permissive();
    root_perms.paths.allowed = ["src/**".to_string()].into_iter().collect();
    root_perms.commands.allowed = ["cargo test".to_string()].into_iter().collect();
    let (cert, holder) = LatticeCertificate::mint(
        root_perms.clone(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );
    assert!(verify_certificate(&cert, &root_pub, Utc::now(), 10).is_ok());

    // The escalation: unrestricted paths + commands, signed by the holder.
    let mut widened = PermissionLattice::permissive();
    widened.paths.allowed.clear();
    widened.commands.allowed.clear();
    widened.commands.allowed_rules.clear();
    let child_key = generate_key(&rng);
    let (_, justification) = meet_with_justification(&root_perms, &widened);
    let mut block = DelegationBlock {
        effective_permissions: widened,
        justification,
        from_identity: cert.authority.root_identity.clone(),
        to_identity: "spiffe://test/agent/a".into(),
        not_after,
        sink_scope: SinkScope::unrestricted(),
        prev_block_hash: cert.authority.block_hash(),
        signature: Vec::new(),
        next_key: child_key.public_key().as_ref().to_vec(),
    };
    block.signature = holder.sign(&block.signing_payload()).as_ref().to_vec();
    let pop = LatticeCertificate::pop_payload_for_block_hash(&block.block_hash());
    let escalated = LatticeCertificate {
        authority: cert.authority.clone(),
        blocks: vec![block],
        final_signature: child_key.sign(&pop).as_ref().to_vec(),
    };
    assert!(
        matches!(
            verify_certificate(&escalated, &root_pub, Utc::now(), 10),
            Err(CertificateError::MonotoneViolation { block_index: 1 })
        ),
        "an unrestricted child under a restricted parent is a widening"
    );

    // The control: an honest narrower child still verifies.
    let mut narrower = root_perms.clone();
    narrower.paths.allowed = ["src/lib.rs".to_string()].into_iter().collect();
    let (child, _) = cert
        .delegate(
            &narrower,
            "spiffe://test/agent/b".into(),
            not_after,
            &holder,
            &rng,
        )
        .unwrap();
    assert!(verify_certificate(&child, &root_pub, Utc::now(), 10).is_ok());
}
