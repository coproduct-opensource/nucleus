//! Property-based and scenario tests for attested delegation certificates.
//!
//! These tests verify that `LatticeCertificate` correctly implements the
//! Biscuit-style Ed25519 signed block chain for lattice-based permissions.

use chrono::{Duration, Utc};
use portcullis::{
    certificate::{verify_certificate, LatticeCertificate},
    CapabilityLevel, PermissionLattice,
};
use proptest::prelude::*;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

fn test_rng() -> SystemRandom {
    SystemRandom::new()
}

fn generate_key(rng: &dyn ring::rand::SecureRandom) -> Ed25519KeyPair {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(rng).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

// Strategy for generating arbitrary CapabilityLevel
fn arb_capability_level() -> impl Strategy<Value = CapabilityLevel> {
    prop_oneof![
        Just(CapabilityLevel::Never),
        Just(CapabilityLevel::LowRisk),
        Just(CapabilityLevel::Always),
    ]
}

// Strategy for generating arbitrary CapabilityLattice
fn arb_capability_lattice() -> impl Strategy<Value = portcullis::CapabilityLattice> {
    (
        (
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
        ),
        arb_capability_level(),
    )
        .prop_map(
            |(
                (
                    read_files,
                    write_files,
                    edit_files,
                    run_bash,
                    glob_search,
                    grep_search,
                    web_search,
                    web_fetch,
                    git_commit,
                    git_push,
                    create_pr,
                    manage_pods,
                ),
                spawn_agent,
            )| {
                portcullis::CapabilityLattice {
                    read_files,
                    write_files,
                    edit_files,
                    run_bash,
                    glob_search,
                    grep_search,
                    web_search,
                    web_fetch,
                    git_commit,
                    git_push,
                    create_pr,
                    manage_pods,
                    spawn_agent,
                    extensions: std::collections::BTreeMap::new(),
                }
            },
        )
}

/// Build a PermissionLattice from arbitrary capabilities.
fn perms_from_caps(caps: portcullis::CapabilityLattice) -> PermissionLattice {
    PermissionLattice {
        capabilities: caps,
        ..Default::default()
    }
    .normalize()
}

// ═══════════════════════════════════════════════════════════════════════════
// PROPERTY TESTS
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    /// Any valid single-hop delegation produces a certificate that verifies.
    #[test]
    fn prop_any_valid_delegation_verifies(
        root_caps in arb_capability_lattice(),
        requested_caps in arb_capability_lattice(),
    ) {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let root_perms = perms_from_caps(root_caps);
        let (cert, holder_key) = LatticeCertificate::mint(
            root_perms,
            "spiffe://test/root".into(),
            not_after,
            &root_key,
            &rng,
        );

        let requested = perms_from_caps(requested_caps);
        let (cert, _delegatee_key) = cert
            .delegate(
                &requested,
                "spiffe://test/agent".into(),
                not_after,
                &holder_key,
                &rng,
            )
            .unwrap();

        let verified = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();
        prop_assert_eq!(verified.chain_depth, 1);
    }

    /// After delegation, effective_permissions.leq(parent_permissions) always holds.
    #[test]
    fn prop_monotone_attenuation_holds(
        root_caps in arb_capability_lattice(),
        requested_caps in arb_capability_lattice(),
    ) {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let not_after = Utc::now() + Duration::hours(8);

        let root_perms = perms_from_caps(root_caps);
        let (cert, holder_key) = LatticeCertificate::mint(
            root_perms.clone(),
            "spiffe://test/root".into(),
            not_after,
            &root_key,
            &rng,
        );

        let requested = perms_from_caps(requested_caps);
        let (cert, _key) = cert
            .delegate(
                &requested,
                "spiffe://test/agent".into(),
                not_after,
                &holder_key,
                &rng,
            )
            .unwrap();

        // The delegation ceiling theorem: effective ≤ root
        prop_assert!(
            cert.effective_permissions().leq(&root_perms),
            "Monotone violation: effective permissions exceed root!"
        );
    }

    /// Two-hop chains always verify and maintain transitivity.
    #[test]
    fn prop_two_hop_chain_transitive(
        root_caps in arb_capability_lattice(),
        req_a in arb_capability_lattice(),
        req_b in arb_capability_lattice(),
    ) {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let root_perms = perms_from_caps(root_caps);
        let (cert, key_a) = LatticeCertificate::mint(
            root_perms.clone(),
            "spiffe://test/root".into(),
            not_after,
            &root_key,
            &rng,
        );

        let (cert, key_b) = cert
            .delegate(
                &perms_from_caps(req_a),
                "spiffe://test/agent-a".into(),
                not_after,
                &key_a,
                &rng,
            )
            .unwrap();

        let mid_perms = cert.effective_permissions().clone();

        let (cert, _key_c) = cert
            .delegate(
                &perms_from_caps(req_b),
                "spiffe://test/agent-b".into(),
                not_after,
                &key_b,
                &rng,
            )
            .unwrap();

        // Verify the full chain
        let verified = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();
        prop_assert_eq!(verified.chain_depth, 2);

        // Transitivity: leaf ≤ mid ≤ root
        prop_assert!(verified.effective.leq(&mid_perms));
        prop_assert!(mid_perms.leq(&root_perms));
        prop_assert!(verified.effective.leq(&root_perms));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO: PAJAMAS ATTACK WITH CERTIFICATES
// ═══════════════════════════════════════════════════════════════════════════

/// Replicate the "pajamas attack" scenario: an orchestrator tries to give
/// a sub-agent write+push permissions when it only has read permissions.
/// The certificate system must prevent this via the monotone check.
#[test]
fn test_pajamas_attack_blocked_by_certificate() {
    let rng = test_rng();
    let root_key = generate_key(&rng);
    let root_pub = root_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + Duration::hours(8);

    // Human Alice grants orchestrator read-only permissions
    let mut alice_grant = PermissionLattice::read_only();
    alice_grant.capabilities.web_search = CapabilityLevel::Always;
    alice_grant = alice_grant.normalize();

    let (cert, orch_key) = LatticeCertificate::mint(
        alice_grant,
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    let (cert, coder_key) = cert
        .delegate(
            &PermissionLattice::read_only(),
            "spiffe://test/agent/orch-001".into(),
            not_after,
            &orch_key,
            &rng,
        )
        .unwrap();

    // Now orchestrator delegates to coder, requesting write+push
    let mut attack_request = PermissionLattice::permissive();
    attack_request.capabilities.write_files = CapabilityLevel::Always;
    attack_request.capabilities.git_push = CapabilityLevel::Always;

    let (cert, _key) = cert
        .delegate(
            &attack_request,
            "spiffe://test/agent/coder-042".into(),
            not_after,
            &coder_key,
            &rng,
        )
        .unwrap();

    // The certificate DOES verify (the meet correctly attenuates)
    let verified = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();

    // But the coder's effective permissions can't exceed the orchestrator's ceiling
    // Specifically: write_files and git_push should be Never (inherited from read_only)
    assert_eq!(
        verified.effective.capabilities.write_files,
        CapabilityLevel::Never
    );
    assert_eq!(
        verified.effective.capabilities.git_push,
        CapabilityLevel::Never
    );
}

/// Test that a certificate signed by root A cannot be verified with root B's key.
/// This ensures cross-chain isolation — certificates from different trust roots
/// are cryptographically separated.
#[test]
fn test_cross_chain_isolation() {
    let rng = test_rng();
    let root_key_a = generate_key(&rng);
    let root_key_b = generate_key(&rng);
    let not_after = Utc::now() + Duration::hours(8);

    // Chain A: signed by root_key_a
    let (cert_a, key_a) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/root-a".into(),
        not_after,
        &root_key_a,
        &rng,
    );

    let (cert_a, _) = cert_a
        .delegate(
            &PermissionLattice::restrictive(),
            "spiffe://test/agent-a".into(),
            not_after,
            &key_a,
            &rng,
        )
        .unwrap();

    // Verifying chain A with root_key_b must fail
    let result = verify_certificate(&cert_a, root_key_b.public_key().as_ref(), Utc::now(), 10);
    assert!(
        result.is_err(),
        "Certificate from root A must not verify with root B's key"
    );

    // Verifying chain A with root_key_a must succeed
    let result = verify_certificate(&cert_a, root_key_a.public_key().as_ref(), Utc::now(), 10);
    assert!(result.is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════
// SERDE ROUNDTRIP
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "serde")]
proptest! {
    /// Certificate survives JSON serialization → deserialization → verification.
    #[test]
    fn prop_certificate_roundtrips_serde(
        root_caps in arb_capability_lattice(),
        requested_caps in arb_capability_lattice(),
    ) {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let (cert, holder_key) = LatticeCertificate::mint(
            perms_from_caps(root_caps),
            "spiffe://test/root".into(),
            not_after,
            &root_key,
            &rng,
        );

        let (cert, _key) = cert
            .delegate(
                &perms_from_caps(requested_caps),
                "spiffe://test/agent".into(),
                not_after,
                &holder_key,
                &rng,
            )
            .unwrap();

        // Roundtrip through JSON
        let bytes = cert.to_bytes().unwrap();
        let restored = LatticeCertificate::from_bytes(&bytes).unwrap();

        // Must still verify
        let verified = verify_certificate(&restored, &root_pub, Utc::now(), 10).unwrap();
        prop_assert_eq!(verified.chain_depth, 1);
    }
}
