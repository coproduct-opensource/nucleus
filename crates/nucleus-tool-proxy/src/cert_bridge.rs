//! Galois bridge between portcullis delegation certificates and
//! nucleus-permission-market Lagrangian pricing.
//!
//! # Mathematical Structure
//!
//! The abstraction function α: PermissionLattice → P(PermissionDimension)
//! collapses 12 capability dimensions into 4 market dimensions via surjection.
//!
//! The concretization function γ: P(PermissionDimension) → PermissionLattice
//! produces the maximal lattice element mapping to a given dimension set.
//!
//! The Galois adjunction: α(L) ⊆ S ⟺ L ≤ γ(S)
//!
//! # Dimension Mapping
//!
//! | Market Dimension | Capability Fields |
//! |------------------|-------------------|
//! | Filesystem | read_files, write_files, edit_files, glob_search, grep_search |
//! | CommandExec | run_bash |
//! | NetworkEgress | web_search, web_fetch, git_push, create_pr |
//! | Approval | obligations.approvals (non-empty) |
//!
//! `git_commit` and `manage_pods` are **pass-through**: no market dimension
//! gates them; they survive from the certificate unchanged.

use chrono::{Duration, Utc};
use nucleus_permission_market::{PermissionBid, PermissionDimension, PermissionGrant, TrustTier};
use portcullis::{
    certificate::VerifiedPermissions, BudgetLattice, CapabilityLattice, CapabilityLevel,
    PermissionLattice, TimeLattice,
};
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use std::collections::HashSet;

// ═══════════════════════════════════════════════════════════════════════════
// α: ABSTRACTION (12-dim → 4-dim)
// ═══════════════════════════════════════════════════════════════════════════

/// Convert verified delegation certificate permissions into a market bid.
///
/// This is the abstraction function (α) of the Galois connection between
/// the 12-dimensional capability lattice and the 4-dimensional market space.
///
/// A dimension is included in the bid if ANY constituent capability is non-Never.
pub fn certificate_to_bid(verified: &VerifiedPermissions) -> PermissionBid {
    let caps = &verified.effective.capabilities;
    let mut requested = Vec::new();

    // Filesystem: read_files, write_files, edit_files, glob_search, grep_search
    if caps.read_files > CapabilityLevel::Never
        || caps.write_files > CapabilityLevel::Never
        || caps.edit_files > CapabilityLevel::Never
        || caps.glob_search > CapabilityLevel::Never
        || caps.grep_search > CapabilityLevel::Never
    {
        requested.push(PermissionDimension::Filesystem);
    }

    // CommandExec: run_bash
    if caps.run_bash > CapabilityLevel::Never {
        requested.push(PermissionDimension::CommandExec);
    }

    // NetworkEgress: web_search, web_fetch, git_push, create_pr
    if caps.web_search > CapabilityLevel::Never
        || caps.web_fetch > CapabilityLevel::Never
        || caps.git_push > CapabilityLevel::Never
        || caps.create_pr > CapabilityLevel::Never
    {
        requested.push(PermissionDimension::NetworkEgress);
    }

    // Approval: meta-dimension, present if there are obligations
    if !verified.effective.obligations.is_empty() {
        requested.push(PermissionDimension::Approval);
    }

    let trust_tier = chain_depth_to_trust_tier(verified.chain_depth);

    let value_estimate = verified
        .effective
        .budget
        .max_cost_usd
        .to_f64()
        .unwrap_or(0.0);

    PermissionBid {
        skill_id: verified.leaf_identity.clone(),
        requested,
        value_estimate,
        trust_tier,
    }
}

/// Map delegation chain depth to market trust tier.
///
/// - Depth 0: root authority itself → Platform (90% discount)
/// - Depth 1: direct delegate → Verified (50% discount)
/// - Depth 2+: transitive delegate → Community (20% discount)
pub fn chain_depth_to_trust_tier(depth: usize) -> TrustTier {
    match depth {
        0 => TrustTier::Platform,
        1 => TrustTier::Verified,
        _ => TrustTier::Community,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// γ: CONCRETIZATION (4-dim → 12-dim)
// ═══════════════════════════════════════════════════════════════════════════

/// Produce a `CapabilityLattice` where all 12 dimensions are `Never`.
///
/// Neither `Default` nor `restrictive()` is all-Never — both include
/// `read_files`, `glob_search`, `grep_search` at `Always`. This function
/// provides the true bottom of the capability lattice.
fn all_never_capabilities() -> CapabilityLattice {
    CapabilityLattice {
        read_files: CapabilityLevel::Never,
        write_files: CapabilityLevel::Never,
        edit_files: CapabilityLevel::Never,
        run_bash: CapabilityLevel::Never,
        glob_search: CapabilityLevel::Never,
        grep_search: CapabilityLevel::Never,
        web_search: CapabilityLevel::Never,
        web_fetch: CapabilityLevel::Never,
        git_commit: CapabilityLevel::Never,
        git_push: CapabilityLevel::Never,
        create_pr: CapabilityLevel::Never,
        manage_pods: CapabilityLevel::Never,
        extensions: std::collections::BTreeMap::new(),
    }
}

/// Produce the maximal `PermissionLattice` whose α-image is contained in
/// the given dimension set.
///
/// For dimensions in the set, all constituent capabilities are `Always`.
/// For dimensions NOT in the set, all constituent capabilities are `Never`.
/// Pass-through capabilities (`git_commit`, `manage_pods`) are `Always`
/// since no market dimension constrains them.
pub fn dimensions_to_ceiling(dimensions: &[PermissionDimension]) -> PermissionLattice {
    let dim_set: HashSet<PermissionDimension> = dimensions.iter().copied().collect();
    let mut caps = all_never_capabilities();

    if dim_set.contains(&PermissionDimension::Filesystem) {
        caps.read_files = CapabilityLevel::Always;
        caps.write_files = CapabilityLevel::Always;
        caps.edit_files = CapabilityLevel::Always;
        caps.glob_search = CapabilityLevel::Always;
        caps.grep_search = CapabilityLevel::Always;
    }

    if dim_set.contains(&PermissionDimension::CommandExec) {
        caps.run_bash = CapabilityLevel::Always;
    }

    if dim_set.contains(&PermissionDimension::NetworkEgress) {
        caps.web_search = CapabilityLevel::Always;
        caps.web_fetch = CapabilityLevel::Always;
        caps.git_push = CapabilityLevel::Always;
        caps.create_pr = CapabilityLevel::Always;
    }

    // Pass-through: git_commit and manage_pods are not market-gated.
    // Set to Always so they survive the meet with the certificate.
    caps.git_commit = CapabilityLevel::Always;
    caps.manage_pods = CapabilityLevel::Always;

    // Build a true top element for non-capability dimensions.
    // We construct this explicitly (NOT from default() or permissive()) because:
    // - default() adds obligations via normalize() that break Galois closure-extensive
    // - default() adds non-empty CommandLattice::allowed that breaks commands.leq()
    // - permissive() creates a time window from Utc::now() (non-deterministic)
    // The uninhabitable_state enforcement happens in the meet() with the certificate.
    // Build a delegation ceiling — a true top element without normalization.
    // Normalization adds obligations that break the Galois closure-extensive
    // property. Use build_unnormalized() + uninhabitable_constraint(false).
    PermissionLattice::builder()
        .description("market-grant-ceiling")
        .capabilities(caps)
        .budget(BudgetLattice {
            max_cost_usd: Decimal::from(1_000_000),
            max_input_tokens: u64::MAX,
            max_output_tokens: u64::MAX,
            ..Default::default()
        })
        .time(TimeLattice::between(
            Utc::now() - Duration::days(365 * 100),
            Utc::now() + Duration::days(365 * 100),
        ))
        .uninhabitable_constraint(false)
        .build_unnormalized()
}

/// Intersect a market grant with certificate-attested permissions.
///
/// The effective permissions are `verified.effective ∧ ceiling(granted)`,
/// using the lattice meet operation. This preserves all invariants
/// (uninhabitable_state enforcement, obligations, paths, budget, commands, time)
/// and is provably correct: meet is monotone and deflationary.
///
/// # Security Invariant
///
/// The result is always ≤ `verified.effective` AND ≤ `ceiling(granted)`.
pub fn intersect_grant_with_certificate(
    grant: &PermissionGrant,
    verified: &VerifiedPermissions,
) -> PermissionLattice {
    let ceiling = dimensions_to_ceiling(&grant.granted);
    verified.effective.meet(&ceiling)
}

/// Extract the set of market dimensions from a `PermissionLattice`.
///
/// This is α applied to an arbitrary lattice element (not just VerifiedPermissions).
/// Useful for testing the Galois properties.
#[cfg(test)]
fn lattice_to_dimensions(perms: &PermissionLattice) -> HashSet<PermissionDimension> {
    let caps = &perms.capabilities;
    let mut dims = HashSet::new();

    if caps.read_files > CapabilityLevel::Never
        || caps.write_files > CapabilityLevel::Never
        || caps.edit_files > CapabilityLevel::Never
        || caps.glob_search > CapabilityLevel::Never
        || caps.grep_search > CapabilityLevel::Never
    {
        dims.insert(PermissionDimension::Filesystem);
    }

    if caps.run_bash > CapabilityLevel::Never {
        dims.insert(PermissionDimension::CommandExec);
    }

    if caps.web_search > CapabilityLevel::Never
        || caps.web_fetch > CapabilityLevel::Never
        || caps.git_push > CapabilityLevel::Never
        || caps.create_pr > CapabilityLevel::Never
    {
        dims.insert(PermissionDimension::NetworkEgress);
    }

    if !perms.obligations.is_empty() {
        dims.insert(PermissionDimension::Approval);
    }

    dims
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use nucleus_permission_market::PermissionMarket;
    use portcullis::certificate::{verify_certificate, LatticeCertificate};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn test_rng() -> SystemRandom {
        SystemRandom::new()
    }

    fn generate_key(rng: &dyn ring::rand::SecureRandom) -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    /// Helper: mint a certificate and verify it, returning VerifiedPermissions.
    fn mint_and_verify(perms: PermissionLattice) -> VerifiedPermissions {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let (cert, _holder_key) = LatticeCertificate::mint(
            perms,
            "spiffe://test/root".into(),
            not_after,
            &root_key,
            &rng,
        );

        verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap()
    }

    /// Helper: mint + delegate, returning verified permissions at depth 1.
    fn mint_delegate_and_verify(
        root_perms: PermissionLattice,
        requested: PermissionLattice,
    ) -> VerifiedPermissions {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let (cert, holder_key) = LatticeCertificate::mint(
            root_perms,
            "spiffe://test/root".into(),
            not_after,
            &root_key,
            &rng,
        );

        let (cert, _delegatee_key) = cert
            .delegate(
                &requested,
                "spiffe://test/agent".into(),
                not_after,
                &holder_key,
                &rng,
            )
            .unwrap();

        verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // α FUNCTION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_alpha_permissive_requests_all_non_approval_dimensions() {
        let verified = mint_and_verify(PermissionLattice::permissive());
        let bid = certificate_to_bid(&verified);

        assert!(bid.requested.contains(&PermissionDimension::Filesystem));
        assert!(bid.requested.contains(&PermissionDimension::CommandExec));
        assert!(bid.requested.contains(&PermissionDimension::NetworkEgress));
        // Approval depends on whether permissive() has obligations
        assert_eq!(bid.skill_id, "spiffe://test/root");
        assert_eq!(bid.trust_tier, TrustTier::Platform); // depth 0
    }

    #[test]
    fn test_alpha_read_only_requests_only_filesystem() {
        let verified = mint_and_verify(PermissionLattice::read_only());
        let bid = certificate_to_bid(&verified);

        assert!(bid.requested.contains(&PermissionDimension::Filesystem));
        assert!(!bid.requested.contains(&PermissionDimension::CommandExec));
        assert!(!bid.requested.contains(&PermissionDimension::NetworkEgress));
    }

    #[test]
    fn test_alpha_all_never_requests_nothing() {
        let perms = PermissionLattice::builder()
            .capabilities(all_never_capabilities())
            .build();
        let verified = mint_and_verify(perms);
        let bid = certificate_to_bid(&verified);

        // No market dimensions requested (possibly Approval if normalize adds obligations)
        assert!(!bid.requested.contains(&PermissionDimension::Filesystem));
        assert!(!bid.requested.contains(&PermissionDimension::CommandExec));
        assert!(!bid.requested.contains(&PermissionDimension::NetworkEgress));
    }

    #[test]
    fn test_chain_depth_trust_mapping() {
        assert_eq!(chain_depth_to_trust_tier(0), TrustTier::Platform);
        assert_eq!(chain_depth_to_trust_tier(1), TrustTier::Verified);
        assert_eq!(chain_depth_to_trust_tier(2), TrustTier::Community);
        assert_eq!(chain_depth_to_trust_tier(5), TrustTier::Community);
        assert_eq!(chain_depth_to_trust_tier(10), TrustTier::Community);
    }

    #[test]
    fn test_delegated_cert_gets_verified_trust() {
        let verified = mint_delegate_and_verify(
            PermissionLattice::permissive(),
            PermissionLattice::read_only(),
        );
        let bid = certificate_to_bid(&verified);

        assert_eq!(bid.trust_tier, TrustTier::Verified); // depth 1
        assert_eq!(bid.skill_id, "spiffe://test/agent");
    }

    #[test]
    fn test_value_estimate_from_budget() {
        let verified = mint_and_verify(PermissionLattice::permissive());
        let bid = certificate_to_bid(&verified);

        // permissive() has max_cost_usd = 100.0
        assert!(bid.value_estimate > 0.0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // γ FUNCTION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_gamma_filesystem_only_ceiling() {
        let ceiling = dimensions_to_ceiling(&[PermissionDimension::Filesystem]);

        assert_eq!(ceiling.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(ceiling.capabilities.write_files, CapabilityLevel::Always);
        assert_eq!(ceiling.capabilities.edit_files, CapabilityLevel::Always);
        assert_eq!(ceiling.capabilities.glob_search, CapabilityLevel::Always);
        assert_eq!(ceiling.capabilities.grep_search, CapabilityLevel::Always);

        // Non-filesystem dimensions should be Never
        assert_eq!(ceiling.capabilities.run_bash, CapabilityLevel::Never);
        assert_eq!(ceiling.capabilities.web_search, CapabilityLevel::Never);
        assert_eq!(ceiling.capabilities.web_fetch, CapabilityLevel::Never);
        assert_eq!(ceiling.capabilities.git_push, CapabilityLevel::Never);
        assert_eq!(ceiling.capabilities.create_pr, CapabilityLevel::Never);

        // Pass-through should be Always
        assert_eq!(ceiling.capabilities.git_commit, CapabilityLevel::Always);
        assert_eq!(ceiling.capabilities.manage_pods, CapabilityLevel::Always);
    }

    #[test]
    fn test_gamma_all_dimensions_ceiling() {
        let ceiling = dimensions_to_ceiling(&[
            PermissionDimension::Filesystem,
            PermissionDimension::CommandExec,
            PermissionDimension::NetworkEgress,
            PermissionDimension::Approval,
        ]);

        // All capabilities should be Always
        assert_eq!(ceiling.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(ceiling.capabilities.run_bash, CapabilityLevel::Always);
        assert_eq!(ceiling.capabilities.web_search, CapabilityLevel::Always);
        assert_eq!(ceiling.capabilities.git_push, CapabilityLevel::Always);
    }

    #[test]
    fn test_gamma_empty_dimensions_only_passthrough() {
        let ceiling = dimensions_to_ceiling(&[]);

        assert_eq!(ceiling.capabilities.read_files, CapabilityLevel::Never);
        assert_eq!(ceiling.capabilities.run_bash, CapabilityLevel::Never);
        assert_eq!(ceiling.capabilities.web_search, CapabilityLevel::Never);
        // Pass-through survives
        assert_eq!(ceiling.capabilities.git_commit, CapabilityLevel::Always);
        assert_eq!(ceiling.capabilities.manage_pods, CapabilityLevel::Always);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // INTERSECTION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_intersection_denies_network_zeroes_egress_caps() {
        let verified = mint_and_verify(PermissionLattice::permissive());

        // Market grants only Filesystem
        let grant = PermissionGrant {
            granted: vec![PermissionDimension::Filesystem],
            denied: vec![],
            total_cost: 0.0,
            expires_at: None,
        };

        let effective = intersect_grant_with_certificate(&grant, &verified);

        // Filesystem survives
        assert!(effective.capabilities.read_files > CapabilityLevel::Never);
        // Network zeroed
        assert_eq!(effective.capabilities.web_search, CapabilityLevel::Never);
        assert_eq!(effective.capabilities.web_fetch, CapabilityLevel::Never);
        assert_eq!(effective.capabilities.git_push, CapabilityLevel::Never);
        assert_eq!(effective.capabilities.create_pr, CapabilityLevel::Never);
        // CommandExec zeroed
        assert_eq!(effective.capabilities.run_bash, CapabilityLevel::Never);
        // Pass-through survives
        assert!(effective.capabilities.git_commit > CapabilityLevel::Never);
    }

    #[test]
    fn test_intersection_preserves_certificate_attenuation() {
        // Certificate only has read_only permissions
        let verified = mint_and_verify(PermissionLattice::read_only());

        // Market grants everything
        let grant = PermissionGrant {
            granted: vec![
                PermissionDimension::Filesystem,
                PermissionDimension::CommandExec,
                PermissionDimension::NetworkEgress,
                PermissionDimension::Approval,
            ],
            denied: vec![],
            total_cost: 0.0,
            expires_at: None,
        };

        let effective = intersect_grant_with_certificate(&grant, &verified);

        // Certificate had read_only: write_files should still be Never
        assert_eq!(effective.capabilities.write_files, CapabilityLevel::Never);
        assert_eq!(effective.capabilities.edit_files, CapabilityLevel::Never);
        assert_eq!(effective.capabilities.run_bash, CapabilityLevel::Never);
        // But read_files should survive
        assert!(effective.capabilities.read_files > CapabilityLevel::Never);
    }

    #[test]
    fn test_passthrough_caps_survive_intersection() {
        let mut perms = PermissionLattice::default();
        perms.capabilities.git_commit = CapabilityLevel::Always;
        perms.capabilities.manage_pods = CapabilityLevel::LowRisk;
        perms = perms.normalize();
        let verified = mint_and_verify(perms);

        // Market grants nothing
        let grant = PermissionGrant {
            granted: vec![],
            denied: vec![],
            total_cost: 0.0,
            expires_at: None,
        };

        let effective = intersect_grant_with_certificate(&grant, &verified);

        // Pass-through capabilities survive even with empty grant
        assert!(effective.capabilities.git_commit > CapabilityLevel::Never);
        assert!(effective.capabilities.manage_pods > CapabilityLevel::Never);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FULL FLOW: CERTIFICATE → MARKET → ENFORCEMENT
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_full_flow_certificate_to_market_to_enforcement() {
        use std::collections::BTreeMap;

        // Step 1: Mint a certificate with permissive capabilities
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let (cert, holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://nucleus/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        // Step 2: Delegate to a sub-agent with read_only request
        let (cert, _agent_key) = cert
            .delegate(
                &PermissionLattice::read_only(),
                "spiffe://nucleus/agent/coder-042".into(),
                not_after,
                &holder_key,
                &rng,
            )
            .unwrap();

        // Step 3: Verify the certificate
        let verified = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();
        assert_eq!(verified.chain_depth, 1);
        assert_eq!(verified.leaf_identity, "spiffe://nucleus/agent/coder-042");

        // Step 4: Convert to market bid (α)
        let bid = certificate_to_bid(&verified);
        assert_eq!(bid.skill_id, "spiffe://nucleus/agent/coder-042");
        assert_eq!(bid.trust_tier, TrustTier::Verified); // depth 1
        assert!(bid.requested.contains(&PermissionDimension::Filesystem));
        assert!(!bid.requested.contains(&PermissionDimension::CommandExec));

        // Step 5: Evaluate against market with high filesystem utilization
        let mut utilizations = BTreeMap::new();
        utilizations.insert(PermissionDimension::Filesystem, 0.9); // λ high
        let market = PermissionMarket::with_utilization(utilizations);
        let grant = market.evaluate_bid(&bid);

        // Step 6: Intersect grant with certificate (γ)
        let effective = intersect_grant_with_certificate(&grant, &verified);

        // Step 7: Verify the result is bounded by both certificate and grant
        assert!(effective.leq(&verified.effective));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GALOIS PROPERTY TESTS
    // ═══════════════════════════════════════════════════════════════════════

    /// Closure-extensive property: L ≤ γ(α(L)) for all L.
    /// This means the round-trip through abstraction and concretization
    /// never loses information that the market cares about.
    #[test]
    fn test_galois_closure_extensive_named_profiles() {
        let profiles = vec![
            PermissionLattice::permissive(),
            PermissionLattice::restrictive(),
            PermissionLattice::read_only(),
        ];

        for perms in profiles {
            let dims: Vec<_> = lattice_to_dimensions(&perms).into_iter().collect();
            let ceiling = dimensions_to_ceiling(&dims);

            // L ≤ γ(α(L)): the original should be ≤ the ceiling of its own dimensions
            assert!(
                perms.leq(&ceiling),
                "Closure-extensive violated for: {:?}",
                perms.description
            );
        }
    }

    /// Kernel-reductive property: α(γ(S)) ⊆ S for all S.
    /// The ceiling of a dimension set, when mapped back, gives at most
    /// the original set (possibly fewer due to pass-through caps).
    #[test]
    fn test_galois_kernel_reductive() {
        let dimension_sets: Vec<Vec<PermissionDimension>> = vec![
            vec![],
            vec![PermissionDimension::Filesystem],
            vec![PermissionDimension::CommandExec],
            vec![PermissionDimension::NetworkEgress],
            vec![
                PermissionDimension::Filesystem,
                PermissionDimension::CommandExec,
            ],
            vec![
                PermissionDimension::Filesystem,
                PermissionDimension::CommandExec,
                PermissionDimension::NetworkEgress,
                PermissionDimension::Approval,
            ],
        ];

        for dims in &dimension_sets {
            let ceiling = dimensions_to_ceiling(dims);
            let roundtrip = lattice_to_dimensions(&ceiling);
            let original_set: HashSet<_> = dims.iter().copied().collect();

            // α(γ(S)) ⊆ S: roundtrip dimensions should be subset of original
            // (Note: pass-through caps like git_commit may add CommandExec to ceiling,
            //  but they don't add to the roundtrip because they're not mapped to any
            //  dimension by lattice_to_dimensions. This is correct.)
            for dim in &roundtrip {
                // Approval might appear if normalize() adds obligations
                if *dim != PermissionDimension::Approval {
                    assert!(
                        original_set.contains(dim),
                        "Kernel-reductive violated: {:?} not in {:?}",
                        dim,
                        dims
                    );
                }
            }
        }
    }

    #[test]
    fn test_intersection_always_leq_certificate() {
        let verified = mint_and_verify(PermissionLattice::permissive());

        let grants = vec![
            PermissionGrant {
                granted: vec![],
                denied: vec![],
                total_cost: 0.0,
                expires_at: None,
            },
            PermissionGrant {
                granted: vec![PermissionDimension::Filesystem],
                denied: vec![],
                total_cost: 0.0,
                expires_at: None,
            },
            PermissionGrant {
                granted: vec![
                    PermissionDimension::Filesystem,
                    PermissionDimension::CommandExec,
                    PermissionDimension::NetworkEgress,
                    PermissionDimension::Approval,
                ],
                denied: vec![],
                total_cost: 0.0,
                expires_at: None,
            },
        ];

        for grant in &grants {
            let effective = intersect_grant_with_certificate(grant, &verified);
            assert!(
                effective.leq(&verified.effective),
                "Intersection exceeded certificate for grant: {:?}",
                grant.granted
            );
        }
    }
}
