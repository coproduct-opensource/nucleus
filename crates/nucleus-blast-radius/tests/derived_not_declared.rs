//! The properties that make a blast radius worth more than a governance
//! document: it is derived from a verified chain, it narrows as the chain
//! delegates, and a claim that disagrees with its own chain is caught by name.

use chrono::{Duration, Utc};
use nucleus_blast_radius::{BlastRadius, RecomputeOutcome, content_hash_hex, issue, verify};
use portcullis::certificate::LatticeCertificate;
use portcullis::{CapabilityLattice, CapabilityLevel, Operation, PermissionLattice};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rust_decimal::Decimal;

const DEPTH: u64 = 8;

fn root_key(rng: &SystemRandom) -> Ed25519KeyPair {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(rng).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

/// A lattice with the given capabilities and a spend ceiling. Portcullis has
/// no per-operation setter; its own `permissive()` / `restrictive()` are the
/// two ends of the range, and individual fields are public for the cases
/// between.
fn lattice(caps: CapabilityLattice, usd: &str) -> PermissionLattice {
    let mut l = PermissionLattice::new("test");
    l.capabilities = caps;
    l.budget.max_cost_usd = usd.parse::<Decimal>().unwrap();
    l
}

#[test]
fn a_permissive_root_and_a_restrictive_root_have_different_radii() {
    let rng = SystemRandom::new();
    let key = root_key(&rng);
    let until = Utc::now() + Duration::hours(1);

    let (wide, _) = LatticeCertificate::mint(
        lattice(CapabilityLattice::permissive(), "100.00"),
        "spiffe://example.org/root".into(),
        until,
        &key,
        &rng,
    );
    let (narrow, _) = LatticeCertificate::mint(
        lattice(CapabilityLattice::restrictive(), "0.50"),
        "spiffe://example.org/root".into(),
        until,
        &key,
        &rng,
    );
    let now = Utc::now();
    let w = issue(wide, key.public_key().as_ref(), now, DEPTH).unwrap();
    let n = issue(narrow, key.public_key().as_ref(), now, DEPTH).unwrap();

    assert_eq!(w.claimed.max_spend_micro, 100_000_000);
    assert_eq!(n.claimed.max_spend_micro, 500_000);
    assert!(
        w.claimed.denied.is_empty(),
        "permissive denies nothing: {:?}",
        w.claimed.denied
    );
    assert!(
        n.claimed.autonomous.len() < w.claimed.autonomous.len(),
        "restrictive must act autonomously in fewer places"
    );
    assert!(!n.claimed.denied.is_empty(), "restrictive denies something");
    assert_ne!(w.claimed, n.claimed, "the projection is not a constant");
    assert_eq!(verify(&w), RecomputeOutcome::Match);
    assert_eq!(verify(&n), RecomputeOutcome::Match);
}

/// `chain_attenuates` observed through the projection: a delegated child's
/// radius is inside its parent's on every axis that orders.
#[test]
fn delegation_can_only_narrow_the_radius() {
    let rng = SystemRandom::new();
    let key = root_key(&rng);
    let until = Utc::now() + Duration::hours(1);
    let (root, holder) = LatticeCertificate::mint(
        lattice(CapabilityLattice::permissive(), "100.00"),
        "spiffe://example.org/root".into(),
        until,
        &key,
        &rng,
    );

    // The child asks for less: two operations denied, a smaller budget.
    let mut narrower = lattice(CapabilityLattice::permissive(), "10.00");
    narrower.capabilities.git_push = CapabilityLevel::Never;
    narrower.capabilities.run_bash = CapabilityLevel::Never;
    let (child, _) = root
        .delegate(
            &narrower,
            "spiffe://example.org/agent".into(),
            until - Duration::minutes(5),
            &holder,
            &rng,
        )
        .unwrap();

    let now = Utc::now();
    let parent = issue(root, key.public_key().as_ref(), now, DEPTH)
        .unwrap()
        .claimed;
    let leaf = issue(child, key.public_key().as_ref(), now, DEPTH)
        .unwrap()
        .claimed;

    assert!(leaf.max_spend_micro <= parent.max_spend_micro);
    assert!(
        leaf.autonomous
            .iter()
            .all(|op| parent.autonomous.contains(op)),
        "a child may not act autonomously where its parent could not"
    );
    assert!(leaf.denied.contains(&Operation::GitPush));
    assert!(leaf.denied.contains(&Operation::RunBash));
    assert_eq!(leaf.chain_depth, parent.chain_depth + 1);
    assert_eq!(leaf.leaf_identity, "spiffe://example.org/agent");
    assert_eq!(leaf.root_identity, parent.root_identity);
}

/// **Derived, never declared.** The claimed radius cannot be widened or
/// narrowed without the chain agreeing, and the mismatch names the field.
#[test]
fn a_claim_that_disagrees_with_its_own_chain_is_caught_by_name() {
    let rng = SystemRandom::new();
    let key = root_key(&rng);
    let until = Utc::now() + Duration::hours(1);
    let mut base_lattice = lattice(CapabilityLattice::permissive(), "5.00");
    base_lattice.capabilities.git_push = CapabilityLevel::Never;
    let (cert, _) = LatticeCertificate::mint(
        base_lattice,
        "spiffe://example.org/root".into(),
        until,
        &key,
        &rng,
    );
    let base = issue(cert, key.public_key().as_ref(), Utc::now(), DEPTH).unwrap();
    assert_eq!(verify(&base), RecomputeOutcome::Match);

    // Widen: claim git push is autonomous when the chain denies it.
    let mut c = base.clone();
    c.claimed.autonomous.push(Operation::GitPush);
    assert!(matches!(
        verify(&c),
        RecomputeOutcome::Mismatch {
            field: "autonomous",
            ..
        }
    ));

    // Narrow: claim a smaller spend ceiling than was delegated. Understating
    // authority is as much a lie to an underwriter as overstating it.
    let mut c = base.clone();
    c.claimed.max_spend_micro = 1;
    assert!(matches!(
        verify(&c),
        RecomputeOutcome::Mismatch {
            field: "max_spend_micro",
            ..
        }
    ));

    // Forge the bit that matters most.
    let mut c = base.clone();
    c.claimed.trifecta_gated = !c.claimed.trifecta_gated;
    assert!(matches!(
        verify(&c),
        RecomputeOutcome::Mismatch {
            field: "trifecta_gated",
            ..
        }
    ));

    // And the expiry, which is the axis a stale claim would quietly extend.
    let mut c = base;
    c.claimed.valid_until = (until + Duration::days(365)).to_rfc3339();
    assert!(matches!(
        verify(&c),
        RecomputeOutcome::Mismatch {
            field: "valid_until",
            ..
        }
    ));
}

/// A chain that does not verify against its own declared root has no radius.
/// `Invalid`, never `Match`.
#[test]
fn the_wrong_root_key_yields_no_radius() {
    let rng = SystemRandom::new();
    let key = root_key(&rng);
    let other = root_key(&rng);
    let (cert, _) = LatticeCertificate::mint(
        lattice(CapabilityLattice::permissive(), "1.00"),
        "spiffe://example.org/root".into(),
        Utc::now() + Duration::hours(1),
        &key,
        &rng,
    );
    let mut claim = issue(cert, key.public_key().as_ref(), Utc::now(), DEPTH).unwrap();
    claim.root_public_key_hex = hex::encode(other.public_key().as_ref());
    assert!(matches!(verify(&claim), RecomputeOutcome::Invalid(_)));
}

/// An expired certificate bounds nothing, so a claim verified after expiry is
/// `Invalid` — and `verified_at` is a declared input precisely so this is
/// decidable from the receipt alone.
#[test]
fn an_expired_chain_yields_no_radius() {
    let rng = SystemRandom::new();
    let key = root_key(&rng);
    let until = Utc::now() + Duration::hours(1);
    let (cert, _) = LatticeCertificate::mint(
        lattice(CapabilityLattice::permissive(), "1.00"),
        "spiffe://example.org/root".into(),
        until,
        &key,
        &rng,
    );
    assert!(
        issue(
            cert.clone(),
            key.public_key().as_ref(),
            until + Duration::hours(1),
            DEPTH
        )
        .is_err()
    );
    let mut claim = issue(cert, key.public_key().as_ref(), Utc::now(), DEPTH).unwrap();
    claim.verified_at = (until + Duration::hours(1)).to_rfc3339();
    assert!(matches!(verify(&claim), RecomputeOutcome::Invalid(_)));
}

/// The trifecta bits come from portcullis's own decision, and the projection
/// reports them as they are — reachable when all three legs are autonomous.
#[test]
fn the_trifecta_bits_are_portcullis_s_own_decision() {
    let rng = SystemRandom::new();
    let key = root_key(&rng);
    let until = Utc::now() + Duration::hours(1);
    let (cert, _) = LatticeCertificate::mint(
        lattice(CapabilityLattice::permissive(), "1.00"),
        "spiffe://example.org/root".into(),
        until,
        &key,
        &rng,
    );
    let claim = issue(cert, key.public_key().as_ref(), Utc::now(), DEPTH).unwrap();
    let r: &BlastRadius = &claim.claimed;
    // Everything autonomous ⇒ all three legs reachable, per portcullis.
    assert!(r.trifecta_reachable, "{r:?}");
    // And the constraint is enforced by default, so it is gated.
    assert!(r.trifecta_gated, "{r:?}");
    assert!(!r.trifecta_ungated());
}

#[test]
fn the_content_hash_moves_with_the_claim() {
    let rng = SystemRandom::new();
    let key = root_key(&rng);
    let (cert, _) = LatticeCertificate::mint(
        lattice(CapabilityLattice::permissive(), "1.00"),
        "spiffe://example.org/root".into(),
        Utc::now() + Duration::hours(1),
        &key,
        &rng,
    );
    let a = issue(cert, key.public_key().as_ref(), Utc::now(), DEPTH).unwrap();
    let h1 = content_hash_hex(&a).unwrap();
    assert_eq!(h1, content_hash_hex(&a).unwrap());
    let mut b = a;
    b.max_chain_depth = 3;
    assert_ne!(h1, content_hash_hex(&b).unwrap());
}
