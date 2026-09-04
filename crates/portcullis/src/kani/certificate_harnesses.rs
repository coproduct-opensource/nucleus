//! Certificate harnesses (#2476, #2477): `verify_certificate` and the lattice
//! half of `mint_child`, DRIVEN with the crypto stubbed. A child module of
//! `kani` so it can reuse the symbolic builders there; split out to keep
//! `kani.rs` under the line sweep. Counted by CI together with `kani.rs`.

use super::{arbitrary_caps, base_permission, fixed_timestamp, obligations_from_masks};
use crate::{BudgetLattice, CommandLattice, PathLattice, PermissionLattice};
use chrono::{DateTime, Utc};
use uuid::Uuid;

// ═══════════════════════════════════════════════════════════════════════════
// C3/C4/C5 — verify_certificate and mint_child, DRIVEN (#2476, #2477)
// ═══════════════════════════════════════════════════════════════════════════
//
// The harnesses below call the real `verify_certificate` and the real lattice
// half of `mint_child` (`attenuate_for_child`). Ed25519 and SHA-256 are
// outside a bounded model checker's reach, so they are STUBBED — every
// signature verifies and every payload/hash is a constant — which makes the
// SUBJECT exactly what the issues asked for: the chain walk (depth, expiry,
// hash linkage, monotone attenuation, sink scope) over symbolic lattices.
// Stubbing is what lets a harness reach the function at all; it does not
// weaken the lattice claims, and it is disclosed here rather than hidden.

#[allow(dead_code)] // referenced from #[kani::stub] attributes only
fn stub_verify_ok(_pk: &[u8], _msg: &[u8], _sig: &[u8]) -> Result<(), ()> {
    Ok(())
}
#[allow(dead_code)]
fn stub_payload_authority(_b: &crate::certificate::AuthorityBlock) -> Vec<u8> {
    Vec::new()
}
#[allow(dead_code)]
fn stub_payload_delegation(_b: &crate::certificate::DelegationBlock) -> Vec<u8> {
    Vec::new()
}
#[allow(dead_code)]
fn stub_hash_authority(_b: &crate::certificate::AuthorityBlock) -> Vec<u8> {
    vec![0u8; 32]
}
#[allow(dead_code)]
fn stub_hash_delegation(_b: &crate::certificate::DelegationBlock) -> Vec<u8> {
    vec![0u8; 32]
}
#[allow(dead_code)]
fn stub_pop_payload(_h: &[u8]) -> Vec<u8> {
    Vec::new()
}
#[allow(dead_code)]
fn stub_now() -> DateTime<Utc> {
    fixed_timestamp()
}
/// `delegate_to` stamps a fresh v4 UUID on the child (OS randomness, which a
/// model checker cannot supply); the id is metadata, not a lattice value.
#[allow(dead_code)]
fn stub_uuid() -> Uuid {
    Uuid::nil()
}

/// A lean base for the certificate harnesses: the same fixed budget/time as
/// `base_permission`, but EMPTY path and command sets. `block_sensitive()`
/// seeds ~20 blocked globs, and every one of them is hashed (SipHash) on
/// every set operation the chain walk performs — that alone kept the first
/// version of these harnesses from terminating. The sets the harness cares
/// about are added symbolically by `symbolic_allow_sets`.
fn lean_permission() -> PermissionLattice {
    let mut p = base_permission();
    p.paths = PathLattice::default();
    p.commands = CommandLattice {
        allowed: std::collections::HashSet::new(),
        blocked: std::collections::HashSet::new(),
        allowed_rules: Vec::new(),
        blocked_rules: Vec::new(),
        allow_metacharacters: false,
    };
    p
}

/// `lean_permission` with symbolic capability levels, obligations and the
/// uninhabitable flag — the same symbolic surface `build_arbitrary_permission`
/// gives, over the lean base.
fn lean_arbitrary_permission() -> PermissionLattice {
    let mut p = lean_permission();
    p.capabilities = arbitrary_caps();
    p.obligations = obligations_from_masks(kani::any::<u16>(), kani::any::<u16>()).0;
    p.uninhabitable_constraint = kani::any::<bool>();
    p
}

/// Symbolic membership over a small concrete alphabet of path globs and
/// commands: empty (UNRESTRICTED) and non-empty allow sets are both reachable,
/// which is exactly the shape #2474's vacuous-subset inversion lived in.
fn symbolic_allow_sets(perms: &mut PermissionLattice) {
    if kani::any::<bool>() {
        perms.paths.allowed.insert("src/**".to_string());
    }
    if kani::any::<bool>() {
        perms.paths.allowed.insert("docs/**".to_string());
    }
    if kani::any::<bool>() {
        perms.commands.allowed.insert("cargo test".to_string());
    }
    if kani::any::<bool>() {
        perms.commands.allowed.insert("git status".to_string());
    }
}

fn block_under(
    parent: &PermissionLattice,
    effective: PermissionLattice,
    not_after: DateTime<Utc>,
) -> crate::certificate::DelegationBlock {
    let justification = crate::delegation::meet_with_justification(parent, &effective).1;
    crate::certificate::DelegationBlock {
        effective_permissions: effective,
        justification,
        from_identity: "spiffe://kani/root".to_string(),
        to_identity: "spiffe://kani/child".to_string(),
        not_after,
        sink_scope: crate::certificate::SinkScope::unrestricted(),
        prev_block_hash: vec![0u8; 32],
        signature: vec![0u8; 64],
        next_key: vec![0u8; 32],
    }
}

fn authority_of(
    root: PermissionLattice,
    not_after: DateTime<Utc>,
) -> crate::certificate::AuthorityBlock {
    crate::certificate::AuthorityBlock {
        root_permissions: root,
        root_identity: "spiffe://kani/root".to_string(),
        not_after,
        signature: vec![0u8; 64],
        next_key: vec![0u8; 32],
        provenance: None,
    }
}

/// **C3 — `verify_certificate` accepts a child iff it attenuates.**
///
/// Symbolic root and child lattices (capabilities, obligations, the
/// uninhabitable constraint, symbolic path/command allow sets, and a budget
/// that may exceed the root's) in a one-hop chain with the crypto stubbed:
/// `Ok` implies `child ≤ root` and the returned effective permissions are
/// `≤ root`; `MonotoneViolation` implies `!(child ≤ root)`; no other verdict
/// is reachable. This is the harness whose absence #2476 names; over the
/// pre-#2474 order it would have found the empty-allow-set inversion.
#[kani::proof]
#[kani::unwind(48)]
#[kani::solver(cadical)]
#[kani::stub(crate::certificate::verify_ed25519_strict, stub_verify_ok)]
#[kani::stub(
    crate::certificate::AuthorityBlock::signing_payload,
    stub_payload_authority
)]
#[kani::stub(
    crate::certificate::DelegationBlock::signing_payload,
    stub_payload_delegation
)]
#[kani::stub(crate::certificate::AuthorityBlock::block_hash, stub_hash_authority)]
#[kani::stub(crate::certificate::DelegationBlock::block_hash, stub_hash_delegation)]
#[kani::stub(
    crate::certificate::LatticeCertificate::pop_payload_for_block_hash,
    stub_pop_payload
)]
fn proof_verify_certificate_accepts_only_attenuating_children() {
    let mut root = lean_arbitrary_permission();
    symbolic_allow_sets(&mut root);
    let mut child = lean_arbitrary_permission();
    symbolic_allow_sets(&mut child);
    if kani::any::<bool>() {
        child.budget = BudgetLattice::with_cost_limit(2.0); // the root holds 1.0
    }
    let now = fixed_timestamp();
    let not_after = DateTime::<Utc>::from_timestamp(3_600, 0).unwrap();

    let attenuates = child.leq(&root);
    let cert = crate::certificate::LatticeCertificate::from_parts(
        authority_of(root.clone(), not_after),
        vec![block_under(&root, child, not_after)],
        vec![0u8; 64],
    );
    match crate::certificate::verify_certificate(&cert, &[0u8; 32], now, 10) {
        Ok(verified) => {
            assert!(attenuates, "verify_certificate accepted a widening child");
            assert!(
                verified.effective().leq(&root),
                "the effective grant exceeds the root"
            );
        }
        Err(crate::certificate::CertificateError::MonotoneViolation { block_index }) => {
            assert!(
                !attenuates,
                "an attenuating child was refused as a widening"
            );
            assert_eq!(block_index, 1);
        }
        Err(_) => panic!("with the crypto stubbed, only the monotone check can refuse"),
    }
}

/// **C4 — `verify_certificate` bounds the chain depth.**
///
/// A chain of `n ≤ 2` self-attenuating blocks against a symbolic
/// `max_chain_depth ≤ 3`: refused as `ChainTooDeep` iff `n > max`, accepted
/// otherwise. Replaces the former tautology over two integers (#2476).
#[kani::proof]
#[kani::unwind(48)]
#[kani::solver(cadical)]
#[kani::stub(crate::certificate::verify_ed25519_strict, stub_verify_ok)]
#[kani::stub(
    crate::certificate::AuthorityBlock::signing_payload,
    stub_payload_authority
)]
#[kani::stub(
    crate::certificate::DelegationBlock::signing_payload,
    stub_payload_delegation
)]
#[kani::stub(crate::certificate::AuthorityBlock::block_hash, stub_hash_authority)]
#[kani::stub(crate::certificate::DelegationBlock::block_hash, stub_hash_delegation)]
#[kani::stub(
    crate::certificate::LatticeCertificate::pop_payload_for_block_hash,
    stub_pop_payload
)]
fn proof_verify_certificate_depth_bound() {
    let n: usize = kani::any();
    kani::assume(n <= 2);
    let max: usize = kani::any();
    kani::assume(max <= 3);
    let root = lean_permission();
    let now = fixed_timestamp();
    let not_after = DateTime::<Utc>::from_timestamp(3_600, 0).unwrap();
    let mut blocks = Vec::new();
    for _ in 0..n {
        blocks.push(block_under(&root, root.clone(), not_after));
    }
    let cert = crate::certificate::LatticeCertificate::from_parts(
        authority_of(root, not_after),
        blocks,
        vec![0u8; 64],
    );
    let verdict = crate::certificate::verify_certificate(&cert, &[0u8; 32], now, max);
    if n > max {
        assert!(
            matches!(
                verdict,
                Err(crate::certificate::CertificateError::ChainTooDeep { .. })
            ),
            "a chain deeper than the bound must be refused"
        );
    } else {
        assert!(
            verdict.is_ok(),
            "a chain within the bound of self-attenuating blocks verifies"
        );
    }
}

/// **C5 — `mint_child`'s lattice half narrows and refuses, never clamps (#2477).**
///
/// `attenuate_for_child` is what `mint_child_with_scope` runs before it signs.
/// For symbolic parent and request: `Ok(child)` implies `child ≤ parent` and
/// `child ≤ request`; a request whose budget exceeds the parent's remaining
/// budget is `InsufficientBudget`, never a clamped success. `chrono::Utc::now`
/// is stubbed to a fixed instant so the parent's time window is not expired.
#[kani::proof]
#[kani::unwind(48)]
#[kani::solver(cadical)]
#[kani::stub(uuid::Uuid::new_v4, stub_uuid)]
#[kani::stub(chrono::Utc::now, stub_now)]
fn proof_mint_child_core_narrows_and_refuses_over_budget() {
    let parent = lean_arbitrary_permission();
    let mut requested = lean_arbitrary_permission();
    let over_budget = kani::any::<bool>();
    if over_budget {
        requested.budget = BudgetLattice::with_cost_limit(2.0); // the parent holds 1.0
    }
    match crate::certificate::LatticeCertificate::attenuate_for_child(&parent, &requested, "kani") {
        Ok(child) => {
            assert!(!over_budget, "an over-budget request was minted");
            assert!(child.leq(&parent), "the child exceeds its parent");
            assert!(child.leq(&requested), "the child exceeds its request");
        }
        Err(crate::DelegationError::InsufficientBudget { .. }) => {
            assert!(
                over_budget,
                "a request within budget was refused as over budget"
            );
        }
        Err(_) => panic!("only the budget check can refuse a fresh parent"),
    }
}
