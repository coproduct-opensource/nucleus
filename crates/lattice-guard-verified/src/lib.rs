//! Formally verified lattice proofs for lattice-guard.
//!
//! This crate contains Verus SMT proofs that the core algebraic structures
//! in lattice-guard satisfy their mathematical laws. These proofs are
//! machine-checked by the Z3 SMT solver via Verus.
//!
//! # Verified Properties
//!
//! ## Phase 1: Algebraic Core
//!
//! ### CapabilityLevel (3-element total order: Never < LowRisk < Always)
//! - Meet (min) and Join (max) form a bounded distributive lattice
//! - All 7 lattice laws: commutativity, associativity, idempotence,
//!   absorption, distributivity, bounded (top/bottom identity)
//! - Partial order consistency: a ≤ b iff meet(a, b) = a
//!
//! ### CapabilityLattice (12-dimensional product lattice)
//! - Product of 12 CapabilityLevel dimensions
//! - Inherits all lattice laws from the component lattice
//! - Meet/join are element-wise min/max
//!
//! ### Nucleus Operator (trifecta normalization)
//! - Idempotent: ν(ν(x)) = ν(x)
//! - Deflationary: ν(x) ≤ x (adds obligations, never removes)
//! - **Not meet-preserving**: ν(x∧y) ≠ ν(x)∧ν(y) in general
//!   (counterexample: threshold triggers for one input but not the meet)
//! - **Not monotone**: x≤y does not imply ν(x)≤ν(y) in general
//!   (counterexample: trifecta fires for y but not x)
//! - Both properties DO hold on the image of ν (fixed points)
//! - The quotient meet (perm_meet, which normalizes) always produces
//!   fixed points and is commutative
//!
//! ## Phase 2: Enforcement Boundary
//!
//! ### Trifecta Risk Grading
//! - Count of components is bounded {0,1,2,3}
//! - Risk is monotone under ≤ (more capabilities → more risk)
//! - Risk decreases under meet, increases under join
//! - No trifecta → no obligations; complete → all active exfil gated
//!
//! ### Normalize Correctness
//! - Preserves capabilities (never modifies capability levels)
//! - Only adds obligations (never removes approval gates)
//! - No-op when trifecta constraint disabled
//! - Meet of fixed points is a fixed point
//!
//! ### Guard Decision (THE CRITICAL PROOFS)
//! - Complete risk + approval required → operation denied
//! - No obligation → always allowed; risk < Complete → always allowed
//! - **End-to-end trifecta safety**: normalize → check_operation
//!   DENIES all exfil ops when trifecta is complete
//! - Read-only profiles never blocked
//! - Guard is monotone in obligations
//!
//! ### Budget Decision
//! - Within budget → allowed; over budget → denied
//! - Monotone in consumption and max
//! - Sequential charges compose correctly
//!
//! # Running Verification
//!
//! ```bash
//! .verus/verus-x86-macos/verus crates/lattice-guard-verified/src/lib.rs
//! ```

use vstd::prelude::*;

verus! {

// ============================================================================
// CapabilityLevel: 3-element total order {Never=0, LowRisk=1, Always=2}
// ============================================================================

/// Models lattice_guard::CapabilityLevel as a u8 in {0, 1, 2}.
/// Never=0, LowRisk=1, Always=2.
///
/// We use u8 rather than an enum because Verus's SMT encoding handles
/// integer arithmetic natively, making proofs more automated.
pub type CapLevel = u8;

/// Valid capability level: 0, 1, or 2.
pub open spec fn valid_cap(c: CapLevel) -> bool {
    c <= 2
}

/// Meet (greatest lower bound) = min.
pub open spec fn cap_meet(a: CapLevel, b: CapLevel) -> CapLevel {
    if a <= b { a } else { b }
}

/// Join (least upper bound) = max.
pub open spec fn cap_join(a: CapLevel, b: CapLevel) -> CapLevel {
    if a >= b { a } else { b }
}

/// Partial order: a ≤ b in the lattice.
pub open spec fn cap_leq(a: CapLevel, b: CapLevel) -> bool {
    a <= b
}

/// Top element (⊤) = Always = 2.
pub open spec fn cap_top() -> CapLevel { 2 }

/// Bottom element (⊥) = Never = 0.
pub open spec fn cap_bot() -> CapLevel { 0 }

// ============================================================================
// Lattice Law Proofs for CapabilityLevel
// ============================================================================

// --- Meet laws ---

/// Meet is commutative: meet(a, b) = meet(b, a)
proof fn proof_meet_commutative(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
    ensures
        cap_meet(a, b) == cap_meet(b, a),
{
}

/// Meet is associative: meet(meet(a, b), c) = meet(a, meet(b, c))
proof fn proof_meet_associative(a: CapLevel, b: CapLevel, c: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
        valid_cap(c),
    ensures
        cap_meet(cap_meet(a, b), c) == cap_meet(a, cap_meet(b, c)),
{
}

/// Meet is idempotent: meet(a, a) = a
proof fn proof_meet_idempotent(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_meet(a, a) == a,
{
}

// --- Join laws ---

/// Join is commutative: join(a, b) = join(b, a)
proof fn proof_join_commutative(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
    ensures
        cap_join(a, b) == cap_join(b, a),
{
}

/// Join is associative: join(join(a, b), c) = join(a, join(b, c))
proof fn proof_join_associative(a: CapLevel, b: CapLevel, c: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
        valid_cap(c),
    ensures
        cap_join(cap_join(a, b), c) == cap_join(a, cap_join(b, c)),
{
}

/// Join is idempotent: join(a, a) = a
proof fn proof_join_idempotent(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_join(a, a) == a,
{
}

// --- Absorption laws ---

/// Absorption: meet(a, join(a, b)) = a
proof fn proof_absorption_meet_join(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
    ensures
        cap_meet(a, cap_join(a, b)) == a,
{
}

/// Absorption: join(a, meet(a, b)) = a
proof fn proof_absorption_join_meet(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
    ensures
        cap_join(a, cap_meet(a, b)) == a,
{
}

// --- Bounded lattice laws ---

/// Top is identity for meet: meet(a, ⊤) = a
proof fn proof_meet_top_identity(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_meet(a, cap_top()) == a,
{
}

/// Bottom is identity for join: join(a, ⊥) = a
proof fn proof_join_bot_identity(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_join(a, cap_bot()) == a,
{
}

/// Bottom is annihilator for meet: meet(a, ⊥) = ⊥
proof fn proof_meet_bot_annihilator(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_meet(a, cap_bot()) == cap_bot(),
{
}

/// Top is annihilator for join: join(a, ⊤) = ⊤
proof fn proof_join_top_annihilator(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_join(a, cap_top()) == cap_top(),
{
}

// --- Distributivity ---

/// Meet distributes over join: meet(a, join(b, c)) = join(meet(a, b), meet(a, c))
proof fn proof_meet_distributes_over_join(a: CapLevel, b: CapLevel, c: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
        valid_cap(c),
    ensures
        cap_meet(a, cap_join(b, c)) == cap_join(cap_meet(a, b), cap_meet(a, c)),
{
}

/// Join distributes over meet: join(a, meet(b, c)) = meet(join(a, b), join(a, c))
proof fn proof_join_distributes_over_meet(a: CapLevel, b: CapLevel, c: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
        valid_cap(c),
    ensures
        cap_join(a, cap_meet(b, c)) == cap_meet(cap_join(a, b), cap_join(a, c)),
{
}

// --- Partial order consistency ---

/// The partial order is consistent with meet: a ≤ b iff meet(a, b) = a
proof fn proof_order_consistent_with_meet(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
    ensures
        cap_leq(a, b) <==> cap_meet(a, b) == a,
{
}

/// The partial order is consistent with join: a ≤ b iff join(a, b) = b
proof fn proof_order_consistent_with_join(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
    ensures
        cap_leq(a, b) <==> cap_join(a, b) == b,
{
}

/// The order is reflexive: a ≤ a
proof fn proof_order_reflexive(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_leq(a, a),
{
}

/// The order is antisymmetric: a ≤ b ∧ b ≤ a ⟹ a = b
proof fn proof_order_antisymmetric(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
        cap_leq(a, b),
        cap_leq(b, a),
    ensures
        a == b,
{
}

/// The order is transitive: a ≤ b ∧ b ≤ c ⟹ a ≤ c
proof fn proof_order_transitive(a: CapLevel, b: CapLevel, c: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
        valid_cap(c),
        cap_leq(a, b),
        cap_leq(b, c),
    ensures
        cap_leq(a, c),
{
}

/// The order is total: a ≤ b ∨ b ≤ a
proof fn proof_order_total(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
    ensures
        cap_leq(a, b) || cap_leq(b, a),
{
}

// ============================================================================
// CapabilityLattice: 12-dimensional product lattice
// ============================================================================

/// Models lattice_guard::CapabilityLattice as a 12-tuple of CapLevels.
///
/// Fields (in order): read_files, write_files, edit_files, run_bash,
/// glob_search, grep_search, web_search, web_fetch, git_commit,
/// git_push, create_pr, manage_pods.
pub struct CapLattice {
    pub f0: CapLevel,  // read_files
    pub f1: CapLevel,  // write_files
    pub f2: CapLevel,  // edit_files
    pub f3: CapLevel,  // run_bash
    pub f4: CapLevel,  // glob_search
    pub f5: CapLevel,  // grep_search
    pub f6: CapLevel,  // web_search
    pub f7: CapLevel,  // web_fetch
    pub f8: CapLevel,  // git_commit
    pub f9: CapLevel,  // git_push
    pub f10: CapLevel, // create_pr
    pub f11: CapLevel, // manage_pods
}

/// A CapLattice is valid when all 12 components are valid CapLevels.
pub open spec fn valid_lattice(l: CapLattice) -> bool {
    valid_cap(l.f0) && valid_cap(l.f1) && valid_cap(l.f2) && valid_cap(l.f3)
    && valid_cap(l.f4) && valid_cap(l.f5) && valid_cap(l.f6) && valid_cap(l.f7)
    && valid_cap(l.f8) && valid_cap(l.f9) && valid_cap(l.f10) && valid_cap(l.f11)
}

/// Element-wise meet of two CapLattices.
pub open spec fn lattice_meet(a: CapLattice, b: CapLattice) -> CapLattice {
    CapLattice {
        f0: cap_meet(a.f0, b.f0),
        f1: cap_meet(a.f1, b.f1),
        f2: cap_meet(a.f2, b.f2),
        f3: cap_meet(a.f3, b.f3),
        f4: cap_meet(a.f4, b.f4),
        f5: cap_meet(a.f5, b.f5),
        f6: cap_meet(a.f6, b.f6),
        f7: cap_meet(a.f7, b.f7),
        f8: cap_meet(a.f8, b.f8),
        f9: cap_meet(a.f9, b.f9),
        f10: cap_meet(a.f10, b.f10),
        f11: cap_meet(a.f11, b.f11),
    }
}

/// Element-wise join of two CapLattices.
pub open spec fn lattice_join(a: CapLattice, b: CapLattice) -> CapLattice {
    CapLattice {
        f0: cap_join(a.f0, b.f0),
        f1: cap_join(a.f1, b.f1),
        f2: cap_join(a.f2, b.f2),
        f3: cap_join(a.f3, b.f3),
        f4: cap_join(a.f4, b.f4),
        f5: cap_join(a.f5, b.f5),
        f6: cap_join(a.f6, b.f6),
        f7: cap_join(a.f7, b.f7),
        f8: cap_join(a.f8, b.f8),
        f9: cap_join(a.f9, b.f9),
        f10: cap_join(a.f10, b.f10),
        f11: cap_join(a.f11, b.f11),
    }
}

/// Element-wise partial order on CapLattices.
pub open spec fn lattice_leq(a: CapLattice, b: CapLattice) -> bool {
    cap_leq(a.f0, b.f0) && cap_leq(a.f1, b.f1) && cap_leq(a.f2, b.f2)
    && cap_leq(a.f3, b.f3) && cap_leq(a.f4, b.f4) && cap_leq(a.f5, b.f5)
    && cap_leq(a.f6, b.f6) && cap_leq(a.f7, b.f7) && cap_leq(a.f8, b.f8)
    && cap_leq(a.f9, b.f9) && cap_leq(a.f10, b.f10) && cap_leq(a.f11, b.f11)
}

/// Top element: all capabilities at Always.
pub open spec fn lattice_top() -> CapLattice {
    CapLattice {
        f0: cap_top(), f1: cap_top(), f2: cap_top(), f3: cap_top(),
        f4: cap_top(), f5: cap_top(), f6: cap_top(), f7: cap_top(),
        f8: cap_top(), f9: cap_top(), f10: cap_top(), f11: cap_top(),
    }
}

/// Bottom element: all capabilities at Never.
pub open spec fn lattice_bot() -> CapLattice {
    CapLattice {
        f0: cap_bot(), f1: cap_bot(), f2: cap_bot(), f3: cap_bot(),
        f4: cap_bot(), f5: cap_bot(), f6: cap_bot(), f7: cap_bot(),
        f8: cap_bot(), f9: cap_bot(), f10: cap_bot(), f11: cap_bot(),
    }
}

// ============================================================================
// Product Lattice Law Proofs
// ============================================================================

/// Product meet is commutative.
proof fn proof_lattice_meet_commutative(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        lattice_meet(a, b) == lattice_meet(b, a),
{
}

/// Product meet is associative.
proof fn proof_lattice_meet_associative(a: CapLattice, b: CapLattice, c: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
        valid_lattice(c),
    ensures
        lattice_meet(lattice_meet(a, b), c) == lattice_meet(a, lattice_meet(b, c)),
{
}

/// Product meet is idempotent.
proof fn proof_lattice_meet_idempotent(a: CapLattice)
    requires
        valid_lattice(a),
    ensures
        lattice_meet(a, a) == a,
{
}

/// Product join is commutative.
proof fn proof_lattice_join_commutative(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        lattice_join(a, b) == lattice_join(b, a),
{
}

/// Product join is associative.
proof fn proof_lattice_join_associative(a: CapLattice, b: CapLattice, c: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
        valid_lattice(c),
    ensures
        lattice_join(lattice_join(a, b), c) == lattice_join(a, lattice_join(b, c)),
{
}

/// Product join is idempotent.
proof fn proof_lattice_join_idempotent(a: CapLattice)
    requires
        valid_lattice(a),
    ensures
        lattice_join(a, a) == a,
{
}

/// Product absorption: meet(a, join(a, b)) = a
proof fn proof_lattice_absorption_meet_join(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        lattice_meet(a, lattice_join(a, b)) == a,
{
}

/// Product absorption: join(a, meet(a, b)) = a
proof fn proof_lattice_absorption_join_meet(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        lattice_join(a, lattice_meet(a, b)) == a,
{
}

/// Product meet distributes over join.
///
/// Proof strategy: invoke the per-component distributivity lemma for each
/// of the 12 dimensions, then Z3 can unify the struct equality.
proof fn proof_lattice_distributive(a: CapLattice, b: CapLattice, c: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
        valid_lattice(c),
    ensures
        lattice_meet(a, lattice_join(b, c))
            == lattice_join(lattice_meet(a, b), lattice_meet(a, c)),
{
    proof_meet_distributes_over_join(a.f0, b.f0, c.f0);
    proof_meet_distributes_over_join(a.f1, b.f1, c.f1);
    proof_meet_distributes_over_join(a.f2, b.f2, c.f2);
    proof_meet_distributes_over_join(a.f3, b.f3, c.f3);
    proof_meet_distributes_over_join(a.f4, b.f4, c.f4);
    proof_meet_distributes_over_join(a.f5, b.f5, c.f5);
    proof_meet_distributes_over_join(a.f6, b.f6, c.f6);
    proof_meet_distributes_over_join(a.f7, b.f7, c.f7);
    proof_meet_distributes_over_join(a.f8, b.f8, c.f8);
    proof_meet_distributes_over_join(a.f9, b.f9, c.f9);
    proof_meet_distributes_over_join(a.f10, b.f10, c.f10);
    proof_meet_distributes_over_join(a.f11, b.f11, c.f11);
}

/// Top is identity for product meet.
proof fn proof_lattice_meet_top(a: CapLattice)
    requires
        valid_lattice(a),
    ensures
        lattice_meet(a, lattice_top()) == a,
{
}

/// Bottom is identity for product join.
proof fn proof_lattice_join_bot(a: CapLattice)
    requires
        valid_lattice(a),
    ensures
        lattice_join(a, lattice_bot()) == a,
{
}

/// Product order is consistent with meet: a ≤ b iff meet(a, b) = a
proof fn proof_lattice_order_consistent(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        lattice_leq(a, b) <==> lattice_meet(a, b) == a,
{
}

// ============================================================================
// Trifecta Detection
// ============================================================================

/// Models the lethal trifecta risk assessment.
///
/// The trifecta is complete when ALL THREE are present at ≥ LowRisk:
/// 1. Private data access (read_files OR glob_search OR grep_search)
/// 2. Untrusted content (web_fetch OR web_search)
/// 3. Exfiltration vector (git_push OR create_pr OR run_bash)
pub open spec fn has_private_access(l: CapLattice) -> bool {
    l.f0 >= 1 || l.f4 >= 1 || l.f5 >= 1  // read_files, glob_search, grep_search
}

pub open spec fn has_untrusted_content(l: CapLattice) -> bool {
    l.f6 >= 1 || l.f7 >= 1  // web_search, web_fetch
}

pub open spec fn has_exfiltration(l: CapLattice) -> bool {
    l.f3 >= 1 || l.f9 >= 1 || l.f10 >= 1  // run_bash, git_push, create_pr
}

pub open spec fn is_trifecta_complete(l: CapLattice) -> bool {
    has_private_access(l) && has_untrusted_content(l) && has_exfiltration(l)
}

/// Meet can only decrease or maintain trifecta risk (monotonicity).
///
/// If neither a nor b has the trifecta, their meet doesn't either.
/// This is because meet takes the min of each component, so if a component
/// is Never in either input, it's Never in the output.
proof fn proof_trifecta_meet_monotone(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
        !is_trifecta_complete(a),
    ensures
        !is_trifecta_complete(lattice_meet(a, b)),
{
}

/// The nucleus (normalize) is deflationary: lattice_leq(meet(a, b), a).
/// Meet of a with anything is ≤ a.
proof fn proof_meet_deflationary(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        lattice_leq(lattice_meet(a, b), a),
{
}

/// Meet preserves the valid_lattice invariant.
proof fn proof_meet_preserves_validity(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        valid_lattice(lattice_meet(a, b)),
{
}

/// Join preserves the valid_lattice invariant.
proof fn proof_join_preserves_validity(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        valid_lattice(lattice_join(a, b)),
{
}

// ============================================================================
// Obligations: modeled as 3 booleans (the exfiltration gates)
// ============================================================================

/// Models the obligations relevant to the trifecta nucleus.
///
/// In the real code, Obligations is a BTreeSet<Operation>. For verification
/// we only model the 3 exfiltration-vector obligations that the nucleus
/// operator can add: run_bash, git_push, create_pr.
///
/// More obligations = more constrained = SMALLER in the lattice order.
/// (Obligations order is REVERSED: superset ≤ subset)
pub struct Obs {
    pub run_bash: bool,   // requires approval for run_bash
    pub git_push: bool,   // requires approval for git_push
    pub create_pr: bool,  // requires approval for create_pr
}

/// Obligations partial order: more obligations = smaller (more constrained).
/// a ≤ b iff a.obligations ⊇ b.obligations
pub open spec fn obs_leq(a: Obs, b: Obs) -> bool {
    // a ≤ b means a has at least all obligations b has
    // (a is more or equally constrained)
    (b.run_bash ==> a.run_bash)
    && (b.git_push ==> a.git_push)
    && (b.create_pr ==> a.create_pr)
}

/// Union of obligations (meet in obligation space = more constrained).
pub open spec fn obs_union(a: Obs, b: Obs) -> Obs {
    Obs {
        run_bash: a.run_bash || b.run_bash,
        git_push: a.git_push || b.git_push,
        create_pr: a.create_pr || b.create_pr,
    }
}

/// Intersection of obligations (join in obligation space = less constrained).
pub open spec fn obs_intersection(a: Obs, b: Obs) -> Obs {
    Obs {
        run_bash: a.run_bash && b.run_bash,
        git_push: a.git_push && b.git_push,
        create_pr: a.create_pr && b.create_pr,
    }
}

/// Empty obligations (no approval required = top of obligation lattice).
pub open spec fn obs_empty() -> Obs {
    Obs { run_bash: false, git_push: false, create_pr: false }
}

/// Full obligations (all approvals required = bottom of obligation lattice).
pub open spec fn obs_full() -> Obs {
    Obs { run_bash: true, git_push: true, create_pr: true }
}

// ============================================================================
// Full Permission Model: Capabilities × Obligations
// ============================================================================

/// The permission lattice product: capabilities and obligations.
///
/// In the real code this also includes paths, budget, commands, time —
/// but the nucleus operator only touches capabilities and obligations,
/// so we model just those two dimensions.
pub struct Perm {
    pub caps: CapLattice,
    pub obs: Obs,
    pub trifecta_constraint: bool,
}

/// Compute the trifecta obligations for a given capability set.
///
/// If the trifecta is complete, returns obligations requiring approval
/// for each exfiltration vector that is ≥ LowRisk.
pub open spec fn trifecta_obligations(caps: CapLattice) -> Obs {
    if is_trifecta_complete(caps) {
        Obs {
            run_bash: caps.f3 >= 1,   // run_bash ≥ LowRisk
            git_push: caps.f9 >= 1,   // git_push ≥ LowRisk
            create_pr: caps.f10 >= 1, // create_pr ≥ LowRisk
        }
    } else {
        obs_empty()
    }
}

/// The nucleus operator ν: normalize a permission by adding trifecta obligations.
///
/// This models lattice_guard::PermissionLattice::normalize().
/// If trifecta_constraint is true and the trifecta is complete,
/// add approval obligations for the exfiltration vectors.
pub open spec fn nucleus(p: Perm) -> Perm {
    if p.trifecta_constraint {
        Perm {
            caps: p.caps,
            obs: obs_union(p.obs, trifecta_obligations(p.caps)),
            trifecta_constraint: true,
        }
    } else {
        p
    }
}

/// Permission meet: capabilities meet + obligations union + trifecta enforcement.
///
/// Models PermissionLattice::meet() from lattice.rs.
pub open spec fn perm_meet(a: Perm, b: Perm) -> Perm {
    let caps = lattice_meet(a.caps, b.caps);
    let obs = obs_union(a.obs, b.obs);
    let enforce = a.trifecta_constraint || b.trifecta_constraint;
    let final_obs = if enforce {
        obs_union(obs, trifecta_obligations(caps))
    } else {
        obs
    };
    Perm {
        caps: caps,
        obs: final_obs,
        trifecta_constraint: enforce,
    }
}

/// Permission partial order: caps ≤ AND obligations ≤ (more obligations = smaller).
pub open spec fn perm_leq(a: Perm, b: Perm) -> bool {
    lattice_leq(a.caps, b.caps) && obs_leq(a.obs, b.obs)
}

/// Valid permission: all capabilities valid, trifecta constraint is true.
pub open spec fn valid_perm(p: Perm) -> bool {
    valid_lattice(p.caps) && p.trifecta_constraint
}

// ============================================================================
// Nucleus Operator Proofs — The Three Laws
// ============================================================================

// --- Law 1: Idempotency ---

/// ν(ν(x)) = ν(x) — applying the nucleus twice equals applying it once.
///
/// This is the key idempotency property. After normalization, re-normalizing
/// changes nothing because the trifecta obligations are already present.
proof fn proof_nucleus_idempotent(p: Perm)
    requires
        valid_perm(p),
    ensures
        nucleus(nucleus(p)) == nucleus(p),
{
    // After first application, trifecta_constraint is true and obligations
    // already include trifecta_obligations(caps). The second application
    // unions the same obligations again, which is idempotent (a || a == a).
}

// --- Law 2: Deflationary ---

/// ν(x) ≤ x — the nucleus only adds obligations, never removes them,
/// and never increases capabilities.
///
/// Since obligations use reversed order (more obligations = smaller),
/// adding obligations makes the result ≤ the input.
proof fn proof_nucleus_deflationary(p: Perm)
    requires
        valid_perm(p),
    ensures
        perm_leq(nucleus(p), p),
{
    // Capabilities are unchanged (same caps), so caps ≤ holds trivially.
    // Obligations: nucleus(p).obs = union(p.obs, trifecta_obs(p.caps))
    // which is a superset of p.obs, so obs_leq holds.
}

// --- Law 3: Meet Preservation — DOES NOT HOLD ---
//
// The nucleus ν does NOT distribute over meets in general:
//   ν(x ∧ y) ≠ ν(x) ∧ ν(y)
//
// The fundamental reason: trifecta_obligations is a THRESHOLD function.
// When we meet two permissions, the meet can destroy the trifecta
// (e.g., removing all private access), losing the obligations that
// ν would have added to the individual inputs.
//
// Concretely: if a has full capabilities (trifecta complete) and
// b has no private access (trifecta incomplete), then:
//   - meet(a,b) has no private access → trifecta incomplete → ν adds nothing
//   - But ν(a) already has trifecta obligations, which persist in ν(a) ∧ ν(b)
//
// This means the nucleus as defined is NOT a nucleus in the frame-theoretic
// sense. It IS an idempotent, deflationary operator (a "kernel operator"),
// but without meet preservation the quotient fixpoints don't automatically
// form a sublattice under the raw meet.
//
// However, the QUOTIENT meet (perm_meet, which normalizes after meeting)
// always produces fixed points — see proof_quotient_meet_is_fixed_point.

/// Counterexample: ν does not preserve meets.
///
/// Witness: a = full caps (trifecta complete), b = no private access.
/// LHS ν(a∧b) has no trifecta obligations; RHS (ν(a))∧(ν(b)) does.
proof fn proof_nucleus_not_meet_preserving()
    ensures
        ({
            let a = Perm {
                caps: lattice_top(),
                obs: obs_empty(),
                trifecta_constraint: true,
            };
            let b = Perm {
                caps: CapLattice {
                    f0: 0, f1: 2, f2: 2, f3: 2, f4: 0, f5: 0,
                    f6: 2, f7: 2, f8: 2, f9: 2, f10: 2, f11: 2,
                },
                obs: obs_empty(),
                trifecta_constraint: true,
            };
            // ν(meet(a,b)) ≠ meet(ν(a), ν(b))
            nucleus(perm_meet(a, b)) != perm_meet(nucleus(a), nucleus(b))
        }),
{
}

/// The quotient meet always produces fixed points of ν.
///
/// Since perm_meet already applies trifecta_obligations internally,
/// applying ν again is idempotent: ν(perm_meet(a,b)) = perm_meet(a,b).
/// This is the correct algebraic structure — the quotient meet IS the
/// normalized meet, so fixed points are closed under it.
proof fn proof_quotient_meet_is_fixed_point(a: Perm, b: Perm)
    requires
        valid_perm(a),
        valid_perm(b),
    ensures
        nucleus(perm_meet(a, b)) == perm_meet(a, b),
{
    // perm_meet already unions trifecta_obligations(meet_caps) into obs.
    // nucleus unions trifecta_obligations(meet_caps) again — idempotent.
}

/// The quotient meet is commutative: perm_meet(a,b) = perm_meet(b,a).
proof fn proof_quotient_meet_commutative(a: Perm, b: Perm)
    requires
        valid_perm(a),
        valid_perm(b),
    ensures
        perm_meet(a, b) == perm_meet(b, a),
{
    // lattice_meet commutative, obs_union commutative, || commutative.
}

// ============================================================================
// Additional Nucleus Properties
// ============================================================================

// --- Monotonicity — DOES NOT HOLD ---
//
// The nucleus is NOT monotone in general: x ≤ y does NOT imply ν(x) ≤ ν(y).
//
// The issue: if a ≤ b (fewer caps, more obligations), then b might have
// the trifecta complete while a doesn't (a has fewer capabilities, possibly
// below the threshold). The nucleus adds obligations to b but not to a,
// making ν(b) more constrained than ν(a) in the obligation dimension —
// but ν(a) should be MORE constrained for ν(a) ≤ ν(b) to hold.
//
// This is the dual of the meet preservation failure: the threshold
// function is_trifecta_complete is upward-monotone in capabilities,
// but the OBLIGATION addition is downward in the permission order.

/// Counterexample: ν is not monotone.
///
/// Witness: a has no private access (trifecta incomplete), b has all caps.
/// a ≤ b holds, but ν(a) has no trifecta obligations while ν(b) does,
/// so ν(a) ≤ ν(b) fails (ν(a) has fewer obligations = LARGER, not smaller).
proof fn proof_nucleus_not_monotone()
    ensures
        ({
            let a = Perm {
                caps: CapLattice {
                    f0: 0, f1: 2, f2: 2, f3: 2, f4: 0, f5: 0,
                    f6: 2, f7: 2, f8: 2, f9: 2, f10: 2, f11: 2,
                },
                obs: obs_empty(),
                trifecta_constraint: true,
            };
            let b = Perm {
                caps: lattice_top(),
                obs: obs_empty(),
                trifecta_constraint: true,
            };
            // a ≤ b holds ...
            perm_leq(a, b)
            // ... but ν(a) ≤ ν(b) does not
            && !perm_leq(nucleus(a), nucleus(b))
        }),
{
}

/// Trifecta completeness is upward-monotone in capabilities.
///
/// If a has fewer capabilities than b, and a triggers the trifecta,
/// then b also triggers the trifecta. (Each trifecta component is
/// a disjunction of capability levels ≥ 1, and meet only decreases.)
proof fn proof_trifecta_upward_monotone(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
        lattice_leq(a, b),
        is_trifecta_complete(a),
    ensures
        is_trifecta_complete(b),
{
}

/// The nucleus IS monotone on fixed points (trivially: it's the identity).
///
/// If both a and b are already normalized (fixed points of ν),
/// then ν(a) = a ≤ b = ν(b). The monotonicity failure only occurs
/// when the nucleus CHANGES something — on its image, it's harmless.
proof fn proof_nucleus_monotone_on_fixed_points(a: Perm, b: Perm)
    requires
        valid_perm(a),
        valid_perm(b),
        nucleus(a) == a,
        nucleus(b) == b,
        perm_leq(a, b),
    ensures
        perm_leq(nucleus(a), nucleus(b)),
{
}

/// Fixed points of the nucleus are exactly the "safe" configurations.
///
/// A permission is a fixed point (ν(x) = x) iff the trifecta obligations
/// are already present in the obligations set.
proof fn proof_nucleus_fixed_point_characterization(p: Perm)
    requires
        valid_perm(p),
    ensures
        (nucleus(p) == p) <==> (
            obs_union(p.obs, trifecta_obligations(p.caps)) == p.obs
        ),
{
}

/// Trifecta obligations are monotone under meet: if one input doesn't have
/// the trifecta, the meet doesn't either, so obligations don't increase.
proof fn proof_trifecta_obligations_meet_safe(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
        !is_trifecta_complete(a),
    ensures
        trifecta_obligations(lattice_meet(a, b)) == obs_empty(),
{
    // If a doesn't have the trifecta, meet(a,b) can't either
    // (meet only reduces capabilities). trifecta_obligations returns empty.
    proof_trifecta_meet_monotone(a, b);
}

/// The nucleus maps the top element (full permissions) to a safe configuration
/// with exfiltration obligations.
proof fn proof_nucleus_top_has_obligations(p: Perm)
    requires
        valid_perm(p),
        p.caps == lattice_top(),
    ensures
        nucleus(p).obs.run_bash,
        nucleus(p).obs.git_push,
        nucleus(p).obs.create_pr,
{
    // Top has all capabilities at Always (2), so trifecta is complete.
    // All exfiltration vectors are at Always >= LowRisk, so all get obligations.
}

/// The nucleus is the identity on the bottom element (no capabilities).
proof fn proof_nucleus_bottom_is_identity(p: Perm)
    requires
        valid_perm(p),
        p.caps == lattice_bot(),
    ensures
        nucleus(p).obs == p.obs,
{
    // Bottom has all capabilities at Never (0), so trifecta is not complete.
    // trifecta_obligations returns empty, union with empty = identity.
}

// ============================================================================
// Obligation Lattice Proofs
// ============================================================================

/// obs_union is commutative.
proof fn proof_obs_union_commutative(a: Obs, b: Obs)
    ensures
        obs_union(a, b) == obs_union(b, a),
{
}

/// obs_union is associative.
proof fn proof_obs_union_associative(a: Obs, b: Obs, c: Obs)
    ensures
        obs_union(obs_union(a, b), c) == obs_union(a, obs_union(b, c)),
{
}

/// obs_union is idempotent.
proof fn proof_obs_union_idempotent(a: Obs)
    ensures
        obs_union(a, a) == a,
{
}

/// obs_empty is identity for obs_union.
proof fn proof_obs_union_identity(a: Obs)
    ensures
        obs_union(a, obs_empty()) == a,
{
}

/// obs_intersection is commutative.
proof fn proof_obs_intersection_commutative(a: Obs, b: Obs)
    ensures
        obs_intersection(a, b) == obs_intersection(b, a),
{
}

/// obs_intersection is associative.
proof fn proof_obs_intersection_associative(a: Obs, b: Obs, c: Obs)
    ensures
        obs_intersection(obs_intersection(a, b), c)
            == obs_intersection(a, obs_intersection(b, c)),
{
}

/// obs_full is identity for obs_intersection.
proof fn proof_obs_intersection_identity(a: Obs)
    ensures
        obs_intersection(a, obs_full()) == a,
{
}

/// Absorption: obs_union(a, obs_intersection(a, b)) == a
proof fn proof_obs_absorption(a: Obs, b: Obs)
    ensures
        obs_union(a, obs_intersection(a, b)) == a,
{
}

/// obs_leq is reflexive.
proof fn proof_obs_leq_reflexive(a: Obs)
    ensures
        obs_leq(a, a),
{
}

/// obs_leq is transitive.
proof fn proof_obs_leq_transitive(a: Obs, b: Obs, c: Obs)
    requires
        obs_leq(a, b),
        obs_leq(b, c),
    ensures
        obs_leq(a, c),
{
}

/// obs_union produces the meet (greatest lower bound) in obligation order.
proof fn proof_obs_union_is_meet(a: Obs, b: Obs)
    ensures
        obs_leq(obs_union(a, b), a),
        obs_leq(obs_union(a, b), b),
{
}

// ============================================================================
// Fixed Point Helper Lemmas
// ============================================================================

/// A fixed point's obligations subsume its trifecta obligations.
///
/// If ν(p) = p, then p.obs already includes trifecta_obligations(p.caps).
/// This follows directly from the fixed point characterization.
proof fn lemma_fixed_point_includes_trifecta(p: Perm)
    requires
        valid_perm(p),
        nucleus(p) == p,
    ensures
        obs_union(p.obs, trifecta_obligations(p.caps)) == p.obs,
{
    // nucleus(p) = Perm { caps: p.caps, obs: union(p.obs, trifecta_obs(p.caps)), ... }
    // nucleus(p) == p implies union(p.obs, trifecta_obs(p.caps)) == p.obs
}

/// When both inputs are fixed points, trifecta_obligations of their meet
/// is subsumed by the union of their obligations.
///
/// Key insight: if trifecta is complete for meet(a,b), then by upward
/// monotonicity it's complete for both a and b. Each trifecta obligation
/// flag in the meet (e.g., run_bash) requires min(a.f3, b.f3) >= 1,
/// meaning a.f3 >= 1, so trifecta_obligations(a).run_bash = true,
/// and since a is a fixed point, a.obs.run_bash = true.
proof fn lemma_trifecta_obs_meet_subsumed(a: Perm, b: Perm)
    requires
        valid_perm(a),
        valid_perm(b),
        nucleus(a) == a,
        nucleus(b) == b,
    ensures
        obs_union(obs_union(a.obs, b.obs), trifecta_obligations(lattice_meet(a.caps, b.caps)))
            == obs_union(a.obs, b.obs),
{
    // First, establish that a.obs and b.obs already include their trifecta obs.
    lemma_fixed_point_includes_trifecta(a);
    lemma_fixed_point_includes_trifecta(b);

    // For the meet's trifecta obligations, we need:
    // trifecta_obs(meet(a,b)) subsumed by union(a.obs, b.obs)
    //
    // Case 1: trifecta NOT complete for meet(a,b).
    //   Then trifecta_obligations returns empty. union with empty = identity. ✓
    //
    // Case 2: trifecta IS complete for meet(a,b).
    //   Since meet(a,b) ≤ a and meet(a,b) ≤ b (deflationary),
    //   by trifecta upward monotonicity, trifecta is complete for a and b.
    //
    //   For each flag (e.g., run_bash):
    //     trifecta_obs(meet).run_bash = true
    //     → meet.f3 >= 1 → min(a.f3, b.f3) >= 1 → a.f3 >= 1
    //     → trifecta_obs(a).run_bash = true (since trifecta complete for a)
    //     → a.obs.run_bash = true (since a is fixed point)
    //     → union(a.obs, b.obs).run_bash = true ✓
    //
    //   Same for git_push (f9) and create_pr (f10).
    //
    // Z3 handles this by unfolding the boolean definitions.
    let meet_caps = lattice_meet(a.caps, b.caps);
    proof_meet_preserves_validity(a.caps, b.caps);
    proof_meet_deflationary(a.caps, b.caps);

    if is_trifecta_complete(meet_caps) {
        // Trifecta is complete for the meet. By upward monotonicity
        // (meet ≤ a and meet ≤ b), trifecta is complete for both a and b.
        proof_trifecta_upward_monotone(meet_caps, a.caps);
        proof_trifecta_upward_monotone(meet_caps, b.caps);
        // Now Z3 knows:
        //   is_trifecta_complete(a.caps) && is_trifecta_complete(b.caps)
        //   a.obs includes trifecta_obs(a.caps) (from fixed point property)
        //   Each flag in trifecta_obs(meet) implies the flag in trifecta_obs(a)
        //   which implies the flag in a.obs.
    } else {
        // Trifecta not complete for meet → trifecta_obligations = empty.
        // Union with empty is identity. Trivially holds.
    }
}

/// On fixed points, perm_meet simplifies: the trifecta_obligations term
/// is redundant because it's already subsumed by the input obligations.
proof fn lemma_perm_meet_on_fixed_points(a: Perm, b: Perm)
    requires
        valid_perm(a),
        valid_perm(b),
        nucleus(a) == a,
        nucleus(b) == b,
    ensures
        perm_meet(a, b).obs == obs_union(a.obs, b.obs),
        perm_meet(a, b).caps == lattice_meet(a.caps, b.caps),
        perm_meet(a, b).trifecta_constraint == true,
{
    lemma_trifecta_obs_meet_subsumed(a, b);
}

// ============================================================================
// Quotient Meet Associativity (on Fixed Points)
// ============================================================================

/// **The key algebraic property**: perm_meet is associative on fixed points.
///
/// This is what the real code relies on — all PermissionLattice values
/// are constructed via normalize(), so they're fixed points of ν.
/// The associativity of the quotient meet guarantees that policy
/// composition is well-defined regardless of evaluation order.
///
/// The proof strategy:
/// 1. On fixed points, perm_meet.obs = union(a.obs, b.obs) (helper lemma)
/// 2. Boolean union is associative
/// 3. Capability meet is associative
/// 4. Therefore the triple product is equal
proof fn proof_quotient_meet_associative_on_fixed_points(a: Perm, b: Perm, c: Perm)
    requires
        valid_perm(a),
        valid_perm(b),
        valid_perm(c),
        nucleus(a) == a,
        nucleus(b) == b,
        nucleus(c) == c,
    ensures
        perm_meet(perm_meet(a, b), c) == perm_meet(a, perm_meet(b, c)),
{
    // Step 1: Show perm_meet(a,b) is a fixed point
    // (already proved: proof_quotient_meet_is_fixed_point)
    // But we need valid_lattice for the intermediate too.
    proof_meet_preserves_validity(a.caps, b.caps);
    proof_meet_preserves_validity(b.caps, c.caps);

    // Step 2: Show obs simplifies on fixed points
    lemma_perm_meet_on_fixed_points(a, b);
    lemma_perm_meet_on_fixed_points(b, c);

    // Step 3: perm_meet(a,b) is a fixed point, so we can apply the lemma again
    // We need nucleus(perm_meet(a,b)) == perm_meet(a,b)
    // This is proof_quotient_meet_is_fixed_point.
    // And valid_perm(perm_meet(a,b)).

    // Step 4: The intermediate meets are fixed points
    let ab = perm_meet(a, b);
    let bc = perm_meet(b, c);

    // ab and bc have trifecta_constraint = true and valid caps
    assert(valid_lattice(ab.caps));
    assert(valid_lattice(bc.caps));
    assert(ab.trifecta_constraint == true);
    assert(bc.trifecta_constraint == true);

    // Prove ab and bc are fixed points so we can use the lemma
    assert(nucleus(ab) == ab) by {
        lemma_trifecta_obs_meet_subsumed(a, b);
    }
    assert(nucleus(bc) == bc) by {
        lemma_trifecta_obs_meet_subsumed(b, c);
    }

    // Now apply the simplification to the triple meets
    lemma_perm_meet_on_fixed_points(ab, c);
    lemma_perm_meet_on_fixed_points(a, bc);

    // At this point Z3 knows:
    // perm_meet(ab, c).obs = union(ab.obs, c.obs) = union(union(a.obs, b.obs), c.obs)
    // perm_meet(a, bc).obs = union(a.obs, bc.obs) = union(a.obs, union(b.obs, c.obs))
    // These are equal by associativity of boolean ||.

    // And caps:
    // perm_meet(ab, c).caps = meet(meet(a.caps, b.caps), c.caps)
    // perm_meet(a, bc).caps = meet(a.caps, meet(b.caps, c.caps))
    // Equal by lattice meet associativity.
    proof_lattice_meet_associative(a.caps, b.caps, c.caps);

    // And trifecta_constraint = true on both sides.
}

/// Counterexample: perm_meet is NOT associative on arbitrary (non-fixed-point) inputs.
///
/// Witness: a and b have full caps (trifecta complete) but empty obligations.
/// c has no private access. The intermediate meet(a,b) triggers trifecta
/// obligations that persist, but meet(b,c) doesn't trigger them.
proof fn proof_perm_meet_not_associative()
    ensures
        ({
            let a = Perm {
                caps: lattice_top(),
                obs: obs_empty(),
                trifecta_constraint: true,
            };
            let b = Perm {
                caps: lattice_top(),
                obs: obs_empty(),
                trifecta_constraint: true,
            };
            let c = Perm {
                caps: CapLattice {
                    f0: 0, f1: 2, f2: 2, f3: 2, f4: 0, f5: 0,
                    f6: 2, f7: 2, f8: 2, f9: 2, f10: 2, f11: 2,
                },
                obs: obs_empty(),
                trifecta_constraint: true,
            };
            perm_meet(perm_meet(a, b), c) != perm_meet(a, perm_meet(b, c))
        }),
{
    // LHS: meet(a,b) has trifecta complete → adds {t,t,t} obligations
    //       meet(that, c) carries those obligations forward
    // RHS: meet(b,c) has no private access → no trifecta obligations
    //       meet(a, that) also has no private access → no trifecta obligations
    // LHS.obs = {t,t,t}, RHS.obs = {} — provably different
}

// ============================================================================
// Delegation Monotonicity (Ceiling Theorem)
// ============================================================================

/// Delegation via meet is deflationary: the delegated permission is ≤ the delegator's.
///
/// This is the ceiling theorem: you cannot delegate more permission than you have.
/// Since meet(a, b) ≤ a for all b, the delegatee's effective permission is
/// bounded by the delegator's permission.
proof fn proof_delegation_ceiling(delegator: Perm, requested: Perm)
    requires
        valid_perm(delegator),
        valid_perm(requested),
    ensures
        perm_leq(perm_meet(delegator, requested), delegator),
{
    // perm_meet computes meet of capabilities (deflationary) and
    // union of obligations (more constrained). So the result has
    // ≤ capabilities and ≥ obligations compared to the delegator.

    // Caps: meet(delegator.caps, requested.caps) ≤ delegator.caps
    proof_meet_deflationary(delegator.caps, requested.caps);

    // Obs: union(delegator.obs, requested.obs, trifecta_obs) ⊇ delegator.obs
    // obs_leq checks that delegator.obs implies result.obs — which holds
    // since result.obs is a superset of delegator.obs.
}

/// Delegation is transitive with bounded depth:
/// meet(meet(a, b), c) ≤ meet(a, b) ≤ a
///
/// A chain of delegations produces strictly decreasing permissions.
proof fn proof_delegation_chain_monotone(a: Perm, b: Perm, c: Perm)
    requires
        valid_perm(a),
        valid_perm(b),
        valid_perm(c),
    ensures
        perm_leq(perm_meet(perm_meet(a, b), c), perm_meet(a, b)),
        perm_leq(perm_meet(a, b), a),
{
    proof_meet_preserves_validity(a.caps, b.caps);
    proof_delegation_ceiling(a, b);

    // For the chain: meet(meet(a,b), c) ≤ meet(a,b)
    // We need valid_perm for the intermediate
    let ab = perm_meet(a, b);
    assert(valid_lattice(ab.caps));
    assert(ab.trifecta_constraint == true);
    proof_delegation_ceiling(
        Perm { caps: ab.caps, obs: ab.obs, trifecta_constraint: ab.trifecta_constraint },
        c,
    );
}

// ============================================================================
// Phase 2: Enforcement Boundary Proofs
//
// These proofs verify the pure decision logic at the enforcement boundary:
// the functions that sit between the lattice algebra and I/O, deciding
// allow/deny for operations. This is where the audit found fail-open bugs.
// ============================================================================

// ============================================================================
// Tier A: Trifecta Risk Grading
// ============================================================================

/// Count of trifecta components present at ≥ LowRisk.
///
/// Models IncompatibilityConstraint::trifecta_risk() counting logic.
pub open spec fn trifecta_count(c: CapLattice) -> nat {
    (if has_private_access(c) { 1nat } else { 0nat })
    + (if has_untrusted_content(c) { 1nat } else { 0nat })
    + (if has_exfiltration(c) { 1nat } else { 0nat })
}

/// Risk level: 0=None, 1=Low, 2=Medium, 3=Complete.
///
/// Models TrifectaRisk enum as u8.
pub open spec fn trifecta_risk_level(c: CapLattice) -> nat {
    trifecta_count(c)
}

/// Trifecta count is bounded: always ∈ {0, 1, 2, 3}.
proof fn proof_trifecta_count_bounded(c: CapLattice)
    requires
        valid_lattice(c),
    ensures
        trifecta_count(c) <= 3,
{
}

/// Trifecta risk == 3 (Complete) iff all three components present.
proof fn proof_trifecta_complete_iff_count_three(c: CapLattice)
    requires
        valid_lattice(c),
    ensures
        is_trifecta_complete(c) <==> trifecta_count(c) == 3,
{
}

/// Bottom has zero trifecta risk.
proof fn proof_trifecta_bottom_zero_risk(c: CapLattice)
    requires
        c == lattice_bot(),
    ensures
        trifecta_count(c) == 0,
        !has_private_access(c),
        !has_untrusted_content(c),
        !has_exfiltration(c),
{
}

/// Risk is monotone: a ≤ b ⟹ risk(a) ≤ risk(b).
///
/// If a has fewer capabilities than b, a can't have more trifecta
/// components active than b. Each component is a disjunction of
/// capability levels ≥ 1, and since a ≤ b pointwise, if a.field ≥ 1
/// then b.field ≥ 1.
proof fn proof_trifecta_risk_monotone(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
        lattice_leq(a, b),
    ensures
        trifecta_count(a) <= trifecta_count(b),
{
    // For each component: if a has it active, b must too (since a ≤ b).
    // has_private_access: a.f0 >= 1 ∨ a.f4 >= 1 ∨ a.f5 >= 1
    //   If any of these hold for a, they hold for b (pointwise a ≤ b).
    // Same for untrusted and exfil.
    // So each bool for a implies the corresponding bool for b.
    // The count is the sum of 3 bools, so count(a) ≤ count(b).
}

/// Meet can only decrease or maintain risk.
///
/// risk(a ∧ b) ≤ risk(a) and risk(a ∧ b) ≤ risk(b).
proof fn proof_trifecta_meet_risk_decreases(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        trifecta_count(lattice_meet(a, b)) <= trifecta_count(a),
        trifecta_count(lattice_meet(a, b)) <= trifecta_count(b),
{
    proof_meet_preserves_validity(a, b);
    proof_meet_deflationary(a, b);
    // meet(a,b) ≤ a, so by risk monotonicity:
    proof_trifecta_risk_monotone(lattice_meet(a, b), a);
    // meet(a,b) ≤ b:
    let m = lattice_meet(a, b);
    // Need to show m ≤ b. Since meet is commutative, meet(b,a) = meet(a,b)
    // and meet(b,a) ≤ b.
    proof_lattice_meet_commutative(a, b);
    proof_meet_deflationary(b, a);
    proof_trifecta_risk_monotone(lattice_meet(a, b), b);
}

/// Join can only increase or maintain risk.
///
/// risk(a ∨ b) ≥ risk(a) and risk(a ∨ b) ≥ risk(b).
proof fn proof_trifecta_join_risk_increases(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        trifecta_count(lattice_join(a, b)) >= trifecta_count(a),
        trifecta_count(lattice_join(a, b)) >= trifecta_count(b),
{
    proof_join_preserves_validity(a, b);
    // join(a,b) ≥ a pointwise, so risk monotonicity applies.
    // First: a ≤ join(a,b)
    // This follows from: join(a, b) = b iff a ≤ b; or equivalently
    // a ≤ join(a,b) always holds (join is upper bound).
    // We can show: meet(a, join(a,b)) = a (absorption), which means a ≤ join(a,b).
    proof_lattice_absorption_meet_join(a, b);
    // Now lattice_leq(a, join(a,b)) by order consistency
    proof_lattice_order_consistent(a, lattice_join(a, b));
    proof_trifecta_risk_monotone(a, lattice_join(a, b));

    // Similarly b ≤ join(a,b)
    proof_lattice_join_commutative(a, b);
    proof_lattice_absorption_meet_join(b, a);
    proof_lattice_order_consistent(b, lattice_join(b, a));
    proof_trifecta_risk_monotone(b, lattice_join(a, b));
}

/// No trifecta ⟹ no obligations.
///
/// When the trifecta is not complete, trifecta_obligations returns empty.
proof fn proof_no_trifecta_no_obligations(c: CapLattice)
    requires
        valid_lattice(c),
        !is_trifecta_complete(c),
    ensures
        trifecta_obligations(c) == obs_empty(),
{
}

/// Trifecta obligations only target exfiltration operations.
///
/// The obligations produced by trifecta detection are always a subset
/// of {run_bash, git_push, create_pr} — never for read, search, etc.
/// This is structural: trifecta_obligations() only sets those 3 flags.
proof fn proof_trifecta_obligations_only_exfil(c: CapLattice)
    requires
        valid_lattice(c),
    ensures
        // The obligations struct only has run_bash/git_push/create_pr fields.
        // This proof documents that the model matches the production code:
        // obligations_for() only inserts RunBash, GitPush, CreatePr.
        trifecta_obligations(c).run_bash ==>
            (is_trifecta_complete(c) && c.f3 >= 1),
        trifecta_obligations(c).git_push ==>
            (is_trifecta_complete(c) && c.f9 >= 1),
        trifecta_obligations(c).create_pr ==>
            (is_trifecta_complete(c) && c.f10 >= 1),
{
}

/// Trifecta obligations cover ALL active exfiltration vectors.
///
/// If the trifecta is complete and an exfil vector is at ≥ LowRisk,
/// that operation gets an approval obligation. No exfil vector escapes.
proof fn proof_trifecta_obligations_cover_active_exfil(c: CapLattice)
    requires
        valid_lattice(c),
        is_trifecta_complete(c),
    ensures
        c.f3 >= 1 ==> trifecta_obligations(c).run_bash,
        c.f9 >= 1 ==> trifecta_obligations(c).git_push,
        c.f10 >= 1 ==> trifecta_obligations(c).create_pr,
{
}

// ============================================================================
// Tier B: Normalize Correctness (additional proofs)
// ============================================================================

/// Normalize preserves capabilities: ν(p).caps == p.caps.
///
/// The nucleus only adds obligations, never modifies capability levels.
/// This is critical: normalize can't accidentally remove permissions.
proof fn proof_normalize_preserves_capabilities(p: Perm)
    requires
        valid_perm(p),
    ensures
        nucleus(p).caps == p.caps,
{
}

/// Normalize only adds obligations: ν(p).obs ⊇ p.obs.
///
/// In the obligation order (reversed), this means ν(p).obs ≤ p.obs
/// (more obligations = smaller). The nucleus never removes approval gates.
proof fn proof_normalize_only_adds_obligations(p: Perm)
    requires
        valid_perm(p),
    ensures
        obs_leq(nucleus(p).obs, p.obs),
{
    // nucleus(p).obs = union(p.obs, trifecta_obs(p.caps))
    // union with anything is a superset, so leq holds.
}

/// Normalize is a no-op when trifecta constraint is disabled.
proof fn proof_normalize_noop_without_constraint(p: Perm)
    requires
        !p.trifecta_constraint,
    ensures
        nucleus(p) == p,
{
}

/// Meet of two fixed points is a fixed point.
///
/// If both a and b are already normalized, their quotient meet is too.
/// This ensures that composing two safe permission sets stays safe.
proof fn proof_safe_meet_is_safe(a: Perm, b: Perm)
    requires
        valid_perm(a),
        valid_perm(b),
        nucleus(a) == a,
        nucleus(b) == b,
    ensures
        nucleus(perm_meet(a, b)) == perm_meet(a, b),
{
    // Already proved as proof_quotient_meet_is_fixed_point,
    // but this version has the additional precondition that inputs
    // are fixed points. The proof is the same.
}

// ============================================================================
// Tier C: Guard Decision Correctness
//
// This is the critical enforcement boundary. These proofs verify that
// the GradedGuard::check_operation() logic correctly blocks dangerous
// operations under trifecta risk.
// ============================================================================

/// Operations modeled as u8 indices into the CapLattice.
///
/// We care about which are exfiltration vectors:
/// - f3 (run_bash) = op 3
/// - f9 (git_push) = op 9
/// - f10 (create_pr) = op 10
///
/// An operation is an exfiltration vector:
pub open spec fn is_exfil_op(op: nat) -> bool {
    op == 3 || op == 9 || op == 10
}

/// Check if an operation requires approval in the given obligation set.
///
/// Models PermissionLattice::requires_approval(operation).
pub open spec fn requires_approval(obs: Obs, op: nat) -> bool {
    (op == 3 && obs.run_bash)
    || (op == 9 && obs.git_push)
    || (op == 10 && obs.create_pr)
}

/// The guard decision: is an operation allowed?
///
/// Models GradedGuard::check_operation():
/// - If requires_approval AND risk == Complete → denied
/// - Otherwise → allowed
///
/// Note: in the real code, risk is computed from the *same* permission set,
/// so requires_approval && risk==Complete means the trifecta is complete
/// and this operation is an exfil vector that has an obligation.
pub open spec fn check_operation_allowed(obs: Obs, risk: nat, op: nat) -> bool {
    !(requires_approval(obs, op) && risk == 3)
}

/// Complete trifecta risk + approval required → operation denied.
///
/// This is the core enforcement invariant of GradedGuard::check_operation().
proof fn proof_check_denies_trifecta_exfil(obs: Obs, op: nat)
    requires
        requires_approval(obs, op),
    ensures
        !check_operation_allowed(obs, 3, op),
{
}

/// No approval required → operation always allowed regardless of risk.
proof fn proof_check_allows_without_obligation(obs: Obs, risk: nat, op: nat)
    requires
        !requires_approval(obs, op),
    ensures
        check_operation_allowed(obs, risk, op),
{
}

/// Risk below Complete → operation always allowed regardless of obligations.
proof fn proof_check_allows_below_complete(obs: Obs, risk: nat, op: nat)
    requires
        risk < 3,
    ensures
        check_operation_allowed(obs, risk, op),
{
}

/// **THE CRITICAL PROOF**: normalize + check_operation blocks lethal trifecta exfil.
///
/// If we normalize a permission set and then check an exfiltration operation:
/// - If the trifecta is complete, the operation is denied
/// - Specifically: for any exfil op that's active (≥ LowRisk), normalize
///   adds an obligation, and check_operation with risk=Complete denies it
///
/// This is the composition that directly addresses the audit findings:
/// "the algebra, when applied, blocks the attack."
proof fn proof_normalized_blocks_complete_exfil(p: Perm)
    requires
        valid_perm(p),
        is_trifecta_complete(p.caps),
        // run_bash is active (exfil vector present)
        p.caps.f3 >= 1,
    ensures
        // After normalize, check_operation denies run_bash
        !check_operation_allowed(nucleus(p).obs, 3, 3),
{
    // Step 1: trifecta is complete, so trifecta_obligations adds run_bash obligation
    // Step 2: nucleus(p).obs = union(p.obs, trifecta_obligations(p.caps))
    // Step 3: trifecta_obligations(p.caps).run_bash == true (since complete && f3 >= 1)
    // Step 4: therefore nucleus(p).obs.run_bash == true
    // Step 5: requires_approval(nucleus(p).obs, 3) == true
    // Step 6: check_operation_allowed(obs, 3, 3) == !(true && true) == false
}

/// Same proof for git_push (op 9).
proof fn proof_normalized_blocks_git_push_exfil(p: Perm)
    requires
        valid_perm(p),
        is_trifecta_complete(p.caps),
        p.caps.f9 >= 1,
    ensures
        !check_operation_allowed(nucleus(p).obs, 3, 9),
{
}

/// Same proof for create_pr (op 10).
proof fn proof_normalized_blocks_create_pr_exfil(p: Perm)
    requires
        valid_perm(p),
        is_trifecta_complete(p.caps),
        p.caps.f10 >= 1,
    ensures
        !check_operation_allowed(nucleus(p).obs, 3, 10),
{
}

/// Read-only profile has no exfil obligations → all operations allowed.
///
/// A permission set with no exfiltration capability cannot have
/// a complete trifecta, so no obligations are added by normalize.
proof fn proof_read_only_always_safe(p: Perm)
    requires
        valid_perm(p),
        // "read-only": no exfil vectors
        p.caps.f3 == 0, // run_bash = Never
        p.caps.f9 == 0, // git_push = Never
        p.caps.f10 == 0, // create_pr = Never
        // and no pre-existing exfil obligations
        !p.obs.run_bash,
        !p.obs.git_push,
        !p.obs.create_pr,
    ensures
        // After normalize, no exfil operations are obligated
        !requires_approval(nucleus(p).obs, 3),
        !requires_approval(nucleus(p).obs, 9),
        !requires_approval(nucleus(p).obs, 10),
        // So all operations pass the guard
        check_operation_allowed(nucleus(p).obs, trifecta_risk_level(p.caps) as nat, 3),
        check_operation_allowed(nucleus(p).obs, trifecta_risk_level(p.caps) as nat, 9),
        check_operation_allowed(nucleus(p).obs, trifecta_risk_level(p.caps) as nat, 10),
{
    // With no exfil capability, trifecta can't be complete (missing component 3).
    // So trifecta_obligations returns empty. nucleus(p).obs = union(p.obs, empty) = p.obs.
    // p.obs has no exfil obligations, so requires_approval is false for all exfil ops.
}

/// Guard monotonicity: fewer obligations → more operations allowed.
///
/// If a has fewer obligations than b (a ≥ b in obs order), then any
/// operation allowed under b's obligations is also allowed under a's.
proof fn proof_guard_monotone_obligations(a_obs: Obs, b_obs: Obs, risk: nat, op: nat)
    requires
        obs_leq(b_obs, a_obs), // b has more obligations ≤ a (fewer obligations)
        check_operation_allowed(b_obs, risk, op),
    ensures
        check_operation_allowed(a_obs, risk, op),
{
    // b_obs ≤ a_obs means b has superset of a's obligations.
    // If b allows (i.e., !(requires_approval(b_obs, op) && risk==3)),
    // either risk < 3 (then a also allows) or !requires_approval(b_obs, op).
    // If !requires_approval(b_obs, op), then since b has MORE obligations than a,
    // !requires_approval(a_obs, op) also holds.
    //
    // Actually: obs_leq(b_obs, a_obs) means b ≤ a, i.e., b has MORE obligations.
    // requires_approval(b_obs, op) && !requires_approval(a_obs, op) is possible.
    // Wait — obs_leq(b, a) means a.flags implies b.flags.
    // So if a.run_bash then b.run_bash. (a ≤ b means a has superset)
    // No wait: obs_leq(a, b) means (b.flag ==> a.flag).
    // So obs_leq(b_obs, a_obs) means (a_obs.flag ==> b_obs.flag).
    // b has at least all obligations that a has.
    //
    // If requires_approval(a_obs, op) then requires_approval(b_obs, op).
    // Contrapositive: if !requires_approval(b_obs, op) then !requires_approval(a_obs, op).
    //
    // Case: check_operation_allowed(b_obs, risk, op) = true
    //   means !(requires_approval(b_obs, op) && risk == 3)
    //   Case 1: risk != 3. Then check_operation_allowed(a_obs, risk, op) = true. ✓
    //   Case 2: !requires_approval(b_obs, op).
    //     By contrapositive above: !requires_approval(a_obs, op).
    //     So check_operation_allowed(a_obs, risk, op) = true. ✓
}

/// **END-TO-END TRIFECTA SAFETY**: The full composition.
///
/// For ANY permission set with a complete trifecta and ANY active
/// exfiltration operation: normalize → compute risk → check_operation
/// results in DENIAL.
///
/// This proves the system as a whole prevents autonomous exfiltration
/// when the lethal trifecta is present.
proof fn proof_end_to_end_trifecta_safe(p: Perm, op: nat)
    requires
        valid_perm(p),
        is_trifecta_complete(p.caps),
        is_exfil_op(op),
        // The exfil op is active in the capability set
        (op == 3 ==> p.caps.f3 >= 1),
        (op == 9 ==> p.caps.f9 >= 1),
        (op == 10 ==> p.caps.f10 >= 1),
    ensures
        // After normalize, the operation is denied at Complete risk
        !check_operation_allowed(
            nucleus(p).obs,
            trifecta_risk_level(p.caps) as nat,
            op,
        ),
{
    // Step 1: trifecta is complete → risk level = 3
    proof_trifecta_complete_iff_count_three(p.caps);
    assert(trifecta_risk_level(p.caps) == 3);

    // Step 2: normalize adds obligations for active exfil vectors
    // nucleus(p).obs = union(p.obs, trifecta_obligations(p.caps))
    // Since trifecta is complete and the exfil op is active,
    // the corresponding obligation flag is set.
    proof_trifecta_obligations_cover_active_exfil(p.caps);

    // Step 3: requires_approval is true for this op
    // Step 4: check_operation with risk=3 denies
}

// ============================================================================
// Tier D: Budget Decision Correctness
// ============================================================================

/// Budget allows a charge iff consumed + amount ≤ max.
///
/// Models AtomicBudget::charge_micro_usd() decision predicate.
/// (The actual CAS loop is not modeled — just the decision.)
pub open spec fn budget_allows(consumed: nat, max_budget: nat, amount: nat) -> bool {
    consumed + amount <= max_budget
}

/// Zero budget denies all charges (except zero-cost operations).
proof fn proof_budget_zero_denies_nonzero(amount: nat)
    requires
        amount > 0,
    ensures
        !budget_allows(0, 0, amount),
{
}

/// Charge within budget is allowed.
proof fn proof_budget_within_allows(consumed: nat, max_budget: nat, amount: nat)
    requires
        consumed + amount <= max_budget,
    ensures
        budget_allows(consumed, max_budget, amount),
{
}

/// Charge exceeding budget is denied.
proof fn proof_budget_over_denies(consumed: nat, max_budget: nat, amount: nat)
    requires
        consumed + amount > max_budget,
    ensures
        !budget_allows(consumed, max_budget, amount),
{
}

/// Budget is monotone in consumption: more consumed → fewer allowed charges.
///
/// If consumed₁ ≤ consumed₂ and a charge is allowed at consumed₂,
/// it's also allowed at consumed₁ (more budget remaining).
proof fn proof_budget_monotone_consumption(
    consumed1: nat, consumed2: nat, max_budget: nat, amount: nat,
)
    requires
        consumed1 <= consumed2,
        budget_allows(consumed2, max_budget, amount),
    ensures
        budget_allows(consumed1, max_budget, amount),
{
}

/// Budget is monotone in max: higher max → more charges allowed.
proof fn proof_budget_monotone_max(
    consumed: nat, max1: nat, max2: nat, amount: nat,
)
    requires
        max1 <= max2,
        budget_allows(consumed, max1, amount),
    ensures
        budget_allows(consumed, max2, amount),
{
}

/// Sequential charges: if two charges pass individually, their sum
/// is within budget.
proof fn proof_budget_sequential_charges(
    consumed: nat, max_budget: nat, amount1: nat, amount2: nat,
)
    requires
        budget_allows(consumed, max_budget, amount1),
        budget_allows(consumed + amount1, max_budget, amount2),
    ensures
        consumed + amount1 + amount2 <= max_budget,
{
}

fn main() {}

} // verus!
