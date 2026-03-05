//! Formally verified lattice proofs for lattice-guard.
//!
//! This crate contains Verus SMT proofs that the core algebraic structures
//! in lattice-guard satisfy their mathematical laws. These proofs are
//! machine-checked by the Z3 SMT solver via Verus.
//!
//! # Verified Properties
//!
//! ## CapabilityLevel (3-element total order: Never < LowRisk < Always)
//! - Meet (min) and Join (max) form a bounded distributive lattice
//! - All 7 lattice laws: commutativity, associativity, idempotence,
//!   absorption, distributivity, bounded (top/bottom identity)
//! - Partial order consistency: a ≤ b iff meet(a, b) = a
//!
//! ## CapabilityLattice (12-dimensional product lattice)
//! - Product of 12 CapabilityLevel dimensions
//! - Inherits all lattice laws from the component lattice
//! - Meet/join are element-wise min/max
//!
//! ## Nucleus Operator (trifecta normalization)
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
//! ## Heyting Algebra (intuitionistic implication)
//! - Implication a → b: if a ≤ b then ⊤, else b (pointwise on product)
//! - **Adjunction**: (c ∧ a) ≤ b ⟺ c ≤ (a → b) — the defining property
//! - Identity (a → a = ⊤), ex falso (⊥ → a = ⊤), modus ponens
//! - Transitivity: (a → b) ∧ (b → c) ≤ (a → c)
//! - Entailment: a ≤ b ⟺ (a → b) = ⊤
//! - Pseudo-complement: a ∧ ¬a = ⊥
//! - All properties verified both at component and 12-dimensional level
//!
//! ## Modal Operators (necessity □ and possibility ◇)
//! - Necessity: masks capabilities that have obligations (S4 interior)
//! - S4 axiom T: □p ≤ p (necessity implies actuality)
//! - S4 axiom 4: □(□p) = □p (idempotent)
//! - □ distributes over capability meet (shared obligations)
//! - Possibility: join with ceiling (S4 closure)
//! - ◇ is inflationary: p ≤ ◇p
//! - ◇ is idempotent: ◇(◇p) = ◇p
//! - ◇ distributes over capability join
//! - Modal chain: □p ≤ p ≤ ◇p
//! - Necessity breaks trifecta when full obligations present
//!
//! ## Weakening Cost Monoid
//! - (Cost, combine, zero) forms a commutative monoid
//! - combine: additive base, max multipliers
//! - Associativity, commutativity, identity element
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
// Heyting Implication (Intuitionistic Logic)
// ============================================================================
//
// The Heyting implication a → b is defined for a total order as:
//   - If a ≤ b: return ⊤ (trivially true)
//   - If a > b: return b (need to be at most b to satisfy)
//
// For the 12-dimensional product lattice, implication is computed pointwise.
// The key property is the ADJUNCTION:
//   (c ∧ a) ≤ b  ⟺  c ≤ (a → b)
//
// This models lattice_guard::heyting::level_implies and HeytingAlgebra::implies.

/// Heyting implication for capability levels.
///
/// Models `level_implies(a, b)` from heyting.rs:
/// - If a ≤ b: returns ⊤ (Always = 2)
/// - If a > b: returns b
pub open spec fn cap_implies(a: CapLevel, b: CapLevel) -> CapLevel {
    if a <= b { cap_top() } else { b }
}

/// Pointwise Heyting implication for the 12-dimensional product lattice.
///
/// Models `HeytingAlgebra::implies` for CapabilityLattice.
pub open spec fn lattice_implies(a: CapLattice, b: CapLattice) -> CapLattice {
    CapLattice {
        f0: cap_implies(a.f0, b.f0),
        f1: cap_implies(a.f1, b.f1),
        f2: cap_implies(a.f2, b.f2),
        f3: cap_implies(a.f3, b.f3),
        f4: cap_implies(a.f4, b.f4),
        f5: cap_implies(a.f5, b.f5),
        f6: cap_implies(a.f6, b.f6),
        f7: cap_implies(a.f7, b.f7),
        f8: cap_implies(a.f8, b.f8),
        f9: cap_implies(a.f9, b.f9),
        f10: cap_implies(a.f10, b.f10),
        f11: cap_implies(a.f11, b.f11),
    }
}

// --- Component-level Heyting proofs ---

/// cap_implies preserves validity.
proof fn proof_cap_implies_valid(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
    ensures
        valid_cap(cap_implies(a, b)),
{
}

/// Identity: a → a = ⊤
///
/// Every element implies itself. This is the reflexivity of entailment.
proof fn proof_heyting_identity(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_implies(a, a) == cap_top(),
{
}

/// Top implies identity: ⊤ → a = a
///
/// Modus ponens with truth: knowing ⊤ (everything) and a → b gives b.
proof fn proof_heyting_top_implies(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_implies(cap_top(), a) == a,
{
}

/// Bottom implies anything: ⊥ → a = ⊤ (ex falso quodlibet)
///
/// From nothing, everything follows.
proof fn proof_heyting_bottom_implies(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_implies(cap_bot(), a) == cap_top(),
{
}

/// Anything implies top: a → ⊤ = ⊤
///
/// Top is trivially entailed.
proof fn proof_heyting_implies_top(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_implies(a, cap_top()) == cap_top(),
{
}

/// **The Heyting adjunction** for capability levels:
///   cap_meet(c, a) ≤ b  ⟺  c ≤ cap_implies(a, b)
///
/// This is THE defining property of a Heyting algebra. It says that
/// `a → b` is the largest x such that `x ∧ a ≤ b`.
///
/// Z3 verifies this by exhaustive case analysis on {0, 1, 2}³.
proof fn proof_heyting_adjunction(a: CapLevel, b: CapLevel, c: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
        valid_cap(c),
    ensures
        cap_leq(cap_meet(c, a), b) <==> cap_leq(c, cap_implies(a, b)),
{
}

/// Modus ponens at component level: meet(a → b, a) ≤ b
///
/// Having the implication and the antecedent gives the consequent.
proof fn proof_heyting_modus_ponens(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
    ensures
        cap_leq(cap_meet(cap_implies(a, b), a), b),
{
}

/// Transitivity of implication: (a → b) ∧ (b → c) ≤ (a → c)
///
/// If a implies b and b implies c, then a implies c.
proof fn proof_heyting_transitivity(a: CapLevel, b: CapLevel, c: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
        valid_cap(c),
    ensures
        cap_leq(
            cap_meet(cap_implies(a, b), cap_implies(b, c)),
            cap_implies(a, c),
        ),
{
}

/// Pseudo-complement: a ∧ (a → ⊥) = ⊥
///
/// The pseudo-complement ¬a = a → ⊥ is always disjoint from a.
proof fn proof_heyting_pseudo_complement_disjoint(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_meet(a, cap_implies(a, cap_bot())) == cap_bot(),
{
}

// --- Product-level Heyting proofs ---

/// lattice_implies preserves validity.
proof fn proof_lattice_implies_valid(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        valid_lattice(lattice_implies(a, b)),
{
}

/// Product identity: a → a = ⊤
proof fn proof_lattice_heyting_identity(a: CapLattice)
    requires
        valid_lattice(a),
    ensures
        lattice_implies(a, a) == lattice_top(),
{
}

/// Product: ⊤ → a = a
proof fn proof_lattice_heyting_top_implies(a: CapLattice)
    requires
        valid_lattice(a),
    ensures
        lattice_implies(lattice_top(), a) == a,
{
}

/// Product: ⊥ → a = ⊤
proof fn proof_lattice_heyting_bottom_implies(a: CapLattice)
    requires
        valid_lattice(a),
    ensures
        lattice_implies(lattice_bot(), a) == lattice_top(),
{
}

/// **Product Heyting adjunction**: the defining property at lattice level.
///
///   lattice_leq(lattice_meet(c, a), b) ⟺ lattice_leq(c, lattice_implies(a, b))
///
/// Proof strategy: invoke the per-component adjunction lemma for each
/// of the 12 dimensions so Z3 can unify the conjunction.
proof fn proof_lattice_heyting_adjunction(a: CapLattice, b: CapLattice, c: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
        valid_lattice(c),
    ensures
        lattice_leq(lattice_meet(c, a), b)
            <==> lattice_leq(c, lattice_implies(a, b)),
{
    proof_heyting_adjunction(a.f0, b.f0, c.f0);
    proof_heyting_adjunction(a.f1, b.f1, c.f1);
    proof_heyting_adjunction(a.f2, b.f2, c.f2);
    proof_heyting_adjunction(a.f3, b.f3, c.f3);
    proof_heyting_adjunction(a.f4, b.f4, c.f4);
    proof_heyting_adjunction(a.f5, b.f5, c.f5);
    proof_heyting_adjunction(a.f6, b.f6, c.f6);
    proof_heyting_adjunction(a.f7, b.f7, c.f7);
    proof_heyting_adjunction(a.f8, b.f8, c.f8);
    proof_heyting_adjunction(a.f9, b.f9, c.f9);
    proof_heyting_adjunction(a.f10, b.f10, c.f10);
    proof_heyting_adjunction(a.f11, b.f11, c.f11);
}

/// Product modus ponens: meet(a → b, a) ≤ b
///
/// Follows from the adjunction with c = (a → b).
proof fn proof_lattice_heyting_modus_ponens(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        lattice_leq(lattice_meet(lattice_implies(a, b), a), b),
{
    proof_heyting_modus_ponens(a.f0, b.f0);
    proof_heyting_modus_ponens(a.f1, b.f1);
    proof_heyting_modus_ponens(a.f2, b.f2);
    proof_heyting_modus_ponens(a.f3, b.f3);
    proof_heyting_modus_ponens(a.f4, b.f4);
    proof_heyting_modus_ponens(a.f5, b.f5);
    proof_heyting_modus_ponens(a.f6, b.f6);
    proof_heyting_modus_ponens(a.f7, b.f7);
    proof_heyting_modus_ponens(a.f8, b.f8);
    proof_heyting_modus_ponens(a.f9, b.f9);
    proof_heyting_modus_ponens(a.f10, b.f10);
    proof_heyting_modus_ponens(a.f11, b.f11);
}

/// Product transitivity: (a → b) ∧ (b → c) ≤ (a → c)
proof fn proof_lattice_heyting_transitivity(a: CapLattice, b: CapLattice, c: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
        valid_lattice(c),
    ensures
        lattice_leq(
            lattice_meet(lattice_implies(a, b), lattice_implies(b, c)),
            lattice_implies(a, c),
        ),
{
    proof_heyting_transitivity(a.f0, b.f0, c.f0);
    proof_heyting_transitivity(a.f1, b.f1, c.f1);
    proof_heyting_transitivity(a.f2, b.f2, c.f2);
    proof_heyting_transitivity(a.f3, b.f3, c.f3);
    proof_heyting_transitivity(a.f4, b.f4, c.f4);
    proof_heyting_transitivity(a.f5, b.f5, c.f5);
    proof_heyting_transitivity(a.f6, b.f6, c.f6);
    proof_heyting_transitivity(a.f7, b.f7, c.f7);
    proof_heyting_transitivity(a.f8, b.f8, c.f8);
    proof_heyting_transitivity(a.f9, b.f9, c.f9);
    proof_heyting_transitivity(a.f10, b.f10, c.f10);
    proof_heyting_transitivity(a.f11, b.f11, c.f11);
}

/// Entailment equivalence: lattice_leq(a, b) ⟺ lattice_implies(a, b) = ⊤
///
/// This is the constructive interpretation: a entails b exactly when
/// the implication is trivially true.
proof fn proof_lattice_entailment(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        lattice_leq(a, b) <==> lattice_implies(a, b) == lattice_top(),
{
}

// ============================================================================
// Modal Operators: Necessity (□) and Possibility (◇)
// ============================================================================
//
// Necessity: "what can be exercised WITHOUT approval"
//   □p removes capabilities that have corresponding obligations.
//   For our model: if obs.run_bash, then caps.f3 = 0; etc.
//
// Possibility: "what COULD be exercised with escalation"
//   ◇p = join(p.caps, ceiling.caps) — the escalation ceiling.
//
// These model lattice_guard::modal::ModalPermissions.

/// Necessity operator at the capability level.
///
/// Masks capabilities that have obligations: sets them to Never (0).
/// Only models the 3 exfiltration operations tracked by our Obs type.
pub open spec fn cap_necessity(caps: CapLattice, obs: Obs) -> CapLattice {
    CapLattice {
        f0: caps.f0,
        f1: caps.f1,
        f2: caps.f2,
        f3: if obs.run_bash { cap_bot() } else { caps.f3 },
        f4: caps.f4,
        f5: caps.f5,
        f6: caps.f6,
        f7: caps.f7,
        f8: caps.f8,
        f9: if obs.git_push { cap_bot() } else { caps.f9 },
        f10: if obs.create_pr { cap_bot() } else { caps.f10 },
        f11: caps.f11,
    }
}

/// Full necessity on a Perm: reduce capabilities based on obligations.
pub open spec fn necessity(p: Perm) -> Perm {
    Perm {
        caps: cap_necessity(p.caps, p.obs),
        obs: p.obs,
        trifecta_constraint: p.trifecta_constraint,
    }
}

/// Possibility operator at the capability level: join with ceiling.
pub open spec fn cap_possibility(caps: CapLattice, ceiling: CapLattice) -> CapLattice {
    lattice_join(caps, ceiling)
}

/// □p preserves validity.
proof fn proof_necessity_preserves_validity(p: Perm)
    requires
        valid_perm(p),
    ensures
        valid_lattice(necessity(p).caps),
{
}

/// **S4 axiom T**: □A ≤ A — necessity implies actuality.
///
/// The capabilities after masking are ≤ the original capabilities,
/// because we only zero out entries (never increase them).
proof fn proof_necessity_deflationary(p: Perm)
    requires
        valid_perm(p),
    ensures
        lattice_leq(necessity(p).caps, p.caps),
{
}

/// **S4 axiom 4**: □(□A) = □A — positive introspection (idempotent).
///
/// Masking an already-masked capability is idempotent:
/// if obs.run_bash, then f3 is already 0 in □p, so masking again gives 0.
proof fn proof_necessity_idempotent(p: Perm)
    requires
        valid_perm(p),
    ensures
        necessity(necessity(p)) == necessity(p),
{
    // obligations are unchanged by necessity, so the mask is the same.
    // cap_bot() masked again is still cap_bot().
}

/// □ distributes over capability meet: □(a∧b) = □a ∧ □b
/// when both share the same obligations.
///
/// Since the mask depends on obligations (not capabilities),
/// masking the meet = meeting the masks.
proof fn proof_necessity_distributes_over_cap_meet(
    caps_a: CapLattice,
    caps_b: CapLattice,
    obs: Obs,
)
    requires
        valid_lattice(caps_a),
        valid_lattice(caps_b),
    ensures
        cap_necessity(lattice_meet(caps_a, caps_b), obs)
            == lattice_meet(cap_necessity(caps_a, obs), cap_necessity(caps_b, obs)),
{
    // For masked fields (e.g., f3 when obs.run_bash):
    //   LHS: if obs.run_bash { 0 } else { min(a.f3, b.f3) }
    //   RHS: min(if obs.run_bash { 0 } else { a.f3 }, if obs.run_bash { 0 } else { b.f3 })
    //   When obs.run_bash: LHS = 0, RHS = min(0, 0) = 0 ✓
    //   When !obs.run_bash: LHS = min(a.f3, b.f3), RHS = min(a.f3, b.f3) ✓
    // For unmasked fields: both sides are just min(a.fi, b.fi).
}

/// ◇ is inflationary: A ≤ ◇A — actuality implies possibility.
///
/// The join with ceiling can only increase capabilities.
proof fn proof_possibility_inflationary(caps: CapLattice, ceiling: CapLattice)
    requires
        valid_lattice(caps),
        valid_lattice(ceiling),
    ensures
        lattice_leq(caps, cap_possibility(caps, ceiling)),
{
}

/// ◇ is idempotent: ◇(◇A) = ◇A (when using the same ceiling).
///
/// join(join(caps, ceiling), ceiling) = join(caps, ceiling)
/// because join(ceiling, ceiling) = ceiling (idempotent).
proof fn proof_possibility_idempotent(caps: CapLattice, ceiling: CapLattice)
    requires
        valid_lattice(caps),
        valid_lattice(ceiling),
    ensures
        cap_possibility(cap_possibility(caps, ceiling), ceiling)
            == cap_possibility(caps, ceiling),
{
    proof_lattice_join_associative(caps, ceiling, ceiling);
    proof_lattice_join_idempotent(ceiling);
}

/// The modal chain: □p ≤ p ≤ ◇p (at capability level).
///
/// Necessity strips capabilities, possibility adds capabilities.
proof fn proof_modal_chain(caps: CapLattice, obs: Obs, ceiling: CapLattice)
    requires
        valid_lattice(caps),
        valid_lattice(ceiling),
    ensures
        lattice_leq(cap_necessity(caps, obs), caps),
        lattice_leq(caps, cap_possibility(caps, ceiling)),
{
}

/// ◇ distributes over capability join: ◇(a∨b) = ◇a ∨ ◇b
/// when using the same ceiling.
///
/// join(join(a, b), c) = join(join(a, c), join(b, c))
/// follows from join distributivity and commutativity.
proof fn proof_possibility_distributes_over_join(
    caps_a: CapLattice,
    caps_b: CapLattice,
    ceiling: CapLattice,
)
    requires
        valid_lattice(caps_a),
        valid_lattice(caps_b),
        valid_lattice(ceiling),
    ensures
        cap_possibility(lattice_join(caps_a, caps_b), ceiling)
            == lattice_join(
                cap_possibility(caps_a, ceiling),
                cap_possibility(caps_b, ceiling),
            ),
{
    // cap_possibility(join(a,b), c) = join(join(a,b), c)
    // We need: join(join(a,b), c) = join(join(a,c), join(b,c))
    //
    // By join distributes over meet? No — we need the dual:
    // join distributes over join is just associativity + commutativity.
    // Actually: join(join(a,b), c) vs join(join(a,c), join(b,c)).
    //
    // In a distributive lattice, join(join(a,b), c) ≠ join(join(a,c), join(b,c))
    // in general. But join(a∨b, c) = join(a,c) ∨ join(b,c) requires
    // join to distribute over join, which only holds if join is idempotent
    // (absorption). Let's check:
    //
    // join(a∨b, c) means join(join(a,b), c).
    // join(a,c) ∨ join(b,c) means join(join(a,c), join(b,c)).
    //
    // These are equal by the semilattice identity (join is ACI = associative,
    // commutative, idempotent). The multiset {a,b,c} = {a,c,b,c} modulo
    // idempotency. Both reduce to join(a, b, c).
    proof_lattice_join_associative(caps_a, caps_b, ceiling);
    proof_lattice_join_associative(caps_a, ceiling, lattice_join(caps_b, ceiling));
    proof_lattice_join_commutative(caps_b, ceiling);
    proof_lattice_join_associative(caps_a, caps_b, ceiling);

    // Actually, let's just show both sides equal join(a, join(b, c)):
    // LHS = join(join(a,b), c) = join(a, join(b, c))  [associativity]
    // RHS = join(join(a,c), join(b,c))
    //     = join(a, join(c, join(b, c)))  [assoc]
    //     = join(a, join(join(c, b), c))  [assoc on inner]
    //     = join(a, join(b, join(c, c)))  [assoc + comm]
    //     = join(a, join(b, c))           [idempotent]
    // Both sides = join(a, join(b, c)). ✓

    // Let Z3 unfold the component-wise definitions.
}

/// Necessity and possibility have disjoint effects on fixed points:
/// if p is a fixed point of ν (already normalized), then □p's capabilities
/// are exactly the "safe" subset — the trifecta cannot be complete in □p
/// when p has full trifecta obligations.
proof fn proof_necessity_breaks_trifecta_on_full_obligations(caps: CapLattice, obs: Obs)
    requires
        valid_lattice(caps),
        obs.run_bash,
        obs.git_push,
        obs.create_pr,
    ensures
        !has_exfiltration(cap_necessity(caps, obs)),
{
    // All exfiltration capabilities (f3, f9, f10) are masked to 0.
    // has_exfiltration requires at least one of f3, f9, f10 >= 1.
}

// ============================================================================
// Weakening Cost Monoid
// ============================================================================
//
// The WeakeningCost from weakening.rs has:
//   total = base * trifecta_multiplier * isolation_multiplier
//   combine(a, b) = Cost { base: a+b, trifecta: max(a,b), isolation: max(a,b) }
//
// We verify that (Cost, combine, zero) forms a commutative monoid.
// This models lattice_guard::weakening::WeakeningCost::combine.

/// Abstract weakening cost: base + two multipliers.
///
/// Invariant: multipliers ≥ 1 (enforced by valid_cost).
pub struct Cost {
    pub base: nat,
    pub trifecta_mult: nat,
    pub isolation_mult: nat,
}

/// A cost is valid when multipliers are ≥ 1.
pub open spec fn valid_cost(c: Cost) -> bool {
    c.trifecta_mult >= 1 && c.isolation_mult >= 1
}

/// The zero cost (identity for combine).
pub open spec fn cost_zero() -> Cost {
    Cost { base: 0, trifecta_mult: 1, isolation_mult: 1 }
}

/// Combine two costs: additive base, max multipliers.
pub open spec fn cost_combine(a: Cost, b: Cost) -> Cost {
    Cost {
        base: a.base + b.base,
        trifecta_mult: if a.trifecta_mult >= b.trifecta_mult {
            a.trifecta_mult
        } else {
            b.trifecta_mult
        },
        isolation_mult: if a.isolation_mult >= b.isolation_mult {
            a.isolation_mult
        } else {
            b.isolation_mult
        },
    }
}

/// The total cost: base × trifecta × isolation.
pub open spec fn cost_total(c: Cost) -> nat {
    c.base * c.trifecta_mult * c.isolation_mult
}

/// combine preserves validity.
proof fn proof_cost_combine_valid(a: Cost, b: Cost)
    requires
        valid_cost(a),
        valid_cost(b),
    ensures
        valid_cost(cost_combine(a, b)),
{
}

/// zero is valid.
proof fn proof_cost_zero_valid()
    ensures
        valid_cost(cost_zero()),
{
}

/// combine is commutative.
proof fn proof_cost_combine_commutative(a: Cost, b: Cost)
    requires
        valid_cost(a),
        valid_cost(b),
    ensures
        cost_combine(a, b) == cost_combine(b, a),
{
}

/// combine is associative.
proof fn proof_cost_combine_associative(a: Cost, b: Cost, c: Cost)
    requires
        valid_cost(a),
        valid_cost(b),
        valid_cost(c),
    ensures
        cost_combine(cost_combine(a, b), c) == cost_combine(a, cost_combine(b, c)),
{
}

/// zero is the identity for combine.
proof fn proof_cost_zero_identity(a: Cost)
    requires
        valid_cost(a),
    ensures
        cost_combine(a, cost_zero()) == a,
{
}

/// Zero cost has zero total.
proof fn proof_cost_zero_total()
    ensures
        cost_total(cost_zero()) == 0,
{
}

/// Cost total is non-negative (trivially true for nat, but documents intent).
proof fn proof_cost_total_nonneg(c: Cost)
    requires
        valid_cost(c),
    ensures
        cost_total(c) >= 0,
{
}

fn main() {}

} // verus!
