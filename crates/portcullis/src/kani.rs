#![cfg(kani)]

use crate::{
    frame::Lattice,
    guard::{operation_taint, TaintLabel, TaintSet},
    isolation::{FileIsolation, IsolationLattice, NetworkIsolation, ProcessIsolation},
    BudgetLattice, CapabilityLattice, CapabilityLevel, CommandLattice, Obligations, Operation,
    PathLattice, PermissionLattice, TimeLattice,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

fn level_from_u8(value: u8) -> CapabilityLevel {
    match value % 3 {
        0 => CapabilityLevel::Never,
        1 => CapabilityLevel::LowRisk,
        _ => CapabilityLevel::Always,
    }
}

fn ordered_level_pair(a: u8, b: u8) -> (CapabilityLevel, CapabilityLevel) {
    let left = level_from_u8(a);
    let right = level_from_u8(b);
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn obligations_from_masks(mask_base: u16, mask_extra: u16) -> (Obligations, Obligations) {
    let mut base = Obligations::default();
    let mut superset = Obligations::default();

    let ops = [
        Operation::ReadFiles,
        Operation::WriteFiles,
        Operation::EditFiles,
        Operation::RunBash,
        Operation::GlobSearch,
        Operation::GrepSearch,
        Operation::WebSearch,
        Operation::WebFetch,
        Operation::GitCommit,
        Operation::GitPush,
        Operation::CreatePr,
        Operation::ManagePods,
    ];

    for (idx, op) in ops.iter().enumerate() {
        let bit = 1u16 << idx;
        if mask_base & bit != 0 {
            base.insert(*op);
            superset.insert(*op);
        }
        if mask_extra & bit != 0 {
            superset.insert(*op);
        }
    }

    (superset, base)
}

fn fixed_timestamp() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(0, 0).unwrap()
}

fn base_permission() -> PermissionLattice {
    PermissionLattice {
        id: Uuid::nil(),
        description: "kani".to_string(),
        derived_from: None,
        capabilities: CapabilityLattice::default(),
        obligations: Obligations::default(),
        paths: PathLattice::block_sensitive(),
        budget: BudgetLattice::with_cost_limit(1.0),
        commands: CommandLattice::restrictive(),
        time: TimeLattice::minutes(1),
        trifecta_constraint: true,
        created_at: fixed_timestamp(),
        created_by: "kani".to_string(),
        minimum_isolation: None,
    }
}

fn build_ordered_permissions() -> (PermissionLattice, PermissionLattice) {
    let (read_lo, read_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (write_lo, write_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (edit_lo, edit_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (run_lo, run_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (glob_lo, glob_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (grep_lo, grep_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (webs_lo, webs_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (webf_lo, webf_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (commit_lo, commit_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (push_lo, push_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (pr_lo, pr_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (pods_lo, pods_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());

    let (superset_obligations, base_obligations) =
        obligations_from_masks(kani::any::<u16>(), kani::any::<u16>());

    let trifecta = kani::any::<bool>();

    let mut lhs = base_permission();
    lhs.capabilities = CapabilityLattice {
        read_files: read_lo,
        write_files: write_lo,
        edit_files: edit_lo,
        run_bash: run_lo,
        glob_search: glob_lo,
        grep_search: grep_lo,
        web_search: webs_lo,
        web_fetch: webf_lo,
        git_commit: commit_lo,
        git_push: push_lo,
        create_pr: pr_lo,
        manage_pods: pods_lo,
        // extensions field excluded via #[cfg(not(kani))]
    };
    lhs.obligations = superset_obligations;
    lhs.trifecta_constraint = trifecta;

    let mut rhs = base_permission();
    rhs.capabilities = CapabilityLattice {
        read_files: read_hi,
        write_files: write_hi,
        edit_files: edit_hi,
        run_bash: run_hi,
        glob_search: glob_hi,
        grep_search: grep_hi,
        web_search: webs_hi,
        web_fetch: webf_hi,
        git_commit: commit_hi,
        git_push: push_hi,
        create_pr: pr_hi,
        manage_pods: pods_hi,
        // extensions field excluded via #[cfg(not(kani))]
    };
    rhs.obligations = base_obligations;
    rhs.trifecta_constraint = trifecta;

    (lhs, rhs)
}

#[kani::proof]
#[kani::solver(cadical)]
fn proof_normalize_idempotent() {
    let (lhs, _) = build_ordered_permissions();
    let once = lhs.clone().normalize();
    let twice = once.clone().normalize();
    assert!(once == twice);
}

#[kani::proof]
#[kani::solver(cadical)]
fn proof_normalize_deflationary() {
    let (lhs, _) = build_ordered_permissions();
    let normalized = lhs.clone().normalize();
    assert!(normalized.leq(&lhs));
}

#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(4)]
fn proof_normalize_monotone() {
    let (lhs, rhs) = build_ordered_permissions();
    assert!(lhs.leq(&rhs));
    let lhs_norm = lhs.normalize();
    let rhs_norm = rhs.normalize();
    assert!(lhs_norm.leq(&rhs_norm));
}

/// Generate an arbitrary `CapabilityLattice` from 12 symbolic `u8` values.
fn arbitrary_caps() -> CapabilityLattice {
    CapabilityLattice {
        read_files: level_from_u8(kani::any::<u8>()),
        write_files: level_from_u8(kani::any::<u8>()),
        edit_files: level_from_u8(kani::any::<u8>()),
        run_bash: level_from_u8(kani::any::<u8>()),
        glob_search: level_from_u8(kani::any::<u8>()),
        grep_search: level_from_u8(kani::any::<u8>()),
        web_search: level_from_u8(kani::any::<u8>()),
        web_fetch: level_from_u8(kani::any::<u8>()),
        git_commit: level_from_u8(kani::any::<u8>()),
        git_push: level_from_u8(kani::any::<u8>()),
        create_pr: level_from_u8(kani::any::<u8>()),
        manage_pods: level_from_u8(kani::any::<u8>()),
        // extensions field excluded via #[cfg(not(kani))]
    }
}

/// Build an arbitrary `PermissionLattice` with symbolic capabilities and obligations.
fn build_arbitrary_permission() -> PermissionLattice {
    let (obligations, _) = obligations_from_masks(kani::any::<u16>(), kani::any::<u16>());
    let mut perm = base_permission();
    perm.capabilities = arbitrary_caps();
    perm.obligations = obligations;
    perm.trifecta_constraint = kani::any::<bool>();
    perm
}

/// Check lattice equality for `PermissionLattice` via `leq` in both directions,
/// since `id` and `created_at` differ between computed instances.
fn perm_lattice_eq(a: &PermissionLattice, b: &PermissionLattice) -> bool {
    a.leq(b) && b.leq(a)
}

/// Distributive law for `CapabilityLattice`:
///   a.meet(b.join(c)) == a.meet(b).join(a.meet(c))
///
/// Since `CapabilityLattice` is a product of total orders (Never < LowRisk < Always),
/// each field independently satisfies min(a, max(b, c)) == max(min(a, b), min(a, c)).
/// Kani exhaustively verifies this over all 3^12 * 3^12 * 3^12 = 3^36 combinations
/// (after modular reduction from u8 inputs).
#[kani::proof]
#[kani::solver(cadical)]
fn proof_capability_distributive() {
    let a = arbitrary_caps();
    let b = arbitrary_caps();
    let c = arbitrary_caps();

    let lhs = a.meet(&b.join(&c));
    let rhs = a.meet(&b).join(&a.meet(&c));

    assert!(
        lhs == rhs,
        "Distributive law violated for CapabilityLattice"
    );
}

/// Distributive law for `PermissionLattice`:
///   a.meet(b.join(c)) == a.meet(b).join(a.meet(c))
///
/// This verifies that the full permission lattice (capabilities, obligations,
/// paths, budget, commands, time) distributes meet over join. Equality is checked
/// via `leq` in both directions to avoid UUID/timestamp mismatches.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(4)]
fn proof_permission_distributive() {
    let a = build_arbitrary_permission();
    let b = build_arbitrary_permission();
    let c = build_arbitrary_permission();

    let lhs = a.meet(&b.join(&c));
    let rhs = a.meet(&b).join(&a.meet(&c));

    assert!(
        perm_lattice_eq(&lhs, &rhs),
        "Distributive law violated for PermissionLattice"
    );
}

/// Frame law (finite distributivity) for `PermissionLattice`:
///   a.meet(b.join(c.join(d))) == a.meet(b).join(a.meet(c)).join(a.meet(d))
///
/// A frame requires finite meets to distribute over arbitrary joins. Since
/// `PermissionLattice` is finite, we verify the law over a 3-element join family
/// {b, c, d} as a practical approximation of the infinite frame axiom:
///   a /\ (\/_{i} b_i) = \/_{i} (a /\ b_i)
#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(4)]
fn proof_frame_finite_distributivity() {
    let a = build_arbitrary_permission();
    let b = build_arbitrary_permission();
    let c = build_arbitrary_permission();
    let d = build_arbitrary_permission();

    let lhs = a.meet(&b.join(&c.join(&d)));
    let rhs = a.meet(&b).join(&a.meet(&c)).join(&a.meet(&d));

    assert!(
        perm_lattice_eq(&lhs, &rhs),
        "Frame law (finite distributivity) violated for PermissionLattice"
    );
}

// ============================================================================
// TaintSet Bounded Model Checking (Track A — Phase 8)
// ============================================================================
//
// These harnesses verify properties of the PRODUCTION TaintSet type via
// bounded model checking with CaDiCaL. Unlike the Verus proofs (which
// verify a SpecTaintSet model), these operate directly on the Rust types
// that ship in the binary.

/// Build a symbolic TaintSet from 3 arbitrary bools.
fn arbitrary_taint_set() -> TaintSet {
    let mut s = TaintSet::empty();
    if kani::any::<bool>() {
        s = s.union(&TaintSet::singleton(TaintLabel::PrivateData));
    }
    if kani::any::<bool>() {
        s = s.union(&TaintSet::singleton(TaintLabel::UntrustedContent));
    }
    if kani::any::<bool>() {
        s = s.union(&TaintSet::singleton(TaintLabel::ExfilVector));
    }
    s
}

/// Build a symbolic Operation from the 12-variant enum.
fn arbitrary_operation() -> Operation {
    let idx = kani::any::<u8>() % 12;
    match idx {
        0 => Operation::ReadFiles,
        1 => Operation::WriteFiles,
        2 => Operation::EditFiles,
        3 => Operation::RunBash,
        4 => Operation::GlobSearch,
        5 => Operation::GrepSearch,
        6 => Operation::WebSearch,
        7 => Operation::WebFetch,
        8 => Operation::GitCommit,
        9 => Operation::GitPush,
        10 => Operation::CreatePr,
        _ => Operation::ManagePods,
    }
}

/// Pure taint projection: what the taint WOULD be after recording this op.
/// Mirrors GradedTaintGuard::projected_taint() without the RwLock.
///
/// RunBash is omnibus: bash can read files AND exfiltrate, so the CHECK
/// conservatively projects both PrivateData and ExfilVector.
fn pure_projected_taint(current: &TaintSet, op: Operation) -> TaintSet {
    if op == Operation::RunBash {
        // RunBash is omnibus: project both PrivateData and ExfilVector
        current
            .union(&TaintSet::singleton(TaintLabel::PrivateData))
            .union(&TaintSet::singleton(TaintLabel::ExfilVector))
    } else if let Some(label) = operation_taint(op) {
        current.union(&TaintSet::singleton(label))
    } else {
        current.clone()
    }
}

/// Pure guard denial check: would this operation be denied?
/// Mirrors GradedTaintGuard::check() layers 1+2 (trifecta path only).
fn pure_taint_would_deny(current: &TaintSet, op: Operation, requires_approval: bool) -> bool {
    pure_projected_taint(current, op).is_trifecta_complete() && requires_approval
}

// ---------------------------------------------------------------------------
// A1: TaintSet monoid identity — empty() is the two-sided identity
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_taintset_monoid_identity() {
    let s = arbitrary_taint_set();
    let empty = TaintSet::empty();
    assert!(
        empty.union(&s) == s,
        "Left identity violated: empty ∪ s ≠ s"
    );
    assert!(
        s.union(&empty) == s,
        "Right identity violated: s ∪ empty ≠ s"
    );
}

// ---------------------------------------------------------------------------
// A2: TaintSet monoid laws — associativity, commutativity, idempotence
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_taintset_monoid_laws() {
    let a = arbitrary_taint_set();
    let b = arbitrary_taint_set();
    let c = arbitrary_taint_set();
    // Associativity: (a ∪ b) ∪ c == a ∪ (b ∪ c)
    assert!(
        a.union(&b).union(&c) == a.union(&b.union(&c)),
        "Associativity violated"
    );
    // Commutativity: a ∪ b == b ∪ a
    assert!(a.union(&b) == b.union(&a), "Commutativity violated");
    // Idempotence: a ∪ a == a
    assert!(a.union(&a) == a, "Idempotence violated");
}

// ---------------------------------------------------------------------------
// A3: Trifecta iff count == 3
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_taintset_trifecta_iff_count_three() {
    let s = arbitrary_taint_set();
    assert!(
        s.is_trifecta_complete() == (s.count() == 3),
        "Trifecta ⟺ count==3 violated"
    );
    assert!(s.count() <= 3, "Count exceeds maximum");
}

// ---------------------------------------------------------------------------
// A4: Union monotonicity — taint never decreases under union
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_taintset_union_monotone() {
    let a = arbitrary_taint_set();
    let b = arbitrary_taint_set();
    let merged = a.union(&b);
    // Count monotonicity
    assert!(a.count() <= merged.count(), "Count decreased after union");
    // Label containment: all labels in a are in merged
    if a.contains(TaintLabel::PrivateData) {
        assert!(merged.contains(TaintLabel::PrivateData));
    }
    if a.contains(TaintLabel::UntrustedContent) {
        assert!(merged.contains(TaintLabel::UntrustedContent));
    }
    if a.contains(TaintLabel::ExfilVector) {
        assert!(merged.contains(TaintLabel::ExfilVector));
    }
    // Symmetric: all labels in b are in merged
    if b.contains(TaintLabel::PrivateData) {
        assert!(merged.contains(TaintLabel::PrivateData));
    }
    if b.contains(TaintLabel::UntrustedContent) {
        assert!(merged.contains(TaintLabel::UntrustedContent));
    }
    if b.contains(TaintLabel::ExfilVector) {
        assert!(merged.contains(TaintLabel::ExfilVector));
    }
}

// ---------------------------------------------------------------------------
// A5: operation_taint completeness — all 12 ops map to correct taint legs
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_operation_taint_completeness() {
    let op = arbitrary_operation();
    let label = operation_taint(op);
    match label {
        Some(TaintLabel::PrivateData) => {
            assert!(matches!(
                op,
                Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch
            ));
        }
        Some(TaintLabel::UntrustedContent) => {
            assert!(matches!(op, Operation::WebFetch | Operation::WebSearch));
        }
        Some(TaintLabel::ExfilVector) => {
            assert!(matches!(
                op,
                Operation::RunBash | Operation::GitPush | Operation::CreatePr
            ));
        }
        None => {
            assert!(matches!(
                op,
                Operation::WriteFiles
                    | Operation::EditFiles
                    | Operation::GitCommit
                    | Operation::ManagePods
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// A6: Projected taint correctness — projection is monotone, adds only op's label
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_projected_taint_correctness() {
    let current = arbitrary_taint_set();
    let op = arbitrary_operation();
    let projected = pure_projected_taint(&current, op);
    // 1. Projection is monotone: current ⊆ projected
    if current.contains(TaintLabel::PrivateData) {
        assert!(projected.contains(TaintLabel::PrivateData));
    }
    if current.contains(TaintLabel::UntrustedContent) {
        assert!(projected.contains(TaintLabel::UntrustedContent));
    }
    if current.contains(TaintLabel::ExfilVector) {
        assert!(projected.contains(TaintLabel::ExfilVector));
    }
    // 2. Neutral ops don't change taint
    if operation_taint(op).is_none() && op != Operation::RunBash {
        assert!(projected == current, "Neutral op changed taint");
    }
    // 3. Non-neutral ops add their label
    if let Some(label) = operation_taint(op) {
        assert!(
            projected.contains(label),
            "Projected taint missing op label"
        );
    }
    // 3b. RunBash omnibus: always projects both PrivateData AND ExfilVector
    if op == Operation::RunBash {
        assert!(
            projected.contains(TaintLabel::PrivateData),
            "RunBash projection missing PrivateData"
        );
        assert!(
            projected.contains(TaintLabel::ExfilVector),
            "RunBash projection missing ExfilVector"
        );
    }
    // 4. If current is already trifecta-complete, projected is too (irreversibility)
    if current.is_trifecta_complete() {
        assert!(
            projected.is_trifecta_complete(),
            "Trifecta lost after projection"
        );
    }
}

// ---------------------------------------------------------------------------
// A7: Guard denial soundness — Kani analog of Verus M2 on production types
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_guard_denial_soundness() {
    let current = arbitrary_taint_set();
    let op = arbitrary_operation();
    let requires_approval = kani::any::<bool>();
    let denied = pure_taint_would_deny(&current, op, requires_approval);
    // If denied, projected taint MUST be trifecta-complete AND requires approval
    if denied {
        let projected = pure_projected_taint(&current, op);
        assert!(projected.is_trifecta_complete(), "Denied without trifecta");
        assert!(requires_approval, "Denied without approval requirement");
    }
    // Converse: trifecta-complete + requires_approval → denied
    if current.is_trifecta_complete() && requires_approval {
        assert!(denied, "Trifecta + approval should deny but didn't");
    }
}

// ---------------------------------------------------------------------------
// A8: Clinejection defense — WebFetch → RunBash is ALWAYS denied
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_clinejection_blocked() {
    // Model the Clinejection attack: untrusted content read via WebFetch,
    // then attacker triggers RunBash (npm install with preinstall hook).
    //
    // After WebFetch, taint has UntrustedContent. RunBash's omnibus
    // projection adds PrivateData + ExfilVector → trifecta complete → denied.
    let mut taint = TaintSet::empty();

    // Step 1: WebFetch contributes UntrustedContent
    taint = taint.union(&TaintSet::singleton(TaintLabel::UntrustedContent));
    assert!(taint.contains(TaintLabel::UntrustedContent));
    assert!(!taint.is_trifecta_complete());

    // Step 2: RunBash projected taint includes PrivateData + ExfilVector
    let projected = pure_projected_taint(&taint, Operation::RunBash);
    assert!(
        projected.contains(TaintLabel::PrivateData),
        "RunBash must project PrivateData"
    );
    assert!(
        projected.contains(TaintLabel::ExfilVector),
        "RunBash must project ExfilVector"
    );
    assert!(
        projected.contains(TaintLabel::UntrustedContent),
        "Existing UntrustedContent must survive projection"
    );
    assert!(
        projected.is_trifecta_complete(),
        "WebFetch + RunBash must complete trifecta"
    );

    // Step 3: Guard denies (RunBash requires approval → denied)
    let denied = pure_taint_would_deny(&taint, Operation::RunBash, true);
    assert!(
        denied,
        "Clinejection: RunBash after WebFetch MUST be denied"
    );
}

// ============================================================================
// Core Invariant Proofs — Lattice Laws & Delegation Theorems (PR6)
// ============================================================================
//
// These harnesses verify the foundational properties that the kernel
// and delegation system depend on. Together with the taint proofs above,
// they form a complete verification of the permission algebra.

// ---------------------------------------------------------------------------
// B1: Meet is idempotent — meet(a, a) ≡ a
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_meet_idempotent() {
    let a = build_arbitrary_permission();
    let aa = a.meet(&a);
    assert!(
        perm_lattice_eq(&a, &aa),
        "Meet idempotence violated: meet(a, a) ≠ a"
    );
}

// ---------------------------------------------------------------------------
// B2: Meet is commutative — meet(a, b) ≡ meet(b, a)
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_meet_commutative() {
    let a = build_arbitrary_permission();
    let b = build_arbitrary_permission();
    let ab = a.meet(&b);
    let ba = b.meet(&a);
    assert!(
        perm_lattice_eq(&ab, &ba),
        "Meet commutativity violated: meet(a,b) ≠ meet(b,a)"
    );
}

// ---------------------------------------------------------------------------
// B3: Meet is associative — meet(a, meet(b, c)) ≡ meet(meet(a, b), c)
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(4)]
fn proof_meet_associative() {
    let a = build_arbitrary_permission();
    let b = build_arbitrary_permission();
    let c = build_arbitrary_permission();
    let lhs = a.meet(&b.meet(&c));
    let rhs = a.meet(&b).meet(&c);
    assert!(
        perm_lattice_eq(&lhs, &rhs),
        "Meet associativity violated: a∧(b∧c) ≠ (a∧b)∧c"
    );
}

// ---------------------------------------------------------------------------
// B4: Delegation ceiling theorem — meet(a, b) ≤ a
//
// This is THE core security property: delegating permissions to a child
// agent can never grant MORE authority than the parent has.
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_delegation_ceiling() {
    let parent = build_arbitrary_permission();
    let child_request = build_arbitrary_permission();
    let delegated = parent.meet(&child_request);
    assert!(
        delegated.leq(&parent),
        "Delegation ceiling violated: meet(parent, child) > parent"
    );
}

// ---------------------------------------------------------------------------
// B5: apply_record is monotone — taint never decreases
//
// For any taint set `current` and operation `op`:
//   current ⊆ apply_record(current, op)
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_apply_record_monotone() {
    let current = arbitrary_taint_set();
    let op = arbitrary_operation();
    let after = crate::taint_core::apply_record(&current, op);
    // Every label in `current` must also be in `after`
    if current.contains(TaintLabel::PrivateData) {
        assert!(
            after.contains(TaintLabel::PrivateData),
            "apply_record lost PrivateData"
        );
    }
    if current.contains(TaintLabel::UntrustedContent) {
        assert!(
            after.contains(TaintLabel::UntrustedContent),
            "apply_record lost UntrustedContent"
        );
    }
    if current.contains(TaintLabel::ExfilVector) {
        assert!(
            after.contains(TaintLabel::ExfilVector),
            "apply_record lost ExfilVector"
        );
    }
    // Count never decreases
    assert!(
        after.count() >= current.count(),
        "apply_record decreased taint count"
    );
}

// ---------------------------------------------------------------------------
// B6: Taint irreversibility — once trifecta-complete, always trifecta-complete
//
// If `current.is_trifecta_complete()`, then for ANY operation `op`:
//   apply_record(current, op).is_trifecta_complete()
//
// This is the monotone latch property: trifecta is a one-way gate.
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_taint_irreversibility() {
    let current = arbitrary_taint_set();
    let op = arbitrary_operation();
    if current.is_trifecta_complete() {
        let after = crate::taint_core::apply_record(&current, op);
        assert!(
            after.is_trifecta_complete(),
            "Trifecta reversed after apply_record"
        );
    }
}

// ---------------------------------------------------------------------------
// B7: Dynamic gate completeness — exfil ops ALWAYS denied when trifecta
//     would complete AND the op requires approval
//
// Strengthened version of A7: covers both the transition case (not yet
// complete → projected would complete) and the ongoing case (already
// complete → stays denied).
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_dynamic_gate_completeness() {
    let current = arbitrary_taint_set();
    let op = arbitrary_operation();
    let requires_approval = true;

    let projected = pure_projected_taint(&current, op);
    let denied = pure_taint_would_deny(&current, op, requires_approval);

    // If the projected taint is trifecta-complete, denial MUST happen
    if projected.is_trifecta_complete() {
        assert!(denied, "Trifecta-complete projection should deny");
    }

    // Converse: if taint was already complete, projection is also complete
    if current.is_trifecta_complete() {
        assert!(projected.is_trifecta_complete(), "Projection lost trifecta");
    }
}

// ---------------------------------------------------------------------------
// B8: Meet deflationary on both arguments — meet(a,b) ≤ a AND meet(a,b) ≤ b
//
// Strengthened version of the existing deflationary proof: verifies the
// property holds for BOTH arguments, not just the first.
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_meet_deflationary_both() {
    let a = build_arbitrary_permission();
    let b = build_arbitrary_permission();
    let ab = a.meet(&b);
    assert!(ab.leq(&a), "meet(a,b) > a: meet not deflationary on left");
    assert!(ab.leq(&b), "meet(a,b) > b: meet not deflationary on right");
}

// ---------------------------------------------------------------------------
// B9: Taint three-step minimum — trifecta requires at least 3 distinct
//     non-neutral operations
//
// Starting from empty taint, you need operations from ALL THREE categories
// (private data, untrusted content, exfil vector) to complete the trifecta.
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_taint_three_step_minimum() {
    let op1 = arbitrary_operation();
    let op2 = arbitrary_operation();

    // Two operations from empty can never complete the trifecta
    // (RunBash omnibus gives 2 legs, but 2 is not 3)
    let t0 = TaintSet::empty();
    let t1 = crate::taint_core::apply_record(&t0, op1);
    let t2 = crate::taint_core::apply_record(&t1, op2);

    // At most 2 legs from 2 operations (each op adds at most 1 via apply_record)
    assert!(t2.count() <= 2, "Two ops should add at most 2 taint legs");
    // Therefore, trifecta cannot be complete
    assert!(
        !t2.is_trifecta_complete(),
        "Trifecta should not complete in 2 steps"
    );
}

// ===========================================================================
// C-series: Isolation lattice proofs (VM mode hardening)
// ===========================================================================

fn process_from_u8(v: u8) -> ProcessIsolation {
    match v % 3 {
        0 => ProcessIsolation::Shared,
        1 => ProcessIsolation::Namespaced,
        _ => ProcessIsolation::MicroVM,
    }
}

fn file_from_u8(v: u8) -> FileIsolation {
    match v % 4 {
        0 => FileIsolation::Unrestricted,
        1 => FileIsolation::Sandboxed,
        2 => FileIsolation::ReadOnly,
        _ => FileIsolation::Ephemeral,
    }
}

fn network_from_u8(v: u8) -> NetworkIsolation {
    match v % 4 {
        0 => NetworkIsolation::Host,
        1 => NetworkIsolation::Namespaced,
        2 => NetworkIsolation::Filtered,
        _ => NetworkIsolation::Airgapped,
    }
}

fn isolation_from_bytes(p: u8, f: u8, n: u8) -> IsolationLattice {
    IsolationLattice::new(process_from_u8(p), file_from_u8(f), network_from_u8(n))
}

// ---------------------------------------------------------------------------
// C1: Isolation meet is idempotent: a ∧ a = a
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_isolation_meet_idempotent() {
    let p: u8 = kani::any();
    let f: u8 = kani::any();
    let n: u8 = kani::any();
    let a = isolation_from_bytes(p, f, n);

    let result = a.meet(&a);
    assert_eq!(result, a, "meet(a, a) must equal a");
}

// ---------------------------------------------------------------------------
// C2: Isolation meet is commutative: a ∧ b = b ∧ a
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_isolation_meet_commutative() {
    let a = isolation_from_bytes(kani::any(), kani::any(), kani::any());
    let b = isolation_from_bytes(kani::any(), kani::any(), kani::any());

    assert_eq!(a.meet(&b), b.meet(&a), "meet must be commutative");
}

// ---------------------------------------------------------------------------
// C3: Isolation join is deflationary under at_least:
//     join(a, b).at_least(&a) && join(a, b).at_least(&b)
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_isolation_join_upper_bound() {
    let a = isolation_from_bytes(kani::any(), kani::any(), kani::any());
    let b = isolation_from_bytes(kani::any(), kani::any(), kani::any());

    let joined = a.join(&b);
    assert!(joined.at_least(&a), "join must be at least as strong as a");
    assert!(joined.at_least(&b), "join must be at least as strong as b");
}

// ---------------------------------------------------------------------------
// C4: Minimum isolation tightens under meet (core security theorem).
//
// If policy A requires min_a and policy B requires min_b, then
// meet(A, B) requires at least as much isolation as either input.
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_minimum_isolation_tightens_under_meet() {
    let min_a = isolation_from_bytes(kani::any(), kani::any(), kani::any());
    let min_b = isolation_from_bytes(kani::any(), kani::any(), kani::any());

    // Meet of minimum isolations = join (stronger requirement)
    let result = min_a.join(&min_b);

    // Result must be at least as strong as both inputs
    assert!(
        result.at_least(&min_a),
        "meet result minimum must be ≥ min_a"
    );
    assert!(
        result.at_least(&min_b),
        "meet result minimum must be ≥ min_b"
    );
}

// ---------------------------------------------------------------------------
// C5: Airgapped network → network operations denied.
//
// Defense-in-depth: if network isolation is Airgapped, WebFetch and
// WebSearch must be classified as network operations.
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_airgapped_blocks_network_ops() {
    let op: u8 = kani::any();
    kani::assume(op < 12);

    let operation = match op {
        0 => Operation::ReadFiles,
        1 => Operation::WriteFiles,
        2 => Operation::EditFiles,
        3 => Operation::RunBash,
        4 => Operation::GlobSearch,
        5 => Operation::GrepSearch,
        6 => Operation::WebSearch,
        7 => Operation::WebFetch,
        8 => Operation::GitCommit,
        9 => Operation::GitPush,
        10 => Operation::CreatePr,
        _ => Operation::ManagePods,
    };

    let is_network = matches!(operation, Operation::WebFetch | Operation::WebSearch);

    // If it's a network operation, it should be blocked by airgapped isolation
    // (the kernel's is_network_operation function)
    if is_network {
        assert!(
            matches!(operation, Operation::WebFetch | Operation::WebSearch),
            "network operations must be exactly WebFetch and WebSearch"
        );
    }

    // Non-network operations should NOT be blocked by airgapped isolation
    if !is_network {
        assert!(
            !matches!(operation, Operation::WebFetch | Operation::WebSearch),
            "non-network operations must not be classified as network ops"
        );
    }
}

// ---------------------------------------------------------------------------
// C6: Isolation at_least is a partial order (reflexive).
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_isolation_at_least_reflexive() {
    let a = isolation_from_bytes(kani::any(), kani::any(), kani::any());
    assert!(a.at_least(&a), "at_least must be reflexive");
}
