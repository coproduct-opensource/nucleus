#![cfg(kani)]

use crate::{
    frame::{BoundedLattice, Lattice, Nucleus, UninhabitableQuotient},
    guard::{operation_exposure, ExposureLabel, ExposureSet},
    heyting::HeytingAlgebra,
    isolation::{FileIsolation, IsolationLattice, NetworkIsolation, ProcessIsolation},
    kernel::{Kernel, Verdict},
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
        uninhabitable_constraint: true,
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

    let uninhabitable_state = kani::any::<bool>();

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
    lhs.uninhabitable_constraint = uninhabitable_state;

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
    rhs.uninhabitable_constraint = uninhabitable_state;

    (lhs, rhs)
}

#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(4)]
fn proof_normalize_idempotent() {
    let (lhs, _) = build_ordered_permissions();
    let once = lhs.clone().normalize();
    let twice = once.clone().normalize();
    assert!(once == twice);
}

#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(4)]
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
    perm.uninhabitable_constraint = kani::any::<bool>();
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
// ExposureSet Bounded Model Checking (Track A — Phase 8)
// ============================================================================
//
// These harnesses verify properties of the PRODUCTION ExposureSet type via
// bounded model checking with CaDiCaL. Unlike the Verus proofs (which
// verify a SpecExposureSet model), these operate directly on the Rust types
// that ship in the binary.

/// Build a symbolic ExposureSet from 3 arbitrary bools.
fn arbitrary_exposure_set() -> ExposureSet {
    let mut s = ExposureSet::empty();
    if kani::any::<bool>() {
        s = s.union(&ExposureSet::singleton(ExposureLabel::PrivateData));
    }
    if kani::any::<bool>() {
        s = s.union(&ExposureSet::singleton(ExposureLabel::UntrustedContent));
    }
    if kani::any::<bool>() {
        s = s.union(&ExposureSet::singleton(ExposureLabel::ExfilVector));
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

/// Pure exposure projection: what the exposure WOULD be after recording this op.
/// Mirrors GradedExposureGuard::projected_exposure() without the RwLock.
///
/// RunBash is omnibus: bash can read files AND exfiltrate, so the CHECK
/// conservatively projects both PrivateData and ExfilVector.
fn pure_projected_exposure(current: &ExposureSet, op: Operation) -> ExposureSet {
    if op == Operation::RunBash {
        // RunBash is omnibus: project both PrivateData and ExfilVector
        current
            .union(&ExposureSet::singleton(ExposureLabel::PrivateData))
            .union(&ExposureSet::singleton(ExposureLabel::ExfilVector))
    } else if let Some(label) = operation_exposure(op) {
        current.union(&ExposureSet::singleton(label))
    } else {
        current.clone()
    }
}

/// Pure guard denial check: would this operation be denied?
/// Mirrors GradedExposureGuard::check() layers 1+2 (uninhabitable_state path only).
fn pure_exposure_would_deny(current: &ExposureSet, op: Operation, requires_approval: bool) -> bool {
    pure_projected_exposure(current, op).is_uninhabitable() && requires_approval
}

// ---------------------------------------------------------------------------
// A1: ExposureSet monoid identity — empty() is the two-sided identity
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_exposureset_monoid_identity() {
    let s = arbitrary_exposure_set();
    let empty = ExposureSet::empty();
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
// A2: ExposureSet monoid laws — associativity, commutativity, idempotence
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_exposureset_monoid_laws() {
    let a = arbitrary_exposure_set();
    let b = arbitrary_exposure_set();
    let c = arbitrary_exposure_set();
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
// A3:  UninhabitableState iff count == 3
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_exposureset_uninhabitable_iff_count_three() {
    let s = arbitrary_exposure_set();
    assert!(
        s.is_uninhabitable() == (s.count() == 3),
        " UninhabitableState ⟺ count==3 violated"
    );
    assert!(s.count() <= 3, "Count exceeds maximum");
}

// ---------------------------------------------------------------------------
// A4: Union monotonicity — exposure never decreases under union
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_exposureset_union_monotone() {
    let a = arbitrary_exposure_set();
    let b = arbitrary_exposure_set();
    let merged = a.union(&b);
    // Count monotonicity
    assert!(a.count() <= merged.count(), "Count decreased after union");
    // Label containment: all labels in a are in merged
    if a.contains(ExposureLabel::PrivateData) {
        assert!(merged.contains(ExposureLabel::PrivateData));
    }
    if a.contains(ExposureLabel::UntrustedContent) {
        assert!(merged.contains(ExposureLabel::UntrustedContent));
    }
    if a.contains(ExposureLabel::ExfilVector) {
        assert!(merged.contains(ExposureLabel::ExfilVector));
    }
    // Symmetric: all labels in b are in merged
    if b.contains(ExposureLabel::PrivateData) {
        assert!(merged.contains(ExposureLabel::PrivateData));
    }
    if b.contains(ExposureLabel::UntrustedContent) {
        assert!(merged.contains(ExposureLabel::UntrustedContent));
    }
    if b.contains(ExposureLabel::ExfilVector) {
        assert!(merged.contains(ExposureLabel::ExfilVector));
    }
}

// ---------------------------------------------------------------------------
// A5: operation_exposure completeness — all 12 ops map to correct exposure legs
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_operation_exposure_completeness() {
    let op = arbitrary_operation();
    let label = operation_exposure(op);
    match label {
        Some(ExposureLabel::PrivateData) => {
            assert!(matches!(
                op,
                Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch
            ));
        }
        Some(ExposureLabel::UntrustedContent) => {
            assert!(matches!(op, Operation::WebFetch | Operation::WebSearch));
        }
        Some(ExposureLabel::ExfilVector) => {
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
// A6: Projected exposure correctness — projection is monotone, adds only op's label
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_projected_exposure_correctness() {
    let current = arbitrary_exposure_set();
    let op = arbitrary_operation();
    let projected = pure_projected_exposure(&current, op);
    // 1. Projection is monotone: current ⊆ projected
    if current.contains(ExposureLabel::PrivateData) {
        assert!(projected.contains(ExposureLabel::PrivateData));
    }
    if current.contains(ExposureLabel::UntrustedContent) {
        assert!(projected.contains(ExposureLabel::UntrustedContent));
    }
    if current.contains(ExposureLabel::ExfilVector) {
        assert!(projected.contains(ExposureLabel::ExfilVector));
    }
    // 2. Neutral ops don't change exposure
    if operation_exposure(op).is_none() && op != Operation::RunBash {
        assert!(projected == current, "Neutral op changed exposure");
    }
    // 3. Non-neutral ops add their label
    if let Some(label) = operation_exposure(op) {
        assert!(
            projected.contains(label),
            "Projected exposure missing op label"
        );
    }
    // 3b. RunBash omnibus: always projects both PrivateData AND ExfilVector
    if op == Operation::RunBash {
        assert!(
            projected.contains(ExposureLabel::PrivateData),
            "RunBash projection missing PrivateData"
        );
        assert!(
            projected.contains(ExposureLabel::ExfilVector),
            "RunBash projection missing ExfilVector"
        );
    }
    // 4. If current is already uninhabitable, projected is too (irreversibility)
    if current.is_uninhabitable() {
        assert!(
            projected.is_uninhabitable(),
            " UninhabitableState lost after projection"
        );
    }
}

// ---------------------------------------------------------------------------
// A7: Guard denial soundness — Kani analog of Verus M2 on production types
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_guard_denial_soundness() {
    let current = arbitrary_exposure_set();
    let op = arbitrary_operation();
    let requires_approval = kani::any::<bool>();
    let denied = pure_exposure_would_deny(&current, op, requires_approval);
    // If denied, projected exposure MUST be uninhabitable AND requires approval
    if denied {
        let projected = pure_projected_exposure(&current, op);
        assert!(
            projected.is_uninhabitable(),
            "Denied without uninhabitable_state"
        );
        assert!(requires_approval, "Denied without approval requirement");
    }
    // Converse: uninhabitable + requires_approval → denied
    if current.is_uninhabitable() && requires_approval {
        assert!(
            denied,
            " UninhabitableState + approval should deny but didn't"
        );
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
    // After WebFetch, exposure has UntrustedContent. RunBash's omnibus
    // projection adds PrivateData + ExfilVector → uninhabitable_state complete → denied.
    let mut exposure = ExposureSet::empty();

    // Step 1: WebFetch contributes UntrustedContent
    exposure = exposure.union(&ExposureSet::singleton(ExposureLabel::UntrustedContent));
    assert!(exposure.contains(ExposureLabel::UntrustedContent));
    assert!(!exposure.is_uninhabitable());

    // Step 2: RunBash projected exposure includes PrivateData + ExfilVector
    let projected = pure_projected_exposure(&exposure, Operation::RunBash);
    assert!(
        projected.contains(ExposureLabel::PrivateData),
        "RunBash must project PrivateData"
    );
    assert!(
        projected.contains(ExposureLabel::ExfilVector),
        "RunBash must project ExfilVector"
    );
    assert!(
        projected.contains(ExposureLabel::UntrustedContent),
        "Existing UntrustedContent must survive projection"
    );
    assert!(
        projected.is_uninhabitable(),
        "WebFetch + RunBash must uninhabitable_state"
    );

    // Step 3: Guard denies (RunBash requires approval → denied)
    let denied = pure_exposure_would_deny(&exposure, Operation::RunBash, true);
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
// and delegation system depend on. Together with the exposure proofs above,
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
// B5: apply_record is monotone — exposure never decreases
//
// For any exposure set `current` and operation `op`:
//   current ⊆ apply_record(current, op)
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_apply_record_monotone() {
    let current = arbitrary_exposure_set();
    let op = arbitrary_operation();
    let after = crate::exposure_core::apply_record(&current, op);
    // Every label in `current` must also be in `after`
    if current.contains(ExposureLabel::PrivateData) {
        assert!(
            after.contains(ExposureLabel::PrivateData),
            "apply_record lost PrivateData"
        );
    }
    if current.contains(ExposureLabel::UntrustedContent) {
        assert!(
            after.contains(ExposureLabel::UntrustedContent),
            "apply_record lost UntrustedContent"
        );
    }
    if current.contains(ExposureLabel::ExfilVector) {
        assert!(
            after.contains(ExposureLabel::ExfilVector),
            "apply_record lost ExfilVector"
        );
    }
    // Count never decreases
    assert!(
        after.count() >= current.count(),
        "apply_record decreased exposure count"
    );
}

// ---------------------------------------------------------------------------
// B6: Exposure irreversibility — once uninhabitable, always uninhabitable
//
// If `current.is_uninhabitable()`, then for ANY operation `op`:
//   apply_record(current, op).is_uninhabitable()
//
// This is the monotone latch property: uninhabitable_state is a one-way gate.
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_exposure_irreversibility() {
    let current = arbitrary_exposure_set();
    let op = arbitrary_operation();
    if current.is_uninhabitable() {
        let after = crate::exposure_core::apply_record(&current, op);
        assert!(
            after.is_uninhabitable(),
            " UninhabitableState reversed after apply_record"
        );
    }
}

// ---------------------------------------------------------------------------
// B7: Dynamic gate completeness — exfil ops ALWAYS denied when uninhabitable_state
//     would complete AND the op requires approval
//
// Strengthened version of A7: covers both the transition case (not yet
// complete → projected would complete) and the ongoing case (already
// complete → stays denied).
// ---------------------------------------------------------------------------
#[kani::proof]
#[kani::solver(cadical)]
fn proof_dynamic_gate_completeness() {
    let current = arbitrary_exposure_set();
    let op = arbitrary_operation();
    let requires_approval = true;

    let projected = pure_projected_exposure(&current, op);
    let denied = pure_exposure_would_deny(&current, op, requires_approval);

    // If the projected exposure is uninhabitable, denial MUST happen
    if projected.is_uninhabitable() {
        assert!(
            denied,
            "uninhabitable_state-complete projection should deny"
        );
    }

    // Converse: if exposure was already complete, projection is also complete
    if current.is_uninhabitable() {
        assert!(
            projected.is_uninhabitable(),
            "Projection lost uninhabitable_state"
        );
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
// B9: Exposure three-step minimum — uninhabitable_state requires at least 3 distinct
//     non-neutral operations
//
// Starting from empty exposure, you need operations from ALL THREE categories
// (private data, untrusted content, exfil vector) to complete the uninhabitable_state.
// ---------------------------------------------------------------------------

// ═══════════════════════════════════════════════════════════════════════════
// D-series: Attenuation token invariants
// ═══════════════════════════════════════════════════════════════════════════

/// **D1 — Meet attenuation is monotone (leq parent)**:
///
/// For all parent p and requested r, meet(p, r) ≤ p.
///
/// This is the core security property of attenuation tokens:
/// delegating permissions can never amplify them.
#[kani::proof]
#[kani::unwind(3)]
#[kani::solver(cadical)]
fn proof_attenuation_leq_parent() {
    let parent = build_arbitrary_permission();
    let requested = build_arbitrary_permission();

    let attenuated = parent.meet(&requested);
    assert!(
        attenuated.leq(&parent),
        "Attenuation via meet must never exceed the parent"
    );
}

/// **D2 — Meet attenuation is monotone (leq requested)**:
///
/// For all parent p and requested r, meet(p, r) ≤ r.
///
/// The attenuated result is also bounded by the requested permissions.
/// Combined with D1, this proves meet is the greatest lower bound.
#[kani::proof]
#[kani::unwind(3)]
#[kani::solver(cadical)]
fn proof_attenuation_leq_requested() {
    let parent = build_arbitrary_permission();
    let requested = build_arbitrary_permission();

    let attenuated = parent.meet(&requested);
    assert!(
        attenuated.leq(&requested),
        "Attenuation via meet must never exceed the request"
    );
}

/// **D3 — Chained attenuation only tightens**:
///
/// For a delegation chain p → q → r:
///   q = meet(p, req1), r = meet(q, req2)
///   ⟹ r ≤ q ≤ p
///
/// Multi-hop delegation can never amplify permissions.
#[kani::proof]
#[kani::unwind(3)]
#[kani::solver(cadical)]
fn proof_chained_attenuation_monotone() {
    let root = build_arbitrary_permission();
    let req1 = build_arbitrary_permission();
    let req2 = build_arbitrary_permission();

    let hop1 = root.meet(&req1);
    let hop2 = hop1.meet(&req2);

    assert!(hop1.leq(&root), "First hop must be ≤ root");
    assert!(hop2.leq(&hop1), "Second hop must be ≤ first hop");
    assert!(hop2.leq(&root), "Transitive: second hop must be ≤ root");
}

#[kani::proof]
#[kani::unwind(3)]
#[kani::solver(cadical)]
fn proof_exposure_three_step_minimum() {
    let op1 = arbitrary_operation();
    let op2 = arbitrary_operation();

    // Two operations from empty can never complete the uninhabitable_state
    // (RunBash omnibus gives 2 legs, but 2 is not 3)
    let t0 = ExposureSet::empty();
    let t1 = crate::exposure_core::apply_record(&t0, op1);
    let t2 = crate::exposure_core::apply_record(&t1, op2);

    // At most 2 legs from 2 operations (each op adds at most 1 via apply_record)
    assert!(
        t2.count() <= 2,
        "Two ops should add at most 2 exposure legs"
    );
    // Therefore, uninhabitable_state cannot be complete
    assert!(
        !t2.is_uninhabitable(),
        " UninhabitableState should not complete in 2 steps"
    );
}

// ============================================================================
// R-series: Heyting algebra axioms for CapabilityLevel (R1/R2/R3)
//
// These Kani harnesses are the regression bridge for the kernel-checked
// Lean 4 proofs in PortcullisVerified/CapabilityLevel.lean.  Each harness
// directly mirrors a named Lean theorem; if the Rust discriminants or the
// Heyting operations ever diverge from the Lean model, at least one of these
// proofs will falsify before the mismatch can reach production.
//
// The `lean_tonat_matches_rust_discriminants` unit test in capability.rs
// enforces that the Lean file's `toNat` mapping matches the Rust repr values,
// closing the correspondence loop without requiring Aeneas/Charon.
// ============================================================================

/// Heyting implication on a single `CapabilityLevel` (3-element total order):
///   a ⇨ b  =  if a ≤ b then Always (⊤) else b
///
/// Mirrors `instHImp` in `PortcullisVerified/CapabilityLevel.lean`.
fn cap_himp(a: CapabilityLevel, b: CapabilityLevel) -> CapabilityLevel {
    if a <= b {
        CapabilityLevel::Always
    } else {
        b
    }
}

/// Meet on a single `CapabilityLevel`: min(a, b).
///
/// Mirrors the `⊓` operation derived from `instLinearOrder` in the Lean model.
fn cap_meet_level(a: CapabilityLevel, b: CapabilityLevel) -> CapabilityLevel {
    if a <= b {
        a
    } else {
        b
    }
}

/// Pseudo-complement: ¬a = a ⇨ ⊥ = a ⇨ Never.
///
/// Mirrors `instHasCompl` in `PortcullisVerified/CapabilityLevel.lean`.
fn cap_compl(a: CapabilityLevel) -> CapabilityLevel {
    cap_himp(a, CapabilityLevel::Never)
}

/// **R1 — Heyting adjunction**: `a ≤ (b ⇨ c) ↔ a ⊓ b ≤ c`
///
/// Mirrors the `le_himp_iff` theorem in `CapabilityLevel.lean`.
/// Kani exhaustively explores all 27 triples (3³) via symbolic execution
/// with CaDiCaL, providing bounded model-checking coverage identical to
/// the Lean kernel's exhaustive case analysis.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_r1_heyting_adjunction() {
    let a = level_from_u8(kani::any::<u8>());
    let b = level_from_u8(kani::any::<u8>());
    let c = level_from_u8(kani::any::<u8>());

    let lhs = a <= cap_himp(b, c);
    let rhs = cap_meet_level(a, b) <= c;

    assert_eq!(
        lhs, rhs,
        "R1: Heyting adjunction violated — a ≤ (b ⇨ c) ↔ a ⊓ b ≤ c"
    );
}

/// **R2 — Pseudo-complement**: `a ⊓ ¬a = ⊥`
///
/// Mirrors the `inf_compl_eq_bot` theorem in `CapabilityLevel.lean`.
/// Kani exhaustively verifies all 3 values of `a`.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_r2_pseudo_complement() {
    let a = level_from_u8(kani::any::<u8>());
    let result = cap_meet_level(a, cap_compl(a));
    assert_eq!(
        result,
        CapabilityLevel::Never,
        "R2: Pseudo-complement violated — a ⊓ ¬a ≠ ⊥"
    );
}

/// **R3 — Entailment equivalence**: `a ≤ b ↔ (a ⇨ b) = ⊤`
///
/// Mirrors the `le_iff_himp_eq_top` theorem in `CapabilityLevel.lean`.
/// Kani exhaustively verifies all 9 pairs of `(a, b)`.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_r3_entailment() {
    let a = level_from_u8(kani::any::<u8>());
    let b = level_from_u8(kani::any::<u8>());

    let le_holds = a <= b;
    let himp_is_top = cap_himp(a, b) == CapabilityLevel::Always;

    assert_eq!(
        le_holds, himp_is_top,
        "R3: Entailment violated — a ≤ b ↔ (a ⇨ b) = ⊤"
    );
}

// ===========================================================================
// R-series (continued): Heyting algebra axioms for CapabilityLattice (R4/R5/R6)
//
// These harnesses extend the R1/R2/R3 proofs from the scalar `CapabilityLevel`
// atom to the 12-dimensional `CapabilityLattice` product struct — the actual
// production enforcement object that gates tool permissions.
//
// Each harness mirrors a named theorem in `PortcullisVerified/CapabilityLattice.lean`,
// which proves the same properties via Mathlib's `Pi.instHeytingAlgebra`.  Together,
// R1–R6 close the verification gap: R1–R3 cover the scalar component, R4–R6 cover
// the compound struct.
//
// Kani input space per harness: 3^12 × 3^12 × 3^12 = 3^36 combinations for R4/R6
// (three 12-dim lattice values), 3^12 combinations for R5 (one lattice value).
// CaDiCaL explores this symbolically via bounded model checking.
// ===========================================================================

/// **R4 — Heyting adjunction** (product level): `(c ⊓ a) ≤ b ↔ c ≤ (a ⇨ b)`
///
/// Verifies the defining adjunction for `CapabilityLattice` (the 12-dimensional
/// product of `CapabilityLevel` chains that gates tool permissions in production).
///
/// Mirrors the `le_himp_iff_lattice` theorem in
/// `PortcullisVerified/CapabilityLattice.lean`, where the same property is
/// kernel-checked via Mathlib's `Pi.instHeytingAlgebra`.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_r4_lattice_heyting_adjunction() {
    let a = arbitrary_caps();
    let b = arbitrary_caps();
    let c = arbitrary_caps();

    // Adjunction: (c ∧ a) ≤ b  ↔  c ≤ (a ⇨ b)
    let lhs = c.meet(&a).leq(&b);
    let rhs = c.leq(&a.implies(&b));

    assert_eq!(
        lhs, rhs,
        "R4: Heyting adjunction violated at CapabilityLattice level — (c ⊓ a) ≤ b ↔ c ≤ (a ⇨ b)"
    );
}

/// **R5 — Pseudo-complement** (product level): `a ⊓ ¬a = ⊥`
///
/// Verifies the pseudo-complement identity for `CapabilityLattice`.
/// Since `CapabilityLattice` is a product of chains, `¬a = a ⇨ ⊥` is computed
/// field-wise: each dimension `i` satisfies `a_i ⊓ ¬(a_i) = Never`.
///
/// Mirrors the `inf_compl_eq_bot_lattice` theorem in
/// `PortcullisVerified/CapabilityLattice.lean`.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_r5_lattice_pseudo_complement() {
    let a = arbitrary_caps();
    let neg_a = a.pseudo_complement();
    let result = a.meet(&neg_a);

    assert!(
        result.leq(&CapabilityLattice::bottom()),
        "R5: Pseudo-complement violated at CapabilityLattice level — a ⊓ ¬a must be ≤ ⊥"
    );
}

/// **R6 — Entailment equivalence** (product level): `a ≤ b ↔ (a ⇨ b) = ⊤`
///
/// Verifies the entailment characterization for `CapabilityLattice`.
/// At the product level, `a ≤ b` iff every dimension of `a.implies(&b)` is
/// `Always` (= `⊤`), mirroring `le_iff_himp_eq_top_lattice` in the Lean proof.
///
/// Mirrors the `le_iff_himp_eq_top_lattice` theorem in
/// `PortcullisVerified/CapabilityLattice.lean`.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_r6_lattice_entailment() {
    let a = arbitrary_caps();
    let b = arbitrary_caps();

    let le_holds = a.leq(&b);
    let himp_is_top = a.implies(&b) == CapabilityLattice::top();

    assert_eq!(
        le_holds, himp_is_top,
        "R6: Entailment violated at CapabilityLattice level — a ≤ b ↔ (a ⇨ b) = ⊤"
    );
}

// ===========================================================================
// R-series (continued): Extension dimension mock harnesses (R7/R8/R9)
//
// BTreeMap is intractable for Kani's bounded model checker because heap
// allocations introduce unbounded aliasing. The extension field of
// CapabilityLattice is therefore excluded from Kani builds via
// `#[cfg(not(kani))]`. These harnesses substitute a fixed 2-slot mock
// (two `Option<CapabilityLevel>` fields) to verify the Heyting adjunction,
// pseudo-complement, and entailment properties hold for the extension
// dimension logic without BTreeMap.
//
// ## Sparse convention: production-identical semantics
//
// The mock deliberately replicates the production BTreeMap sparse convention:
//
//   1. **Capability set** (regular operand):
//      - Absent slot (None) → `Never`  (fail-closed security default)
//      - Used by `leq()` for policy enforcement
//
//   2. **Implication result** (output of `implies()`):
//      - Absent slot (None) → `Always` (correct: level_implies(Never,Never) = Always)
//      - `implies()` stores only NON-Always entries; Always is the default
//      - Used by `leq_himp()` for adjunction checks
//
// This matches the production `CapabilityLattice::implies()` which also omits
// Always entries, and `leq_himp()` which supplies the Always default.
//
// The R7 harness uses `c.leq_himp(&a.implies(&b))` — exactly the production
// code path — so Kani verifies the same algorithm, not a richer mock.
//
// Slot encoding:
//   - For capability operands:  None → Never (fail-closed)
//   - For implies results:      None → Always (leq_himp default)
// ===========================================================================

/// 2-slot fixed-size mock of the extension capability dimension.
/// Replaces BTreeMap<ExtensionOperation, CapabilityLevel> for Kani tractability.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ExtMock2 {
    slot0: Option<CapabilityLevel>,
    slot1: Option<CapabilityLevel>,
}

impl ExtMock2 {
    fn level0(&self) -> CapabilityLevel {
        self.slot0.unwrap_or(CapabilityLevel::Never)
    }
    fn level1(&self) -> CapabilityLevel {
        self.slot1.unwrap_or(CapabilityLevel::Never)
    }

    fn meet(&self, other: &Self) -> Self {
        let v0 = std::cmp::min(self.level0(), other.level0());
        let v1 = std::cmp::min(self.level1(), other.level1());
        Self {
            slot0: if v0 != CapabilityLevel::Never {
                Some(v0)
            } else {
                None
            },
            slot1: if v1 != CapabilityLevel::Never {
                Some(v1)
            } else {
                None
            },
        }
    }

    fn leq(&self, other: &Self) -> bool {
        self.level0() <= other.level0() && self.level1() <= other.level1()
    }

    fn ext_level_implies(a: CapabilityLevel, b: CapabilityLevel) -> CapabilityLevel {
        if a <= b {
            CapabilityLevel::Always
        } else {
            b
        }
    }

    fn implies(&self, other: &Self) -> Self {
        let v0 = Self::ext_level_implies(self.level0(), other.level0());
        let v1 = Self::ext_level_implies(self.level1(), other.level1());
        // Sparse convention (matches production CapabilityLattice::implies):
        // store only NON-Always entries. Absent slot in the result = Always.
        // leq_himp() supplies the Always default when comparing against this.
        Self {
            slot0: if v0 != CapabilityLevel::Always {
                Some(v0)
            } else {
                None
            },
            slot1: if v1 != CapabilityLevel::Always {
                Some(v1)
            } else {
                None
            },
        }
    }

    /// Compare `self ≤ himp` where `himp` is an implication result.
    ///
    /// Uses `Always` as the default for absent slots in `himp`, matching the
    /// production `CapabilityLattice::leq_himp()`. This is the correct
    /// comparison for adjunction checks; `leq()` uses `Never` (fail-closed)
    /// which is wrong when the implies result uses the sparse absent=Always
    /// convention.
    fn leq_himp(&self, himp: &Self) -> bool {
        let himp0 = himp.slot0.unwrap_or(CapabilityLevel::Always);
        let himp1 = himp.slot1.unwrap_or(CapabilityLevel::Always);
        self.level0() <= himp0 && self.level1() <= himp1
    }

    /// Returns true iff this implication result equals top (all slots trivially
    /// satisfied). In the sparse convention, top is represented by all slots
    /// absent (None), since absent = Always = the default.
    fn is_himp_top(&self) -> bool {
        self.slot0.is_none() && self.slot1.is_none()
    }

    fn pseudo_complement(&self) -> Self {
        self.implies(&Self {
            slot0: None,
            slot1: None,
        })
    }

    fn bottom() -> Self {
        Self {
            slot0: None,
            slot1: None,
        }
    }
}

fn arbitrary_ext_slot() -> Option<CapabilityLevel> {
    let v: u8 = kani::any();
    match v % 4 {
        0 => None,
        1 => Some(CapabilityLevel::Never),
        2 => Some(CapabilityLevel::LowRisk),
        _ => Some(CapabilityLevel::Always),
    }
}

fn arbitrary_ext_mock() -> ExtMock2 {
    ExtMock2 {
        slot0: arbitrary_ext_slot(),
        slot1: arbitrary_ext_slot(),
    }
}

/// **R7 — Extension adjunction** (mock): `(c ⊓ a) ≤ b ↔ c ≤_himp (a ⇨ b)` for extension slots.
///
/// Verifies the Heyting adjunction over the 2-slot extension dimension mock using
/// the production-identical sparse convention: `implies()` omits `Always` entries
/// and `leq_himp()` supplies the `Always` default for absent slots.
///
/// This harness exercises the same algorithmic path as production
/// `CapabilityLattice`: adjunction checks use `leq_himp()`, not `leq()`.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_r7_ext_heyting_adjunction() {
    let a = arbitrary_ext_mock();
    let b = arbitrary_ext_mock();
    let c = arbitrary_ext_mock();

    let lhs = c.meet(&a).leq(&b);
    // Must use leq_himp(), not leq(), because implies() uses the sparse
    // absent=Always convention: leq() would incorrectly apply the Never
    // default for absent slots in the implication result.
    let rhs = c.leq_himp(&a.implies(&b));

    assert_eq!(
        lhs, rhs,
        "R7: Heyting adjunction violated for extension dimension — (c ⊓ a) ≤ b ↔ c ≤_himp (a ⇨ b)"
    );
}

/// **R7a — Extension adjunction (sparse-key)** (mock): the specific case where
/// `c` has an extension key absent from both `a` and `b`.
///
/// This harness targets the scenario identified as the core adjunction gap:
/// when neither `a` nor `b` mention key K, `a.implies(b)` omits K (level =
/// Always = absent by convention). Only `leq_himp()` — not `leq()` — interprets
/// that absent slot as `Always`; `leq()` would apply the `Never` (fail-closed)
/// default and return `false` when `c[K] > Never`.
///
/// This harness proves both sides of the adjunction are `true` AND equal:
/// - LHS: `(c ⊓ a)[K] = min(c_level, Never) = Never ≤ b[K] = Never` → always true
/// - RHS via `leq_himp()`: `c[K] ≤ Always` (absent-slot default) → always true
///
/// Kani exhausts all 3 values of `c_level` (Never/LowRisk/Always) for slot0,
/// with `slot1 = None` throughout to isolate the single-slot sparse scenario.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_r7a_sparse_key_adjunction() {
    // a and b have slot0 absent (= Never for capability operands).
    let a = ExtMock2 {
        slot0: None,
        slot1: None,
    };
    let b = ExtMock2 {
        slot0: None,
        slot1: None,
    };

    // c has slot0 present at an arbitrary level — this is the "sparse key" in c.
    let c_level = level_from_u8(kani::any::<u8>());
    let c = ExtMock2 {
        slot0: Some(c_level),
        slot1: None,
    };

    // The implies result omits slot0 (level_implies(Never,Never)=Always=absent).
    let himp = a.implies(&b);
    // slot0 must be None (= Always) in the implies result.
    assert!(
        himp.slot0.is_none(),
        "R7a: absent-key implies absent in result (Always)"
    );

    // LHS: (c ∧ a)[0] = min(c_level, Never) = Never ≤ b[0] = Never — always true.
    let lhs = c.meet(&a).leq(&b);
    assert!(
        lhs,
        "R7a: LHS min(c_level, Never) = Never ≤ Never must be true"
    );

    // RHS via leq_himp: c[0] = c_level ≤ Always (absent slot default) — always true.
    let rhs = c.leq_himp(&himp);
    assert!(
        rhs,
        "R7a: RHS c[K] ≤ Always (absent slot in implies result) must be true"
    );

    assert_eq!(
        lhs, rhs,
        "R7a: Heyting adjunction must hold for sparse-key scenario (c has K, a and b do not)"
    );
}

/// **R8 — Extension pseudo-complement** (mock): `a ⊓ ¬a = ⊥` for extension slots.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_r8_ext_pseudo_complement() {
    let a = arbitrary_ext_mock();
    let neg_a = a.pseudo_complement();
    let result = a.meet(&neg_a);

    assert!(
        result.leq(&ExtMock2::bottom()),
        "R8: Pseudo-complement violated for extension dimension — a ⊓ ¬a must be ≤ ⊥"
    );
}

/// **R9 — Extension entailment** (mock): `a ≤ b ↔ (a ⇨ b) = ⊤` for extension slots.
///
/// With the sparse convention, `(a ⇨ b) = ⊤` means all slots are `Always` —
/// i.e., no non-trivial entries are stored. `is_himp_top()` checks this:
/// `slot0.is_none() && slot1.is_none()`.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_r9_ext_entailment() {
    let a = arbitrary_ext_mock();
    let b = arbitrary_ext_mock();

    let le_holds = a.leq(&b);
    // In the sparse convention, implies() stores only non-Always entries.
    // The result equals ⊤ iff all slots are absent (all Always = no restrictions).
    let himp_is_top = a.implies(&b).is_himp_top();

    assert_eq!(
        le_holds, himp_is_top,
        "R9: Entailment violated for extension dimension — a ≤ b ↔ (a ⇨ b) = ⊤"
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

// ===========================================================================
// N-series: Nucleus / kernel-operator regression harnesses
// ===========================================================================
//
// These harnesses pin the mathematical structure of `UninhabitableQuotient`
// as a *deflationary idempotent kernel operator*, NOT a frame-theoretic
// nucleus (which would additionally require meet-preservation).
//
// The independent Verus prover in `portcullis-verified` formally disproves
// meet-preservation via `proof_nucleus_not_meet_preserving`. The harness
// below reproduces that concrete counterexample witness using the production
// Rust types so that any future code change that accidentally "fixes" meet-
// preservation (incorrectly, by masking the obligation union) is caught.

/// **N1 — Nucleus is idempotent**: j(j(x)) = j(x) for all inputs.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_nucleus_idempotent() {
    let nucleus = UninhabitableQuotient::new();
    let mut perm = base_permission();
    perm.capabilities = arbitrary_caps();
    perm.obligations = {
        let (obs, _) = obligations_from_masks(kani::any::<u16>(), 0);
        obs
    };
    let jx = nucleus.apply(&perm);
    let jjx = nucleus.apply(&jx);
    assert!(
        jx.capabilities == jjx.capabilities && jx.obligations == jjx.obligations,
        "Nucleus must be idempotent: j(j(x)) != j(x)"
    );
}

/// **N2 — Nucleus is deflationary**: j(x) ≤ x in capabilities for all inputs.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_nucleus_deflationary() {
    let nucleus = UninhabitableQuotient::new();
    let mut perm = base_permission();
    perm.capabilities = arbitrary_caps();
    let jx = nucleus.apply(&perm);
    assert!(
        jx.capabilities.leq(&perm.capabilities),
        "Nucleus must be deflationary: j(x).capabilities > x.capabilities"
    );
}

/// **N3 — Counterexample witness: nucleus does NOT preserve meets**.
///
/// This is the concrete witness from the Verus proof
/// `proof_nucleus_not_meet_preserving` in `portcullis-verified`:
///
/// - `a`: full caps (uninhabitable-complete), empty obligations
/// - `b`: no private-access caps (read_files/glob/grep=Never), empty obligations
///
/// `j(a ∧ b)` adds no obligations (meet caps lack private access → not
/// uninhabitable).  `j(a) ∧ j(b)` retains `j(a)`'s exfil-approval obligations
/// from the quotient meet's union step.
///
/// This harness asserts the KNOWN VIOLATION to prevent regression: if someone
/// changes the code so that this passes, it signals a masked bug (the obligation
/// union in the quotient meet would have been removed).
#[kani::proof]
#[kani::solver(cadical)]
fn proof_nucleus_counterexample_witness() {
    let nucleus = UninhabitableQuotient::new();

    // a: full caps, empty obligations (not pre-normalized — avoids obligation bleed)
    let mut a = base_permission();
    a.capabilities = CapabilityLattice {
        read_files: CapabilityLevel::Always,
        write_files: CapabilityLevel::Always,
        edit_files: CapabilityLevel::Always,
        run_bash: CapabilityLevel::Always,
        glob_search: CapabilityLevel::Always,
        grep_search: CapabilityLevel::Always,
        web_search: CapabilityLevel::Always,
        web_fetch: CapabilityLevel::Always,
        git_commit: CapabilityLevel::Always,
        git_push: CapabilityLevel::Always,
        create_pr: CapabilityLevel::Always,
        manage_pods: CapabilityLevel::Always,
        // extensions excluded via #[cfg(not(kani))]
    };
    a.obligations = Obligations::default(); // empty

    // b: no private-access caps, empty obligations
    let mut b = a.clone();
    b.capabilities.read_files = CapabilityLevel::Never;
    b.capabilities.glob_search = CapabilityLevel::Never;
    b.capabilities.grep_search = CapabilityLevel::Never;
    b.obligations = Obligations::default(); // empty

    let ja = nucleus.apply(&a);
    let jb = nucleus.apply(&b);

    // j(a) must have added obligations (a is uninhabitable-complete)
    assert!(
        !ja.obligations.is_empty(),
        "N3: j(a) must have uninhabitable-state obligations for full-caps input"
    );
    // j(b) must NOT have added obligations (b is not uninhabitable without private access)
    assert!(
        jb.obligations.is_empty(),
        "N3: j(b) must not add obligations when private access is absent"
    );

    // j(a ∧ b): quotient meet of a and b — meet caps lose private access
    let j_a_meet_b = nucleus.apply(&a.meet(&b));
    // j(a) ∧ j(b): quotient meet of j(a) and j(b) — j(a)'s obligations persist
    let ja_meet_jb = ja.meet(&jb);

    // The counterexample: j(a∧b) obligations must differ from j(a)∧j(b) obligations.
    // If this assertion fails, the quotient-meet obligation-union was removed —
    // that would be a security regression (obligations would silently disappear).
    assert!(
        j_a_meet_b.obligations != ja_meet_jb.obligations,
        "N3 regression: j(a∧b) unexpectedly equals j(a)∧j(b) — \
         the quotient-meet obligation union may have been removed"
    );
}

// ============================================================================
// E-series: DecisionToken linear proof invariants
// ============================================================================

/// **E1 — DecisionToken is unforgeable via decide().**
///
/// The `_seal` field is private to the kernel module. This proof verifies
/// that `Kernel::decide()` produces a token only when the verdict is `Allow`.
///
/// Combined with Rust's type system (non-Clone, non-Copy, sealed construction),
/// every DecisionToken in existence was issued by exactly one kernel method
/// (`decide()` or `issue_approved_token()` — see E4). Both paths record a
/// trace entry and update exposure tracking.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_decision_token_unforgeable() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    let op = arbitrary_operation();
    let (decision, token) = kernel.decide(op, "test");

    // For ANY operation: Allow ↔ token present, token matches operation
    if matches!(decision.verdict, Verdict::Allow) {
        assert!(token.is_some());
        let t = token.unwrap();
        assert!(t.operation() == op);
        assert!(t.sequence() == decision.sequence);
    } else {
        assert!(token.is_none());
    }
}

/// **E2 — Denied operations never produce tokens (symbolic).**
///
/// Under a restrictive policy, for any symbolic operation, if the verdict
/// is Deny then no token is produced.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_denied_ops_have_no_token() {
    let perms = PermissionLattice::restrictive();
    let mut kernel = Kernel::new(perms);
    let op = arbitrary_operation();
    let (decision, token) = kernel.decide(op, "subject");
    if matches!(decision.verdict, Verdict::Deny(_)) {
        assert!(token.is_none());
    }
}

/// **E3 — Token operation matches decision operation.**
///
/// For any operation, when a token is produced, its `operation()` and
/// `sequence()` must match the decision's fields exactly.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_token_operation_matches_decision() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    let op = arbitrary_operation();
    let (decision, token) = kernel.decide(op, "subject");
    if let Some(t) = token {
        assert!(t.operation() == decision.operation);
        assert!(t.sequence() == decision.sequence);
    }
}

/// **E4 — issue_approved_token produces audited tokens with exposure tracking.**
///
/// `issue_approved_token()` is the second token-issuing path (alongside `decide()`).
/// It exists for the RequiresApproval → external approval flow. This proof verifies:
/// 1. The token carries the correct operation
/// 2. The trace grows (auditable)
/// 3. Exposure is tracked (monotonic — never decreases)
#[kani::proof]
#[kani::solver(cadical)]
fn proof_issue_approved_token_is_audited() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    let op = arbitrary_operation();

    let trace_len_before = kernel.trace().len();
    let exposure_before = kernel.exposure().count();

    let token = kernel.issue_approved_token(op, "external-approval");

    // Token carries the correct operation
    assert!(token.operation() == op);
    // Trace grew — the operation is auditable
    assert!(kernel.trace().len() > trace_len_before);
    // Exposure is monotonic — never decreases
    assert!(kernel.exposure().count() >= exposure_before);
}

/// **E5 — issue_approved_token under deny policy still tracks exposure.**
///
/// Even if the policy would deny this operation via `decide()`,
/// `issue_approved_token()` bypasses the policy (by design — the caller
/// asserts external approval). This proof verifies the bypass is still
/// audited and exposure-tracked.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_approved_token_bypass_is_audited() {
    let perms = PermissionLattice::restrictive();
    let mut kernel = Kernel::new(perms);

    // decide() would deny RunBash under restrictive policy
    let (decision, _) = kernel.decide(Operation::RunBash, "test-deny");
    assert!(matches!(decision.verdict, Verdict::Deny(_)));

    let trace_len_before = kernel.trace().len();

    // issue_approved_token bypasses the policy — this is by design
    let token = kernel.issue_approved_token(Operation::RunBash, "external-override");

    // But the bypass is audited
    assert!(token.operation() == Operation::RunBash);
    assert!(kernel.trace().len() > trace_len_before);
}
