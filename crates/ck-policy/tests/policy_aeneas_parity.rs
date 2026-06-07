//! Tier-4 PARITY: bind the Aeneas-EXTRACTED + Lean-PROVEN monotonicity-gate core
//! to the PRODUCTION `ck_policy::check_monotonicity`.
//!
//! ── The three honesty tiers (DO NOT CONFLATE) ────────────────────────────────
//!
//! * DEDUCTIVE (tier-1). `crates/ck-policy/lean-aeneas/CkPolicyAeneas.lean` proves
//!   soundness theorems (`T1_extracted_gate_sound`, `rules_non_weakening_sound`,
//!   `passed_core_decomp`, `budget_not_violated`) DIRECTLY over the Charon+Aeneas
//!   GENERATED Lean translation of `ck_policy::extracted` (the self-contained,
//!   monomorphized core in `src/extracted.rs`). `#print axioms` on each is
//!   `[propext, Classical.choice, Quot.sound]` — no `sorryAx`, no `native_decide`.
//!
//! * STATISTICAL (tier-4, THIS FILE). The extracted core
//!   `ck_policy::extracted::passed_core` is bound to the PRODUCTION
//!   `ck_policy::check_monotonicity(parent, child).passed` by asserting they AGREE
//!   over ≥2048 randomized `PolicyManifest` pairs spanning all authority axes and
//!   ALL parent AND child governance-flag combinations. A proptest is NOT a proof;
//!   it narrows the core↔production gap PROBABILISTICALLY.
//!
//! ── What is NOT claimed ───────────────────────────────────────────────────────
//!
//! The literal `check_monotonicity` is NOT extracted: it operates on
//! `ck_types::PolicyManifest` whose fields are `BTreeSet<String>` — constructs the
//! Aeneas Lean backend cannot translate (no `BTreeSet`, no `String`, no generics).
//! The honest claim is: a self-contained, monomorphized core that faithfully
//! mirrors the gate's verdict was extracted by Charon+Aeneas and PROVEN sound in
//! Lean; this test binds that core to the shipped `check_monotonicity`.
//!
//! TCB caveat — **verified Rust != verified binary**. The tier-1 proofs trust
//! Charon (MIR→LLBC), Aeneas (LLBC→Lean), the Lean kernel, and rustc (which
//! compiles the production binary). This parity test runs the REAL production
//! function (`check_monotonicity`) and the REAL extracted core
//! (`extracted::passed_core`) — both rustc-compiled — and checks they agree; it
//! does not bridge source↔binary.
//!
//! ── The adapter (the crux of faithfulness) ───────────────────────────────────
//!
//! The extracted core has ONE interned-`u32` set per authority axis; production
//! compares SEVERAL sub-axes per axis (6 capability sub-axes incl. the scalar
//! `max_parallel_tasks`, 5 io sub-axes, 3 proof-requirement classes). The adapter
//! `intern_*` collapses each axis's sub-axes into ONE id-set, NAMESPACING every
//! sub-axis by a distinct id offset so that "child ⊆ parent on the collapsed set"
//! holds IFF "child ⊆ parent on EVERY sub-axis". `max_parallel_tasks` is encoded
//! as the presence of ids `[0, n)` so subset ⟺ `child_n ≤ parent_n`. This makes
//! the collapsed-core verdict equal the per-axis production verdict by
//! construction; the proptest then CHECKS that equality empirically.
//!
//! Mutation check (performed during authoring — the binding is load-bearing, not
//! vacuous): TWO independent confirmations.
//!
//! 1. The dedicated `adapter_binding_is_load_bearing` test below shows that
//!    dropping the `max_parallel_tasks` id-range encoding makes a known
//!    parallel-task escalation WRONGLY pass (parity would break on it).
//! 2. Collapsing ALL sub-axis namespaces to one (`ns(0, …)` for every axis) made
//!    `production_passed_agrees_with_extracted_core` FAIL after 212 randomized
//!    cases — the per-sub-axis namespacing is required for parity. (Re-run that
//!    mutation manually to reproduce; the committed adapter uses distinct
//!    `ns(axis, …)` namespaces.)
//!
//! NOTE: the proptest fixtures use INDEPENDENT per-sub-axis bitmasks (see
//! `set_of`/`manifest`); a single shared keep-mask makes all sub-axes co-vary and
//! would silently mask namespace bugs.

use std::collections::BTreeSet;

use ck_policy::check_monotonicity;
use ck_policy::extracted::passed_core;
use ck_types::manifest::{
    AmendmentRules, BudgetBounds, CapabilitySet, IoSurface, PolicyManifest, ProofRequirements,
};
use proptest::prelude::*;

// ── Interning: BTreeSet<String> sub-axes → one namespaced Vec<u32> per axis ───

/// Stable interning of a string into a u32 id, NAMESPACED by `axis` so distinct
/// sub-axes never collide. We hash within a bounded pool; collisions only ever
/// MERGE distinct strings (making subset checks STRICTER on both sides equally),
/// so they cannot create a parity divergence. To be airtight we use the index in
/// a per-test sorted union as the id (see `intern_axis`).
fn ns(axis: u32, local_id: u32) -> u32 {
    // 1024 ids reserved per sub-axis namespace; far above the small test pools.
    axis.wrapping_mul(1024).wrapping_add(local_id)
}

/// Intern one sub-axis (a `BTreeSet<String>`) into namespaced ids using the
/// position of each element in the GLOBAL pool ordering. `pool` is the sorted
/// union of every string that can appear on this sub-axis across parent+child,
/// guaranteeing parent and child share the same id assignment.
fn intern_axis(set: &BTreeSet<String>, pool: &[String], axis: u32) -> Vec<u32> {
    set.iter()
        .filter_map(|s| pool.iter().position(|p| p == s))
        .map(|i| ns(axis, i as u32))
        .collect()
}

/// Collapse the six CAPABILITY sub-axes into one namespaced id-set. The scalar
/// `max_parallel_tasks` is encoded as the id-range `[0, n)` in its own namespace
/// (axis 5): `child ⊆ parent` on that range ⟺ `child_n ≤ parent_n`.
fn intern_caps(c: &CapabilitySet, pools: &CapPools) -> Vec<u32> {
    let mut out = Vec::new();
    out.extend(intern_axis(&c.filesystem_read, &pools.fs_read, 0));
    out.extend(intern_axis(&c.filesystem_write, &pools.fs_write, 1));
    out.extend(intern_axis(&c.network_allow, &pools.net, 2));
    out.extend(intern_axis(&c.tools_allow, &pools.tools, 3));
    out.extend(intern_axis(&c.secret_classes, &pools.secrets, 4));
    for i in 0..c.max_parallel_tasks {
        out.push(ns(5, i));
    }
    out
}

/// Collapse the five IO sub-axes into one namespaced id-set.
fn intern_io(io: &IoSurface, pools: &IoPools) -> Vec<u32> {
    let mut out = Vec::new();
    out.extend(intern_axis(&io.outbound_domains, &pools.domains, 0));
    out.extend(intern_axis(&io.local_file_roots, &pools.roots, 1));
    out.extend(intern_axis(&io.env_vars_readable, &pools.envs, 2));
    out.extend(intern_axis(&io.tool_namespaces, &pools.namespaces, 3));
    out.extend(intern_axis(&io.repo_write_targets, &pools.repos, 4));
    out
}

/// Collapse the three PROOF-REQUIREMENT classes into one namespaced id-set.
fn intern_proof(p: &ProofRequirements, pools: &ProofPools) -> Vec<u32> {
    let mut out = Vec::new();
    out.extend(intern_axis(&p.config_patch, &pools.config, 0));
    out.extend(intern_axis(&p.controller_patch, &pools.controller, 1));
    out.extend(intern_axis(&p.evaluator_patch, &pools.evaluator, 2));
    out
}

fn budget_arr(b: &BudgetBounds) -> [u64; 8] {
    [
        b.max_tokens,
        b.max_wall_ms,
        b.max_cpu_ms,
        b.max_memory_bytes,
        b.max_network_calls,
        b.max_files_touched,
        b.max_dollar_spend_millicents,
        b.max_patch_attempts as u64,
    ]
}

fn flags(r: &AmendmentRules) -> [bool; 3] {
    [
        r.require_monotone_capabilities,
        r.require_monotone_io,
        r.require_monotone_proofreq,
    ]
}

// ── Per-axis string pools (sorted unions of parent+child) ─────────────────────

struct CapPools {
    fs_read: Vec<String>,
    fs_write: Vec<String>,
    net: Vec<String>,
    tools: Vec<String>,
    secrets: Vec<String>,
}
struct IoPools {
    domains: Vec<String>,
    roots: Vec<String>,
    envs: Vec<String>,
    namespaces: Vec<String>,
    repos: Vec<String>,
}
struct ProofPools {
    config: Vec<String>,
    controller: Vec<String>,
    evaluator: Vec<String>,
}

fn union(a: &BTreeSet<String>, b: &BTreeSet<String>) -> Vec<String> {
    let mut s: BTreeSet<String> = a.clone();
    s.extend(b.iter().cloned());
    s.into_iter().collect()
}

fn cap_pools(p: &CapabilitySet, c: &CapabilitySet) -> CapPools {
    CapPools {
        fs_read: union(&p.filesystem_read, &c.filesystem_read),
        fs_write: union(&p.filesystem_write, &c.filesystem_write),
        net: union(&p.network_allow, &c.network_allow),
        tools: union(&p.tools_allow, &c.tools_allow),
        secrets: union(&p.secret_classes, &c.secret_classes),
    }
}
fn io_pools(p: &IoSurface, c: &IoSurface) -> IoPools {
    IoPools {
        domains: union(&p.outbound_domains, &c.outbound_domains),
        roots: union(&p.local_file_roots, &c.local_file_roots),
        envs: union(&p.env_vars_readable, &c.env_vars_readable),
        namespaces: union(&p.tool_namespaces, &c.tool_namespaces),
        repos: union(&p.repo_write_targets, &c.repo_write_targets),
    }
}
fn proof_pools(p: &ProofRequirements, c: &ProofRequirements) -> ProofPools {
    ProofPools {
        config: union(&p.config_patch, &c.config_patch),
        controller: union(&p.controller_patch, &c.controller_patch),
        evaluator: union(&p.evaluator_patch, &c.evaluator_patch),
    }
}

/// Run the EXTRACTED core on the adapted (interned) projections of two manifests.
fn core_verdict(parent: &PolicyManifest, child: &PolicyManifest) -> bool {
    let cp = cap_pools(&parent.capabilities, &child.capabilities);
    let ip = io_pools(&parent.io_surface, &child.io_surface);
    let pp = proof_pools(&parent.proof_requirements, &child.proof_requirements);

    let parent_caps = intern_caps(&parent.capabilities, &cp);
    let child_caps = intern_caps(&child.capabilities, &cp);
    let parent_io = intern_io(&parent.io_surface, &ip);
    let child_io = intern_io(&child.io_surface, &ip);
    let parent_proof = intern_proof(&parent.proof_requirements, &pp);
    let child_proof = intern_proof(&child.proof_requirements, &pp);
    let parent_budget = budget_arr(&parent.budget_bounds);
    let child_budget = budget_arr(&child.budget_bounds);

    passed_core(
        flags(&parent.amendment_rules),
        flags(&child.amendment_rules),
        &parent_caps,
        &child_caps,
        &parent_io,
        &child_io,
        &parent_proof,
        &child_proof,
        &parent_budget,
        &child_budget,
    )
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn budget(vals: [u64; 8]) -> BudgetBounds {
    BudgetBounds {
        max_tokens: vals[0],
        max_wall_ms: vals[1],
        max_cpu_ms: vals[2],
        max_memory_bytes: vals[3],
        max_network_calls: vals[4],
        max_files_touched: vals[5],
        max_dollar_spend_millicents: vals[6],
        max_patch_attempts: vals[7] as u32,
    }
}

/// Select pool elements by an INDEPENDENT bit-slice of `bits` starting at `shift`
/// (one bit per element). Independent per-sub-axis masks are essential: they let
/// an escalation occur on ONE sub-axis but not its siblings, which is the ONLY
/// way the per-sub-axis namespacing in the adapter is actually exercised. (A
/// single shared keep-mask makes all sub-axes co-vary and masks namespace bugs.)
fn set_of(items: &[&str], bits: u32, shift: u32) -> BTreeSet<String> {
    items
        .iter()
        .enumerate()
        .filter(|(i, _)| (bits >> (shift + *i as u32)) & 1 == 1)
        .map(|(_, s)| (*s).to_string())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn manifest(
    cap_bits: u32,
    io_bits: u32,
    proof_bits: u32,
    budget_vals: [u64; 8],
    parallel: u32,
    flag_cap: bool,
    flag_io: bool,
    flag_proof: bool,
) -> PolicyManifest {
    // Distinct per-sub-axis pools so the interner exercises every namespace.
    let fs_read = ["/r1", "/r2", "/r3"];
    let fs_write = ["/w1", "/w2"];
    let net = ["net1", "net2", "net3"];
    let tools = ["tool1", "tool2"];
    let secrets = ["secretA", "secretB"];
    let dom = ["dom1", "dom2", "dom3"];
    let root = ["root1", "root2"];
    let env = ["ENV1", "ENV2"];
    let nsp = ["ns1", "ns2", "ns3"];
    let repo = ["o/r1", "o/r2"];
    let proof = ["build_pass", "tests_pass", "kani_pass", "replay_pass"];
    PolicyManifest {
        version: 1,
        // Each sub-axis reads its OWN bit-slice of `cap_bits` (shifts chosen so
        // the slices do not overlap: 3+2+3+2+2 = 12 bits).
        capabilities: CapabilitySet {
            filesystem_read: set_of(&fs_read, cap_bits, 0),
            filesystem_write: set_of(&fs_write, cap_bits, 3),
            network_allow: set_of(&net, cap_bits, 5),
            tools_allow: set_of(&tools, cap_bits, 8),
            secret_classes: set_of(&secrets, cap_bits, 10),
            max_parallel_tasks: parallel,
        },
        // 3+2+2+3+2 = 12 bits.
        io_surface: IoSurface {
            outbound_domains: set_of(&dom, io_bits, 0),
            local_file_roots: set_of(&root, io_bits, 3),
            env_vars_readable: set_of(&env, io_bits, 5),
            tool_namespaces: set_of(&nsp, io_bits, 7),
            repo_write_targets: set_of(&repo, io_bits, 10),
        },
        budget_bounds: budget(budget_vals),
        // 4+4+4 = 12 bits.
        proof_requirements: ProofRequirements {
            config_patch: set_of(&proof, proof_bits, 0),
            controller_patch: set_of(&proof, proof_bits, 4),
            evaluator_patch: set_of(&proof, proof_bits, 8),
        },
        amendment_rules: AmendmentRules {
            may_modify: BTreeSet::new(),
            may_not_modify: BTreeSet::new(),
            require_monotone_capabilities: flag_cap,
            require_monotone_io: flag_io,
            require_monotone_proofreq: flag_proof,
            constitutional_human_signatures: 2,
        },
    }
}

// ── The parity proptest (≥2048 cases, all axes + all flag combos) ─────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// PRODUCTION `check_monotonicity(parent, child).passed` AGREES with the
    /// Aeneas-EXTRACTED `extracted::passed_core` run on the adapted projections,
    /// over randomized manifest pairs spanning all authority sub-axes and ALL
    /// parent AND child governance-flag combinations.
    #[test]
    fn production_passed_agrees_with_extracted_core(
        // 12-bit independent per-sub-axis masks (one bit per pool element).
        pcaps in 0u32..4096, ccaps in 0u32..4096,
        pio in 0u32..4096, cio in 0u32..4096,
        ppr in 0u32..4096, cpr in 0u32..4096,
        pbud in proptest::array::uniform8(0u64..8),
        cbud in proptest::array::uniform8(0u64..8),
        ppar in 0u32..6,
        cpar in 0u32..6,
        pf_cap in any::<bool>(), pf_io in any::<bool>(), pf_proof in any::<bool>(),
        cf_cap in any::<bool>(), cf_io in any::<bool>(), cf_proof in any::<bool>(),
    ) {
        let parent = manifest(pcaps, pio, ppr, pbud, ppar, pf_cap, pf_io, pf_proof);
        let child = manifest(ccaps, cio, cpr, cbud, cpar, cf_cap, cf_io, cf_proof);

        let prod = check_monotonicity(&parent, &child).passed;
        let core = core_verdict(&parent, &child);
        prop_assert_eq!(
            prod, core,
            "production↔extracted-core divergence: prod={}, core={}\nparent={:?}\nchild={:?}",
            prod, core, parent, child
        );
    }
}

// ── Fixed adversarial vector: the anti-coup case (parity, both directions) ─────

#[test]
fn meta_gap_coup_parity() {
    let zero = [0u64; 8];
    // fullParent: every monotone flag ON, empty projections.
    let parent = manifest(0, 0, 0, zero, 0, true, true, true);
    // disarmingChild: identical projections, capability flag OFF.
    let mut child = parent.clone();
    child.amendment_rules.require_monotone_capabilities = false;

    let prod = check_monotonicity(&parent, &child).passed;
    let core = core_verdict(&parent, &child);
    // Production rejects the disarming amendment (anti-coup); the extracted+proven
    // core agrees (its UNCONDITIONAL rules_non_weakening fires).
    assert!(!prod, "production must reject the disarming amendment");
    assert_eq!(
        prod, core,
        "core must agree with production on the coup vector"
    );
}

// ── Mutation check: confirm the binding is load-bearing (not vacuous) ─────────

/// A DELIBERATELY BROKEN adapter that drops the `max_parallel_tasks` encoding.
/// Used only to prove the binding has teeth: with this adapter, a parent/child
/// that differ ONLY in `max_parallel_tasks` (an escalation) would WRONGLY parity
/// as "agree-pass". The real `core_verdict` (which DOES encode parallelism)
/// correctly diverges from production-vs-broken — so the encoding is load-bearing.
#[cfg(test)]
fn core_verdict_broken_no_parallel(parent: &PolicyManifest, child: &PolicyManifest) -> bool {
    let cp = cap_pools(&parent.capabilities, &child.capabilities);
    let ip = io_pools(&parent.io_surface, &child.io_surface);
    let pp = proof_pools(&parent.proof_requirements, &child.proof_requirements);
    // BROKEN: intern caps WITHOUT the max_parallel_tasks id-range.
    let intern_caps_broken = |c: &CapabilitySet| -> Vec<u32> {
        let mut out = Vec::new();
        out.extend(intern_axis(&c.filesystem_read, &cp.fs_read, 0));
        out.extend(intern_axis(&c.filesystem_write, &cp.fs_write, 1));
        out.extend(intern_axis(&c.network_allow, &cp.net, 2));
        out.extend(intern_axis(&c.tools_allow, &cp.tools, 3));
        out.extend(intern_axis(&c.secret_classes, &cp.secrets, 4));
        out // <-- missing parallel encoding
    };
    let parent_caps = intern_caps_broken(&parent.capabilities);
    let child_caps = intern_caps_broken(&child.capabilities);
    let parent_io = intern_io(&parent.io_surface, &ip);
    let child_io = intern_io(&child.io_surface, &ip);
    let parent_proof = intern_proof(&parent.proof_requirements, &pp);
    let child_proof = intern_proof(&child.proof_requirements, &pp);
    passed_core(
        flags(&parent.amendment_rules),
        flags(&child.amendment_rules),
        &parent_caps,
        &child_caps,
        &parent_io,
        &child_io,
        &parent_proof,
        &child_proof,
        &budget_arr(&parent.budget_bounds),
        &budget_arr(&child.budget_bounds),
    )
}

#[test]
fn adapter_binding_is_load_bearing() {
    // Parent allows 1 parallel task; child wants 3 → a capability ESCALATION.
    // Parent has the capability monotonicity flag ON, so production REJECTS.
    let zero = [0u64; 8];
    let parent = manifest(0, 0, 0, zero, 1, true, true, true);
    let child = manifest(0, 0, 0, zero, 3, true, true, true);

    let prod = check_monotonicity(&parent, &child).passed;
    assert!(!prod, "production must reject the parallel-task escalation");

    // The CORRECT adapter agrees with production (both reject).
    assert_eq!(
        prod,
        core_verdict(&parent, &child),
        "correct adapter must match production on the parallel escalation"
    );

    // The BROKEN adapter (no parallel encoding) WRONGLY passes — proving the
    // parallel encoding in the real adapter is load-bearing for parity.
    assert!(
        core_verdict_broken_no_parallel(&parent, &child),
        "broken adapter (sanity) wrongly passes the escalation"
    );
    assert_ne!(
        prod,
        core_verdict_broken_no_parallel(&parent, &child),
        "the binding has teeth: dropping the parallel encoding BREAKS parity"
    );
}
