//! Core capability lattice types — the Aeneas verification target.
//!
//! This crate contains the minimal, dependency-free types that form the
//! permission lattice verified by the Lean 4 HeytingAlgebra proofs.
//!
//! ## Primary surface for callers: `portcullis-effects`
//!
//! **New code should use the `portcullis-effects` crate, not this one directly.**
//!
//! `portcullis-effects` provides sealed effect traits (`FileEffect`, `WebEffect`,
//! `ShellEffect`, `GitEffect`) backed by a `PolicyEnforced<E>` wrapper. The
//! capability lattice defined here becomes internal enforcement state — callers
//! never call `std::fs` or `std::process` directly; they receive an effect
//! handler from `production_effects(policy)` and every call is policy-checked
//! at the type boundary.
//!
//! [`CapabilityLattice`] (the 13-dimension product policy) is defined here and
//! remains the *verified algebraic core* — the source of truth for what a policy
//! means. Its scalar [`CapabilityLevel`], the IFC label lattice, and the rest of
//! the reference monitor were carved into the dependency-free `nucleus-ifc-kernel`
//! crate (MVK M3) and are re-exported here, so `portcullis_core::CapabilityLevel`
//! / `::IFCLabel` / `::flow` etc. still resolve unchanged.
//! `portcullis-effects` consumes these; agent builders interact with effects.
//!
//! ## Why a separate crate?
//!
//! Aeneas (the Rust MIR → Lean 4 translator) requires dependency-free code.
//! The full `portcullis` crate imports serde, BTreeMap, chrono, uuid, etc.
//! which Aeneas cannot model. This crate (and the kernel it re-exports) extracts
//! just the lattice core:
//!
//! - [`CapabilityLevel`] — the 3-element total order (Never < LowRisk < Always),
//!   defined in `nucleus-ifc-kernel`, re-exported here
//! - [`CapabilityLattice`] — product of 13 capability dimensions, defined here
//! - `meet`, `join`, `leq` — lattice operations (pointwise min/max/≤)
//!
//! ## Relationship to the production `portcullis` crate
//!
//! The production `portcullis` crate re-exports `CapabilityLevel` (and the rest
//! of the kernel surface) transitively from here — there is ONE definition, one
//! source of truth, zero translation layers. The verified type IS the production
//! type.
//!
//! Serde support is gated behind the optional `serde` feature flag.
//! When `portcullis` depends on `portcullis-core` with `features = ["serde"]`,
//! the type gains `Serialize`/`Deserialize`. Without the feature, the crate
//! remains dependency-free for Aeneas translation.
//!
//! ## Aeneas pipeline
//!
//! ```text
//! portcullis-core (this crate)
//!     → Charon (rustc nightly, MIR extraction)
//!     → Aeneas (OCaml, LLBC → Lean 4 translation)
//!     → PortcullisCore.lean (generated Lean model)
//!     → Mathlib HeytingAlgebra proof (connects to generated types)
//! ```
//!
//! ## What the proof covers (and does not cover)
//!
//! The Aeneas pipeline generates the Lean **type** from this Rust crate and
//! keeps it in sync via CI. The HeytingAlgebra proof is on the generated type
//! (kernel-checked, no `sorry`). This means:
//!
//! - **Covered**: The type definition (`CapabilityLevel`, `CapabilityLattice`)
//!   is machine-translated from Rust to Lean. The proof that these types form
//!   a HeytingAlgebra is kernel-checked against the generated code.
//!
//! - **Not yet covered**: Function-level correspondence (proving that the Rust
//!   `meet()` implementation equals the lattice meet in the Lean proof) requires
//!   completing the `FunsExternal.lean` stubs. This is tracked as future work.
//!
//! - **Defense in depth**: 62 Kani proofs verify the production lattice operations
//!   (meet monotonicity, Heyting adjunction, etc.) in CI on every PR. The Lean
//!   proof verifies algebraic structure of the type. Together they provide
//!   complementary assurance.

pub mod agent_message;
#[cfg(feature = "artifact")]
pub mod artifact;
pub mod attenuation;
#[cfg(feature = "attestation")]
pub mod attestation;
pub mod autonomy;
pub mod bilattice;
pub mod builtin_checks;
#[cfg(feature = "artifact")]
pub mod c2pa_assertions;
#[cfg(feature = "c2pa-manifest")]
pub mod c2pa_manifest;
#[cfg(feature = "c2pa-manifest")]
pub mod c2pa_signer;
pub mod capability_traits;
pub mod category;
pub mod combinators;
pub mod compartment;
#[cfg(feature = "serde")]
pub mod compartmentfile;
#[cfg(feature = "serde")]
pub mod compose;
#[cfg(feature = "serde")]
pub mod compose_runner;
pub mod declassify;
pub mod delegation;
#[cfg(feature = "serde")]
pub mod enterprise;
#[cfg(feature = "envelope")]
pub mod envelope;
pub mod flow_algebra;
pub mod hash_types;
pub mod labeled;
#[cfg(feature = "serde")]
pub mod managed_settings;
pub mod manifest;
#[cfg(feature = "serde")]
pub mod memory;
#[cfg(feature = "serde")]
pub mod nist_metadata;
pub mod parser_registry;
pub mod policy_rules;
#[cfg(feature = "envelope")]
pub mod promotion;
#[cfg(feature = "serde")]
pub mod prov_export;
pub mod provenance_node;
#[cfg(feature = "artifact")]
pub mod provenance_output;
pub mod provenance_schema;
pub mod quarantine;
pub mod receipt;
pub mod redaction;
#[cfg(feature = "artifact")]
pub mod registry;
#[cfg(feature = "envelope")]
pub mod replay;
pub mod sanitize;
pub mod structured_prompt;
pub mod task_shield;
#[cfg(feature = "artifact")]
pub mod tool_manifest;
pub mod verdict;
#[cfg(feature = "wasm-sandbox")]
pub mod wasm_sandbox;
pub mod wire;
#[cfg(feature = "envelope")]
pub mod witness;
#[cfg(feature = "zkvm")]
pub mod zkvm_receipt;

// ═══════════════════════════════════════════════════════════════════════════
// IFC admission core — re-exported from `nucleus-ifc-kernel` (MVK M3)
//
// The reference monitor (the IFC label lattice, the operation/sink vocabulary,
// `CapabilityLevel`, the flow tracker, the discharge pipeline, and the
// Aeneas-extracted IFC slices) was carved into its own dependency-free crate so
// the kernel boundary is enforced by the dependency graph. These re-exports keep
// every existing `portcullis_core::{IFCLabel, Operation, CapabilityLevel, …}`
// path resolving exactly as before — there is ONE definition, one source of
// truth, zero translation layers. The ENTIRE Aeneas-verified surface now lives
// in the kernel crate — `CapabilityLattice`, the exposure detector, and
// `decide_pure` moved too (MVK M3 whole-core), so every proof extraction is
// single-crate. portcullis-core keeps only the unverified machinery.
// ═══════════════════════════════════════════════════════════════════════════

// Glob: lattice/label/operation types + `CapabilityLevel` (crate-root items).
pub use nucleus_ifc_kernel::*;

// Module paths so `portcullis_core::flow::…` / `::extracted::…` etc. survive.
pub use nucleus_ifc_kernel::{discharge, effect, extracted, flow, ifc_api, storage_lane};

// ═══════════════════════════════════════════════════════════════════════════
// Kani BMC harnesses — IFCLabel bounded lattice axioms
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(kani)]
mod kani_ifc_label_proofs {
    use super::*;

    /// Generate a symbolic ConfLevel (3 variants — exhaustive).
    fn any_conf() -> ConfLevel {
        let v: u8 = kani::any();
        kani::assume(v <= 2);
        match v {
            0 => ConfLevel::Public,
            1 => ConfLevel::Internal,
            _ => ConfLevel::Secret,
        }
    }

    /// Generate a symbolic IntegLevel (3 variants — exhaustive).
    fn any_integ() -> IntegLevel {
        let v: u8 = kani::any();
        kani::assume(v <= 2);
        match v {
            0 => IntegLevel::Adversarial,
            1 => IntegLevel::Untrusted,
            _ => IntegLevel::Trusted,
        }
    }

    /// Generate a symbolic AuthorityLevel (4 variants — exhaustive).
    fn any_auth() -> AuthorityLevel {
        let v: u8 = kani::any();
        kani::assume(v <= 3);
        match v {
            0 => AuthorityLevel::NoAuthority,
            1 => AuthorityLevel::Informational,
            2 => AuthorityLevel::Suggestive,
            _ => AuthorityLevel::Directive,
        }
    }

    /// Generate a symbolic DerivationClass (5 variants — exhaustive).
    fn any_derivation() -> DerivationClass {
        let v: u8 = kani::any();
        kani::assume(v <= 4);
        match v {
            0 => DerivationClass::Deterministic,
            1 => DerivationClass::AIDerived,
            2 => DerivationClass::Mixed,
            3 => DerivationClass::HumanPromoted,
            _ => DerivationClass::OpaqueExternal,
        }
    }

    /// Generate a symbolic IFCLabel with bounded provenance (6-bit) and
    /// bounded freshness for tractable verification.
    fn any_label() -> IFCLabel {
        IFCLabel {
            confidentiality: any_conf(),
            integrity: any_integ(),
            provenance: ProvenanceSet::from_bits(kani::any::<u8>()),
            freshness: Freshness {
                observed_at: kani::any(),
                ttl_secs: kani::any(),
            },
            authority: any_auth(),
            derivation: any_derivation(),
        }
    }

    // ── L1: Join idempotence — a ⊔ a = a ──────────────────────────────

    /// **L1 — IFCLabel join is idempotent.**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_join_idempotent() {
        let a = any_label();
        let result = a.join(a);
        assert_eq!(result.confidentiality, a.confidentiality);
        assert_eq!(result.integrity, a.integrity);
        assert_eq!(result.authority, a.authority);
        assert_eq!(result.provenance.bits(), a.provenance.bits());
    }

    // ── L2: Join commutativity — a ⊔ b = b ⊔ a ───────────────────────

    /// **L2 — IFCLabel join is commutative.**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_join_commutative() {
        let a = any_label();
        let b = any_label();
        let ab = a.join(b);
        let ba = b.join(a);
        assert_eq!(ab.confidentiality, ba.confidentiality);
        assert_eq!(ab.integrity, ba.integrity);
        assert_eq!(ab.authority, ba.authority);
        assert_eq!(ab.provenance.bits(), ba.provenance.bits());
    }

    // ── L3: Join associativity — (a ⊔ b) ⊔ c = a ⊔ (b ⊔ c) ─────────

    /// **L3 — IFCLabel join is associative.**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_join_associative() {
        let a = any_label();
        let b = any_label();
        let c = any_label();
        let lhs = a.join(b).join(c);
        let rhs = a.join(b.join(c));
        assert_eq!(lhs.confidentiality, rhs.confidentiality);
        assert_eq!(lhs.integrity, rhs.integrity);
        assert_eq!(lhs.authority, rhs.authority);
        assert_eq!(lhs.provenance.bits(), rhs.provenance.bits());
    }

    // ── L4: Meet idempotence — a ⊓ a = a ──────────────────────────────

    /// **L4 — IFCLabel meet is idempotent.**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_meet_idempotent() {
        let a = any_label();
        let result = a.meet(a);
        assert_eq!(result.confidentiality, a.confidentiality);
        assert_eq!(result.integrity, a.integrity);
        assert_eq!(result.authority, a.authority);
        assert_eq!(result.provenance.bits(), a.provenance.bits());
    }

    // ── L5: Meet commutativity — a ⊓ b = b ⊓ a ───────────────────────

    /// **L5 — IFCLabel meet is commutative.**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_meet_commutative() {
        let a = any_label();
        let b = any_label();
        let ab = a.meet(b);
        let ba = b.meet(a);
        assert_eq!(ab.confidentiality, ba.confidentiality);
        assert_eq!(ab.integrity, ba.integrity);
        assert_eq!(ab.authority, ba.authority);
        assert_eq!(ab.provenance.bits(), ba.provenance.bits());
    }

    // ── L6: Meet associativity — (a ⊓ b) ⊓ c = a ⊓ (b ⊓ c) ─────────

    /// **L6 — IFCLabel meet is associative.**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_meet_associative() {
        let a = any_label();
        let b = any_label();
        let c = any_label();
        let lhs = a.meet(b).meet(c);
        let rhs = a.meet(b.meet(c));
        assert_eq!(lhs.confidentiality, rhs.confidentiality);
        assert_eq!(lhs.integrity, rhs.integrity);
        assert_eq!(lhs.authority, rhs.authority);
        assert_eq!(lhs.provenance.bits(), rhs.provenance.bits());
    }

    // ── L7: Absorption — a ⊔ (a ⊓ b) = a ─────────────────────────────

    /// **L7 — IFCLabel absorption law (join over meet).**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_absorption_join_meet() {
        let a = any_label();
        let b = any_label();
        let result = a.join(a.meet(b));
        assert_eq!(result.confidentiality, a.confidentiality);
        assert_eq!(result.integrity, a.integrity);
        assert_eq!(result.authority, a.authority);
        assert_eq!(result.provenance.bits(), a.provenance.bits());
    }

    // ── L8: Absorption — a ⊓ (a ⊔ b) = a ─────────────────────────────

    /// **L8 — IFCLabel absorption law (meet over join).**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_absorption_meet_join() {
        let a = any_label();
        let b = any_label();
        let result = a.meet(a.join(b));
        assert_eq!(result.confidentiality, a.confidentiality);
        assert_eq!(result.integrity, a.integrity);
        assert_eq!(result.authority, a.authority);
        assert_eq!(result.provenance.bits(), a.provenance.bits());
    }

    // ── L9: Bottom identity — a ⊔ ⊥ = a ──────────────────────────────

    /// **L9 — Bottom is the identity for join.**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_bottom_join_identity() {
        let a = any_label();
        let result = a.join(IFCLabel::bottom());
        assert_eq!(result.confidentiality, a.confidentiality);
        assert_eq!(result.integrity, a.integrity);
        assert_eq!(result.authority, a.authority);
        assert_eq!(result.provenance.bits(), a.provenance.bits());
    }

    // ── L10: Top identity — a ⊓ ⊤ = a ─────────────────────────────────

    /// **L10 — Top is the identity for meet.**
    ///
    /// Note: Freshness dimension uses observed_at=0,ttl_secs=1 for top,
    /// which makes this hold for the non-freshness dimensions. Freshness
    /// is checked separately in check_flow (Rule 4), not in the lattice order.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_top_meet_identity() {
        let a = any_label();
        let result = a.meet(IFCLabel::top());
        assert_eq!(result.confidentiality, a.confidentiality);
        assert_eq!(result.integrity, a.integrity);
        assert_eq!(result.authority, a.authority);
        assert_eq!(result.provenance.bits(), a.provenance.bits());
    }

    // ── L11: leq consistent with join — a ≤ b iff a ⊔ b = b ──────────

    /// **L11 — Lattice order is consistent with join.**
    ///
    /// Verifies the core lattice identity: a ≤ b ⟺ a ⊔ b = b,
    /// restricted to the non-freshness dimensions (conf, integ, auth, prov).
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_leq_consistent_with_join() {
        let a = any_label();
        let b = any_label();

        // Fix freshness to be equal so leq is determined by other dims
        let a = IFCLabel {
            freshness: Freshness {
                observed_at: 100,
                ttl_secs: 0,
            },
            ..a
        };
        let b = IFCLabel {
            freshness: Freshness {
                observed_at: 100,
                ttl_secs: 0,
            },
            ..b
        };

        let join_ab = a.join(b);
        let leq = a.leq(b);

        // a ≤ b → a ⊔ b = b (on all non-freshness dims)
        if leq {
            assert_eq!(join_ab.confidentiality, b.confidentiality);
            assert_eq!(join_ab.integrity, b.integrity);
            assert_eq!(join_ab.authority, b.authority);
            assert_eq!(join_ab.provenance.bits(), b.provenance.bits());
        }

        // a ⊔ b = b → a ≤ b
        if join_ab.confidentiality == b.confidentiality
            && join_ab.integrity == b.integrity
            && join_ab.authority == b.authority
            && join_ab.provenance.bits() == b.provenance.bits()
        {
            assert!(a.leq(b));
        }
    }

    // ── DPI-1: No silent cleansing — AIDerived ⊔ x ≠ Deterministic ───

    /// **DPI-1 — AIDerived can never be laundered back to Deterministic.**
    ///
    /// For all DerivationClass values x, `AIDerived.join(x) != Deterministic`.
    /// This is the foundational DPI invariant: AI-generated data carries its
    /// taint irreversibly through all join operations.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_derivation_no_silent_cleansing() {
        let x = any_derivation();
        let result = DerivationClass::AIDerived.join(x);
        assert!(result != DerivationClass::Deterministic);
    }

    // ── DPI-2: Monotone join — join never reduces taint level ─────────

    /// Map DerivationClass to its height in the Hasse diagram (taint level).
    ///
    /// ```text
    ///       OpaqueExternal  = 3 (top)
    ///            |
    ///          Mixed         = 2
    ///         /     \
    ///   AIDerived  HumanPromoted  = 1
    ///         \     /
    ///       Deterministic    = 0 (bottom)
    /// ```
    fn taint_level(d: DerivationClass) -> u8 {
        match d {
            DerivationClass::Deterministic => 0,
            DerivationClass::AIDerived => 1,
            DerivationClass::HumanPromoted => 1,
            DerivationClass::Mixed => 2,
            DerivationClass::OpaqueExternal => 3,
        }
    }

    /// **DPI-2 — DerivationClass join is monotone in taint level.**
    ///
    /// For all a, b: `taint_level(join(a, b)) >= max(taint_level(a), taint_level(b))`.
    /// Joining data can only increase (or maintain) the taint level, never reduce it.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_derivation_join_monotone() {
        let a = any_derivation();
        let b = any_derivation();
        let result = a.join(b);
        let max_input = if taint_level(a) >= taint_level(b) {
            taint_level(a)
        } else {
            taint_level(b)
        };
        assert!(taint_level(result) >= max_input);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_level_ordering() {
        assert!(CapabilityLevel::Never < CapabilityLevel::LowRisk);
        assert!(CapabilityLevel::LowRisk < CapabilityLevel::Always);
    }

    #[test]
    fn meet_is_min() {
        assert_eq!(
            CapabilityLevel::Always.meet(CapabilityLevel::Never),
            CapabilityLevel::Never
        );
        assert_eq!(
            CapabilityLevel::LowRisk.meet(CapabilityLevel::Always),
            CapabilityLevel::LowRisk
        );
    }

    #[test]
    fn join_is_max() {
        assert_eq!(
            CapabilityLevel::Never.join(CapabilityLevel::Always),
            CapabilityLevel::Always
        );
    }

    #[test]
    fn heyting_implication() {
        // a ≤ b → (a → b) = ⊤
        assert_eq!(
            CapabilityLevel::Never.implies(CapabilityLevel::Always),
            CapabilityLevel::Always
        );
        // a > b → (a → b) = b
        assert_eq!(
            CapabilityLevel::Always.implies(CapabilityLevel::Never),
            CapabilityLevel::Never
        );
    }

    #[test]
    fn pseudo_complement() {
        // ¬⊥ = ⊤
        assert_eq!(CapabilityLevel::Never.complement(), CapabilityLevel::Always);
        // ¬⊤ = ⊥
        assert_eq!(CapabilityLevel::Always.complement(), CapabilityLevel::Never);
    }

    #[test]
    fn lattice_meet_pointwise() {
        let a = CapabilityLattice::top();
        let b = CapabilityLattice::bottom();
        assert_eq!(a.meet(&b), CapabilityLattice::bottom());
    }

    #[test]
    fn lattice_join_pointwise() {
        let a = CapabilityLattice::top();
        let b = CapabilityLattice::bottom();
        assert_eq!(a.join(&b), CapabilityLattice::top());
    }

    #[test]
    fn lattice_leq() {
        assert!(CapabilityLattice::bottom().leq(&CapabilityLattice::top()));
        assert!(!CapabilityLattice::top().leq(&CapabilityLattice::bottom()));
    }

    #[test]
    fn lattice_idempotent_meet() {
        let a = CapabilityLattice::default();
        assert_eq!(a.meet(&a), a);
    }

    #[test]
    fn lattice_idempotent_join() {
        let a = CapabilityLattice::default();
        assert_eq!(a.join(&a), a);
    }

    #[test]
    fn read_only_preserves_reads() {
        let full = CapabilityLattice::top();
        let ro = full.read_only();
        assert_eq!(ro.read_files, CapabilityLevel::Always);
        assert_eq!(ro.glob_search, CapabilityLevel::Always);
        assert_eq!(ro.grep_search, CapabilityLevel::Always);
        assert_eq!(ro.web_search, CapabilityLevel::Always);
        assert_eq!(ro.web_fetch, CapabilityLevel::Always);
    }

    #[test]
    fn read_only_blocks_writes() {
        let full = CapabilityLattice::top();
        let ro = full.read_only();
        assert_eq!(ro.write_files, CapabilityLevel::Never);
        assert_eq!(ro.edit_files, CapabilityLevel::Never);
        assert_eq!(ro.run_bash, CapabilityLevel::Never);
        assert_eq!(ro.git_commit, CapabilityLevel::Never);
        assert_eq!(ro.git_push, CapabilityLevel::Never);
        assert_eq!(ro.create_pr, CapabilityLevel::Never);
        assert_eq!(ro.manage_pods, CapabilityLevel::Never);
    }

    #[test]
    fn read_only_is_deflationary() {
        let a = CapabilityLattice::default();
        let ro = a.read_only();
        assert!(ro.leq(&a));
    }

    // ════════════════════════════════════════════════════════════════════
    // Named profiles (#1214)
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn for_read_only_profile() {
        let p = CapabilityLattice::for_read_only();
        assert_eq!(p.read_files, CapabilityLevel::Always);
        assert_eq!(p.glob_search, CapabilityLevel::Always);
        assert_eq!(p.grep_search, CapabilityLevel::Always);
        // Everything else is Never
        assert_eq!(p.write_files, CapabilityLevel::Never);
        assert_eq!(p.edit_files, CapabilityLevel::Never);
        assert_eq!(p.run_bash, CapabilityLevel::Never);
        assert_eq!(p.web_search, CapabilityLevel::Never);
        assert_eq!(p.web_fetch, CapabilityLevel::Never);
        assert_eq!(p.git_commit, CapabilityLevel::Never);
        assert_eq!(p.git_push, CapabilityLevel::Never);
        assert_eq!(p.create_pr, CapabilityLevel::Never);
        assert_eq!(p.manage_pods, CapabilityLevel::Never);
        assert_eq!(p.spawn_agent, CapabilityLevel::Never);
    }

    #[test]
    fn for_research_profile() {
        let p = CapabilityLattice::for_research();
        assert_eq!(p.read_files, CapabilityLevel::Always);
        assert_eq!(p.glob_search, CapabilityLevel::Always);
        assert_eq!(p.grep_search, CapabilityLevel::Always);
        assert_eq!(p.web_search, CapabilityLevel::Always);
        assert_eq!(p.web_fetch, CapabilityLevel::Always);
        // No writes, no shell, no git
        assert_eq!(p.write_files, CapabilityLevel::Never);
        assert_eq!(p.run_bash, CapabilityLevel::Never);
        assert_eq!(p.git_commit, CapabilityLevel::Never);
        assert_eq!(p.git_push, CapabilityLevel::Never);
    }

    #[test]
    fn for_codegen_profile() {
        let p = CapabilityLattice::for_codegen();
        assert_eq!(p.read_files, CapabilityLevel::Always);
        assert_eq!(p.write_files, CapabilityLevel::Always);
        assert_eq!(p.edit_files, CapabilityLevel::Always);
        assert_eq!(p.run_bash, CapabilityLevel::Always);
        assert_eq!(p.glob_search, CapabilityLevel::Always);
        assert_eq!(p.grep_search, CapabilityLevel::Always);
        assert_eq!(p.git_commit, CapabilityLevel::Always);
        // No network, no push
        assert_eq!(p.web_search, CapabilityLevel::Never);
        assert_eq!(p.web_fetch, CapabilityLevel::Never);
        assert_eq!(p.git_push, CapabilityLevel::Never);
        assert_eq!(p.create_pr, CapabilityLevel::Never);
    }

    #[test]
    fn for_review_profile() {
        let p = CapabilityLattice::for_review();
        assert_eq!(p.read_files, CapabilityLevel::Always);
        assert_eq!(p.glob_search, CapabilityLevel::Always);
        assert_eq!(p.grep_search, CapabilityLevel::Always);
        assert_eq!(p.web_search, CapabilityLevel::Always);
        assert_eq!(p.web_fetch, CapabilityLevel::Always);
        assert_eq!(p.git_commit, CapabilityLevel::Always);
        assert_eq!(p.git_push, CapabilityLevel::Always);
        assert_eq!(p.create_pr, CapabilityLevel::Always);
        // No writes, no shell
        assert_eq!(p.write_files, CapabilityLevel::Never);
        assert_eq!(p.run_bash, CapabilityLevel::Never);
    }

    #[test]
    fn profiles_are_leq_top() {
        let top = CapabilityLattice::top();
        assert!(CapabilityLattice::for_read_only().leq(&top));
        assert!(CapabilityLattice::for_research().leq(&top));
        assert!(CapabilityLattice::for_codegen().leq(&top));
        assert!(CapabilityLattice::for_review().leq(&top));
    }

    #[test]
    fn profiles_are_geq_bottom() {
        let bottom = CapabilityLattice::bottom();
        assert!(bottom.leq(&CapabilityLattice::for_read_only()));
        assert!(bottom.leq(&CapabilityLattice::for_research()));
        assert!(bottom.leq(&CapabilityLattice::for_codegen()));
        assert!(bottom.leq(&CapabilityLattice::for_review()));
    }

    #[test]
    fn read_only_leq_research() {
        // Research is a superset of read-only.
        assert!(CapabilityLattice::for_read_only().leq(&CapabilityLattice::for_research()));
    }

    // ════════════════════════════════════════════════════════════════════
    // Builder (#1214)
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn builder_defaults_to_never() {
        let p = CapabilityLattice::builder().build();
        assert_eq!(p, CapabilityLattice::bottom());
    }

    #[test]
    fn builder_sets_individual_fields() {
        let p = CapabilityLattice::builder()
            .read_files(CapabilityLevel::Always)
            .web_fetch(CapabilityLevel::LowRisk)
            .build();
        assert_eq!(p.read_files, CapabilityLevel::Always);
        assert_eq!(p.web_fetch, CapabilityLevel::LowRisk);
        assert_eq!(p.write_files, CapabilityLevel::Never);
        assert_eq!(p.run_bash, CapabilityLevel::Never);
    }

    #[test]
    fn builder_reproduces_codegen_profile() {
        let from_builder = CapabilityLattice::builder()
            .read_files(CapabilityLevel::Always)
            .write_files(CapabilityLevel::Always)
            .edit_files(CapabilityLevel::Always)
            .run_bash(CapabilityLevel::Always)
            .glob_search(CapabilityLevel::Always)
            .grep_search(CapabilityLevel::Always)
            .git_commit(CapabilityLevel::Always)
            .build();
        assert_eq!(from_builder, CapabilityLattice::for_codegen());
    }

    #[test]
    fn builder_all_fields() {
        let p = CapabilityLattice::builder()
            .read_files(CapabilityLevel::Always)
            .write_files(CapabilityLevel::Always)
            .edit_files(CapabilityLevel::Always)
            .run_bash(CapabilityLevel::Always)
            .glob_search(CapabilityLevel::Always)
            .grep_search(CapabilityLevel::Always)
            .web_search(CapabilityLevel::Always)
            .web_fetch(CapabilityLevel::Always)
            .git_commit(CapabilityLevel::Always)
            .git_push(CapabilityLevel::Always)
            .create_pr(CapabilityLevel::Always)
            .manage_pods(CapabilityLevel::Always)
            .spawn_agent(CapabilityLevel::Always)
            .build();
        assert_eq!(p, CapabilityLattice::top());
    }

    // ════════════════════════════════════════════════════════════════════
    // BTreeMap bridge (#1286)
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn to_map_has_13_entries() {
        let lattice = CapabilityLattice::default();
        let map = lattice.to_map();
        assert_eq!(map.len(), 13);
    }

    #[test]
    fn from_map_roundtrip() {
        let original = CapabilityLattice::for_codegen();
        let map = original.to_map();
        let restored = CapabilityLattice::from_map(&map);
        assert_eq!(original, restored);
    }

    #[test]
    fn from_map_missing_keys_default_to_never() {
        let map = std::collections::BTreeMap::new();
        let lattice = CapabilityLattice::from_map(&map);
        assert_eq!(lattice, CapabilityLattice::bottom());
    }

    #[test]
    fn get_set_by_string_key() {
        let mut lattice = CapabilityLattice::bottom();
        assert_eq!(lattice.get("run_bash"), Some(CapabilityLevel::Never));
        assert!(lattice.set("run_bash", CapabilityLevel::Always));
        assert_eq!(lattice.get("run_bash"), Some(CapabilityLevel::Always));
    }

    #[test]
    fn get_unknown_key_returns_none() {
        let lattice = CapabilityLattice::default();
        assert_eq!(lattice.get("unknown_capability"), None);
    }

    #[test]
    fn set_unknown_key_returns_false() {
        let mut lattice = CapabilityLattice::default();
        assert!(!lattice.set("unknown_capability", CapabilityLevel::Always));
    }

    // ════════════════════════════════════════════════════════════════════
    // Capability lens projections (#1149)
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn project_reads_from_research() {
        let research = CapabilityLattice::for_research();
        let reads = research.project(&DimGroup::READS);
        assert_eq!(reads.read_files, CapabilityLevel::Always);
        assert_eq!(reads.glob_search, CapabilityLevel::Always);
        assert_eq!(reads.grep_search, CapabilityLevel::Always);
        // Non-read dims zeroed
        assert_eq!(reads.web_fetch, CapabilityLevel::Never);
        assert_eq!(reads.write_files, CapabilityLevel::Never);
    }

    #[test]
    fn inject_reads_from_a_writes_from_b() {
        let research = CapabilityLattice::for_research();
        let codegen = CapabilityLattice::for_codegen();

        let merged = CapabilityLattice::bottom()
            .inject(&research, &DimGroup::READS)
            .inject(&codegen, &DimGroup::WRITES);

        // Reads from research
        assert_eq!(merged.read_files, CapabilityLevel::Always);
        // Writes from codegen
        assert_eq!(merged.write_files, CapabilityLevel::Always);
        assert_eq!(merged.edit_files, CapabilityLevel::Always);
        // Neither has git_push
        assert_eq!(merged.git_push, CapabilityLevel::Never);
    }

    #[test]
    fn merge_from_combines_via_join() {
        let base = CapabilityLattice::for_read_only();
        let extra = CapabilityLattice::for_research();

        // Merge network dims from extra into base
        let merged = base.merge_from(&extra, &DimGroup::NETWORK);
        assert_eq!(merged.web_fetch, CapabilityLevel::Always); // from extra
        assert_eq!(merged.web_search, CapabilityLevel::Always); // from extra
        assert_eq!(merged.read_files, CapabilityLevel::Always); // preserved from base
    }

    #[test]
    fn project_all_is_identity() {
        let codegen = CapabilityLattice::for_codegen();
        assert_eq!(codegen.project(&DimGroup::ALL), codegen);
    }

    #[test]
    fn inject_is_idempotent() {
        let research = CapabilityLattice::for_research();
        let once = CapabilityLattice::bottom().inject(&research, &DimGroup::READS);
        let twice = once.clone().inject(&research, &DimGroup::READS);
        assert_eq!(once, twice);
    }

    // ════════════════════════════════════════════════════════════════════
    // Operation tests
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn operation_all_has_13_variants() {
        assert_eq!(Operation::ALL.len(), 13);
    }

    #[test]
    fn operation_display_roundtrip() {
        for op in Operation::ALL {
            let s = op.to_string();
            assert!(!s.is_empty(), "Display for {:?} should not be empty", op);
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // SinkClass tests
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn sink_class_all_has_19_variants() {
        assert_eq!(SinkClass::ALL.len(), 19);
    }

    #[test]
    fn sink_class_display_roundtrip() {
        for sink in SinkClass::ALL {
            let s = sink.to_string();
            assert!(!s.is_empty(), "Display for {:?} should not be empty", sink);
        }
    }

    #[test]
    fn sink_class_exfil_vectors() {
        // Exfil vectors: HTTPEgress, GitPush, PRCommentWrite, EmailSend, AgentSpawn, CloudMutation
        assert!(SinkClass::HTTPEgress.is_exfil_vector());
        assert!(SinkClass::GitPush.is_exfil_vector());
        assert!(SinkClass::PRCommentWrite.is_exfil_vector());
        assert!(SinkClass::EmailSend.is_exfil_vector());
        assert!(SinkClass::AgentSpawn.is_exfil_vector());
        assert!(SinkClass::CloudMutation.is_exfil_vector());

        assert!(SinkClass::TicketWrite.is_exfil_vector());

        // Non-exfil: workspace writes, bash exec, git commit, memory persist, MCP write, secret read
        assert!(!SinkClass::WorkspaceWrite.is_exfil_vector());
        assert!(!SinkClass::SystemWrite.is_exfil_vector());
        assert!(!SinkClass::BashExec.is_exfil_vector());
        assert!(!SinkClass::GitCommit.is_exfil_vector());
        assert!(!SinkClass::MemoryPersist.is_exfil_vector());
        assert!(!SinkClass::MCPWrite.is_exfil_vector());
        assert!(!SinkClass::SecretRead.is_exfil_vector());
        assert!(!SinkClass::ProposedTableWrite.is_exfil_vector());
        assert!(!SinkClass::VerifiedTableWrite.is_exfil_vector());
        assert!(!SinkClass::SearchIndexWrite.is_exfil_vector());
        assert!(!SinkClass::CacheWrite.is_exfil_vector());
        assert!(!SinkClass::AuditLogAppend.is_exfil_vector());
    }

    #[test]
    fn sink_class_authority_requirements() {
        // SecretRead and AuditLogAppend require no authority
        assert_eq!(
            SinkClass::SecretRead.required_authority(),
            AuthorityLevel::NoAuthority
        );
        assert_eq!(
            SinkClass::AuditLogAppend.required_authority(),
            AuthorityLevel::NoAuthority
        );
        // All write/exec sinks require Suggestive
        for sink in SinkClass::ALL {
            if sink != SinkClass::SecretRead && sink != SinkClass::AuditLogAppend {
                assert_eq!(
                    sink.required_authority(),
                    AuthorityLevel::Suggestive,
                    "Expected Suggestive authority for {:?}",
                    sink
                );
            }
        }
    }

    #[test]
    fn sink_class_integrity_requirements() {
        // Publish vectors require Trusted
        assert_eq!(SinkClass::GitPush.required_integrity(), IntegLevel::Trusted);
        assert_eq!(
            SinkClass::PRCommentWrite.required_integrity(),
            IntegLevel::Trusted
        );
        assert_eq!(
            SinkClass::EmailSend.required_integrity(),
            IntegLevel::Trusted
        );
        // SecretRead has no integrity requirement
        assert_eq!(
            SinkClass::SecretRead.required_integrity(),
            IntegLevel::Adversarial
        );
        // Most write sinks require Untrusted
        assert_eq!(
            SinkClass::WorkspaceWrite.required_integrity(),
            IntegLevel::Untrusted
        );
        assert_eq!(
            SinkClass::BashExec.required_integrity(),
            IntegLevel::Untrusted
        );
        // New data-pipeline sinks
        assert_eq!(
            SinkClass::TicketWrite.required_integrity(),
            IntegLevel::Trusted
        );
        assert_eq!(
            SinkClass::VerifiedTableWrite.required_integrity(),
            IntegLevel::Trusted
        );
        assert_eq!(
            SinkClass::ProposedTableWrite.required_integrity(),
            IntegLevel::Untrusted
        );
        assert_eq!(
            SinkClass::SearchIndexWrite.required_integrity(),
            IntegLevel::Untrusted
        );
        assert_eq!(
            SinkClass::CacheWrite.required_integrity(),
            IntegLevel::Untrusted
        );
        assert_eq!(
            SinkClass::AuditLogAppend.required_integrity(),
            IntegLevel::Adversarial
        );
    }

    #[test]
    fn default_sink_class_for_all_operations() {
        // Every operation maps to a valid sink class
        for op in Operation::ALL {
            let _ = default_sink_class(op);
        }
    }

    #[test]
    fn default_sink_class_specific_mappings() {
        assert_eq!(
            default_sink_class(Operation::ReadFiles),
            SinkClass::SecretRead
        );
        assert_eq!(
            default_sink_class(Operation::WriteFiles),
            SinkClass::WorkspaceWrite
        );
        assert_eq!(default_sink_class(Operation::RunBash), SinkClass::BashExec);
        assert_eq!(
            default_sink_class(Operation::WebFetch),
            SinkClass::HTTPEgress
        );
        assert_eq!(
            default_sink_class(Operation::GitCommit),
            SinkClass::GitCommit
        );
        assert_eq!(default_sink_class(Operation::GitPush), SinkClass::GitPush);
        assert_eq!(
            default_sink_class(Operation::CreatePr),
            SinkClass::PRCommentWrite
        );
        assert_eq!(
            default_sink_class(Operation::ManagePods),
            SinkClass::CloudMutation
        );
        assert_eq!(
            default_sink_class(Operation::SpawnAgent),
            SinkClass::AgentSpawn
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // ExposureSet tests
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn exposure_set_empty_is_not_uninhabitable() {
        assert!(!ExposureSet::empty().is_uninhabitable());
        assert_eq!(ExposureSet::empty().count(), 0);
    }

    #[test]
    fn exposure_set_singleton() {
        let s = ExposureSet::singleton(ExposureLabel::PrivateData);
        assert!(s.contains(ExposureLabel::PrivateData));
        assert!(!s.contains(ExposureLabel::UntrustedContent));
        assert!(!s.contains(ExposureLabel::ExfilVector));
        assert_eq!(s.count(), 1);
    }

    #[test]
    fn exposure_set_union_accumulates() {
        let a = ExposureSet::singleton(ExposureLabel::PrivateData);
        let b = ExposureSet::singleton(ExposureLabel::UntrustedContent);
        let c = a.union(&b);
        assert!(c.contains(ExposureLabel::PrivateData));
        assert!(c.contains(ExposureLabel::UntrustedContent));
        assert!(!c.contains(ExposureLabel::ExfilVector));
        assert_eq!(c.count(), 2);
    }

    #[test]
    fn exposure_set_all_three_is_uninhabitable() {
        let s = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent))
            .union(&ExposureSet::singleton(ExposureLabel::ExfilVector));
        assert!(s.is_uninhabitable());
        assert_eq!(s.count(), 3);
    }

    #[test]
    fn exposure_set_union_idempotent() {
        let s = ExposureSet::singleton(ExposureLabel::PrivateData);
        assert_eq!(s.union(&s), s);
    }

    #[test]
    fn exposure_set_union_commutative() {
        let a = ExposureSet::singleton(ExposureLabel::PrivateData);
        let b = ExposureSet::singleton(ExposureLabel::ExfilVector);
        assert_eq!(a.union(&b), b.union(&a));
    }

    #[test]
    fn exposure_set_union_associative() {
        let a = ExposureSet::singleton(ExposureLabel::PrivateData);
        let b = ExposureSet::singleton(ExposureLabel::UntrustedContent);
        let c = ExposureSet::singleton(ExposureLabel::ExfilVector);
        assert_eq!(a.union(&b).union(&c), a.union(&b.union(&c)));
    }

    #[test]
    fn exposure_set_monotonicity() {
        // Once set, a label cannot be unset
        let mut s = ExposureSet::empty();
        s.set(ExposureLabel::PrivateData);
        assert!(s.contains(ExposureLabel::PrivateData));

        // Union with empty doesn't lose information
        let u = s.union(&ExposureSet::empty());
        assert!(u.contains(ExposureLabel::PrivateData));
    }

    // ════════════════════════════════════════════════════════════════════
    // Classification function tests
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn classify_operation_coverage() {
        let expected = [
            (Operation::ReadFiles, Some(ExposureLabel::PrivateData)),
            // Local sinks are exfil legs now (most-paranoid #4).
            (Operation::WriteFiles, Some(ExposureLabel::ExfilVector)),
            (Operation::EditFiles, Some(ExposureLabel::ExfilVector)),
            (Operation::RunBash, Some(ExposureLabel::ExfilVector)),
            (Operation::GlobSearch, Some(ExposureLabel::PrivateData)),
            (Operation::GrepSearch, Some(ExposureLabel::PrivateData)),
            (Operation::WebSearch, Some(ExposureLabel::UntrustedContent)),
            (Operation::WebFetch, Some(ExposureLabel::UntrustedContent)),
            (Operation::GitCommit, Some(ExposureLabel::ExfilVector)),
            (Operation::GitPush, Some(ExposureLabel::ExfilVector)),
            (Operation::CreatePr, Some(ExposureLabel::ExfilVector)),
            (Operation::ManagePods, Some(ExposureLabel::ExfilVector)),
        ];
        for (op, exp) in expected {
            assert_eq!(classify_operation(op), exp, "mismatch for {:?}", op);
        }
    }

    #[test]
    fn project_exposure_adds_label() {
        let empty = ExposureSet::empty();
        let projected = project_exposure(&empty, Operation::ReadFiles);
        assert!(projected.contains(ExposureLabel::PrivateData));
        assert!(!projected.contains(ExposureLabel::UntrustedContent));
        assert!(!projected.contains(ExposureLabel::ExfilVector));
    }

    #[test]
    fn project_exposure_local_sink_adds_exfil() {
        // WriteFiles is an exfil leg now (most-paranoid #4).
        let s = ExposureSet::singleton(ExposureLabel::PrivateData);
        let projected = project_exposure(&s, Operation::WriteFiles);
        assert!(projected.contains(ExposureLabel::PrivateData));
        assert!(projected.contains(ExposureLabel::ExfilVector));
    }

    #[test]
    fn is_exfil_operation_identifies_vectors() {
        assert!(is_exfil_operation(Operation::RunBash));
        assert!(is_exfil_operation(Operation::GitPush));
        assert!(is_exfil_operation(Operation::CreatePr));
        assert!(!is_exfil_operation(Operation::ReadFiles));
        assert!(!is_exfil_operation(Operation::WebFetch));
        // Local sinks are exfil vectors now (most-paranoid #4).
        assert!(is_exfil_operation(Operation::WriteFiles));
        assert!(is_exfil_operation(Operation::GitCommit));
    }

    /// MVK M1b parity: the moved direct-match `is_exfil_operation` (in `ifc_ops`)
    /// must agree, for EVERY operation, with the original `classify_operation`-based
    /// definition (`== Some(ExfilVector)`) that lived in lib.rs. Guards the
    /// reimplementation against drift.
    #[test]
    fn is_exfil_operation_matches_classifier() {
        let all = [
            Operation::ReadFiles,
            Operation::WriteFiles,
            Operation::EditFiles,
            Operation::RunBash,
            Operation::GlobSearch,
            Operation::GrepSearch,
            Operation::WebFetch,
            Operation::WebSearch,
            Operation::GitCommit,
            Operation::GitPush,
            Operation::CreatePr,
            Operation::ManagePods,
            Operation::SpawnAgent,
        ];
        for op in all {
            assert_eq!(
                is_exfil_operation(op),
                matches!(classify_operation(op), Some(ExposureLabel::ExfilVector)),
                "is_exfil_operation diverged from classifier for {op:?}"
            );
        }
    }

    #[test]
    fn should_gate_blocks_completing_uninhabitable() {
        // Two legs active: PrivateData + UntrustedContent
        let exposure = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent));
        // GitPush would complete the uninhabitable state → gated
        assert!(should_gate(&exposure, Operation::GitPush));
        // ReadFiles doesn't complete it (already has PrivateData) → not gated
        assert!(!should_gate(&exposure, Operation::ReadFiles));
        // WriteFiles is an exfil leg now → completes the trifecta → gated.
        assert!(should_gate(&exposure, Operation::WriteFiles));
    }

    #[test]
    fn should_gate_already_uninhabitable() {
        let full = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent))
            .union(&ExposureSet::singleton(ExposureLabel::ExfilVector));
        // Already uninhabitable → all exfil ops gated
        assert!(should_gate(&full, Operation::GitPush));
        assert!(should_gate(&full, Operation::CreatePr));
        assert!(should_gate(&full, Operation::RunBash));
        // Non-exfil ops still not gated
        assert!(!should_gate(&full, Operation::ReadFiles));
        assert!(!should_gate(&full, Operation::WebFetch));
    }

    #[test]
    fn should_gate_safe_state_allows_everything() {
        let empty = ExposureSet::empty();
        for op in Operation::ALL {
            assert!(
                !should_gate(&empty, op),
                "should not gate {:?} from empty state",
                op
            );
        }
    }

    #[test]
    fn apply_record_matches_project() {
        for op in Operation::ALL {
            let s = ExposureSet::singleton(ExposureLabel::PrivateData);
            assert_eq!(
                apply_record(&s, op),
                project_exposure(&s, op),
                "apply_record and project_exposure should agree for {:?}",
                op
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // IFC Label tests
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn ifc_join_confidentiality_covariant() {
        let public = IFCLabel {
            confidentiality: ConfLevel::Public,
            ..IFCLabel::default()
        };
        let secret = IFCLabel {
            confidentiality: ConfLevel::Secret,
            ..IFCLabel::default()
        };
        assert_eq!(public.join(secret).confidentiality, ConfLevel::Secret);
    }

    #[test]
    fn ifc_join_integrity_contravariant() {
        let trusted = IFCLabel {
            integrity: IntegLevel::Trusted,
            ..IFCLabel::default()
        };
        let adversarial = IFCLabel {
            integrity: IntegLevel::Adversarial,
            ..IFCLabel::default()
        };
        // Least trusted wins
        assert_eq!(trusted.join(adversarial).integrity, IntegLevel::Adversarial);
    }

    #[test]
    fn ifc_join_authority_contravariant() {
        let directive = IFCLabel {
            authority: AuthorityLevel::Directive,
            ..IFCLabel::default()
        };
        let no_auth = IFCLabel {
            authority: AuthorityLevel::NoAuthority,
            ..IFCLabel::default()
        };
        // Least authority wins
        assert_eq!(
            directive.join(no_auth).authority,
            AuthorityLevel::NoAuthority
        );
    }

    #[test]
    fn ifc_join_provenance_union() {
        let user = IFCLabel {
            provenance: ProvenanceSet::USER,
            ..IFCLabel::default()
        };
        let web = IFCLabel {
            provenance: ProvenanceSet::WEB,
            ..IFCLabel::default()
        };
        let joined = user.join(web);
        assert!(joined.provenance.contains(ProvenanceSet::USER));
        assert!(joined.provenance.contains(ProvenanceSet::WEB));
    }

    #[test]
    fn ifc_web_content_plus_user_prompt_kills_authority() {
        // THE key indirect-injection defense test:
        // User prompt (Directive) + web content (NoAuthority) = NoAuthority
        let user = IFCLabel::user_prompt(1000);
        let web = IFCLabel::web_content(1000);
        let combined = user.join(web);
        assert_eq!(combined.authority, AuthorityLevel::NoAuthority);
        assert_eq!(combined.integrity, IntegLevel::Adversarial);
    }

    #[test]
    fn ifc_secret_does_not_flow_to_public() {
        let secret = IFCLabel::secret(1000);
        let public_sink = IFCLabel {
            confidentiality: ConfLevel::Public,
            ..IFCLabel::default()
        };
        assert!(!secret.flows_to(public_sink));
    }

    #[test]
    fn ifc_untrusted_does_not_flow_to_trusted() {
        let untrusted = IFCLabel {
            integrity: IntegLevel::Untrusted,
            ..IFCLabel::default()
        };
        let trusted_sink = IFCLabel {
            integrity: IntegLevel::Trusted,
            ..IFCLabel::default()
        };
        assert!(!untrusted.flows_to(trusted_sink));
    }

    #[test]
    fn ifc_no_authority_does_not_flow_to_directive() {
        let no_auth = IFCLabel {
            authority: AuthorityLevel::NoAuthority,
            ..IFCLabel::default()
        };
        let directive_sink = IFCLabel {
            authority: AuthorityLevel::Directive,
            ..IFCLabel::default()
        };
        assert!(!no_auth.flows_to(directive_sink));
    }

    #[test]
    fn ifc_bottom_flows_to_everything() {
        let bot = IFCLabel::bottom();
        let top = IFCLabel::top();
        assert!(bot.flows_to(top));
    }

    #[test]
    fn ifc_top_flows_to_nothing_but_itself() {
        let top = IFCLabel::top();
        let bot = IFCLabel::bottom();
        assert!(!top.flows_to(bot));
        assert!(top.flows_to(top));
    }

    #[test]
    fn ifc_quotient_map_backward_compatible() {
        // The quotient φ maps IFCLabel to ExposureSet correctly
        let secret_untrusted = IFCLabel {
            confidentiality: ConfLevel::Secret,
            integrity: IntegLevel::Untrusted,
            ..IFCLabel::default()
        };
        let exposure = ifc_to_exposure(&secret_untrusted, Operation::GitPush);
        assert!(exposure.contains(ExposureLabel::PrivateData));
        assert!(exposure.contains(ExposureLabel::UntrustedContent));
        assert!(exposure.contains(ExposureLabel::ExfilVector));
        assert!(exposure.is_uninhabitable());
    }

    #[test]
    fn ifc_quotient_public_trusted_is_safe() {
        let safe = IFCLabel {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Trusted,
            ..IFCLabel::default()
        };
        let exposure = ifc_to_exposure(&safe, Operation::ReadFiles);
        assert!(!exposure.is_uninhabitable());
    }

    #[test]
    fn ifc_freshness_join_oldest_shortest() {
        let a = Freshness {
            observed_at: 1000,
            ttl_secs: 3600,
        };
        let b = Freshness {
            observed_at: 500,
            ttl_secs: 7200,
        };
        let joined = a.join(b);
        assert_eq!(joined.observed_at, 500); // oldest
        assert_eq!(joined.ttl_secs, 3600); // shortest
    }

    #[test]
    fn ifc_freshness_expiry() {
        let f = Freshness {
            observed_at: 1000,
            ttl_secs: 3600,
        };
        assert!(!f.is_expired_at(2000));
        assert!(f.is_expired_at(5000));
    }

    #[test]
    fn ifc_freshness_overflow_does_not_make_stale_data_fresh() {
        // #1221: observed_at + ttl_secs would wrap u64. With wrapping add,
        // the deadline would be a small number and stale data would appear fresh.
        // saturating_add ensures the deadline saturates to u64::MAX.
        let f = Freshness {
            observed_at: u64::MAX - 100,
            ttl_secs: 200,
        };
        // With saturating_add: deadline = u64::MAX. now < u64::MAX → not expired.
        assert!(!f.is_expired_at(1_700_000_000));
        // Test the opposite direction:
        let f2 = Freshness {
            observed_at: 1,
            ttl_secs: u64::MAX - 50,
        };
        // Without fix: 1 + (u64::MAX - 50) wraps to u64::MAX - 49.
        // now=1_700_000_000 > (u64::MAX - 49) is false → appears NOT expired (BUG)
        // With saturating_add: deadline = u64::MAX.
        // now=1_700_000_000 > u64::MAX is false → appears NOT expired
        // This is correct: TTL is ~18 quintillion seconds, so data IS still valid.
        assert!(!f2.is_expired_at(1_700_000_000));

        // The critical case: max observed_at with moderate TTL
        let f3 = Freshness {
            observed_at: u64::MAX - 100,
            ttl_secs: 50,
        };
        // Deadline: u64::MAX - 100 + 50 = u64::MAX - 50 (no overflow, exact)
        // now=1_700_000_000 < u64::MAX - 50 → not expired (correct: observed in far future)
        assert!(!f3.is_expired_at(1_700_000_000));

        // Zero TTL is never expired regardless of overflow
        let f4 = Freshness {
            observed_at: u64::MAX,
            ttl_secs: 0,
        };
        assert!(!f4.is_expired_at(u64::MAX));
    }

    #[test]
    fn provenance_union_and_subset() {
        let user_web = ProvenanceSet::USER.union(ProvenanceSet::WEB);
        assert!(ProvenanceSet::USER.is_subset_of(user_web));
        assert!(ProvenanceSet::WEB.is_subset_of(user_web));
        assert!(!ProvenanceSet::MEMORY.is_subset_of(user_web));
    }

    // -----------------------------------------------------------------------
    // Lean-Rust structural correspondence tests
    //
    // These verify that the Lean models in lean/generated/ match the Rust
    // source. If a field is added/removed in Rust without updating Lean,
    // these tests will fail — alerting the developer to update.
    // -----------------------------------------------------------------------

    #[test]
    fn lean_correspondence_capability_lattice_field_count() {
        // The Lean CapabilityLattice has 13 fields (matching Rust).
        // If you add a field to Rust, this test reminds you to update
        // lean/generated/Types.lean and lean/PortcullisCoreBridge.lean.
        assert_eq!(
            Operation::ALL.len(),
            13,
            "Rust CapabilityLattice has 13 dimensions — update Lean Types.lean if this changes"
        );
    }

    #[test]
    fn lean_correspondence_capability_level_variants() {
        // Lean CapabilityLevel has 3 variants: Never, LowRisk, Always
        // with discriminants 0, 1, 2 matching repr(u8).
        assert_eq!(CapabilityLevel::Never as u8, 0);
        assert_eq!(CapabilityLevel::LowRisk as u8, 1);
        assert_eq!(CapabilityLevel::Always as u8, 2);
    }

    #[test]
    fn lean_correspondence_operation_count() {
        // Lean proofs assume 13 operations. If this changes,
        // update ExposureProofs.lean classify_operation coverage.
        assert_eq!(
            Operation::ALL.len(),
            13,
            "Operation count changed — update Lean ExposureProofs.lean"
        );
    }

    #[test]
    fn lean_correspondence_exposure_labels() {
        // ExposureProofs.lean models 3 exposure labels.
        assert_eq!(ExposureLabel::PrivateData as u8, 0);
        assert_eq!(ExposureLabel::UntrustedContent as u8, 1);
        assert_eq!(ExposureLabel::ExfilVector as u8, 2);
    }

    #[test]
    fn lean_correspondence_spawn_agent_is_exfil() {
        // Lean models SpawnAgent as ExfilVector.
        // This must match classify_operation.
        assert_eq!(
            classify_operation(Operation::SpawnAgent),
            Some(ExposureLabel::ExfilVector),
            "SpawnAgent must be ExfilVector — matches Lean ExposureProofs"
        );
    }

    #[test]
    fn lean_correspondence_meet_commutative() {
        // The Lean HeytingAlgebra proof includes commutativity.
        // Verify the Rust implementation matches.
        let a = CapabilityLevel::Always;
        let b = CapabilityLevel::Never;
        assert_eq!(a.meet(b), b.meet(a));
    }

    #[test]
    fn lean_correspondence_meet_idempotent() {
        for level in [
            CapabilityLevel::Never,
            CapabilityLevel::LowRisk,
            CapabilityLevel::Always,
        ] {
            assert_eq!(level.meet(level), level);
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // DerivationClass lattice tests
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn derivation_join_exhaustive_table() {
        use DerivationClass::*;
        // Exhaustive 5x5 join table matching the diamond lattice:
        //       OpaqueExternal
        //            |
        //          Mixed
        //         /     \
        //   AIDerived  HumanPromoted
        //         \     /
        //       Deterministic
        let cases = [
            // Deterministic is bottom — identity for join
            (Deterministic, Deterministic, Deterministic),
            (Deterministic, AIDerived, AIDerived),
            (Deterministic, Mixed, Mixed),
            (Deterministic, HumanPromoted, HumanPromoted),
            (Deterministic, OpaqueExternal, OpaqueExternal),
            // AIDerived joins
            (AIDerived, Deterministic, AIDerived),
            (AIDerived, AIDerived, AIDerived),
            (AIDerived, Mixed, Mixed),
            (AIDerived, HumanPromoted, Mixed),
            (AIDerived, OpaqueExternal, OpaqueExternal),
            // Mixed joins
            (Mixed, Deterministic, Mixed),
            (Mixed, AIDerived, Mixed),
            (Mixed, Mixed, Mixed),
            (Mixed, HumanPromoted, Mixed),
            (Mixed, OpaqueExternal, OpaqueExternal),
            // HumanPromoted joins
            (HumanPromoted, Deterministic, HumanPromoted),
            (HumanPromoted, AIDerived, Mixed),
            (HumanPromoted, Mixed, Mixed),
            (HumanPromoted, HumanPromoted, HumanPromoted),
            (HumanPromoted, OpaqueExternal, OpaqueExternal),
            // OpaqueExternal is top — absorbs everything
            (OpaqueExternal, Deterministic, OpaqueExternal),
            (OpaqueExternal, AIDerived, OpaqueExternal),
            (OpaqueExternal, Mixed, OpaqueExternal),
            (OpaqueExternal, HumanPromoted, OpaqueExternal),
            (OpaqueExternal, OpaqueExternal, OpaqueExternal),
        ];
        for (a, b, expected) in cases {
            assert_eq!(
                a.join(b),
                expected,
                "{:?}.join({:?}) should be {:?}",
                a,
                b,
                expected
            );
        }
    }

    #[test]
    fn derivation_join_commutative() {
        use DerivationClass::*;
        let all = [
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ];
        for &a in &all {
            for &b in &all {
                assert_eq!(
                    a.join(b),
                    b.join(a),
                    "{:?}.join({:?}) not commutative",
                    a,
                    b
                );
            }
        }
    }

    #[test]
    fn derivation_join_associative() {
        use DerivationClass::*;
        let all = [
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ];
        for &a in &all {
            for &b in &all {
                for &c in &all {
                    assert_eq!(
                        a.join(b).join(c),
                        a.join(b.join(c)),
                        "({:?} join {:?}) join {:?} != {:?} join ({:?} join {:?})",
                        a,
                        b,
                        c,
                        a,
                        b,
                        c
                    );
                }
            }
        }
    }

    #[test]
    fn derivation_join_idempotent() {
        use DerivationClass::*;
        for &d in &[
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ] {
            assert_eq!(d.join(d), d, "{:?}.join({:?}) should be idempotent", d, d);
        }
    }

    #[test]
    fn derivation_leq_reflexive() {
        use DerivationClass::*;
        for &d in &[
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ] {
            assert!(d.leq(d), "{:?} should be leq itself", d);
        }
    }

    #[test]
    fn derivation_leq_antisymmetric() {
        use DerivationClass::*;
        let all = [
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ];
        for &a in &all {
            for &b in &all {
                if a.leq(b) && b.leq(a) {
                    assert_eq!(
                        a, b,
                        "{:?} leq {:?} and {:?} leq {:?} but not equal",
                        a, b, b, a
                    );
                }
            }
        }
    }

    #[test]
    fn derivation_lattice_ordering() {
        use DerivationClass::*;
        // Deterministic is bottom
        assert!(Deterministic.leq(AIDerived));
        assert!(Deterministic.leq(HumanPromoted));
        assert!(Deterministic.leq(Mixed));
        assert!(Deterministic.leq(OpaqueExternal));

        // AIDerived and HumanPromoted are incomparable
        assert!(!AIDerived.leq(HumanPromoted));
        assert!(!HumanPromoted.leq(AIDerived));

        // Both are below Mixed
        assert!(AIDerived.leq(Mixed));
        assert!(HumanPromoted.leq(Mixed));
        assert!(!Mixed.leq(AIDerived));
        assert!(!Mixed.leq(HumanPromoted));

        // OpaqueExternal is top
        for &d in &[
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ] {
            assert!(d.leq(OpaqueExternal), "{:?} should be <= OpaqueExternal", d);
        }
    }

    #[test]
    fn derivation_no_silent_cleansing() {
        use DerivationClass::*;
        // AIDerived joined with anything that is not HumanPromoted
        // must never produce Deterministic.
        for &other in &[
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ] {
            let result = AIDerived.join(other);
            assert_ne!(
                result, Deterministic,
                "AIDerived.join({:?}) = Deterministic violates no-silent-cleansing",
                other
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // DPI invariant test mirrors (non-Kani mirrors of Kani proofs)
    // ════════════════════════════════════════════════════════════════════

    /// Taint level height in the Hasse diagram (mirrors Kani taint_level).
    fn taint_level(d: DerivationClass) -> u8 {
        match d {
            DerivationClass::Deterministic => 0,
            DerivationClass::AIDerived => 1,
            DerivationClass::HumanPromoted => 1,
            DerivationClass::Mixed => 2,
            DerivationClass::OpaqueExternal => 3,
        }
    }

    #[test]
    fn derivation_no_silent_cleansing_exhaustive() {
        use DerivationClass::*;
        // DPI-1: For ALL variants, AIDerived.join(x) != Deterministic
        for &x in &[
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ] {
            let result = AIDerived.join(x);
            assert_ne!(
                result, Deterministic,
                "DPI-1 violated: AIDerived.join({:?}) = Deterministic",
                x
            );
        }
    }

    #[test]
    fn derivation_join_monotone_exhaustive() {
        use DerivationClass::*;
        // DPI-2: For ALL pairs, taint_level(join(a,b)) >= max(taint_level(a), taint_level(b))
        let all = [
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ];
        for &a in &all {
            for &b in &all {
                let result = a.join(b);
                let max_input = taint_level(a).max(taint_level(b));
                assert!(
                    taint_level(result) >= max_input,
                    "DPI-2 violated: taint_level({:?}.join({:?})) = {} < max({}, {}) = {}",
                    a,
                    b,
                    taint_level(result),
                    taint_level(a),
                    taint_level(b),
                    max_input
                );
            }
        }
    }

    #[test]
    fn derivation_meet_exhaustive() {
        use DerivationClass::*;
        // Meet is dual of join — verify key properties
        let all = [
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ];
        for &a in &all {
            for &b in &all {
                let m = a.meet(b);
                // meet(a,b) <= a and meet(a,b) <= b
                assert!(
                    m.leq(a),
                    "meet({:?},{:?}) = {:?} should be <= {:?}",
                    a,
                    b,
                    m,
                    a
                );
                assert!(
                    m.leq(b),
                    "meet({:?},{:?}) = {:?} should be <= {:?}",
                    a,
                    b,
                    m,
                    b
                );
            }
        }
    }

    #[test]
    fn derivation_propagation_through_flow() {
        // Deterministic file + AIDerived model plan = AIDerived
        // (Deterministic is bottom, so it's absorbed by AIDerived)
        let file_label = IFCLabel {
            derivation: DerivationClass::Deterministic,
            ..IFCLabel::bottom()
        };
        let model_label = IFCLabel {
            derivation: DerivationClass::AIDerived,
            ..IFCLabel::bottom()
        };
        let result = file_label.join(model_label);
        assert_eq!(result.derivation, DerivationClass::AIDerived);

        // AIDerived + HumanPromoted = Mixed (incomparable elements)
        let ai_label = IFCLabel {
            derivation: DerivationClass::AIDerived,
            ..IFCLabel::bottom()
        };
        let human_label = IFCLabel {
            derivation: DerivationClass::HumanPromoted,
            ..IFCLabel::bottom()
        };
        let result = ai_label.join(human_label);
        assert_eq!(result.derivation, DerivationClass::Mixed);
    }

    #[test]
    fn derivation_opaque_absorbs_in_join() {
        // Any label joined with OpaqueExternal produces OpaqueExternal derivation
        let opaque = IFCLabel {
            derivation: DerivationClass::OpaqueExternal,
            ..IFCLabel::bottom()
        };
        for &d in &[
            DerivationClass::Deterministic,
            DerivationClass::AIDerived,
            DerivationClass::Mixed,
            DerivationClass::HumanPromoted,
        ] {
            let other = IFCLabel {
                derivation: d,
                ..IFCLabel::bottom()
            };
            assert_eq!(
                opaque.join(other).derivation,
                DerivationClass::OpaqueExternal,
                "OpaqueExternal should absorb {:?} in IFCLabel join",
                d
            );
        }
    }

    #[test]
    fn derivation_intrinsic_labels_correct() {
        use crate::flow::{NodeKind, intrinsic_label};
        let now = 1000;

        // Deterministic sources
        assert_eq!(
            intrinsic_label(NodeKind::UserPrompt, now).derivation,
            DerivationClass::Deterministic
        );
        assert_eq!(
            intrinsic_label(NodeKind::FileRead, now).derivation,
            DerivationClass::Deterministic
        );
        assert_eq!(
            intrinsic_label(NodeKind::EnvVar, now).derivation,
            DerivationClass::Deterministic
        );
        assert_eq!(
            intrinsic_label(NodeKind::Secret, now).derivation,
            DerivationClass::Deterministic
        );
        assert_eq!(
            intrinsic_label(NodeKind::ToolResponse, now).derivation,
            DerivationClass::Deterministic
        );

        // AI-derived sources
        assert_eq!(
            intrinsic_label(NodeKind::ModelPlan, now).derivation,
            DerivationClass::AIDerived
        );
        assert_eq!(
            intrinsic_label(NodeKind::MemoryWrite, now).derivation,
            DerivationClass::AIDerived
        );
        assert_eq!(
            intrinsic_label(NodeKind::Summarization, now).derivation,
            DerivationClass::AIDerived
        );

        // OpaqueExternal
        assert_eq!(
            intrinsic_label(NodeKind::WebContent, now).derivation,
            DerivationClass::OpaqueExternal
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // IFCLabel bounded lattice axiom tests (test-mode mirrors of Kani proofs)
    // ════════════════════════════════════════════════════════════════════

    /// Helper: enumerate all ConfLevel x IntegLevel x AuthorityLevel x DerivationClass
    /// x ProvenanceSet combinations with fixed freshness (11520 labels).
    fn all_labels() -> Vec<IFCLabel> {
        let confs = [ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];
        let integs = [
            IntegLevel::Adversarial,
            IntegLevel::Untrusted,
            IntegLevel::Trusted,
        ];
        let auths = [
            AuthorityLevel::NoAuthority,
            AuthorityLevel::Informational,
            AuthorityLevel::Suggestive,
            AuthorityLevel::Directive,
        ];
        let derivs = [
            DerivationClass::Deterministic,
            DerivationClass::AIDerived,
            DerivationClass::Mixed,
            DerivationClass::HumanPromoted,
            DerivationClass::OpaqueExternal,
        ];
        let fresh = Freshness {
            observed_at: 100,
            ttl_secs: 0,
        };

        let mut labels = Vec::new();
        for &c in &confs {
            for &i in &integs {
                for &a in &auths {
                    for &d in &derivs {
                        for prov_bits in 0..64u8 {
                            labels.push(IFCLabel {
                                confidentiality: c,
                                integrity: i,
                                provenance: ProvenanceSet::from_bits(prov_bits),
                                freshness: fresh,
                                authority: a,
                                derivation: d,
                            });
                        }
                    }
                }
            }
        }
        labels
    }

    #[test]
    fn ifc_join_idempotent_exhaustive() {
        for a in all_labels() {
            let r = a.join(a);
            assert_eq!(r.confidentiality, a.confidentiality);
            assert_eq!(r.integrity, a.integrity);
            assert_eq!(r.authority, a.authority);
            assert_eq!(r.provenance.bits(), a.provenance.bits());
            assert_eq!(r.derivation, a.derivation);
        }
    }

    #[test]
    fn ifc_join_commutative_exhaustive() {
        // Sample pairs (full cross-product is 2304^2 ≈ 5M — too many)
        let labels = all_labels();
        // Test every label against a representative set
        let reps = [
            IFCLabel::bottom(),
            IFCLabel::top(),
            IFCLabel::web_content(100),
            IFCLabel::user_prompt(100),
            IFCLabel::secret(100),
        ];
        for a in &labels {
            for b in &reps {
                let ab = a.join(*b);
                let ba = b.join(*a);
                assert_eq!(ab.confidentiality, ba.confidentiality);
                assert_eq!(ab.integrity, ba.integrity);
                assert_eq!(ab.authority, ba.authority);
                assert_eq!(ab.provenance.bits(), ba.provenance.bits());
            }
        }
    }

    #[test]
    fn ifc_meet_idempotent_exhaustive() {
        for a in all_labels() {
            let r = a.meet(a);
            assert_eq!(r.confidentiality, a.confidentiality);
            assert_eq!(r.integrity, a.integrity);
            assert_eq!(r.authority, a.authority);
            assert_eq!(r.provenance.bits(), a.provenance.bits());
        }
    }

    #[test]
    fn ifc_absorption_join_meet() {
        let labels = all_labels();
        let reps = [
            IFCLabel::bottom(),
            IFCLabel::top(),
            IFCLabel::web_content(100),
            IFCLabel::user_prompt(100),
        ];
        for a in &labels {
            for b in &reps {
                let r = a.join(a.meet(*b));
                assert_eq!(r.confidentiality, a.confidentiality);
                assert_eq!(r.integrity, a.integrity);
                assert_eq!(r.authority, a.authority);
                assert_eq!(r.provenance.bits(), a.provenance.bits());
            }
        }
    }

    #[test]
    fn ifc_absorption_meet_join() {
        let labels = all_labels();
        let reps = [
            IFCLabel::bottom(),
            IFCLabel::top(),
            IFCLabel::web_content(100),
            IFCLabel::user_prompt(100),
        ];
        for a in &labels {
            for b in &reps {
                let r = a.meet(a.join(*b));
                assert_eq!(r.confidentiality, a.confidentiality);
                assert_eq!(r.integrity, a.integrity);
                assert_eq!(r.authority, a.authority);
                assert_eq!(r.provenance.bits(), a.provenance.bits());
            }
        }
    }

    #[test]
    fn ifc_bottom_is_join_identity() {
        for a in all_labels() {
            let r = a.join(IFCLabel::bottom());
            assert_eq!(r.confidentiality, a.confidentiality);
            assert_eq!(r.integrity, a.integrity);
            assert_eq!(r.authority, a.authority);
            assert_eq!(r.provenance.bits(), a.provenance.bits());
        }
    }

    #[test]
    fn ifc_top_is_meet_identity() {
        for a in all_labels() {
            let r = a.meet(IFCLabel::top());
            assert_eq!(r.confidentiality, a.confidentiality);
            assert_eq!(r.integrity, a.integrity);
            assert_eq!(r.authority, a.authority);
            assert_eq!(r.provenance.bits(), a.provenance.bits());
        }
    }
}
