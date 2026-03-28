//! Core capability lattice types — the Aeneas verification target.
//!
//! This crate contains the minimal, dependency-free types that form the
//! permission lattice verified by the Lean 4 HeytingAlgebra proofs.
//!
//! ## Why a separate crate?
//!
//! Aeneas (the Rust MIR → Lean 4 translator) requires dependency-free code.
//! The full `portcullis` crate imports serde, BTreeMap, chrono, uuid, etc.
//! which Aeneas cannot model. This crate extracts just the lattice core:
//!
//! - [`CapabilityLevel`] — the 3-element total order (Never < LowRisk < Always)
//! - [`CapabilityLattice`] — product of 12 capability dimensions
//! - `meet`, `join`, `leq` — lattice operations (pointwise min/max/≤)
//!
//! ## Relationship to the production `portcullis` crate
//!
//! The production `portcullis` crate re-exports `CapabilityLevel` from this
//! crate — there is ONE type, one source of truth, zero translation layers.
//! The verified type IS the production type.
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

/// Tool permission levels in lattice ordering.
///
/// The ordering is: `Never < LowRisk < Always`
///
/// This is a 3-element bounded lattice where:
/// - `Never` is the bottom element (⊥)
/// - `Always` is the top element (⊤)
/// - `meet` = min, `join` = max
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[repr(u8)]
pub enum CapabilityLevel {
    /// Never allow — bottom element (⊥)
    #[default]
    Never = 0,
    /// Auto-approve for low-risk operations
    LowRisk = 1,
    /// Always auto-approve — top element (⊤)
    Always = 2,
}

impl std::fmt::Display for CapabilityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapabilityLevel::Never => write!(f, "never"),
            CapabilityLevel::LowRisk => write!(f, "low_risk"),
            CapabilityLevel::Always => write!(f, "always"),
        }
    }
}

impl CapabilityLevel {
    /// Meet operation (greatest lower bound): min of two levels.
    pub fn meet(self, other: Self) -> Self {
        if self <= other { self } else { other }
    }

    /// Join operation (least upper bound): max of two levels.
    pub fn join(self, other: Self) -> Self {
        if self >= other { self } else { other }
    }

    /// Heyting implication: a → b = max { c | c ∧ a ≤ b }
    ///
    /// For a 3-element chain: a → b = if a ≤ b then ⊤ else b
    pub fn implies(self, other: Self) -> Self {
        if self <= other {
            CapabilityLevel::Always
        } else {
            other
        }
    }

    /// Pseudo-complement: ¬a = a → ⊥
    pub fn complement(self) -> Self {
        self.implies(CapabilityLevel::Never)
    }

    /// Partial order check.
    pub fn leq(self, other: Self) -> bool {
        self <= other
    }
}

/// Capability lattice for tool permissions.
///
/// Product of 12 capability dimensions, each a [`CapabilityLevel`].
/// Meet, join, and leq are computed pointwise.
///
/// This is the primary verification target for the Aeneas pipeline.
/// The Lean 4 proof shows this forms a distributive Heyting algebra
/// (as a product of Heyting algebras).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityLattice {
    pub read_files: CapabilityLevel,
    pub write_files: CapabilityLevel,
    pub edit_files: CapabilityLevel,
    pub run_bash: CapabilityLevel,
    pub glob_search: CapabilityLevel,
    pub grep_search: CapabilityLevel,
    pub web_search: CapabilityLevel,
    pub web_fetch: CapabilityLevel,
    pub git_commit: CapabilityLevel,
    pub git_push: CapabilityLevel,
    pub create_pr: CapabilityLevel,
    pub manage_pods: CapabilityLevel,
}

impl Default for CapabilityLattice {
    fn default() -> Self {
        Self {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::LowRisk,
            edit_files: CapabilityLevel::LowRisk,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: CapabilityLevel::LowRisk,
            web_fetch: CapabilityLevel::LowRisk,
            git_commit: CapabilityLevel::LowRisk,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::LowRisk,
            manage_pods: CapabilityLevel::Never,
        }
    }
}

impl CapabilityLattice {
    /// Bottom element — all dimensions Never.
    pub fn bottom() -> Self {
        Self {
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
        }
    }

    /// Top element — all dimensions Always.
    pub fn top() -> Self {
        Self {
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
        }
    }

    /// Meet operation (greatest lower bound): pointwise min.
    pub fn meet(&self, other: &Self) -> Self {
        Self {
            read_files: self.read_files.meet(other.read_files),
            write_files: self.write_files.meet(other.write_files),
            edit_files: self.edit_files.meet(other.edit_files),
            run_bash: self.run_bash.meet(other.run_bash),
            glob_search: self.glob_search.meet(other.glob_search),
            grep_search: self.grep_search.meet(other.grep_search),
            web_search: self.web_search.meet(other.web_search),
            web_fetch: self.web_fetch.meet(other.web_fetch),
            git_commit: self.git_commit.meet(other.git_commit),
            git_push: self.git_push.meet(other.git_push),
            create_pr: self.create_pr.meet(other.create_pr),
            manage_pods: self.manage_pods.meet(other.manage_pods),
        }
    }

    /// Join operation (least upper bound): pointwise max.
    pub fn join(&self, other: &Self) -> Self {
        Self {
            read_files: self.read_files.join(other.read_files),
            write_files: self.write_files.join(other.write_files),
            edit_files: self.edit_files.join(other.edit_files),
            run_bash: self.run_bash.join(other.run_bash),
            glob_search: self.glob_search.join(other.glob_search),
            grep_search: self.grep_search.join(other.grep_search),
            web_search: self.web_search.join(other.web_search),
            web_fetch: self.web_fetch.join(other.web_fetch),
            git_commit: self.git_commit.join(other.git_commit),
            git_push: self.git_push.join(other.git_push),
            create_pr: self.create_pr.join(other.create_pr),
            manage_pods: self.manage_pods.join(other.manage_pods),
        }
    }

    /// Partial order check: pointwise ≤.
    pub fn leq(&self, other: &Self) -> bool {
        self.read_files.leq(other.read_files)
            && self.write_files.leq(other.write_files)
            && self.edit_files.leq(other.edit_files)
            && self.run_bash.leq(other.run_bash)
            && self.glob_search.leq(other.glob_search)
            && self.grep_search.leq(other.grep_search)
            && self.web_search.leq(other.web_search)
            && self.web_fetch.leq(other.web_fetch)
            && self.git_commit.leq(other.git_commit)
            && self.git_push.leq(other.git_push)
            && self.create_pr.leq(other.create_pr)
            && self.manage_pods.leq(other.manage_pods)
    }

    /// Heyting implication: pointwise →.
    pub fn implies(&self, other: &Self) -> Self {
        Self {
            read_files: self.read_files.implies(other.read_files),
            write_files: self.write_files.implies(other.write_files),
            edit_files: self.edit_files.implies(other.edit_files),
            run_bash: self.run_bash.implies(other.run_bash),
            glob_search: self.glob_search.implies(other.glob_search),
            grep_search: self.grep_search.implies(other.grep_search),
            web_search: self.web_search.implies(other.web_search),
            web_fetch: self.web_fetch.implies(other.web_fetch),
            git_commit: self.git_commit.implies(other.git_commit),
            git_push: self.git_push.implies(other.git_push),
            create_pr: self.create_pr.implies(other.create_pr),
            manage_pods: self.manage_pods.implies(other.manage_pods),
        }
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
}
