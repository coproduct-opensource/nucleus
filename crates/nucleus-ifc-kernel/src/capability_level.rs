//! The 3-element capability lattice level — the source of truth for
//! `CapabilityLevel`.
//!
//! Carved out of `portcullis-core`'s `lib.rs` in MVK M3. The product lattice
//! [`CapabilityLattice`]
//! (13 dimensions of this type) stays in `portcullis-core`; only the scalar
//! level lives here, in the dependency-free kernel that Aeneas translates.

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

// Compile-time invariant: declaration order MUST match discriminant values.
// The Aeneas-generated Lean code uses `read_discriminant` (declaration-order index)
// while FunsExternal.lean uses `toNat` (discriminant value). These must be equal.
// If someone reorders the enum variants, this assertion fails the build.
const _: () = {
    assert!(CapabilityLevel::Never as u8 == 0);
    assert!(CapabilityLevel::LowRisk as u8 == 1);
    assert!(CapabilityLevel::Always as u8 == 2);
};

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
