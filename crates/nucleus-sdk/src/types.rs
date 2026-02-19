//! Re-exports from `nucleus-spec` and `lattice-guard`.
//!
//! Users can depend solely on `nucleus-sdk` without adding `nucleus-spec`
//! or `lattice-guard` to their own Cargo.toml.

// Pod specification types
pub use nucleus_spec::{
    BudgetModelSpec, CredentialsSpec, Metadata, NetworkSpec, PodSpec, PodSpecInner, PolicySpec,
    ResourceSpec,
};

// Permission lattice types
pub use lattice_guard::{
    CapabilityLattice, CapabilityLevel, IncompatibilityConstraint, Obligations, Operation,
    PermissionLattice, TrifectaRisk,
};
