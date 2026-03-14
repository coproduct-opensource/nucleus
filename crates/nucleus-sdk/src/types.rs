//! Re-exports from `nucleus-spec` and `portcullis`.
//!
//! Users can depend solely on `nucleus-sdk` without adding `nucleus-spec`
//! or `portcullis` to their own Cargo.toml.

// Pod specification types
pub use nucleus_spec::{
    BudgetModelSpec, CredentialsSpec, Metadata, NetworkSpec, PodSpec, PodSpecInner, PolicySpec,
    ResourceSpec,
};

// Permission lattice types
pub use portcullis::{
    CapabilityLattice, CapabilityLevel, IncompatibilityConstraint, Obligations, Operation,
    PermissionLattice, StateRisk,
};
