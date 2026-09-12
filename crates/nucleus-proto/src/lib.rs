// ADR 0007 totality: a function whose signature says it returns is lying if it
// panics. Denied for the shipped build only — `assert!` IS a panic, so denying
// inside `#[cfg(test)]` would forbid the thing tests are made of. This is the
// same line `is_production_path` draws when it strips the test region.
//
// Added because this crate measures ZERO of all seven lints today, per
// `clippy.toml`'s own rule: entries are added only when the tree is already
// clean of them.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

/// Generated gRPC types for nucleus-node service.
pub mod nucleus_node {
    tonic::include_proto!("nucleus.node.v1");
}

/// Generated gRPC types for the control-plane JobService.
/// Iter-1 surface: Submit + Get; iter-2 adds StreamEvents + Cancel.
pub mod control_plane {
    tonic::include_proto!("nucleus.control_plane.v1");
}

/// The SPIFFE Workload API (X.509-SVID profile).
///
/// The proto declares no package — the standard method path is
/// `/SpiffeWorkloadAPI/FetchX509SVID` with no prefix, and real clients
/// hard-code it — so prost emits the generated code as `_`.
pub mod spiffe_workload {
    tonic::include_proto!("_");
}
