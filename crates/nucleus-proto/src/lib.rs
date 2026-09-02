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
