/// Generated gRPC types for nucleus-node service.
pub mod nucleus_node {
    tonic::include_proto!("nucleus.node.v1");
}

/// Generated gRPC types for the control-plane JobService.
/// Iter-1 surface: Submit + Get; iter-2 adds StreamEvents + Cancel.
pub mod control_plane {
    tonic::include_proto!("nucleus.control_plane.v1");
}
