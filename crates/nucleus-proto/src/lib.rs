/// HTTP header constants for nucleus protocol.
pub mod headers {
    /// Timestamp header for request signing.
    ///
    /// Contains the Unix timestamp when the request was created.
    /// Used in HMAC-based authentication to prevent replay attacks.
    pub const HEADER_TIMESTAMP: &str = "x-nucleus-timestamp";

    /// Signature header for request authentication.
    ///
    /// Contains the HMAC-SHA256 signature of the request.
    /// Used to verify the request was created by a client with the shared secret.
    pub const HEADER_SIGNATURE: &str = "x-nucleus-signature";

    /// Actor identifier header.
    ///
    /// Identifies the principal making the request.
    /// Used for audit logging and authorization decisions.
    pub const HEADER_ACTOR: &str = "x-nucleus-actor";

    /// Drand round header for approval requests.
    ///
    /// References a specific drand round number to anchor the request
    /// in verifiable randomness, preventing pre-computation attacks.
    pub const HEADER_DRAND_ROUND: &str = "x-nucleus-drand-round";
}

/// Generated gRPC types for nucleus-node service.
pub mod nucleus_node {
    tonic::include_proto!("nucleus.node.v1");
}
