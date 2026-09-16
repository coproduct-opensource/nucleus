//! The registry of pod identities the node keeps.
//!
//! This module used to hold `WorkloadApiServer`, a node-wide line-protocol server
//! that handed an arbitrary registered identity's SVID to any local connector
//! (#2197), and the two clients that spoke to it. Its last caller was removed in
//! #2197, and the server and clients were deleted once nothing referenced them. Pods
//! fetch their identity over their own vsock bridge (`nucleus-node`'s
//! `workload_api_vsock`) or the standard SPIFFE Workload API
//! (`spiffe_workload_api`).

use crate::identity::Identity;
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Registry mapping connection identifiers to SPIFFE identities.
pub type VmRegistry = RwLock<HashMap<String, Identity>>;
