//! Public admission metadata obtained from an authenticated node, separately
//! from execution evidence. This is not a signed receipt or a build verdict.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadAdmission {
    pub pod_id: String,
    pub created_at_unix: u64,
    pub source_commit: String,
    pub source_tree: String,
    pub gate: String,
    /// Identity of the effective spec after host admission.
    pub program_digest: String,
    pub architecture: String,
    pub artifacts: BTreeMap<String, String>,
    pub session_id: String,
    pub issuer_kid: String,
    /// Public Ed25519 key only. Enrollment must authenticate the node and
    /// compare this with the controller's configured signer when one exists.
    pub verifying_key: [u8; 32],
}
