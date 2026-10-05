//! Host transport observations linked to exact signed authorizations. An HTTP
//! response is not proof that the remote service performed the intended action.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VERSION: u32 = 1;
pub const LOG_FILE: &str = "host-effect-outcomes.jsonl";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Termination {
    ResponseRead,
    TransportFailure,
    Interrupted,
    ResponseRejected,
    ResponseTruncated,
    GuestDisconnected,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub status: u16,
    /// Hash and count of bytes observed by the host, not acknowledged by a guest.
    pub body_sha256: String,
    pub body_bytes: u64,
    /// True only when the host observed the upstream response body's end.
    pub body_complete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub version: u32,
    pub pod_id: String,
    pub sequence: u64,
    pub authorization_record_sha256: String,
    pub observed_unix: u64,
    pub termination: Termination,
    pub response: Option<Response>,
    pub previous_record_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedOutcome {
    pub outcome: Outcome,
    pub signature: String,
}

pub fn signing_bytes(claim: &Outcome) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = b"nucleus.host-effect-outcome.v1\n".to_vec();
    bytes.extend(serde_json_canonicalizer::to_vec(claim)?);
    Ok(bytes)
}

pub fn record_hash(record: &SignedOutcome) -> Result<String, serde_json::Error> {
    Ok(hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(record)?,
    )))
}
