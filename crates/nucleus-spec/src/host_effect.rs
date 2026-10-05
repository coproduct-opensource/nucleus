//! Host authorization evidence. This claims a committed host decision, not
//! successful execution, a truthful guest report, or completeness of a session.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod outcome;

pub const VERSION: u32 = 2;
pub const LOG_FILE: &str = "host-effect-authorizations.jsonl";
const DOMAIN: &[u8] = b"nucleus.host-effect-authorization.v2\n";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub version: u32,
    pub pod_id: String,
    pub sequence: u64,
    /// Canonical resolved effect digest computed by the host.
    pub effect_sha256: String,
    pub operation: String,
    pub subject: String,
    pub authorized_unix: u64,
    /// Operator-defined tariff debited by the host for this dispatch attempt.
    pub call_charge_micro_usd: u64,
    /// Empty only on sequence 1; otherwise the previous signed record's hash.
    pub previous_record_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorization {
    pub authorization: Authorization,
    /// Signature under the node's independently pinned certificate-root key.
    pub signature: String,
}

pub fn signing_bytes(claim: &Authorization) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(serde_json_canonicalizer::to_vec(claim)?);
    Ok(bytes)
}

pub fn record_hash(record: &SignedAuthorization) -> Result<String, serde_json::Error> {
    Ok(hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(record)?,
    )))
}
