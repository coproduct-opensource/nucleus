//! Host transport observations linked to exact signed authorizations. An HTTP
//! response is not proof that the remote service performed the intended action.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Version 2 adds an optional bounded provider error and an optional cost
/// settlement. Both are omitted when absent, so a version-1 record's bytes and
/// signature are unchanged; a version-1 record carrying either is invalid.
pub const VERSION: u32 = 2;
pub const SUPPORTED_VERSIONS: [u32; 2] = [1, 2];
pub const LOG_FILE: &str = "host-effect-outcomes.jsonl";
/// Bounds on what a provider's refusal may put in the record.
pub const MAX_PROVIDER_STATUS: usize = 64;
pub const MAX_PROVIDER_MESSAGE: usize = 512;

/// A refused response's own machine-readable reason, read from the JSON fields
/// the operator named for that upstream, bounded. No other body text is kept.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderError {
    pub code: Option<u32>,
    pub status: String,
    pub message: String,
}

/// Token counts the upstream reported for the call, read from the JSON fields the
/// operator named for that upstream.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub input_tokens: u64,
    /// Every count the operator named as billed output, summed.
    pub output_tokens: u64,
}

/// A metered upstream's successful call, settled against the flat tariff
/// already debited at authorization. The ledger only grows, so the tariff is a
/// floor: a top-up is debited after the call and an overestimate is not
/// refunded. Unreadable usage is recorded as such, never as a zero cost.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Settlement {
    Priced {
        usage: Usage,
        priced_micro_usd: u64,
        tariff_micro_usd: u64,
        top_up_micro_usd: u64,
    },
    UsageUnreadable {
        tariff_micro_usd: u64,
        reason: String,
    },
}

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
    /// Version 2: a non-2xx response's bounded, provider-stated reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_error: Option<ProviderError>,
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
    /// Version 2: the priced cost and any top-up debited after the call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement: Option<Settlement>,
}

impl Outcome {
    /// A supported version, and version-2 fields only on version-2 records.
    pub fn schema_valid(&self) -> bool {
        let v2_fields = self.settlement.is_some()
            || self
                .response
                .as_ref()
                .is_some_and(|r| r.provider_error.is_some());
        SUPPORTED_VERSIONS.contains(&self.version) && (self.version >= 2 || !v2_fields)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn v1() -> Outcome {
        Outcome {
            version: 1,
            pod_id: "pod".into(),
            sequence: 1,
            authorization_record_sha256: "a".into(),
            observed_unix: 1,
            termination: Termination::ResponseRead,
            response: Some(Response {
                status: 200,
                body_sha256: "b".into(),
                body_bytes: 1,
                body_complete: true,
                provider_error: None,
            }),
            previous_record_sha256: String::new(),
            settlement: None,
        }
    }

    /// A version-1 record signs the same bytes as before version 2 existed, so
    /// every existing signature and chain hash still verifies.
    #[test]
    fn version_one_bytes_are_unchanged() {
        let bytes = String::from_utf8(signing_bytes(&v1()).unwrap()).unwrap();
        assert_eq!(
            bytes,
            "nucleus.host-effect-outcome.v1\n{\"authorization_record_sha256\":\"a\",\"observed_unix\":1,\"pod_id\":\"pod\",\"previous_record_sha256\":\"\",\"response\":{\"body_bytes\":1,\"body_complete\":true,\"body_sha256\":\"b\",\"status\":200},\"sequence\":1,\"termination\":\"response_read\",\"version\":1}"
        );
        let parsed: Outcome =
            serde_json::from_str(&bytes["nucleus.host-effect-outcome.v1\n".len()..]).unwrap();
        assert_eq!(parsed, v1());
    }

    #[test]
    fn version_two_fields_only_on_version_two() {
        assert!(v1().schema_valid());
        let mut smuggled = v1();
        smuggled.settlement = Some(Settlement::UsageUnreadable {
            tariff_micro_usd: 1,
            reason: "x".into(),
        });
        assert!(
            !smuggled.schema_valid(),
            "a v1 record may not carry a settlement"
        );
        let mut v2 = smuggled.clone();
        v2.version = 2;
        assert!(v2.schema_valid());
        let mut future = v1();
        future.version = 3;
        assert!(!future.schema_valid());
    }
}
