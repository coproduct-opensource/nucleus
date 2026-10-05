//! Wire types for operator review of action-bound host approvals.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalView {
    pub id: Uuid,
    pub operation: String,
    pub subject: String,
    pub effect_sha256: String,
    pub call_charge_micro_usd: u64,
    pub expires_unix: u64,
    pub status: ApprovalStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Granted,
    Refused,
    Spent,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Grant,
    Refuse,
}

/// Canonical credentialed request; credential values never enter this record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRequest {
    /// An additional guest-side approval requirement, bound to this effect.
    #[serde(default, skip_serializing_if = "is_false")]
    pub require_approval: bool,
    pub operation: String,
    pub upstream: String,
    pub url: String,
    pub method: String,
    pub credential_header: String,
    pub content_type: String,
    pub body_sha256: [u8; 32],
    pub body_bytes: u64,
    pub call_charge_micro_usd: Option<u64>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl EffectRequest {
    /// Preserve the broker's v3 canonical preimage, shared with review clients.
    pub fn digest(&self) -> Result<[u8; 32], serde_json::Error> {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"nucleus-broker-effect-v3\0");
        hash.update(serde_json::to_vec(self)?);
        Ok(hash.finalize().into())
    }

    pub fn matches_body(&self, body: &[u8]) -> bool {
        use sha2::{Digest, Sha256};
        body.len() as u64 == self.body_bytes
            && <[u8; 32]>::from(Sha256::digest(body)) == self.body_sha256
    }
}

/// Exact retained guest payload plus the host-resolved request it belongs to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReview {
    pub approval: ApprovalView,
    pub request: EffectRequest,
    pub body_base64: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn shared_review_encoding_preserves_the_existing_v3_broker_digest() {
        let request = EffectRequest {
            require_approval: false,
            operation: "WebFetch".into(),
            upstream: "api".into(),
            url: "https://api.invalid/run".into(),
            method: "POST".into(),
            credential_header: "authorization".into(),
            content_type: "application/json".into(),
            body_sha256: Sha256::digest(b"hello").into(),
            body_bytes: 5,
            call_charge_micro_usd: Some(1234),
        };
        // Golden hash of the pre-existing v3 serialized broker effect.
        assert_eq!(
            hex::encode(request.digest().unwrap()),
            "279839bdb14f3e400071c251115970e5c4d0385099257834bdc5d9f538b7937f"
        );
        assert!(request.matches_body(b"hello"));
        assert!(!request.matches_body(b"jello"));
        assert!(!request.matches_body(b"hello!"));
    }
}
