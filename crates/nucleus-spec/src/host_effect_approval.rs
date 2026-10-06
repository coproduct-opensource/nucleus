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
    /// What granting this approval does. Required on the wire: a view that
    /// cannot say whether it declassifies is not read as one that does not.
    pub category: ApprovalCategory,
}

/// What a grant releases, decided by the host when it asked (#3258).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalCategory {
    /// One request the host's policy gates on an operator's approval.
    Ordinary,
    /// One request the kernel held because it would carry a tainted
    /// session's data to an exfiltration sink (a `TaintHold`, #3255).
    /// Granting it declassifies that data into the sink — the enclosing
    /// view's `operation` and `subject`. `input` is the host's label for the
    /// session's data when it held the request; the signed record of the
    /// released effect carries the same label.
    Declassification {
        input: crate::host_effect::InputLabel,
    },
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
    /// Guest-proposed headers the host forwards (names lower-case), after the
    /// operator's per-upstream allowlist. Bound into the digest because they
    /// change what the upstream does (a protocol version, an encoding); absent
    /// from the preimage when empty, so a call without any keeps the digest it
    /// had before the field existed.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub request_headers: std::collections::BTreeMap<String, String>,
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

    /// The approval view says what a grant does, and a view that does not
    /// say is refused rather than read as ordinary (#3258).
    #[test]
    fn an_approval_view_states_its_category_on_the_wire() {
        use crate::host_effect::InputLabel;
        let input = InputLabel {
            integrity: portcullis_core::IntegLevel::Adversarial,
            confidentiality: portcullis_core::ConfLevel::Internal,
            derivation: portcullis_core::DerivationClass::AIDerived,
        };
        let mut view = ApprovalView {
            id: Uuid::nil(),
            operation: "git_push".into(),
            subject: "https://forge.invalid/repo.git/git-receive-pack".into(),
            effect_sha256: "ab".repeat(32),
            call_charge_micro_usd: 0,
            expires_unix: 1,
            status: ApprovalStatus::Pending,
            category: ApprovalCategory::Ordinary,
        };
        let ordinary = serde_json::to_value(&view).unwrap();
        assert_eq!(ordinary["category"], "ordinary");
        view.category = ApprovalCategory::Declassification { input };
        let held = serde_json::to_value(&view).unwrap();
        assert_eq!(
            held["category"],
            serde_json::json!({"declassification": {"input": {
                "integrity": "adversarial", "confidentiality": "internal",
                "derivation": "a_i_derived",
            }}})
        );
        let back: ApprovalView = serde_json::from_value(held).unwrap();
        assert_eq!(back.category, view.category);
        let mut silent = ordinary;
        silent.as_object_mut().unwrap().remove("category");
        assert!(serde_json::from_value::<ApprovalView>(silent).is_err());
        let text = input.describe();
        assert!(text.integrity.starts_with("adversarial:"));
        assert!(text.confidentiality.starts_with("internal:"));
        assert!(text.derivation.starts_with("AI-derived:"));
    }

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
            request_headers: Default::default(),
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
