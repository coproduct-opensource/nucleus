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
    /// Present when this effect carried a tainted session's data to a sink
    /// and an operator's approval of exactly this effect released it (#3255).
    /// Absent from every other record, which therefore signs and hashes
    /// exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declassification: Option<Declassification>,
}

/// Flow evidence for one declassified effect: what the session's data was
/// labelled when the host held it, and which single-use approval released it.
///
/// The sink is not restated: it is the enclosing record's `operation`,
/// `subject` and `effect_sha256`, which the approval was bound to. No payload
/// is recorded, only labels.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Declassification {
    /// The operator approval this effect spent. It cannot be spent again.
    pub approval_id: uuid::Uuid,
    /// The host's label for the session's data at the hold.
    pub input: InputLabel,
}

/// The label dimensions the egress gate reads, as the host held them.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InputLabel {
    pub integrity: portcullis_core::IntegLevel,
    pub confidentiality: portcullis_core::ConfLevel,
    pub derivation: portcullis_core::DerivationClass,
}

/// [`InputLabel`] in an operator's words, one line per dimension: the level,
/// then what data at that level is.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InputLabelText {
    pub integrity: String,
    pub confidentiality: String,
    pub derivation: String,
}

impl InputLabel {
    /// The operator-facing reading of this label (#3258). Every match is
    /// exhaustive, so a new level cannot render as an older one's words.
    pub fn describe(&self) -> InputLabelText {
        use portcullis_core::{ConfLevel, DerivationClass, IntegLevel};
        let integrity = match self.integrity {
            IntegLevel::Adversarial => {
                "adversarial: content an outside party controls (upstream or model responses, web pages, issue bodies)"
            }
            IntegLevel::Untrusted => "untrusted: tool output nobody has vouched for",
            IntegLevel::Trusted => "trusted: operator or user input and verified sources",
        };
        let confidentiality = match self.confidentiality {
            ConfLevel::Public => "public: data anyone may see",
            ConfLevel::Internal => "internal: private repository, workspace or environment data",
            ConfLevel::Secret => "secret: credentials, keys or personal data",
        };
        let derivation = match self.derivation {
            DerivationClass::Deterministic => "deterministic: a reproducible computation",
            DerivationClass::AIDerived => "AI-derived: model output, not reproducible",
            DerivationClass::Mixed => "mixed: model output combined with other data",
            DerivationClass::HumanPromoted => "human-promoted: model output a person attested",
            DerivationClass::OpaqueExternal => {
                "opaque external: an outside system of unknown provenance"
            }
        };
        InputLabelText {
            integrity: integrity.into(),
            confidentiality: confidentiality.into(),
            derivation: derivation.into(),
        }
    }
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
