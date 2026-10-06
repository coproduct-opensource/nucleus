//! The relying party's inputs as one JSON document, and one entry point that
//! takes evidence, reference manifest and those inputs as documents.
//!
//! This is what the browser (`sdks/verifier-js`) and Python
//! (`sdks/verifier-py`) verifiers call, so a stranger holding three files gets
//! the same verdict whatever language they check it in. It adds no decision:
//! [`report`] parses, calls [`appraise`], and serializes what `appraise`
//! returned. The report's shape is derived from the crate's own types (ADR 0007
//! F-1), so no binding restates the tiers.
//!
//! Every field of [`RelyingParty`] is required (ADR 0007 B-1): an omitted
//! operator pin list is not "no pins", it is a parse error, so a relying party
//! that meant "trust nothing" writes `[]`.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::anchor::{AnchorPolicy, OperatorPin};
use crate::appraise::{AppraisalPolicy, FreshnessExpectation, Refusal, appraise};
use crate::binding::KeyBinding;
use crate::evidence::{NodeEvidence, evidence_digest};
use crate::reference::ReferenceManifest;

/// Everything the relying party brings to an appraisal, as a document.
///
/// ```json
/// {
///   "binding": { "executor_key": { "ed25519": "<hex>" }, "federation": "not_federated" },
///   "freshness": { "epoch": { "receipt_time": 1791247262, "max_age_secs": 900, "max_future_secs": 60 } },
///   "trust_roots": [],
///   "operator_pins": [ { "source": "<source>", "ak_spki_sha256": "<hex>" } ],
///   "now": 1791247262
/// }
/// ```
///
/// `freshness` is either `{"challenge": {"sent": "<nonce hex>"}}` (the nonce
/// this relying party sent) or the epoch form above. `binding` names the
/// executor key the receipt was signed with — taken from the receipt, never
/// from the evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelyingParty {
    /// The executor key (and federation set) the receipt names.
    pub binding: KeyBinding,
    /// The freshness requirement.
    pub freshness: FreshnessExpectation,
    /// Root certificates an AK certificate chain may end at, base64 DER.
    pub trust_roots: Vec<String>,
    /// Operator pins this relying party chose to accept. The weakest anchor.
    pub operator_pins: Vec<OperatorPin>,
    /// The time to check certificate validity at, Unix seconds. A browser
    /// passes `Math.floor(Date.now() / 1000)`; a test passes a fixed value.
    pub now: i64,
}

/// An input document that did not parse. Not a verdict about the node: the
/// relying party gave the verifier something it cannot read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InputError {
    /// The evidence document.
    #[error("evidence: {0}")]
    Evidence(String),
    /// The reference manifest.
    #[error("reference manifest: {0}")]
    Reference(String),
    /// The relying party's inputs.
    #[error("relying party: {0}")]
    RelyingParty(String),
}

/// The result of checking one evidence document, as the verifiers report it.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Report {
    /// The evidence is evidence; `ear` says what it shows. `ear.status` is
    /// `affirming` only for `Attested`.
    Appraised {
        /// SHA-256 of the evidence document bytes, hex — the digest a
        /// receipt's `node_platform.evidence_sha256` names.
        evidence_sha256: String,
        /// The EAR-shaped result ([`crate::Appraisal::to_ear`]).
        ear: serde_json::Value,
    },
    /// The evidence is not evidence.
    Refused {
        /// SHA-256 of the evidence document bytes, hex.
        evidence_sha256: String,
        /// Why.
        refusal: Refusal,
    },
}

impl RelyingParty {
    fn anchors(&self) -> Result<AnchorPolicy, InputError> {
        let mut trust_roots = Vec::with_capacity(self.trust_roots.len());
        for (i, root) in self.trust_roots.iter().enumerate() {
            let der = base64::engine::general_purpose::STANDARD
                .decode(root)
                .map_err(|e| InputError::RelyingParty(format!("trust_roots[{i}]: {e}")))?;
            trust_roots.push(der);
        }
        for pin in &self.operator_pins {
            let fp = &pin.ak_spki_sha256;
            if fp.len() != 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(InputError::RelyingParty(format!(
                    "operator pin {:?}: ak_spki_sha256 is not SHA-256 hex",
                    pin.source
                )));
            }
        }
        Ok(AnchorPolicy {
            trust_roots,
            operator_pins: self.operator_pins.clone(),
        })
    }
}

/// Parse the three documents and appraise. The EAR names this crate's
/// version as the verifier build, whichever binding called it, so the same
/// inputs give byte-identical reports in Rust, the browser and Python.
pub fn report(
    evidence_json: &[u8],
    reference_json: &[u8],
    relying_party_json: &[u8],
) -> Result<Report, InputError> {
    let evidence: NodeEvidence =
        serde_json::from_slice(evidence_json).map_err(|e| InputError::Evidence(e.to_string()))?;
    let reference: ReferenceManifest =
        serde_json::from_slice(reference_json).map_err(|e| InputError::Reference(e.to_string()))?;
    let rp: RelyingParty = serde_json::from_slice(relying_party_json)
        .map_err(|e| InputError::RelyingParty(e.to_string()))?;
    let anchors = rp.anchors()?;
    let evidence_sha256 = hex::encode(evidence_digest(evidence_json));
    Ok(
        match appraise(
            &evidence,
            &AppraisalPolicy {
                expected_binding: &rp.binding,
                freshness: rp.freshness.clone(),
                reference: &reference,
                anchors: &anchors,
                now: rp.now,
            },
        ) {
            Ok(a) => Report::Appraised {
                evidence_sha256,
                ear: a.to_ear(env!("CARGO_PKG_VERSION"), rp.now),
            },
            Err(refusal) => Report::Refused {
                evidence_sha256,
                refusal,
            },
        },
    )
}
