//! The records and their bytes: what a proposal freezes, what the owner signs, and the one
//! encoding both sides use.
//!
//! **The encoding** is the `gate approve` convention: a domain line, then `serde_json` of a
//! closed struct in its declared field order. There are no maps and no floats in any of these
//! types, so the bytes are deterministic. It is not RFC 8785, and nothing here pretends to be.
//!
//! **The one rule the approval path lacks** is [`decode_batch`]'s: the signature is checked over
//! the bytes that arrived, and those bytes are then parsed with `deny_unknown_fields`,
//! re-serialized, and refused unless the two byte strings are equal. Duplicate keys, reordered
//! fields, whitespace, alternative escapes and missing optional fields all fail that comparison,
//! so there is no second canonicalizer to drift from this one.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::DecisionError;

/// Domain of one option's digest.
pub const OPTION_DOMAIN: &[u8] = b"nucleus/owner-option/v1\n";
/// Domain of a frozen question's digest.
pub const QUESTION_DOMAIN: &[u8] = b"nucleus/owner-question/v1\n";
/// Domain of a decision's id.
pub const DECISION_DOMAIN: &[u8] = b"nucleus/owner-decision/v1\n";
/// Domain of the bytes the owner's key signs. Distinct from every approval domain, so a
/// decision batch cannot be presented as an approval or the reverse.
pub const BATCH_DOMAIN: &[u8] = b"nucleus/owner-decision-batch/v1\n";

/// Most decisions one batch may carry.
pub const MAX_BATCH: usize = 25;
/// Fewest and most options a question may offer.
pub const MIN_OPTIONS: usize = 2;
/// See [`MIN_OPTIONS`].
pub const MAX_OPTIONS: usize = 8;
/// The longest a decision may be relied on: 365 days, in seconds.
pub const MAX_VALIDITY_SECS: u64 = 365 * 24 * 60 * 60;

/// One option as proposed. All four fields are shown to the owner verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionBody {
    /// `"a".."h"`, unique within the question.
    pub id: String,
    /// What happens if this option is chosen.
    pub does: String,
    /// What it costs, for example `"S"` or `"M: two PRs"`.
    pub cost: String,
    /// What could go wrong.
    pub risk: String,
}

/// What a proposal freezes. The recommendation is inside, so swapping it later is a new digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionCore {
    /// `github~owner~name`, the control plane's tenant form.
    pub tenant: String,
    /// `owner/name`.
    pub repo: String,
    /// `[a-z0-9-]{1,64}`, unique per tenant.
    pub question_id: String,
    /// The question, as shown.
    pub question: String,
    /// Two to four lines of context.
    pub context: Vec<String>,
    /// URLs, or repository paths with lines.
    pub evidence: Vec<String>,
    /// The options, in display order.
    pub options: Vec<OptionBody>,
    /// The proposer's recommended option id, if any. The proposer's, never the owner's.
    pub recommended: Option<String>,
    /// Why the proposer recommends it.
    pub recommended_why: String,
    /// What a decision would authorize. The owner may narrow it, never widen it.
    pub proposed_scope: Scope,
}

/// What a decision authorizes, as structured lists. Never parsed out of prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    /// `owner/name#N`: the issues and pull requests the decision is about.
    pub refs: Vec<String>,
    /// Where acting on the decision may write: a literal path, or `<dir>/**` (see
    /// [`crate::Coverage`] for the exact grammar).
    pub paths: Vec<String>,
    /// Named runtime capabilities, for example `release.publish`.
    pub capabilities: Vec<String>,
}

/// One option the owner was shown, by id and digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionDigest {
    /// The option's id.
    pub id: String,
    /// [`option_sha256`] of the option's body, lowercase hex.
    pub option_sha256: String,
}

/// One owner decision. Signed only inside a [`DecisionBatch`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerDecision {
    /// Must equal the verifier's expected tenant.
    pub tenant: String,
    /// `owner/name`.
    pub repo: String,
    /// The question decided.
    pub question_id: String,
    /// [`question_sha256`] of the exact question, context and recommendation shown.
    pub question_sha256: String,
    /// EVERY option shown, in order, not only the chosen one.
    pub options: Vec<OptionDigest>,
    /// Must equal exactly one `options[i].id`.
    pub chosen: String,
    /// The proposed scope or a narrowing of it.
    pub scope: Scope,
    /// The owner's own words at signing. They constrain; a verifier never widens scope from them.
    pub conditions: Vec<String>,
    /// A one-shot decision may be spent once ([`crate::DecisionLedger::spend`]).
    pub single_use: bool,
    /// The decision id this one replaces, for the same question.
    pub supersedes: Option<String>,
    /// Unix seconds from which the decision may be relied on.
    pub valid_from: u64,
    /// Unix seconds after which it may not. At most [`MAX_VALIDITY_SECS`] after `valid_from`.
    pub not_after: u64,
}

/// What the owner's key signs, under [`BATCH_DOMAIN`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionBatch {
    /// The signing key's id ([`crate::kid_for`]).
    pub kid: String,
    /// The control-plane origin and tenant the batch was made for.
    pub aud: String,
    /// Unix seconds.
    pub issued_at: u64,
    /// The control plane's acceptance window only. A verifier relying on a decision reads
    /// `valid_from..not_after` instead: a batch is accepted within minutes, a decision is relied
    /// on for weeks.
    pub submit_by: u64,
    /// 128 bits, 32 lowercase hex.
    pub nonce: String,
    /// One to [`MAX_BATCH`] decisions, one tenant, strictly ascending by `question_id`.
    pub decisions: Vec<OwnerDecision>,
}

fn json<T: Serialize>(value: &T) -> Result<Vec<u8>, DecisionError> {
    // Every type here is a closed struct of strings, integers, booleans and vectors of those,
    // which serde_json cannot fail to write; the arm exists so a future field that could fail
    // refuses rather than signs nothing.
    serde_json::to_vec(value).map_err(|_| DecisionError::Unencodable)
}

fn domain_json<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>, DecisionError> {
    let mut out = domain.to_vec();
    out.extend_from_slice(&json(value)?);
    Ok(out)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `SHA-256(OPTION_DOMAIN || json(option))`, lowercase hex.
pub fn option_sha256(option: &OptionBody) -> Result<String, DecisionError> {
    Ok(sha256_hex(&domain_json(OPTION_DOMAIN, option)?))
}

/// `SHA-256(QUESTION_DOMAIN || json(core))`, lowercase hex.
pub fn question_sha256(core: &QuestionCore) -> Result<String, DecisionError> {
    Ok(sha256_hex(&domain_json(QUESTION_DOMAIN, core)?))
}

impl OwnerDecision {
    /// The decision's canonical bytes: [`DECISION_DOMAIN`] then its JSON. Its id is their hash.
    pub fn message(&self) -> Result<Vec<u8>, DecisionError> {
        domain_json(DECISION_DOMAIN, self)
    }

    /// `SHA-256(DECISION_DOMAIN || json(decision))`.
    pub fn decision_id(&self) -> Result<crate::DecisionId, DecisionError> {
        Ok(crate::DecisionId(Sha256::digest(self.message()?).into()))
    }

    /// The option digests a question's body yields, in its order: what this decision's
    /// `options` must equal.
    pub fn option_digests_of(core: &QuestionCore) -> Result<Vec<OptionDigest>, DecisionError> {
        core.options
            .iter()
            .map(|o| {
                Ok(OptionDigest {
                    id: o.id.clone(),
                    option_sha256: option_sha256(o)?,
                })
            })
            .collect()
    }
}

impl DecisionBatch {
    /// The exact bytes the owner's key signs: [`BATCH_DOMAIN`] then the batch's JSON.
    pub fn message(&self) -> Result<Vec<u8>, DecisionError> {
        domain_json(BATCH_DOMAIN, self)
    }
}

/// Parse a signed message into a batch, refusing any bytes that do not re-serialize to
/// themselves.
///
/// Call it only on bytes whose signature has already verified ([`crate::verify`] does); it
/// authorizes nothing by itself.
pub fn decode_batch(message: &[u8]) -> Result<DecisionBatch, DecisionError> {
    let body = message
        .strip_prefix(BATCH_DOMAIN)
        .ok_or(DecisionError::WrongDomain)?;
    let batch: DecisionBatch =
        serde_json::from_slice(body).map_err(|e| DecisionError::Malformed(e.to_string()))?;
    if batch.message()? != message {
        return Err(DecisionError::NonCanonical);
    }
    Ok(batch)
}
