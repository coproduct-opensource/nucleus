//! The records and their one encoding.
//!
//! **The encoding** is the signed-decision convention: a domain line, then `serde_json` of a
//! closed struct in declared field order. Maps are `BTreeMap`, so their keys serialize sorted.
//! There are no floats and no `serde_json::Value` anywhere in these types: an embedded
//! execution receipt travels as base64 of its own bytes, so the certificate's bytes never
//! depend on which `serde_json` map-ordering feature a build happens to unify.
//!
//! [`decode`] refuses any bytes that are not exactly that encoding: it parses with
//! `deny_unknown_fields`, re-serializes, and compares. An id is a digest of the exact signed
//! bytes, so there is one byte string per meaning and one id per generation.

use std::collections::BTreeMap;

use nucleus_ci_verdict::execution::RecordedExecution;
use nucleus_signed_decision::DecisionBundle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain of a seed's id.
pub const SEED_DOMAIN: &[u8] = b"nucleus/generation-seed/v1\n";
/// Domain of a generation's id and of the bytes its judge signs.
pub const GENERATION_DOMAIN: &[u8] = b"nucleus/generation/v1\n";
/// Domain of a rollback record's id and of the bytes its signer signs.
pub const ROLLBACK_DOMAIN: &[u8] = b"nucleus/generation-rollback/v1\n";
/// The capability an owner decision must name, exactly, to roll the judge back:
/// `generation.rollback:<seed id>:<from id>:<to id>`.
pub const ROLLBACK_CAPABILITY: &str = "generation.rollback";
/// The capability an owner waiver must name, exactly, for each metric it lets regress:
/// `generation.regress:<seed id>:<generation number>:<metric>`.
pub const WAIVER_CAPABILITY: &str = "generation.regress";

/// Which of the two co-recursive subjects a generation releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// The runtime: the thing that executes the judge's gates.
    Runtime,
    /// The judge: the CI that admits every generation, its own successors included.
    Judge,
}

impl Role {
    /// The ledger namespace this role's metrics live in. A generation measures and may move
    /// only its own namespace; the other carries forward unchanged.
    pub const fn namespace(self) -> &'static str {
        match self {
            Self::Runtime => "runtime.",
            Self::Judge => "judge.",
        }
    }
}

/// Which way a metric is better. Fixed when the metric first appears and never changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Higher is better: a rise improves, a fall regresses.
    Higher,
    /// Lower is better: a fall improves, a rise regresses.
    Lower,
    /// May not fall, and a rise is not an improvement: the anti-Goodhart partner of a
    /// metric that could otherwise be improved by deleting what it measures.
    Guard,
}

/// How strongly a generation's release is reproduced. Ordered weakest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Two or more builders disagreed on the release digest. The promoted digest is one of
    /// theirs, and the disagreement is shown, not hidden.
    Disagreed,
    /// One builder.
    SingleBuilder,
    /// Two or more distinct builders produced the same digest.
    Reproduced,
}

/// Generation zero: what the chain trusts before anything was judged. The operator pins its
/// id; everything after is derived from it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seed {
    /// A human name for the chain. Not an authority.
    pub chain: String,
    /// `owner/name` of the runtime.
    pub runtime_repo: String,
    /// `owner/name` of the judge.
    pub judge_repo: String,
    /// The signed-decision tenant an owner waiver must name.
    pub owner_tenant: String,
    /// The key id the first judge signs with.
    pub judge_kid: String,
    /// The first judge's Ed25519 verifying key, 64 lowercase hex.
    pub judge_key: String,
    /// SHA-256 of the runtime release the chain starts from.
    pub runtime_release_sha256: String,
    /// SHA-256 of the judge release the chain starts from.
    pub judge_release_sha256: String,
    /// The direction of every metric in [`Self::ledger`].
    pub directions: BTreeMap<String, Direction>,
    /// The starting value of every metric, both namespaces.
    pub ledger: BTreeMap<String, i64>,
    /// The weakest reproduction tier a generation may be promoted at.
    pub min_tier: Tier,
    /// Unix seconds.
    pub issued_at: u64,
}

/// One required gate's evidence: the node's execution receipt, and what the judge expected of
/// it. The expectation is the judge's record, but the executor key it names must also be one
/// the relying party pinned; a key is never trusted because a certificate carries it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateEvidence {
    /// Standard base64 of the receipt's exact JSON bytes.
    pub receipt_b64: String,
    /// The judge's expectation for that receipt.
    pub expected: RecordedExecution,
}

/// One builder's result for the release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Build {
    /// Which builder. Distinct builders must have distinct names.
    pub builder: String,
    /// The architecture it built on.
    pub architecture: String,
    /// SHA-256 of what it produced.
    pub artifact_sha256: String,
}

/// The key a judge generation will sign its successors' certificates with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeKey {
    /// Its key id.
    pub kid: String,
    /// Ed25519 verifying key, 64 lowercase hex.
    pub key: String,
}

/// One generation: a release of one role, judged by the latest judge generation before it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generation {
    /// The seed id this chain started from.
    pub seed: String,
    /// 1, 2, 3, ... with no gap.
    pub number: u64,
    /// The previous generation's id, or the seed id for generation 1.
    pub parent: String,
    /// Which subject this releases.
    pub role: Role,
    /// Must equal the seed's repository for this role.
    pub repo: String,
    /// The exact commit judged.
    pub source_commit: String,
    /// The exact tree judged.
    pub source_tree: String,
    /// SHA-256 of the admitted plan. Opaque here; the judge decided it.
    pub plan_sha256: String,
    /// The plan's required gates, strictly ascending. Never empty.
    pub required_gates: Vec<String>,
    /// One per required gate, in the same order.
    pub evidence: Vec<GateEvidence>,
    /// The required gate whose artifact is this generation's ledger.
    pub ledger_gate: String,
    /// That artifact's name in the gate's execution claim.
    pub ledger_artifact: String,
    /// Every metric in this role's namespace, after the change. Its exact bytes
    /// ([`ledger_bytes`]) are what the ledger gate's artifact digest must name.
    pub ledger: BTreeMap<String, i64>,
    /// Directions for metrics this generation introduces. A new metric cannot count as this
    /// generation's improvement.
    pub added_directions: BTreeMap<String, Direction>,
    /// The owner's signed decision letting named metrics regress. `None` means no metric may.
    pub waiver: Option<DecisionBundle>,
    /// Every builder's result. Never empty.
    pub builds: Vec<Build>,
    /// SHA-256 of what is promoted. Must be one of [`Self::builds`].
    pub release_sha256: String,
    /// For a judge generation, the key it will sign with once promoted. `None` for a runtime
    /// generation, and required for a judge generation.
    pub next_judge: Option<JudgeKey>,
    /// The id of the judge generation that judged this one (the seed id for the first judge).
    pub judged_by: String,
    /// The key id it signed with.
    pub judge_kid: String,
    /// Unix seconds. Never before the previous generation's.
    pub issued_at: u64,
}

/// A generation as it travels: the exact body bytes and the judge's signature over
/// [`GENERATION_DOMAIN`] followed by those bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGeneration {
    /// Standard base64 of the body's canonical JSON bytes.
    pub body_b64: String,
    /// Standard base64 of the 64-byte Ed25519 signature.
    pub signature_b64: String,
}

/// Moving one role's promotion pointer back to an earlier verified generation.
///
/// Owner decision, 2026-10-26: **a rollback is not a generation.** Under strict improvement a
/// revert can never be one, since it can only hold or regress what the generation it undoes
/// improved (gatehouse F-231). So a rollback carries no number and is judged for no
/// improvement: it restores the target's release and its role's ledger, and, for the judge, the
/// target's judge key. It is still linked into the log (the next entry's `parent` is its id), so
/// it cannot be dropped from a chain without breaking the chain.
///
/// Who may sign it follows from who might be broken:
///
/// * **Runtime:** the current judge, alone. Rolling back a runtime that failed its health check
///   is the judge's call and must not wait for a person.
/// * **Judge:** the judge key being restored, *and* an owner decision naming the capability
///   [`rollback_capability`]. The current judge's signature is not required, because the judge
///   being rolled back is the one that may be broken, and requiring it would let a broken judge
///   lock out its own repair (gatehouse F-211).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rollback {
    /// The seed id this chain started from.
    pub seed: String,
    /// The previous log entry's id: a generation, a rollback, or the seed.
    pub parent: String,
    /// Which role's pointer moves.
    pub role: Role,
    /// The generation currently promoted for that role (the seed id if none has been).
    pub from: String,
    /// An earlier verified generation of the same role, or the seed id.
    pub to: String,
    /// Why, in words. Never empty.
    pub reason: String,
    /// The owner's decision: required exactly for a judge rollback.
    pub decision: Option<DecisionBundle>,
    /// The key id of the signer.
    pub signer_kid: String,
    /// Unix seconds. Never before the previous entry's.
    pub issued_at: u64,
}

/// A rollback as it travels: the exact body bytes and the signature over [`ROLLBACK_DOMAIN`]
/// followed by those bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRollback {
    /// Standard base64 of the body's canonical JSON bytes.
    pub body_b64: String,
    /// Standard base64 of the 64-byte Ed25519 signature.
    pub signature_b64: String,
}

/// One entry of the log a relying party verifies, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "entry", rename_all = "snake_case")]
pub enum Entry {
    /// A generation.
    Generation(SignedGeneration),
    /// A rollback.
    Rollback(SignedRollback),
}

/// The capability an owner decision must carry to roll the judge back from `from` to `to` in
/// the chain seeded by `seed_id`.
pub fn rollback_capability(seed_id: &str, from: &str, to: &str) -> String {
    format!("{ROLLBACK_CAPABILITY}:{seed_id}:{from}:{to}")
}

/// Canonical bytes of any record: `serde_json` in declared field order.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(value)
}

/// Parse bytes as `T` and refuse them unless they are exactly [`encode`]'s output.
pub fn decode<T: Serialize + for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, DecodeError> {
    let value: T = serde_json::from_slice(bytes).map_err(|e| DecodeError::Parse(e.to_string()))?;
    let again = encode(&value).map_err(|e| DecodeError::Parse(e.to_string()))?;
    if again != bytes {
        return Err(DecodeError::NotCanonical);
    }
    Ok(value)
}

/// Why bytes are not a record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// Not JSON of the record's shape, or an unknown field.
    #[error("not a record: {0}")]
    Parse(String),
    /// A record, but not in its one encoding.
    #[error("not the canonical encoding")]
    NotCanonical,
}

/// The id of a domain-separated record: lowercase hex of `SHA-256(domain || bytes)`.
pub fn id_of(domain: &[u8], bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    hex::encode(h.finalize())
}

/// The exact bytes of a ledger artifact: [`encode`] of the map, keys sorted.
pub fn ledger_bytes(ledger: &BTreeMap<String, i64>) -> Result<Vec<u8>, serde_json::Error> {
    encode(ledger)
}

/// The capability string an owner waiver must carry to let `metric` regress in generation
/// `number` of the chain seeded by `seed_id`.
pub fn waiver_capability(seed_id: &str, number: u64, metric: &str) -> String {
    format!("{WAIVER_CAPABILITY}:{seed_id}:{number}:{metric}")
}
