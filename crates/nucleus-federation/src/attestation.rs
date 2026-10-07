// SPDX-License-Identifier: MIT
//
//! What an assertion says about the platform of the node that signed it
//! (ADR 0012, addendum A3).
//!
//! Every outbound assertion carries four flat string claims:
//!
//! | claim | value |
//! |---|---|
//! | [`TIER_CLAIM`] `nucleus_att_tier` | `attested`, `contested`, `expired` or `unattested` |
//! | [`EPOCH_CLAIM`] `nucleus_att_epoch` | the evidence epoch counter, decimal, or `none` |
//! | [`TIME_CLAIM`] `nucleus_att_time` | the epoch quote's time, Unix seconds, decimal, or `none` |
//! | [`EVIDENCE_CLAIM`] `nucleus_evidence_digest` | SHA-256 (hex) of the evidence document, or `none` |
//!
//! # Where the tier comes from
//!
//! [`NodeAttestation::of_current_evidence`] is the node's appraisal of its
//! **current** evidence: it parses the epoch document in force, runs
//! [`nucleus_node_evidence::appraise`] on it at the mint time, and takes the
//! tier from the [`Appraisal`] that returns. Nothing caches the result. A tier
//! other than `unattested` can only be built from an `Appraisal`, which only
//! `appraise` mints (ADR 0007 C-1), so no caller can write `attested` into an
//! assertion by hand.
//!
//! "Could not look" is never "attested" (ADR 0007 A-2). A node with no TPM, a
//! node whose evidence cannot be read, a node with no reference manifest to
//! appraise against, and evidence the appraisal refuses all yield
//! `unattested`. The node does **not** refuse to mint in those cases: nodes
//! without a TPM federate today, and refusing would turn an honest platform
//! fact into an outage. `unattested` is a claim a relying party can act on;
//! a refusal to mint is not.
//!
//! # The claims are never omitted
//!
//! [`crate::AssertionClaims::new`] takes a [`NodeAttestation`], not an
//! `Option`, and all four claims are always serialized. An omitted claim is
//! not a negative: a relying-party rule that tests `tier == 'attested'`
//! reads an absent claim as an error, and a verifier that tests
//! `tier != 'contested'` would read it as a pass. [`verify_attestation_claims`]
//! refuses an assertion that lacks any of them.
//!
//! # How stale `attested` can be
//!
//! The node appraises with a maximum age of one epoch plus
//! [`QUOTE_GRACE_SECS`] at the mint time `iat`, and the assertion lives
//! `exp - iat <= MAX_TTL`. So at any instant `T` a relying party accepts the
//! assertion (`T < exp`), the quote it names is at most
//! `epoch_secs + QUOTE_GRACE_SECS + (exp - iat)` old: 630 s with the
//! defaults (300 + 30 + 300). A relying party tightens that itself with
//! `exp - nucleus_att_time <= max`, which needs no clock of its own beyond the
//! `exp` check it already makes ([`RELYING_PARTY_CONDITION`]).

use nucleus_node_evidence::{
    AnchorPolicy, AppraisalPolicy, Freshness, FreshnessExpectation, KeyBinding, NodeEvidence,
    ReferenceManifest, Refusal, Tier, appraise, evidence_digest,
};
use serde::Serialize;
use serde_json::{Map, Value};

/// The appraised tier claim.
pub const TIER_CLAIM: &str = "nucleus_att_tier";
/// The evidence epoch counter claim.
pub const EPOCH_CLAIM: &str = "nucleus_att_epoch";
/// The epoch quote time claim (Unix seconds).
pub const TIME_CLAIM: &str = "nucleus_att_time";
/// The evidence document digest claim.
pub const EVIDENCE_CLAIM: &str = "nucleus_evidence_digest";
/// Every attestation claim, in the order the profile lists them.
pub const ATTESTATION_CLAIMS: [&str; 4] = [TIER_CLAIM, EPOCH_CLAIM, TIME_CLAIM, EVIDENCE_CLAIM];
/// The value of the epoch, time and digest claims when no evidence is named.
pub const NO_EVIDENCE: &str = "none";

/// Time the node allows past one epoch for the next re-quote to land, before
/// its own appraisal turns the evidence in force `expired`. A re-quote is a
/// TPM command plus a file write; thirty seconds is generous for it and
/// short against a 300 s epoch.
pub const QUOTE_GRACE_SECS: u64 = 30;

/// Clock skew tolerated between the quote's time and the time it is judged
/// at, in either party's appraisal. The same value `nucleus-audit` uses.
pub const MAX_FUTURE_SECS: u64 = 60;

/// The relying party's attribute condition, as a CEL expression over the
/// assertion's claims: the platform is `attested`, the quote the claim names
/// is at most 900 s old at the assertion's `exp` (and so at any time the
/// assertion is accepted), and it is not from after the assertion was minted
/// beyond [`MAX_FUTURE_SECS`].
///
/// Written against `assertion.*` only, so a provider that evaluates CEL over
/// the presented token needs no attribute mapping for it. JSON numbers reach
/// CEL as doubles and the epoch claims are strings, so both sides go through
/// `int()`. `docs/federated-upstream-profile.md` §8 quotes this string and the
/// runbook's provider recipe quotes [`relying_party_condition_for`]; a
/// `nucleus-node` test holds them equal (the node's test gate reads `docs/`).
pub const RELYING_PARTY_CONDITION: &str = "assertion.nucleus_att_tier == 'attested' \
     && int(assertion.exp) - int(assertion.nucleus_att_time) <= 900 \
     && int(assertion.nucleus_att_time) <= int(assertion.iat) + 60";

/// [`RELYING_PARTY_CONDITION`] behind the profile's upstream matcher
/// (`nucleus_upstream`, profile §2.2 rule 11): the condition one provider
/// registration for the registry entry `upstream` uses. `upstream` is a
/// registry name, which is never quoted text.
pub fn relying_party_condition_for(upstream: &str) -> String {
    format!("assertion.nucleus_upstream == '{upstream}' && {RELYING_PARTY_CONDITION}")
}

/// The tier an assertion states. The four EAR tiers, by their claim values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimedTier {
    /// The appraisal affirmed the platform.
    Attested,
    /// The measurements diverged from the reference.
    Contested,
    /// The evidence was not fresh at the mint time.
    Expired,
    /// No claim about the platform can be made.
    Unattested,
}

impl ClaimedTier {
    /// The tier of an appraisal. Exhaustive, so a tier added to the verifier
    /// does not compile here until it is given a claim value (E-1).
    pub fn of(tier: &Tier) -> Self {
        match tier {
            Tier::Attested => Self::Attested,
            Tier::Contested => Self::Contested,
            Tier::Expired { .. } => Self::Expired,
            Tier::Unattested { .. } => Self::Unattested,
        }
    }

    /// The claim value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attested => "attested",
            Self::Contested => "contested",
            Self::Expired => "expired",
            Self::Unattested => "unattested",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "attested" => Some(Self::Attested),
            "contested" => Some(Self::Contested),
            "expired" => Some(Self::Expired),
            "unattested" => Some(Self::Unattested),
            _ => None,
        }
    }
}

impl std::fmt::Display for ClaimedTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The epoch evidence a claim names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochRef {
    /// The epoch counter.
    pub counter: u64,
    /// The quote's time, Unix seconds.
    pub quoted_at: i64,
    /// SHA-256 of the evidence document bytes, lowercase hex.
    pub evidence_sha256: String,
}

/// Which evidence, if any, a claim names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceRef {
    /// None: the claim is `unattested` and names no document.
    NoEvidence,
    /// An epoch document.
    Epoch(EpochRef),
}

/// What the node states about its platform in one assertion.
///
/// Fields private: built only by [`NodeAttestation::without_evidence`]
/// (always `unattested`) or [`NodeAttestation::of_current_evidence`] (the
/// tier of an appraisal, or `unattested`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeAttestation {
    tier: ClaimedTier,
    evidence: EvidenceRef,
    /// Why the tier is what it is, for the node's log. Never a claim.
    note: String,
}

/// The node's inputs for appraising its own evidence. The same inputs a
/// relying party brings, chosen by the operator; none comes from the
/// evidence being appraised.
#[derive(Clone, Copy, Debug)]
pub struct SelfAppraisal<'a> {
    /// The binding the node's quotes must carry now: its executor key and the
    /// digest of the JWKS it currently publishes.
    pub binding: &'a KeyBinding,
    /// The reference manifest.
    pub reference: &'a ReferenceManifest,
    /// The anchors (operator pins, trust roots) for the AK.
    pub anchors: &'a AnchorPolicy,
    /// The oldest the evidence may be at the mint time
    /// ([`SelfAppraisal::max_age_for_epoch`]).
    pub max_age_secs: u64,
}

impl SelfAppraisal<'_> {
    /// The maximum age for a node that re-quotes every `epoch_secs`: one
    /// epoch, plus [`QUOTE_GRACE_SECS`] for the re-quote to land.
    pub fn max_age_for_epoch(epoch_secs: u64) -> u64 {
        epoch_secs.saturating_add(QUOTE_GRACE_SECS)
    }
}

impl NodeAttestation {
    /// `unattested`, naming no evidence: the node has no TPM attester, or
    /// could not read the evidence in force.
    pub fn without_evidence(reason: impl Into<String>) -> Self {
        Self {
            tier: ClaimedTier::Unattested,
            evidence: EvidenceRef::NoEvidence,
            note: reason.into(),
        }
    }

    /// The node's appraisal of its current epoch evidence `document` at
    /// `now`, the mint time.
    ///
    /// `appraisal` is `None` when the node has no reference to appraise
    /// against: the claim then names the evidence (a relying party can
    /// appraise it) and states `unattested`, because the node did not look.
    /// A document that does not parse or is not epoch evidence names nothing.
    /// A refusal is `unattested`, naming the document.
    pub fn of_current_evidence(
        document: &[u8],
        appraisal: Option<&SelfAppraisal<'_>>,
        now: i64,
    ) -> Self {
        let evidence: NodeEvidence = match serde_json::from_slice(document) {
            Ok(e) => e,
            Err(e) => return Self::without_evidence(format!("evidence does not parse: {e}")),
        };
        let Freshness::Epoch { counter, iat } = evidence.freshness else {
            return Self::without_evidence("the evidence in force is not epoch evidence");
        };
        let named = EvidenceRef::Epoch(EpochRef {
            counter,
            quoted_at: iat,
            evidence_sha256: hex::encode(evidence_digest(document)),
        });
        let Some(inputs) = appraisal else {
            return Self {
                tier: ClaimedTier::Unattested,
                evidence: named,
                note: "no reference manifest to appraise against".into(),
            };
        };
        let policy = AppraisalPolicy {
            expected_binding: inputs.binding,
            freshness: FreshnessExpectation::Epoch {
                receipt_time: now,
                max_age_secs: inputs.max_age_secs,
                max_future_secs: MAX_FUTURE_SECS,
            },
            reference: inputs.reference,
            anchors: inputs.anchors,
            now,
        };
        match appraise(&evidence, &policy) {
            Ok(a) => Self {
                tier: ClaimedTier::of(a.tier()),
                evidence: named,
                note: format!("appraised: {}", a.tier().ear_status()),
            },
            Err(refusal) => Self {
                tier: ClaimedTier::Unattested,
                evidence: named,
                note: format!("own evidence refused: {refusal}"),
            },
        }
    }

    /// The stated tier.
    pub fn tier(&self) -> ClaimedTier {
        self.tier
    }

    /// The evidence named.
    pub fn evidence(&self) -> &EvidenceRef {
        &self.evidence
    }

    /// Why the tier is what it is.
    pub fn note(&self) -> &str {
        &self.note
    }

    /// The four claim values, in [`ATTESTATION_CLAIMS`] order. One function
    /// writes them, and every one is a string whatever the evidence.
    pub(crate) fn claim_values(&self) -> (ClaimedTier, String, String, String) {
        match &self.evidence {
            EvidenceRef::NoEvidence => (
                self.tier,
                NO_EVIDENCE.into(),
                NO_EVIDENCE.into(),
                NO_EVIDENCE.into(),
            ),
            EvidenceRef::Epoch(e) => (
                self.tier,
                e.counter.to_string(),
                e.quoted_at.to_string(),
                e.evidence_sha256.clone(),
            ),
        }
    }
}

/// Why an assertion's attestation claims were refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ClaimRefusal {
    /// A claim is absent. An absent claim is not a negative.
    #[error("claim {0} is absent; an omitted attestation claim is refused, never read as a value")]
    Omitted(&'static str),
    /// A claim is present but not of its form.
    #[error("claim {0} is malformed")]
    Malformed(&'static str),
    /// Some of epoch, time and digest are `none` and some are not.
    #[error("the epoch, time and digest claims must all name evidence or all be `none`")]
    PartialEvidence,
    /// A tier other than `unattested` that names no evidence.
    #[error("tier {0} names no evidence")]
    TierWithoutEvidence(ClaimedTier),
    /// The named quote is older than the relying party allows.
    #[error("the named evidence is {age_secs}s old, beyond the {max_age_secs}s allowed")]
    Stale {
        /// Its age at the relying party's `now`.
        age_secs: u64,
        /// The relying party's limit.
        max_age_secs: u64,
    },
    /// The named quote's time is after the relying party's `now` beyond the skew.
    #[error("the named evidence is {ahead_secs}s in the future")]
    FromTheFuture {
        /// How far ahead.
        ahead_secs: u64,
    },
    /// The evidence held is not the document the digest claim names.
    #[error("the evidence held does not hash to {EVIDENCE_CLAIM}")]
    EvidenceDigest,
    /// The evidence held does not parse.
    #[error("the evidence held does not parse: {0}")]
    EvidenceUnreadable(String),
    /// The evidence is not the epoch, at the time, the claims name.
    #[error("the evidence held is not the epoch and time the claims name")]
    EpochMismatch,
    /// The evidence is not evidence.
    #[error("the named evidence is refused: {0}")]
    EvidenceRefused(Refusal),
    /// The claimed tier is not what the relying party's appraisal found.
    #[error("the assertion claims {claimed}, but the named evidence appraises {appraised}")]
    TierMismatch {
        /// What the assertion says.
        claimed: ClaimedTier,
        /// What the relying party's own appraisal says.
        appraised: ClaimedTier,
    },
}

/// The evidence a relying party holds for the claim, with its own appraisal
/// inputs.
#[derive(Clone, Copy, Debug)]
pub struct HeldEvidence<'a> {
    /// The evidence document's bytes, as fetched by the digest the claim names.
    pub document: &'a [u8],
    /// The binding the evidence must carry: the node's executor key and the
    /// SHA-256 of the JWKS the relying party registered for this issuer.
    pub binding: &'a KeyBinding,
    /// The relying party's reference manifest.
    pub reference: &'a ReferenceManifest,
    /// The relying party's anchors.
    pub anchors: &'a AnchorPolicy,
}

/// Whether the relying party re-appraises the evidence the claim names.
#[derive(Clone, Copy, Debug)]
pub enum Reappraisal<'a> {
    /// It does not: the claim is checked for presence, form and age only.
    ClaimOnly,
    /// It does, with this evidence and these inputs.
    Evidence(HeldEvidence<'a>),
}

/// The relying party's side of the check.
#[derive(Clone, Copy, Debug)]
pub struct RelyingPartyCheck<'a> {
    /// The relying party's time, Unix seconds.
    pub now: i64,
    /// The oldest the named quote may be at `now`. The same bound also limits
    /// the re-appraisal at the assertion's `iat`.
    pub max_age_secs: u64,
    /// Whether to re-appraise.
    pub reappraisal: Reappraisal<'a>,
}

/// An assertion's attestation claims that passed [`verify_attestation_claims`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAttestation {
    /// The claimed tier.
    pub tier: ClaimedTier,
    /// The evidence it names.
    pub evidence: EvidenceRef,
    /// The relying party's own tier for that evidence, when it re-appraised.
    pub reappraised: Option<ClaimedTier>,
}

fn string_claim<'a>(
    claims: &'a Map<String, Value>,
    name: &'static str,
) -> Result<&'a str, ClaimRefusal> {
    match claims.get(name) {
        None => Err(ClaimRefusal::Omitted(name)),
        Some(Value::String(s)) => Ok(s),
        Some(_) => Err(ClaimRefusal::Malformed(name)),
    }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Read the four attestation claims from an assertion's claim set. Every one
/// must be present and of its form; `none` must be all or nothing.
///
/// # Errors
/// [`ClaimRefusal::Omitted`], [`ClaimRefusal::Malformed`],
/// [`ClaimRefusal::PartialEvidence`], [`ClaimRefusal::TierWithoutEvidence`].
pub fn read_attestation_claims(
    claims: &Map<String, Value>,
) -> Result<(ClaimedTier, EvidenceRef), ClaimRefusal> {
    let tier = ClaimedTier::parse(string_claim(claims, TIER_CLAIM)?)
        .ok_or(ClaimRefusal::Malformed(TIER_CLAIM))?;
    let epoch = string_claim(claims, EPOCH_CLAIM)?;
    let time = string_claim(claims, TIME_CLAIM)?;
    let digest = string_claim(claims, EVIDENCE_CLAIM)?;
    let evidence = match (
        epoch == NO_EVIDENCE,
        time == NO_EVIDENCE,
        digest == NO_EVIDENCE,
    ) {
        (true, true, true) => EvidenceRef::NoEvidence,
        (false, false, false) => {
            let counter = epoch
                .parse::<u64>()
                .ok()
                .filter(|_| epoch.bytes().all(|b| b.is_ascii_digit()))
                .ok_or(ClaimRefusal::Malformed(EPOCH_CLAIM))?;
            let quoted_at = time
                .parse::<i64>()
                .ok()
                .filter(|_| time.bytes().all(|b| b.is_ascii_digit()))
                .ok_or(ClaimRefusal::Malformed(TIME_CLAIM))?;
            if !is_sha256_hex(digest) {
                return Err(ClaimRefusal::Malformed(EVIDENCE_CLAIM));
            }
            EvidenceRef::Epoch(EpochRef {
                counter,
                quoted_at,
                evidence_sha256: digest.to_string(),
            })
        }
        _ => return Err(ClaimRefusal::PartialEvidence),
    };
    if evidence == EvidenceRef::NoEvidence && tier != ClaimedTier::Unattested {
        return Err(ClaimRefusal::TierWithoutEvidence(tier));
    }
    Ok((tier, evidence))
}

fn age_check(quoted_at: i64, now: i64, max_age_secs: u64) -> Result<(), ClaimRefusal> {
    let age = i128::from(now).saturating_sub(i128::from(quoted_at));
    if age < 0 {
        let ahead = u64::try_from(age.saturating_neg()).unwrap_or(u64::MAX);
        if ahead > MAX_FUTURE_SECS {
            return Err(ClaimRefusal::FromTheFuture { ahead_secs: ahead });
        }
        return Ok(());
    }
    let age = u64::try_from(age).unwrap_or(u64::MAX);
    if age > max_age_secs {
        return Err(ClaimRefusal::Stale {
            age_secs: age,
            max_age_secs,
        });
    }
    Ok(())
}

/// Check an assertion's attestation claims, as a relying party.
///
/// `claims` must be the claim set of an assertion whose signature, `iss`,
/// `aud` and `exp` the caller has already verified (for example the
/// [`crate::ValidatedCaller::claims`] of an
/// [`crate::ExternalIssuerValidator`] configured with the node's issuer). The
/// claims are only as good as that check and as the key that signed them:
/// see ADR 0012 for why a TPM-bound key makes the tier more than the node's
/// word.
///
/// 1. All four claims are present and well formed ([`read_attestation_claims`]).
/// 2. The named quote is no older than `max_age_secs` at `now`, and not from
///    the future beyond [`MAX_FUTURE_SECS`].
/// 3. With [`Reappraisal::Evidence`]: the document hashes to the digest claim,
///    is the epoch and time the claims name, and the relying party's own
///    appraisal of it at the assertion's `iat` gives the claimed tier. A
///    claim of `unattested` is never contradicted by a stronger appraisal:
///    it is the node saying it did not vouch, which is never false.
///
/// # Errors
/// [`ClaimRefusal`], naming the first check that failed.
pub fn verify_attestation_claims(
    claims: &Map<String, Value>,
    check: &RelyingPartyCheck<'_>,
) -> Result<VerifiedAttestation, ClaimRefusal> {
    let (tier, evidence) = read_attestation_claims(claims)?;
    let epoch = match &evidence {
        EvidenceRef::NoEvidence => None,
        EvidenceRef::Epoch(e) => {
            age_check(e.quoted_at, check.now, check.max_age_secs)?;
            Some(e)
        }
    };
    let reappraised = match (check.reappraisal, epoch) {
        (Reappraisal::ClaimOnly, _) => None,
        // Nothing named, nothing to re-appraise: the claim is `unattested`.
        (Reappraisal::Evidence(_), None) => None,
        (Reappraisal::Evidence(held), Some(e)) => {
            Some(reappraise(&held, e, tier, claims, check.max_age_secs)?)
        }
    };
    Ok(VerifiedAttestation {
        tier,
        evidence,
        reappraised,
    })
}

fn reappraise(
    held: &HeldEvidence<'_>,
    named: &EpochRef,
    claimed: ClaimedTier,
    claims: &Map<String, Value>,
    max_age_secs: u64,
) -> Result<ClaimedTier, ClaimRefusal> {
    if hex::encode(evidence_digest(held.document)) != named.evidence_sha256 {
        return Err(ClaimRefusal::EvidenceDigest);
    }
    let evidence: NodeEvidence = serde_json::from_slice(held.document)
        .map_err(|e| ClaimRefusal::EvidenceUnreadable(e.to_string()))?;
    match evidence.freshness {
        Freshness::Epoch { counter, iat } if counter == named.counter && iat == named.quoted_at => {
        }
        _ => return Err(ClaimRefusal::EpochMismatch),
    }
    let iat = match claims.get("iat") {
        None => return Err(ClaimRefusal::Omitted("iat")),
        Some(v) => v.as_i64().ok_or(ClaimRefusal::Malformed("iat"))?,
    };
    let appraisal = appraise(
        &evidence,
        &AppraisalPolicy {
            expected_binding: held.binding,
            freshness: FreshnessExpectation::Epoch {
                receipt_time: iat,
                max_age_secs,
                max_future_secs: MAX_FUTURE_SECS,
            },
            reference: held.reference,
            anchors: held.anchors,
            now: iat,
        },
    )
    .map_err(ClaimRefusal::EvidenceRefused)?;
    let appraised = ClaimedTier::of(appraisal.tier());
    if claimed == appraised || claimed == ClaimedTier::Unattested {
        Ok(appraised)
    } else {
        Err(ClaimRefusal::TierMismatch { claimed, appraised })
    }
}
