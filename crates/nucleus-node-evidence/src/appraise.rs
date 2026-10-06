//! Appraisal: the RATS Verifier role (RFC 9334 §3). Evidence in, an
//! attestation result out.
//!
//! The result has two layers, kept apart because they have different
//! consequences (ADR 0007 A-8):
//!
//! * [`Refusal`] — the evidence is not evidence. A signature that does not
//!   verify, a log that does not replay to the quote, a quote bound to a
//!   different executor key, an anchor claim that is false. Nothing is
//!   appraised; the relying party must treat the node as unverified.
//! * [`Appraisal`] — the evidence is internally sound, and its [`Tier`] says
//!   what it shows: `Attested` (affirming), `Contested` (measurements diverge
//!   from the reference), `Expired` (not fresh under the relying party's
//!   policy), or `Unattested` (nothing ties the quote to a TPM, or there was
//!   no evidence at all — an honest tier, not an error).
//!
//! The four tiers are the AR4SI / EAR (draft-ietf-rats-ear) status tiers:
//! affirming, contraindicated, warning, none. An [`Appraisal`] can be minted
//! only by [`appraise`] (ADR 0007 C-1, C-2); an `Attested` tier always carries
//! an anchored AK, a fresh quote, and an empty divergence list, because the
//! one function that builds it computes the tier from those three facts.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::Malformed;
use crate::anchor::{self, AkAnchor, AnchorPolicy, UnanchoredReason};
use crate::binding::{Freshness, KeyBinding, Nonce, qualifying_data};
use crate::crypto::HashAlg;
use crate::eventlog::{BootFacts, SecureBoot, parse_event_log};
use crate::evidence::{BootLog, EVIDENCE_PROFILE, ImaLog, NodeEvidence};
use crate::ima::{ImaFacts, verify_ima_log};
use crate::reference::{CmdlineRule, DigestSet, Expect, REFERENCE_PROFILE, ReferenceManifest};
use crate::tpm::{AkPublic, SignatureError, parse_quote, verify_quote_signature};

const PCR_IMA: u8 = 10;

/// What the relying party expects about freshness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FreshnessExpectation {
    /// The relying party sent this nonce and wants a quote over it.
    Challenge {
        /// The nonce it sent.
        sent: Nonce,
    },
    /// The relying party checks epoch evidence against a receipt's time.
    Epoch {
        /// The receipt's time, Unix seconds.
        receipt_time: i64,
        /// The oldest the epoch quote may be at `receipt_time`.
        max_age_secs: u64,
        /// How far after `receipt_time` the quote may be (clock skew).
        max_future_secs: u64,
    },
}

/// Everything the relying party brings to an appraisal. None of it comes
/// from the evidence.
#[derive(Clone, Debug)]
pub struct AppraisalPolicy<'a> {
    /// The executor key (and federation set) the receipt names.
    pub expected_binding: &'a KeyBinding,
    /// The freshness requirement.
    pub freshness: FreshnessExpectation,
    /// The reference values.
    pub reference: &'a ReferenceManifest,
    /// The trust inputs for the AK anchor.
    pub anchors: &'a AnchorPolicy,
    /// The time to check certificate validity at, Unix seconds.
    pub now: i64,
}

/// Why evidence was refused outright.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize)]
#[serde(rename_all = "snake_case", tag = "refusal", content = "detail")]
pub enum Refusal {
    /// `eat_profile` is not [`EVIDENCE_PROFILE`].
    #[error("unknown evidence profile {0:?}")]
    UnknownProfile(String),
    /// The reference manifest's profile is not [`REFERENCE_PROFILE`].
    #[error("unknown reference manifest profile {0:?}")]
    UnknownReferenceProfile(String),
    /// A base64 or hex field did not decode.
    #[error("{field} does not decode: {reason}")]
    Encoding {
        /// The field.
        field: &'static str,
        /// The decoder's complaint.
        reason: String,
    },
    /// A binary structure did not parse.
    #[error("malformed: {0}")]
    Malformed(String),
    /// The AK lacks attributes a TPM attestation key has.
    #[error("the AK is not a restricted signing key (lacks {0:?})")]
    NotAnAttestationKey(Vec<&'static str>),
    /// The quote signature uses an unsupported scheme.
    #[error("unsupported quote signature: {0}")]
    UnsupportedSignature(String),
    /// The quote signature does not verify.
    #[error("the quote signature does not verify under the AK")]
    BadSignature,
    /// The quote's PCR selection is not one SHA-256 bank equal to the PCRs supplied.
    #[error("PCR selection: {0}")]
    PcrSelection(String),
    /// The supplied PCR values do not hash to the quote's `pcrDigest`.
    #[error("the supplied PCR values do not hash to the quoted pcrDigest")]
    PcrDigest,
    /// The evidence speaks for different keys than the receipt names.
    #[error("the evidence is bound to a different executor key or federation set")]
    BindingMismatch,
    /// The quote's qualifying data is not the binding + freshness the evidence claims.
    #[error("the quote's qualifying data does not commit to the claimed binding and freshness")]
    QualifyingData,
    /// The AK anchor the evidence claims is false (e.g. a broken certificate chain).
    #[error("false AK anchor claim: {0}")]
    FalseAnchor(String),
    /// The boot event log does not replay to a quoted PCR.
    #[error("the boot event log does not replay to quoted PCR {pcr}")]
    EventLogDoesNotReplay {
        /// The PCR.
        pcr: u8,
    },
    /// No prefix of the IMA log replays to the quoted PCR 10.
    #[error("no prefix of the IMA log replays to the quoted PCR 10")]
    ImaLogDoesNotReplay,
}

impl From<Malformed> for Refusal {
    fn from(m: Malformed) -> Self {
        Self::Malformed(m.to_string())
    }
}

/// Why evidence is not fresh.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleReason {
    /// A challenge quote over a nonce other than the one sent: a replay.
    NonceMismatch,
    /// A challenge was sent but the evidence is epoch evidence.
    NotAChallengeResponse,
    /// Epoch freshness was required but the evidence answers someone's challenge.
    NotEpochEvidence,
    /// The epoch quote is older than the policy allows at the receipt's time.
    TooOld {
        /// Seconds between the quote and the receipt.
        age_secs: u64,
        /// The policy's limit.
        max_age_secs: u64,
    },
    /// The epoch quote claims a time after the receipt beyond the allowed skew.
    FromTheFuture {
        /// Seconds the quote is ahead of the receipt.
        ahead_secs: u64,
    },
}

/// The freshness verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessVerdict {
    /// Fresh under the policy.
    Fresh,
    /// Not fresh.
    Stale(StaleReason),
}

/// One way the measurements differ from the reference, or could not be
/// compared with it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "item")]
pub enum Divergence {
    /// A pinned PCR has a different (or no quoted) value.
    Pcr {
        /// The PCR.
        index: u8,
        /// The pinned value.
        expected: String,
        /// The quoted value; `None` when the quote did not cover it.
        observed: Option<String>,
    },
    /// Secure Boot is in the other state.
    SecureBoot {
        /// Required state.
        expected: bool,
    },
    /// An EFI application not in the allowed set was loaded.
    EfiApplicationNotAllowed {
        /// Its digest.
        digest: String,
    },
    /// A required EFI application was not loaded.
    EfiApplicationMissing {
        /// Its digest.
        digest: String,
    },
    /// The boot loader loaded a file not in the allowed set.
    BootFileNotAllowed {
        /// Its digest.
        digest: String,
        /// The loader's (unauthenticated) path.
        path_label: String,
    },
    /// A required boot file was not loaded.
    BootFileMissing {
        /// Its digest.
        digest: String,
    },
    /// The kernel command line does not satisfy the rule.
    KernelCmdline {
        /// The measured command lines.
        observed: Vec<String>,
    },
    /// IMA measured a file not in the allowlist, or with a digest not allowed for its path.
    ImaFileNotAllowed {
        /// The path.
        path: String,
        /// The digest.
        digest: String,
    },
    /// IMA measured a file with a non-SHA-256 digest.
    ImaNotSha256 {
        /// The path.
        path: String,
        /// The algorithm.
        algorithm: String,
    },
    /// IMA recorded a measurement violation (a file changed while measured).
    ImaViolation,
    /// A required file was not measured with an allowed digest.
    ImaRequiredMissing {
        /// The path.
        path: String,
    },
    /// The check is required but could not be made. Never a pass (ADR 0007 A-2).
    NotEvaluable {
        /// The reference item.
        check: &'static str,
        /// Why.
        reason: String,
    },
}

/// Why the tier is `Unattested`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnattestedReason {
    /// The quote verified but nothing ties its key to a TPM.
    AkUnanchored(UnanchoredReason),
}

/// The attestation result tier (AR4SI / EAR status).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "tier")]
pub enum Tier {
    /// Affirming: anchored, fresh, and every required check matched.
    Attested,
    /// Contraindicated: the measurements diverge from the reference.
    Contested,
    /// Warning: the evidence is not fresh under the policy.
    Expired {
        /// Why.
        reason: StaleReason,
    },
    /// None: no claim about what booted can be made.
    Unattested {
        /// Why.
        reason: UnattestedReason,
    },
}

impl Tier {
    /// The EAR `ear.status` value for this tier.
    pub fn ear_status(&self) -> &'static str {
        match self {
            Self::Attested => "affirming",
            Self::Contested => "contraindicated",
            Self::Expired { .. } => "warning",
            Self::Unattested { .. } => "none",
        }
    }
}

/// The quote's clock and identity, for the record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QuoteSummary {
    /// SHA-256 of the AK's SubjectPublicKeyInfo, hex.
    pub ak_spki_sha256: String,
    /// The AK's key family.
    pub ak_family: &'static str,
    /// Quoted PCR indices.
    pub pcrs: BTreeSet<u8>,
    /// TPM reset count (boots).
    pub reset_count: u32,
    /// TPM restart count.
    pub restart_count: u32,
    /// TPM clock, ms.
    pub clock: u64,
    /// TPM firmware version.
    pub firmware_version: u64,
}

/// An attestation result. Minted only by [`appraise`].
#[derive(Clone, Debug, Serialize)]
pub struct Appraisal {
    tier: Tier,
    anchor: AkAnchor,
    freshness: FreshnessVerdict,
    divergences: Vec<Divergence>,
    not_checked: BTreeMap<&'static str, String>,
    binding: KeyBinding,
    evidence_freshness: Freshness,
    quote: QuoteSummary,
    boot: Option<BootFacts>,
    ima: Option<ImaFacts>,
}

impl Appraisal {
    /// The tier.
    pub fn tier(&self) -> &Tier {
        &self.tier
    }
    /// The AK anchor established.
    pub fn anchor(&self) -> &AkAnchor {
        &self.anchor
    }
    /// The freshness verdict.
    pub fn freshness(&self) -> &FreshnessVerdict {
        &self.freshness
    }
    /// Every divergence from the reference (empty for `Attested`).
    pub fn divergences(&self) -> &[Divergence] {
        &self.divergences
    }
    /// The reference items the manifest says are not checked, and why.
    pub fn not_checked(&self) -> &BTreeMap<&'static str, String> {
        &self.not_checked
    }
    /// The quote summary.
    pub fn quote(&self) -> &QuoteSummary {
        &self.quote
    }
    /// The verified boot facts, if a boot log was attached.
    pub fn boot(&self) -> Option<&BootFacts> {
        self.boot.as_ref()
    }
    /// The verified IMA facts, if an IMA log was attached and PCR 10 quoted.
    pub fn ima(&self) -> Option<&ImaFacts> {
        self.ima.as_ref()
    }

    /// An EAR-shaped (draft-ietf-rats-ear) JSON attestation result.
    pub fn to_ear(&self, verifier_build: &str, iat: i64) -> serde_json::Value {
        serde_json::json!({
            "eat_profile": "tag:github.com,2023:veraison/ear",
            "iat": iat,
            "ear.verifier-id": { "developer": "nucleus", "build": verifier_build },
            "submods": {
                "node": {
                    "ear.status": self.tier.ear_status(),
                    "nucleus.appraisal": self,
                }
            }
        })
    }
}

fn b64(field: &'static str, s: &str) -> Result<Vec<u8>, Refusal> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| Refusal::Encoding {
            field,
            reason: e.to_string(),
        })
}

fn hex32(field: &'static str, s: &str) -> Result<[u8; 32], Refusal> {
    let v = hex::decode(s).map_err(|e| Refusal::Encoding {
        field,
        reason: e.to_string(),
    })?;
    v.try_into().map_err(|_| Refusal::Encoding {
        field,
        reason: "expected 32 bytes".into(),
    })
}

fn freshness_verdict(claimed: &Freshness, expected: &FreshnessExpectation) -> FreshnessVerdict {
    let stale = FreshnessVerdict::Stale;
    match (claimed, expected) {
        (Freshness::Challenge { eat_nonce }, FreshnessExpectation::Challenge { sent }) => {
            if eat_nonce == sent {
                FreshnessVerdict::Fresh
            } else {
                stale(StaleReason::NonceMismatch)
            }
        }
        (Freshness::Epoch { .. }, FreshnessExpectation::Challenge { .. }) => {
            stale(StaleReason::NotAChallengeResponse)
        }
        (Freshness::Challenge { .. }, FreshnessExpectation::Epoch { .. }) => {
            stale(StaleReason::NotEpochEvidence)
        }
        (
            Freshness::Epoch { iat, .. },
            FreshnessExpectation::Epoch {
                receipt_time,
                max_age_secs,
                max_future_secs,
            },
        ) => {
            // i64 - i64 always fits in i128; saturating keeps the lint honest.
            let delta = i128::from(*receipt_time).saturating_sub(i128::from(*iat));
            if delta < 0 {
                let ahead = u64::try_from(delta.saturating_neg()).unwrap_or(u64::MAX);
                if ahead > *max_future_secs {
                    return stale(StaleReason::FromTheFuture { ahead_secs: ahead });
                }
                FreshnessVerdict::Fresh
            } else {
                let age = u64::try_from(delta).unwrap_or(u64::MAX);
                if age > *max_age_secs {
                    stale(StaleReason::TooOld {
                        age_secs: age,
                        max_age_secs: *max_age_secs,
                    })
                } else {
                    FreshnessVerdict::Fresh
                }
            }
        }
    }
}

fn check_digests(
    set: &DigestSet,
    observed: &[String],
    not_allowed: impl Fn(&String) -> Divergence,
    missing: impl Fn(&String) -> Divergence,
    out: &mut Vec<Divergence>,
) {
    let seen: BTreeSet<String> = observed.iter().map(|d| d.to_ascii_lowercase()).collect();
    for d in &seen {
        if !set.allowed.contains(d) {
            out.push(not_allowed(d));
        }
    }
    for d in &set.required {
        if !seen.contains(&d.to_ascii_lowercase()) {
            out.push(missing(d));
        }
    }
}

/// Collect the reference checks into divergences and not-checked items.
fn compare(
    manifest: &ReferenceManifest,
    quoted: &BTreeMap<u8, [u8; 32]>,
    boot: Option<&BootFacts>,
    boot_absent: &str,
    ima: Option<&ImaFacts>,
    ima_absent: &str,
) -> (Vec<Divergence>, BTreeMap<&'static str, String>) {
    let rv = &manifest.reference_values;
    let mut out = Vec::new();
    let mut skipped = BTreeMap::new();

    for (index, expected) in &rv.pcrs {
        let observed = quoted.get(index).map(hex::encode);
        if observed.as_deref() != Some(expected.to_ascii_lowercase().as_str()) {
            out.push(Divergence::Pcr {
                index: *index,
                expected: expected.clone(),
                observed,
            });
        }
    }

    // A boot-log check needs the log and the PCR it reads from verified.
    let needs = |check: &'static str, pcr: u8, out: &mut Vec<Divergence>| -> Option<&BootFacts> {
        match boot {
            None => {
                out.push(Divergence::NotEvaluable {
                    check,
                    reason: boot_absent.to_string(),
                });
                None
            }
            Some(b) if !b.verified_pcrs.contains(&pcr) => {
                out.push(Divergence::NotEvaluable {
                    check,
                    reason: format!("PCR {pcr} was not quoted or has no logged events"),
                });
                None
            }
            Some(b) => Some(b),
        }
    };

    match &rv.secure_boot {
        Expect::NotChecked(why) => {
            skipped.insert("secure_boot", why.clone());
        }
        Expect::Required(expected) => {
            if let Some(b) = needs("secure_boot", 7, &mut out) {
                match (&b.secure_boot, expected) {
                    (SecureBoot::Enabled, true) | (SecureBoot::Disabled, false) => {}
                    (SecureBoot::Enabled, false) | (SecureBoot::Disabled, true) => {
                        out.push(Divergence::SecureBoot {
                            expected: *expected,
                        })
                    }
                    (SecureBoot::Unknown(why), _) => out.push(Divergence::NotEvaluable {
                        check: "secure_boot",
                        reason: why.clone(),
                    }),
                }
            }
        }
    }

    match &rv.efi_applications {
        Expect::NotChecked(why) => {
            skipped.insert("efi_applications", why.clone());
        }
        Expect::Required(set) => {
            if let Some(b) = needs("efi_applications", 4, &mut out) {
                check_digests(
                    set,
                    &b.efi_applications,
                    |d| Divergence::EfiApplicationNotAllowed { digest: d.clone() },
                    |d| Divergence::EfiApplicationMissing { digest: d.clone() },
                    &mut out,
                );
            }
        }
    }

    match &rv.boot_files {
        Expect::NotChecked(why) => {
            skipped.insert("boot_files", why.clone());
        }
        Expect::Required(set) => {
            if let Some(b) = needs("boot_files", 9, &mut out) {
                let digests: Vec<String> = b.boot_files.iter().map(|f| f.sha256.clone()).collect();
                let label = |d: &String| {
                    b.boot_files
                        .iter()
                        .find(|f| &f.sha256 == d)
                        .map(|f| f.path_label.clone())
                        .unwrap_or_default()
                };
                check_digests(
                    set,
                    &digests,
                    |d| Divergence::BootFileNotAllowed {
                        digest: d.clone(),
                        path_label: label(d),
                    },
                    |d| Divergence::BootFileMissing { digest: d.clone() },
                    &mut out,
                );
            }
        }
    }

    match &rv.kernel_cmdline {
        Expect::NotChecked(why) => {
            skipped.insert("kernel_cmdline", why.clone());
        }
        Expect::Required(rule) => {
            if let Some(b) = needs("kernel_cmdline", 8, &mut out) {
                if b.kernel_cmdlines.is_empty() {
                    out.push(Divergence::NotEvaluable {
                        check: "kernel_cmdline",
                        reason: "no digest-authenticated kernel_cmdline event in PCR 8".into(),
                    });
                } else {
                    let ok = b.kernel_cmdlines.iter().all(|c| match rule {
                        CmdlineRule::Exact(s) => c == s,
                        CmdlineRule::RequiredParams(ps) => {
                            let toks: BTreeSet<&str> = c.split_whitespace().collect();
                            ps.iter().all(|p| toks.contains(p.as_str()))
                        }
                        CmdlineRule::ExactParams(ps) => {
                            let toks: BTreeSet<&str> = c.split_whitespace().collect();
                            toks == ps.iter().map(String::as_str).collect()
                        }
                    });
                    if !ok {
                        out.push(Divergence::KernelCmdline {
                            observed: b.kernel_cmdlines.clone(),
                        });
                    }
                }
            }
        }
    }

    match &rv.ima {
        Expect::NotChecked(why) => {
            skipped.insert("ima", why.clone());
        }
        Expect::Required(reference) => match ima {
            None => out.push(Divergence::NotEvaluable {
                check: "ima",
                reason: ima_absent.to_string(),
            }),
            Some(facts) => {
                let mut satisfied = BTreeSet::new();
                for e in &facts.entries {
                    if e.path == "<violation>" {
                        out.push(Divergence::ImaViolation);
                        continue;
                    }
                    if e.path == "boot_aggregate" {
                        continue;
                    }
                    if e.algorithm != "sha256" {
                        out.push(Divergence::ImaNotSha256 {
                            path: e.path.clone(),
                            algorithm: e.algorithm.clone(),
                        });
                        continue;
                    }
                    let allowed = reference
                        .allowlist
                        .get(&e.path)
                        .is_some_and(|ds| ds.iter().any(|d| d.eq_ignore_ascii_case(&e.digest)));
                    if allowed {
                        satisfied.insert(e.path.clone());
                    } else {
                        out.push(Divergence::ImaFileNotAllowed {
                            path: e.path.clone(),
                            digest: e.digest.clone(),
                        });
                    }
                }
                for p in &reference.required {
                    if !satisfied.contains(p) {
                        out.push(Divergence::ImaRequiredMissing { path: p.clone() });
                    }
                }
            }
        },
    }
    (out, skipped)
}

/// Appraise `evidence` under `policy`.
pub fn appraise(
    evidence: &NodeEvidence,
    policy: &AppraisalPolicy<'_>,
) -> Result<Appraisal, Refusal> {
    if evidence.eat_profile != EVIDENCE_PROFILE {
        return Err(Refusal::UnknownProfile(evidence.eat_profile.clone()));
    }
    if policy.reference.profile != REFERENCE_PROFILE {
        return Err(Refusal::UnknownReferenceProfile(
            policy.reference.profile.clone(),
        ));
    }

    // 1. The quote is a quote, signed by a restricted signing key.
    let ak = AkPublic::from_tpm2b_public(&b64("tpm.ak_public", &evidence.tpm.ak_public)?)?;
    let missing = ak.missing_attestation_attributes();
    if !missing.is_empty() {
        return Err(Refusal::NotAnAttestationKey(missing));
    }
    let attest = b64("tpm.attest", &evidence.tpm.attest)?;
    let signature = b64("tpm.signature", &evidence.tpm.signature)?;
    let quote = parse_quote(&attest)?;
    let hash = verify_quote_signature(&ak, &attest, &signature).map_err(|e| match e {
        SignatureError::Unsupported(s) => Refusal::UnsupportedSignature(s),
        SignatureError::Malformed(m) => Refusal::from(m),
        SignatureError::Invalid => Refusal::BadSignature,
    })?;

    // 2. The PCR values supplied are the ones quoted.
    let [(bank, selected)] = quote.pcr_selection.as_slice() else {
        return Err(Refusal::PcrSelection(format!(
            "{} banks selected; exactly one (SHA-256) is accepted",
            quote.pcr_selection.len()
        )));
    };
    if HashAlg::from_tpm(*bank) != Some(HashAlg::Sha256) {
        return Err(Refusal::PcrSelection(format!(
            "bank 0x{bank:04x} is not SHA-256"
        )));
    }
    let mut quoted = BTreeMap::new();
    for (index, value) in &evidence.tpm.pcrs {
        quoted.insert(*index, hex32("tpm.pcrs", value)?);
    }
    let supplied: BTreeSet<u8> = quoted.keys().copied().collect();
    if &supplied != selected {
        return Err(Refusal::PcrSelection(format!(
            "quote selects {selected:?} but evidence supplies {supplied:?}"
        )));
    }
    let concat: Vec<u8> = quoted.values().flatten().copied().collect();
    if hash.digest(&concat) != quote.pcr_digest {
        return Err(Refusal::PcrDigest);
    }

    // 3. The quote speaks for the receipt's keys, at the claimed freshness.
    if &evidence.binding != policy.expected_binding {
        return Err(Refusal::BindingMismatch);
    }
    if quote.extra_data != qualifying_data(&evidence.binding, &evidence.freshness) {
        return Err(Refusal::QualifyingData);
    }

    // 4. The anchor, against the relying party's inputs only.
    let anchor = anchor::resolve(&evidence.ak_anchor, &ak, policy.anchors, policy.now)
        .map_err(Refusal::FalseAnchor)?;

    // 5. The logs replay to the quote.
    let (boot, boot_absent) = match &evidence.boot_event_log {
        BootLog::Absent(why) => (None, format!("boot event log not attached: {why}")),
        BootLog::Attached(b) => {
            let log = parse_event_log(&b64("boot_event_log", b)?)?;
            let facts = log
                .verify_against(&quoted)
                .map_err(|m| Refusal::EventLogDoesNotReplay { pcr: m.pcr })?;
            (Some(facts), String::new())
        }
    };
    let (ima, ima_absent) = match (&evidence.ima_log, quoted.get(&PCR_IMA)) {
        (ImaLog::Absent(why), _) => (None, format!("IMA log not attached: {why}")),
        (ImaLog::Attached { .. }, None) => (None, "PCR 10 was not quoted".to_string()),
        (ImaLog::Attached { format, log }, Some(pcr10)) => {
            let facts = verify_ima_log(&b64("ima_log", log)?, *format, pcr10)?
                .ok_or(Refusal::ImaLogDoesNotReplay)?;
            (Some(facts), String::new())
        }
    };

    // 6. Freshness and the reference.
    let freshness = freshness_verdict(&evidence.freshness, &policy.freshness);
    let (divergences, not_checked) = compare(
        policy.reference,
        &quoted,
        boot.as_ref(),
        &boot_absent,
        ima.as_ref(),
        &ima_absent,
    );

    // 7. The tier, from the three facts and nothing else.
    let tier = match (&anchor, &freshness, divergences.is_empty()) {
        (AkAnchor::None { reason }, _, _) => Tier::Unattested {
            reason: UnattestedReason::AkUnanchored(reason.clone()),
        },
        (_, FreshnessVerdict::Stale(reason), _) => Tier::Expired {
            reason: reason.clone(),
        },
        (_, FreshnessVerdict::Fresh, false) => Tier::Contested,
        (
            AkAnchor::CertificateChain { .. } | AkAnchor::OperatorFetched { .. },
            FreshnessVerdict::Fresh,
            true,
        ) => Tier::Attested,
    };

    Ok(Appraisal {
        tier,
        anchor,
        freshness,
        divergences,
        not_checked,
        binding: evidence.binding.clone(),
        evidence_freshness: evidence.freshness.clone(),
        quote: QuoteSummary {
            ak_spki_sha256: hex::encode(ak.spki_sha256()),
            ak_family: ak.family(),
            pcrs: supplied,
            reset_count: quote.reset_count,
            restart_count: quote.restart_count,
            clock: quote.clock,
            firmware_version: quote.firmware_version,
        },
        boot,
        ima,
    })
}
