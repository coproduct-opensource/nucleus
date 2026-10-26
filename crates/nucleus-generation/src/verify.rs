//! The one verifier: walk a chain from its pinned seed and mint a [`VerifiedChain`].

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use nucleus_ci_verdict::execution::{ExecutionClaim, verify_execution};
use nucleus_receipt::Receipt;
use nucleus_signed_decision::{Coverage, ScopeRef, TrustRoots};
use sha2::{Digest, Sha256};

use crate::improve::{Judgement, judge};
use crate::record::{
    Build, DecodeError, Direction, GENERATION_DOMAIN, Generation, Role, SEED_DOMAIN, Seed,
    SignedGeneration, Tier, decode, id_of, ledger_bytes, waiver_capability,
};

/// What the relying party pins. Nothing here is read out of a certificate.
pub struct Pins<'a> {
    /// The seed id the chain must start from.
    pub seed_id: &'a str,
    /// Executor (node) keys whose execution receipts count. A key a certificate names that is
    /// not here is refused, however well it verifies.
    pub executor_keys: &'a [[u8; 32]],
    /// The owner's decision trust roots, for waivers.
    pub owner_roots: &'a TrustRoots,
}

/// Why a seed is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SeedError {
    /// The bytes are not a seed in its one encoding.
    #[error("seed: {0}")]
    Decode(DecodeError),
    /// The seed's id is not the pinned one.
    #[error("seed id {got} is not the pinned {pinned}")]
    NotPinned {
        /// The pin.
        pinned: String,
        /// What the bytes hash to.
        got: String,
    },
    /// A field is malformed.
    #[error("seed field {0} is malformed")]
    Malformed(&'static str),
    /// A metric has no direction, or a direction no metric.
    #[error("seed metric {0} lacks a direction or a value")]
    Directions(String),
    /// A metric is in neither namespace.
    #[error("seed metric {0} is in no role's namespace")]
    Namespace(String),
}

/// Why a generation is refused. Each names the defect it exists to catch.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The envelope's base64 does not decode.
    #[error("envelope field {0} is not base64")]
    Envelope(&'static str),
    /// The signature does not verify under the current judge's key. This is the refusal a
    /// candidate that tried to judge itself gets: its own key is not the current judge's.
    #[error("not signed by the current judge")]
    BadSignature,
    /// The signed bytes are not a generation in its one encoding.
    #[error("body: {0}")]
    Decode(DecodeError),
    /// The generation names another chain.
    #[error("names seed {0}, not this chain's")]
    WrongSeed(String),
    /// Out of sequence.
    #[error("number {got}, expected {expected}")]
    Number {
        /// The next number.
        expected: u64,
        /// What it says.
        got: u64,
    },
    /// The parent link does not name the previous generation.
    #[error("parent {0} is not the previous generation")]
    Parent(String),
    /// The judge it names is not the latest judge generation.
    #[error("judged by {got}, but the current judge is {current}")]
    NotCurrentJudge {
        /// The current judge generation's id.
        current: String,
        /// The one it names.
        got: String,
    },
    /// The key id it names is not the current judge's.
    #[error("judge kid {got} is not the current judge's {current}")]
    JudgeKid {
        /// The current judge's kid.
        current: String,
        /// The one it names.
        got: String,
    },
    /// The repository is not the seed's for this role.
    #[error("repository {0} is not this role's")]
    Repo(String),
    /// Issued before its predecessor.
    #[error("issued at {got}, before the previous {previous}")]
    IssuedBackwards {
        /// The previous issue time.
        previous: u64,
        /// This one.
        got: u64,
    },
    /// A field is malformed.
    #[error("field {0} is malformed")]
    Malformed(&'static str),
    /// The required gates are empty, unsorted or repeated.
    #[error("required gates must be non-empty and strictly ascending")]
    RequiredGates,
    /// The evidence does not match the required gates one to one, in order.
    #[error("evidence for gate {0} is missing or out of order")]
    EvidenceShape(String),
    /// The expectation names another commit or tree than the generation's.
    #[error("gate {0}: expectation is for another commit or tree")]
    WrongSubject(String),
    /// The executor key is not one the relying party pinned.
    #[error("gate {0}: executor key is not pinned")]
    UnpinnedExecutor(String),
    /// The receipt does not decode.
    #[error("gate {gate}: receipt does not decode: {reason}")]
    Receipt {
        /// Which gate.
        gate: String,
        /// Why.
        reason: String,
    },
    /// The receipt does not verify against its expectation.
    #[error("gate {gate}: {reason}")]
    Execution {
        /// Which gate.
        gate: String,
        /// The execution verifier's refusal.
        reason: String,
    },
    /// The gate did not exit zero. A missing result is a failure, not a pass.
    #[error("gate {gate} did not pass: exit {exit:?}")]
    GateFailed {
        /// Which gate.
        gate: String,
        /// What it observed.
        exit: Option<i32>,
    },
    /// The ledger gate is not a required gate, or its artifact is absent.
    #[error("ledger artifact {0} is not produced by a required gate")]
    LedgerSource(String),
    /// The ledger's bytes do not hash to the artifact the verified execution names.
    #[error("ledger does not match the ledger gate's artifact")]
    LedgerBinding,
    /// A metric outside this role's namespace.
    #[error("metric {0} is outside this role's namespace")]
    Namespace(String),
    /// A metric that was measured before is missing now.
    #[error("metric {0} vanished")]
    Vanished(String),
    /// A metric with no direction.
    #[error("metric {0} has no direction")]
    NoDirection(String),
    /// A direction for a metric that already had one. Directions never change.
    #[error("metric {0} already has a direction")]
    Redirected(String),
    /// Nothing strictly improved. Owner decision 2026-10-26: not waivable.
    #[error("no metric strictly improved")]
    NoImprovement,
    /// A metric regressed and no owner waiver names it.
    #[error("metric {0} regressed and no owner waiver names it")]
    Unwaived(String),
    /// The waiver does not verify.
    #[error("waiver: {0}")]
    Waiver(String),
    /// A waiver is attached and nothing regressed.
    #[error("a waiver is attached and nothing regressed")]
    UnusedWaiver,
    /// The builds are empty or name a builder twice.
    #[error("builds must be non-empty with distinct builders")]
    Builds,
    /// The promoted digest is not one any builder produced.
    #[error("release is not one any builder produced")]
    ReleaseNotBuilt,
    /// The reproduction tier is below the seed's floor.
    #[error("tier {got:?} is below the seed's floor {floor:?}")]
    BelowTier {
        /// The floor.
        floor: Tier,
        /// What this reached.
        got: Tier,
    },
    /// A judge generation without a successor key, or a runtime generation with one.
    #[error("next_judge must be present exactly for a judge generation")]
    NextJudge,
    /// The generation number overflowed.
    #[error("generation number overflow")]
    Overflow,
}

/// A chain refusal: the seed, or the generation at a position and why.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// The seed itself.
    #[error("{0}")]
    Seed(SeedError),
    /// The generation at this position (1-based, the number it should carry).
    #[error("generation {at}: {refusal}")]
    Generation {
        /// Position.
        at: u64,
        /// Why.
        refusal: Refusal,
    },
}

/// One verified generation, as a relying party reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGeneration {
    id: String,
    number: u64,
    role: Role,
    release_sha256: String,
    tier: Tier,
    improved: Vec<String>,
    waived: Vec<String>,
}

impl VerifiedGeneration {
    /// Its id.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Its number.
    pub const fn number(&self) -> u64 {
        self.number
    }
    /// Which role it released.
    pub const fn role(&self) -> Role {
        self.role
    }
    /// What was promoted.
    pub fn release_sha256(&self) -> &str {
        &self.release_sha256
    }
    /// How strongly the release was reproduced. Shown on every generation, never hidden.
    pub const fn tier(&self) -> Tier {
        self.tier
    }
    /// The metrics it strictly improved. Never empty.
    pub fn improved(&self) -> &[String] {
        &self.improved
    }
    /// The metrics the owner let regress. Usually empty.
    pub fn waived(&self) -> &[String] {
        &self.waived
    }
}

/// A chain whose every generation verified from the pinned seed.
///
/// Fields private; the only constructor is [`verify_chain`] (ADR 0007 C-1).
#[derive(Debug)]
#[must_use = "a verified chain is evidence; read its head"]
pub struct VerifiedChain {
    seed_id: String,
    /// The head this was decided against: the last generation's id, or the seed id for an
    /// empty chain. A verified chain is only current while its head is still the head; a
    /// relying party compares this before acting on it, rather than trusting a verdict about
    /// a chain that has since grown.
    generation: String,
    generations: Vec<VerifiedGeneration>,
    ledger: BTreeMap<String, i64>,
    runtime_release: String,
    judge_release: String,
}

impl VerifiedChain {
    /// The seed it starts from.
    pub fn seed_id(&self) -> &str {
        &self.seed_id
    }
    /// The head this was verified against (see the field). Compare it to the live head before
    /// relying on anything else here.
    pub fn generation(&self) -> &str {
        &self.generation
    }
    /// Every generation, in order.
    pub fn generations(&self) -> &[VerifiedGeneration] {
        &self.generations
    }
    /// The ledger after the last generation, both namespaces.
    pub fn ledger(&self) -> &BTreeMap<String, i64> {
        &self.ledger
    }
    /// The runtime release now promoted.
    pub fn runtime_release(&self) -> &str {
        &self.runtime_release
    }
    /// The judge release now promoted.
    pub fn judge_release(&self) -> &str {
        &self.judge_release
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn key_of(hex64: &str) -> Option<ed25519_dalek::VerifyingKey> {
    if !is_hex64(hex64) {
        return None;
    }
    let bytes: [u8; 32] = hex::decode(hex64).ok()?.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()
}

/// What the walk carries from one generation to the next.
struct State {
    seed_id: String,
    seed: Seed,
    previous_id: String,
    previous_issued_at: u64,
    next_number: u64,
    judge_id: String,
    judge_kid: String,
    judge_key: ed25519_dalek::VerifyingKey,
    directions: BTreeMap<String, Direction>,
    ledger: BTreeMap<String, i64>,
    runtime_release: String,
    judge_release: String,
}

fn open_seed(bytes: &[u8], pinned: &str) -> Result<State, SeedError> {
    let id = id_of(SEED_DOMAIN, bytes);
    if id != pinned {
        return Err(SeedError::NotPinned {
            pinned: pinned.to_string(),
            got: id,
        });
    }
    let seed: Seed = decode(bytes).map_err(SeedError::Decode)?;
    let Seed {
        chain: _,
        runtime_repo,
        judge_repo,
        owner_tenant,
        judge_kid,
        judge_key,
        runtime_release_sha256,
        judge_release_sha256,
        directions,
        ledger,
        min_tier: _,
        issued_at,
    } = &seed;
    for (field, ok) in [
        ("runtime_repo", !runtime_repo.is_empty()),
        (
            "judge_repo",
            !judge_repo.is_empty() && judge_repo != runtime_repo,
        ),
        ("owner_tenant", !owner_tenant.is_empty()),
        ("judge_kid", !judge_kid.is_empty()),
        ("runtime_release_sha256", is_hex64(runtime_release_sha256)),
        ("judge_release_sha256", is_hex64(judge_release_sha256)),
    ] {
        if !ok {
            return Err(SeedError::Malformed(field));
        }
    }
    let key = key_of(judge_key).ok_or(SeedError::Malformed("judge_key"))?;
    let named: BTreeSet<&String> = directions.keys().chain(ledger.keys()).collect();
    for name in named {
        if !directions.contains_key(name) || !ledger.contains_key(name) {
            return Err(SeedError::Directions(name.clone()));
        }
        if !name.starts_with(Role::Runtime.namespace())
            && !name.starts_with(Role::Judge.namespace())
        {
            return Err(SeedError::Namespace(name.clone()));
        }
    }
    Ok(State {
        seed_id: id.clone(),
        previous_id: id.clone(),
        previous_issued_at: *issued_at,
        next_number: 1,
        judge_id: id,
        judge_kid: judge_kid.clone(),
        judge_key: key,
        directions: directions.clone(),
        ledger: ledger.clone(),
        runtime_release: runtime_release_sha256.clone(),
        judge_release: judge_release_sha256.clone(),
        seed,
    })
}

/// Verify a chain: the seed's bytes, then every generation in order.
///
/// For each generation, in order, each a refusal by name: the signature over the received bytes
/// under the **current** judge's key (so a candidate can never judge itself); the canonical
/// encoding; the seed, number, parent, judge id and kid; the repository for its role; issue
/// time not running backwards; every required gate evidenced once, in order, by a receipt for
/// this exact commit and tree, from a pinned executor, that verifies and exited zero; the ledger
/// bytes bound to the ledger gate's verified artifact; the namespace, no vanished metric, no
/// direction changed; strict improvement, with every regression named in a verified owner
/// waiver; the builds, the release among them, and the reproduction tier against the seed's
/// floor; and a successor judge key exactly when the role is the judge.
///
/// What it does not check: freshness. Each receipt's window was the judge's to enforce when it
/// judged; re-checking it against today's clock would refuse every historical generation. Nor
/// does it check log inclusion or witness cosignatures; that is a separate, later layer.
pub fn verify_chain(
    seed_bytes: &[u8],
    generations: &[SignedGeneration],
    pins: &Pins<'_>,
) -> Result<VerifiedChain, ChainError> {
    let mut state = open_seed(seed_bytes, pins.seed_id).map_err(ChainError::Seed)?;
    let mut verified = Vec::with_capacity(generations.len());
    for signed in generations {
        let at = state.next_number;
        let one = step(&mut state, signed, pins)
            .map_err(|refusal| ChainError::Generation { at, refusal })?;
        verified.push(one);
    }
    let State {
        seed_id,
        seed: _,
        previous_id,
        previous_issued_at: _,
        next_number: _,
        judge_id: _,
        judge_kid: _,
        judge_key: _,
        directions: _,
        ledger,
        runtime_release,
        judge_release,
    } = state;
    Ok(VerifiedChain {
        seed_id,
        generation: previous_id,
        generations: verified,
        ledger,
        runtime_release,
        judge_release,
    })
}

fn decode_b64(field: &'static str, s: &str) -> Result<Vec<u8>, Refusal> {
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|_| Refusal::Envelope(field))
}

fn step(
    state: &mut State,
    signed: &SignedGeneration,
    pins: &Pins<'_>,
) -> Result<VerifiedGeneration, Refusal> {
    // Authenticate first: nothing in the body is read before the current judge's key verifies
    // the exact bytes that arrived.
    let body = decode_b64("body_b64", &signed.body_b64)?;
    let sig = decode_b64("signature_b64", &signed.signature_b64)?;
    let sig: [u8; 64] = sig
        .try_into()
        .map_err(|_| Refusal::Envelope("signature_b64"))?;
    let mut message = GENERATION_DOMAIN.to_vec();
    message.extend_from_slice(&body);
    state
        .judge_key
        .verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| Refusal::BadSignature)?;
    let id = id_of(GENERATION_DOMAIN, &body);
    let generation: Generation = decode(&body).map_err(Refusal::Decode)?;

    let Generation {
        seed,
        number,
        parent,
        role,
        repo,
        source_commit,
        source_tree,
        plan_sha256,
        required_gates,
        evidence,
        ledger_gate,
        ledger_artifact,
        ledger,
        added_directions,
        waiver,
        builds,
        release_sha256,
        next_judge,
        judged_by,
        judge_kid,
        issued_at,
    } = generation;

    // Where it sits in the chain.
    if seed != state.seed_id {
        return Err(Refusal::WrongSeed(seed));
    }
    if number != state.next_number {
        return Err(Refusal::Number {
            expected: state.next_number,
            got: number,
        });
    }
    if parent != state.previous_id {
        return Err(Refusal::Parent(parent));
    }
    if judged_by != state.judge_id {
        return Err(Refusal::NotCurrentJudge {
            current: state.judge_id.clone(),
            got: judged_by,
        });
    }
    if judge_kid != state.judge_kid {
        return Err(Refusal::JudgeKid {
            current: state.judge_kid.clone(),
            got: judge_kid,
        });
    }
    let expected_repo = match role {
        Role::Runtime => &state.seed.runtime_repo,
        Role::Judge => &state.seed.judge_repo,
    };
    if &repo != expected_repo {
        return Err(Refusal::Repo(repo));
    }
    if issued_at < state.previous_issued_at {
        return Err(Refusal::IssuedBackwards {
            previous: state.previous_issued_at,
            got: issued_at,
        });
    }
    for (field, ok) in [
        ("source_commit", !source_commit.is_empty()),
        ("source_tree", !source_tree.is_empty()),
        ("plan_sha256", is_hex64(&plan_sha256)),
        ("release_sha256", is_hex64(&release_sha256)),
    ] {
        if !ok {
            return Err(Refusal::Malformed(field));
        }
    }

    // Every required gate ran on this exact tree, on a pinned executor, and passed.
    let claims = check_evidence(
        &required_gates,
        &evidence,
        &source_commit,
        &source_tree,
        pins,
    )?;

    // The numbers are the ledger gate's output, not the issuer's say-so.
    let claim = claims
        .get(&ledger_gate)
        .ok_or_else(|| Refusal::LedgerSource(ledger_gate.clone()))?;
    let artifact = claim
        .artifacts
        .get(&ledger_artifact)
        .ok_or_else(|| Refusal::LedgerSource(ledger_artifact.clone()))?;
    let bytes = ledger_bytes(&ledger).map_err(|_| Refusal::Malformed("ledger"))?;
    let len = u64::try_from(bytes.len()).map_err(|_| Refusal::Malformed("ledger"))?;
    if hex::encode(Sha256::digest(&bytes)) != artifact.sha256 || artifact.size != len {
        return Err(Refusal::LedgerBinding);
    }

    // Namespace, vanished metrics, and directions that never change.
    let ns = role.namespace();
    if let Some(name) = ledger.keys().find(|k| !k.starts_with(ns)) {
        return Err(Refusal::Namespace(name.clone()));
    }
    for name in added_directions.keys() {
        if !name.starts_with(ns) {
            return Err(Refusal::Namespace(name.clone()));
        }
        if state.directions.contains_key(name) {
            return Err(Refusal::Redirected(name.clone()));
        }
        if !ledger.contains_key(name) {
            return Err(Refusal::NoDirection(name.clone()));
        }
    }
    let before: BTreeMap<String, i64> = state
        .ledger
        .iter()
        .filter(|(k, _)| k.starts_with(ns))
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    if let Some(name) = before.keys().find(|k| !ledger.contains_key(*k)) {
        return Err(Refusal::Vanished(name.clone()));
    }
    if let Some(name) = ledger
        .keys()
        .find(|k| !state.directions.contains_key(*k) && !added_directions.contains_key(*k))
    {
        return Err(Refusal::NoDirection(name.clone()));
    }

    // Strictly better, and every regression waived by the owner by name.
    let Judgement {
        improved,
        regressed,
    } = judge(&state.directions, &before, &ledger).map_err(Refusal::Vanished)?;
    if improved.is_empty() {
        return Err(Refusal::NoImprovement);
    }
    let waived = match (waiver, regressed.is_empty()) {
        (None, true) => Vec::new(),
        (Some(_), true) => return Err(Refusal::UnusedWaiver),
        (None, false) => {
            let first = regressed.into_iter().next().unwrap_or_default();
            return Err(Refusal::Unwaived(first));
        }
        (Some(bundle), false) => {
            let decision = nucleus_signed_decision::verify(
                &bundle,
                pins.owner_roots,
                issued_at,
                &state.seed.owner_tenant,
            )
            .map_err(|e| Refusal::Waiver(e.to_string()))?;
            for metric in &regressed {
                let cap = waiver_capability(&state.seed_id, number, metric);
                match decision.covers(ScopeRef::Capability(&cap)) {
                    Coverage::Covered => {}
                    Coverage::OutOfScope | Coverage::CannotTell => {
                        return Err(Refusal::Unwaived(metric.clone()));
                    }
                }
            }
            regressed
        }
    };

    // Who built it, and how strongly that is reproduced.
    let tier = tier_of(&builds, &release_sha256)?;
    if tier < state.seed.min_tier {
        return Err(Refusal::BelowTier {
            floor: state.seed.min_tier,
            got: tier,
        });
    }

    // A judge names the key it will judge with; a runtime names none.
    let successor = match (role, next_judge) {
        (Role::Judge, Some(next)) => {
            let key = key_of(&next.key).ok_or(Refusal::Malformed("next_judge.key"))?;
            if next.kid.is_empty() {
                return Err(Refusal::Malformed("next_judge.kid"));
            }
            Some((next.kid, key))
        }
        (Role::Runtime, None) => None,
        (Role::Judge, None) | (Role::Runtime, Some(_)) => return Err(Refusal::NextJudge),
    };

    // Promote.
    state.directions.extend(added_directions);
    for (k, v) in &ledger {
        state.ledger.insert(k.clone(), *v);
    }
    match role {
        Role::Runtime => state.runtime_release = release_sha256.clone(),
        Role::Judge => state.judge_release = release_sha256.clone(),
    }
    if let Some((kid, key)) = successor {
        state.judge_id = id.clone();
        state.judge_kid = kid;
        state.judge_key = key;
    }
    state.previous_id = id.clone();
    state.previous_issued_at = issued_at;
    state.next_number = number.checked_add(1).ok_or(Refusal::Overflow)?;

    Ok(VerifiedGeneration {
        id,
        number,
        role,
        release_sha256,
        tier,
        improved,
        waived,
    })
}

fn check_evidence(
    required: &[String],
    evidence: &[crate::record::GateEvidence],
    commit: &str,
    tree: &str,
    pins: &Pins<'_>,
) -> Result<BTreeMap<String, ExecutionClaim>, Refusal> {
    if required.is_empty() || required.windows(2).any(|w| matches!(w, [a, b] if a >= b)) {
        return Err(Refusal::RequiredGates);
    }
    if evidence.len() != required.len() {
        let missing = required
            .iter()
            .find(|g| !evidence.iter().any(|e| &e.expected.gate == *g))
            .or_else(|| required.first())
            .cloned()
            .unwrap_or_default();
        return Err(Refusal::EvidenceShape(missing));
    }
    let mut claims = BTreeMap::new();
    for (gate, one) in required.iter().zip(evidence) {
        let expected = &one.expected;
        if &expected.gate != gate {
            return Err(Refusal::EvidenceShape(gate.clone()));
        }
        if expected.source_commit != commit || expected.source_tree != tree {
            return Err(Refusal::WrongSubject(gate.clone()));
        }
        if !pins.executor_keys.contains(&expected.verifying_key) {
            return Err(Refusal::UnpinnedExecutor(gate.clone()));
        }
        let raw = decode_b64("receipt_b64", &one.receipt_b64)?;
        let receipt: Receipt = serde_json::from_slice(&raw).map_err(|e| Refusal::Receipt {
            gate: gate.clone(),
            reason: e.to_string(),
        })?;
        let verified = verify_execution(&receipt, &expected.as_expected()).map_err(|e| {
            Refusal::Execution {
                gate: gate.clone(),
                reason: e.to_string(),
            }
        })?;
        let claim = verified.claim().clone();
        if claim.exit_code != Some(0) {
            return Err(Refusal::GateFailed {
                gate: gate.clone(),
                exit: claim.exit_code,
            });
        }
        claims.insert(gate.clone(), claim);
    }
    Ok(claims)
}

fn tier_of(builds: &[Build], release: &str) -> Result<Tier, Refusal> {
    let mut names = BTreeSet::new();
    if builds.is_empty()
        || !builds
            .iter()
            .all(|b| !b.builder.is_empty() && names.insert(b.builder.as_str()))
    {
        return Err(Refusal::Builds);
    }
    if builds.iter().any(|b| !is_hex64(&b.artifact_sha256)) {
        return Err(Refusal::Malformed("builds.artifact_sha256"));
    }
    if !builds.iter().any(|b| b.artifact_sha256 == release) {
        return Err(Refusal::ReleaseNotBuilt);
    }
    Ok(match builds {
        [_] => Tier::SingleBuilder,
        _ if builds.iter().all(|b| b.artifact_sha256 == release) => Tier::Reproduced,
        _ => Tier::Disagreed,
    })
}
