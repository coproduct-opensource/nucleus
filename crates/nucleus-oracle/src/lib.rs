//! `nucleus-oracle` — a self-contained, DETERMINISTIC, sandboxed **held-out
//! grading oracle**.
//!
//! Given a solver's RECORDED execution outputs bundled against a grading bundle,
//! this crate *decidably* produces a grade plus a tamper-evident
//! [`GradeReceipt`], and QUARANTINES submissions that show oracle-gaming
//! signals. It is the layer that *populates* rubric grades with the correct,
//! honest [`nucleus_rubric::Provenance`] — so a downstream
//! [`nucleus_rubric::Rubric`] ranks only the one load-bearing dimension.
//!
//! # What this crate is NOT
//!
//! It runs **no** subprocess, **no** network, and **no** LLM. It grades
//! *recorded* outputs. The live solver execution (e.g. running a solver to
//! produce those outputs) is a SEPARATE concern handled outside this crate. This
//! crate is pure, deterministic, integer/byte-only computation over recorded
//! data — every signal re-runs to the same answer, which is exactly what makes
//! the receipt tamper-evident.
//!
//! # The four grading signals (and which one is load-bearing)
//!
//! This crate is scrupulous about the honesty tier of every number it reports,
//! re-applying `nucleus-eval` / `nucleus-rubric`'s three-tier boundary:
//!
//! 1. **EXACT HELD-OUT RECOMPUTE — the ONLY load-bearing dimension
//!    ([`nucleus_rubric::Provenance::RecomputeVerified`]).** Re-derive
//!    produced-vs-expected over HELD-OUT cases the solver never saw; the
//!    pass-rate is `matched / total` by byte-equality. Mirrors
//!    [`nucleus_eval::DeterministicCheck`]. A re-run reproduces the count — this
//!    is the fraud proof.
//! 2. **METAMORPHIC-RELATION (MR) INVARIANCE — STATISTICAL adequacy
//!    (carried, NOT load-bearing).** Each MR is `(source_output,
//!    perturbed_output, relation)`; only EXACT, byte-checkable relations are
//!    implemented. Each MR check is itself recompute-verifiable as a *boolean*
//!    (re-compare the recorded bytes), but MR *coverage* — how many hold — is a
//!    statistical adequacy signal, not a correctness proof. It is carried as a
//!    reported count and never moves the load-bearing grade.
//! 3. **k-of-n DETERMINISM-PINNING — a quarantine gate, NOT consensus.** Given
//!    `n` recorded re-executions of the deterministic check, require `>= k`
//!    byte-IDENTICAL result hashes. This catches nondeterminism / RNG-seeded
//!    gaming *within one grader's re-runs*. It is deliberately NOT named
//!    "consensus": there is no trust-distributed multi-party agreement here.
//! 4. **MUTATION KILL-SCORE — STATISTICAL test-adequacy (carried, NOT
//!    load-bearing).** Given recorded results of the held-out cases against a set
//!    of injected MUTANTS of a reference, `kill_score = killed / total`. It does
//!    not move the load-bearing grade, but a held-out suite that kills 0 mutants
//!    is *suspect*: a nonzero kill-score is *evidence* the exact recompute (#1)
//!    has teeth (it is harder to fake vacuously) — evidence, not a proof.
//!
//! # The honesty-tier boundary (THE rule)
//!
//! When a NON-quarantined receipt is minted into rubric criteria
//! ([`grade_rubric_inputs`]):
//!
//! * the **exact held-out pass-rate** dimension is tagged
//!   [`nucleus_rubric::Provenance::RecomputeVerified`] — load-bearing;
//! * **MR-coverage** and **mutation-kill** dimensions are tagged
//!   [`nucleus_rubric::Provenance::Attested`] — carried, provably inert on the
//!   rank;
//! * a **QUARANTINED** receipt mints NO `RecomputeVerified` grade at all — the
//!   oracle refuses to mint load-bearing credit for a submission that tripped a
//!   gaming signal.
//!
//! # The quarantine gate (decidable, deterministic, CONSERVATIVE)
//!
//! A submission is quarantined (graded UNTRUSTED, no load-bearing credit) if ANY
//! [`QuarantineReason`] fires. Each is a distinct, decidable check over recorded
//! integers / bytes — never a fuzzy heuristic. The leakage check in particular is
//! a *structural* guard (it reads an explicit flag the bundle carries), not a
//! universal anti-cheat. See [`QuarantineReason`].
//!
//! # WASM safety
//!
//! Integer/byte-only (no float), `serde` + `serde_json` + `sha2` + `hex` +
//! `thiserror` + path deps only — no `ring` / `tokio` / `redb` / entropy `rand`.
//! Builds for `wasm32` exactly like `nucleus-eval` / `nucleus-rubric`.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use nucleus_eval::EvalCase;
use nucleus_rubric::{Criterion, Provenance};

mod summary;
pub use summary::{summarize, PortfolioSummary};

/// Versioned, domain-separated tag prefixed to the canonical receipt bytes before
/// hashing — the `RECEIPT_DOMAIN` discipline re-applied from `nucleus-eval` /
/// `nucleus-recompute`. Bumping the `vN` suffix versions the receipt wire format.
pub const ORACLE_RECEIPT_DOMAIN: &[u8] = b"nucleus-oracle/grade-receipt/v1\0";

// ── Signal #1: EXACT HELD-OUT RECOMPUTE (load-bearing) ──────────────────────

/// The exact held-out recompute dimension: held-out [`EvalCase`]s the solver
/// never saw, re-graded by byte-equality. Mirrors
/// [`nucleus_eval::DeterministicCheck`] — `recompute = count(case.passes())` is
/// the load-bearing, tamper-evident number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldOutRecompute {
    /// The recorded held-out cases. `(matched, total)` is re-derived from these.
    pub cases: Vec<EvalCase>,
}

impl HeldOutRecompute {
    /// Re-derive `(matched, total)` by byte-equality over the recorded cases.
    /// This is the recompute — independent of any claimed number.
    pub fn recompute(&self) -> (u64, u64) {
        let matched = self.cases.iter().filter(|c| c.passes()).count() as u64;
        let total = self.cases.len() as u64;
        (matched, total)
    }
}

// ── Signal #2: METAMORPHIC-RELATION INVARIANCE (statistical) ────────────────

/// An EXACT, byte-checkable metamorphic relation between a source output and a
/// perturbed-input output. Only relations that reduce to a deterministic byte
/// comparison are representable — there are no fuzzy / probabilistic relations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "relation", rename_all = "snake_case")]
pub enum MetamorphicRelation {
    /// `output(perturbed)` must byte-equal `output(source)` (an invariance MR).
    Equal,
    /// `output(perturbed)` must byte-equal a recorded expected transform of the
    /// source output (a recorded-transform MR). The expected bytes are carried
    /// explicitly so the check stays an exact byte comparison.
    ExpectedTransform {
        /// The exact bytes `output(perturbed)` is required to equal.
        expected: String,
    },
}

/// One metamorphic check: the recorded source/perturbed outputs and the relation
/// they must satisfy. [`MetamorphicCheck::holds`] re-compares the recorded bytes,
/// so the boolean is recompute-verifiable; the *interpretation* of coverage as
/// quality is statistical (see crate docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetamorphicCheck {
    /// Stable identifier (diagnostics only; not part of any verdict).
    pub id: String,
    /// Recorded `output(source_input)`.
    pub source_output: String,
    /// Recorded `output(perturbed_input)`.
    pub perturbed_output: String,
    /// The exact relation the pair must satisfy.
    pub relation: MetamorphicRelation,
}

impl MetamorphicCheck {
    /// Whether this MR holds — a pure, deterministic byte comparison.
    pub fn holds(&self) -> bool {
        match &self.relation {
            MetamorphicRelation::Equal => self.perturbed_output == self.source_output,
            MetamorphicRelation::ExpectedTransform { expected } => {
                &self.perturbed_output == expected
            }
        }
    }
}

// ── Signal #3: k-of-n DETERMINISM-PINNING (quarantine gate) ─────────────────

/// k-of-n determinism-pinning over recorded re-executions of the deterministic
/// check. NOT consensus: this is `n` re-runs *of one grader*, requiring `>= k`
/// byte-IDENTICAL result hashes. A spread of distinct hashes is the
/// nondeterminism / RNG-gaming signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterminismPinning {
    /// The recorded per-re-run result hashes (e.g. `sha256` of each re-run's
    /// serialized deterministic outputs), one entry per re-execution.
    pub run_result_hashes: Vec<String>,
    /// The pin threshold `k`: at least `k` of the `n` hashes must be identical.
    pub k: u64,
}

impl DeterminismPinning {
    /// `n` — the number of recorded re-executions.
    pub fn n(&self) -> u64 {
        self.run_result_hashes.len() as u64
    }

    /// The largest count of byte-identical result hashes (the modal agreement).
    /// Deterministic: hashes are tallied via a sorted scan, no map iteration
    /// order dependence.
    pub fn max_agreement(&self) -> u64 {
        if self.run_result_hashes.is_empty() {
            return 0;
        }
        let mut sorted = self.run_result_hashes.clone();
        sorted.sort();
        let mut best: u64 = 0;
        let mut cur: u64 = 0;
        let mut prev: Option<&String> = None;
        for h in &sorted {
            if prev == Some(h) {
                cur += 1;
            } else {
                cur = 1;
                prev = Some(h);
            }
            if cur > best {
                best = cur;
            }
        }
        best
    }

    /// Whether determinism is pinned: `max_agreement >= k` and `k >= 1` and there
    /// is at least one recorded re-run.
    pub fn is_pinned(&self) -> bool {
        self.k >= 1 && self.n() >= 1 && self.max_agreement() >= self.k
    }
}

// ── Signal #4: MUTATION KILL-SCORE (statistical) ────────────────────────────

/// One recorded mutant outcome: whether the held-out suite CAUGHT (killed) this
/// injected mutant of the reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutantOutcome {
    /// Stable identifier of the mutant (diagnostics only).
    pub id: String,
    /// `true` iff the held-out cases detected (killed) this mutant.
    pub killed: bool,
}

/// Mutation kill-score adequacy signal: did the held-out suite have teeth? A
/// STATISTICAL test-adequacy measure (carried, not load-bearing), but a `0` kill
/// score alongside a `100%` exact pass-rate is a degenerate-gaming signal (see
/// [`QuarantineReason::DegenerateNoTeeth`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationAdequacy {
    /// The recorded per-mutant outcomes.
    pub mutants: Vec<MutantOutcome>,
}

impl MutationAdequacy {
    /// `(killed, total)` over the recorded mutants.
    pub fn score(&self) -> (u64, u64) {
        let killed = self.mutants.iter().filter(|m| m.killed).count() as u64;
        let total = self.mutants.len() as u64;
        (killed, total)
    }
}

// ── The grading bundle (recorded inputs the oracle grades) ──────────────────

/// The recorded submission the oracle grades: a solver's outputs against a
/// grading bundle. Every field is RECORDED data — the oracle re-derives grades
/// from it without executing anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GradingBundle {
    /// Identity of the solver / submission being graded.
    pub submission_id: String,
    /// Signal #1 — the load-bearing exact held-out recompute.
    pub held_out: HeldOutRecompute,
    /// Signal #2 — metamorphic checks (coverage is statistical).
    pub metamorphic: Vec<MetamorphicCheck>,
    /// Signal #3 — k-of-n determinism-pinning over recorded re-runs.
    pub determinism: DeterminismPinning,
    /// Signal #4 — mutation kill-score (statistical adequacy).
    pub mutation: MutationAdequacy,
    /// STRUCTURAL leakage guard. The grading bundle is responsible for setting
    /// this flag when the solver's declared inputs *structurally* contained an
    /// expected-output field that should have been absent (i.e. the solver could
    /// only "pass" because it copied a held-out expected value verbatim). This is
    /// a conservative, documented structural flag carried by the bundle — NOT a
    /// fuzzy heuristic and NOT a universal hack-detector.
    pub held_out_expected_leaked: bool,
}

// ── Quarantine reasons (decidable, distinct, Display) ───────────────────────

/// Why a submission was quarantined (graded UNTRUSTED, no load-bearing credit).
///
/// Every variant is a distinct, decidable check over recorded integers / bytes.
/// HONESTY: this is a CONSERVATIVE structural gate, not a universal anti-cheat —
/// it catches the specific, named gaming signals below and nothing more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum QuarantineReason {
    /// k-of-n determinism-pinning failed: fewer than `k` of the `n` recorded
    /// re-runs produced byte-identical results (nondeterministic output).
    #[error(
        "determinism not pinned: only {max_agreement} of {n} re-runs agree, need k={k} \
         (nondeterministic output)"
    )]
    DeterminismNotPinned {
        /// Largest count of byte-identical result hashes.
        max_agreement: u64,
        /// Number of recorded re-runs.
        n: u64,
        /// The required pin threshold.
        k: u64,
    },
    /// The structural leakage guard fired: the bundle flagged that the solver's
    /// "pass" only stands because a held-out expected-output field that should
    /// have been absent from the solver's inputs was echoed verbatim. A structural
    /// guard, not a universal hack-detector.
    #[error(
        "held-out expected values leaked into the solver's inputs (structural guard): a pass \
         that only stands because expected bytes were copied is not trustworthy"
    )]
    HeldOutExpectedLeaked,
    /// Degenerate "passes everything, catches nothing": the exact held-out
    /// pass-rate is 100% while the mutation kill-score is 0 over a non-empty
    /// mutant set — the held-out suite has no teeth, so the perfect pass-rate is
    /// suspect (vacuous).
    #[error(
        "degenerate suite: exact pass-rate is 100% ({matched}/{total}) but mutation kill-score \
         is 0/{mutants_total} — the held-out cases catch nothing"
    )]
    DegenerateNoTeeth {
        /// Matched held-out cases.
        matched: u64,
        /// Total held-out cases.
        total: u64,
        /// Total mutants (all of which went uncaught).
        mutants_total: u64,
    },
}

// ── The grade receipt (output) ──────────────────────────────────────────────

/// A `(matched, total)` count pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountPair {
    /// The numerator (matched / holds / killed).
    pub matched: u64,
    /// The denominator (total).
    pub total: u64,
}

/// The determinism-pinning summary carried in the receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KofN {
    /// Largest count of byte-identical re-run result hashes.
    pub agree: u64,
    /// Number of recorded re-runs.
    pub n: u64,
    /// The required pin threshold `k`.
    pub k: u64,
    /// Whether `agree >= k` (and the inputs were well-formed).
    pub pinned: bool,
}

/// The tamper-evident grade receipt: the four signals' recorded outcomes, the
/// quarantine verdict, and a domain-separated content hash. Round-trips through
/// serde; the hash is deterministic + domain-separated (mirrors
/// `nucleus-eval` / `nucleus-recompute` hashing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GradeReceipt {
    /// Identity of the graded submission.
    pub submission_id: String,
    /// Signal #1 (load-bearing): exact held-out recompute `(matched, total)`.
    pub exact_pass: CountPair,
    /// Signal #2 (statistical): metamorphic-relation `(holds, total)`.
    pub mr: CountPair,
    /// Signal #3 (gate): k-of-n determinism-pinning summary.
    pub k_of_n: KofN,
    /// Signal #4 (statistical): mutation `(killed, total)`.
    pub mutation: CountPair,
    /// `Some(reason)` iff the submission tripped a gaming signal — then NO
    /// load-bearing credit is minted.
    pub quarantine: Option<QuarantineReason>,
}

impl GradeReceipt {
    /// Whether the submission was quarantined.
    pub fn is_quarantined(&self) -> bool {
        self.quarantine.is_some()
    }

    /// Canonical, domain-separated bytes: [`ORACLE_RECEIPT_DOMAIN`] followed by
    /// the receipt's canonical JSON. Deterministic for a given receipt (the type
    /// contains no maps, so serde field/element order is stable), hence stable
    /// across recomputation.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ORACLE_RECEIPT_DOMAIN.len() + 256);
        out.extend_from_slice(ORACLE_RECEIPT_DOMAIN);
        serde_json::to_writer(&mut out, self).expect("grade receipt serialization is infallible");
        out
    }

    /// `sha256` over [`GradeReceipt::canonical_bytes`] — the receipt's content
    /// hash. Versioned via [`ORACLE_RECEIPT_DOMAIN`], deterministic across
    /// recomputation.
    pub fn receipt_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.canonical_bytes());
        h.finalize().into()
    }

    /// Hex-encoded [`GradeReceipt::receipt_hash`].
    pub fn receipt_hash_hex(&self) -> String {
        hex::encode(self.receipt_hash())
    }
}

// ── The grader (pure, deterministic) ────────────────────────────────────────

/// Grade a recorded [`GradingBundle`] into a tamper-evident [`GradeReceipt`].
///
/// Pure and deterministic: re-runs reproduce the receipt byte-identically. The
/// quarantine gate is evaluated in a fixed order; the FIRST tripped reason is
/// recorded (the verdict is "quarantined or not", so any one reason suffices).
pub fn grade(bundle: &GradingBundle) -> GradeReceipt {
    let (matched, total) = bundle.held_out.recompute();
    let exact_pass = CountPair { matched, total };

    let mr_holds = bundle.metamorphic.iter().filter(|m| m.holds()).count() as u64;
    let mr = CountPair {
        matched: mr_holds,
        total: bundle.metamorphic.len() as u64,
    };

    let agree = bundle.determinism.max_agreement();
    let pinned = bundle.determinism.is_pinned();
    let k_of_n = KofN {
        agree,
        n: bundle.determinism.n(),
        k: bundle.determinism.k,
        pinned,
    };

    let (killed, mutants_total) = bundle.mutation.score();
    let mutation = CountPair {
        matched: killed,
        total: mutants_total,
    };

    let quarantine = detect_quarantine(bundle, &exact_pass, &k_of_n, &mutation);

    GradeReceipt {
        submission_id: bundle.submission_id.clone(),
        exact_pass,
        mr,
        k_of_n,
        mutation,
        quarantine,
    }
}

/// The decidable quarantine gate. Checks run in a fixed order; the first that
/// fires is the recorded reason. All are conservative structural / arithmetic
/// guards (see [`QuarantineReason`]).
fn detect_quarantine(
    bundle: &GradingBundle,
    exact_pass: &CountPair,
    k_of_n: &KofN,
    mutation: &CountPair,
) -> Option<QuarantineReason> {
    // (1) Determinism-pinning failure → nondeterministic output.
    if !k_of_n.pinned {
        return Some(QuarantineReason::DeterminismNotPinned {
            max_agreement: k_of_n.agree,
            n: k_of_n.n,
            k: k_of_n.k,
        });
    }
    // (2) Structural leakage guard.
    if bundle.held_out_expected_leaked {
        return Some(QuarantineReason::HeldOutExpectedLeaked);
    }
    // (3) Degenerate "passes everything, catches nothing".
    //     100% exact pass-rate over a non-empty held-out set AND a non-empty
    //     mutant set with zero kills.
    if exact_pass.total > 0
        && exact_pass.matched == exact_pass.total
        && mutation.total > 0
        && mutation.matched == 0
    {
        return Some(QuarantineReason::DegenerateNoTeeth {
            matched: exact_pass.matched,
            total: exact_pass.total,
            mutants_total: mutation.total,
        });
    }
    None
}

// ── Minting rubric inputs (THE honesty-tier boundary) ───────────────────────

/// Stable criterion id for the load-bearing exact held-out pass-rate dimension.
pub const CRITERION_EXACT_PASS: &str = "exact_held_out_pass";
/// Stable criterion id for the (carried, inert) MR-coverage dimension.
pub const CRITERION_MR_COVERAGE: &str = "mr_coverage";
/// Stable criterion id for the (carried, inert) mutation-kill dimension.
pub const CRITERION_MUTATION_KILL: &str = "mutation_kill";

/// A `(criterion, grade)` pair the oracle mints for a downstream
/// [`nucleus_rubric::Rubric`] / [`nucleus_rubric::Scorecard`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GradedDimension {
    /// The criterion (id + honest provenance + weight + max_grade).
    pub criterion: Criterion,
    /// The integer grade for this dimension.
    pub grade: u32,
}

/// The rubric inputs minted from a [`GradeReceipt`] — see
/// [`grade_rubric_inputs`]. The criteria carry the HONEST provenance tier; the
/// grades line up positionally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RubricInputs {
    /// The criteria (in canonical: exact-pass, mr-coverage, mutation-kill order).
    /// A quarantined receipt omits the load-bearing exact-pass criterion.
    pub criteria: Vec<Criterion>,
    /// Grades aligned positionally to `criteria`.
    pub grades: Vec<u32>,
    /// `Some` iff the source receipt was quarantined — then there is NO
    /// RecomputeVerified criterion and no load-bearing credit was minted.
    pub quarantine: Option<QuarantineReason>,
}

impl RubricInputs {
    /// The minted dimensions as `(criterion, grade)` pairs.
    pub fn dimensions(&self) -> Vec<GradedDimension> {
        self.criteria
            .iter()
            .cloned()
            .zip(self.grades.iter().copied())
            .map(|(criterion, grade)| GradedDimension { criterion, grade })
            .collect()
    }

    /// Whether any minted criterion is load-bearing
    /// ([`nucleus_rubric::Provenance::RecomputeVerified`]). False for a
    /// quarantined receipt — the whole point of the gate.
    pub fn mints_load_bearing(&self) -> bool {
        self.criteria.iter().any(|c| c.provenance.is_load_bearing())
    }
}

/// Saturating `u64 → u32`.
fn sat_u32(v: u64) -> u32 {
    v.min(u32::MAX as u64) as u32
}

/// Turn a [`GradeReceipt`] into rubric criteria + grades, applying THE
/// honesty-tier boundary:
///
/// * exact held-out pass-rate → [`nucleus_rubric::Provenance::RecomputeVerified`]
///   (load-bearing), graded by the recomputed `matched` count;
/// * MR-coverage and mutation-kill → [`nucleus_rubric::Provenance::Attested`]
///   (carried, provably inert), graded by their `holds` / `killed` counts;
/// * a **quarantined** receipt mints NO `RecomputeVerified` criterion — the
///   load-bearing exact-pass dimension is OMITTED, so a downstream rubric awards
///   it zero load-bearing standing. (The carried, inert Attested dimensions are
///   still emitted for provenance.)
///
/// `exact_weight` is the weight assigned to the load-bearing criterion; the
/// Attested criteria are emitted with the supplied `attested_weight` but are
/// inert on any [`nucleus_rubric`] rank regardless of weight.
pub fn grade_rubric_inputs(
    receipt: &GradeReceipt,
    exact_weight: u32,
    attested_weight: u32,
) -> RubricInputs {
    let mut criteria = Vec::with_capacity(3);
    let mut grades = Vec::with_capacity(3);

    // The load-bearing dimension — minted ONLY for a non-quarantined receipt.
    if receipt.quarantine.is_none() {
        criteria.push(Criterion {
            id: CRITERION_EXACT_PASS.to_string(),
            provenance: Provenance::RecomputeVerified,
            weight: exact_weight,
            max_grade: sat_u32(receipt.exact_pass.total),
        });
        grades.push(sat_u32(receipt.exact_pass.matched));
    }

    // Carried, inert adequacy dimensions — minted regardless (provenance only).
    criteria.push(Criterion {
        id: CRITERION_MR_COVERAGE.to_string(),
        provenance: Provenance::Attested,
        weight: attested_weight,
        max_grade: sat_u32(receipt.mr.total),
    });
    grades.push(sat_u32(receipt.mr.matched));

    criteria.push(Criterion {
        id: CRITERION_MUTATION_KILL.to_string(),
        provenance: Provenance::Attested,
        weight: attested_weight,
        max_grade: sat_u32(receipt.mutation.total),
    });
    grades.push(sat_u32(receipt.mutation.matched));

    RubricInputs {
        criteria,
        grades,
        quarantine: receipt.quarantine.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Fixtures ────────────────────────────────────────────────────────────

    /// Held-out cases: `matched` of `total` pass by byte-equality.
    fn held_out(matched: u64, total: u64) -> HeldOutRecompute {
        let cases = (0..total)
            .map(|i| EvalCase {
                case_id: format!("held-{i}"),
                produced: if i < matched {
                    "ok".into()
                } else {
                    "WRONG".into()
                },
                expected: "ok".into(),
            })
            .collect();
        HeldOutRecompute { cases }
    }

    /// `n` re-runs all producing the same result hash (pinned).
    fn pinned_runs(n: u64, k: u64) -> DeterminismPinning {
        DeterminismPinning {
            run_result_hashes: (0..n).map(|_| "aa".to_string()).collect(),
            k,
        }
    }

    /// Metamorphic checks: `holds` of `total` satisfy an Equal relation.
    fn mrs(holds: u64, total: u64) -> Vec<MetamorphicCheck> {
        (0..total)
            .map(|i| MetamorphicCheck {
                id: format!("mr-{i}"),
                source_output: "x".into(),
                perturbed_output: if i < holds { "x".into() } else { "y".into() },
                relation: MetamorphicRelation::Equal,
            })
            .collect()
    }

    /// Mutation outcomes: `killed` of `total` caught.
    fn mutants(killed: u64, total: u64) -> MutationAdequacy {
        MutationAdequacy {
            mutants: (0..total)
                .map(|i| MutantOutcome {
                    id: format!("mut-{i}"),
                    killed: i < killed,
                })
                .collect(),
        }
    }

    /// A well-formed, non-degenerate, pinned bundle.
    fn bundle(
        matched: u64,
        total: u64,
        mr_holds: u64,
        mr_total: u64,
        killed: u64,
        mut_total: u64,
    ) -> GradingBundle {
        GradingBundle {
            submission_id: "sub-1".into(),
            held_out: held_out(matched, total),
            metamorphic: mrs(mr_holds, mr_total),
            determinism: pinned_runs(3, 2),
            mutation: mutants(killed, mut_total),
            held_out_expected_leaked: false,
        }
    }

    // ── 1. Full exact pass → RV grade minted ─────────────────────────────────

    #[test]
    fn full_exact_pass_mints_load_bearing_rv_grade() {
        // 5/5 exact pass, but mutants have teeth (3/4 killed) so NOT degenerate.
        let r = grade(&bundle(5, 5, 2, 3, 3, 4));
        assert!(!r.is_quarantined());
        assert_eq!(
            r.exact_pass,
            CountPair {
                matched: 5,
                total: 5
            }
        );

        let inputs = grade_rubric_inputs(&r, 10, 7);
        assert!(inputs.mints_load_bearing());
        // The load-bearing criterion is the exact-pass dimension at grade 5.
        let rv: Vec<_> = inputs
            .dimensions()
            .into_iter()
            .filter(|d| d.criterion.provenance.is_load_bearing())
            .collect();
        assert_eq!(rv.len(), 1);
        assert_eq!(rv[0].criterion.id, CRITERION_EXACT_PASS);
        assert_eq!(rv[0].grade, 5);
    }

    // ── 2. Partial pass → strictly smaller load-bearing grade ────────────────

    #[test]
    fn partial_pass_is_strictly_smaller_load_bearing_grade() {
        let full = grade(&bundle(5, 5, 0, 0, 3, 4));
        let partial = grade(&bundle(3, 5, 0, 0, 3, 4));
        assert!(!full.is_quarantined() && !partial.is_quarantined());

        let fi = grade_rubric_inputs(&full, 10, 7);
        let pi = grade_rubric_inputs(&partial, 10, 7);
        let fg = fi
            .dimensions()
            .into_iter()
            .find(|d| d.criterion.id == CRITERION_EXACT_PASS)
            .unwrap()
            .grade;
        let pg = pi
            .dimensions()
            .into_iter()
            .find(|d| d.criterion.id == CRITERION_EXACT_PASS)
            .unwrap()
            .grade;
        assert_eq!(fg, 5);
        assert_eq!(pg, 3);
        assert!(pg < fg);
    }

    // ── 3. MR coverage does NOT move the load-bearing grade ──────────────────

    #[test]
    fn mr_coverage_is_reported_but_inert_on_load_bearing_grade() {
        // Same exact pass-rate, different MR coverage (all-hold vs some-fail).
        let all_hold = grade(&bundle(4, 5, 5, 5, 3, 4));
        let some_fail = grade(&bundle(4, 5, 2, 5, 3, 4));
        // Coverage is reported and differs.
        assert_eq!(
            all_hold.mr,
            CountPair {
                matched: 5,
                total: 5
            }
        );
        assert_eq!(
            some_fail.mr,
            CountPair {
                matched: 2,
                total: 5
            }
        );
        // ...but the load-bearing exact-pass grade is identical.
        let g = |r: &GradeReceipt| {
            grade_rubric_inputs(r, 10, 7)
                .dimensions()
                .into_iter()
                .find(|d| d.criterion.id == CRITERION_EXACT_PASS)
                .unwrap()
                .grade
        };
        assert_eq!(g(&all_hold), g(&some_fail));
        // MR-coverage criterion is Attested (carried, inert), never RV.
        let mr_dim = grade_rubric_inputs(&all_hold, 10, 7)
            .dimensions()
            .into_iter()
            .find(|d| d.criterion.id == CRITERION_MR_COVERAGE)
            .unwrap();
        assert_eq!(mr_dim.criterion.provenance, Provenance::Attested);
        assert!(!mr_dim.criterion.provenance.is_load_bearing());
    }

    // ── 4. ExpectedTransform MR is an exact byte check ───────────────────────

    #[test]
    fn expected_transform_mr_is_exact_byte_check() {
        let ok = MetamorphicCheck {
            id: "t".into(),
            source_output: "abc".into(),
            perturbed_output: "ABC".into(),
            relation: MetamorphicRelation::ExpectedTransform {
                expected: "ABC".into(),
            },
        };
        let bad = MetamorphicCheck {
            perturbed_output: "AbC".into(),
            ..ok.clone()
        };
        assert!(ok.holds());
        assert!(!bad.holds());
    }

    // ── 5. k-of-n pinned vs unpinned → unpinned QUARANTINES ──────────────────

    #[test]
    fn k_of_n_unpinned_quarantines() {
        // 3 re-runs, all distinct hashes → max agreement 1 < k=2 → not pinned.
        let mut b = bundle(3, 5, 0, 0, 3, 4);
        b.determinism = DeterminismPinning {
            run_result_hashes: vec!["aa".into(), "bb".into(), "cc".into()],
            k: 2,
        };
        let r = grade(&b);
        assert!(r.is_quarantined());
        assert!(matches!(
            r.quarantine,
            Some(QuarantineReason::DeterminismNotPinned {
                max_agreement: 1,
                n: 3,
                k: 2
            })
        ));
        assert!(!r.k_of_n.pinned);

        // Pinned counterpart is not quarantined for this reason.
        let ok = grade(&bundle(3, 5, 0, 0, 3, 4));
        assert!(ok.k_of_n.pinned);
        assert!(!ok.is_quarantined());
    }

    // ── 6. Degenerate: mutation kill 0 with 100% pass → QUARANTINES ──────────

    #[test]
    fn degenerate_full_pass_zero_kill_quarantines() {
        // 5/5 exact pass, 0/4 mutants killed → no teeth → quarantine.
        let r = grade(&bundle(5, 5, 3, 3, 0, 4));
        assert!(r.is_quarantined());
        assert!(matches!(
            r.quarantine,
            Some(QuarantineReason::DegenerateNoTeeth {
                matched: 5,
                total: 5,
                mutants_total: 4
            })
        ));
    }

    #[test]
    fn full_pass_with_zero_mutants_is_not_degenerate() {
        // No mutant set at all → cannot conclude "no teeth"; not quarantined for
        // the degenerate reason (conservative).
        let r = grade(&bundle(5, 5, 3, 3, 0, 0));
        assert!(!r.is_quarantined());
    }

    // ── 7. Structural leakage flag → QUARANTINES ─────────────────────────────

    #[test]
    fn structural_leakage_flag_quarantines() {
        let mut b = bundle(5, 5, 3, 3, 3, 4);
        b.held_out_expected_leaked = true;
        let r = grade(&b);
        assert!(r.is_quarantined());
        assert!(matches!(
            r.quarantine,
            Some(QuarantineReason::HeldOutExpectedLeaked)
        ));
    }

    #[test]
    fn unset_leakage_flag_does_not_quarantine() {
        // Same otherwise-clean bundle with the structural flag left false must NOT
        // trip leakage — the guard is a pure passthrough of the caller's flag, so
        // it never false-positives. Pins that the gate stays conservative.
        let b = bundle(5, 5, 3, 3, 3, 4);
        assert!(!b.held_out_expected_leaked);
        let r = grade(&b);
        assert!(!matches!(
            r.quarantine,
            Some(QuarantineReason::HeldOutExpectedLeaked)
        ));
    }

    // ── 8. Quarantined receipt yields NO RecomputeVerified grade ─────────────

    #[test]
    fn quarantined_receipt_mints_no_load_bearing_grade() {
        // Quarantine via leakage; exact pass-rate is a perfect 5/5.
        let mut b = bundle(5, 5, 3, 3, 3, 4);
        b.held_out_expected_leaked = true;
        let r = grade(&b);
        assert!(r.is_quarantined());

        let inputs = grade_rubric_inputs(&r, 10, 7);
        // No RecomputeVerified criterion at all — the gate refuses load-bearing
        // credit even though the recomputed pass-rate is perfect.
        assert!(!inputs.mints_load_bearing());
        assert!(inputs
            .dimensions()
            .iter()
            .all(|d| !d.criterion.provenance.is_load_bearing()));
        // The exact-pass criterion id is absent.
        assert!(!inputs.criteria.iter().any(|c| c.id == CRITERION_EXACT_PASS));
        // The carried inert dimensions are still emitted.
        assert!(inputs
            .criteria
            .iter()
            .any(|c| c.id == CRITERION_MR_COVERAGE));
        assert!(inputs
            .criteria
            .iter()
            .any(|c| c.id == CRITERION_MUTATION_KILL));
        assert_eq!(inputs.quarantine, r.quarantine);
    }

    // ── 9. Receipt hash deterministic + domain-separated ─────────────────────

    #[test]
    fn receipt_hash_is_deterministic_and_domain_separated() {
        let r = grade(&bundle(4, 5, 2, 3, 3, 4));
        assert_eq!(r.receipt_hash(), r.clone().receipt_hash());
        assert!(r.canonical_bytes().starts_with(ORACLE_RECEIPT_DOMAIN));
        assert_eq!(r.receipt_hash_hex().len(), 64);

        // A different submission → a different hash (tamper-evident).
        let other = grade(&bundle(3, 5, 2, 3, 3, 4));
        assert_ne!(r.receipt_hash(), other.receipt_hash());
    }

    // ── 10. Serde round-trip ─────────────────────────────────────────────────

    #[test]
    fn receipt_round_trips_through_serde() {
        for r in [
            grade(&bundle(5, 5, 3, 3, 3, 4)), // clean
            grade(&bundle(5, 5, 3, 3, 0, 4)), // degenerate quarantine
            {
                let mut b = bundle(5, 5, 3, 3, 3, 4);
                b.held_out_expected_leaked = true;
                grade(&b) // leakage quarantine
            },
        ] {
            let bytes = serde_json::to_vec(&r).unwrap();
            let back: GradeReceipt = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(r, back);
            // Hash is stable across the round-trip.
            assert_eq!(r.receipt_hash(), back.receipt_hash());
        }
    }

    #[test]
    fn grading_bundle_round_trips_through_serde() {
        let b = bundle(3, 5, 2, 4, 1, 3);
        let bytes = serde_json::to_vec(&b).unwrap();
        let back: GradingBundle = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(b, back);
        // Re-grading the round-tripped bundle yields a byte-identical receipt.
        assert_eq!(grade(&b).receipt_hash(), grade(&back).receipt_hash());
    }

    // ── 11. The mint maps provenance correctly ───────────────────────────────

    #[test]
    fn mint_maps_provenance_to_the_honest_tier() {
        let r = grade(&bundle(4, 5, 2, 3, 3, 4));
        let inputs = grade_rubric_inputs(&r, 10, 7);
        for d in inputs.dimensions() {
            match d.criterion.id.as_str() {
                CRITERION_EXACT_PASS => {
                    assert_eq!(d.criterion.provenance, Provenance::RecomputeVerified);
                    assert!(d.criterion.provenance.is_load_bearing());
                }
                CRITERION_MR_COVERAGE | CRITERION_MUTATION_KILL => {
                    assert_eq!(d.criterion.provenance, Provenance::Attested);
                    assert!(!d.criterion.provenance.is_load_bearing());
                }
                other => panic!("unexpected criterion id {other}"),
            }
        }
        // EXACTLY ONE load-bearing dimension.
        assert_eq!(
            inputs
                .criteria
                .iter()
                .filter(|c| c.provenance.is_load_bearing())
                .count(),
            1
        );
    }

    // ── 12. Minted RV grade equals the recomputed count, not any claim ───────

    #[test]
    fn minted_rv_grade_is_the_recomputed_count() {
        // The grade is derived from the held-out cases' byte-equality, full stop.
        let r = grade(&bundle(3, 7, 0, 0, 2, 3));
        assert_eq!(
            r.exact_pass,
            CountPair {
                matched: 3,
                total: 7
            }
        );
        let inputs = grade_rubric_inputs(&r, 10, 7);
        let rv = inputs
            .dimensions()
            .into_iter()
            .find(|d| d.criterion.id == CRITERION_EXACT_PASS)
            .unwrap();
        assert_eq!(rv.grade, 3);
        assert_eq!(rv.criterion.max_grade, 7);
    }

    // ── 13. Mutation-kill is reported but inert on the load-bearing grade ─────

    #[test]
    fn mutation_kill_is_reported_but_inert_on_load_bearing_grade() {
        // Same exact pass-rate, different (non-zero) kill scores → same RV grade.
        let strong = grade(&bundle(4, 5, 0, 0, 4, 4));
        let weak = grade(&bundle(4, 5, 0, 0, 1, 4));
        assert_eq!(
            strong.mutation,
            CountPair {
                matched: 4,
                total: 4
            }
        );
        assert_eq!(
            weak.mutation,
            CountPair {
                matched: 1,
                total: 4
            }
        );
        let g = |r: &GradeReceipt| {
            grade_rubric_inputs(r, 10, 7)
                .dimensions()
                .into_iter()
                .find(|d| d.criterion.id == CRITERION_EXACT_PASS)
                .unwrap()
                .grade
        };
        assert_eq!(g(&strong), g(&weak));
    }

    // ── 14. max_agreement counts the modal byte-identical hash ───────────────

    #[test]
    fn max_agreement_counts_the_modal_hash() {
        let d = DeterminismPinning {
            run_result_hashes: vec!["a".into(), "b".into(), "a".into(), "a".into(), "b".into()],
            k: 3,
        };
        assert_eq!(d.n(), 5);
        assert_eq!(d.max_agreement(), 3); // "a" appears 3 times
        assert!(d.is_pinned()); // 3 >= 3
        let d2 = DeterminismPinning { k: 4, ..d };
        assert!(!d2.is_pinned()); // 3 < 4
    }

    // ── 15. Empty determinism input is not pinned (quarantines) ──────────────

    #[test]
    fn empty_determinism_is_not_pinned() {
        let mut b = bundle(3, 5, 0, 0, 3, 4);
        b.determinism = DeterminismPinning {
            run_result_hashes: vec![],
            k: 1,
        };
        let r = grade(&b);
        assert!(!r.k_of_n.pinned);
        assert!(matches!(
            r.quarantine,
            Some(QuarantineReason::DeterminismNotPinned { .. })
        ));
    }
}
