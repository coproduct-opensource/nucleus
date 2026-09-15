//! `nucleus-eval` — turn a recorded agent **eval run** into a real
//! [`nucleus_creditworthiness::CreditEvent`] whose magnitude is bounded by a
//! **recomputed** deterministic pass-rate, so a lie cannot inflate its own reward.
//!
//! This is the eval analogue of `nucleus-recompute`'s clearing receipts: a receipt
//! carries **declared inputs** + **claimed outputs**, and verification RE-DERIVES
//! the outputs from the inputs and compares them field-by-field. The recompute IS
//! the fraud proof.
//!
//! # The honesty boundary (read this before trusting a number)
//!
//! An [`EvalRun`] mixes dimensions that differ in how much you can trust them.
//! `nucleus-eval` is scrupulous about which ones move money:
//!
//! * **Deterministic check — RECOMPUTE-VERIFIED (strong).** The
//!   [`DeterministicCheck`] carries, for every case, the agent's recorded
//!   `produced` output and the `expected` output. We *re-run* the comparison:
//!   `recompute = count(produced == expected)`. The receipt also carries the
//!   agent's CLAIMED `tests_passed` / `tests_total`; [`verify_run`] compares the
//!   recomputed counts against the claim. **This is the only dimension that sets
//!   the minted weight and polarity.**
//! * **`cost_micro_usd`, `tokens`, `latency_ms` — ATTESTED (carried, not
//!   recomputed).** They are environmental measurements that cannot be re-derived
//!   from the receipt, so they are recorded for provenance but **never** change
//!   the minted [`CreditEvent`]'s weight or polarity.
//! * **`llm_judge_score` — ATTESTATION-ONLY.** A soft, non-deterministic signal.
//!   Carried, never load-bearing on the mint.
//!
//! # The mint rule (the whole thesis in three lines)
//!
//! Let `(passed, total)` be the **recomputed** counts and `M =
//! declared_magnitude_micro` (a DECLARED input — never a claimed output, so the
//! lie can't inflate its own penalty):
//!
//! * claimed counts **≠** recomputed counts ⇒ [`EvalOutcome::Mismatch`] ⇒
//!   [`CreditEvent::caught_defection`] (a **debit** of weight `M`). An overclaim
//!   mints a penalty, not a fat credit.
//! * claimed counts **==** recomputed counts ⇒ honest ⇒ a **credit** scaled by the
//!   recomputed pass-rate: `weight = floor(M * passed / total)`. A zero-pass honest
//!   run mints a zero-weight credit (no reputation gain).
//!
//! All arithmetic is integer micro-USD (`u128` intermediates, no floating point).
//! The minted event is the **real** [`nucleus_creditworthiness::CreditEvent`] type
//! — this crate composes the credit economics, it never re-implements them.
//!
//! # WASM safety
//!
//! Integer-only, `serde` + `sha2` + `serde_json` only — no tokio / redb / ring /
//! native sockets. It builds for `wasm32` exactly like
//! `nucleus-creditworthiness`'s default build.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Versioned, domain-separated tag prefixed to the canonical receipt bytes before
/// hashing — the [`RECEIPT_DOMAIN`] discipline (mirrors
/// `nucleus-recompute`'s `RECEIPT_DOMAIN`). Bumping the `vN` suffix is how the
/// receipt wire format is versioned.
const RECEIPT_DOMAIN: &[u8] = b"nucleus-eval/eval-receipt/v1\0";

/// One deterministic test case: the agent's recorded `produced` output and the
/// `expected` output. Recompute compares them byte-for-byte — this is the
/// re-derivable ground truth, not a number to be taken on faith.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalCase {
    /// Stable identifier for the case (for diagnostics; not part of the verdict).
    pub case_id: String,
    /// Declared input: the output the agent actually produced for this case.
    pub produced: String,
    /// Declared input: the reference output this case is checked against.
    pub expected: String,
}

impl EvalCase {
    /// Whether this case passes — `produced == expected`. This is the recompute.
    pub fn passes(&self) -> bool {
        self.produced == self.expected
    }
}

/// The RECOMPUTE-VERIFIED deterministic dimension of an eval run.
///
/// It carries enough to independently re-derive `(tests_passed, tests_total)`
/// from the [`EvalCase`]s, plus the agent's CLAIMED counts so verification can
/// compare recomputed-vs-claimed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicCheck {
    /// The recorded cases. `recompute = count(case.passes())`.
    pub cases: Vec<EvalCase>,
    /// Claimed output: how many cases the agent says passed.
    pub claimed_passed: u64,
    /// Claimed output: how many cases the agent says there were in total.
    pub claimed_total: u64,
}

impl DeterministicCheck {
    /// Re-derive `(passed, total)` from the recorded cases. Independent of the
    /// claimed counts — this is what makes a lie catchable.
    pub fn recompute(&self) -> (u64, u64) {
        let passed = self.cases.iter().filter(|c| c.passes()).count() as u64;
        let total = self.cases.len() as u64;
        (passed, total)
    }
}

/// ATTESTATION-ONLY signals. Carried for provenance; never load-bearing on the
/// mint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attested {
    /// A soft, non-deterministic LLM-judge score (e.g. 0..=100). Attestation-only:
    /// it does NOT affect the minted [`CreditEvent`]'s weight or polarity.
    pub llm_judge_score: Option<u64>,
}

/// A recorded agent eval run = an eval receipt.
///
/// See the crate docs for the honesty boundary: only [`EvalRun::deterministic`]
/// is recompute-verified; [`EvalRun::cost_micro_usd`], [`EvalRun::tokens`],
/// [`EvalRun::latency_ms`] are ATTESTED and [`EvalRun::attested`] is
/// attestation-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalRun {
    /// Identity of the agent under eval.
    pub agent_id: String,
    /// Identity of the task / benchmark.
    pub task_id: String,
    /// ATTESTED (carried, not recomputed): observed cost in micro-USD.
    pub cost_micro_usd: u64,
    /// ATTESTED (carried, not recomputed): observed token count.
    pub tokens: u64,
    /// ATTESTED (carried, not recomputed): observed wall-clock latency, ms.
    pub latency_ms: u64,
    /// RECOMPUTE-VERIFIED: the deterministic test outcomes.
    pub deterministic: DeterministicCheck,
    /// ATTESTATION-ONLY soft signals.
    pub attested: Attested,
    /// DECLARED input: the economic magnitude this run is worth, micro-USD. The
    /// minted weight is derived from THIS (scaled by the recomputed pass-rate, or
    /// charged in full on a caught defection) — never from a claimed output.
    pub declared_magnitude_micro: u64,
}

/// The result of recomputing an [`EvalRun`]'s deterministic check and comparing
/// it to the claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalOutcome {
    /// Claimed counts equal recomputed counts — an honest run.
    Match {
        /// Recomputed passing-case count.
        passed: u64,
        /// Recomputed total-case count.
        total: u64,
    },
    /// Claimed counts diverge from recomputed counts — the recompute is the fraud
    /// proof.
    Mismatch {
        /// What the agent claimed passed.
        claimed_passed: u64,
        /// What actually passed on recompute.
        recomputed_passed: u64,
        /// What the agent claimed the total was.
        claimed_total: u64,
        /// What the total actually was on recompute.
        recomputed_total: u64,
    },
}

impl EvalOutcome {
    /// Whether the receipt recomputed honestly.
    pub fn is_match(&self) -> bool {
        matches!(self, EvalOutcome::Match { .. })
    }
}

/// Recompute the deterministic check and compare against the agent's claim.
///
/// `Match` ⟺ both the passed count AND the total count claimed equal what the
/// recorded cases actually yield. Anything else is a `Mismatch` — including an
/// overclaim of `tests_passed` while the recorded `produced` outputs say
/// otherwise.
pub fn verify_run(run: &EvalRun) -> EvalOutcome {
    let (recomputed_passed, recomputed_total) = run.deterministic.recompute();
    let claimed_passed = run.deterministic.claimed_passed;
    let claimed_total = run.deterministic.claimed_total;
    if claimed_passed == recomputed_passed && claimed_total == recomputed_total {
        EvalOutcome::Match {
            passed: recomputed_passed,
            total: recomputed_total,
        }
    } else {
        EvalOutcome::Mismatch {
            claimed_passed,
            recomputed_passed,
            claimed_total,
            recomputed_total,
        }
    }
}

/// Canonical, domain-separated bytes of an eval receipt — the [`RECEIPT_DOMAIN`]
/// tag followed by the receipt's canonical JSON. Deterministic for a given
/// receipt (and hence stable across recomputation).
pub fn canonical_bytes(run: &EvalRun) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECEIPT_DOMAIN.len() + 256);
    out.extend_from_slice(RECEIPT_DOMAIN);
    // Infallible for these concrete, map-free types.
    serde_json::to_writer(&mut out, run).expect("eval receipt serialization is infallible");
    out
}

/// `sha256` over [`canonical_bytes`] — the receipt's content hash, bound into the
/// minted [`CreditEvent`] as its `receipt_hash` provenance commitment. Versioned
/// via [`RECEIPT_DOMAIN`] and deterministic across recomputation.
pub fn receipt_hash(run: &EvalRun) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(canonical_bytes(run));
    h.finalize().into()
}

/// Hex-encoded [`receipt_hash`], for logging / lineage edges.
pub fn receipt_hash_hex(run: &EvalRun) -> String {
    let h = receipt_hash(run);
    let mut s = String::with_capacity(64);
    for b in h {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Pass-rate-scaled magnitude, integer micro-USD: `floor(M * passed / total)`.
/// `total == 0` yields `0` (a no-case honest run earns nothing). `u128`
/// intermediates avoid overflow; no floating point.
pub fn scaled_weight(declared_magnitude_micro: u64, passed: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    let scaled = (u128::from(declared_magnitude_micro) * u128::from(passed)) / u128::from(total);
    // passed <= total ⇒ scaled <= declared_magnitude_micro <= u64::MAX.
    scaled as u64
}

// ═══════════════════════════════════════════════════════════════════════════
// The minters were REMOVED here (#2509). Read this before adding one back.
// ═══════════════════════════════════════════════════════════════════════════
//
// This crate used to expose `mint_event`, `mint_events` and
// `credit_file_from_runs`, each building a `CreditEvent` from an `EvalRun`.
// `CreditEvent` is now sealed: it is mintable only from a `nucleus-recompute`
// witness over a `ClearingReceipt`, and an `EvalRun` is not one.
//
// That is not an oversight in the seal. #2500 records this crate as one of the
// paths that "opts out of the recompute gate", and `verify_run` is why: it
// recomputes an aggregate over `produced`/`expected` strings the CALLER
// supplied, so a run that agrees with itself mints standing without anything
// independent ever having checked the work. The old `mint_event` was the step
// that turned that into money.
//
// `verify_run` / `EvalOutcome` are untouched and still exported — recomputing an
// eval is a real and useful thing to do. What is gone is the leap from that to
// bond-substituting credit.
//
// Restoring a path here is #2502's job (grading integrity through to
// settlement), not a local fix: its decision routes minting through
// `nucleus-oracle::grade` with the magnitude bound to a clearing price. A
// `CreditEvent::from_eval` added here would re-open exactly the hole the seal
// closed, whatever it was called.

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a run whose recorded cases genuinely yield `passed` of `total`, with
    /// the claimed counts set to whatever the agent asserts.
    fn run_with(
        produced_passes: u64,
        total: u64,
        claimed_passed: u64,
        claimed_total: u64,
        declared_magnitude_micro: u64,
    ) -> EvalRun {
        let mut cases = Vec::new();
        for i in 0..total {
            let pass = i < produced_passes;
            cases.push(EvalCase {
                case_id: format!("case-{i}"),
                produced: if pass { "ok".into() } else { "WRONG".into() },
                expected: "ok".into(),
            });
        }
        EvalRun {
            agent_id: "agent-a".into(),
            task_id: "task-1".into(),
            cost_micro_usd: 1_000,
            tokens: 5_000,
            latency_ms: 250,
            deterministic: DeterministicCheck {
                cases,
                claimed_passed,
                claimed_total,
            },
            attested: Attested {
                llm_judge_score: Some(90),
            },
            declared_magnitude_micro,
        }
    }

    /// What a run RECOMPUTES to, kept as a measurement now that nothing here
    /// mints. Each test below is the old minting test with its assertion moved
    /// off the `CreditEvent` and onto the recompute that used to justify one —
    /// the properties were about `verify_run`, not about the mint.
    fn recomputed(run: &EvalRun) -> (bool, u64) {
        match verify_run(run) {
            EvalOutcome::Match { passed, total } => (
                true,
                scaled_weight(run.declared_magnitude_micro, passed, total),
            ),
            EvalOutcome::Mismatch { .. } => (false, run.declared_magnitude_micro),
        }
    }

    #[test]
    fn full_pass_recomputes_to_the_full_declared_magnitude() {
        let run = run_with(10, 10, 10, 10, 1_000_000);
        assert!(verify_run(&run).is_match());
        assert_eq!(recomputed(&run), (true, 1_000_000));
    }

    #[test]
    fn partial_pass_recomputes_strictly_smaller() {
        let (full_ok, full) = recomputed(&run_with(10, 10, 10, 10, 1_000_000));
        let (part_ok, partial) = recomputed(&run_with(7, 10, 7, 10, 1_000_000));
        assert!(full_ok && part_ok);
        assert_eq!(partial, 700_000); // floor(1_000_000 * 7 / 10)
        assert!(partial < full);
    }

    #[test]
    fn overclaim_is_caught_rather_than_believed() {
        // Only 5 of 10 cases actually pass, but the agent CLAIMS all 10 passed.
        // A handler that read back claimed_passed would treat this as a full
        // success; the recompute catches the lie.
        let run = run_with(5, 10, 10, 10, 1_000_000);
        assert!(!verify_run(&run).is_match());
        assert_eq!(recomputed(&run), (false, 1_000_000));
    }

    #[test]
    fn inflating_only_the_claim_never_increases_the_recomputed_weight() {
        // Recomputed produced/expected fixed at 7/10. Sweep the claimed_passed.
        let (ok, honest) = recomputed(&run_with(7, 10, 7, 10, 1_000_000));
        assert!(ok);
        assert_eq!(honest, 700_000);
        for claimed in [8, 9, 10] {
            let (matched, w) = recomputed(&run_with(7, 10, claimed, 10, 1_000_000));
            // Overclaiming is caught; it never yields a bigger honest weight.
            assert!(!matched);
            assert!(!(matched && w > honest));
        }
    }

    #[test]
    fn attested_fields_do_not_move_the_recompute() {
        let base = run_with(8, 10, 8, 10, 1_000_000);
        let mut twiddled = base.clone();
        twiddled.cost_micro_usd = 999_999_999;
        twiddled.tokens = 1;
        twiddled.latency_ms = 0;
        twiddled.attested.llm_judge_score = Some(0);
        assert_eq!(recomputed(&base), recomputed(&twiddled));
    }

    #[test]
    fn attested_fields_do_change_the_receipt_hash_but_not_the_verdict() {
        // The hash commits to the WHOLE receipt (provenance), even attested
        // fields, yet the VERDICT ignores them — independent guarantees.
        let base = run_with(8, 10, 8, 10, 1_000_000);
        let mut twiddled = base.clone();
        twiddled.cost_micro_usd += 1;
        assert_ne!(receipt_hash(&base), receipt_hash(&twiddled));
        assert_eq!(recomputed(&base).1, recomputed(&twiddled).1);
    }

    #[test]
    fn zero_pass_honest_recomputes_to_zero() {
        assert_eq!(recomputed(&run_with(0, 10, 0, 10, 1_000_000)), (true, 0));
    }

    #[test]
    fn receipt_hash_is_deterministic_and_domain_separated() {
        let run = run_with(10, 10, 10, 10, 1_000_000);
        assert_eq!(receipt_hash(&run), receipt_hash(&run));
        assert!(canonical_bytes(&run).starts_with(RECEIPT_DOMAIN));
        assert_eq!(receipt_hash_hex(&run).len(), 64);
    }

    #[test]
    fn a_batch_recomputes_independently_per_run() {
        // Was `batch_folds_into_a_real_credit_file`, which asserted the fold into
        // a `CreditFile` saturated at 0. The fold is gone with the minters; what
        // it was really pinning — that each run's verdict and weight is decided
        // by its own recompute and not by its neighbours — is kept here.
        let runs = [
            run_with(10, 10, 10, 10, 400_000),  // honest, full
            run_with(5, 10, 5, 10, 200_000),    // honest, half
            run_with(3, 10, 10, 10, 1_000_000), // overclaim
        ];
        let got: Vec<(bool, u64)> = runs.iter().map(recomputed).collect();
        assert_eq!(
            got,
            vec![(true, 400_000), (true, 100_000), (false, 1_000_000)]
        );
    }
}
