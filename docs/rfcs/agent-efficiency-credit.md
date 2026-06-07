# RFC: Agent-efficiency credit — the `Efficiency` dimension + eval-receipt kernel

**Status:** Draft / design sketch (no code yet)
**Slots next to:** `crates/nucleus-creditworthiness/src/mint.rs`
**Depends on:** `nucleus-creditworthiness` (the credit file), `nucleus-envelope` (the
attested transcript), `nucleus-externality::AssuranceRung` (per-event assurance)

## Motivation

The financial credit file (`mint.rs`) turns recompute-verified *clearing* receipts
into bond-substituting reputation. But the demand for honest-settlement receipts is
thin today (agent↔agent commerce ≈ 0). The demand for **"is prompt/agent/config A
provably better than B?"** is thick *now* — evals are the most-budgeted activity in
agent dev.

This RFC adds a second, demand-rich dimension on the **same rails**: a
recompute-verified, portable, time-rooted track record of **agent efficiency**. The
product shape is "GitHub for agent efficiency": public, forkable profiles whose
numbers are *recomputable by anyone*, not trust-me vendor dashboards
(LangSmith / Braintrust / Langfuse / OpenAI-evals).

## The two-layer trust model (the crux)

An eval is not self-contained the way a clearing receipt is. It splits in two:

1. **Generation is ATTESTED, not recomputed.** You cannot recompute a
   non-deterministic LLM. The *recorded run* — a signed transcript of
   (prompt, model, params, tools) → (outputs, cost, tokens, latency) — is trusted
   via its signature, exactly like a `nucleus-envelope` bundle.
2. **The SCORE is RECOMPUTED.** Given the recorded transcript + a declared
   deterministic grader, anyone re-derives the metrics. This is the `mint` pattern:
   `Match` → efficiency credit, `Mismatch` → a *caught faked eval* (debit / burns
   standing), `Invalid` → nothing.

So the eval kernel takes **(receipt, transcript)** — unlike `verify_receipt`
(self-contained). The receipt commits to `transcript_hash`; you supply the
transcript; the transcript's signature is verified separately (layer 1); the grader
is re-run over its recorded outputs (layer 2).

## Honesty boundary (lead with the strong part)

| Metric | Recompute status |
|---|---|
| tokens, latency_ms | **recomputed** (recorded numbers, read from the transcript) |
| cost_micro | **recomputed** as `tokens × price_table@version` (price table must be declared+versioned, else only `tokens` is sound) |
| deterministic pass (unit-tests / exact-match / json-schema / tool-call-correct) | **recomputed** (deterministic fn of recorded outputs) |
| LLM-as-judge "quality" | **attestation-grade only** — judge drift is non-deterministic; at most recompute the *aggregation* over the judge's *recorded* outputs. Mark `assurance = attested`, never `recomputed`. |

Every event carries an `AssuranceRung` (reuse `nucleus-externality`): `recomputed` >
`attested` > `self_reported`. A ledger's headline number is only as strong as its
weakest-link rung — same anti-greenwashing primitive as the externality path.

Two more honest caveats, stated up front:
- **Backward-looking.** "This subject *did* score X, verifiably" — not "*will*."
- **Goodhart.** A record on a *fixed, self-authored* benchmark is worthless. Defenses
  below (within-suite scoping, suite provenance, held-out suites, mismatch-burns).

## Data model (sketch — `eval.rs`, behind `feature = "recompute"`)

```rust
/// Content-addressed identity of the thing evaluated (a prompt template + its
/// config). Same bytes → same subject; a changed prompt is a NEW subject (a fork).
/// This is the "GitHub for agent efficiency" unit + the namespace-as-property hook.
pub struct EvalSubject {
    pub subject_hash: [u8; 32],         // canonical hash of (prompt, model, params, tools)
    pub parent_hash: Option<[u8; 32]>,  // fork lineage, if any (recorded, NOT inherited)
}

/// A declared, versioned grader. Deterministic variants recompute; LlmJudge is
/// attestation-grade.
pub enum Grader {
    MetricsOnly,                              // cost/tokens/latency only, no scoring
    ExactMatch { expected_hash: [u8; 32] },
    UnitTests  { harness_id: String },        // deterministic harness, version-pinned
    JsonSchema { schema_hash: [u8; 32] },
    ToolCallCorrect,
    LlmJudge   { judge_subject: EvalSubject }, // attestation-grade (records judge output)
}

pub struct EvalMetrics {
    pub cost_micro: u64,
    pub tokens: u64,
    pub latency_ms: u64,
    pub passed: bool,             // deterministic graders; for LlmJudge = recorded judgment
    pub assurance: AssuranceRung, // recomputed | attested | self_reported
}

/// One claimed evaluation outcome for a subject on a task in a suite.
pub struct EvalReceipt {
    pub subject: EvalSubject,
    pub suite_id: String,         // scopes comparability (anti-Goodhart)
    pub task_id: String,
    pub transcript_hash: [u8; 32],// binds to the signed run (generation = attested)
    pub grader: Grader,
    pub claimed: EvalMetrics,
}
```

## Recompute kernel

```rust
/// The recorded run the receipt commits to. In practice a verified
/// `nucleus-envelope` bundle / lineage chain: `transcript_hash` == its head edge
/// hash, and it carries the subject's prompt hash + recorded cost/tokens/latency +
/// outputs. Its SIGNATURE is verified separately (layer 1, attestation).
pub struct Transcript { /* prompt_hash, recorded io, cost/tokens/latency, ... */ }

pub enum EvalOutcome {
    Match,
    Mismatch { field: &'static str, claimed: String, recomputed: String },
    Invalid(String),  // transcript hash mismatch, subject≠transcript prompt, unknown/
                      // non-deterministic grader, or missing price table for cost
}

/// Re-derive metrics from the transcript + declared grader; compare to `claimed`.
/// Subject-binding is enforced: the transcript's prompt hash MUST equal
/// receipt.subject.subject_hash, else `Invalid` — you can't credit prompt A with
/// prompt B's good run.
pub fn verify_eval_receipt(r: &EvalReceipt, t: &Transcript) -> EvalOutcome { /* … */ }
```

## Mint + ledger (the `mint`-shaped bridge + the accrual)

```rust
pub enum EfficiencyEvent {
    Verified  { suite_id: String, metrics: EvalMetrics }, // a Match
    FakedClaim { suite_id: String, field: String },        // a Mismatch — burns standing
}

/// Recompute one receipt → an event. `None` for `Invalid` (nothing to attribute).
pub fn mint_eval_event(r: &EvalReceipt, t: &Transcript) -> Option<EfficiencyEvent>;

/// Per-subject performance ledger. Additive counters ⇒ commutative monoid ⇒
/// order-independent ⇒ recompute-stable (the SAME proof shape as `CreditFile`).
/// Aggregated PER SUITE so comparison is within-suite (anti-Goodhart).
pub struct EvalLedger {
    pub subject: EvalSubject,
    suites: BTreeMap<String, SuiteAgg>,
    faked_claims: u64,
}
pub struct SuiteAgg {
    pub task_count: u64,
    pub pass_count: u64,
    pub total_cost_micro: u128,
    pub total_tokens: u128,
    pub total_latency_ms: u128,
}
impl SuiteAgg {
    pub fn pass_rate_bps(&self) -> u64; // derived, not stored
    pub fn avg_cost_micro(&self) -> u64;
    pub fn avg_latency_ms(&self) -> u64;
}
impl EvalLedger {
    pub fn observe(&mut self, e: &EfficiencyEvent);
    pub fn merge(self, other: Self) -> Self;            // monoid op
    pub fn from_receipts(subject: EvalSubject,
                         pairs: &[(EvalReceipt, Transcript)]) -> Self;
}
```

### Why a sibling `EvalLedger`, not a field inside `CreditFile`

`CreditFile`'s per-dimension accumulator is *value-standing* (`credit − debit →`
capital substitute). Efficiency is *performance counters → derived rates*
(lower-is-better cost vs higher-is-better pass-rate) — a different shape. So the
clean realization is a **sibling** ledger that reuses the recompute + mint + monoid
*pattern*, not the `DimAcc` *struct*. The "Efficiency dimension" lives at the
product level: an agent's reputation = `{ CreditFile (financial), EvalLedger
(efficiency), … }`. (A future generalization could make `CreditDimension` carry a
typed accumulator enum and unify them; out of scope here.)

## Properties to prove (proptests, same rigor as the credit file)

- **Commutative monoid** over `EfficiencyEvent`s (`EvalLedger::default` identity,
  `merge` assoc + commut) ⇒ order-independent ⇒ **recompute-stable** (any verifier
  replaying the same eval receipts derives the same ledger).
- **Faked-claim can't pay.** A `Mismatch` increments `faked_claims` and contributes
  no positive metrics — lying about a score is self-defeating (recompute is the
  fraud proof), the efficiency analog of "caught defection burns standing."
- **Fork earns its own record.** A fresh `subject_hash` starts empty — a fork cannot
  inherit the parent's proven history (the sybil-no-discount analog).
- **Subject binding.** An event credits *only* the subject whose hash matches the
  transcript's prompt hash.
- **Within-suite monotonicity.** A verified pass never lowers `pass_count`; cost /
  token / latency aggregates are additive.

## Anti-Goodhart (beyond "burns standing")

- **Within-suite scoping.** Records are only comparable inside a `suite_id`; a great
  score on a trivial/self-authored suite is *visible* (suite + its task set are
  hashable + named).
- **Suite provenance.** The ledger records who authored a suite; the strongest
  records are on **held-out / rotating** suites the subject didn't author and
  couldn't pre-train on.
- **Diverse / real-task evals** over a static benchmark wherever possible.

## Selection & the "credit" tie-in

A buyer/router ranks candidate prompts/agents by within-suite `(pass_rate_bps,
avg_cost_micro, avg_latency_ms)` on a held-out suite — *provably*, no vendor
dashboard. It **composes** with the financial credit file: a marketplace can
select/price an agent on BOTH its financial standing (`CreditFile`) and its
efficiency profile (`EvalLedger`). Same identity, two recompute-verified lenses.

## Dogfood path (we are the first staker)

`nucleus-platform` already has `claude-code-capture` (Claude Code session JSONL →
LineageEdges). That is the `Transcript` source. Pipeline:

```
our agent sessions → claude-code-capture → verified transcript (envelope)
   → EvalReceipt (MetricsOnly + UnitTests/ExactMatch grader over our task runs)
   → mint_eval_event → EvalLedger per prompt/agent subject
```

We accrue a recompute-verified efficiency record of our own agents from day one —
the forward bet, on a surface that pays immediately (we *want* to know which prompt
is cheaper/better).

**Boundary (per repo CLAUDE.md):** the **generic** kernel (`Transcript`, `Grader`,
`verify_eval_receipt`, `EvalLedger`) lives in OSS `nucleus-creditworthiness` —
vendor-agnostic. The **vendor-specific** capture (`claude-code-capture`) stays in
the private platform and feeds Claude sessions in.

## Open questions

1. **Transcript = envelope bundle?** Strongly lean yes: reuse `nucleus-envelope`;
   `transcript_hash` = head edge hash; signature verification = layer 1. Confirms
   "generation attested" with existing machinery.
2. **Grader determinism guarantee.** How to register + version graders and *assert*
   determinism (a non-deterministic "deterministic" grader silently breaks
   recompute-stability). Probably a small pinned-harness registry + a determinism
   self-test in CI.
3. **Cost recompute.** Needs a declared, versioned `price_table` (tokens → cost). If
   absent, credit only `tokens` (fully sound) and leave `cost_micro` `self_reported`.
4. **LLM-judge aggregation.** Exact recorded-output format so the *aggregation*
   recomputes even though the judgment doesn't.
5. **Suite registry + held-out provenance.** How held-out suites are published,
   authored, and rotated to keep records Goodhart-resistant.

## Sequencing

Land after the `@coproduct_inc/verify` fold (so `nucleus-creditworthiness` is
published to crates.io and the platform can consume it the consolidation-correct
way). Then: `eval.rs` (kernel + ledger + proptests) → WASM bindings
(`evalLedgerFromReceipts`, `passRateBps`, `avgCostMicro`) → dogfood via
`claude-code-capture`.
