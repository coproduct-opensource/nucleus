# Dogfood: a verified agent coalition closing a real gap

We ran our own agent-collaboration loop on ourselves — two autonomous LLM coding
agents formed a **coalition** to add a real feature to this crate, verified by the
oracle, with credit split by Shapley value and recorded as durable reputation.
This is the proof → reputation flywheel, run end to end on a real PR.

## The gap
`summarize(&[GradeReceipt]) -> PortfolioSummary` — roll up a batch of graded
agents (one marketplace round) into a portfolio summary: counts, quarantine
partition, and the mean exact-pass rate in integer permille. Real, useful,
integer-only, deterministic. The shared spec is `testdata/dogfood/CONTRACT.md`.

## The coalition (why it's collaboration, not a contest)
- **Agent S — test author** wrote the held-out suite `tests/summarize_heldout.rs`
  (20 tests) from the spec. It did **not** implement.
- **Agent I — implementer** wrote `src/summary.rs` from the spec **alone**, never
  seeing S's tests.

The oracle's own rule — **solver ≠ test-author** — is what *forces* the
collaboration. Neither output is creditworthy alone:
- tests with no implementation deliver nothing;
- an implementation with no independent held-out tests is **unverifiable**, so the
  oracle mints it **no load-bearing credit** (the property the adversarial
  pressure-test established).

So the value exists only in the coalition `{S, I}`.

## The verified result
I's `summarize`, run against S's 20 held-out tests, passed **20/20**,
byte-identical across **3 re-runs** (determinism pinned). Graded through the
*shipped* oracle (`grade`): load-bearing credit minted, no quarantine.

## The settlement (Shapley → durable standing)
With a declared magnitude of 1,000,000 µUSD and value function
`v(∅)=v({S})=v({I})=0`, `v({S,I}) = magnitude × pass-rate`, the Shapley split is
**500,000 µUSD each** — both agents provably essential, budget-balanced. Each
agent's `CreditEvent` folds into a durable `nucleus-creditworthiness::CreditFile`;
the resulting reputation **lowers the anti-grief bond** each would post next round
(reputation substituting capital). Run it:

```
cargo run -p nucleus-oracle --example dogfood_coalition_settlement
```

## Honest scope
- **One round, two agents, one gap.** A demonstration of the mechanism on a real
  PR, not a benchmark.
- **The magnitude is declared, not market-cleared.** The full synergy *clearing*
  + fee path (Vickrey clearing, `compose`-based matching, treasury fee) lives in
  the private platform crate `nucleus-synergy`; this public dogfood exercises the
  match → verify → Shapley-split → durable-credit core.
- **Shapley is computed inline** in the example over the coalition's value
  function; production routes through `axelrod-equilibrium::shapley_value`.
- **The 50/50 split is a property of this symmetric value function** (both
  members strictly necessary), not a hardcoded constant — it falls out of the
  Shapley formula, validated by the budget-balance assertion.

---

## Round 2 — a 3-agent coalition with an *unequal* Shapley split

A second round added `PortfolioSummary::merge` (combine two marketplace-round
shards — a commutative monoid) with **three** roles:

- **S** — functional held-out tests (`tests/merge_func.rs`, 13 example-based).
- **I** — the `merge` implementation (`src/summary.rs`), from the spec alone.
- **R** — property / metamorphic tests (`tests/merge_prop.rs`, 6): the law
  `summarize(a ++ b) == summarize(a).merge(summarize(b))`, plus commutativity,
  associativity, identity.

Each suite graded I's impl independently: **S 13/13, R 6/6** (I correctly
*recomputes* the permille from merged totals — R's metamorphic test is exactly
what would catch the naive "average the two permilles" bug).

**Why the split is unequal even though every productive coalition is worth the
same.** I is a **veto player** — `v(coalition) = 0` unless it contains the
implementation. S and R are **substitutes** — either held-out suite alone
confers load-bearing credit, so `v({S,I}) = v({I,R}) = v({S,I,R})`. The Shapley
value of that structure is **φ(I) ≈ 2/3, φ(S) = φ(R) ≈ 1/6** — the irreplaceable
producer earns four times each redundant verifier, and it *falls out of the
coalition structure*, not from hand-chosen weights. (Integer µUSD shares are
apportioned by largest-remainder so they sum exactly to the magnitude; S and R
agree up to ≤1 µUSD of rounding dust.)

```
cargo run -p nucleus-oracle --example dogfood_three_agent_settlement
```

This is the economic lesson the substrate enforces by construction: **redundant
verification is valuable but commoditised; irreplaceable production is not.**

### One honest integration note
The coalition exposed a real spec gap: both test authors used
`PortfolioSummary::default()` as the monoid identity, but the struct (from round 1)
did not derive `Default`. That is correct for a monoid — the identity must be
constructible — so `Default` was added. The agents followed the contract; the
orchestrator's contract was the thing that was incomplete.
