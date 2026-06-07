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
