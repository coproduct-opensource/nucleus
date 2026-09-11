<!--
Keep this short. Delete any heading that does not apply — an empty heading is
worse than no heading. The house style is: say what changed, say what still
holds, say what you ran.
-->

## What this is

<!-- One paragraph. What was wrong or missing, and what this does about it. -->

## The product test

<!--
ADR 0005: the objective is to expand the frontier of safely delegatable machine
agency. Answer in one line — which of the four does this change move?

  more agency      — a principal can now delegate a kind of work they could not
  more precisely   — ρ (granted ÷ observably required) falls toward 1
  more easily      — C(T) falls; the correct grant costs fewer decisions
  more confidence  — a claim gets a proof, a receipt, a measurement, or a caveat

"Peripheral, and here is why it is worth doing anyway" is a valid answer.
Infrastructure, CI and hygiene changes usually take it.
-->

## Invariants kept

<!--
Say it explicitly if this change touches authority. The one that is never
negotiable: exercised authority ≼ delegated authority. A change may not raise
the objective by weakening the invariant — no widened default, no ceiling raised
to make a task pass, no authority dimension added without a way to grant less of
it. If a default did widen, say so here in the first sentence.
-->

## Validation

<!--
The commands you ran and what they said — tests with counts, clippy, the gates
this touches. If you published a number, name the committed harness run behind
it (docs/PROOFS.md tiers: PROVEN / TESTED / ATTESTED-MODELED / MEASURED).
-->
