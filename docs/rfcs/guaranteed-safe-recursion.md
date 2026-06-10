# RFC: Guaranteed-safe recursion — Lean proofs for (probably-)safe unsupervised self-improvement

**Status:** moonshot / research target. Honest framing: this proves *probably-safe*
in the precise Guaranteed-Safe-AI sense (a frozen verifier provably enforces fixed
safety invariants, preserved under the loop's modification grammar), **not**
"provably safe self-trust" (Löb-blocked — see §1). The keystone already exists and
is partially verified (§3); this RFC is the target to complete and unify it.
Related: `regenerative-default-substrate.md`, `regenerative-dominance.md` (when
written), the `ck-types`/`ck-policy`/`ck-kernel` crates, the `merge-gate` sibling.

## 1. The two walls (what is provably impossible — don't chase it)

1. **Löb / Gödel — no self-trust.** A consistent system as strong as PA cannot
   prove its own consistency; Löb's theorem turns this into the *Löbian obstacle*:
   an agent cannot fully trust a successor that reasons in the same logic (MIRI,
   *Tiling Agents for Self-Modifying AI*). So "the loop proves its successor is
   safe using its own logic" is impossible. Known escapes (Marcello's Waterfall =
   descending proof strength; model polymorphism) are partial and exotic.
2. **Rice — no semantic oracle.** No proof decides arbitrary semantic properties
   of a successor's behaviour, and no proof shows the *specification* captures all
   real harm. Proven ⇒ "satisfies the written invariants," never "beneficial."

Conclusion: do not try to prove "the recursion is safe." Prove the tractable,
load-bearing thing instead.

## 2. The tractable reframe: Guaranteed-Safe AI

Per *Towards Guaranteed Safe AI* (Dalrymple, Bengio, Russell, Tegmark; arXiv
2405.06624): **World Model + Safety Specification + Verifier → an auditable proof
certificate** that the system meets the spec relative to the model. We don't prove
"safe"; we prove **a fixed, decidable verifier soundly enforces a fixed safety
spec, and the spec is preserved under every modification the loop can make.** This
is Löb-free: we never prove a self-strengthening logic sound — we prove a *frozen
checker* correct.

**Our unfair advantage — the world model is recompute.** GSAI's weakest link is
the world model (for a robot, physics — un-formalizable). For us a modification's
effect on the world *is* its recomputed outcome: finite, byte-exact, already
verifiable. The hardest part of the program is nearly free here.

## 3. The keystone already exists (and is partially verified)

The Constitutional Kernel **is** the GSAI verifier for the self-amendment grammar:

- **`ck-types`** — `PolicyManifest` (capabilities / I/O / budgets / proof
  requirements), `WitnessBundle` (the proof-carrying certificate), `PatchClass`
  (self-modification danger levels), `ConstitutionalInvariant`.
- **`ck-policy`** — `check_monotonicity(parent, child)`, a *pure* function
  enforcing four invariants on every amendment:
  1. **Capability non-escalation** `Cap(child) ⊆ Cap(parent)`
  2. **I/O confinement** `IO(child) ⊆ IO(parent)`
  3. **Resource boundedness** `Budget(child) ≤ Budget(parent)`
  4. **Governance monotonicity (anti-coup)** `ProofReq(child) ⊇ ProofReq(parent)`
- **`ck-kernel`** — the frozen admission engine ("rejects self-serving amendments
  even when the proposer is clever"): structure + monotonicity + evidence +
  lineage. **Kani-verified** (8 `#[kani::proof]` harnesses in `src/kani.rs`).
- **`merge-gate`** (sibling repo) — the deployed service that runs ck-kernel
  admission as a CI/merge gate.
- **Lean, already proven** (`nucleus-econ-kernels/lean/Nucleus/WitnessOlog.lean`):
  `gov_is_functor` and `gov_no_upgrade` — the Gov functor carries a step's
  assurance through *exactly*, never inflating trust.

**Invariant #4 is the concrete Löbian sidestep.** Governance monotonicity means
the loop *cannot lower its own proof requirements* — it can only ever make the bar
**stricter**. Combined with a *frozen* checker, this is what makes bounded
self-amendment safe without self-trust: the recursion provably cannot weaken the
thing that judges it.

## 4. The unified safety specification

The full spec = ck's four manifest invariants **+** the recompute/economic
invariants already proven separately, lifted into one `ConstitutionalInvariant`
set the gate enforces:

- **Honesty-tier non-promotion** — `faithfulTotal_inert_under_non_rv`
  (`nucleus-rubric/lean`): only recompute-verified columns move load-bearing
  standing. *(The loop must never make a statistical/judge signal load-bearing.)*
- **Conservation / no-skim** — `routed_conserves` (`Commons.lean`): routed +
  retained = pool; no value minted from nothing.
- **Sybil floor** — `required_bond` floor (`nucleus-creditworthiness` +
  `nucleus-witness-olog`): a fresh identity buys no discount.
- **Credit ≤ achievement** — the oracle's load-bearing credit never exceeds the
  recompute-verified result (the adversarial pressure-test's empirical property,
  to be lifted to a theorem).

## 5. The theorem suite to add (the moonshot, concretely)

Against the *real* definitions above. T1–T5 are reachable; T6 is the wall.

- **T1 — gate soundness (Kani → Lean).** Lift `check_monotonicity` from its
  bounded Kani harnesses to an unbounded Lean theorem:
  `∀ p c, check_monotonicity p c = Pass → (Cap c ⊆ Cap p ∧ IO c ⊆ IO p ∧ Budget c ≤ Budget p ∧ ProofReq c ⊇ ProofReq p)`.
- **T2 — tier non-promotion under amendment (keystone).** Universally quantify the
  existing inertness theorem over the amendment grammar:
  `∀ manifest' ∈ Reachable(amend), faithful_total(manifest') reads only RV columns`.
  Proves the loop can never promote a non-recompute signal to load-bearing.
- **T3 — conservation + Sybil-floor preserved under amendment.** Lift
  `routed_conserves` and the bond floor to "holds for every clearing / credit file
  the loop can produce."
- **T4 — anti-self-weakening (governance monotonicity, ∞-form).** From
  `gov_no_upgrade`: the enforced proof-requirement strength is non-decreasing
  across any admitted amendment chain — the loop cannot drop ProofReq below the
  safety floor.
- **T5 — inductive preservation across iterations.** Model "the verifier core
  changes only via an out-of-loop signature" as a transition system whose moves
  *exclude* edits to the gate; prove T1–T4 are preserved by induction over
  iterations ⇒ ∞-step bounded safety. **Löb-free** because the checker is fixed and
  external — no self-trust needed.
- **T6 — full self-trust / self-strengthening recursion.** **Löb-blocked.**
  Deliberately out of scope.

## 6. Wiring: route the loop through admission

The recursive self-improvement loop's merges go through `ck-kernel` admission (via
`merge-gate`): a self-modification is admitted only if it (a) `check_monotonicity`
passes, (b) carries a valid `WitnessBundle` (recompute certificate), and (c) leaves
the verifier core unchanged unless accompanied by an out-of-loop signature. The
loop's *modification grammar* = constitutional amendments + code changes carrying a
witness. This is the GSAI triple, closed.

## 7. The honest residual (what even a complete proof does NOT give)

- **Modeling gap (Rice's real bite):** proven = "satisfies our invariants," not
  "beneficial." The invariants must actually encode what matters; that is a human
  judgement, re-litigable, outside Lean.
- **Trust anchor shrinks, isn't zero:** you still trust the fixed checker logic +
  the out-of-loop signing key. Trust moves from "the whole recursion" to "a small
  frozen kernel + a key" — the entire point, but not nothing.
- **Grammar / sandbox coverage:** the proof covers moves in the modeled grammar.
  The loop must be sandboxed to exactly that grammar (no compiler-bug / side-channel
  escape). Recompute helps: the world is small and checkable.
- **Bounded vs. ∀:** ck-kernel is Kani-verified (bounded model checking) until T1
  lifts it to a Lean `∀`. Until then, the guarantee is "no counterexample up to the
  bound," not "for all."

## 8. Status & ask

Built + partially verified today: the Constitutional Kernel (Kani), `gov_no_upgrade`
/ `gov_is_functor` (Lean), the merge-gate deployment, and the §4 invariants as
standalone theorems. **Not yet:** T1 (Kani→Lean lift), T2/T3 (universal
quantification over the amendment grammar), T5 (inductive preservation), the unified
`ConstitutionalInvariant` spec, and the loop↔admission wiring. Completing T1–T5 is
what would let the human come off the *non-core* surfaces of the recursion — the
self-proving-system goal, made formal. This RFC is the recompute-verifiable target;
each theorem is independently discharge-able by us or by other agents.
