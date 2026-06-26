# RFC: Multi-Hop Non-Interference via an Unwinding Theorem (the "D1" initiative)

- **Status:** Draft
- **Author:** (initial draft)
- **Scope:** `nucleus` — `portcullis-core` / `nucleus-ifc` information-flow core
- **Tracking:** roadmap bet **D1** ("the one moonshot worth a year") from the
  algebraic-closure-frontier analysis. Concrete on-ramp is task #45
  (`FlowTracker` loop → `fold`).
- **Horizon:** human-led research, ~multi-quarter. Not loop-grindable.

---

## 1. Summary

Prove that nucleus's information-flow gate enforces non-interference **along
chains of arbitrary length** — not merely on a single step. Today the IFC gate
is proven safe *per decision* (`flows_to` / `decide_pure`, the model-level
`integrity_sink_never_admitted`). This RFC proposes lifting that single-step
guarantee to **whole traces** via a machine-checked **unwinding theorem**: no
adversarial-tainted data reaches a clean sink across a delegation chain, receipt
DAG, or multi-agent tool-call sequence of *any* depth, given correct labels.

This is the qualitative jump from *bounded* to *unbounded* assurance. Every
guarantee nucleus has today — exhaustive `decide`, the A3 Rust↔Lean parity, the
attack corpus — is finite/bounded. The set of all traces is finite-but-**unbounded**;
enumeration is not a proof there. An induction is.

## 2. Motivation

### 2.1 The gap

`nucleus-ifc/src/decision.rs` + `portcullis-core` prove the gate correct for a
**single** evaluation. But real agent execution is multi-hop:

- **delegation chains** (pcjwt / PoHAW — authority flows across N hops),
- **receipt DAGs** (`nucleus-receipt` colimit — provenance composes),
- **multi-agent tool-call sequences** (the `FlowTracker` accumulates taint over a
  whole session).

Non-interference *over these traces* is currently **asserted, not proven**. The
`FlowTracker` join is monotone per step (proven), but "an adversarial source at
hop 1 can never influence a clean sink at hop N" has no machine-checked proof.

### 2.2 Why it is the keystone

The north star — proof-carrying topologies, trustless delegation DAGs, "the agent
economy as one proof-carrying-data computation" — **rests entirely on
non-interference composing along arbitrary-length chains**. Without this theorem,
multi-hop trust is an assumption; with it, it is a consequence. D1 is the theorem
that turns the PCD vision from aspirational to sound.

## 3. Background / State of the Art

The unwinding technique is the standard route to machine-checked
non-interference. We adopt a well-trodden discipline, not a novel one:

- **Goguen & Meseguer (1982)** — non-interference + the original *unwinding*
  theorem: reduce a global security property to local conditions on single steps.
- **seL4 information-flow proof** — Murray et al., *seL4: from General Purpose to
  a Proof of Information Flow Enforcement*, IEEE S&P 2013
  (<https://sel4.systems/Research/pdfs/sel4-from-general-purpose-to-proof-information-flow-enforcement.pdf>);
  and *Noninterference for Operating System Kernels*. **The direct template:** a
  machine-checked formulation of **intransitive** non-interference with **sound
  and complete unwinding conditions** + a **proof calculus over a nondeterministic
  state monad** for discharging them across an implementation.
- **SAFE / A Verified Information-Flow Architecture** — Azevedo de Amorim et al.
  (<https://arxiv.org/pdf/1509.06503>): unwinding conditions sufficient for
  **termination-insensitive non-interference (TINI)** on a generic machine —
  the property class we target.
- **Noninfluence = Noninterference + Nonleakage** (von Oheimb 2004) and
  **Dynamic Intransitive Non-interference Revisited** (<https://arxiv.org/pdf/1601.05187>)
  — directly relevant because nucleus's labels are **dynamic** (taint accumulates;
  declassification at trusted boundaries is *intransitive*), so the static
  Goguen-Meseguer form is insufficient and the dynamic/intransitive treatment is
  required.

**What we adopt:** the unwinding-condition + induction-over-trace structure, and
the state-monad proof calculus.
**What is different here:** the subject is an agent IFC `FlowTracker` (not an OS
kernel), the stack is Rust + Lean 4 + Aeneas (not Isabelle/C), and the carrier is
the `IFCLabel` lattice with declassification, so we land in the **dynamic,
intransitive** regime from day one.

## 4. The theorem (target statement)

Informally:

> For any trace `t = [n₁, …, n_k]` of `FlowTracker` steps over node sources of
> any length `k`, and any sink `s`, if the gate admits the flow to `s`, then no
> source `nᵢ` whose label does **not** flow to `s` (per `flows_to`) has
> influenced the observable at `s`. Equivalently: observationally-equivalent
> initial states remain observationally-equivalent at every sink the policy
> separates — for traces of unbounded length.

Formally we will state **termination-insensitive, intransitive
non-interference** for the `FlowTracker` transition relation, parameterised by an
observation/equivalence relation `≈_d` per security domain `d` (a `flows_to`
downset), discharged by unwinding conditions over a single step and an induction
lemma over the trace.

## 5. Proof architecture

```
single-step gate proofs (HAVE)          ── repackage ──▶  unwinding conditions
  flows_to / decide_pure correctness                       (per-step lemmas)
  FlowTracker.join monotonicity                                   │
  integrity_sink_never_admitted                                   │ induction
                                                                  ▼
                                                  whole-trace non-interference
                                                  (arbitrary-length traces)
```

### 5.1 Candidate unwinding conditions

Stated over one `FlowTracker` step `step : State → Node → State` and a
per-domain observation `≈_d`:

1. **Output / observation consistency** — if `σ ≈_d τ` then the `d`-observable of
   `step σ n` equals that of `step τ n` (a step's visible effect at domain `d`
   depends only on the `d`-visible part of the state).
2. **Step consistency (locally respects `↝`)** — `step` preserves `≈_d`:
   if `σ ≈_d τ` and the source `n` does not flow to `d`
   (`¬ intrinsic_label(n).flows_to(d)`), then `step σ n ≈_d σ`
   (a non-`d` source cannot perturb the `d`-view).
3. **Label monotonicity (HAVE)** — `join` only raises confidentiality / lowers
   integrity & authority (already proven; the contravariant axes are why
   `FlowTracker` must originate at `from_label`, not `bottom` — see §7).

Soundness obligation: conditions (1)+(2)+(3) imply the §4 statement by induction
on trace length (the unwinding theorem itself).

### 5.2 Mapping to code

| Abstraction | nucleus artifact |
|---|---|
| transition `step` | `FlowTracker` accumulate (`nucleus-ifc/src/flow.rs`) — **as a `fold`**, task #45 |
| domain `d` / `≈_d` | a `flows_to` downset over `IFCLabel`; `≈_d` = equality of the `d`-visible projection |
| gate / admit | `flow_algebra::FlowState::flows_to(SinkClass)` + `decide_pure` |
| single-step facts | `IFCSemilatticeProofs`, `FlowProofs`, `DecidePureProofs`, the integrity result |
| declassification | trusted-boundary label lowering ⇒ **intransitive** policy (von Oheimb / dynamic NI) |

## 6. Dependencies & sequencing

1. **#45 — `FlowTracker` loop → `fold`** (prerequisite). Induction runs cleanly
   over an accumulator fold; a hand-mirrored loop does not. Also the prerequisite
   for C1 below.
2. **C1 — extract the confidentiality axis to Aeneas** (strengthens, not strictly
   required). If the induction runs over the **Aeneas-extracted** fold rather than
   a hand model, the result binds the extracted Rust, not a separate mirror —
   pulling D1 toward the binary.
3. **D1** — the unwinding conditions + induction lemma (this RFC).
4. **Unblocks** — proof-carrying topologies / trustless delegation DAGs / PoHAW
   recursion: each needs non-interference along arbitrary-length chains.

## 7. Scope boundaries (what this does NOT prove)

Honesty is load-bearing; D1 is bounded by exactly the assumptions seL4's proof is:

- **Termination-insensitive.** Timing and termination channels are out of scope
  (TINI, per SAFE). Covert/side channels generally are out of scope.
- **Label adequacy is assumed, not proven.** D1 proves non-interference *given
  correct labels*, along the explicit data-flow. Whether a `NodeKind`'s
  `intrinsic_label` is *semantically* right is outside the algebra (the permanent
  assumption shared with the rest of the IFC core).
- **Model, not binary.** Even over the extracted fold, the residual TCB stays
  `{Lean kernel, Charon + Aeneas, rustc, LLVM}` — there is no verified Rust
  compiler. Never claim "verified binary."
- **Intransitive by necessity.** Declassification at trusted boundaries means the
  policy is intransitive; the transitive Goguen-Meseguer form is insufficient and
  must not be used as a shortcut.

## 8. Open problems (the research content)

1. **Discovering the right unwinding relation `≈_d`** — strong enough to be
   inductive, weak enough to be true of the real `step`. This is the crux; it is
   not mechanical.
2. **Dynamic / intransitive labels.** Taint accumulates and declassifies, so we
   need the dynamic-intransitive treatment (arXiv 1601.05187) rather than static
   unwinding. Picking the right "sources" / policy-change semantics is open.
3. **State-monad shape.** seL4's calculus is over a nondeterministic state monad;
   our fold is (currently) deterministic. Determinism should simplify, but the
   `Freshness`/`ProvenanceSet` infinite-domain axes must be handled (bound or
   carry them abstractly — they are not bit-blastable; cf. the C4 wall).
4. **DAG vs linear trace.** Receipt provenance is a DAG, not a list; the induction
   must generalise from sequential traces to a partial order (fold over a
   topological order, or structural induction on the DAG).

## 9. Milestones

- **M0** — land #45 (`fold`); restate the existing single-step gate facts as
  unwinding conditions (1)+(2) over one `fold` step. Lean, kernel-checked.
- **M1** — prove the **transitive (static)** unwinding theorem over linear traces
  for the **integrity** axis (the already-extracted axis). First unbounded result.
- **M2** — extend to **intransitive** policy (declassification) and to the
  **confidentiality** axis (post-C1, over the extracted fold).
- **M3** — generalise from linear traces to the **receipt/delegation DAG**;
  connect to the PCD topology theorems.
- Each milestone ships a `#print axioms` assertion (`[propext, Quot.sound]`-class,
  no `ofReduceBool` on the soundness path) and a non-vacuity check.

## 10. Success criteria

1. A Lean theorem quantifying over traces of **arbitrary length** (no fixed
   bound, no `decide` enumeration) proving §4, kernel-checked with a clean axiom
   footprint.
2. The single-step conditions discharged from the **existing** proven gate facts
   (re-use, not re-proof).
3. Over the **Aeneas-extracted** `fold` (post-C1) for at least the integrity axis,
   so the result is `ExtractedKernelChecked`, not hand-model.
4. An honest scope statement (§7) shipped alongside — TINI, label-adequacy-assumed,
   model-not-binary — so the claim is never overstated.

## 11. Honesty ledger

D1 delivers **unbounded, kernel-checked** non-interference for the IFC core's
data-flow — a guarantee enumeration cannot provide and that no surveyed peer
(MVAR/FIDES/AgentSpec, all runtime-enforced + empirically evaluated) holds. It
does **not** make nucleus "more secure end-to-end": it is bounded by label
adequacy, termination/timing channels, and the model↔binary ceiling, exactly as
seL4's information-flow proof is. The win is *what becomes provable* (arbitrary
chains), stated with its limits intact.
