# Falsification experiment: `CommonSyntacticCollapse` is false as stated

> **Two results here are now Lean theorems**, `sorry`-free and in the CI gate:
> `GkatCollapseRefutation.not_commonSyntacticCollapse` refutes the cospan target, and
> `GkatSpanWitness.span_for_the_refuting_pair` shows the span replacement survives that
> same pair. These scripts are kept as corroboration, as an independent check on the
> transcription, and as the tool for B′ (below), which is *not* settled.

These scripts are an **executable mirror** of the Lean Thompson construction in
`GkatThompsonUniquenessProofs.lean` — `thompsonTest`, `thompsonAction`,
`iteInitialized`, `seqInitialized`, `loopInitialized`, `sumGSystem`, `seqGSystem`,
`InitializedGAut.toGAut` — plus `firstMatch` / `autStep` / `bval` from
`GkatKleeneProofs.lean` / `GkatGuardedStringProofs.lean`, transcribed constructor by
constructor. They are research scaffolding, not part of any gate; the conclusions they
support are recorded (with the structural argument that does not depend on them) in the
doc-comment of `GkatCrystallizationProofs.lean`.

Every automaton built is asserted to satisfy `UniformWF` (halting and stepping disjoint at
every atom), so a transcription error surfaces as an assertion failure rather than a wrong
answer. Uniformity is exact, not sampled: quantifying over all `W : T → X → Bool` is
quantifying over all valuations of the primitive tests, and those are enumerated in full.

## Running

Plain Python 3, no dependencies. Run from this directory, in order (`run3` and `run5`/`run6`
read `crux.pkl`, written by `run2`).

| Script | Question | Result |
|---|---|---|
| `run1.py` | Does the plan's own week-one pair (the W1 unrolling) falsify anything? | No — for every body tried, the target *is* `thompson(e)`, so the pair sits inside the class `equivBA_of_cover` already settles. |
| `run2.py 4` | Over all expressions up to size 4, how many equivalent pairs need a *third* program? | 3,026 equivalent pairs; 1,728 (57%) are "crux" — neither side's automaton is the forced target. |
| `run3.py 4 5` | Is the forced target realised by some Thompson automaton? | 1,548 / 1,728 yes within a bounded pool; 180 candidates left over. |
| `run4.py 2` | **Decide** the smallest candidate, exhaustively. | Closes the Thompson combinators to a fixpoint: 4,767 one-action automata over two tests, saturating after four rounds. The target is absent. |
| `run5.py` | Does the span (common *refinement*) repair it? | Yes for the refuting pair, via `h = if b then e else f`. |
| `run6.py 5` | Is the canonical span candidate — the pullback — Thompson-realisable? | Projections surjective in all 374 single-action crux pairs; 232 pullbacks realised in a small pool, 142 unresolved by that pool (not shown impossible). |

## The refuting pair

Over one test `b` and one action `p`:

```
e = p ; while b do p
f = (if b then 1 else p) ; while b do p
```

Both automata have three states and are fully reachable, and the two programs are
uniformly language-equivalent. Because GKAT automata are deterministic, a functional
bisimulation identifying the two starts is forced to identify `δ_e w` with `δ_f w` for
every trace `w` and to be step-closed — so the reachable part of any target is pinned to
the joint trace quotient, here

```
state 0:  never halts,   steps p → state 1  at every atom
state 1:  halts on ¬b,   steps p → state 1  on b
```

which is already bisimulation-collapsed. So a target must be isomorphic to it exactly:
one core state, i.e. one action occurrence in `h`. No such `h` exists — a self-looping
single core state can only be the body state of a `while g do _` with `g ⊆ b`, and every
transition entering a loop body from outside carries that guard conjoined
(`loopInitialized.initTrans` is `.and guard _`; `seq` / `ite` / `wh` only conjoin further),
so no Thompson start can step into it at a `¬b` atom.

`⊢ e = f` is derivable regardless (distribute the leading conditional over the sequence,
rewrite the `b` branch by W1, the branches coincide), so **completeness is untouched** —
the collapse was sufficient, never necessary.

## What replaced it

`CommonSyntacticRefinement` in `GkatCrystallizationProofs.lean`: a *span* (one program
covering both) rather than a cospan (both collapsing onto one program).
`completeness_of_common_syntactic_refinement` derives `FiniteAxiomsCompleteBA` from it in
three lines, using only `equivBA_of_cover` and transitivity — no new machinery.


## B′: does the span always exist?

`span-search/` is a Rust + rayon closure over the Thompson combinators. It answers a
sharper question than a bounded expression enumeration, because two facts make the bound
sound rather than a sampling artefact:

* composition never decreases the core-state count (`seq`/`ite` add, `wh` preserves), so an
  automaton with `k` states is only ever built from automata with `<= k`;
* an unreachable state of a component stays unreachable in every composite, so a fully
  reachable composite is built only from fully reachable components.

Together the closure is **complete** for fully reachable targets with at most `K` core
states. `igsem.py` states the same semantic algebra in Python and `check_algebra` validates
every clause against the literal Lean transcription in `crystal.py`; `xcheck.py` then diffs
the Python closure against the Rust one (identical at `K=1`: 43 automata, and at `K=2`:
573).

Run: `cd span-search && cargo run --release -- <atoms> <K> <pair-k>`.

Complete closures, one test and one action:

| K | fully reachable Thompson automata |
|---|---|
| 1 | 43 |
| 2 | 573 |
| 3 | 9,004 |
| 4 | 156,601 |
| 5 | 2,902,884 |
| 6 | 56,174,753 |

### Result

Over the 273 crux pairs whose two sides each have at most 3 core states and in which every
state can still terminate:

| bound on `h` | pairs with a span | residue |
|---|---|---|
| K = 4 | 219 | 54 |
| K = 5 | 253 | 20 |
| K = 6 | **267** | **6** |

The residue is explained by the bound, not by an obstruction: four of the six have
pullbacks needing 7 core states, and the other two have 6-state pullbacks that are not
themselves Thompson, so any witness must be a strictly larger unfolding. **Nothing refutes
the span.** Contrast the cospan, where the target was *pinned* and provably absent from a
saturated closure — that was a decision; this is an unrefuted bound.

### Where the failures live when the filter is dropped

Without the productivity filter the picture inverts: nearly every failure sits in a
null-language or divergent region (`hl` identically zero, or a state that can never reach a
halt). Those are exactly what `nullLanguage_complete` and `dead_thompson_label_eq_zero`
already discharge, and exactly what Phase A pruning removes. So the span target wants
stating for *productive* programs, with pruning as the bridge — which promotes Phase A from
tidy-up to precondition.


## Does the open existence case actually arise?

The n=2 existence frontier (`GkatExistenceFrontierProofs`, narrowed in
`GkatExistenceNarrowProofs`) leaves open exactly one configuration: **two-exit mutual
recursion** — two mutually reachable states that can each leave the cycle — with
non-degenerate guards and an undecided crossing.

A tempting mechanism for closing it is to show the configuration never arises where
completeness needs it. Two measurements:

**Falsified for Thompson automata.** 44,432 of the 2,902,884 syntax-generated automata at
`K=5` contain a two-halt 2-cycle, so syntax-generation does not exclude it. That test was
also aimed at the wrong object: for a Thompson automaton existence is free — its own
canonical labelling is a solution. The systems that actually need solving are the *joint*
ones.

**Retargeted to the pullbacks**, the picture is sharper:

| pullbacks | with a two-halt 2-cycle |
|---|---|
| solvable by the syntax | 95 / 253 (37.5%) |
| **not** solvable at `K<=5` | **18 / 20 (90%)** |

So the configuration the equational frontier leaves open is strongly enriched among exactly
the pullbacks the automaton-level search cannot cover. Two independent lines — the blocked
`LeftDistrib` elimination and the span search — point at the same structure.

It is a correlate, not a characterization: two unsolvable pullbacks lack the configuration
and 95 solvable ones have it. But it is evidence that the frontier's open case is the real
obstruction rather than an artefact of the elimination strategy.


## Testing the refinement mechanism

The candidate mechanism for the undecided residue is: do not commute the guard, **refine the
expression** until its automaton folds onto the system. `unrollCover` and the `unroll_in_*`
context lemmas make each refinement step a proved cover, and `InitCover.comp` chains them.

Its cheapest prediction is that the pullbacks the closure cannot cover become coverable
after unrolling. `unroll_variants` in the search implements the automaton-level move —
rewrite some `while g do B` occurring anywhere inside a program as
`if g then (B ; while g do B) else 1` — and applies it to every same-behaviour candidate.

**The prediction failed.** For each of the four uncoverable pullbacks at `K=5`:

| |P| | candidates | variants | usable | largest | covered |
|---|---|---|---|---|---|
| 5 | 60 | 70 | 70 | 8 | no |
| 5 | 60 | 70 | 70 | 8 | no |
| 5 | 60 | 69 | 69 | 8 | no |
| 5 | 60 | 69 | 69 | 8 | no |

The negative is not an artefact of filtering: every variant generated was within the
representable bound and fully reachable, so all 70 were actually tested.

What it does not settle: only **one** unrolling was applied (iterating needs provenance on
the variants, which the closure does not carry), candidates came from the `K=5` closure, and
variants were capped at 8 core states — the largest generated hit exactly that cap, so
larger unrollings were dropped rather than tested.

So the mechanism is not refuted, but its first concrete prediction did not hold. Keeping it
alive requires either iterated unrolling, a larger bound, or a different refinement move
than W1-unrolling.

### All three, tested — and the verdict above was premature

Candidates are now carried as **trees** rather than automata, so refinements can be iterated
(the constructors are not invertible, which is why one step was all the earlier test could
manage). `MAXK` was raised from 8 to 16. And a second move was added:

* **W1-unrolling** — `while g do B ⟶ if g then (B ; while g do B) else 1`
* **guard-split duplication** — `e ⟶ if g then e else e`, doubling a subterm's states and
  entering the copies under complementary guards. This is the move that produced the span
  witness for the refuting pair, and it is not an unrolling.

On the four pullbacks that are within the closure bound and uncoverable: **4 / 4 rescued**
by two rounds of unrolling. On all twenty uncovered pairs:

| refinement | rescued | largest variant |
|---|---|---|
| unroll ×1 | 6 / 20 | 10 |
| **unroll ×2** | **12 / 20** | 15 |
| unroll ×3 | 12 / 20 | 15 |
| **unroll + dup ×1** | **12 / 20** | 10 |
| unroll + dup ×2 | 12 / 20 | 16 |

Two things follow. **Iteration matters**: one round rescues 6, two rescue 12. **Duplication
is the stronger move**: it reaches 12 in a single round where unrolling needs two. The
earlier negative was an artefact of testing one step with an 8-state cap.

The eight that resist are uniform: `|P|` of 6 or 7, all carrying the two-halt 2-cycle, and
all with only 15 candidates in their behaviour class against 60 for the rescued four. That
last number is a plausible confound — the search may simply lack the right starting program
rather than the refinements being insufficient.


## The right frame: these are covering spaces

`InitCover` is a functional bisimulation that is onto. Because GKAT automata are
deterministic, each state's outgoing edges are indexed by atoms on *both* sides and the
cover matches them in both directions — so the map is **bijective on stars**. That is
exactly Stallings' definition of a **covering map of graphs** (an *immersion* is injective
on stars; a covering is bijective).

So "which systems are covered by a Thompson automaton" is a covering-space question, and the
standard dictionary applies: coverings of a graph correspond to subgroups of its fundamental
group, which for a graph is free; finite covers correspond to finite-index subgroups; and
Stallings' folding theorem factors any graph map into folds followed by an immersion.

Two consequences that are not decoration.

**The fibre-product fact explains the pullback sizes.** The pullback of two covers
decomposes into components indexed by double cosets; for covers of a circle of degrees `m`
and `n`, the components have length `lcm(m, n)`. That is directly what the search sees — a
period-2 lasso against a period-3 cycle produces a 6-state pullback, computed by hand early
in this work before the frame was recognised.

**It explains which refinements can and cannot help.** To cover a system whose cycle has
length `L`, a candidate needs a cycle whose length `L` divides — and a Thompson automaton's
cycle length is the number of action occurrences in its loop body. Neither tested move
changes that:

* **W1-unrolling** *peels*: `while g do B` becomes a lasso with a longer tail and the **same
  cycle**. It adds prefix states, not cycle length.
* **Guard-split duplication** doubles a subterm's states into two parallel copies, again
  leaving cycle length alone.

So both moves saturate, exactly as observed (×3 and ×2 add nothing over ×2 and ×1). The
resistant cases have pullbacks of 6–7 states against a candidate pool capped at 5 core
states — under this frame that is not a confound to be explained away but the *prediction*:
the covering that would work needs a longer loop body than any candidate in the pool has.
The test is to widen the pool, not to refine harder.

### The K=6 run settles it: the residue was the pool

Re-running the refinement test against the K=6 closure (56,174,753 fully reachable Thompson
automata, 36,657,811 behaviour classes) gives:

```
SPAN FOUND        : 267 / 273 crux pairs
NO span (k <= 6)  :   6
refinement test on 6 uncoverable pullbacks (MAXK=16):
  unroll x1     : rescued 6 / 6
```

Compare K=5, where the residue was 20 and iterated refinement saturated at 12/20 with eight
permanently resistant. Widening the pool by one state both covers 14 of the 20 directly and
drops the remaining 6 to a single unrolling step. **Zero residue across the whole
enumeration.**

The two-halt 2-cycle correlation sharpens with it: 6/6 (100%) of unsolvable pullbacks carry
it, against 107/267 (40%) of solvable ones.

The size law is the standard one: the fibre product of an m-fold and an n-fold cover of a
circle has gcd(m,n) components each of degree lcm(m,n). A pullback's cycle is therefore
longer than either side's, and covering it needs a candidate whose cycle length lcm(m,n)
divides — so the pool must exceed the pullback. That is why the residue tracked K (54 -> 20
-> 6 -> 0-with-one-unroll) and never tracked refinement depth.

Both refinement moves in the search leave the covering degree fixed: W1-unrolling lengthens
the tail, guard-split duplication widens. The move that changes it is the degree-k cyclic
cover of a loop, whose syntax is the loop body repeated. That is the next candidate-
generating move to test, and it is a different question from "unroll further".

### The loop-body-repeated move, tested

Added as a third refinement, the degree-2 cyclic cover of a loop:

    while g do p   ==>   while g do (p ; if g then p else 1)

**Soundness first.** Checked as a semantic identity before using it: every cyclic cover of
degree 2 and 3, at every loop position, over a 400,000-program prefix of the closure —
1,271,934 variants at K=5 and 624,246 at K=4, **zero behaviour mismatches**.

**It closes both enumerations, and the old moves cannot.**

```
                    K=4 (54 uncoverable)   K=5 (20 uncoverable)
  W1 x1                   10 / 54                 6 / 20
  W1 x2                   16 / 54                12 / 20      <- saturates
  W1+dup x1               34 / 54                12 / 20
  W1+dup x2               34 / 54                12 / 20      <- saturates
  cyc2 alone x1           28 / 54                12 / 20
  cyc2 alone x3           32 / 54                16 / 20      <- saturates
  W1+cyc2 x2              48 / 54                20 / 20
  W1+cyc2 x3              54 / 54                20 / 20      <- COMPLETE
  W1+dup+cyc2 x1          54 / 54                20 / 20      <- complete in ONE round
```

Three things fall out:

* **Degree 2 is enough.** Degree 3 never rescues anything that iterated degree-2 does not.
  So the missing ingredient is a single equation, not a scheme indexed by k.
* **The moves are complementary; neither subsumes the other.** cyc2 alone saturates (32/54,
  16/20) exactly as W1 alone does. W1 changes the tail, cyc2 changes the cycle, and the
  pullback generally needs both.
* **Pool width was a symptom, not the cause.** K=6 closed the K=5 residue only because a
  wider pool happens to contain longer-cycle programs. The cyclic cover manufactures them
  from a small candidate: at K=5 it closes all 20 with variants of at most 12 states.

**Derivability: settled, and it is derivable.** `GkatCyclicCoverProofs.lean` proves
`cyclicCover` — the doubled automaton covers the loop's, for an arbitrary body — and from it
`loop_doubling_provable : EquivBA (while g do e) (while g do (e ; if g then e else 1))`.
`EquivBA` is the finite system with no uniqueness axiom, so loop doubling is a finite-axiom
theorem, and using it as a refinement move is not circular.

The hand derivation misled: deriving it from W1 stalls exactly where UA lives. Unrolling both sides of
`x^(b) = (x(x +_b 1))^(b)` and writing `L`, `R` for the two loops reduces the goal to
`x(xL +_b 1) = x(xR +_b 1)`, i.e. to `L = R` — the two sides are two solutions of the same
guarded system, and identifying them is precisely what the uniqueness axiom does. The cover
route never takes that step: the doubled automaton covers the loop's, so the loop's canonical
labelling lifts to a solution of the doubled system, and *Thompson uniqueness* — a theorem
about syntax-generated automata, not an axiom — makes the lifted solution provably canonical
pointwise. The lesson generalises: a stalled hand derivation is not evidence that UA is
needed, because the cover architecture discharges fixpoint identifications that direct
equational reasoning cannot reach.

### The whole space, not just pullbacks — and why the general statement is the wrong target

The natural next theorem looked like **`Nested ⟹ HasThompsonCover`**: every automaton
satisfying the nesting coequation is *covered* by a Thompson automaton, not merely bisimilar
to one. Schmid–Kappé–Kozen–Silva prove the bisimilarity version and that the class is a
covariety; the cover version would finish the programme, because covarieties are closed
under subobjects and products, so pullbacks satisfy the coequation for free.

`expansion_test` checks it directly. It generates **every** fully reachable automaton with at
most `kmax` states in BFS-canonical form — the space the closure is only a sample of — and
for each one that is productive and bisimilar to an expression, asks whether an expression
also covers it.

Against the K=6 closure at `kmax = 3` (1,357,508 automata, 179,225 dropped as dead
null-language regions that `nullLanguage_complete` discharges):

```
  productive AND bisimilar to an expression : 9191
  DIRECTLY covered by an expression         : 9171
  rescued by refinement (4 rounds, cap 200k):   14
  RESIST                                    :    6
  of the uncovered, ARE a crux pullback     :    0
```

The residue is 6 and it is stable: identical at 2 and at 4 refinement rounds, so depth is
saturated, and it fell 56 → 6 only when the pool went K=5 → K=6. All six share `k=3`,
`ih=0`, `it=[1,2]` — the pseudostate never halts and splits on the atom straight into two
distinct states.

**The last line is the point.** Not one of the six is a pullback. Meanwhile every crux
pullback *is* covered — 267 of 273 directly, the other 6 by a single W1-unrolling. So the
general statement and the statement the programme needs come apart, and only the second is
supported. `CommonCoveredIntermediate` asks for *some* common covered intermediate and the
pullback is the canonical one; arbitrary coequation-satisfying automata never have to be
covered at all.

Attacking `Nested ⟹ HasThompsonCover` would have been months spent on a theorem that looks
false. The target is the narrower one: **the pullback of two equivalent Thompson automata is
covered by a Thompson automaton.**

### Performance

The search is hash-bound: at K=6 every one of 56M automata is looked up on production, and
most lookups hit. What the profile-driven pass changed, all outputs held identical:

* the round loop cloned `seen` (~3 GB at K=6) and rebuilt the state-count buckets from
  scratch, both serially, both every round — the parallel section was starved;
* buckets held bare automata, so the innermost loop paid a hash lookup per `(x, y)` pair to
  recover an index already known — buckets now carry `(Aut, index)` and the hot loop hashes
  nothing;
* products were all materialised and only then tested against `seen`; the test moved inside
  the parallel section, so a round's output holds only genuinely new automata;
* `behaviour()` built a `HashMap` and two `HashSet`s *per refinement round* and is called
  once per closure member — rewritten allocation-free (`k <= MAXK = 16`, so fixed arrays);
* FxHash throughout, `Aut::hash` over the live `k`-state prefix only, `VecDeque` → fixed ring
  buffers in `canon`/`covers`, and `vec![vec![false;k];k]` → `[u16; MAXK]` bitmask rows.

```
  K=4   2.80s -> 0.79s
  K=5  31.4s  -> 4.84s        CPU 185% -> 393%
  K=6  full run incl. expansion test: 1m52s
```

### The corrected target, and what it factors into

Stallings' Lemma supplies the dictionary. Covers of a graph `m` correspond to subgroups of
the free group `π₁ m`; a Thompson automaton picks out a "Thompson subgroup"; and the fibre
product of two covers has

    π₁ (a ⊗_m b)  =  π₁ a ∩ π₁ b.

So the pullback of two equivalent Thompson automata *is* the subgroup `H_e ∩ H_f`, and the
corrected target says some Thompson subgroup lies below it.

That suggests a statement stronger than the target but weaker than the refuted one, and it
is exactly the property the counterexamples lack:

    ThompsonCofinal:  a system that COVERS a Thompson automaton is COVERED by one.

A pullback always satisfies the hypothesis — it projects onto both sides. Group-theoretically
this says Thompson subgroups are **cofinal below every Thompson subgroup**, which handles the
intersection case and explains the counterexamples at once: they lie below no Thompson
subgroup at all, so nothing is required of them.

Measured at `kmax = 3` against the K=6 closure:

```
  productive AND bisimilar to an expression : 9191
  COVER a Thompson automaton (hypothesis)   : 2542
    ... of those, COVERED by one            : 2542      <- no exceptions, none needing refinement
  RESIST (bisimilar but uncovered)          :    6
    ... of those, COVER a Thompson automaton:    0      <- every counterexample fails the hypothesis
```

`GkatCofinalityProofs.lean` names the split and proves the reduction:
`commonCoveredIntermediate_of_halves` derives the residual obligation from `SpanExists`
(a construction — the pullback) plus `ThompsonCofinal` (the substantive half), and
`completeness_of_halves` chains it to `FiniteAxiomsCompleteBA`. Both are `sorry`-free.

It also records why no degree-3 cyclic cover was ever needed: `cyclicCover4` is
`cyclicCover` composed with itself, so every power of two comes for free from
`InitCover.comp`, and the data shows degree 3 rescues nothing those do not.
