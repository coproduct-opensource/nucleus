
---

## 235 — THE OWED CHECK: THE CONSTRUCTORS ARE FAITHFUL.  So the gap is my search.

234 owed a verification before any eighth certificate attempt: are the Rust
constructors actually the Lean Thompson construction?  Every requirement-(a)
measurement since 228 assumes it.

**Checked, line against line.**

  * `a_seq` — Lean's `seqGSystem` appends `right.initTrans` to each left state's
    transitions guarded by `left.hlt s ∧ gᵢ`, and sets
    `hlt(inl s) = left.hlt s ∧ right.initHlt`.  Rust's
    `if l.st defined … else if l.hl then jump to r.it` reproduces that exactly
    under `CoreHaltDisjoint` — a state never both halts and steps at one atom —
    and `hl[s][i] = l.hl[s][i] ∧ r.ih[i]` matches verbatim.
  * `a_ite` — dispatches at the pseudostate on `g`, bodies copied unchanged.
  * `a_wh` — matches `loopInitialized`, verified back at 223.
  * State counts follow `certifiedThompson`'s recursion exactly: `|test| = 0`
    (Empty), `|act| = 1` (Unit), `seq`/`ite` sum, `wh` body.

**Clean.  The check found nothing, which is the useful outcome:** the ~0.2% of
Thompson automata failing the certificate are not a harness artifact, so seven
iterations of measurement were at least measuring the right objects.

**Which localises the gap precisely.**  Grabmayer's theorem says EVERY chart of
an expression has LLEE.  My test says 99.8%.  The constructors are faithful and
the condition is derived rather than guessed (234).  So the failure is in the
LOOP DECOMPOSITION: **DFS natural loops are strictly narrower than LLEE's loop
sub-charts.**  233 searched elimination orders over natural loops and 234
searched guards over natural loops — both searched the wrong axis, because both
kept `natural_loops` as the generator of candidates.

That is a real algorithmic gap, not a modelling one, and it is the first time in
eight iterations the remaining defect has been isolated to a single component.

**Odds: 78%, held.**  A check that finds no bug does not advance a proof, but it
does retire a live alternative explanation and leave exactly one standing.  The
route's load-bearing facts are unchanged.

**Next.**  Replace `natural_loops` as the candidate generator: enumerate loop
sub-charts directly — a body `B` with an entry `h ∈ B` such that every edge into
`B` from outside targets `h` — rather than only those a DFS discovers.  That is
LLEE's own notion, and it is what both previous searches were ranging over the
wrong dimension of.
