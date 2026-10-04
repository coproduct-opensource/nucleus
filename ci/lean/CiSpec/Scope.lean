/-
  CiSpec / Scope — a gate's verdict is a function of its declared read-set.

  **STATUS: PROVED (0 `sorry`).** Mathlib-free: `List` + `Bool` + `decide` +
  structural induction. Lean 4 v4.30.0, `autoImplicit = false`.

  # Why this file exists

  Every gate in `.gatehouse/gates/*.json` declares a `scope.include` glob list,
  every step declares what it `reads`, and every receipt carries a `scope`
  digest BESIDE its `tree` digest. So the ingredients for "this verdict depends
  only on these paths" are already recorded on every run. Nothing states it,
  and nothing relies on it.

  Two things follow from stating it.

  **Reuse.** If the verdict factors through the projection, then a push that
  touches nothing in a gate's read-set cannot change that gate's verdict, and
  the previous verdict is still valid. On 2026-09-21 four pull requests were
  pushed to in order to fix coverage, a clippy ceiling and a merge conflict.
  Each push restarted all five gates on a one-at-a-time builder, and each of
  those runs then died on the five-hour deadline having verified between zero
  and four gates. `.scorecard-ratchet.toml` is not in `test-core`'s declared
  scope — `CiSpecBite.ratchet_is_outside_test_core` — so one of those restarts
  was provably unnecessary.

  **Soundness.** The same statement is an obligation. A gate that reads
  anything outside its declared scope makes this false, and such a gate has a
  verdict depending on undeclared input — which is the defect `#2968` ("every
  gate declares what it runs, and the kernel reads it") set out to make
  visible. Determinacy is the property that makes the declaration mean
  something.

  # What is modelled

  * A `Tree` is a list of (path, content digest) entries; `proj` is the part a
    gate may read, using `Pipeline`'s directory-prefix globs.
  * `ScopeDetermined` says the verdict factors through `proj`.
  * The reuse theorem is then a congruence: equal projections, equal verdict.

  # What is NOT modelled (stated, not hidden)

  * That the system ACTUALLY banks a verdict. This proves reuse is sound, not
    that anyone caches. The controller keys on `tree` today.
  * Whether a gate is in fact scope-determined. That is a property of the
    command, not of the declaration, and it is exactly what a scope-escape
    lint would have to decide. Here it is a hypothesis with a name.
  * Order and duplicate paths. `proj` is a filter, so it preserves both; two
    trees that differ only by entry order are NOT related by these theorems.
  * Glob syntax beyond directory prefixes, inherited from `Pipeline`.
-/

import CiSpec.Verdict

namespace CiSpec

/-- A content digest. Only equality matters here, so `Nat` is enough. -/
abbrev Digest := Nat

/-- One tracked file: its path and the digest of its contents. -/
abbrev Entry := Path × Digest

/-- A source tree, as the gate sees it. -/
abbrev Tree := List Entry

/-- The part of a tree a gate is declared to read. -/
def proj (pats : List Pattern) (t : Tree) : Tree :=
  t.filter (fun e => matched pats e.1)

/-- A gate's verdict is scope-determined when it depends on nothing outside
    its declared read-set. This is the obligation a `scope` declaration makes
    and that nothing currently checks. -/
def ScopeDetermined (pats : List Pattern) (run : Tree → Verdict) : Prop :=
  ∀ t t' : Tree, proj pats t = proj pats t' → run t = run t'

theorem proj_nil (pats : List Pattern) : proj pats [] = [] := rfl

/-- An entry the gate may not read drops out of the projection. -/
theorem proj_cons_unmatched {pats : List Pattern} {e : Entry} {t : Tree}
    (h : matched pats e.1 = false) : proj pats (e :: t) = proj pats t := by
  simp [proj, List.filter_cons, h]

/-- An entry the gate may read stays in it. Non-vacuity for the lemma above:
    `proj` is not the constant empty function. -/
theorem proj_cons_matched {pats : List Pattern} {e : Entry} {t : Tree}
    (h : matched pats e.1 = true) : proj pats (e :: t) = e :: proj pats t := by
  simp [proj, List.filter_cons, h]

/-- **Reuse is sound.** Two trees differing only in an entry outside the
    declared scope give the same verdict, so a verdict already computed is
    still valid across such a change. This is the theorem that makes a cache
    key of (gate definition, scope digest, environment) legitimate, in place
    of the whole-tree key that forced today's restarts. -/
theorem verdict_survives_an_unmatched_change {pats : List Pattern}
    {run : Tree → Verdict} (hd : ScopeDetermined pats run)
    {e e' : Entry} {t : Tree}
    (h : matched pats e.1 = false) (h' : matched pats e'.1 = false) :
    run (e :: t) = run (e' :: t) :=
  hd _ _ (by rw [proj_cons_unmatched h, proj_cons_unmatched h'])

/-- The same statement for a whole unmatched prefix: any number of changes
    outside the scope leave the verdict alone. -/
theorem verdict_survives_unmatched_prefix {pats : List Pattern}
    {run : Tree → Verdict} (hd : ScopeDetermined pats run)
    {u u' : Tree} {t : Tree}
    (h : ∀ e, e ∈ u → matched pats e.1 = false)
    (h' : ∀ e, e ∈ u' → matched pats e.1 = false) :
    run (u ++ t) = run (u' ++ t) := by
  apply hd
  have key : ∀ v : Tree, (∀ e, e ∈ v → matched pats e.1 = false) →
      proj pats (v ++ t) = proj pats t := by
    intro v hv
    induction v with
    | nil => rfl
    | cons a as ih =>
      have ha : matched pats a.1 = false := hv a List.mem_cons_self
      have has : ∀ e, e ∈ as → matched pats e.1 = false :=
        fun e he => hv e (List.mem_cons_of_mem a he)
      simpa [List.cons_append, proj_cons_unmatched ha] using ih has
  rw [key u h, key u' h']

/-- **The residual, stated rather than discovered.** A scope that matches every
    path admits no reuse at all: nothing is outside it, so the hypothesis of
    `verdict_survives_an_unmatched_change` is never satisfiable. A gate whose
    declared read-set is the whole tree pays the full restart on every push,
    and no theorem here helps it. -/
theorem everything_is_matched (p : Path) : matched [[]] p = true := by
  simp [matched, globMatch, List.isPrefixOf]

end CiSpec
