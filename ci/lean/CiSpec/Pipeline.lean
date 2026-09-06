/-
  CiSpec / Pipeline — required status checks, path-filtered twins, and the
  merge rollup, as a model.

  **STATUS: PROVED (0 `sorry`).** Mathlib-free: `List` + `Bool` + `simp` /
  `decide`. Lean 4 v4.30.0-rc2, `autoImplicit = false`.

  The decision procedures in `crates/ci-spec` (I1 twin completeness, I3
  reported-under-merge_group-and-not-skippable) are the HYPOTHESES of the
  theorems here; the properties the merge queue silently relied on until
  2026-09-05 are the conclusions.

  # What is modelled

  * A `Path` is a list of segments; a `Pattern` is a directory prefix (the
    `**` glob at directory granularity, which is every filter this
    repository uses).
  * GitHub's `paths:` fires a workflow when SOME changed file matches;
    `paths-ignore:` fires when SOME changed file is NOT matched. That
    asymmetry is the whole subject of `twin_covers` / `twin_both_iff`.
  * A `Producer` is a job that reports a check-run name; `reportsInQueue`
    is what ci-spec's I3 decides per producer.
  * `rollup` is GitHub's merge rule: a required context with NO verdict
    (skipped, or never reported) counts as passed.

  # What is NOT modelled (stated, not hidden)

  * Glob syntax beyond directory prefixes (`*.rs`, `!negation`).
  * Which of two same-named check runs the rollup consults — the reason
    `twin_both_iff`'s straddling case is reported as a residual, not fixed.
  * Time. `CiSpec.Queue` orders events; it does not clock them.
-/

namespace CiSpec

abbrev Seg := String
abbrev Path := List Seg
abbrev Pattern := List Seg

/-- `**` at directory granularity: a pattern matches every path under it. -/
def globMatch (pat : Pattern) (f : Path) : Bool := pat.isPrefixOf f

/-- Some pattern in the list matches the file. -/
def matched (pats : List Pattern) (f : Path) : Bool := pats.any (fun p => globMatch p f)

/-- GitHub `paths:` — fires when SOME changed file matches. -/
def firesPaths (pats : List Pattern) (change : List Path) : Bool :=
  change.any (fun f => matched pats f)

/-- GitHub `paths-ignore:` — fires when SOME changed file is NOT matched. -/
def firesIgnore (pats : List Pattern) (change : List Path) : Bool :=
  change.any (fun f => !matched pats f)

/-- **T2 (coverage).** A real twin filtered on `pats` and a noop twin ignoring
    the SAME list never leave a non-empty change with NEITHER: the required
    context is always reported on a pull request. This is what ci-spec I1
    (`paths-ignore == paths`) buys. -/
theorem twin_covers (pats : List Pattern) (change : List Path) (h : change ≠ []) :
    firesPaths pats change = true ∨ firesIgnore pats change = true := by
  cases change with
  | nil => exact absurd rfl h
  | cons f rest =>
    unfold firesPaths firesIgnore
    cases hm : matched pats f
    · right
      simp [List.any_cons, hm]
    · left
      simp [List.any_cons, hm]

/-- **T2 (residual).** BOTH twins fire exactly when the change straddles the
    filter — one file inside, one outside. That case is a GitHub semantics
    limit (two check runs share one name), reported by ci-spec as the known
    residual of the twin pattern rather than repaired. -/
theorem twin_both_iff (pats : List Pattern) (change : List Path) :
    (firesPaths pats change = true ∧ firesIgnore pats change = true) ↔
    ((∃ f, f ∈ change ∧ matched pats f = true) ∧
     (∃ f, f ∈ change ∧ matched pats f = false)) := by
  simp [firesPaths, firesIgnore, List.any_eq_true]

/-- **Bite (both).** When the noop ignores a STRICT SUBSET of the real twin's
    paths, a homogeneous one-file change under a real-only pattern fires
    BOTH twins. `aeneas-ifc-scoped-noop.yml` on 2026-09-05, with
    `f = crates/nucleus-ifc-kernel/src/lib.rs`. -/
theorem drift_fires_both (pats ignore : List Pattern) (f : Path)
    (hp : matched pats f = true) (hi : matched ignore f = false) :
    firesPaths pats [f] = true ∧ firesIgnore ignore [f] = true := by
  simp [firesPaths, firesIgnore, hp, hi]

/-- **Bite (neither).** When the noop ignores MORE than the real twin
    filters, a one-file change under an ignore-only pattern fires NEITHER:
    the required context is never reported and the PR blocks forever. -/
theorem drift_fires_neither (pats ignore : List Pattern) (f : Path)
    (hp : matched pats f = false) (hi : matched ignore f = true) :
    firesPaths pats [f] = false ∧ firesIgnore ignore [f] = false := by
  simp [firesPaths, firesIgnore, hp, hi]

/-- A job that reports a check-run name. The three booleans are exactly what
    ci-spec I3 reads off the workflow: the producing workflow has a
    `merge_group:` trigger; the job's `if:` cannot be false there and every
    job it `needs:` is itself required (so it cannot be SKIPPED). -/
structure Producer where
  ctx : String
  isNoop : Bool
  onMergeGroup : Bool
  skippableInQueue : Bool

/-- Does `p` report `c` on the merge-queue branch, with a real verdict? -/
def reportsInQueue (p : Producer) (c : String) : Bool :=
  p.ctx == c && !p.isNoop && p.onMergeGroup && !p.skippableInQueue

/-- ci-spec's I3, as a Boolean over the model. -/
def I3 (ps : List Producer) (required : List String) : Bool :=
  required.all (fun c => ps.any (fun p => reportsInQueue p c))

/-- GitHub's merge rollup: every required context must pass, and a context
    with NO verdict counts as passed. This is the documented behaviour for
    skipped jobs, and it is the vacuity every I3 defect exploits. -/
def rollup (verdict : String → Option Bool) (required : List String) : Bool :=
  required.all (fun c => (verdict c).getD true)

/-- A verdict assignment is honest for `ps` if every context that some real,
    merge_group-triggered, non-skippable producer reports actually carries a
    verdict — a job that runs, reports. -/
def Honest (ps : List Producer) (verdict : String → Option Bool) : Prop :=
  ∀ c, ps.any (fun p => reportsInQueue p c) = true → (verdict c).isSome = true

/-- **T1 (soundness).** Under I3, every required context carries a real
    verdict on the queue branch; the rollup can never pass a required
    context by silence. -/
theorem T1_required_verdicts_exist (ps : List Producer) (required : List String)
    (h : I3 ps required = true) (verdict : String → Option Bool) (hv : Honest ps verdict) :
    ∀ c, c ∈ required → (verdict c).isSome = true := by
  intro c hc
  exact hv c (List.all_eq_true.mp h c hc)

/-- **T1 (rollup).** With every required verdict present and green, the
    rollup passes — and, by `T1_required_verdicts_exist`, "present" is what
    I3 guarantees; greenness is the checks' job, not the pipeline's. -/
theorem rollup_of_verdicts (verdict : String → Option Bool) (required : List String)
    (h : ∀ c, c ∈ required → verdict c = some true) :
    rollup verdict required = true := by
  unfold rollup
  apply List.all_eq_true.mpr
  intro c hc
  rw [h c hc]
  rfl

/-- **Bite (vacuous merge).** Without I3 — a required context whose only
    producer can be skipped — the rollup passes it with NO verdict at all.
    This is the seven contexts hanging off two non-required detector jobs on
    2026-09-05: a red detector reported them all as SKIPPED, and skipped
    counts as passed. -/
theorem vacuous_merge_without_I3 (c : String) :
    rollup (fun _ => none) [c] = true := by
  simp [rollup]

end CiSpec
