/-
  CiSpec / Queue — the merge queue as a state machine.

  **STATUS: PROVED (0 `sorry`).** Mathlib-free: `Nat` + `List` + `Bool` +
  `simp` / `omega` + structural induction. Lean 4 v4.30.0-rc2,
  `autoImplicit = false`.

  The shape is the one Mergify's and Aviator's TLA+ merge-queue specs use
  (a train of entries, per-PR lifecycle sets), reduced to what this
  repository's queue does: build concurrency 1, ALLGREEN grouping, squash.

  # Events

  * `enqueue p` — a waiting PR joins the tail of the queue.
  * `pass p` / `fail p` — the group's required checks report green / red
    (the queue's check timeout is a `fail`).
  * `push p` — a push to a queued PR's head: GitHub removes it from the
    queue and drops auto-merge (observed 2026-09-04; modelled so it cannot
    be forgotten).
  * `cancel p` — a workflow run of p's group is cancelled. For a QUEUED p
    this is a red check (an ejection); for a DEQUEUED p it touches nothing
    the queue reads.
  * `merge` — the head merges if its checks are green.

  # Theorems

  * **T3** `consistent` is preserved: a PR is in the queue list exactly when
    its location says `queued`, and the queue has no duplicates (NoPRLost /
    NoDuplicate, by construction of the transition function).
  * **T4** `mergedLog` is a subsequence of `enqLog`: merges happen in
    enqueue order, never out of it.
  * **T5** cancelling a run of a PR that is no longer in the queue changes
    neither the queue nor whether the head can merge — the "cancel
    superseded runs" policy of the merge-only directive is safe.
  * **T6** a push to a queued PR returns it to waiting and removes it from
    the queue.

  # Not modelled

  * Time and runners (that is `CiSpec.Capacity`, the next file).
  * Speculative groups (`max_entries_to_build > 1`) — this repository runs
    at 1, and the pin in ci/merge-queue.toml is what live-parity holds.
-/

namespace CiSpec

inductive Loc
  | waiting
  | queued
  | merged
  | ejected
  deriving DecidableEq, Repr

structure State where
  loc : Nat → Loc
  queue : List Nat
  enqLog : List Nat
  mergedLog : List Nat
  /-- The group's required checks are green. -/
  checks : Nat → Bool

def State.init : State :=
  { loc := fun _ => .waiting, queue := [], enqLog := [], mergedLog := [], checks := fun _ => false }

inductive Ev
  | enqueue (p : Nat)
  | pass (p : Nat)
  | fail (p : Nat)
  | push (p : Nat)
  | cancel (p : Nat)
  | merge

def upd (f : Nat → Loc) (p : Nat) (l : Loc) : Nat → Loc :=
  fun q => if q = p then l else f q

def setB (f : Nat → Bool) (p : Nat) (b : Bool) : Nat → Bool :=
  fun q => if q = p then b else f q

/-- Remove every occurrence of `p`. -/
def without (q : List Nat) (p : Nat) : List Nat := q.filter (fun x => x != p)

/-- Eject `p` from the queue (red check, timeout, cancelled run). -/
def eject (s : State) (p : Nat) : State :=
  { s with loc := upd s.loc p .ejected, queue := without s.queue p, checks := setB s.checks p false }

def step (s : State) (e : Ev) : State :=
  match e with
  | .enqueue p =>
    if s.loc p = .waiting then
      { s with loc := upd s.loc p .queued, queue := s.queue ++ [p], enqLog := s.enqLog ++ [p] }
    else s
  | .pass p =>
    if s.loc p = .queued then { s with checks := setB s.checks p true } else s
  | .fail p =>
    if s.loc p = .queued then eject s p else s
  | .push p =>
    if s.loc p = .queued then
      { s with loc := upd s.loc p .waiting, queue := without s.queue p, checks := setB s.checks p false }
    else s
  | .cancel p =>
    if s.loc p = .queued then eject s p else { s with checks := setB s.checks p false }
  | .merge =>
    match s.queue with
    | h :: t =>
      if s.checks h then
        { s with loc := upd s.loc h .merged, queue := t, mergedLog := s.mergedLog ++ [h] }
      else s
    | [] => s

def run (s : State) (evs : List Ev) : State := evs.foldl step s

/-- Can the head merge right now? -/
def mergeEnabled (s : State) : Bool :=
  match s.queue with
  | h :: _ => s.checks h
  | [] => false

/-- The queue list and the location map agree, and the queue has no
    duplicates. -/
structure Consistent (s : State) : Prop where
  mem_iff : ∀ p, p ∈ s.queue ↔ s.loc p = .queued
  nodup : s.queue.Nodup

/-- The merged log, followed by the live queue, is a subsequence of the
    enqueue log. -/
def Ordered (s : State) : Prop := (s.mergedLog ++ s.queue).Sublist s.enqLog

-- ── List helpers (Mathlib-free) ─────────────────────────────────────────

theorem mem_without {q : List Nat} {p x : Nat} :
    x ∈ without q p ↔ x ∈ q ∧ x ≠ p := by
  simp [without, List.mem_filter]

theorem not_mem_without (q : List Nat) (p : Nat) : p ∉ without q p := by
  intro h
  exact (mem_without.mp h).2 rfl

theorem nodup_without {q : List Nat} (h : q.Nodup) (p : Nat) : (without q p).Nodup := by
  induction q with
  | nil => simp [without]
  | cons a rest ih =>
    rw [List.nodup_cons] at h
    have ih' := ih h.2
    unfold without at ih' ⊢
    rw [List.filter_cons]
    split
    · rw [List.nodup_cons]
      refine ⟨?_, ih'⟩
      intro m
      exact h.1 (List.mem_filter.mp m).1
    · exact ih'

theorem nodup_snoc {l : List Nat} {p : Nat} (h : l.Nodup) (hp : p ∉ l) :
    (l ++ [p]).Nodup := by
  induction l with
  | nil => simp
  | cons a rest ih =>
    rw [List.nodup_cons] at h
    have hpa : p ≠ a := fun e => hp (e ▸ List.mem_cons_self)
    have hp' : p ∉ rest := fun m => hp (List.mem_cons_of_mem a m)
    rw [List.cons_append, List.nodup_cons]
    refine ⟨?_, ih h.2 hp'⟩
    intro m
    rw [List.mem_append, List.mem_singleton] at m
    cases m with
    | inl m => exact h.1 m
    | inr m => exact hpa m.symm

theorem without_sublist (q : List Nat) (p : Nat) : (without q p).Sublist q :=
  List.filter_sublist

-- ── T3: consistency is an invariant ──────────────────────────────────────

theorem consistent_init : Consistent State.init := by
  refine ⟨?_, List.nodup_nil⟩
  intro p
  simp [State.init]

theorem consistent_eject {s : State} (hs : Consistent s) (p : Nat) : Consistent (eject s p) := by
  refine ⟨?_, nodup_without hs.nodup p⟩
  intro q
  simp only [eject, upd]
  rw [mem_without, hs.mem_iff]
  by_cases hq : q = p
  · subst hq
    simp
  · simp [hq]

theorem consistent_step {s : State} (hs : Consistent s) (e : Ev) : Consistent (step s e) := by
  cases e with
  | enqueue p =>
    simp only [step]
    split
    · rename_i hw
      have hnot : p ∉ s.queue := by
        intro m
        rw [hs.mem_iff] at m
        rw [m] at hw
        exact absurd hw (by decide)
      refine ⟨?_, nodup_snoc hs.nodup hnot⟩
      intro q
      simp only [upd]
      rw [List.mem_append, List.mem_singleton, hs.mem_iff]
      by_cases hq : q = p
      · subst hq
        simp
      · simp [hq]
    · exact hs
  | pass p =>
    simp only [step]
    split
    · exact ⟨hs.mem_iff, hs.nodup⟩
    · exact hs
  | fail p =>
    simp only [step]
    split
    · exact consistent_eject hs p
    · exact hs
  | push p =>
    simp only [step]
    split
    · refine ⟨?_, nodup_without hs.nodup p⟩
      intro q
      simp only [upd]
      rw [mem_without, hs.mem_iff]
      by_cases hq : q = p
      · subst hq
        simp
      · simp [hq]
    · exact hs
  | cancel p =>
    simp only [step]
    split
    · exact consistent_eject hs p
    · exact ⟨hs.mem_iff, hs.nodup⟩
  | merge =>
    simp only [step]
    split
    · rename_i h t hq
      split
      · have hn := hs.nodup
        rw [hq, List.nodup_cons] at hn
        refine ⟨?_, hn.2⟩
        intro q
        simp only [upd]
        have hm := hs.mem_iff q
        rw [hq, List.mem_cons] at hm
        by_cases hqh : q = h
        · subst hqh
          simp [hn.1]
        · simp only [hqh, ↓reduceIte]
          rw [← hm]
          simp [hqh]
      · exact hs
    · exact hs

theorem consistent_run (evs : List Ev) : Consistent (run State.init evs) := by
  unfold run
  suffices h : ∀ (s : State), Consistent s → Consistent (evs.foldl step s) from
    h State.init consistent_init
  induction evs with
  | nil => intro s hs; exact hs
  | cons e rest ih =>
    intro s hs
    exact ih (step s e) (consistent_step hs e)

-- ── T4: merges are in enqueue order ──────────────────────────────────────

theorem ordered_init : Ordered State.init := by
  simp [Ordered, State.init]

theorem ordered_eject {s : State} (ho : Ordered s) (p : Nat) : Ordered (eject s p) := by
  unfold Ordered at *
  simp only [eject]
  exact ((without_sublist s.queue p).append_left s.mergedLog).trans ho

theorem ordered_step {s : State} (ho : Ordered s) (e : Ev) : Ordered (step s e) := by
  cases e with
  | enqueue p =>
    simp only [step]
    split
    · unfold Ordered at *
      simp only
      rw [← List.append_assoc]
      exact ho.append_right [p]
    · exact ho
  | pass p =>
    simp only [step]
    split <;> exact ho
  | fail p =>
    simp only [step]
    split
    · exact ordered_eject ho p
    · exact ho
  | push p =>
    simp only [step]
    split
    · unfold Ordered at *
      simp only
      exact ((without_sublist s.queue p).append_left s.mergedLog).trans ho
    · exact ho
  | cancel p =>
    simp only [step]
    split
    · exact ordered_eject ho p
    · exact ho
  | merge =>
    simp only [step]
    split
    · rename_i h t hq
      split
      · unfold Ordered at *
        simp only
        rw [hq] at ho
        rw [List.append_assoc, List.singleton_append]
        exact ho
      · exact ho
    · exact ho

theorem ordered_run (evs : List Ev) : Ordered (run State.init evs) := by
  unfold run
  suffices h : ∀ (s : State), Ordered s → Ordered (evs.foldl step s) from
    h State.init ordered_init
  induction evs with
  | nil => intro s hs; exact hs
  | cons e rest ih =>
    intro s hs
    exact ih (step s e) (ordered_step hs e)

/-- **T4.** Every reachable state merges in enqueue order. -/
theorem T4_merge_order (evs : List Ev) :
    (run State.init evs).mergedLog.Sublist (run State.init evs).enqLog :=
  (List.sublist_append_left _ _).trans (ordered_run evs)

-- ── T5: cancelling a dequeued PR's run is safe ───────────────────────────

/-- **T5.** If `p` is not in the queue, cancelling one of its runs leaves the
    queue as it was and does not change whether the head can merge. This is
    what makes "cancel every superseded merge_group run" a safe policy. -/
theorem T5_cancel_safe {s : State} (hs : Consistent s) (p : Nat) (hp : p ∉ s.queue) :
    (step s (.cancel p)).queue = s.queue ∧
    mergeEnabled (step s (.cancel p)) = mergeEnabled s := by
  have hloc : s.loc p ≠ .queued := by
    intro h
    exact hp ((hs.mem_iff p).mpr h)
  simp only [step, hloc, ↓reduceIte]
  refine ⟨?_, ?_⟩
  · first | rfl | trivial
  unfold mergeEnabled
  cases hq : s.queue with
  | nil => rfl
  | cons h t =>
    have hhp : h ≠ p := by
      intro e
      subst e
      exact hp (hq ▸ List.mem_cons_self)
    simp [setB, hhp]

-- ── T6: a push dequeues ───────────────────────────────────────────────────

/-- **T6.** A push to a queued PR's head returns it to waiting and removes it
    from the queue: pushing to a queued PR is a dequeue, so re-runs and fixes
    to a PR that is not next cost the queue its entry. -/
theorem T6_push_dequeues {s : State} (p : Nat) (hp : s.loc p = .queued) :
    (step s (.push p)).loc p = .waiting ∧ p ∉ (step s (.push p)).queue := by
  simp only [step, hp, ↓reduceIte]
  exact ⟨by simp [upd], not_mem_without s.queue p⟩

end CiSpec
