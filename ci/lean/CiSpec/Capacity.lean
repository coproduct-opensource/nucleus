/-
  CiSpec / Capacity — when can the queue's check timeout eject an entry?

  **STATUS: PROVED (0 `sorry`).** Mathlib-free: `Nat` + `List` + `omega` +
  structural induction. Lean 4 v4.30.0-rc2, `autoImplicit = false`.

  On 2026-09-04 entries were ejected from the merge queue by the 60-minute
  check timeout — not by any red check. The group's jobs were sharing four
  or five build runners with every pull request's own runs, and the queue
  waited longer than it was willing to. This file states what the merge-only
  directive assumed: with build concurrency 1 and the whole pool to itself, a
  group whose work fits the pool finishes inside the budget.

  2026-09-09: build concurrency is 4, because the pool is now 38 warm machines
  and at concurrency 1 most of them idled while a group took 40 to 70 minutes.
  T7's hypothesis is then read against a group's SHARE of the pool rather than
  the pool (T12), which is sound exactly while each group's work fits its share
  — and the bite carries the numbers for the pool this queue actually has.

  # The model

  A pool of `q + 1` runners carries a *load* each (busy minutes already
  assigned). Placing a job of duration `d` on a runner whose load `x` is no
  more than the pool average (`(q+1) * x ≤ Σ loads`) is what "no runner idles
  while work waits" amounts to — a least-loaded runner always qualifies.
  `Sched` is every schedule built from such placements; `greedy` is the
  concrete one (first least-loaded runner), used by the bites via `decide`.

  # The theorem (Graham's list-scheduling bound, in `Nat`)

  For jobs of total work `W = Σ ds` and longest job `L`, every runner's final
  load `x` satisfies `(q+1) * x ≤ W + q * L`. So if `W + q * L ≤ (q+1) * T`,
  no job finishes after `T`: **T7**, no timeout ejection.

  # What is NOT proved (stated)

  * That `greedy` is an instance of `Sched` (it is — the first least-loaded
    runner is at most the average — but the argmin bookkeeping is not
    formalised here; the bites evaluate `greedy` on instances by `decide`).
  * `needs:` chains (a DAG). Jobs are independent; the critical path is a
    single job. With chains the same bound holds with `L` the longest chain
    (Graham 1966); the induction here is the independent-jobs core.
  * Competing runs. They appear as non-zero INITIAL loads; the bite shows
    how they break the bound the directive relied on.
-/

namespace CiSpec

/-- Schedules over `q + 1` runners: `Sched q ds l l'` places the jobs `ds`
    (in order) starting from loads `l`, ending at loads `l'`. Each placement
    chooses a runner no busier than the pool average. -/
inductive Sched (q : Nat) : List Nat → List Nat → List Nat → Prop
  | nil (l : List Nat) : Sched q [] l l
  | step (d x : Nat) (ds a b l' : List Nat)
      (hx : (q + 1) * x ≤ (a ++ x :: b).sum)
      (h : Sched q ds (a ++ (x + d) :: b) l') :
      Sched q (d :: ds) (a ++ x :: b) l'

theorem sched_sum {q : Nat} {ds l l' : List Nat} (h : Sched q ds l l') :
    l'.sum = l.sum + ds.sum := by
  induction h with
  | nil l => simp
  | step d x ds a b l' hx h ih =>
    rw [ih]
    simp [List.sum_append, List.sum_cons]
    omega

/-- The Graham invariant: every load is at most the average plus `q/(q+1)`
    of the longest job. Preserved by every average-or-better placement. -/
theorem sched_bound {q L : Nat} {ds l l' : List Nat} (h : Sched q ds l l')
    (hL : ∀ d, d ∈ ds → d ≤ L)
    (hinv : ∀ x, x ∈ l → (q + 1) * x ≤ l.sum + q * L) :
    ∀ x, x ∈ l' → (q + 1) * x ≤ l'.sum + q * L := by
  induction h with
  | nil l => exact hinv
  | step d x ds a b l' hx h ih =>
    apply ih
    · intro e he
      exact hL e (List.mem_cons_of_mem d he)
    · have hd : d ≤ L := hL d List.mem_cons_self
      have hqd : q * d ≤ q * L := Nat.mul_le_mul_left q hd
      have hsum : (a ++ (x + d) :: b).sum = (a ++ x :: b).sum + d := by
        rw [List.sum_append, List.sum_append, List.sum_cons, List.sum_cons]
        omega
      intro y hy
      rw [hsum]
      rw [List.mem_append, List.mem_cons] at hy
      rcases hy with hy | hy | hy
      · have := hinv y (by rw [List.mem_append]; exact Or.inl hy)
        omega
      · subst hy
        have e1 : (q + 1) * (x + d) = (q + 1) * x + (q * d + d) := by
          rw [Nat.mul_add, Nat.add_mul q 1 d, Nat.one_mul]
        omega
      · have := hinv y (by rw [List.mem_append, List.mem_cons]; exact Or.inr (Or.inr hy))
        omega

theorem sum_replicate_zero (n : Nat) : (List.replicate n 0).sum = 0 := by
  induction n with
  | zero => rfl
  | succ k ih => simp [List.replicate_succ, List.sum_cons, ih]

/-- **T7 (no timeout ejection).** `q + 1` idle runners, no competing runs,
    jobs `ds` of longest length `L` with `Σ ds + q * L ≤ (q + 1) * T`: every
    runner finishes by `T`. Under build concurrency 1 with the pool to
    itself, a group that fits the budget cannot be ejected by the timeout. -/
theorem T7_no_timeout_ejection {q T L : Nat} {ds l' : List Nat}
    (h : Sched q ds (List.replicate (q + 1) 0) l')
    (hL : ∀ d, d ∈ ds → d ≤ L)
    (hcap : ds.sum + q * L ≤ (q + 1) * T) :
    ∀ x, x ∈ l' → x ≤ T := by
  intro x hx
  have hb := sched_bound h hL (l := List.replicate (q + 1) 0) (by
    intro y hy
    rw [List.mem_replicate] at hy
    rw [hy.2]
    omega) x hx
  rw [sched_sum h, sum_replicate_zero] at hb
  have : (q + 1) * x ≤ (q + 1) * T := by omega
  exact Nat.le_of_mul_le_mul_left this (Nat.succ_pos q)

/-- **T12 (build concurrency divides the pool).** `c` groups building at once
    take a share each, and the shares fit: `(p / c) * c ≤ p`. So T7 applies to a
    group against `p / c` runners rather than `p`, and raising build concurrency
    is sound exactly while each group's work still fits its own share. The other
    groups are not "competing load" in the sense of `T7_with_competing_load`;
    they are a smaller pool, which is a weaker and truer statement. -/
theorem T12_shares_fit_the_pool (p c : Nat) : (p / c) * c ≤ p :=
  Nat.div_mul_le_self p c

/-- **T7 (with competitors).** The same bound with an initial load `C` on the
    pool: `(q+1) * x ≤ C + Σ ds + q * L`. The directive's "cancel every
    competing run" is the act of making `C = 0`. -/
theorem T7_with_competing_load {q L : Nat} {ds l l' : List Nat}
    (h : Sched q ds l l')
    (hL : ∀ d, d ∈ ds → d ≤ L)
    (hinv : ∀ x, x ∈ l → (q + 1) * x ≤ l.sum + q * L) :
    ∀ x, x ∈ l' → (q + 1) * x ≤ l.sum + ds.sum + q * L := by
  intro x hx
  have hb := sched_bound h hL hinv x hx
  rw [sched_sum h] at hb
  exact hb

-- ── The concrete scheduler, for the bites ────────────────────────────────

/-- The smallest load in the pool (0 for an empty pool). -/
def minOf : List Nat → Nat
  | [] => 0
  | x :: rest => rest.foldl Nat.min x

/-- Add `d` to the first runner whose load is `m`. -/
def addToFirst (m d : Nat) : List Nat → List Nat
  | [] => []
  | x :: rest => if x = m then (x + d) :: rest else x :: addToFirst m d rest

/-- Place one job on the first least-loaded runner. -/
def assignMin (l : List Nat) (d : Nat) : List Nat := addToFirst (minOf l) d l

/-- Greedy list scheduling from initial loads `l0`. -/
def greedyFrom (l0 : List Nat) (ds : List Nat) : List Nat := ds.foldl assignMin l0

/-- Greedy list scheduling on `p` idle runners. -/
def greedy (p : Nat) (ds : List Nat) : List Nat := greedyFrom (List.replicate p 0) ds

/-- When the last runner finishes. -/
def makespan (l : List Nat) : Nat := l.foldl Nat.max 0

-- ── Machine slots: the other capacity the queue depends on ───────────────
/-
  2026-09-09. The Fly Machine pool that replaced the hosted runners deadlocked
  with every machine warm and 44 jobs queued, and every start answered HTTP 422.
  Writing a boot's runner registration into a machine is an UPDATE, and the
  substrate satisfies an update by REPLACING the machine — which needs a free
  slot under the organization's machine cap. The pool held 27 of the
  organization's 99 machines against a cap of 100, so every update was refused,
  so no job was taken, so no machine ever stopped, so nothing freed a slot.

  This is a capacity budget of exactly T7's shape over a different resource:
  machines rather than minutes. What it adds to "count the machines" is the
  `inflight` term — the replacements the launches in a pass need AT THE SAME
  TIME — and that term is the whole content, because it is what makes a pool
  sized to the cap unable to start anything at all rather than merely full.

  These are decided over a declaration, not measured: nothing here knows how
  many machines the organization really has. The measurement is the substrate's
  own refusal (`Error::is_at_capacity` in crates/ci-fly-runner), which refutes
  the declaration and makes the pool give a machine back — the A-8 move, not
  this one.
-/

/-- The organization's machine ledger during one pass. -/
structure Slots where
  /-- The organization's machine cap. -/
  budget : Nat
  /-- Machines held by everything that is not this pool. -/
  elsewhere : Nat
  /-- Machines this pool holds. -/
  pooled : Nat
  /-- Launches in flight; each needs a replacement slot while it is in flight. -/
  inflight : Nat
deriving DecidableEq, Repr

/-- Machines needed at the PEAK of a pass: everything already running, a
    replacement for each launch in flight, and the manager itself. -/
def Slots.peak (s : Slots) : Nat := s.elsewhere + s.pooled + s.inflight + 1

/-- Whether a pass can be carried out at all. -/
def Slots.fits (s : Slots) : Bool := s.peak ≤ s.budget

/-- **T9 (a deployment that fits leaves room to launch).** Every launch in the
    pass has a slot for the replacement its update needs. -/
theorem T9_fits_leaves_room (s : Slots) (h : s.fits = true) :
    s.elsewhere + s.pooled + s.inflight + 1 ≤ s.budget := by
  simp [Slots.fits, Slots.peak] at h
  omega

/-- **T10 (at the cap, nothing starts).** A pool whose machines and neighbours
    already fill the budget cannot carry out a pass with any launch in it — and
    since a launch is the only thing that puts a job on a machine, and only a
    finished job stops one, nothing frees the slot either. This is the deadlock,
    and it is reachable from a configuration that merely looks full. -/
theorem T10_at_cap_cannot_launch (s : Slots)
    (hcap : s.budget ≤ s.elsewhere + s.pooled + 1) (hlaunch : 0 < s.inflight) :
    s.fits = false := by
  simp [Slots.fits, Slots.peak]
  omega

/-- **T11 (giving machines back restores it).** Shrinking the pool by at least
    the shortfall makes the pass fit again. This is what the manager does when
    the substrate refuses: one machine at a time until a pass fits. -/
theorem T11_shrink_restores_fit (s : Slots) (k : Nat)
    (hk : s.peak ≤ s.budget + k) (hle : k ≤ s.pooled) :
    ({ s with pooled := s.pooled - k } : Slots).fits = true := by
  simp [Slots.fits, Slots.peak] at *
  omega

end CiSpec
