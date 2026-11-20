/-
  The decision channel between a pod's proxy and the node (ADR 0014 §7,
  ADR 0015 §2, ADR 0017 §1): what a late answer means, before any code.

  Found 2026-11-19 (ADR 0017 local rehearsal): one node answer arrived about
  2.2 s after the proxy's 2 s deadline, and the proxy then refused every later
  request on that pod as `Poisoned`. One stall left a pod whose links and egress
  never carried anything again. The code treated a late answer as evidence of a
  broken peer. It is not: lateness is a property of one request, and the
  channel can stay in use as long as a late answer can never be read as the
  answer to a different request.

  The model:
    * the proxy numbers each request (`ask`); one is outstanding at a time;
    * each has a deadline; a request whose deadline passes is refused (fail
      closed, journalled `timeout`), and its number joins `owed`: the node owes
      an answer that will be dropped when it comes;
    * an answer is applied only to the outstanding request with its number;
    * an answer for an owed number is dropped, never applied to anything;
    * an answer for any other number, or a frame that does not parse, is
      evidence of a broken peer: the channel is poisoned, and the outstanding
      request (if any) is refused;
    * more than `cap` owed answers is also a broken peer (the node is not
      answering at all), and poisons.

  Each request's outcome is written once (`outcome` is write-once), so the
  theorems below are about the journal a reader of the receipts sees.
  Mathlib-free, like `LinkTable.lean`.
-/

namespace DecisionChannel

abbrev Seq := Nat
abbrev Time := Nat

inductive Outcome where
  /-- The node's answer, applied: `admit` is the verdict. -/
  | decided (admit : Bool)
  /-- The deadline passed; refused. The node's answer, if it comes, is dropped. -/
  | timeout
  /-- The peer broke the protocol while this request was outstanding; refused. -/
  | protocol
  deriving DecidableEq, Repr

structure State where
  now : Time
  /-- The next number to issue. -/
  next : Seq
  /-- The outstanding request and its deadline. -/
  current : Option (Seq × Time)
  /-- Numbers whose request timed out; their answers are owed and dropped. -/
  owed : List Seq
  poisoned : Bool
  /-- Each request's outcome, written once. -/
  outcome : Seq → Option Outcome
  /-- Requests refused without a number because the channel was poisoned. -/
  refusedPoisoned : Nat

/-- How many owed answers a channel tolerates before it is a broken peer. -/
def cap : Nat := 64

inductive Op where
  /-- A request asks, with `wait` time units before its deadline. -/
  | ask (wait : Time)
  | tick
  /-- The node answers number `s` with verdict `admit`. -/
  | answer (s : Seq) (admit : Bool)
  /-- A frame that does not parse, or is not a verdict. -/
  | malformed

def write (f : Seq → Option Outcome) (s : Seq) (o : Outcome) : Seq → Option Outcome :=
  fun t => if t = s then some o else f t

/-- What to do with an answer: the scalar decision the proxy extracts. -/
inductive Disposition where
  | apply
  | dropLate
  | poison
  deriving DecidableEq, Repr

def disposition (isCurrent isOwed : Bool) : Disposition :=
  if isCurrent then .apply else if isOwed then .dropLate else .poison

/-- Refuse the outstanding request (if any) as a protocol break, and poison. -/
def breakChannel (σ : State) : State :=
  match σ.current with
  | some (c, _) => { σ with poisoned := true, current := none, outcome := write σ.outcome c .protocol }
  | none => { σ with poisoned := true }

def step (σ : State) : Op → State
  | .ask wait =>
    if σ.poisoned then { σ with refusedPoisoned := σ.refusedPoisoned + 1 }
    else
      match σ.current with
      | some _ => σ  -- one at a time: the caller waits (modelled as no-op)
      | none => { σ with current := some (σ.next, σ.now + wait), next := σ.next + 1 }
  | .tick =>
    let σ' := { σ with now := σ.now + 1 }
    match σ.current with
    | some (c, dl) =>
      if σ'.now > dl then
        let σ'' := { σ' with current := none, owed := c :: σ.owed,
                             outcome := write σ.outcome c .timeout }
        if σ''.owed.length > cap then { σ'' with poisoned := true } else σ''
      else σ'
    | none => σ'
  | .answer s admit =>
    if σ.poisoned then σ
    else
      let isCurrent := match σ.current with | some (c, _) => c == s | none => false
      match disposition isCurrent (σ.owed.contains s) with
      | .apply => { σ with current := none, outcome := write σ.outcome s (.decided admit) }
      | .dropLate => { σ with owed := σ.owed.erase s }
      | .poison => breakChannel σ
  | .malformed => if σ.poisoned then σ else breakChannel σ

/-! ## The invariant: the outstanding request has no outcome yet -/

def Inv (σ : State) : Prop :=
  ∀ c dl, σ.current = some (c, dl) → σ.outcome c = none

theorem step_inv {σ : State} (op : Op) (h : Inv σ) (hfresh : ∀ t, t ≥ σ.next → σ.outcome t = none) :
    Inv (step σ op) := by
  have hn := hfresh σ.next (Nat.le_refl _)
  unfold Inv at h
  intro c dl hc
  cases op with
  | ask wait =>
    cases hp : σ.poisoned <;> cases hcur : σ.current <;> simp_all [step]
  | tick =>
    cases hcur : σ.current with
    | none => simp_all [step]
    | some p =>
      obtain ⟨c0, dl0⟩ := p
      simp only [step, hcur] at hc ⊢
      by_cases hl : σ.now + 1 > dl0
      · rw [if_pos hl] at hc ⊢
        by_cases hk : (c0 :: σ.owed).length > cap
        · rw [if_pos hk] at hc; simp at hc
        · rw [if_neg hk] at hc; simp at hc
      · rw [if_neg hl] at hc ⊢
        simp only [Option.some.injEq, Prod.mk.injEq] at hc
        obtain ⟨rfl, rfl⟩ := hc
        exact h c0 dl0 hcur
  | answer s admit =>
    cases hp : σ.poisoned
    · cases hcur : σ.current with
      | none =>
        cases hm : σ.owed.contains s <;> simp_all [step, disposition, breakChannel]
      | some p =>
        obtain ⟨c0, dl0⟩ := p
        by_cases e : c0 = s
        · subst e; simp_all [step, disposition]
        · cases hm : σ.owed.contains s <;> simp_all [step, disposition, breakChannel]
    · simp_all [step]
  | malformed =>
    cases hp : σ.poisoned
    · cases hcur : σ.current <;> simp_all [step, breakChannel]
    · simp_all [step]

/-! ## Write-once: an outcome, once in the journal, never changes -/

theorem write_keeps {f : Seq → Option Outcome} {s t : Seq} {o o' : Outcome}
    (hs : f s = none) (ht : f t = some o') : write f s o t = some o' := by
  simp only [write]
  by_cases e : t = s
  · subst e; rw [hs] at ht; cases ht
  · simp [e, ht]

theorem outcome_write_once {σ : State} (op : Op) (h : Inv σ) {t : Seq} {o : Outcome}
    (ht : σ.outcome t = some o) : (step σ op).outcome t = some o := by
  cases op with
  | ask wait =>
    simp only [step]; split
    · exact ht
    · split <;> exact ht
  | tick =>
    simp only [step]; split
    · rename_i c dl hc
      split
      · split <;> exact write_keeps (h c dl hc) ht
      · exact ht
    · exact ht
  | answer s admit =>
    unfold Inv at h
    cases hp : σ.poisoned
    · cases hcur : σ.current with
      | none =>
        by_cases hm : s ∈ σ.owed
        · simp [step, hp, hcur, disposition, hm]; exact ht
        · simp [step, hp, hcur, disposition, hm, breakChannel]; exact ht
      | some p =>
        obtain ⟨c0, dl0⟩ := p
        have hc0 := h c0 dl0 hcur
        by_cases e : c0 = s
        · subst e
          simp [step, hp, hcur, disposition]
          exact write_keeps hc0 ht
        · by_cases hm : s ∈ σ.owed
          · simp [step, hp, hcur, disposition, e, hm]; exact ht
          · simp [step, hp, hcur, disposition, e, hm, breakChannel]
            exact write_keeps hc0 ht
    · simp [step, hp]; exact ht
  | malformed =>
    simp only [step]; split
    · exact ht
    · simp only [breakChannel]; split
      · rename_i c dl hc; exact write_keeps (h c dl hc) ht
      · exact ht

/-! ## The theorems the ADRs cite -/

/-- An answer never admits any request but its own: the only outcome an
    answer step can add is for the number it carries. -/
theorem answer_admits_only_its_request (σ : State) (s : Seq) (admit admit' : Bool) (t : Seq)
    (hnew : σ.outcome t = none) (hset : (step σ (.answer s admit)).outcome t = some (.decided admit')) :
    t = s := by
  simp only [step] at hset
  split at hset
  · rw [hnew] at hset; cases hset
  · split at hset
    · simp only [write] at hset; by_cases e : t = s
      · exact e
      · simp [e, hnew] at hset
    · rw [hnew] at hset; cases hset
    · simp only [breakChannel] at hset; split at hset
      · simp only [write] at hset; split at hset <;> simp_all
      · rw [hnew] at hset; cases hset

/-- Fail closed: a request that timed out is never delivered, whatever arrives
    later, in every following state. -/
theorem late_answer_never_admits {σ : State} (op : Op) (h : Inv σ) {t : Seq}
    (ht : σ.outcome t = some .timeout) : (step σ op).outcome t = some .timeout :=
  outcome_write_once op h ht

/-- A late answer for an owed number is dropped: the channel is not poisoned and
    the outstanding request is untouched. -/
theorem late_answer_dropped (σ : State) (s : Seq) (admit : Bool)
    (hp : σ.poisoned = false) (howed : s ∈ σ.owed)
    (hnotcur : ∀ dl, σ.current ≠ some (s, dl)) :
    (step σ (.answer s admit)).poisoned = false ∧
      (step σ (.answer s admit)).current = σ.current ∧
      (step σ (.answer s admit)).outcome = σ.outcome := by
  cases hcs : σ.current with
  | none => simp [step, hp, hcs, disposition, howed]
  | some p =>
    obtain ⟨c, dl⟩ := p
    have e : c ≠ s := fun e => hnotcur dl (e ▸ hcs)
    simp [step, hp, hcs, disposition, howed, e]

/-- Recovery: after a timeout, a request asked on the unpoisoned channel and
    answered before its deadline is decided normally. -/
theorem channel_recovers_after_timeout (σ : State) (wait : Time) (admit : Bool)
    (hp : σ.poisoned = false) (hidle : σ.current = none) :
    let σ₁ := step σ (.ask wait)
    (step σ₁ (.answer σ.next admit)).outcome σ.next = some (.decided admit) := by
  simp [step, hp, hidle, disposition, write]

/-- An overdue request is resolved by the next tick: no request waits forever. -/
theorem tick_resolves_overdue (σ : State) (c dl : Nat) (hc : σ.current = some (c, dl))
    (hlate : σ.now + 1 > dl) : (step σ .tick).outcome c = some .timeout := by
  simp only [step, hc, hlate, if_true]
  split <;> simp [write]

/-- A broken peer still poisons: an answer with a number that is neither the
    outstanding request's nor owed. -/
theorem unissued_answer_poisons (σ : State) (s : Seq) (admit : Bool)
    (hp : σ.poisoned = false) (hnowed : s ∉ σ.owed)
    (hnotcur : ∀ dl, σ.current ≠ some (s, dl)) :
    (step σ (.answer s admit)).poisoned = true := by
  have hc : (match σ.current with | some (c, _) => c == s | none => false) = false := by
    cases hcs : σ.current with
    | none => rfl
    | some p =>
      obtain ⟨c, dl⟩ := p
      simp only [beq_eq_false_iff_ne, ne_eq]
      intro e; subst e; exact hnotcur dl hcs
  have hm : σ.owed.contains s = false := by simpa using hnowed
  simp only [step, hp, hc, hm, disposition, Bool.false_eq_true, if_false]
  simp only [breakChannel]; split <;> rfl

/-! ## Worked case: the rehearsal's stall, decided by the kernel -/

def fresh : State :=
  { now := 0, next := 0, current := none, owed := [], poisoned := false,
    outcome := fun _ => none, refusedPoisoned := 0 }

/-- Request 0 asks with 2 units; three ticks pass; it times out. Its late answer
    arrives and is dropped; request 1 asks and is answered in time. -/
def stalled : State :=
  let σ := step fresh (.ask 2)
  let σ := step σ .tick
  let σ := step σ .tick
  let σ := step σ .tick
  let σ := step σ (.answer 0 true)
  let σ := step σ (.ask 2)
  step σ (.answer 1 true)

example : stalled.outcome 0 = some .timeout := by decide
example : stalled.outcome 1 = some (.decided true) := by decide
example : stalled.poisoned = false := by decide
/-- The old behaviour, for contrast: a number never issued poisons. -/
example : (step fresh (.answer 7 true)).poisoned = true := by decide

end DecisionChannel
