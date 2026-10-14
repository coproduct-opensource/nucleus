/-
  Context-indexed, versioned memory — the M1 model (Program B).

  A memory space is an OBJECT with a linear, hash-chained history of versions. A run
  never inherits a process's powers over it: the node mints a fresh BINDING per run,
  carrying a view (scope × label ceiling), a pinned base version and an epoch. This
  file is the hand-written Lean model of the pure kernel in
  `crates/nucleus-memory-context`, and it proves:

    * restriction laws — identity, composition, through-an-intermediate, and that a
      restriction never widens the scope nor raises the ceiling; an observed entry
      is always the stored entry, so restriction never lowers a label;
    * version-stable observation — a pinned version's view is unchanged by every
      later commit;
    * assembly recovers each accepted local section (and keeps the base where no
      patch wrote);
    * whole-candidate validity — a `valid` verdict means no keyed conflict, no label
      lowered, and the global additive quota holds; with the 6 + 6 > 10 budget
      counterexample showing overlap agreement does NOT imply validity;
    * current-epoch admission — admitted iff the epoch is current and the binding is
      not expired; a revocation (epoch bump) refuses every older binding;
    * contextual noninterference by unwinding over the ops
      {bind, propose, publish, revoke}: another principal's bind / propose / publish
      never changes what a bound run observes.

  The unwinding conditions are stated directly, as in `PodCrossView.lean`:
  `UnwindingNoninterference.lean`'s `JoinOrder` class is a DAG-fold label order and
  does not fit a state machine over sections. As there, the view relation is
  UNTRUSTED: the "coarse relation fails" examples at the end show that a relation
  which ignores the epoch, or observes the head instead of the pinned version, or
  pins a version that does not yet exist, breaks an unwinding condition.

  WHAT THIS IS NOT. A hand-written model, not Aeneas output: the Rust crate's
  extracted slices are bound to its production functions by exhaustive Rust parity
  tests, and this file mirrors the same definitions by hand. The publish VERDICT is
  not part of the observation here (see the last example): the global quota is
  computed over the whole candidate, so a refusal can depend on content outside the
  publisher's view. That channel is named, not proved away.

  Mathlib-free (core `Nat`/`List`/`Option` only); every finite fact is closed by
  kernel `decide`, never `native_decide`; no proof holes.
-/

namespace MemoryContext

/-! ## 1. Views and restriction

Rust: `Scope(u8)` (a bitmask over `ScopeAtom`s, bits 1/2/4) and `LabelRank::rank`. -/

/-- A view: which scope atoms (namespaces / schema classes) a run may see, and the
    highest label rank it may see. -/
structure View where
  scope : Nat
  ceiling : Nat
deriving DecidableEq, Repr

/-- `s ⊆ t` as bitmasks. Rust: `extracted::view::scope_subset`. -/
def subsetB (s t : Nat) : Bool := (s &&& t) == s

/-- `n` is no wider than `v`: its scope is a subset and its ceiling is no higher. -/
def View.le (n v : View) : Bool := subsetB n.scope v.scope && decide (n.ceiling ≤ v.ceiling)

/-- Restriction only narrows: `narrower` is returned iff it is `≤ view`. Restriction is
    not authorization — it can only take away. Rust: `restrict`. -/
def restrict (view narrower : View) : Option View :=
  if narrower.le view then some narrower else none

theorem subsetB_refl (s : Nat) : subsetB s s = true := by
  simp [subsetB, Nat.and_self]

theorem subsetB_trans {s t u : Nat} (h1 : subsetB s t = true) (h2 : subsetB t u = true) :
    subsetB s u = true := by
  simp only [subsetB, beq_iff_eq] at *
  calc s &&& u = (s &&& t) &&& u := by rw [h1]
    _ = s &&& (t &&& u) := Nat.and_assoc s t u
    _ = s &&& t := by rw [h2]
    _ = s := h1

theorem View.le_refl (v : View) : v.le v = true := by
  simp [View.le, subsetB_refl]

theorem View.le_trans {n m v : View} (h1 : n.le m = true) (h2 : m.le v = true) :
    n.le v = true := by
  simp only [View.le, Bool.and_eq_true, decide_eq_true_eq] at *
  exact ⟨subsetB_trans h1.1 h2.1, Nat.le_trans h1.2 h2.2⟩

theorem restrict_eq_some {v n r : View} (h : restrict v n = some r) : n.le v = true ∧ r = n := by
  unfold restrict at h
  split at h
  · exact ⟨by assumption, (Option.some.inj h).symm⟩
  · cases h

/-- **Restriction identity.** -/
theorem restrict_identity (v : View) : restrict v v = some v := by
  simp [restrict, View.le_refl]

/-- **Restriction composition.** Two successive restrictions are one restriction. -/
theorem restrict_composition {v m n m' n' : View}
    (h1 : restrict v m = some m') (h2 : restrict m' n = some n') : restrict v n = some n' := by
  obtain ⟨hm, rfl⟩ := restrict_eq_some h1
  obtain ⟨hn, rfl⟩ := restrict_eq_some h2
  simp [restrict, View.le_trans hn hm]

/-- **Restricting through an intermediate equals restricting directly.** -/
theorem restrict_through_intermediate {v m n : View} (hm : m.le v = true) (hn : n.le m = true) :
    (restrict v m).bind (fun m' => restrict m' n) = restrict v n := by
  simp [restrict, hm, hn, View.le_trans hn hm]

/-- **Restriction never widens the scope nor raises the ceiling.** -/
theorem restrict_never_widens {v n r : View} (h : restrict v n = some r) :
    subsetB r.scope v.scope = true ∧ r.ceiling ≤ v.ceiling := by
  obtain ⟨hle, rfl⟩ := restrict_eq_some h
  simp only [View.le, Bool.and_eq_true, decide_eq_true_eq] at hle
  exact hle

/-- A wider request is refused, not clipped. -/
theorem restrict_refuses_wider {v n : View} (h : n.le v = false) : restrict v n = none := by
  simp [restrict, h]

-- Non-vacuity: a wider scope and a higher ceiling are each refused.
example : restrict ⟨1, 1⟩ ⟨3, 1⟩ = none := by decide
example : restrict ⟨3, 0⟩ ⟨3, 1⟩ = none := by decide
example : restrict ⟨7, 2⟩ ⟨5, 1⟩ = some ⟨5, 1⟩ := by decide

/-! ## 2. Sections and observation

Four keys, each in one namespace atom (Rust: `Key::atom`): `k0`, `k1` in atom 0
(bit 1), `k2` in atom 1 (bit 2), `k3` in atom 2 (bit 4). A section is a keyed map,
one optional entry per key — uniqueness of a key is a type, not a check. -/

/-- One stored entry: an opaque content id, its label rank, its quota units. -/
structure Entry where
  value : Nat
  label : Nat
  units : Nat
deriving DecidableEq, Repr

inductive Key
  | k0
  | k1
  | k2
  | k3
deriving DecidableEq, Repr

/-- The scope bit of the atom a key belongs to. Rust: `Key::atom().bit()`. -/
def Key.bit : Key → Nat
  | .k0 => 1
  | .k1 => 1
  | .k2 => 2
  | .k3 => 4

def allKeys : List Key := [.k0, .k1, .k2, .k3]

theorem mem_allKeys (k : Key) : k ∈ allKeys := by
  cases k <;> decide

structure Section where
  s0 : Option Entry
  s1 : Option Entry
  s2 : Option Entry
  s3 : Option Entry
deriving DecidableEq, Repr

def Section.empty : Section := ⟨none, none, none, none⟩

def Section.get (σ : Section) : Key → Option Entry
  | .k0 => σ.s0
  | .k1 => σ.s1
  | .k2 => σ.s2
  | .k3 => σ.s3

def Section.ofFn (f : Key → Option Entry) : Section := ⟨f .k0, f .k1, f .k2, f .k3⟩

@[simp] theorem Section.get_ofFn (f : Key → Option Entry) (k : Key) :
    (Section.ofFn f).get k = f k := by
  cases k <;> rfl

theorem Section.ext : ∀ {a b : Section}, (∀ k, a.get k = b.get k) → a = b
  | ⟨a0, a1, a2, a3⟩, ⟨b0, b1, b2, b3⟩, h => by
    have h0 : a0 = b0 := h .k0
    have h1 : a1 = b1 := h .k1
    have h2 : a2 = b2 := h .k2
    have h3 : a3 = b3 := h .k3
    subst h0 h1 h2 h3
    rfl

/-- May a run holding `v` see entry `e` under key `k`? Rust: `extracted::observe::slot_visible`. -/
def visible (v : View) (k : Key) (e : Entry) : Bool :=
  ((v.scope &&& k.bit) != 0) && decide (e.label ≤ v.ceiling)

def observeSlot (v : View) (k : Key) : Option Entry → Option Entry
  | none => none
  | some e => if visible v k e then some e else none

/-- What a view sees of a section: every visible entry, unchanged; nothing else. -/
def observe (σ : Section) (v : View) : Section :=
  Section.ofFn fun k => observeSlot v k (σ.get k)

/-- **Observation never alters an entry** — so restriction never lowers (or drops to
    a lower) label: anything seen is exactly what is stored, label included. -/
theorem observe_keeps_entries {σ : Section} {v : View} {k : Key} {e : Entry}
    (h : (observe σ v).get k = some e) : σ.get k = some e := by
  simp only [observe, Section.get_ofFn] at h
  generalize σ.get k = s at h ⊢
  cases s with
  | none => simp [observeSlot] at h
  | some e' =>
    simp only [observeSlot] at h
    split at h
    · exact h
    · cases h

theorem visible_mono {n v : View} {k : Key} {e : Entry} (hle : n.le v = true)
    (hv : visible n k e = true) : visible v k e = true := by
  simp only [View.le, subsetB, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hle
  simp only [visible, Bool.and_eq_true, bne_iff_ne, ne_eq, decide_eq_true_eq] at hv ⊢
  refine ⟨?_, Nat.le_trans hv.2 hle.2⟩
  intro h0
  apply hv.1
  rw [← hle.1, Nat.and_assoc, h0, Nat.and_zero]

/-- **Observing through a narrower view is restricting the observation.** -/
theorem observe_restrict {σ : Section} {v n : View} (hle : n.le v = true) :
    observe (observe σ v) n = observe σ n := by
  apply Section.ext
  intro k
  simp only [observe, Section.get_ofFn]
  generalize σ.get k = s
  cases s with
  | none => rfl
  | some e =>
    by_cases hn : visible n k e = true
    · have hv := visible_mono hle hn
      simp [observeSlot, hv, hn]
    · cases hv : visible v k e <;> simp [observeSlot, hv, hn]

theorem observe_of_restrict {σ : Section} {v n r : View} (h : restrict v n = some r) :
    observe (observe σ v) r = observe σ r := by
  obtain ⟨hle, rfl⟩ := restrict_eq_some h
  exact observe_restrict hle

/-! ## 3. Overlap and assembly -/

/-- Two optional entries agree where both are present. Rust: `extracted::overlap::slots_agree`. -/
def slotsAgree : Option Entry → Option Entry → Bool
  | some a, some b => decide (a = b)
  | _, _ => true

/-- Two local sections agree on their overlap. Rust: `compare_on_overlap` (`Agree`). -/
def compareOnOverlap (a b : Section) : Bool :=
  allKeys.all fun k => slotsAgree (a.get k) (b.get k)

/-- The per-key accumulator of an assembly. Rust: `extracted::assemble::FlatAcc`. -/
structure SlotAcc where
  slot : Option Entry
  touched : Bool
  conflict : Bool
deriving DecidableEq, Repr

/-- One patch's entry for one key. The first patch to write a key sets it; a later
    patch that writes a DIFFERENT entry marks the key conflicted (keyed conflicts are
    refused, never silently last-writer-wins). Rust: `extracted::assemble::step_slot`. -/
def stepSlot (a : SlotAcc) : Option Entry → SlotAcc
  | none => a
  | some e =>
    if a.touched then
      if decide (a.slot = some e) then a else { a with conflict := true }
    else { slot := some e, touched := true, conflict := a.conflict }

def assembleSlot (base : Option Entry) (ps : List (Option Entry)) : SlotAcc :=
  ps.foldl stepSlot ⟨base, false, false⟩

/-- A candidate: the base it was assembled over, the merged section, and which keys
    two patches disagreed on. Rust: `Candidate`. -/
structure Candidate where
  base : Section
  merged : Section
  conflicted : Key → Bool

/-- Rust: `assemble_candidate`. -/
def assemble (base : Section) (ps : List Section) : Candidate :=
  { base := base
    merged := Section.ofFn fun k => (assembleSlot (base.get k) (ps.map fun p => p.get k)).slot
    conflicted := fun k => (assembleSlot (base.get k) (ps.map fun p => p.get k)).conflict }

theorem stepSlot_conflict_mono (a : SlotAcc) (x : Option Entry)
    (h : (stepSlot a x).conflict = false) : a.conflict = false := by
  cases x with
  | none => exact h
  | some e =>
    simp only [stepSlot] at h
    by_cases ht : a.touched = true
    · by_cases hs : decide (a.slot = some e) = true
      · rw [if_pos ht, if_pos hs] at h
        exact h
      · rw [if_pos ht, if_neg hs] at h
        simp at h
    · rw [if_neg ht] at h
      exact h

theorem foldl_conflict_mono (xs : List (Option Entry)) :
    ∀ a : SlotAcc, (xs.foldl stepSlot a).conflict = false → a.conflict = false := by
  induction xs with
  | nil => intro a h; exact h
  | cons x xs ih =>
    intro a h
    exact stepSlot_conflict_mono a x (ih (stepSlot a x) h)

theorem stepSlot_keeps (a : SlotAcc) (e : Entry) (ht : a.touched = true) (hs : a.slot = some e)
    (x : Option Entry) (h : (stepSlot a x).conflict = false) :
    (stepSlot a x).touched = true ∧ (stepSlot a x).slot = some e := by
  cases x with
  | none => exact ⟨ht, hs⟩
  | some e' =>
    simp only [stepSlot] at h ⊢
    by_cases hs' : decide (a.slot = some e') = true
    · rw [if_pos ht, if_pos hs']
      exact ⟨ht, hs⟩
    · rw [if_pos ht, if_neg hs'] at h
      simp at h

theorem foldl_keeps (e : Entry) (xs : List (Option Entry)) :
    ∀ a : SlotAcc, a.touched = true → a.slot = some e →
      (xs.foldl stepSlot a).conflict = false → (xs.foldl stepSlot a).slot = some e := by
  induction xs with
  | nil => intro a _ hs _; exact hs
  | cons x xs ih =>
    intro a ht hs h
    have hstep : (stepSlot a x).conflict = false := foldl_conflict_mono xs (stepSlot a x) h
    obtain ⟨ht', hs'⟩ := stepSlot_keeps a e ht hs x hstep
    exact ih (stepSlot a x) ht' hs' h

theorem stepSlot_some (a : SlotAcc) (e : Entry) (h : (stepSlot a (some e)).conflict = false) :
    (stepSlot a (some e)).touched = true ∧ (stepSlot a (some e)).slot = some e := by
  simp only [stepSlot] at h ⊢
  by_cases ht : a.touched = true
  · by_cases hs : decide (a.slot = some e) = true
    · rw [if_pos ht, if_pos hs]
      exact ⟨ht, of_decide_eq_true hs⟩
    · rw [if_pos ht, if_neg hs] at h
      simp at h
  · rw [if_neg ht]
    exact ⟨rfl, rfl⟩

theorem foldl_recovers (e : Entry) (xs : List (Option Entry)) :
    ∀ a : SlotAcc, some e ∈ xs →
      (xs.foldl stepSlot a).conflict = false → (xs.foldl stepSlot a).slot = some e := by
  induction xs with
  | nil => intro a hm; cases hm
  | cons x xs ih =>
    intro a hm h
    rcases List.mem_cons.mp hm with hx | hx
    · subst hx
      have hstep : (stepSlot a (some e)).conflict = false :=
        foldl_conflict_mono xs (stepSlot a (some e)) h
      obtain ⟨ht, hs⟩ := stepSlot_some a e hstep
      exact foldl_keeps e xs (stepSlot a (some e)) ht hs h
    · exact ih (stepSlot a x) hx h

/-- **Assembly recovers each accepted local section.** Wherever a key is not
    conflicted, the merged candidate holds exactly what every patch that wrote that
    key wrote — gluing loses no accepted local section. -/
theorem assembly_recovers (base : Section) (ps : List Section) (p : Section) (hp : p ∈ ps)
    (k : Key) (e : Entry) (he : p.get k = some e)
    (hok : (assemble base ps).conflicted k = false) :
    (assemble base ps).merged.get k = some e := by
  simp only [assemble, assembleSlot, Section.get_ofFn] at hok ⊢
  exact foldl_recovers e _ _ (List.mem_map.mpr ⟨p, hp, he⟩) hok

theorem foldl_all_none (xs : List (Option Entry)) :
    ∀ a : SlotAcc, (∀ x ∈ xs, x = none) → xs.foldl stepSlot a = a := by
  induction xs with
  | nil => intro a _; rfl
  | cons x xs ih =>
    intro a h
    have hx : x = none := h x (List.mem_cons_self ..)
    subst hx
    exact ih a (fun y hy => h y (List.mem_cons_of_mem _ hy))

/-- **Assembly keeps the base where no patch wrote.** -/
theorem assembly_keeps_base (base : Section) (ps : List Section) (k : Key)
    (h : ∀ p ∈ ps, p.get k = none) :
    (assemble base ps).merged.get k = base.get k := by
  simp only [assemble, assembleSlot, Section.get_ofFn]
  rw [foldl_all_none]
  intro x hx
  obtain ⟨p, hp, rfl⟩ := List.mem_map.mp hx
  exact h p hp

/-- For two patches, a key is conflicted exactly when they disagree on it. -/
theorem two_patch_conflict (b x y : Option Entry) :
    (assembleSlot b [x, y]).conflict = !slotsAgree x y := by
  cases x with
  | none => cases y <;> simp [assembleSlot, stepSlot, slotsAgree]
  | some a =>
    cases y with
    | none => simp [assembleSlot, stepSlot, slotsAgree]
    | some c => by_cases h : a = c <;> simp [assembleSlot, stepSlot, slotsAgree, h]

/-! ## 4. Whole-candidate validation -/

/-- The verdict of `validate`, refusals by name. Rust: `CandidateRefusal` (+ `Ok`). -/
inductive Verdict
  | valid
  | keyConflict (k : Key)
  | entryDropped (k : Key)
  | labelLowered (k : Key)
  | quotaExceeded (total quota : Nat)
deriving DecidableEq, Repr

def slotUnits : Option Entry → Nat
  | none => 0
  | some e => e.units

/-- The global additive quota measure: every unit in the whole candidate. -/
def total (σ : Section) : Nat :=
  allKeys.foldl (fun acc k => acc + slotUnits (σ.get k)) 0

/-- The per-key check, in the Rust order: conflict, then dropped, then lowered.
    Rust: `extracted::validate::slot_check`. -/
def checkSlot (k : Key) (conflict : Bool) (b m : Option Entry) : Option Verdict :=
  if conflict then some (.keyConflict k)
  else
    match b, m with
    | some _, none => some (.entryDropped k)
    | some be, some me => if me.label < be.label then some (.labelLowered k) else none
    | none, _ => none

/-- Rust: `validate_candidate`. The first per-key refusal in key order, else the
    global quota over the WHOLE candidate. -/
def validate (c : Candidate) (quota : Nat) : Verdict :=
  match allKeys.findSome? (fun k => checkSlot k (c.conflicted k) (c.base.get k) (c.merged.get k)) with
  | some r => r
  | none => if total c.merged ≤ quota then .valid else .quotaExceeded (total c.merged) quota

theorem checkSlot_ne_valid (k : Key) (cf : Bool) (b m : Option Entry) :
    checkSlot k cf b m ≠ some .valid := by
  unfold checkSlot
  cases cf with
  | true => simp
  | false =>
    cases b with
    | none => simp
    | some be =>
      cases m with
      | none => simp
      | some me => by_cases h : me.label < be.label <;> simp [h]

theorem checkSlot_none {k : Key} {cf : Bool} {b m : Option Entry} (h : checkSlot k cf b m = none) :
    cf = false ∧ (∀ be, b = some be → ∃ me, m = some me ∧ be.label ≤ me.label) := by
  unfold checkSlot at h
  cases cf with
  | true => simp at h
  | false =>
    refine ⟨rfl, ?_⟩
    intro be hb
    subst hb
    cases m with
    | none => simp at h
    | some me =>
      by_cases hl : me.label < be.label
      · simp [hl] at h
      · exact ⟨me, rfl, by omega⟩

/-- **A valid candidate is valid as a whole**: no key conflicted, no stored label
    lowered or dropped, and the global quota holds. -/
theorem validate_valid {c : Candidate} {q : Nat} (h : validate c q = .valid) :
    (∀ k, c.conflicted k = false) ∧
    (∀ k be, c.base.get k = some be → ∃ me, c.merged.get k = some me ∧ be.label ≤ me.label) ∧
    total c.merged ≤ q := by
  unfold validate at h
  split at h
  · rename_i r hr
    subst h
    obtain ⟨k, -, hk⟩ := List.exists_of_findSome?_eq_some hr
    exact absurd hk (checkSlot_ne_valid _ _ _ _)
  · rename_i hn
    have hall := List.findSome?_eq_none_iff.mp hn
    refine ⟨fun k => (checkSlot_none (hall k (mem_allKeys k))).1,
            fun k => (checkSlot_none (hall k (mem_allKeys k))).2, ?_⟩
    by_cases hq : total c.merged ≤ q
    · exact hq
    · rw [if_neg hq] at h
      cases h

/-- A conflicted key is refused, whatever the quota. -/
theorem validate_refuses_conflict {c : Candidate} {q : Nat} {k : Key}
    (hk : c.conflicted k = true) : validate c q ≠ .valid := by
  intro h
  have := (validate_valid h).1 k
  rw [hk] at this
  cases this

/-! ### The budget counterexample: overlap agreement is not validity

Two patches on DISJOINT keys (so they agree on every overlap, vacuously) each
spend 6 units. Each alone is valid under a quota of 10; glued, they spend 12. A
validator that checks only overlap agreement would accept the gluing. -/

def e6 (v : Nat) : Entry := ⟨v, 0, 6⟩
def patchA : Section := { Section.empty with s0 := some (e6 1) }
def patchB : Section := { Section.empty with s2 := some (e6 2) }

example : compareOnOverlap patchA patchB = true := by decide
example : validate (assemble Section.empty [patchA]) 10 = .valid := by decide
example : validate (assemble Section.empty [patchB]) 10 = .valid := by decide
example : validate (assemble Section.empty [patchA, patchB]) 10 = .quotaExceeded 12 10 := by decide

/-- The coarse validator — "every pair of patches agrees on its overlap". -/
def overlapOnly : List Section → Bool
  | [] => true
  | p :: ps => ps.all (compareOnOverlap p) && overlapOnly ps

/-- **Coarse relation fails.** Overlap agreement accepts the budget case; whole-candidate
    validation refuses it. -/
example : overlapOnly [patchA, patchB] = true ∧
    validate (assemble Section.empty [patchA, patchB]) 10 ≠ .valid := by decide

-- A keyed conflict is refused by name, and so is a lowered label.
def patchA' : Section := { Section.empty with s0 := some (e6 9) }
example : validate (assemble Section.empty [patchA, patchA']) 100 = .keyConflict .k0 := by decide
def secretBase : Section := { Section.empty with s0 := some ⟨1, 2, 1⟩ }
def lowering : Section := { Section.empty with s0 := some ⟨1, 0, 1⟩ }
example : validate (assemble secretBase [lowering]) 100 = .labelLowered .k0 := by decide

/-! ## 5. Versions

Index 0 is the genesis version; the head is the last index. Rust: `History`. -/

abbrev History := List Section

def pinned (h : History) (n : Nat) : Section := h.getD n Section.empty

/-- Compare-and-swap commit: refused unless `expectedHead` IS the head. Rust: `History::commit`. -/
def commit (h : History) (expectedHead : Nat) (s : Section) : Option History :=
  if h.length = expectedHead + 1 then some (h ++ [s]) else none

theorem pinned_append (h later : History) (n : Nat) (hn : n < h.length) :
    pinned (h ++ later) n = pinned h n := by
  simp [pinned, List.getD_eq_getElem?_getD, List.getElem?_append_left hn]

/-- **Version-stable observation.** A view of a pinned version is unchanged by a
    later commit. -/
theorem version_stable {h h' : History} {e n : Nat} {s : Section} (hn : n < h.length)
    (hc : commit h e s = some h') (v : View) :
    observe (pinned h' n) v = observe (pinned h n) v := by
  unfold commit at hc
  split at hc
  · cases hc
    rw [pinned_append h [s] n hn]
  · cases hc

/-- … and by any number of later commits. -/
theorem version_stable_many (h later : History) (n : Nat) (hn : n < h.length) (v : View) :
    observe (pinned (h ++ later) n) v = observe (pinned h n) v := by
  rw [pinned_append h later n hn]

/-- A stale expected head is refused. -/
theorem commit_refuses_stale {h : History} {e : Nat} (s : Section) (hst : h.length ≠ e + 1) :
    commit h e s = none := by
  simp [commit, hst]

/-! ## 6. Admission -/

inductive Admission
  | admitted
  | foreignEpoch
  | expired
deriving DecidableEq, Repr

/-- Rust: `admit` / `extracted::admit::admit_code`. Epoch first, then expiry. -/
def admission (bindingEpoch notAfter currentEpoch now : Nat) : Admission :=
  if bindingEpoch ≠ currentEpoch then .foreignEpoch
  else if notAfter < now then .expired
  else .admitted

/-- **Current-epoch admission.** Admitted iff the epoch is current and not expired. -/
theorem admission_iff (be na ce now : Nat) :
    admission be na ce now = .admitted ↔ be = ce ∧ now ≤ na := by
  unfold admission
  by_cases h1 : be = ce
  · by_cases h2 : na < now
    · simp [h1, h2] <;> omega
    · simp [h1, h2] <;> omega
  · simp [h1]

/-- **Revocation refuses every older binding**, whatever its expiry. -/
theorem old_epoch_refused {be ce : Nat} (na now : Nat) (h : be < ce) :
    admission be na ce now = .foreignEpoch := by
  have : be ≠ ce := by omega
  simp [admission, this]

theorem revoke_refuses (be na now : Nat) : admission be na (be + 1) now = .foreignEpoch :=
  old_epoch_refused na now (Nat.lt_succ_self be)

/-! ## 7. Contextual noninterference, by unwinding

A node-wide state for one space: its history, the epoch, the per-principal binding
the node minted, and each binding's private branch (overlay). A run observes its
pinned version and its own branch, through its view, while its epoch is current. -/

structure Binding where
  view : View
  base : Nat
  epoch : Nat
deriving DecidableEq, Repr

structure State where
  history : History
  epoch : Nat
  bindings : Nat → Option Binding
  branches : Nat → Section

def update {α : Type} (f : Nat → α) (i : Nat) (x : α) : Nat → α :=
  fun j => if j = i then x else f j

inductive Op
  /-- The node mints a FRESH binding for principal `id` at the current epoch, pinned
      to an existing version, with an empty branch — never inherited. -/
  | bind (id : Nat) (view : View) (base : Nat)
  /-- `id` writes a patch to its own branch. -/
  | propose (id : Nat) (patch : Section)
  /-- `id` publishes its branch over `expectedHead`: assemble, validate, CAS commit. -/
  | publish (id : Nat) (expectedHead : Nat) (quota : Nat)
  /-- The tenant bumps the epoch. -/
  | revoke

def admittedAt (s : State) (id : Nat) : Option Binding :=
  match s.bindings id with
  | some b => if b.epoch = s.epoch then some b else none
  | none => none

def publishStep (s : State) (id expectedHead quota : Nat) : State :=
  let c := assemble (pinned s.history expectedHead) [s.branches id]
  if validate c quota = .valid then
    match commit s.history expectedHead c.merged with
    | some h' => { s with history := h' }
    | none => s
  else s

def step (s : State) : Op → State
  | .bind id v n =>
    if n < s.history.length then
      { s with bindings := update s.bindings id (some ⟨v, n, s.epoch⟩)
               branches := update s.branches id Section.empty }
    else s
  | .propose id p =>
    match admittedAt s id with
    | some _ => { s with branches := update s.branches id p }
    | none => s
  | .publish id e q =>
    match admittedAt s id with
    | some _ => publishStep s id e q
    | none => s
  | .revoke => { s with epoch := s.epoch + 1 }

def run (s : State) (ops : List Op) : State := ops.foldl step s

/-- What run `me` observes. -/
def obs (me : Nat) (s : State) : Option (Section × Section) :=
  match admittedAt s me with
  | some b => some (observe (pinned s.history b.base) b.view, observe (s.branches me) b.view)
  | none => none

/-- The context relation for `me` holding binding `b`. -/
def related (me : Nat) (b : Binding) (s t : State) : Prop :=
  s.bindings me = some b ∧ t.bindings me = some b ∧ s.epoch = t.epoch ∧
  b.base < s.history.length ∧ b.base < t.history.length ∧
  observe (pinned s.history b.base) b.view = observe (pinned t.history b.base) b.view ∧
  observe (s.branches me) b.view = observe (t.branches me) b.view

theorem related_symm {me : Nat} {b : Binding} {s t : State} (h : related me b s t) :
    related me b t s := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := h
  exact ⟨h2, h1, h3.symm, h5, h4, h6.symm, h7.symm⟩

theorem related_trans {me : Nat} {b : Binding} {s t u : State}
    (h : related me b s t) (h' : related me b t u) : related me b s u := by
  obtain ⟨h1, -, h3, h4, -, h6, h7⟩ := h
  obtain ⟨-, h2', h3', -, h5', h6', h7'⟩ := h'
  exact ⟨h1, h2', h3.trans h3', h4, h5', h6.trans h6', h7.trans h7'⟩

/-- **Output consistency (lower bound).** Related states give `me` the same observation. -/
theorem output_consistency {me : Nat} {b : Binding} {s t : State} (h : related me b s t) :
    obs me s = obs me t := by
  obtain ⟨hs, ht, he, -, -, hp, hbr⟩ := h
  have hs1 : admittedAt s me = (if b.epoch = t.epoch then some b else none) := by
    simp [admittedAt, hs, he]
  have ht1 : admittedAt t me = (if b.epoch = t.epoch then some b else none) := by
    simp [admittedAt, ht]
  by_cases hep : b.epoch = t.epoch
  · rw [if_pos hep] at hs1 ht1
    simp only [obs, hs1, ht1, hp, hbr]
  · rw [if_neg hep] at hs1 ht1
    simp only [obs, hs1, ht1]

/-- A step that changes nothing `me` depends on, and only extends the history, keeps
    the relation. -/
theorem related_extend {me : Nat} {b : Binding} {s t s' t' : State} (h : related me b s t)
    (hb : s'.bindings me = s.bindings me) (he : s'.epoch = s.epoch)
    (hbr : s'.branches me = s.branches me) (ls : List Section) (hh : s'.history = s.history ++ ls)
    (hb' : t'.bindings me = t.bindings me) (he' : t'.epoch = t.epoch)
    (hbr' : t'.branches me = t.branches me) (lt : List Section) (hh' : t'.history = t.history ++ lt) :
    related me b s' t' := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := h
  refine ⟨hb.trans h1, hb'.trans h2, by rw [he, he', h3], ?_, ?_, ?_, ?_⟩
  · rw [hh, List.length_append]; omega
  · rw [hh', List.length_append]; omega
  · rw [hh, hh', pinned_append _ _ _ h4, pinned_append _ _ _ h5, h6]
  · rw [hbr, hbr', h7]

/-- Every step only ever extends the history. -/
theorem publishStep_shape (s : State) (id e q : Nat) :
    ∃ ls, (publishStep s id e q).history = s.history ++ ls ∧
      (publishStep s id e q).epoch = s.epoch ∧
      (publishStep s id e q).bindings = s.bindings ∧
      (publishStep s id e q).branches = s.branches := by
  unfold publishStep
  simp only
  split
  · split
    · rename_i h' hc
      unfold commit at hc
      split at hc
      · cases hc
        exact ⟨_, rfl, rfl, rfl, rfl⟩
      · cases hc
    · exact ⟨[], by simp, rfl, rfl, rfl⟩
  · exact ⟨[], by simp, rfl, rfl, rfl⟩

theorem publish_shape (s : State) (id e q : Nat) :
    ∃ ls, (step s (.publish id e q)).history = s.history ++ ls ∧
      (step s (.publish id e q)).epoch = s.epoch ∧
      (step s (.publish id e q)).bindings = s.bindings ∧
      (step s (.publish id e q)).branches = s.branches := by
  simp only [step]
  split
  · exact publishStep_shape s id e q
  · exact ⟨[], by simp, rfl, rfl, rfl⟩

/-- Which ops the policy says must NOT reach `me`: another principal's bind / propose /
    publish. A revocation is the tenant's, and reaching every binding is its purpose. -/
def Op.isOthers (me : Nat) : Op → Bool
  | .bind id _ _ => id != me
  | .propose id _ => id != me
  | .publish id _ _ => id != me
  | .revoke => false

/-- Rebinding `me` starts a NEW run with a new context; the theorem is about one run. -/
def Op.rebinds (me : Nat) : Op → Bool
  | .bind id _ _ => id == me
  | _ => false

theorem update_ne {α : Type} (f : Nat → α) {i j : Nat} (x : α) (h : j ≠ i) : update f i x j = f j := by
  simp [update, h]

theorem update_eq {α : Type} (f : Nat → α) (i : Nat) (x : α) : update f i x i = x := by
  simp [update]

/-- **Local respect (upper bound).** Another principal's bind, propose or publish
    leaves `me`'s context unchanged. -/
theorem local_respect {me : Nat} {b : Binding} {s : State} (hw : related me b s s)
    (op : Op) (ho : op.isOthers me = true) : related me b s (step s op) := by
  cases op with
  | bind id v n =>
    have hne : me ≠ id := by
      intro heq; subst heq; simp [Op.isOthers] at ho
    simp only [step]
    split
    · exact related_extend hw rfl rfl rfl [] (by simp) (update_ne _ _ hne) rfl
        (update_ne _ _ hne) [] (by simp)
    · exact hw
  | propose id p =>
    have hne : me ≠ id := by
      intro heq; subst heq; simp [Op.isOthers] at ho
    simp only [step]
    split
    · exact related_extend hw rfl rfl rfl [] (by simp) rfl rfl (update_ne _ _ hne) [] (by simp)
    · exact hw
  | publish id e q =>
    obtain ⟨ls, hh, he, hb, hbr⟩ := publish_shape s id e q
    exact related_extend hw rfl rfl rfl [] (by simp) (by rw [hb]) he (by rw [hbr]) ls hh
  | revoke => simp [Op.isOthers] at ho

/-- **Step consistency.** `me`'s own propose and publish, and a revocation, keep
    related states related. -/
theorem step_consistency {me : Nat} {b : Binding} {s t : State} (h : related me b s t)
    (op : Op) (ho : op.isOthers me = false) (hr : op.rebinds me = false) :
    related me b (step s op) (step t op) := by
  cases op with
  | bind id v n =>
    have : id = me := by simpa [Op.isOthers] using ho
    subst this
    simp [Op.rebinds] at hr
  | propose id p =>
    have hid : id = me := by simpa [Op.isOthers] using ho
    subst hid
    -- `subst` kept the name `id` for the run under test.
    obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := h
    have hs1 : admittedAt s id = (if b.epoch = s.epoch then some b else none) := by
      simp [admittedAt, h1]
    have ht1 : admittedAt t id = (if b.epoch = t.epoch then some b else none) := by
      simp [admittedAt, h2]
    by_cases hep : b.epoch = s.epoch
    · have hep' : b.epoch = t.epoch := hep.trans h3
      have ha : admittedAt s id = some b := by rw [hs1, if_pos hep]
      have hb : admittedAt t id = some b := by rw [ht1, if_pos hep']
      simp only [step, ha, hb]
      exact ⟨h1, h2, h3, h4, h5, h6, by simp only [update_eq]⟩
    · have hep' : ¬ b.epoch = t.epoch := fun h' => hep (h'.trans h3.symm)
      have ha : admittedAt s id = none := by rw [hs1, if_neg hep]
      have hb : admittedAt t id = none := by rw [ht1, if_neg hep']
      simp only [step, ha, hb]
      exact ⟨h1, h2, h3, h4, h5, h6, h7⟩
  | publish id e q =>
    obtain ⟨ls, hh, he, hb, hbr⟩ := publish_shape s id e q
    obtain ⟨lt, hh', he', hb', hbr'⟩ := publish_shape t id e q
    exact related_extend h (by rw [hb]) he (by rw [hbr]) ls hh (by rw [hb']) he' (by rw [hbr']) lt hh'
  | revoke =>
    exact related_extend h rfl rfl rfl [] (by simp) rfl rfl rfl [] (by simp) |> fun r => by
      obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := r
      exact ⟨h1, h2, by simp [step, h3], h4, h5, h6, h7⟩

/-- Remove every op that the policy says must not reach `me`. -/
def purge (me : Nat) (ops : List Op) : List Op := ops.filter fun o => !o.isOthers me

/-- **The unwinding theorem.** From related states, running a trace on one side and
    its purge on the other keeps them related. -/
theorem unwinding {me : Nat} {b : Binding} :
    ∀ (ops : List Op) (s t : State), related me b s t →
      (∀ o ∈ ops, o.rebinds me = false) →
      related me b (run s ops) (run t (purge me ops)) := by
  intro ops
  induction ops with
  | nil => intro s t h _; exact h
  | cons o os ih =>
    intro s t h hr
    have hr' : ∀ o' ∈ os, o'.rebinds me = false := fun o' hm => hr o' (List.mem_cons_of_mem _ hm)
    by_cases ho : o.isOthers me = true
    · have hpurge : purge me (o :: os) = purge me os := by
        simp [purge, ho]
      rw [hpurge]
      have hss : related me b s s := related_trans h (related_symm h)
      have hstep : related me b (step s o) t :=
        related_trans (related_symm (local_respect hss o ho)) h
      exact ih (step s o) t hstep hr'
    · have ho' : o.isOthers me = false := by simpa using ho
      have hpurge : purge me (o :: os) = o :: purge me os := by
        simp [purge, ho']
      rw [hpurge]
      exact ih (step s o) (step t o)
        (step_consistency h o ho' (hr o (List.mem_cons_self ..))) hr'

/-- **Contextual noninterference.** For a run `me` bound with `b`, every trace that
    does not rebind `me` gives the SAME observation as the trace with every other
    principal's bind, propose and publish deleted. Siblings never see each other's
    branches, a later publish never moves a pinned view, and a binding minted for
    someone else reaches nothing of `me`'s. -/
theorem contextual_noninterference {me : Nat} {b : Binding} {s : State}
    (hw : related me b s s) (ops : List Op) (hr : ∀ o ∈ ops, o.rebinds me = false) :
    obs me (run s ops) = obs me (run s (purge me ops)) :=
  output_consistency (unwinding ops s s hw hr)

/-! ## 8. Non-vacuity and the coarse-relation-fails guardrails

Run 1 is bound to version 0 with a view of atom 0 at ceiling 1. Run 2 is a sibling. -/

def v1 : View := ⟨1, 1⟩
def genesis : Section := { Section.empty with s0 := some ⟨10, 0, 1⟩ }
def sibPatch : Section := { Section.empty with s1 := some ⟨20, 0, 1⟩ }

def st0 : State :=
  { history := [genesis]
    epoch := 0
    bindings := fun i => if i = 1 then some ⟨v1, 0, 0⟩ else if i = 2 then some ⟨v1, 0, 0⟩ else none
    branches := fun i => if i = 2 then sibPatch else Section.empty }

-- Run 1's own propose DOES change its observation: the relation is not the constant.
example : obs 1 (step st0 (.propose 1 sibPatch)) ≠ obs 1 st0 := by decide
-- A revocation DOES reach run 1 (the declared interferer): it is refused afterwards.
example : obs 1 (step st0 .revoke) = none ∧ obs 1 st0 ≠ none := by decide
-- The sibling's branch is invisible to run 1, though both are in view and in scope…
example : obs 1 st0 = some (observe genesis v1, Section.empty) := by decide
-- … and the sibling's publish lands a new head without moving run 1's pinned view.
example : (step st0 (.publish 2 0 10)).history.length = 2 ∧
    obs 1 (step st0 (.publish 2 0 10)) = obs 1 st0 := by decide

/-- **Coarse relation fails (1): ignore the epoch.** Two states that agree on
    everything but the epoch give run 1 different observations, so a relation without
    `s.epoch = t.epoch` breaks output consistency. -/
example : obs 1 st0 ≠ obs 1 { st0 with epoch := 1 } := by decide

/-- The observation a relation that ignores the VERSION would induce: the head, not
    the pinned base. -/
def obsHead (me : Nat) (s : State) : Option Section :=
  match admittedAt s me with
  | some b => some (observe (pinned s.history (s.history.length - 1)) b.view)
  | none => none

/-- **Coarse relation fails (2): ignore the version.** The sibling's publish moves the
    head-view, so local respect fails for it. -/
example : obsHead 1 (step st0 (.publish 2 0 10)) ≠ obsHead 1 st0 := by decide

/-- **Coarse relation fails (3): pin a version that does not exist yet.** Without the
    `base < length` guard `bind` enforces, a "pinned" view sees the next commit. -/
example : pinned ([genesis] ++ [sibPatch]) 1 ≠ pinned [genesis] 1 := by decide

/-- **Named channel, NOT covered: the publish verdict.** Two states that run 1 cannot
    tell apart (same pinned view, same branch) — they differ only in an entry under
    atom 2, outside its scope — yet run 1's identical publish is accepted in one and
    refused in the other, because the global quota counts the hidden entry. `obs`
    does not include the verdict; the M5 oracle must treat it as a declared channel. -/
def hiddenHeavy : Section := { genesis with s3 := some ⟨30, 0, 9⟩ }
def stHidden : State := { st0 with history := [hiddenHeavy] }
def myPatch : Section := { Section.empty with s1 := some ⟨40, 0, 1⟩ }

example : obs 1 (step st0 (.propose 1 myPatch)) = obs 1 (step stHidden (.propose 1 myPatch)) ∧
    (run st0 [.propose 1 myPatch, .publish 1 0 10]).history.length = 2 ∧
    (run stHidden [.propose 1 myPatch, .publish 1 0 10]).history.length = 1 := by decide

end MemoryContext
