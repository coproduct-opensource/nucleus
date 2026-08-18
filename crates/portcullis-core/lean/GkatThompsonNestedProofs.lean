import GkatNestedClosureProofs

/-!
# Thompson automata satisfy the nesting coequation — the last leaf

`GkatNestedClosureProofs` packaged the sum route's nestedness down to one hypothesis:
`Nested V (Thompson e)`.  This file proves it, by structural induction over the certified
Thompson construction, closing the chain

    Nested (Thompson e)  →  Nested (sum)  →  Nested (start-merged quotient)

into theorems end to end.  The 274,461-sample "nested: 100%" measurement is now a corollary.

The induction has one shape, used three times.  Each composite constructor conjoins the
component halt guards with a COMMON FACTOR and guards its cross-edges so they die exactly when
that factor does:

  * `seqInitialized`: left halts become `hlt ∧ right.initHlt`; the only cross-edges go left to
    right and never return, so mutually-reachable pairs live in one component.
  * `iteInitialized`: components do not touch at all.
  * `loopInitialized`: body halts become `hlt ∧ ¬g`, and the new back-edges carry `∧ g ∧`.

In every case a complementary halt pair FORCES the common factor to be true at every atom —
at any atom where it fails, both conjoined halts are false and `false = !false` refutes the
complementarity outright.  With the factor everywhere true, halts and steps coincide with the
component's, mutual reachability transfers, and the induction hypothesis finishes.  The `wh`
case is the pretty one: complementarity forces `¬g` everywhere true, which kills every
back-edge, so the loop's new cycles are unreachable under the very valuation that could have
exploited them.
-/

namespace GkatThompsonNested

open GkatSyntax GkatGS GkatKleene GkatThompson GkatNestedClosure GkatSumQuotient

variable {A T S S₁ S₂ Atom : Type}

/-! ## Generic facts about `toGAut` -/

/-- `autStep` on a proper state is the core's `firstMatch`, targets injected by `some`. -/
theorem autStep_toGAut_some (aut : InitializedGAut S A T)
    (V : T → Atom → Bool) (s : S) (a : Atom) :
    autStep V aut.toGAut (some s) a =
      (firstMatch V a (aut.core.trans s)).map (fun y => (y.1, some y.2)) := by
  show firstMatch V a ((aut.core.trans s).map (fun t => (t.1, t.2.1, some t.2.2))) = _
  exact firstMatch_map_target_to V a some (aut.core.trans s)

/-- No step of a `toGAut` targets the pseudostate. -/
theorem step_target_some {aut : InitializedGAut S A T} {V : T → Atom → Bool}
    {t u : Option S} (h : AutStep1 V aut.toGAut t u) : ∃ w, u = some w := by
  obtain ⟨a, q, hq⟩ := h
  cases t with
  | none =>
      have : firstMatch V a (aut.initTrans.map (fun tr => (tr.1, tr.2.1, some tr.2.2)))
          = some (q, u) := hq
      rw [firstMatch_map_target_to] at this
      cases hf : firstMatch V a aut.initTrans with
      | none => rw [hf] at this; exact absurd this (by simp)
      | some y =>
          rw [hf] at this
          simp only [Option.map_some] at this
          injection this with h1
          injection h1 with _ h2
          exact ⟨y.2, h2.symm⟩
  | some s =>
      have := hq
      rw [autStep_toGAut_some] at this
      cases hf : firstMatch V a (aut.core.trans s) with
      | none => rw [hf] at this; exact absurd this (by simp)
      | some y =>
          rw [hf] at this
          simp only [Option.map_some] at this
          injection this with h1
          injection h1 with _ h2
          exact ⟨y.2, h2.symm⟩

/-- Reaching the pseudostate means never having left it. -/
theorem reaches_to_none {aut : InitializedGAut S A T} {V : T → Atom → Bool}
    {t : Option S} (h : AutReaches V aut.toGAut t none) : t = none := by
  cases h with
  | refl => rfl
  | tail _ hstep => obtain ⟨w, hw⟩ := step_target_some hstep; exact absurd hw (by simp)

/-- In a mutually-reachable pair of a `toGAut`, both states are proper. -/
theorem mutual_some {aut : InitializedGAut S A T} {V : T → Atom → Bool}
    {s1 s2 : Option S}
    (h12 : AutReaches1 V aut.toGAut s1 s2) (h21 : AutReaches1 V aut.toGAut s2 s1) :
    (∃ w1, s1 = some w1) ∧ ∃ w2, s2 = some w2 := by
  constructor
  · cases s1 with
    | some w => exact ⟨w, rfl⟩
    | none =>
        obtain ⟨m, hstep, hreach⟩ := h21
        have hm := reaches_to_none hreach
        subst hm
        obtain ⟨w, hw⟩ := step_target_some hstep
        exact absurd hw (by simp)
  · cases s2 with
    | some w => exact ⟨w, rfl⟩
    | none =>
        obtain ⟨m, hstep, hreach⟩ := h12
        have hm := reaches_to_none hreach
        subst hm
        obtain ⟨w, hw⟩ := step_target_some hstep
        exact absurd hw (by simp)

/-! ## Step characterisations for the three composites -/

section Seq

variable {left : InitializedGAut S₁ A T} {right : InitializedGAut S₂ A T}
variable {V : T → Atom → Bool}

/-- A step of the sequence from a left state landing in the left component reflects. -/
theorem seq_step_inl {s u : S₁} {a : Atom} {q : A}
    (h : autStep V (seqInitialized left right).toGAut (some (Sum.inl s)) a
      = some (q, some (Sum.inl u))) :
    autStep V left.toGAut (some s) a = some (q, some u) := by
  rw [autStep_toGAut_some] at h
  rw [autStep_toGAut_some]
  have hcore : (seqInitialized left right).core.trans (Sum.inl s) =
      (left.core.trans s).map (fun tr => (tr.1, tr.2.1, Sum.inl tr.2.2)) ++
      right.initTrans.map (fun tr =>
        (BExp.and (left.core.hlt s) tr.1, tr.2.1, Sum.inr tr.2.2)) := rfl
  rw [hcore] at h
  cases hf : firstMatch V a (left.core.trans s) with
  | some y =>
      have h1 : firstMatch V a ((left.core.trans s).map
          (fun tr => (tr.1, tr.2.1, Sum.inl tr.2.2)))
          = some (y.1, (Sum.inl y.2 : Sum S₁ S₂)) := by
        rw [firstMatch_map_target_to, hf]; rfl
      rw [firstMatch_append_some V a _ _ h1] at h
      injection h with h2
      injection h2 with hq hu
      injection hu with hu2
      injection hu2 with hu3
      simp only [Option.map_some]
      rw [hq, hu3]
  | none =>
      have h1 : firstMatch V a ((left.core.trans s).map
          (fun tr => (tr.1, tr.2.1, Sum.inl tr.2.2)))
          = (none : Option (A × Sum S₁ S₂)) := by
        rw [firstMatch_map_target_to, hf]; rfl
      rw [firstMatch_append_none V a _ _ h1] at h
      have hsplit : (right.initTrans.map (fun tr =>
            (BExp.and (left.core.hlt s) tr.1, tr.2.1, Sum.inr tr.2.2)))
          = ((right.initTrans.map (fun tr => (BExp.and (left.core.hlt s) tr.1, tr.2))).map
              (fun t => (t.1, t.2.1, (Sum.inr t.2.2 : Sum S₁ S₂)))) := by
        rw [List.map_map]; rfl
      rw [hsplit, firstMatch_map_target_to] at h
      cases hg : firstMatch V a (right.initTrans.map
          (fun tr => (BExp.and (left.core.hlt s) tr.1, tr.2))) with
      | none => rw [hg] at h; exact absurd h (by simp)
      | some y =>
          rw [hg] at h
          simp only [Option.map_some] at h
          injection h with h2
          injection h2 with _ hu
          injection hu with hu2
          exact absurd hu2 (by simp)

/-- A step of the sequence from a right state stays right and reflects. -/
theorem seq_step_inr {b : S₂} {a : Atom} {t : Option (Sum S₁ S₂)} {q : A}
    (h : autStep V (seqInitialized left right).toGAut (some (Sum.inr b)) a = some (q, t)) :
    ∃ c, t = some (Sum.inr c) ∧ autStep V right.toGAut (some b) a = some (q, some c) := by
  rw [autStep_toGAut_some] at h
  have hcore : (seqInitialized left right).core.trans (Sum.inr b) =
      (right.core.trans b).map (fun tr => (tr.1, tr.2.1, Sum.inr tr.2.2)) := rfl
  rw [hcore, firstMatch_map_target_to] at h
  cases hf : firstMatch V a (right.core.trans b) with
  | none => rw [hf] at h; exact absurd h (by simp)
  | some y =>
      rw [hf] at h
      simp only [Option.map_some] at h
      injection h with h1
      injection h1 with hq ht
      refine ⟨y.2, ht.symm, ?_⟩
      rw [autStep_toGAut_some, hf]
      simp only [Option.map_some]
      rw [hq]

/-- Right states never reach back into the left component. -/
theorem seq_no_inr_to_inl {b : S₂} {t : Option (Sum S₁ S₂)}
    (h : AutReaches V (seqInitialized left right).toGAut (some (Sum.inr b)) t) :
    ∀ x : S₁, t = some (Sum.inl x) → False := by
  induction h with
  | refl => intro x hx; injection hx with hx2; exact absurd hx2 (by simp)
  | tail hr hstep ih =>
      intro x hx
      subst hx
      obtain ⟨a, q, hq⟩ := hstep
      rename_i m
      cases m with
      | none =>
          have := reaches_to_none hr
          exact absurd this (by simp)
      | some w =>
          cases w with
          | inl w1 => exact ih w1 rfl
          | inr w2 =>
              obtain ⟨c, hc, -⟩ := seq_step_inr hq
              injection hc with hc2
              exact absurd hc2 (by simp)

/-- Left-to-left reachability in the sequence reflects to the left automaton. -/
theorem seq_reaches_inl {t₀ t : Option (Sum S₁ S₂)}
    (h : AutReaches V (seqInitialized left right).toGAut t₀ t) :
    ∀ x y : S₁, t₀ = some (Sum.inl x) → t = some (Sum.inl y) →
      AutReaches V left.toGAut (some x) (some y) := by
  induction h with
  | refl =>
      intro x y hx hy
      rw [hx] at hy
      injection hy with h1
      injection h1 with h2
      rw [h2]
      exact AutReaches.refl _
  | tail hr hstep ih =>
      intro x y hx hy
      subst hx hy
      obtain ⟨a, q, hq⟩ := hstep
      rename_i m
      cases m with
      | none =>
          have := reaches_to_none hr
          exact absurd this (by simp)
      | some w =>
          cases w with
          | inr w2 =>
              obtain ⟨c, hc, -⟩ := seq_step_inr hq
              injection hc with hc2
              exact absurd hc2 (by simp)
          | inl w1 =>
              have hstep' := seq_step_inl hq
              exact AutReaches.tail (ih x w1 rfl rfl) ⟨a, q, hstep'⟩

/-- Right-to-right reachability in the sequence reflects to the right automaton. -/
theorem seq_reaches_inr {t₀ t : Option (Sum S₁ S₂)}
    (h : AutReaches V (seqInitialized left right).toGAut t₀ t) :
    ∀ x y : S₂, t₀ = some (Sum.inr x) → t = some (Sum.inr y) →
      AutReaches V right.toGAut (some x) (some y) := by
  induction h with
  | refl =>
      intro x y hx hy
      rw [hx] at hy
      injection hy with h1
      injection h1 with h2
      rw [h2]
      exact AutReaches.refl _
  | tail hr hstep ih =>
      intro x y hx hy
      subst hx hy
      obtain ⟨a, q, hq⟩ := hstep
      rename_i m
      cases m with
      | none =>
          have := reaches_to_none hr
          exact absurd this (by simp)
      | some w =>
          cases w with
          | inl w1 => exact (seq_no_inr_to_inl hr w1 rfl).elim
          | inr w2 =>
              obtain ⟨c, hc, hstep'⟩ := seq_step_inr hq
              injection hc with hc2
              injection hc2 with hc3
              rw [hc3]
              exact AutReaches.tail (ih x w2 rfl rfl) ⟨a, q, hstep'⟩

end Seq

/-! ## The `ite` composite: components never touch -/

section Ite

variable {left : InitializedGAut S₁ A T} {right : InitializedGAut S₂ A T}
variable {g : BExp T} {V : T → Atom → Bool}

theorem ite_step_inl {s : S₁} {a : Atom} {t : Option (Sum S₁ S₂)} {q : A}
    (h : autStep V (iteInitialized g left right).toGAut (some (Sum.inl s)) a = some (q, t)) :
    ∃ u, t = some (Sum.inl u) ∧ autStep V left.toGAut (some s) a = some (q, some u) := by
  rw [autStep_toGAut_some] at h
  have hcore : (iteInitialized g left right).core.trans (Sum.inl s) =
      (left.core.trans s).map (fun tr => (tr.1, tr.2.1, Sum.inl tr.2.2)) := rfl
  rw [hcore, firstMatch_map_target_to] at h
  cases hf : firstMatch V a (left.core.trans s) with
  | none => rw [hf] at h; exact absurd h (by simp)
  | some y =>
      rw [hf] at h
      simp only [Option.map_some] at h
      injection h with h1
      injection h1 with hq ht
      refine ⟨y.2, ht.symm, ?_⟩
      rw [autStep_toGAut_some, hf]
      simp only [Option.map_some]
      rw [hq]

theorem ite_step_inr {s : S₂} {a : Atom} {t : Option (Sum S₁ S₂)} {q : A}
    (h : autStep V (iteInitialized g left right).toGAut (some (Sum.inr s)) a = some (q, t)) :
    ∃ u, t = some (Sum.inr u) ∧ autStep V right.toGAut (some s) a = some (q, some u) := by
  rw [autStep_toGAut_some] at h
  have hcore : (iteInitialized g left right).core.trans (Sum.inr s) =
      (right.core.trans s).map (fun tr => (tr.1, tr.2.1, Sum.inr tr.2.2)) := rfl
  rw [hcore, firstMatch_map_target_to] at h
  cases hf : firstMatch V a (right.core.trans s) with
  | none => rw [hf] at h; exact absurd h (by simp)
  | some y =>
      rw [hf] at h
      simp only [Option.map_some] at h
      injection h with h1
      injection h1 with hq ht
      refine ⟨y.2, ht.symm, ?_⟩
      rw [autStep_toGAut_some, hf]
      simp only [Option.map_some]
      rw [hq]

theorem ite_reaches_inl {t₀ t : Option (Sum S₁ S₂)}
    (h : AutReaches V (iteInitialized g left right).toGAut t₀ t) :
    ∀ x y : S₁, t₀ = some (Sum.inl x) → t = some (Sum.inl y) →
      AutReaches V left.toGAut (some x) (some y) := by
  induction h with
  | refl =>
      intro x y hx hy
      rw [hx] at hy
      injection hy with h1
      injection h1 with h2
      rw [h2]
      exact AutReaches.refl _
  | tail hr hstep ih =>
      intro x y hx hy
      subst hx hy
      obtain ⟨a, q, hq⟩ := hstep
      rename_i m
      cases m with
      | none =>
          have := reaches_to_none hr
          exact absurd this (by simp)
      | some w =>
          cases w with
          | inr w2 =>
              obtain ⟨c, hc, -⟩ := ite_step_inr hq
              injection hc with hc2
              exact absurd hc2 (by simp)
          | inl w1 =>
              obtain ⟨c, hc, hstep'⟩ := ite_step_inl hq
              injection hc with hc2
              injection hc2 with hc3
              rw [hc3]
              exact AutReaches.tail (ih x w1 rfl rfl) ⟨a, q, hstep'⟩

theorem ite_reaches_inr {t₀ t : Option (Sum S₁ S₂)}
    (h : AutReaches V (iteInitialized g left right).toGAut t₀ t) :
    ∀ x y : S₂, t₀ = some (Sum.inr x) → t = some (Sum.inr y) →
      AutReaches V right.toGAut (some x) (some y) := by
  induction h with
  | refl =>
      intro x y hx hy
      rw [hx] at hy
      injection hy with h1
      injection h1 with h2
      rw [h2]
      exact AutReaches.refl _
  | tail hr hstep ih =>
      intro x y hx hy
      subst hx hy
      obtain ⟨a, q, hq⟩ := hstep
      rename_i m
      cases m with
      | none =>
          have := reaches_to_none hr
          exact absurd this (by simp)
      | some w =>
          cases w with
          | inl w1 =>
              obtain ⟨c, hc, -⟩ := ite_step_inl hq
              injection hc with hc2
              exact absurd hc2 (by simp)
          | inr w2 =>
              obtain ⟨c, hc, hstep'⟩ := ite_step_inr hq
              injection hc with hc2
              injection hc2 with hc3
              rw [hc3]
              exact AutReaches.tail (ih x w2 rfl rfl) ⟨a, q, hstep'⟩

/-- Left states never reach the right component in an `ite`. -/
theorem ite_no_inl_to_inr {t₀ t : Option (Sum S₁ S₂)}
    (h : AutReaches V (iteInitialized g left right).toGAut t₀ t) :
    ∀ (x : S₁) (b : S₂), t₀ = some (Sum.inl x) → t = some (Sum.inr b) → False := by
  induction h with
  | refl =>
      intro x b hx hy
      rw [hx] at hy
      injection hy with h1
      exact absurd h1 (by simp)
  | tail hr hstep ih =>
      intro x b hx hy
      subst hx hy
      obtain ⟨a, q, hq⟩ := hstep
      rename_i m
      cases m with
      | none =>
          have := reaches_to_none hr
          exact absurd this (by simp)
      | some w =>
          cases w with
          | inl w1 =>
              obtain ⟨c, hc, -⟩ := ite_step_inl hq
              injection hc with hc2
              exact absurd hc2 (by simp)
          | inr w2 => exact ih x w2 rfl rfl

/-- Right states never reach the left component in an `ite`. -/
theorem ite_no_inr_to_inl {t₀ t : Option (Sum S₁ S₂)}
    (h : AutReaches V (iteInitialized g left right).toGAut t₀ t) :
    ∀ (b : S₂) (x : S₁), t₀ = some (Sum.inr b) → t = some (Sum.inl x) → False := by
  induction h with
  | refl =>
      intro b x hx hy
      rw [hx] at hy
      injection hy with h1
      exact absurd h1 (by simp)
  | tail hr hstep ih =>
      intro b x hx hy
      subst hx hy
      obtain ⟨a, q, hq⟩ := hstep
      rename_i m
      cases m with
      | none =>
          have := reaches_to_none hr
          exact absurd this (by simp)
      | some w =>
          cases w with
          | inr w2 =>
              obtain ⟨c, hc, -⟩ := ite_step_inr hq
              injection hc with hc2
              exact absurd hc2 (by simp)
          | inl w1 => exact ih b w1 rfl rfl

end Ite

/-! ## The `wh` composite: back-edges die with the guard -/

section Loop

variable {body : InitializedGAut S A T} {g : BExp T} {V : T → Atom → Bool}

theorem firstMatch_all_false {L : List (BExp T × A × S)} {a : Atom}
    (h : ∀ tr ∈ L, bval V tr.1 a = false) : firstMatch V a L = none := by
  induction L with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨gg, q, s'⟩ := hd
      show (if bval V gg a then some (q, s') else firstMatch V a tl) = none
      rw [if_neg (by rw [h (gg, q, s') (List.Mem.head _)]; simp)]
      exact ih (fun tr htr => h tr (List.Mem.tail _ htr))

/-- With the loop guard everywhere false, the loop automaton steps exactly as the body. -/
theorem loop_step_eq (hg : ∀ x : Atom, bval V g x = false) (s : S) (a : Atom) :
    autStep V (loopInitialized g body).toGAut (some s) a
      = autStep V body.toGAut (some s) a := by
  rw [autStep_toGAut_some, autStep_toGAut_some]
  have hcore : (loopInitialized g body).core.trans s =
      body.core.trans s ++ body.initTrans.map (fun tr =>
        (BExp.and (body.core.hlt s) (BExp.and g tr.1), tr.2)) := rfl
  rw [hcore]
  congr 1
  cases hf : firstMatch V a (body.core.trans s) with
  | some y => exact firstMatch_append_some V a _ _ hf
  | none =>
      rw [firstMatch_append_none V a _ _ hf]
      exact firstMatch_all_false (fun tr htr => by
        obtain ⟨orig, horig, rfl⟩ := List.mem_map.mp htr
        show (bval V (body.core.hlt s) a && (bval V g a && bval V orig.1 a)) = false
        rw [hg a]
        simp)

theorem loop_reaches (hg : ∀ x : Atom, bval V g x = false)
    {t₀ t : Option S}
    (h : AutReaches V (loopInitialized g body).toGAut t₀ t) :
    ∀ x y : S, t₀ = some x → t = some y → AutReaches V body.toGAut (some x) (some y) := by
  induction h with
  | refl =>
      intro x y hx hy
      rw [hx] at hy
      injection hy with h1
      rw [h1]
      exact AutReaches.refl _
  | tail hr hstep ih =>
      intro x y hx hy
      subst hx hy
      obtain ⟨a, q, hq⟩ := hstep
      rename_i m
      cases m with
      | none =>
          have := reaches_to_none hr
          exact absurd this (by simp)
      | some w =>
          rw [loop_step_eq hg] at hq
          exact AutReaches.tail (ih x w rfl rfl) ⟨a, q, hq⟩

end Loop

/-! ## Membership plumbing -/

theorem mem_seq_inl {left : InitializedGAut S₁ A T} {right : InitializedGAut S₂ A T} {x : S₁}
    (h : (some (Sum.inl x) : Option (Sum S₁ S₂)) ∈ (seqInitialized left right).toGAut.states) :
    (some x : Option S₁) ∈ left.toGAut.states := by
  rcases List.mem_cons.mp h with hn | hs
  · exact absurd hn (by simp)
  · obtain ⟨w, hw, hwe⟩ := List.mem_map.mp hs
    injection hwe with hwe2
    subst hwe2
    rcases List.mem_append.mp hw with hl | hr
    · obtain ⟨u, hu, hue⟩ := List.mem_map.mp hl
      injection hue with hue2
      rw [← hue2]
      exact List.Mem.tail _ (List.mem_map_of_mem hu)
    · obtain ⟨u, -, hue⟩ := List.mem_map.mp hr
      exact absurd hue (by simp)

theorem mem_seq_inr {left : InitializedGAut S₁ A T} {right : InitializedGAut S₂ A T} {b : S₂}
    (h : (some (Sum.inr b) : Option (Sum S₁ S₂)) ∈ (seqInitialized left right).toGAut.states) :
    (some b : Option S₂) ∈ right.toGAut.states := by
  rcases List.mem_cons.mp h with hn | hs
  · exact absurd hn (by simp)
  · obtain ⟨w, hw, hwe⟩ := List.mem_map.mp hs
    injection hwe with hwe2
    subst hwe2
    rcases List.mem_append.mp hw with hl | hr
    · obtain ⟨u, -, hue⟩ := List.mem_map.mp hl
      exact absurd hue (by simp)
    · obtain ⟨u, hu, hue⟩ := List.mem_map.mp hr
      injection hue with hue2
      rw [← hue2]
      exact List.Mem.tail _ (List.mem_map_of_mem hu)

theorem mem_ite_inl {left : InitializedGAut S₁ A T} {right : InitializedGAut S₂ A T}
    {g : BExp T} {x : S₁}
    (h : (some (Sum.inl x) : Option (Sum S₁ S₂))
      ∈ (iteInitialized g left right).toGAut.states) :
    (some x : Option S₁) ∈ left.toGAut.states := by
  rcases List.mem_cons.mp h with hn | hs
  · exact absurd hn (by simp)
  · obtain ⟨w, hw, hwe⟩ := List.mem_map.mp hs
    injection hwe with hwe2
    subst hwe2
    rcases List.mem_append.mp hw with hl | hr
    · obtain ⟨u, hu, hue⟩ := List.mem_map.mp hl
      injection hue with hue2
      rw [← hue2]
      exact List.Mem.tail _ (List.mem_map_of_mem hu)
    · obtain ⟨u, -, hue⟩ := List.mem_map.mp hr
      exact absurd hue (by simp)

theorem mem_ite_inr {left : InitializedGAut S₁ A T} {right : InitializedGAut S₂ A T}
    {g : BExp T} {b : S₂}
    (h : (some (Sum.inr b) : Option (Sum S₁ S₂))
      ∈ (iteInitialized g left right).toGAut.states) :
    (some b : Option S₂) ∈ right.toGAut.states := by
  rcases List.mem_cons.mp h with hn | hs
  · exact absurd hn (by simp)
  · obtain ⟨w, hw, hwe⟩ := List.mem_map.mp hs
    injection hwe with hwe2
    subst hwe2
    rcases List.mem_append.mp hw with hl | hr
    · obtain ⟨u, -, hue⟩ := List.mem_map.mp hl
      exact absurd hue (by simp)
    · obtain ⟨u, hu, hue⟩ := List.mem_map.mp hr
      injection hue with hue2
      rw [← hue2]
      exact List.Mem.tail _ (List.mem_map_of_mem hu)

/-! ## The three constructor lemmas -/

theorem Nested_seqInitialized {left : InitializedGAut S₁ A T}
    {right : InitializedGAut S₂ A T} {V : T → Atom → Bool}
    (hl : Nested V left.toGAut) (hr : Nested V right.toGAut) :
    Nested V (seqInitialized left right).toGAut := by
  intro s1 s2 hmem h12 h21 hcomp
  obtain ⟨⟨w1, rfl⟩, ⟨w2, rfl⟩⟩ := mutual_some h12 h21
  cases w1 with
  | inl x =>
      cases w2 with
      | inr b =>
          obtain ⟨m, hstep, hreach⟩ := h21
          cases m with
          | none => obtain ⟨w, hw⟩ := step_target_some hstep; exact absurd hw (by simp)
          | some w =>
              cases w with
              | inl w1' =>
                  obtain ⟨a, q, hq⟩ := hstep
                  obtain ⟨c, hc, -⟩ := seq_step_inr hq
                  injection hc with hc2
                  exact absurd hc2 (by simp)
              | inr w2' => exact seq_no_inr_to_inl hreach x rfl
      | inl y =>
          have h12' : AutReaches1 V left.toGAut (some x) (some y) := by
            obtain ⟨m, hstep, hreach⟩ := h12
            cases m with
            | none => obtain ⟨w, hw⟩ := step_target_some hstep; exact absurd hw (by simp)
            | some w =>
                cases w with
                | inr b => exact (seq_no_inr_to_inl hreach y rfl).elim
                | inl m' =>
                    obtain ⟨a, q, hq⟩ := hstep
                    exact ⟨some m', ⟨a, q, seq_step_inl hq⟩, seq_reaches_inl hreach m' y rfl rfl⟩
          have h21' : AutReaches1 V left.toGAut (some y) (some x) := by
            obtain ⟨m, hstep, hreach⟩ := h21
            cases m with
            | none => obtain ⟨w, hw⟩ := step_target_some hstep; exact absurd hw (by simp)
            | some w =>
                cases w with
                | inr b => exact (seq_no_inr_to_inl hreach x rfl).elim
                | inl m' =>
                    obtain ⟨a, q, hq⟩ := hstep
                    exact ⟨some m', ⟨a, q, seq_step_inl hq⟩, seq_reaches_inl hreach m' x rfl rfl⟩
          have hc : ∀ a : Atom, bval V right.initHlt a = true := by
            intro a
            have hthis := hcomp a
            have e2 : bval V ((seqInitialized left right).toGAut.hlt (some (Sum.inl y))) a
                = (bval V (left.core.hlt y) a && bval V right.initHlt a) := rfl
            have e1 : bval V ((seqInitialized left right).toGAut.hlt (some (Sum.inl x))) a
                = (bval V (left.core.hlt x) a && bval V right.initHlt a) := rfl
            rw [e1, e2] at hthis
            cases hcv : bval V right.initHlt a with
            | true => rfl
            | false =>
                rw [hcv, Bool.and_false, Bool.and_false] at hthis
                simp at hthis
          refine hl (some x) (some y) (mem_seq_inl hmem) h12' h21' (fun a => ?_)
          have hthis := hcomp a
          have e2 : bval V ((seqInitialized left right).toGAut.hlt (some (Sum.inl y))) a
              = (bval V (left.core.hlt y) a && bval V right.initHlt a) := rfl
          have e1 : bval V ((seqInitialized left right).toGAut.hlt (some (Sum.inl x))) a
              = (bval V (left.core.hlt x) a && bval V right.initHlt a) := rfl
          rw [e1, e2, hc a, Bool.and_true, Bool.and_true] at hthis
          exact hthis
  | inr b =>
      cases w2 with
      | inl y =>
          obtain ⟨m, hstep, hreach⟩ := h12
          cases m with
          | none => obtain ⟨w, hw⟩ := step_target_some hstep; exact absurd hw (by simp)
          | some w =>
              cases w with
              | inl w1' =>
                  obtain ⟨a, q, hq⟩ := hstep
                  obtain ⟨c, hc, -⟩ := seq_step_inr hq
                  injection hc with hc2
                  exact absurd hc2 (by simp)
              | inr w2' => exact seq_no_inr_to_inl hreach y rfl
      | inr c =>
          have h12' : AutReaches1 V right.toGAut (some b) (some c) := by
            obtain ⟨m, hstep, hreach⟩ := h12
            cases m with
            | none => obtain ⟨w, hw⟩ := step_target_some hstep; exact absurd hw (by simp)
            | some w =>
                obtain ⟨a, q, hq⟩ := hstep
                obtain ⟨u, hu, hstep'⟩ := seq_step_inr hq
                injection hu with hu2
                subst hu2
                exact ⟨some u, ⟨a, q, hstep'⟩, seq_reaches_inr hreach u c rfl rfl⟩
          have h21' : AutReaches1 V right.toGAut (some c) (some b) := by
            obtain ⟨m, hstep, hreach⟩ := h21
            cases m with
            | none => obtain ⟨w, hw⟩ := step_target_some hstep; exact absurd hw (by simp)
            | some w =>
                obtain ⟨a, q, hq⟩ := hstep
                obtain ⟨u, hu, hstep'⟩ := seq_step_inr hq
                injection hu with hu2
                subst hu2
                exact ⟨some u, ⟨a, q, hstep'⟩, seq_reaches_inr hreach u b rfl rfl⟩
          exact hr (some b) (some c) (mem_seq_inr hmem) h12' h21' (fun a => hcomp a)

theorem Nested_iteInitialized {left : InitializedGAut S₁ A T}
    {right : InitializedGAut S₂ A T} {g : BExp T} {V : T → Atom → Bool}
    (hl : Nested V left.toGAut) (hr : Nested V right.toGAut) :
    Nested V (iteInitialized g left right).toGAut := by
  intro s1 s2 hmem h12 h21 hcomp
  obtain ⟨⟨w1, rfl⟩, ⟨w2, rfl⟩⟩ := mutual_some h12 h21
  cases w1 with
  | inl x =>
      cases w2 with
      | inr b =>
          obtain ⟨m, hstep, hreach⟩ := h12
          cases m with
          | none => obtain ⟨w, hw⟩ := step_target_some hstep; exact absurd hw (by simp)
          | some w =>
              cases w with
              | inr w2' =>
                  obtain ⟨a, q, hq⟩ := hstep
                  obtain ⟨c, hc, -⟩ := ite_step_inl hq
                  injection hc with hc2
                  exact absurd hc2 (by simp)
              | inl w1' => exact ite_no_inl_to_inr hreach w1' b rfl rfl
      | inl y =>
          have h12' : AutReaches1 V left.toGAut (some x) (some y) := by
            obtain ⟨m, hstep, hreach⟩ := h12
            cases m with
            | none => obtain ⟨w, hw⟩ := step_target_some hstep; exact absurd hw (by simp)
            | some w =>
                obtain ⟨a, q, hq⟩ := hstep
                obtain ⟨u, hu, hstep'⟩ := ite_step_inl hq
                injection hu with hu2
                subst hu2
                exact ⟨some u, ⟨a, q, hstep'⟩, ite_reaches_inl hreach u y rfl rfl⟩
          have h21' : AutReaches1 V left.toGAut (some y) (some x) := by
            obtain ⟨m, hstep, hreach⟩ := h21
            cases m with
            | none => obtain ⟨w, hw⟩ := step_target_some hstep; exact absurd hw (by simp)
            | some w =>
                obtain ⟨a, q, hq⟩ := hstep
                obtain ⟨u, hu, hstep'⟩ := ite_step_inl hq
                injection hu with hu2
                subst hu2
                exact ⟨some u, ⟨a, q, hstep'⟩, ite_reaches_inl hreach u x rfl rfl⟩
          exact hl (some x) (some y) (mem_ite_inl hmem) h12' h21' (fun a => hcomp a)
  | inr b =>
      cases w2 with
      | inl y =>
          obtain ⟨m, hstep, hreach⟩ := h12
          cases m with
          | none => obtain ⟨w, hw⟩ := step_target_some hstep; exact absurd hw (by simp)
          | some w =>
              cases w with
              | inl w1' =>
                  obtain ⟨a, q, hq⟩ := hstep
                  obtain ⟨c, hc, -⟩ := ite_step_inr hq
                  injection hc with hc2
                  exact absurd hc2 (by simp)
              | inr w2' => exact ite_no_inr_to_inl hreach w2' y rfl rfl
      | inr c =>
          have h12' : AutReaches1 V right.toGAut (some b) (some c) := by
            obtain ⟨m, hstep, hreach⟩ := h12
            cases m with
            | none => obtain ⟨w, hw⟩ := step_target_some hstep; exact absurd hw (by simp)
            | some w =>
                obtain ⟨a, q, hq⟩ := hstep
                obtain ⟨u, hu, hstep'⟩ := ite_step_inr hq
                injection hu with hu2
                subst hu2
                exact ⟨some u, ⟨a, q, hstep'⟩, ite_reaches_inr hreach u c rfl rfl⟩
          have h21' : AutReaches1 V right.toGAut (some c) (some b) := by
            obtain ⟨m, hstep, hreach⟩ := h21
            cases m with
            | none => obtain ⟨w, hw⟩ := step_target_some hstep; exact absurd hw (by simp)
            | some w =>
                obtain ⟨a, q, hq⟩ := hstep
                obtain ⟨u, hu, hstep'⟩ := ite_step_inr hq
                injection hu with hu2
                subst hu2
                exact ⟨some u, ⟨a, q, hstep'⟩, ite_reaches_inr hreach u b rfl rfl⟩
          exact hr (some b) (some c) (mem_ite_inr hmem) h12' h21' (fun a => hcomp a)

theorem Nested_loopInitialized {body : InitializedGAut S A T} {g : BExp T}
    {V : T → Atom → Bool} (hb : Nested V body.toGAut) :
    Nested V (loopInitialized g body).toGAut := by
  intro s1 s2 hmem h12 h21 hcomp
  obtain ⟨⟨x, rfl⟩, ⟨y, rfl⟩⟩ := mutual_some h12 h21
  have hg : ∀ a : Atom, bval V g a = false := by
    intro a
    have hthis := hcomp a
    have e2 : bval V ((loopInitialized g body).toGAut.hlt (some y)) a
        = (bval V (body.core.hlt y) a && ! bval V g a) := rfl
    have e1 : bval V ((loopInitialized g body).toGAut.hlt (some x)) a
        = (bval V (body.core.hlt x) a && ! bval V g a) := rfl
    rw [e1, e2] at hthis
    cases hgv : bval V g a with
    | false => rfl
    | true =>
        rw [hgv] at hthis
        simp at hthis
  have h12' : AutReaches1 V body.toGAut (some x) (some y) := by
    obtain ⟨m, hstep, hreach⟩ := h12
    cases m with
    | none => obtain ⟨w, hw⟩ := step_target_some hstep; exact absurd hw (by simp)
    | some w =>
        obtain ⟨a, q, hq⟩ := hstep
        rw [loop_step_eq hg] at hq
        exact ⟨some w, ⟨a, q, hq⟩, loop_reaches hg hreach w y rfl rfl⟩
  have h21' : AutReaches1 V body.toGAut (some y) (some x) := by
    obtain ⟨m, hstep, hreach⟩ := h21
    cases m with
    | none => obtain ⟨w, hw⟩ := step_target_some hstep; exact absurd hw (by simp)
    | some w =>
        obtain ⟨a, q, hq⟩ := hstep
        rw [loop_step_eq hg] at hq
        exact ⟨some w, ⟨a, q, hq⟩, loop_reaches hg hreach w x rfl rfl⟩
  refine hb (some x) (some y) hmem h12' h21' (fun a => ?_)
  have hthis := hcomp a
  have e2 : bval V ((loopInitialized g body).toGAut.hlt (some y)) a
      = (bval V (body.core.hlt y) a && ! bval V g a) := rfl
  have e1 : bval V ((loopInitialized g body).toGAut.hlt (some x)) a
      = (bval V (body.core.hlt x) a && ! bval V g a) := rfl
  rw [e1, e2, hg a, Bool.not_false, Bool.and_true, Bool.and_true] at hthis
  exact hthis

/-! ## Base cases and the main induction -/

theorem Nested_thompsonTest (b : BExp T) (V : T → Atom → Bool) :
    Nested V (thompsonTest (A := A) b).toGAut := by
  intro s1 s2 hmem h12 h21 hcomp
  obtain ⟨⟨w1, rfl⟩, -⟩ := mutual_some h12 h21
  exact nomatch w1

theorem Nested_thompsonAction (q : A) (V : T → Atom → Bool) :
    Nested V (thompsonAction (T := T) q).toGAut := by
  intro s1 s2 hmem h12 h21 hcomp
  obtain ⟨⟨w1, rfl⟩, ⟨w2, rfl⟩⟩ := mutual_some h12 h21
  obtain ⟨m, hstep, -⟩ := h12
  obtain ⟨a, qq, hq⟩ := hstep
  rw [autStep_toGAut_some] at hq
  have hnil : firstMatch V a ((thompsonAction (T := T) q).core.trans w1)
      = (none : Option (A × Unit)) := rfl
  rw [hnil] at hq
  exact absurd hq (by simp)

/-- **Every Thompson automaton satisfies the nesting coequation.** -/
theorem Nested_certifiedThompson (V : T → Atom → Bool) :
    ∀ e : Exp A T, Nested V (GkatThompson.certifiedThompson A T e).aut.toGAut
  | .test b => Nested_thompsonTest b V
  | .act q => Nested_thompsonAction q V
  | .ite g l r =>
      Nested_iteInitialized
        (Nested_certifiedThompson V l) (Nested_certifiedThompson V r)
  | .seq l r =>
      Nested_seqInitialized
        (Nested_certifiedThompson V l) (Nested_certifiedThompson V r)
  | .wh g bdy => Nested_loopInitialized (Nested_certifiedThompson V bdy)

/-- **The capstone, unconditional.**  Every uniform behavioural quotient of the sum of two
    Thompson automata is nested — the chain leaf + coproduct closure + quotient closure, with
    no hypotheses left.  The 274,461-sample measurement is now a corollary. -/
theorem Nested_sum_quotient_unconditional {Q : Type} {V : T → Atom → Bool}
    {e f : Exp A T} {quot : GAut Q A T}
    (π : UniformBehavioralGAutQuotient
      (sumGAut (GkatThompson.certifiedThompson A T e).aut.toGAut
               (GkatThompson.certifiedThompson A T f).aut.toGAut) quot) :
    Nested V quot :=
  Nested_thompson_sum_quotient π
    (Nested_certifiedThompson V e) (Nested_certifiedThompson V f)

#print axioms Nested_certifiedThompson
#print axioms Nested_sum_quotient_unconditional

end GkatThompsonNested
