import GkatDerivativeProofs

/-!
# Finitely many derivatives — the termination lemma for the decision procedure

`bisim_sound` reduces `⟦e⟧ = ⟦f⟧` to exhibiting a bisimulation, and a decision
procedure searches for one by enumerating the residual pairs reachable from `(e,f)`
under the one-step derivative `next`. That search terminates because the set of
derivatives of a fixed expression is **finite** (Antimirov 1996 for KA; Smolka et
al. POPL'20 for GKAT). This file machine-checks that finiteness.

Crucially, the `next` of `GkatDerivativeProofs` keeps derivatives finite *as
syntactic objects*: stepping `seq e f` yields `seq e' f` with the tail `f`
**fixed**, and stepping `e^(b)` yields `seq e' (e^(b))` with the loop **fixed** — the
residual never grows an unbounded stack. So an explicit over-approximating list
`derivs e` is next-closed, and its length bounds the derivative set:

  * `mem_self`     : `e ∈ derivs e`,
  * `deriv_mem`    : `next e a = some (q,e')` ⟹ `e' ∈ derivs e`,
  * `derivs_trans` : `e₀ ∈ derivs e` ⟹ `derivs e₀ ⊆ derivs e`,
  * `derivs_closed`: `e₀ ∈ derivs e` and `next e₀ a = some (q,e')` ⟹ `e' ∈ derivs e`.

`derivs_closed` + `mem_self` are exactly the finiteness a bisimulation search needs:
every residual ever reachable from `e` lives in the finite list `derivs e`, so the
worklist of pairs is confined to `derivs e × derivs f` and cannot diverge.

Axioms `[propext, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatDeriv

open GkatSyntax GkatGS

variable {A T Atom : Type}

/-- A finite over-approximation of the set of derivatives reachable from `e`. It
    contains `e` and is closed under `next`; stepping a `seq`/`wh` keeps the fixed
    tail, so the list is finite. -/
def derivs : Exp A T → List (Exp A T)
  | .act p     => [.act p, .test .one]
  | .test t    => [.test t]
  | .seq e f   => (derivs e).map (fun e' => .seq e' f) ++ derivs f
  | .ite b e f => .ite b e f :: (derivs e ++ derivs f)
  | .wh b e    => .wh b e :: (derivs e).map (fun e' => .seq e' (.wh b e))

/-- `e` is among its own derivatives (the search starts here). -/
theorem mem_self (e : Exp A T) : e ∈ derivs e := by
  cases e with
  | act p => simp [derivs]
  | test t => simp [derivs]
  | seq e f => simp only [derivs, List.mem_append, List.mem_map]; exact Or.inl ⟨e, mem_self e, rfl⟩
  | ite b e f => simp [derivs]
  | wh b e => simp [derivs]

/-- The one-step residual of `e` is among `e`'s derivatives. -/
theorem deriv_mem {V : T → Atom → Bool} (e : Exp A T) {a : Atom} {q : A} {e' : Exp A T} :
    next V e a = some (q, e') → e' ∈ derivs e := by
  induction e generalizing q e' with
  | act p =>
      intro h; simp only [next, Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h; simp [derivs]
  | test t => intro h; simp [next] at h
  | seq e f ihe ihf =>
      intro h; simp only [next] at h
      cases hne : next V e a with
      | some pe =>
          rw [hne] at h; obtain ⟨p0, e0⟩ := pe
          rw [Option.some.injEq, Prod.mk.injEq] at h
          rw [← h.2]
          simp only [derivs, List.mem_append, List.mem_map]
          exact Or.inl ⟨e0, ihe hne, rfl⟩
      | none =>
          rw [hne] at h
          by_cases hE : bval V (E e) a = true
          · rw [if_pos hE] at h
            simp only [derivs, List.mem_append]; exact Or.inr (ihf h)
          · rw [if_neg hE] at h; simp at h
  | ite b e f ihe ihf =>
      intro h; simp only [next] at h
      simp only [derivs, List.mem_cons, List.mem_append]
      by_cases hb : bval V b a = true
      · rw [if_pos hb] at h; exact Or.inr (Or.inl (ihe h))
      · rw [if_neg hb] at h; exact Or.inr (Or.inr (ihf h))
  | wh b e ihe =>
      intro h; simp only [next] at h
      by_cases hb : bval V b a = true
      · rw [if_pos hb] at h
        cases hne : next V e a with
        | some pe =>
            rw [hne] at h; obtain ⟨p0, e0⟩ := pe
            rw [Option.some.injEq, Prod.mk.injEq] at h
            rw [← h.2]
            simp only [derivs, List.mem_cons, List.mem_map]
            exact Or.inr ⟨e0, ihe hne, rfl⟩
        | none => rw [hne] at h; simp at h
      · rw [if_neg hb] at h; simp at h

/-- `derivs` is transitive: a derivative's derivatives are derivatives. -/
theorem derivs_trans (e : Exp A T) {e0 : Exp A T} (h0 : e0 ∈ derivs e) :
    ∀ x ∈ derivs e0, x ∈ derivs e := by
  induction e generalizing e0 with
  | act p =>
      simp only [derivs, List.mem_cons, List.not_mem_nil, or_false] at h0
      rcases h0 with rfl | rfl <;> intro x hx <;> simp_all [derivs]
  | test t =>
      simp only [derivs, List.mem_cons, List.not_mem_nil, or_false] at h0
      subst h0; exact fun x hx => hx
  | seq e f ihe ihf =>
      simp only [derivs, List.mem_append, List.mem_map] at h0
      rcases h0 with ⟨e', he', rfl⟩ | h0
      · intro x hx
        simp only [derivs, List.mem_append, List.mem_map] at hx ⊢
        rcases hx with ⟨e'', he'', rfl⟩ | hx
        · exact Or.inl ⟨e'', ihe he' e'' he'', rfl⟩
        · exact Or.inr hx
      · intro x hx
        simp only [derivs, List.mem_append, List.mem_map]
        exact Or.inr (ihf h0 x hx)
  | ite b e f ihe ihf =>
      simp only [derivs, List.mem_cons, List.mem_append] at h0
      rcases h0 with rfl | he0 | hf0
      · exact fun x hx => hx
      · intro x hx; simp only [derivs, List.mem_cons, List.mem_append]
        exact Or.inr (Or.inl (ihe he0 x hx))
      · intro x hx; simp only [derivs, List.mem_cons, List.mem_append]
        exact Or.inr (Or.inr (ihf hf0 x hx))
  | wh b e ihe =>
      simp only [derivs, List.mem_cons, List.mem_map] at h0
      rcases h0 with rfl | ⟨e', he', rfl⟩
      · exact fun x hx => hx
      · intro x hx
        simp only [derivs, List.mem_cons, List.mem_append, List.mem_map] at hx
        simp only [derivs, List.mem_cons, List.mem_map]
        rcases hx with ⟨e'', he'', heq⟩ | hx2
        · exact Or.inr ⟨e'', ihe he' e'' he'', heq⟩
        · rcases hx2 with rfl | ⟨e'', he'', heq⟩
          · exact Or.inl rfl
          · exact Or.inr ⟨e'', he'', heq⟩

/-- **Finiteness / termination.** Every residual reachable from `e` in one step from
    any derivative stays inside the finite list `derivs e`. With `mem_self`, the
    bisimulation search is confined to `derivs e × derivs f` and terminates. -/
theorem derivs_closed {V : T → Atom → Bool} (e : Exp A T) {e0 : Exp A T}
    (h0 : e0 ∈ derivs e) {a : Atom} {q : A} {e' : Exp A T}
    (hn : next V e0 a = some (q, e')) : e' ∈ derivs e :=
  derivs_trans e h0 e' (deriv_mem e0 hn)

#print axioms derivs_closed
#print axioms mem_self

end GkatDeriv
