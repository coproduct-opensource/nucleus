import GkatGuardedStringProofs

/-!
# The coalgebraic derivative: `den` factors through a one-step `next` (with loops)

The equational (Salomaa + Uniqueness-Axiom) completeness of GKAT is open, but the
**coalgebraic** account is settled and decidable: expression equivalence is
bisimilarity of the derivative automaton (Smolka et al. POPL'20, near-linear time),
and the cyclic proof system of Rooduijn–Silva–Kozen (IJCAR 2024) is sound, complete
for the language model, and decidable. Both rest on the **fundamental theorem of
derivatives**: an expression's language is determined by whether it can *halt now*
and its *one-step residual* `next`.

This file machine-checks that theorem over the guarded-string model for the **full**
language, `while` loops included:

  * `next`      : the one-step (Brzozowski) derivative, `Exp → Atom → Option (A×Exp)`,
  * `den_nil`   : `⟦e⟧` accepts `(a,[])` ↔ `E(e)` at `a`   (halt-now; = `den_empty_E`),
  * `den_cons`  : `⟦e⟧` accepts `(a,(q,a')::w)` ↔ `next e a = some (q,e')` and `⟦e'⟧`
                  accepts `(a',w)` — for **every** expression, loops included,
  * `next_halt_exclusive` : halt-now and step-now are mutually exclusive — `⟨E, next⟩`
                  is a genuine deterministic coalgebra.

The `while` case of `den_cons` is the substantive part: `⟦e^(b)⟧ = InLoop b ⟦e⟧` is a
least fixpoint, so the forward direction inducts on the `InLoop` derivation — an
*empty* loop iteration (the body accepts the empty string) is idempotent and is
absorbed by the strictly-smaller sub-proof, while a *productive* iteration steps via
the body's derivative into the residual `e'·e^(b)`.

**Payoff:** `decDen` — membership `den V e gs` is **decidable** for every expression,
by iterating `⟨E, next⟩` along the guarded string. In particular loop membership
`den (e^(b)) gs` — an inductive-`Prop` least fixpoint that is not obviously decidable
from its definition — is decided by the one-step derivative.

Axioms `[propext]`, `sorryAx`-free.
-/

namespace GkatDeriv

open GkatSyntax GkatGS

variable {A T Atom : Type} (V : T → Atom → Bool)

/-- The **one-step derivative**: at atom `a`, the unique `(action, residual)` the
    expression performs, or `none` if it cannot step (it halts or is dead). -/
def next : Exp A T → Atom → Option (A × Exp A T)
  | .act p,    _ => some (p, .test .one)
  | .test _,   _ => none
  | .seq e f,  a => match next e a with
      | some (p, e') => some (p, .seq e' f)
      | none         => if bval V (E e) a then next f a else none
  | .ite b e f, a => if bval V b a then next e a else next f a
  | .wh b e,   a => if bval V b a then
      (match next e a with
        | some (p, e') => some (p, .seq e' (.wh b e))
        | none         => none)
    else none

/-- **Determinism.** An expression that steps at `a` cannot halt at `a`. Holds for
    every expression, loops included. -/
theorem next_halt_exclusive (e : Exp A T) (a : Atom) :
    ∀ x : A × Exp A T, next V e a = some x → bval V (E e) a = false := by
  induction e generalizing a with
  | act p => intro _ _; rfl
  | test t => intro x h; simp [next] at h
  | seq e f ihe ihf =>
      intro x h; simp only [next] at h; simp only [E, bval]
      cases hne : next V e a with
      | some pe => simp [ihe a pe hne]
      | none =>
          rw [hne] at h
          by_cases hE : bval V (E e) a = true
          · rw [if_pos hE] at h; simp [hE, ihf a x h]
          · simp [(by simpa using hE : bval V (E e) a = false)]
  | ite b e f ihe ihf =>
      intro x h; simp only [next] at h; simp only [E, bval]
      by_cases hb : bval V b a = true
      · rw [if_pos hb] at h; simp [hb, ihe a x h]
      · have hbf : bval V b a = false := by simpa using hb
        rw [if_neg hb] at h; simp [hbf, ihf a x h]
  | wh b e _ =>
      intro x h
      by_cases hb : bval V b a = true
      · simp [E, bval, hb]
      · simp only [next] at h; rw [if_neg hb] at h; simp at h

/-- **Halt-now** (`= den_empty_E`): `⟦e⟧` accepts `(a,[])` iff `E(e)` at `a`. -/
theorem den_nil (e : Exp A T) (a : Atom) :
    den V e (a, []) ↔ bval V (E e) a = true := den_empty_E V e a

/-- **The fundamental theorem of derivatives.** `⟦e⟧` accepts `(a,(q,a')::w)` iff `e`
    steps at `a` via `q` to a residual `e'` whose language accepts `(a',w)`. Holds for
    every expression; the `while` case inducts on the `InLoop` least-fixpoint proof. -/
theorem den_cons (e : Exp A T) (a : Atom) (q : A) (a' : Atom) (w : List (A × Atom)) :
    den V e (a, (q, a') :: w) ↔
      ∃ e', next V e a = some (q, e') ∧ den V e' (a', w) := by
  induction e generalizing a q a' w with
  | act p =>
      simp only [next]
      constructor
      · rintro ⟨x, y, h⟩
        injection h with ha hlist; injection hlist with hpair hw; injection hpair with hq hy
        subst hw; subst hq
        exact ⟨.test .one, rfl, rfl, rfl⟩
      · rintro ⟨e', h, hd⟩
        rw [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨_, rfl⟩ := hd
        exact ⟨a, a', rfl⟩
  | test t =>
      simp only [next]
      constructor
      · rintro ⟨_, h⟩; exact absurd h (by simp)
      · rintro ⟨_, h, _⟩; exact absurd h (by simp)
  | seq e f ihe ihf =>
      simp only [den_seq]
      constructor
      · rintro ⟨l1, l2, hl, hde, hdf⟩
        cases l1 with
        | nil =>
            rw [List.nil_append] at hl; subst hl
            have hEe : bval V (E e) a = true := (den_nil V e a).mp hde
            have hne : next V e a = none := by
              cases hn : next V e a with
              | none => rfl
              | some x => simp [next_halt_exclusive V e a x hn] at hEe
            obtain ⟨f', hnf, hdf'⟩ := (ihf a q a' w).mp hdf
            exact ⟨f', by simp [next, hne, hEe, hnf], hdf'⟩
        | cons hd tl =>
            obtain ⟨hhd, htl⟩ : hd = (q, a') ∧ tl ++ l2 = w := by
              simpa [List.cons_append] using hl.symm
            subst hhd
            obtain ⟨e0, hne, hde0⟩ := (ihe a q a' tl).mp hde
            refine ⟨.seq e0 f, by simp [next, hne], ?_⟩
            exact ⟨tl, l2, htl.symm, hde0, by simpa [lastAtom] using hdf⟩
      · rintro ⟨e', hnext, hd⟩
        simp only [next] at hnext
        cases hne : next V e a with
        | some pe =>
            rw [hne] at hnext; obtain ⟨p0, e0⟩ := pe
            rw [Option.some.injEq, Prod.mk.injEq] at hnext
            obtain ⟨rfl, rfl⟩ := hnext
            obtain ⟨m1, m2, hw, hde0, hdf⟩ := (den_seq V e0 f (a', w)).mp hd
            refine ⟨(p0, a') :: m1, m2, ?_,
              (ihe a p0 a' m1).mpr ⟨e0, hne, hde0⟩, by simpa [lastAtom] using hdf⟩
            have hw2 : w = m1 ++ m2 := hw
            show (p0, a') :: w = (p0, a') :: m1 ++ m2
            simp [hw2]
        | none =>
            rw [hne] at hnext
            by_cases hE : bval V (E e) a = true
            · rw [if_pos hE] at hnext
              have hdf : den V f (a, (q, a') :: w) := (ihf a q a' w).mpr ⟨e', hnext, hd⟩
              exact ⟨[], (q, a') :: w, rfl, (den_nil V e a).mpr hE, by simpa [lastAtom] using hdf⟩
            · rw [if_neg hE] at hnext; simp at hnext
  | ite b e f ihe ihf =>
      have hn : next V (.ite b e f) a = if bval V b a then next V e a else next V f a := rfl
      rw [den_ite, hn]
      by_cases hb : bval V b a = true
      · rw [if_pos hb]
        constructor
        · rintro (⟨_, hde⟩ | ⟨hbf, _⟩)
          · exact (ihe a q a' w).mp hde
          · rw [hb] at hbf; exact absurd hbf (by simp)
        · intro h; exact Or.inl ⟨hb, (ihe a q a' w).mpr h⟩
      · have hbf : bval V b a = false := by simpa using hb
        rw [if_neg hb]
        constructor
        · rintro (⟨hbt, _⟩ | ⟨_, hdf⟩)
          · rw [hbf] at hbt; exact absurd hbt (by simp)
          · exact (ihf a q a' w).mp hdf
        · intro h; exact Or.inr ⟨hbf, (ihf a q a' w).mpr h⟩
  | wh b e ihe =>
      constructor
      · intro h
        -- ⟦e^(b)⟧ = InLoop b ⟦e⟧; induct on the least-fixpoint proof, string generalized
        have gen : ∀ gs : GS A Atom, InLoop V b (den V e) gs →
            ∀ q a' w, gs.2 = (q, a') :: w →
              ∃ e', next V (.wh b e) gs.1 = some (q, e') ∧ den V e' (a', w) := by
          intro gs hgs
          induction hgs with
          | exit a0 hb0 => intro q a' w hl; simp at hl
          | step a0 l1 rest hb0 hbody hrec ih =>
              intro q a' w hl
              have hl' : l1 ++ rest = (q, a') :: w := hl
              cases l1 with
              | nil =>
                  rw [List.nil_append] at hl'
                  simpa using ih q a' w (by simpa using hl')
              | cons hd tl =>
                  obtain ⟨rfl, htl⟩ : hd = (q, a') ∧ tl ++ rest = w := by
                    simpa [List.cons_append] using hl'
                  obtain ⟨e0, hne, hde0⟩ := (ihe a0 q a' tl).mp hbody
                  refine ⟨.seq e0 (.wh b e), by simp [next, hb0, hne], tl, rest, htl.symm, hde0, ?_⟩
                  simpa [lastAtom] using hrec
        exact gen (a, (q, a') :: w) h q a' w rfl
      · rintro ⟨e', hnext, hd⟩
        simp only [next] at hnext
        by_cases hb : bval V b a = true
        · rw [if_pos hb] at hnext
          cases hne : next V e a with
          | some pe =>
              rw [hne] at hnext; obtain ⟨q0, e0⟩ := pe
              rw [Option.some.injEq, Prod.mk.injEq] at hnext
              obtain ⟨rfl, rfl⟩ := hnext
              obtain ⟨m1, m2, hw, hde0, hloop⟩ := (den_seq V e0 (.wh b e) (a', w)).mp hd
              have hbody : den V e (a, (q0, a') :: m1) := (ihe a q0 a' m1).mpr ⟨e0, hne, hde0⟩
              have hw2 : w = m1 ++ m2 := hw
              show InLoop V b (den V e) (a, (q0, a') :: w)
              rw [hw2, show (q0, a') :: (m1 ++ m2) = ((q0, a') :: m1) ++ m2 from rfl]
              exact InLoop.step a ((q0, a') :: m1) m2 hb hbody (by simpa [lastAtom] using hloop)
          | none => rw [hne] at hnext; simp at hnext
        · rw [if_neg hb] at hnext; simp at hnext

/-- **Membership is decidable** for every expression, by iterating `⟨E, next⟩` along
    the guarded string. Loop membership (`den (e^(b)) gs`), an inductive-`Prop` least
    fixpoint, is decided here purely by the one-step derivative. -/
def decDen [DecidableEq A] (V : T → Atom → Bool) :
    ∀ (w : List (A × Atom)) (a : Atom) (e : Exp A T), Decidable (den V e (a, w))
  | [], a, e => decidable_of_iff _ (den_nil V e a).symm
  | (q, a') :: w, a, e =>
      match hn : next V e a with
      | none => isFalse (by
          rw [den_cons]; rintro ⟨e', he, _⟩; rw [hn] at he; exact absurd he (by simp))
      | some (q0, e0) =>
          have : Decidable (den V e0 (a', w)) := decDen V w a' e0
          decidable_of_iff (q0 = q ∧ den V e0 (a', w)) (by
            rw [den_cons]
            constructor
            · rintro ⟨rfl, hd⟩; exact ⟨e0, hn, hd⟩
            · rintro ⟨e', he, hd⟩
              rw [hn, Option.some.injEq, Prod.mk.injEq] at he
              obtain ⟨rfl, rfl⟩ := he; exact ⟨rfl, hd⟩)

#print axioms den_cons
#print axioms next_halt_exclusive

end GkatDeriv
