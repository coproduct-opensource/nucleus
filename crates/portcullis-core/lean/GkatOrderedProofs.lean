import GkatGuardedStringProofs

/-!
# A minimal *ordered* GKAT: the least-fixpoint (Park / star-induction) rule

The equational GKAT base derives `UA₂` for a crossed two-state system only through a
*guard-pullback witness* `wp(e₀,b₁)` (`GkatUAIndependenceProofs`), which need not exist
(`GkatPullbackWitnessProofs`). The cyclic-proof completeness route (Rooduijn–Kozen–Silva
2024) and the left-handed KA route (Das–Doumane–Pous) both regularize cycles into an
**inequational / least-fixpoint** system instead — GKAT deliberately dropped the order,
so the equational theory uses Salomaa/UA where the ordered theory would use least fixed
points.

This file builds that ordered layer, minimally: an inclusion relation `Leq` (`⊑`) with a
**star-induction** rule (`e^(b)·f` is the *least* pre-fixpoint of `g ⊒ b?(e·g):f`), and
proves it **sound** for guarded-string language inclusion (`le_sound`) — so `Leq` is a
genuine, consistent refinement of `Equiv`, not a vacuous relation.

* `InLoop_mono` — the loop language is monotone in its body (needed for `wh` congruence).
* `star_ind_den` — the loop is the LEAST fixpoint in the model (the semantic heart).
* `le_sound` — `Leq e f ⟹ ⟦e⟧ ⊆ ⟦f⟧`.
* `salomaa_least` — `e^(b)·f ⊑ g` whenever `b?(e·g):f ⊑ g`: the ordered analogue of `W3`,
  but giving LEASTNESS **without any productivity side-condition** (unlike equational `W3`,
  which needs `E(e)≡0` for *uniqueness*). This is exactly the trade the order buys.

**Scope, honestly.** This gives leastness/existence order-free-of-witness. Full crossed
*uniqueness* in the ordered system is the DDP-for-GKAT completeness content — it needs the
guardedness (global-trace / well-foundedness) principle on top of star-induction, which is
the general n-ary uniqueness (= `UAₙ`) itself, i.e. the still-open problem. So the ordered
layer relocates the obstruction to precisely where the literature places it.
-/

namespace GkatOrdered

open GkatSyntax GkatGS

variable {A T : Type}

/-- Inequational GKAT: `e ⊑ f` (below in language inclusion). Preorder + monotone
    operations + the equational theory + **star-induction** (least fixpoint). -/
inductive Leq : Exp A T → Exp A T → Prop where
  | refl (e : Exp A T) : Leq e e
  | trans {e f g : Exp A T} : Leq e f → Leq f g → Leq e g
  | equiv {e f : Exp A T} : Equiv e f → Leq e f
  | seq_mono {e e' f f' : Exp A T} : Leq e e' → Leq f f' → Leq (.seq e f) (.seq e' f')
  | ite_mono {b : BExp T} {e e' f f' : Exp A T} : Leq e e' → Leq f f' → Leq (.ite b e f) (.ite b e' f')
  | wh_mono {b : BExp T} {e e' : Exp A T} : Leq e e' → Leq (.wh b e) (.wh b e')
  | star_ind {b : BExp T} {e f g : Exp A T} :
      Leq (.ite b (.seq e g) f) g → Leq (.seq (.wh b e) f) g

variable {Atom : Type} (V : T → Atom → Bool)

/-- The loop language is monotone in its body predicate. -/
theorem InLoop_mono {b : BExp T} {P Q : GS A Atom → Prop} (h : ∀ gs, P gs → Q gs) :
    ∀ gs, InLoop V b P gs → InLoop V b Q gs := by
  intro gs hgs
  induction hgs with
  | exit a hb => exact InLoop.exit a hb
  | step a l1 rest hb hP _ ih => exact InLoop.step a l1 rest hb (h _ hP) ih

/-- **The semantic heart: the loop is the LEAST fixpoint.** If `b?(e·g):f` denotes a
    sublanguage of `g`, then so does every unrolling `e^(b)·f`. Proved by induction on the
    loop derivation `InLoop`, using `lastAtom_append` and the fusion product. No
    productivity needed — leastness is unconditional. -/
theorem star_ind_den {b : BExp T} {e f g : Exp A T}
    (H : ∀ gs, den V (.ite b (.seq e g) f) gs → den V g gs) :
    ∀ (gs : GS A Atom), InLoop V b (den V e) gs →
      ∀ l2, den V f (lastAtom gs.1 gs.2, l2) → den V g (gs.1, gs.2 ++ l2) := by
  intro gs hloop
  induction hloop with
  | exit a hb =>
    intro l2 hf
    simp only [List.nil_append, lastAtom] at hf ⊢
    exact H (a, l2) (Or.inr ⟨hb, hf⟩)
  | step a l1' rest hb hden _ ih =>
    intro l2 hf
    simp only [List.append_assoc]
    refine H (a, l1' ++ (rest ++ l2)) (Or.inl ⟨hb, l1', rest ++ l2, rfl, hden, ?_⟩)
    exact ih l2 (by rw [lastAtom_append] at hf; exact hf)

/-- **Soundness / consistency: `Leq` refines language inclusion.** Hence `Leq` is a genuine
    ordered theory, not the total relation. -/
theorem le_sound {e f : Exp A T} (h : Leq e f) : ∀ gs, den V e gs → den V f gs := by
  induction h with
  | refl e => exact fun _ h => h
  | trans _ _ ih1 ih2 => exact fun gs h => ih2 gs (ih1 gs h)
  | equiv h => exact fun gs => (sound V h gs).mp
  | seq_mono _ _ ihe ihf =>
    exact fun gs ⟨l1, l2, hs, he, hf⟩ => ⟨l1, l2, hs, ihe _ he, ihf _ hf⟩
  | ite_mono _ _ ihe ihf =>
    intro gs h
    rcases h with ⟨hb, he⟩ | ⟨hb, hf⟩
    · exact Or.inl ⟨hb, ihe _ he⟩
    · exact Or.inr ⟨hb, ihf _ hf⟩
  | @wh_mono b e e' _ ihe =>
    exact InLoop_mono V (fun gs => ihe gs)
  | @star_ind b e f g _ ih =>
    rintro ⟨g1, g2⟩ ⟨l1, l2, hs, hloop, hf⟩
    simp only at hs
    subst hs
    exact star_ind_den V ih (g1, l1) hloop l2 hf

/-- **The ordered analogue of `W3`: leastness, no productivity.** `e^(b)·f` is the least
    solution of `g ⊒ b?(e·g):f`. Where equational `W3` needs `E(e)≡0` to conclude *equality*
    (uniqueness), star-induction concludes `⊑` (leastness) with NO side-condition — the exact
    expressive trade between the unique-fixpoint (Salomaa/UA) and least-fixpoint (Kozen/DDP)
    formulations. -/
theorem salomaa_least {b : BExp T} {e f g : Exp A T}
    (h : Leq (.ite b (.seq e g) f) g) : Leq (.seq (.wh b e) f) g :=
  Leq.star_ind h

#print axioms le_sound
#print axioms star_ind_den
#print axioms salomaa_least

end GkatOrdered
