import GkatDecompProofs

/-! # Toward plan existence: the attack on `DecompCovered`

    `completeness_of_decompCovered` reduced the open problem to one hypothesis.  This
    file opens the attack.  The strategy decomposes `DecompCovered` into:

    * **S1 — the canonical quotient**: for uniformly equivalent `e, f`, the
      start-merging behavioural quotient of the Thompson sum exists.
      - S1a (below, PROVED): the sum's two start states are language-equal at every
        carrier and valuation — the semantic germ of the merge.
      - S1b (open): the quotient construction itself — the sum modulo state language
        equivalence, as a `UniformBehavioralGAutQuotient`.  Technical care: language
        equality gives halt-guard agreement pointwise and derivative-language
        agreement, but step-matching in `GAutBisim` needs the automaton normalized
        (dead-continuation transitions trimmed), the Lean incarnation of the
        harness's trim/canon discipline.
    * **S2 — role existence (the mathematical core, open)**: the canonical quotient's
      states admit `StateRole` witnesses.  Evidence: 100% measured on three exhaustive
      spaces and the sampled frontier; the walk-planner is the constructive skeleton;
      the guarded Caron–Ziadi orbit analogy names the invariants.
    * **S3 — assembly**: from constructive S2, the `qsol` assignment and witnesses
      (definitional given S2's form).

    S1a is proved here; S1b and S2 are the open work, in that order. -/

namespace GkatPlanExistence

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open GkatDecomp

variable {A T : Type}

/-- **S1a.  The starts are language-equal.**  Uniform language equivalence of the
    programs transfers along the Thompson start-language theorem and the coproduct
    embeddings: at every carrier and valuation, the sum's two start states accept the
    same guarded strings. -/
theorem sum_starts_language_equal (e f : Exp A T)
    (heq : UniformLanguageEquivalent e f)
    {X : Type} (W : T → X → Bool) :
    autLang W (sumGAut (certifiedThompson A T e).aut.toGAut
                       (certifiedThompson A T f).aut.toGAut) (Sum.inl none)
      = autLang W (sumGAut (certifiedThompson A T e).aut.toGAut
                           (certifiedThompson A T f).aut.toGAut) (Sum.inr none) := by
  have hl : autLang W (certifiedThompson A T e).aut.toGAut none
      = autLang W (sumGAut (certifiedThompson A T e).aut.toGAut
                           (certifiedThompson A T f).aut.toGAut) (Sum.inl none) :=
    autLang_eq_of_gautBisim
      (gAutHom_bisim (GAutHom.inl (certifiedThompson A T e).aut.toGAut
        (certifiedThompson A T f).aut.toGAut) W) rfl
  have hr : autLang W (certifiedThompson A T f).aut.toGAut none
      = autLang W (sumGAut (certifiedThompson A T e).aut.toGAut
                           (certifiedThompson A T f).aut.toGAut) (Sum.inr none) :=
    autLang_eq_of_gautBisim
      (gAutHom_bisim (GAutHom.inr (certifiedThompson A T e).aut.toGAut
        (certifiedThompson A T f).aut.toGAut) W) rfl
  rw [← hl, ← hr, certifiedThompson_start_language, certifiedThompson_start_language]
  funext gs
  exact propext (heq X W gs)

#print axioms sum_starts_language_equal

end GkatPlanExistence
