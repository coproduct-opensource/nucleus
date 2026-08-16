import GkatCommonTargetProofs

/-!
# The behavioural target, constructed

`NormalCommonTarget` is the remaining construction: two uniformly equivalent programs in
normal form (productive and fully reachable) admit a system both their Thompson automata
cover.  This file builds it.

The mathematics is `crossEquiv_step`: in a productive system, same-language states step
alike onto same-language targets.  Running the two automata in lockstep from their
pseudostates — which are language-equal because the programs are — therefore matches every
reachable state of one with a state of the other, and the matching respects steps by
construction.  The target is then the common set of classes, with a chosen representative
per class.

Reachability earns its place here rather than being inherited from the search's habits: an
unreachable state realises languages the other program need not realise anywhere, so no
system can be onto both.  That is the second half of what the `0` vs `a ; 0` counterexample
was pointing at.
-/

namespace GkatQuotient

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatSynthesis GkatCofinality GkatPullback GkatAtomTransfer GkatCommonTarget

variable {A T : Type}
variable {S₁ S₂ : Type} {a : InitializedGAut S₁ A T} {b : InitializedGAut S₂ A T}

/-! ## Steps land in core states -/

/-- Every step of `toGAut` lands in a *core* state: both branches of `toGAut.trans` push
    their targets through `some`. -/
theorem step_target_some {S X : Type} (aut : InitializedGAut S A T)
    (W : T → X → Bool) (s : Option S) (x : X) {q : A} {t : Option S}
    (hstep : autStep W aut.toGAut s x = some (q, t)) : ∃ u, t = some u := by
  cases s with
  | none =>
      have : firstMatch W x (aut.initTrans.map
          (fun tr => (tr.1, tr.2.1, some tr.2.2))) = some (q, t) := hstep
      rw [firstMatch_map_target_to] at this
      cases hf : firstMatch W x aut.initTrans with
      | none => rw [hf] at this; exact absurd this (by simp)
      | some o =>
          rw [hf] at this
          exact ⟨o.2, (congrArg Prod.snd (Option.some.inj this)).symm⟩
  | some v =>
      have : firstMatch W x ((aut.core.trans v).map
          (fun tr => (tr.1, tr.2.1, some tr.2.2))) = some (q, t) := hstep
      rw [firstMatch_map_target_to] at this
      cases hf : firstMatch W x (aut.core.trans v) with
      | none => rw [hf] at this; exact absurd this (by simp)
      | some o =>
          rw [hf] at this
          exact ⟨o.2, (congrArg Prod.snd (Option.some.inj this)).symm⟩

/-! ## Lockstep matching

    Two productive systems whose pseudostates have the same language stay matched: every
    state reachable in one has a same-language partner in the other, and a partner of a
    *core* state is again a core state, because a step lands in one on both sides. -/

/-- **The matching lemma.**  Induction on reachability, with `crossEquiv_step` doing the
    work at each step.  The second conjunct is what keeps core states matched to core
    states: `step_target_some` applies on both sides at once. -/
theorem match_reaches (hprod : Productive a) (h0 : CrossEquiv a b none none)
    {u : Option S₁} (hu : Reaches a u) :
    ∃ v : Option S₂, CrossEquiv a b u v ∧ (∀ s, u = some s → ∃ t, v = some t) := by
  induction hu with
  | start => exact ⟨none, h0, fun s hs => absurd hs (by simp)⟩
  | @step u u' X W x q _ hstep ih =>
      obtain ⟨v, hv, _⟩ := ih
      obtain ⟨v', hstep', hv'⟩ := crossEquiv_step hprod hv W x hstep
      exact ⟨v', hv', fun _ _ => step_target_some b W v x hstep'⟩

/-- Every core state of a reachable, productive system has a same-language core partner. -/
theorem match_core (hprod : Productive a) (hreach : Reachable a)
    (h0 : CrossEquiv a b none none) (s : S₁) :
    ∃ t : S₂, CrossEquiv a b (some s) (some t) := by
  obtain ⟨v, hv, hsome⟩ := match_reaches hprod h0 (hreach s)
  obtain ⟨t, rfl⟩ := hsome s rfl
  exact ⟨t, hv⟩

/-! ## Canonical representatives

    The target's states are the language classes, and a class has to be named by an actual
    state because `hlt` is a *syntactic* `BExp`: two same-language states can carry
    different guards, so `Quot.lift` does not apply and the class must be given a
    representative.  `Quotient.exists_rep` plus `Classical.choose` is enough, and stays
    inside core Lean. -/

/-- Same-language is an equivalence on core states. -/
private def langSetoid (aut : InitializedGAut S₁ A T) : Setoid S₁ where
  r s t := LangEquiv aut (some s) (some t)
  iseqv := ⟨fun _ _ _ _ => Iff.rfl, fun h => h.symm, fun h₁ h₂ => h₁.trans h₂⟩

/-- A chosen representative of a class.  Factored through the class rather than the state so
    that `rep_eq_of_equiv` is a `congrArg` — rewriting under `Classical.choose` directly is
    blocked by a dependent motive. -/
noncomputable def repOfClass (aut : InitializedGAut S₁ A T)
    (c : Quotient (langSetoid aut)) : S₁ :=
  Classical.choose (Quotient.exists_rep c)

private theorem repOfClass_mk (aut : InitializedGAut S₁ A T) (c : Quotient (langSetoid aut)) :
    Quotient.mk (langSetoid aut) (repOfClass aut c) = c :=
  Classical.choose_spec (Quotient.exists_rep c)

/-- A chosen representative of each language class. -/
noncomputable def rep (aut : InitializedGAut S₁ A T) (s : S₁) : S₁ :=
  repOfClass aut (Quotient.mk (langSetoid aut) s)

/-- A state and its representative have the same language. -/
theorem rep_equiv (aut : InitializedGAut S₁ A T) (s : S₁) :
    LangEquiv aut (some s) (some (rep aut s)) :=
  (Quotient.exact (repOfClass_mk aut (Quotient.mk (langSetoid aut) s)) :
    LangEquiv aut (some (rep aut s)) (some s)).symm

/-- Same-language states are given the *same* representative — the property that makes the
    target deterministic, and the reason a mere choice of partner is not enough. -/
theorem rep_eq_of_equiv {aut : InitializedGAut S₁ A T} {s t : S₁}
    (h : LangEquiv aut (some s) (some t)) : rep aut s = rep aut t :=
  congrArg (repOfClass aut) (Quotient.sound h)

theorem rep_idem (aut : InitializedGAut S₁ A T) (s : S₁) :
    rep aut (rep aut s) = rep aut s :=
  rep_eq_of_equiv (rep_equiv aut s).symm

#print axioms step_target_some
#print axioms match_reaches
#print axioms match_core
#print axioms rep_equiv
#print axioms rep_eq_of_equiv

end GkatQuotient
