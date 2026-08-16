import GkatCommonTargetProofs
import GkatDeadBranchProofs

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
open GkatDeadBranch

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
theorem match_reaches (hsa : StepAgree a b) (hlist : GAutTargetsListed b.toGAut)
    (h0 : CrossEquiv a b none none) {u : Option S₁} (hu : Reaches a u) :
    ∃ v : Option S₂, CrossEquiv a b u v ∧ v ∈ b.toGAut.states ∧
      (∀ s, u = some s → ∃ t, v = some t) := by
  induction hu with
  | start =>
      exact ⟨none, h0, List.Mem.head _, fun s hs => absurd hs (by simp)⟩
  | @step u u' X W x q _ hstep ih =>
      obtain ⟨v, hv, hvmem, _⟩ := ih
      obtain ⟨v', hstep', hv'⟩ := hsa hv W x hstep
      exact ⟨v', hv', autStep_target_listed hlist W x hvmem hstep',
        fun _ _ => step_target_some b W v x hstep'⟩

/-- Every core state of a reachable, productive system has a same-language core partner. -/
theorem match_core (hsa : StepAgree a b) (hreach : Reachable a)
    (hlist : GAutTargetsListed b.toGAut) (h0 : CrossEquiv a b none none) (s : S₁) :
    ∃ t : S₂, CrossEquiv a b (some s) (some t) ∧ t ∈ b.core.states := by
  obtain ⟨v, hv, hvmem, hsome⟩ := match_reaches hsa hlist h0 (hreach s)
  obtain ⟨t, rfl⟩ := hsome s rfl
  refine ⟨t, hv, ?_⟩
  rcases List.mem_cons.mp hvmem with hc | hc
  · exact absurd hc (by simp)
  · obtain ⟨y, hy, hye⟩ := List.mem_map.mp hc
    exact (Option.some.inj hye) ▸ hy

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

/-! ## The target system

    Minimisation is the epi half of the epi-mono factorisation of the final map, and the epi
    is a coalgebra homomorphism — which is exactly an `InitCover`.  Building it concretely
    needs representatives rather than a `Quot`, because `hlt` is a syntactic `BExp`: two
    same-language states can carry different guards, so there is nothing to lift. -/

theorem autStep_core (aut : InitializedGAut S₁ A T) (t : S₁) {X : Type}
    (W : T → X → Bool) (x : X) :
    autStep W aut.toGAut (some t) x
      = (firstMatch W x (aut.core.trans t)).map (fun o => (o.1, some o.2)) :=
  firstMatch_map_target_to W x some (aut.core.trans t)

theorem autStep_init (aut : InitializedGAut S₁ A T) {X : Type}
    (W : T → X → Bool) (x : X) :
    autStep W aut.toGAut none x
      = (firstMatch W x aut.initTrans).map (fun o => (o.1, some o.2)) :=
  firstMatch_map_target_to W x some aut.initTrans

/-- **Steps respect representatives.**  A state and its representative take the same action
    to targets with the same representative — `crossEquiv_step` gives the action and the
    language equality, `rep_eq_of_equiv` turns the latter into an identity.  This is what
    makes the target deterministic. -/
theorem rep_step (hsb : StepAgree b b) (t : S₂) {X : Type} (W : T → X → Bool) (x : X) :
    (firstMatch W x (b.core.trans t)).map (fun o => (o.1, rep b o.2))
      = (firstMatch W x (b.core.trans (rep b t))).map (fun o => (o.1, rep b o.2)) := by
  have he := rep_equiv b t
  cases h1 : firstMatch W x (b.core.trans t) with
  | none =>
      cases h2 : firstMatch W x (b.core.trans (rep b t)) with
      | none => rfl
      | some o₂ =>
          have hs : autStep W b.toGAut (some (rep b t)) x = some (o₂.1, some o₂.2) := by
            rw [autStep_core, h2]; rfl
          obtain ⟨v, hv, _⟩ := hsb he.symm W x hs
          rw [autStep_core, h1] at hv
          exact absurd hv (by simp)
  | some o₁ =>
      have hs : autStep W b.toGAut (some t) x = some (o₁.1, some o₁.2) := by
        rw [autStep_core, h1]; rfl
      obtain ⟨v, hv, hveq⟩ := hsb he W x hs
      rw [autStep_core] at hv
      cases h2 : firstMatch W x (b.core.trans (rep b t)) with
      | none => rw [h2] at hv; exact absurd hv (by simp)
      | some o₂ =>
          rw [h2] at hv
          have hpair : (o₂.1, some o₂.2) = (o₁.1, v) := Option.some.inj hv
          have hact : o₂.1 = o₁.1 := congrArg (fun z : A × Option S₂ => z.1) hpair
          have htgt : v = some o₂.2 :=
            (congrArg (fun z : A × Option S₂ => z.2) hpair).symm
          have : rep b o₁.2 = rep b o₂.2 :=
            rep_eq_of_equiv (aut := b) (htgt ▸ hveq)
          simp only [Option.map_some]
          rw [hact, this]

/-- **The behavioural target.**  States are the language classes, named by representatives;
    halting and transitions are read off the representative and targets are pushed through
    `rep`. -/
noncomputable def target (b : InitializedGAut S₂ A T) : InitializedGAut S₂ A T where
  core := {
    states := b.core.states.map (rep b)
    hlt := fun v => b.core.hlt (rep b v)
    trans := fun v => (b.core.trans (rep b v)).map (fun t => (t.1, t.2.1, rep b t.2.2))
  }
  initHlt := b.initHlt
  initTrans := b.initTrans.map (fun t => (t.1, t.2.1, rep b t.2.2))

/-- **The near side of the span.**  `b` covers its own behavioural target, by `rep`. -/
noncomputable def targetCover (hsb : StepAgree b b) : InitCover b (target b) where
  map := rep b
  initHlt_eq := fun _ _ _ => rfl
  coreHlt_eq := fun t X W x => by
    show bval W (b.core.hlt t) x = bval W (b.core.hlt (rep b (rep b t))) x
    rw [rep_idem]
    exact crossEquiv_hlt (rep_equiv b t) X W x
  initStep_eq := fun X W x => by
    show (firstMatch W x b.initTrans).map (fun o => (o.1, rep b o.2))
      = firstMatch W x (b.initTrans.map (fun t => (t.1, t.2.1, rep b t.2.2)))
    rw [firstMatch_map_target_to]
  coreStep_eq := fun t X W x => by
    show (firstMatch W x (b.core.trans t)).map (fun o => (o.1, rep b o.2))
      = firstMatch W x
          ((b.core.trans (rep b (rep b t))).map (fun tr => (tr.1, tr.2.1, rep b tr.2.2)))
    rw [rep_idem, firstMatch_map_target_to]
    exact rep_step hsb t W x
  maps := fun t ht => List.mem_map_of_mem ht
  onto := by
    intro q hq
    obtain ⟨t, ht, rfl⟩ := List.mem_map.mp hq
    exact ⟨t, ht, rfl⟩

/-! ## The far side of the span

    `b` covers its own target by `rep`; the work is showing `a` covers it too.  Every state
    of `a` is matched to a state of `b` with the same language, and `rep` collapses the
    choice of partner to a canonical one — which is what makes the two legs land on the
    *same* target rather than on two isomorphic ones. -/

/-- Everything the two automata must satisfy for the span to exist.

    The matching is now **data**, not a consequence of reachability.  Reachability was only
    ever a way to *produce* a same-language partner for each state, and it is not the only
    way — `matched_of_reachable` recovers the old route, while a padding argument can supply
    the partner directly and needs no reachability at all.

    `partner` gives each state of `a` a same-language state of `b`; `cover` says the partners
    exhaust `b`'s states up to language, which is what makes the far leg of the span *onto*. -/
structure Matched (a : InitializedGAut S₁ A T) (b : InitializedGAut S₂ A T) where
  stepab : StepAgree a b
  stepba : StepAgree b a
  stepbb : StepAgree b b
  init : CrossEquiv a b none none
  partner : S₁ → S₂
  partner_equiv : ∀ s : S₁, CrossEquiv a b (some s) (some (partner s))
  partner_mem : ∀ s ∈ a.core.states, partner s ∈ b.core.states
  cover : ∀ t ∈ b.core.states, ∃ s ∈ a.core.states, CrossEquiv a b (some s) (some t)

/-- **The old route.**  Reachability plus listed targets produces the partner by lockstep
    matching, so nothing that already satisfied `Matched` stops doing so. -/
noncomputable def matched_of_reachable {a : InitializedGAut S₁ A T} {b : InitializedGAut S₂ A T}
    (stepab : StepAgree a b) (stepba : StepAgree b a) (stepbb : StepAgree b b)
    (reacha : Reachable a) (reachb : Reachable b)
    (lista : GAutTargetsListed a.toGAut) (listb : GAutTargetsListed b.toGAut)
    (init : CrossEquiv a b none none) : Matched a b where
  stepab := stepab
  stepba := stepba
  stepbb := stepbb
  init := init
  partner := fun s => Classical.choose (match_core stepab reacha listb init s)
  partner_equiv := fun s => (Classical.choose_spec (match_core stepab reacha listb init s)).1
  partner_mem := fun s _ => (Classical.choose_spec (match_core stepab reacha listb init s)).2
  cover := fun t _ => by
    obtain ⟨s, hs, hsmem⟩ := match_core stepba reachb lista init.symm t
    exact ⟨s, hsmem, hs.symm⟩

/-- The chosen same-language partner in `b` for each state of `a`. -/
def matchTo (M : Matched a b) (s : S₁) : S₂ := M.partner s

theorem matchTo_equiv (M : Matched a b) (s : S₁) :
    CrossEquiv a b (some s) (some (matchTo M s)) := M.partner_equiv s

theorem matchTo_mem (M : Matched a b) {s : S₁} (hs : s ∈ a.core.states) :
    matchTo M s ∈ b.core.states := M.partner_mem s hs

/-- Partners are canonical after `rep`: any two same-language states of `b` get the same
    representative, so it does not matter which partner was chosen. -/
theorem rep_matchTo (M : Matched a b) {s : S₁} {t : S₂}
    (h : CrossEquiv a b (some s) (some t)) : rep b (matchTo M s) = rep b t :=
  rep_eq_of_equiv (aut := b) ((matchTo_equiv M s).symm.trans h)

/-- The two automata step alike from matched states, onto matched states. -/
private theorem cross_step_rep (M : Matched a b) {u : Option S₁} {v : Option S₂}
    (h : CrossEquiv a b u v) {X : Type} (W : T → X → Bool) (x : X) :
    (autStep W a.toGAut u x).map (fun o => (o.1, o.2.map (fun s => rep b (matchTo M s))))
      = (autStep W b.toGAut v x).map (fun o => (o.1, o.2.map (rep b))) := by
  cases h1 : autStep W a.toGAut u x with
  | none =>
      cases h2 : autStep W b.toGAut v x with
      | none => rfl
      | some o₂ =>
          obtain ⟨w, hw, _⟩ := M.stepba h.symm W x h2
          rw [h1] at hw; exact absurd hw (by simp)
  | some o₁ =>
      obtain ⟨w, hw, hweq⟩ := M.stepab h W x h1
      rw [hw]
      obtain ⟨s, hs⟩ := step_target_some a W u x h1
      obtain ⟨t, ht⟩ := step_target_some b W v x hw
      rw [hs, ht] at hweq
      simp only [hs, ht, Option.map_some]
      rw [rep_matchTo M hweq]

/-- `toGAut` wraps every target in `some`; the cover conditions are stated one level down,
    so it has to come back off. -/
private theorem strip_some {R₁ R₂ Q : Type} {X : Option (A × R₁)} {Y : Option (A × R₂)}
    {f : R₁ → Q} {g : R₂ → Q}
    (h : X.map (fun o => (o.1, some (f o.2))) = Y.map (fun o => (o.1, some (g o.2)))) :
    X.map (fun o => (o.1, f o.2)) = Y.map (fun o => (o.1, g o.2)) := by
  cases X with
  | none => cases Y with
    | none => rfl
    | some o => exact absurd h (by simp)
  | some o₁ => cases Y with
    | none => exact absurd h (by simp)
    | some o₂ =>
        simp only [Option.map_some] at h ⊢
        obtain ⟨h1, h2⟩ := Prod.mk.injEq .. ▸ Option.some.inj h
        rw [h1, Option.some.inj h2]

/-- **The far side.**  `a` covers `b`'s behavioural target, through the matching. -/
noncomputable def matchCover (M : Matched a b) : InitCover a (target b) where
  map := fun s => rep b (matchTo M s)
  initHlt_eq := fun X W x => crossEquiv_hlt M.init X W x
  coreHlt_eq := fun s X W x => by
    show bval W (a.core.hlt s) x = bval W (b.core.hlt (rep b (rep b (matchTo M s)))) x
    rw [rep_idem]
    exact (crossEquiv_hlt (matchTo_equiv M s) X W x).trans
      (crossEquiv_hlt (rep_equiv b (matchTo M s)) X W x)
  initStep_eq := fun X W x => by
    show (firstMatch W x a.initTrans).map (fun o => (o.1, rep b (matchTo M o.2)))
      = firstMatch W x (b.initTrans.map (fun t => (t.1, t.2.1, rep b t.2.2)))
    rw [firstMatch_map_target_to]
    refine strip_some (f := fun u : S₁ => rep b (matchTo M u)) (g := rep b) ?_
    have := cross_step_rep M M.init W x
    rwa [autStep_init, autStep_init, Option.map_map, Option.map_map] at this
  coreStep_eq := fun s X W x => by
    show (firstMatch W x (a.core.trans s)).map (fun o => (o.1, rep b (matchTo M o.2)))
      = firstMatch W x
          ((b.core.trans (rep b (rep b (matchTo M s)))).map
            (fun t => (t.1, t.2.1, rep b t.2.2)))
    rw [rep_idem, firstMatch_map_target_to, ← rep_step M.stepbb (matchTo M s) W x]
    refine strip_some (f := fun u : S₁ => rep b (matchTo M u)) (g := rep b) ?_
    have := cross_step_rep M (matchTo_equiv M s) W x
    rwa [autStep_core, autStep_core, Option.map_map, Option.map_map] at this
  maps := fun s hs => List.mem_map_of_mem (matchTo_mem M hs)
  onto := by
    intro q hq
    obtain ⟨t, ht, rfl⟩ := List.mem_map.mp hq
    obtain ⟨s, hsmem, hs⟩ := M.cover t ht
    exact ⟨s, hsmem, rep_matchTo M hs⟩

/-! ## The span -/

/-- **`NormalCommonTarget`, discharged.**  Two normal automata whose pseudostates have the
    same language both cover one system: `b`'s behavioural target.  The far leg is the
    matching, the near leg is `rep`, and they land on the *same* target — which is the whole
    point of choosing representatives rather than partners. -/
theorem span_of_matched (M : Matched a b) :
    Nonempty (InitCover a (target b)) ∧ Nonempty (InitCover b (target b)) :=
  ⟨⟨matchCover M⟩, ⟨targetCover M.stepbb⟩⟩

#print axioms step_target_some
#print axioms match_reaches
#print axioms match_core
#print axioms rep_equiv
#print axioms rep_eq_of_equiv
#print axioms rep_step
#print axioms targetCover
#print axioms matchCover
#print axioms span_of_matched

end GkatQuotient
