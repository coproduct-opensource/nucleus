import GkatDeadBranchProofs

/-!
# UA₂ eliminated at every decided crossing

`GkatUAIndependenceProofs` proves the positive half of the UA obstruction: **UA₂ is
derivable from the finite base plus UA₁ plus a guard-pullback witness.**  What it does
not do — and could not, before `post_all` — is *produce* such a witness.  Witnesses were
hypotheses.

This file produces them.  Whenever the crossing guard is **decided** by the prefix (the
prefix always establishes it, or always refutes it), the witness exists and is a constant
guard, and `post_all` proves it.  Composing with the crossed closed form gives:

    ua2_eliminated_of_decided_true / _false
      :  UA₂ for the crossed two-state system is a THEOREM of the finite axioms.

No `UA` of any arity is assumed; the only fixpoint principle is `W3` (= UA₁), which the
finite system already contains.

The `GkatUAIndep` originals are stated in `Equiv`; the crossed closed form is re-derived
here in `EquivBA` so that the Boolean-guard reasoning `post_all` needs is available.  The
derivation is the same one: congruence, the witness, `S1`, `U3`, `W3`.

Axioms: `[propext, Classical.choice, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatDecidedUA

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson
open GkatGuardedAlgebra GkatAtomTransfer GkatNullSemantics GkatNullLanguage
open GkatDecidedPullback

variable {A T : Type}

/-! ## The witness, in the Boolean-aware theory -/

/-- Guard-pullback witness, stated in `EquivBA`.  Identical in content to
    `GkatUAIndep.Pullback`, but in the theory that can also reason about guards. -/
def PullbackBA (e : Exp A T) (b c : BExp T) : Prop :=
  ∀ x y : Exp A T,
    EquivBA (.seq e (.ite b x y)) (.ite c (.seq e x) (.seq e y))

/-- A crossing the prefix always establishes has the constant witness `1`. -/
theorem pullbackBA_one_of_must (e : Exp A T) (z : BExp T)
    (hmust : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (mustTest e z) x = true) :
    PullbackBA e z .one := by
  intro x y
  have hdead : UniformExpLempty
      (.seq (.test (.one : BExp T)) (.seq e (.test (.not z)))) := by
    refine ULempty_of_guard_implies ?_ (mustTest_dead e z)
    intro X W v _
    exact hmust X W v
  have hpost := post_all e .one z x y hdead
  refine EquivBA.trans (EquivBA.symm (one_seq (.seq e (.ite z x y)))) ?_
  refine EquivBA.trans hpost ?_
  refine EquivBA.trans (one_seq (.seq e x)) ?_
  exact EquivBA.symm (ite_one (.seq e x) (.seq e y))

/-- A crossing the prefix always refutes has the constant witness `0`. -/
theorem pullbackBA_zero_of_cannot (e : Exp A T) (z : BExp T)
    (hcannot : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (cannotTest e z) x = true) :
    PullbackBA e z .zero := by
  intro x y
  have hguard : ∀ (X : Type) (W : T → X → Bool) (v : X),
      bval W (.and (.one : BExp T) (cannotTest e z)) v = bval W (.one : BExp T) v := by
    intro X W v
    change (true && bval W (cannotTest e z) v) = true
    rw [hcannot X W v]
    rfl
  have hpost := post_decided_false (.one : BExp T) z e x y
  refine EquivBA.trans (EquivBA.symm (one_seq (.seq e (.ite z x y)))) ?_
  refine EquivBA.trans
    (test_seq_guard_congr (.seq e (.ite z x y))
      (fun X W v => (hguard X W v).symm)) ?_
  refine EquivBA.trans hpost ?_
  refine EquivBA.trans (test_seq_guard_congr (.seq e y) hguard) ?_
  refine EquivBA.trans (one_seq (.seq e y)) ?_
  exact EquivBA.symm (EquivBA.base (ite_zero (.seq e x) (.seq e y)))

/-! ## The crossed closed form, in `EquivBA` -/

/-- Closed form of the crossed two-state system under a witness.  This is
    `GkatUAIndep.crossed_closed_form_of_pullback`, re-derived in the Boolean-aware
    theory: substitute `g₁`, apply the witness to reshape `e₀·(b₁ ? e₁·g₀ : f₁)` into a
    guarded prefix of `g₀`, associate (`S1`), flatten (`U3`), and close with `W3`. -/
theorem crossed_closed_form_of_pullbackBA
    {b0 b1 c1 : BExp T} {e0 e1 f0 f1 g0 g1 : Exp A T}
    (hguard : EquivBA (.test (E (.seq e0 e1)) : Exp A T) (.test .zero))
    (hpb : PullbackBA e0 b1 c1)
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq e1 g0) f1)) :
    EquivBA g0
      (.seq (.wh (.and c1 b0) (.seq e0 e1)) (.ite b0 (.seq e0 f1) f0)) := by
  have step : EquivBA g0
      (.ite (.and c1 b0) (.seq (.seq e0 e1) g0) (.ite b0 (.seq e0 f1) f0)) := by
    refine EquivBA.trans h0 ?_
    refine EquivBA.trans
      (EquivBA.ite_c (EquivBA.seq_c (EquivBA.base (Equiv.refl e0)) h1)
        (EquivBA.base (Equiv.refl f0))) ?_
    refine EquivBA.trans
      (EquivBA.ite_c (hpb (.seq e1 g0) f1) (EquivBA.base (Equiv.refl f0))) ?_
    refine EquivBA.trans
      (EquivBA.ite_c
        (EquivBA.ite_c (EquivBA.symm (EquivBA.base (Equiv.s1 e0 e1 g0)))
          (EquivBA.base (Equiv.refl (.seq e0 f1))))
        (EquivBA.base (Equiv.refl f0))) ?_
    exact EquivBA.base (Equiv.u3 c1 b0 (.seq (.seq e0 e1) g0) (.seq e0 f1) f0)
  exact EquivBA.w3_ba hguard step

/-- **UA₂ from base + UA₁ + a witness**, in `EquivBA`. -/
theorem ua2_of_pullbackBA
    {b0 b1 c1 : BExp T} {e0 e1 f0 f1 g0 g1 g0' g1' : Exp A T}
    (hguard : EquivBA (.test (E (.seq e0 e1)) : Exp A T) (.test .zero))
    (hpb : PullbackBA e0 b1 c1)
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq e1 g0) f1))
    (h0' : EquivBA g0' (.ite b0 (.seq e0 g1') f0))
    (h1' : EquivBA g1' (.ite b1 (.seq e1 g0') f1)) :
    EquivBA g0 g0' :=
  EquivBA.trans (crossed_closed_form_of_pullbackBA hguard hpb h0 h1)
    (EquivBA.symm (crossed_closed_form_of_pullbackBA hguard hpb h0' h1'))

/-! ## UA₂ eliminated

    The two headline theorems: at a decided crossing the witness hypothesis disappears,
    so `UA₂` is a theorem of the finite axioms rather than an assumption. -/

/-- **UA₂ eliminated — the prefix always establishes the crossing guard.** -/
theorem ua2_eliminated_of_decided_true
    {b0 b1 : BExp T} {e0 e1 f0 f1 g0 g1 g0' g1' : Exp A T}
    (hmust : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (mustTest e0 b1) x = true)
    (hguard : EquivBA (.test (E (.seq e0 e1)) : Exp A T) (.test .zero))
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq e1 g0) f1))
    (h0' : EquivBA g0' (.ite b0 (.seq e0 g1') f0))
    (h1' : EquivBA g1' (.ite b1 (.seq e1 g0') f1)) :
    EquivBA g0 g0' :=
  ua2_of_pullbackBA hguard (pullbackBA_one_of_must e0 b1 hmust) h0 h1 h0' h1'

/-- **UA₂ eliminated — the prefix always refutes the crossing guard.** -/
theorem ua2_eliminated_of_decided_false
    {b0 b1 : BExp T} {e0 e1 f0 f1 g0 g1 g0' g1' : Exp A T}
    (hcannot : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (cannotTest e0 b1) x = true)
    (hguard : EquivBA (.test (E (.seq e0 e1)) : Exp A T) (.test .zero))
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq e1 g0) f1))
    (h0' : EquivBA g0' (.ite b0 (.seq e0 g1') f0))
    (h1' : EquivBA g1' (.ite b1 (.seq e1 g0') f1)) :
    EquivBA g0 g0' :=
  ua2_of_pullbackBA hguard (pullbackBA_zero_of_cannot e0 b1 hcannot) h0 h1 h0' h1'

/-- The same crossing is also *solvable*: the closed form really is a solution, so a
    decided crossing is solvable-and-unique with no `UA` at all. -/
theorem crossed_solvable_of_decided_true
    {b0 b1 : BExp T} {e0 e1 f0 f1 : Exp A T}
    (hmust : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (mustTest e0 b1) x = true) :
    EquivBA
      (.seq (.wh (.and .one b0) (.seq e0 e1)) (.ite b0 (.seq e0 f1) f0))
      (.ite b0 (.seq e0 (.ite b1 (.seq e1
          (.seq (.wh (.and .one b0) (.seq e0 e1))
            (.ite b0 (.seq e0 f1) f0))) f1)) f0) := by
  have hpb := pullbackBA_one_of_must e0 b1 hmust
  refine EquivBA.trans
    (EquivBA.base (salomaa_solution_exists (.and .one b0) (.seq e0 e1)
      (.ite b0 (.seq e0 f1) f0))) ?_
  refine EquivBA.trans
    (EquivBA.symm (EquivBA.base (Equiv.u3 .one b0
      (.seq (.seq e0 e1)
        (.seq (.wh (.and .one b0) (.seq e0 e1)) (.ite b0 (.seq e0 f1) f0)))
      (.seq e0 f1) f0))) ?_
  refine EquivBA.trans
    (EquivBA.ite_c
      (EquivBA.ite_c
        (EquivBA.base (Equiv.s1 e0 e1
          (.seq (.wh (.and .one b0) (.seq e0 e1)) (.ite b0 (.seq e0 f1) f0))))
        (EquivBA.base (Equiv.refl (.seq e0 f1))))
      (EquivBA.base (Equiv.refl f0))) ?_
  exact EquivBA.ite_c
    (EquivBA.symm (hpb _ f1)) (EquivBA.base (Equiv.refl f0))

/-! ## Non-vacuity

    A decided crossing is not a degenerate case.  Whenever the crossing guard is a
    tautology the prefix trivially establishes it, and the elimination applies to a
    genuinely two-state cycle. -/

theorem mustTest_taut_of_guard_taut (e : Exp A T) (z : BExp T)
    (hz : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W z x = true) :
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (mustTest e z) x = true := by
  intro X W x
  refine (deadTestOver_greatest (mem_splitGuards_head _ _) ?_) X W x rfl
  intro Y W' gs hden
  obtain ⟨a, l⟩ := gs
  obtain ⟨_, hrest⟩ := (den_test_seq_iff W' _ _ a l).mp hden
  obtain ⟨_, hz'⟩ := (den_seq_test_iff W' e _ a l).mp hrest
  change (! bval W' z (lastAtom a l)) = true at hz'
  rw [hz (Y) W' (lastAtom a l)] at hz'
  exact Bool.noConfusion hz'

/-- With a tautologous crossing guard, `UA₂` for the crossed system is unconditionally a
    theorem of the finite axioms. -/
theorem ua2_eliminated_of_taut_crossing
    {b0 b1 : BExp T} {e0 e1 f0 f1 g0 g1 g0' g1' : Exp A T}
    (hz : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W b1 x = true)
    (hguard : EquivBA (.test (E (.seq e0 e1)) : Exp A T) (.test .zero))
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq e1 g0) f1))
    (h0' : EquivBA g0' (.ite b0 (.seq e0 g1') f0))
    (h1' : EquivBA g1' (.ite b1 (.seq e1 g0') f1)) :
    EquivBA g0 g0' :=
  ua2_eliminated_of_decided_true (mustTest_taut_of_guard_taut e0 b1 hz)
    hguard h0 h1 h0' h1'

/-! ## Exactness: an undecided crossing has *no* witness at all

    The constructions above produce a *constant* witness on the decided regions.  The
    obvious worry is that a cleverer, non-constant guard might work on the residue.  It
    cannot: a witness forces `e·z ≡ c·e`, and that equation already fails pointwise at any
    atom from which `e` can reach both sides of `z`.

    So `decided` is not a convenient sufficient condition — it is exactly the condition
    under which the guard-pullback witness of `GkatUAIndependenceProofs` exists. -/

/-- A witness collapses to the commuting square `e·z ≡ c·e` (the probe at `(1,0)`). -/
theorem pullbackBA_square {e : Exp A T} {z c : BExp T} (hpb : PullbackBA e z c) :
    EquivBA (.seq e (.test z)) (.seq (.test c) e) := by
  refine EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.refl e)) (test_eq_ite_one_zero z)) ?_
  refine EquivBA.trans (hpb (.test .one) (.test .zero)) ?_
  refine EquivBA.trans (EquivBA.ite_c (seq_one e) (seq_zero_right e)) ?_
  exact ite_zero_else c e

/-- **No witness at an undecided atom.**  If `e` can reach both sides of `z` from `x`,
    then no guard `c` whatsoever satisfies `PullbackBA e z c`. -/
theorem no_pullbackBA_of_undecided {e : Exp A T} {z c : BExp T}
    (hpb : PullbackBA e z c)
    {X : Type} {W : T → X → Bool} {x : X}
    (hmust : bval W (mustTest e z) x = false)
    (hcannot : bval W (cannotTest e z) x = false) : False := by
  have hsquare := pullbackBA_square hpb
  -- first extension: a run of `e` landing outside `z`
  obtain ⟨Y₁, W₁, emb₁, l₁, hagree₁, hden₁⟩ :=
    exists_den_at_atom _ (.seq e (.test (.not z)))
      (mem_splitGuards_prim _ _) W x hmust
  have hcannot₁ : bval W₁ (cannotTest e z) (emb₁ x) = false := by
    rw [bval_relabel (W := W) (W' := W₁) (f := emb₁) (cannotTest e z)
      (fun _ _ _ => hagree₁ _ _) x]
    exact hcannot
  -- second extension, on top of the first: a run of `e` landing inside `z`
  obtain ⟨Y₂, W₂, emb₂, l₂, hagree₂, hden₂⟩ :=
    exists_den_at_atom _ (.seq e (.test z))
      (mem_splitGuards_prim _ _) W₁ (emb₁ x) hcannot₁
  -- transport the first run into the second carrier
  have hden₁' : den W₂ (.seq e (.test (.not z)))
      (emb₂ (emb₁ x), mapAtoms emb₂ l₁) :=
    den_relabel (W := W₁) (W' := W₂) (f := emb₂) (.seq e (.test (.not z)))
      (fun _ _ _ => hagree₂ _ _) (emb₁ x) l₁ hden₁
  -- the witness forces `c` to hold here …
  have hc : bval W₂ c (emb₂ (emb₁ x)) = true := by
    have := (sound_BA W₂ hsquare (emb₂ (emb₁ x), l₂)).mp hden₂
    exact ((den_test_seq_iff W₂ c e _ l₂).mp this).1
  -- … and then every run of `e` from here must land inside `z`
  obtain ⟨he, hnz⟩ := (den_seq_test_iff W₂ e (.not z) _ (mapAtoms emb₂ l₁)).mp hden₁'
  have hin : den W₂ (.seq e (.test z))
      (emb₂ (emb₁ x), mapAtoms emb₂ l₁) :=
    (sound_BA W₂ hsquare (emb₂ (emb₁ x), mapAtoms emb₂ l₁)).mpr
      ((den_test_seq_iff W₂ c e _ (mapAtoms emb₂ l₁)).mpr ⟨hc, he⟩)
  have hz := ((den_seq_test_iff W₂ e z _ (mapAtoms emb₂ l₁)).mp hin).2
  change (! bval W₂ z (lastAtom (emb₂ (emb₁ x)) (mapAtoms emb₂ l₁))) = true at hnz
  rw [hz] at hnz
  exact Bool.noConfusion hnz

/-- **The exact characterisation.**  Over the atoms of a fixed valuation, a guard-pullback
    witness for `(e, z)` exists only where the crossing is decided.  Combined with
    `pullbackBA_one_of_must` / `pullbackBA_zero_of_cannot`, "decided" is necessary and
    sufficient — the residue of `pullback_trichotomy` is irreducible for *any* witness,
    not merely for constant ones. -/
theorem pullbackBA_forces_decided {e : Exp A T} {z c : BExp T}
    (hpb : PullbackBA e z c)
    {X : Type} (W : T → X → Bool) (x : X) :
    bval W (mustTest e z) x = true ∨ bval W (cannotTest e z) x = true := by
  cases hmust : bval W (mustTest e z) x with
  | true => exact Or.inl rfl
  | false =>
      cases hcannot : bval W (cannotTest e z) x with
      | true => exact Or.inr rfl
      | false => exact absurd (no_pullbackBA_of_undecided hpb hmust hcannot) (fun c => c)

#print axioms pullbackBA_one_of_must
#print axioms pullbackBA_zero_of_cannot
#print axioms crossed_closed_form_of_pullbackBA
#print axioms ua2_eliminated_of_decided_true
#print axioms ua2_eliminated_of_decided_false
#print axioms crossed_solvable_of_decided_true
#print axioms ua2_eliminated_of_taut_crossing
/-- **A concrete crossing with no witness at all.**  An action followed by a primitive
    test: the action can land on any atom, so the crossing is undecided everywhere and no
    guard whatsoever is a pullback witness.  This is the route-closure made concrete —
    `ua2_of_pullback` cannot be the mechanism for `UA₂` at crossings of this shape, and
    crossings of this shape are exactly what a productive cycle produces. -/
theorem no_witness_for_action_crossing (c : BExp Unit) :
    ¬ PullbackBA (Exp.act () : Exp Unit Unit) (.prim ()) c := by
  intro hpb
  exact no_pullbackBA_of_undecided hpb
    action_crossing_undecided.1 action_crossing_undecided.2

#print axioms pullbackBA_square
#print axioms no_pullbackBA_of_undecided
#print axioms pullbackBA_forces_decided
#print axioms no_witness_for_action_crossing

end GkatDecidedUA
