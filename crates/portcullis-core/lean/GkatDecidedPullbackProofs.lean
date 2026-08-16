import GkatNullLanguageProofs

/-!
# Where UA is actually needed: the undecided residue

`GkatUAIndependenceProofs` locates the whole gap between `UA₂` and `UA₁` in a single
object, the **guard-pullback witness**

    Pullback e b c  :≡  ∀ x y,  e·(b ? x : y) ≡ c ? (e·x) : (e·y)

and `GkatPullbackWitnessProofs` shows such a `c` need not exist as a guard.  This file
says exactly *when* it does exist, and proves that the leftover really is irreducible.

## The trichotomy

Fix a prefix `e` and a crossing guard `z`.  Every atom falls into one of three regions,
each of them a syntactic guard built from the finite Boolean cells of `e` and `z`:

| region | meaning | witness |
|---|---|---|
| `mustTest e z`   | `e` can never land outside `z` | `c = 1` |
| `cannotTest e z` | `e` can never land inside `z`  | `c = 0` |
| the residue      | `e` can land on both sides     | none (see below) |

`pullback_trichotomy` decomposes `b·e·(z ? p : q)` along exactly these three regions,
and on the first two the branch is *deleted* inside the finite theory — no `UA`, no
uniqueness principle beyond `W3`.  The deletion is `GkatNullLanguage.post_all`.

`undecided_residue_branches` proves the third region is not an artefact of the proof:
on it, `e` demonstrably reaches both sides of `z`, so no constant witness can exist
there.  This is the precise sense in which **global uniqueness was never load-bearing
for decided control flow** — what `UA` is still doing lives entirely in the residue,
where the prefix genuinely branches on the crossing guard.

Axioms: `[propext, Classical.choice, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatDecidedPullback

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson
open GkatGuardedAlgebra GkatAtomTransfer GkatNullSemantics GkatNullLanguage

variable {A T : Type}

/-! ## The two decided regions -/

/-- The region from which `e` **must** land inside `z`. -/
noncomputable def mustTest (e : Exp A T) (z : BExp T) : BExp T :=
  deadTestOver (splitGuards .one (.seq e (.test (.not z))))
    (.seq e (.test (.not z)))

/-- The region from which `e` **cannot** land inside `z`. -/
noncomputable def cannotTest (e : Exp A T) (z : BExp T) : BExp T :=
  deadTestOver (splitGuards .one (.seq e (.test z))) (.seq e (.test z))

theorem mustTest_dead (e : Exp A T) (z : BExp T) :
    UniformExpLempty (.seq (.test (mustTest e z)) (.seq e (.test (.not z)))) :=
  deadTestOver_dead _ _

theorem cannotTest_dead (e : Exp A T) (z : BExp T) :
    UniformExpLempty (.seq (.test (cannotTest e z)) (.seq e (.test z))) :=
  deadTestOver_dead _ _

/-! ## Splitting an assertion along a region -/

/-- Any asserted expression splits into its two subregions, each carrying the full
    region that selects it.  `U1`, `U4` and Boolean congruence only. -/
theorem region_split (b r : BExp T) (m : Exp A T) :
    EquivBA (.seq (.test b) m)
      (.ite (.and b r) (.seq (.test (.and b r)) m)
        (.seq (.test (.and b (.not r))) m)) := by
  have hguard : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and (.not (.and b r)) b) x = bval W (.and b (.not r)) x := by
    intro X W x
    simp only [bval]
    cases bval W b x <;> cases bval W r x <;> rfl
  refine EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (EquivBA.symm (EquivBA.base (Equiv.u1 r m)))) ?_
  refine EquivBA.trans (test_seq_ite b r m m) ?_
  refine EquivBA.trans
    (EquivBA.base (Equiv.u4 (.and b r) m (.seq (.test b) m))) ?_
  refine EquivBA.trans
    (ite_restrict_else (.and b r) (.seq (.test (.and b r)) m)
      (.seq (.test b) m)) ?_
  refine EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ?_
  exact EquivBA.trans (test_seq_merge (.not (.and b r)) b m)
    (test_seq_guard_congr m hguard)

/-! ## The decided cases: the witness is a constant -/

/-- On `mustTest e z` the crossing branch collapses to its then arm: the pullback
    witness exists and is the constant guard `1`. -/
theorem post_decided_true (b z : BExp T) (e p q : Exp A T) :
    EquivBA (.seq (.test (.and b (mustTest e z))) (.seq e (.ite z p q)))
      (.seq (.test (.and b (mustTest e z))) (.seq e p)) := by
  refine post_all e (.and b (mustTest e z)) z p q ?_
  refine ULempty_of_guard_implies ?_ (mustTest_dead e z)
  intro X W x hx
  change (bval W b x && bval W (mustTest e z) x) = true at hx
  cases hv : bval W (mustTest e z) x with
  | true => rfl
  | false => rw [hv] at hx; exact absurd hx (by simp)

/-- On `cannotTest e z` the crossing branch collapses to its else arm: the pullback
    witness exists and is the constant guard `0`. -/
theorem post_decided_false (b z : BExp T) (e p q : Exp A T) :
    EquivBA (.seq (.test (.and b (cannotTest e z))) (.seq e (.ite z p q)))
      (.seq (.test (.and b (cannotTest e z))) (.seq e q)) := by
  have hnn : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W z x = bval W (.not (.not z)) x := by
    intro X W x
    simp only [bval]
    cases bval W z x <;> rfl
  have hdead : UniformExpLempty
      (.seq (.test (.and b (cannotTest e z)))
        (.seq e (.test (.not (.not z))))) := by
    refine ULempty_congr
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (EquivBA.baTest hnn))) ?_
    refine ULempty_of_guard_implies ?_ (cannotTest_dead e z)
    intro X W x hx
    change (bval W b x && bval W (cannotTest e z) x) = true at hx
    cases hv : bval W (cannotTest e z) x with
    | true => rfl
    | false => rw [hv] at hx; exact absurd hx (by simp)
  refine EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (EquivBA.base (Equiv.u2 z p q)))) ?_
  exact post_all e (.and b (cannotTest e z)) (.not z) q p hdead

/-- The decided-true case, stated in the shape of `GkatUAIndep.Pullback`: the witness is
    literally the constant guard `1`. -/
theorem pullback_witness_one (b z : BExp T) (e p q : Exp A T) :
    EquivBA (.seq (.test (.and b (mustTest e z))) (.seq e (.ite z p q)))
      (.seq (.test (.and b (mustTest e z)))
        (.ite .one (.seq e p) (.seq e q))) :=
  EquivBA.trans (post_decided_true b z e p q)
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (EquivBA.symm (ite_one (.seq e p) (.seq e q))))

/-- The decided-false case, stated with the constant witness `0`. -/
theorem pullback_witness_zero (b z : BExp T) (e p q : Exp A T) :
    EquivBA (.seq (.test (.and b (cannotTest e z))) (.seq e (.ite z p q)))
      (.seq (.test (.and b (cannotTest e z)))
        (.ite .zero (.seq e p) (.seq e q))) :=
  EquivBA.trans (post_decided_false b z e p q)
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (EquivBA.symm (EquivBA.base (ite_zero (.seq e p) (.seq e q)))))

/-! ## The trichotomy -/

/-- **Every crossing splits into two eliminable regions and a residue.**  The first two
    branches have had the crossing guard deleted inside the finite theory; only the
    third still carries it. -/
theorem pullback_trichotomy (b z : BExp T) (e p q : Exp A T) :
    EquivBA (.seq (.test b) (.seq e (.ite z p q)))
      (.ite (.and b (mustTest e z))
        (.seq (.test (.and b (mustTest e z))) (.seq e p))
        (.ite (.and (.and b (.not (mustTest e z))) (cannotTest e z))
          (.seq (.test (.and (.and b (.not (mustTest e z))) (cannotTest e z)))
            (.seq e q))
          (.seq (.test (.and (.and b (.not (mustTest e z)))
              (.not (cannotTest e z))))
            (.seq e (.ite z p q))))) := by
  refine EquivBA.trans
    (region_split b (mustTest e z) (.seq e (.ite z p q))) ?_
  refine EquivBA.ite_c (post_decided_true b z e p q) ?_
  refine EquivBA.trans
    (region_split (.and b (.not (mustTest e z))) (cannotTest e z)
      (.seq e (.ite z p q))) ?_
  exact EquivBA.ite_c
    (post_decided_false (.and b (.not (mustTest e z))) z e p q)
    (EquivBA.base (Equiv.refl _))

/-! ## The residue is irreducible -/

/-- **Sharpness.**  On the residue the prefix demonstrably reaches *both* sides of the
    crossing guard.  So no constant witness can work there, and the residue is not an
    artefact of how the decomposition was chosen: it is exactly the set of atoms at
    which `e` genuinely branches on `z`. -/
theorem undecided_residue_branches (e : Exp A T) (z : BExp T)
    {X : Type} (W : T → X → Bool) (x : X)
    (hmust : bval W (mustTest e z) x = false)
    (hcannot : bval W (cannotTest e z) x = false) :
    (∃ (Y : Type) (W' : T → Y → Bool) (emb : X → Y) (l : List (A × Y)),
        (∀ (t : T) (u : X), W' t (emb u) = W t u) ∧
        den W' (.seq e (.test (.not z))) (emb x, l)) ∧
      (∃ (Y : Type) (W' : T → Y → Bool) (emb : X → Y) (l : List (A × Y)),
        (∀ (t : T) (u : X), W' t (emb u) = W t u) ∧
        den W' (.seq e (.test z)) (emb x, l)) := by
  constructor
  · exact exists_den_at_atom _ (.seq e (.test (.not z)))
      (mem_splitGuards_prim _ _) W x hmust
  · exact exists_den_at_atom _ (.seq e (.test z))
      (mem_splitGuards_prim _ _) W x hcannot

/-- Complementary sharpness: outside the residue the decomposition is *exhaustive* —
    the two decided regions plus the residue cover everything, by construction. -/
theorem trichotomy_covers (b : BExp T) (e : Exp A T) (z : BExp T)
    {X : Type} (W : T → X → Bool) (x : X) (hb : bval W b x = true) :
    bval W (.and b (mustTest e z)) x = true ∨
      bval W (.and (.and b (.not (mustTest e z))) (cannotTest e z)) x = true ∨
      bval W (.and (.and b (.not (mustTest e z)))
        (.not (cannotTest e z))) x = true := by
  cases hmust : bval W (mustTest e z) x with
  | true =>
      refine Or.inl ?_
      change (bval W b x && bval W (mustTest e z) x) = true
      rw [hb, hmust]
      rfl
  | false =>
      cases hcannot : bval W (cannotTest e z) x with
      | true =>
          refine Or.inr (Or.inl ?_)
          change ((bval W b x && (! bval W (mustTest e z) x)) &&
            bval W (cannotTest e z) x) = true
          rw [hb, hmust, hcannot]
          rfl
      | false =>
          refine Or.inr (Or.inr ?_)
          change ((bval W b x && (! bval W (mustTest e z) x)) &&
            (! bval W (cannotTest e z) x)) = true
          rw [hb, hmust, hcannot]
          rfl

/-! ## Non-vacuity of the residue -/

/-- A single witness landing outside `z` already refutes membership in `mustTest`. -/
theorem mustTest_false_of_den {e : Exp A T} {z : BExp T} {X : Type}
    {W : T → X → Bool} {x : X} {l : List (A × X)}
    (h : den W (.seq e (.test (.not z))) (x, l)) :
    bval W (mustTest e z) x = false := by
  cases hv : bval W (mustTest e z) x with
  | false => rfl
  | true =>
      exact absurd (mustTest_dead e z X W (x, l)
        ((den_test_seq_iff W _ _ x l).mpr ⟨hv, h⟩)) (fun c => c)

/-- Dually for `cannotTest`. -/
theorem cannotTest_false_of_den {e : Exp A T} {z : BExp T} {X : Type}
    {W : T → X → Bool} {x : X} {l : List (A × X)}
    (h : den W (.seq e (.test z)) (x, l)) :
    bval W (cannotTest e z) x = false := by
  cases hv : bval W (cannotTest e z) x with
  | false => rfl
  | true =>
      exact absurd (cannotTest_dead e z X W (x, l)
        ((den_test_seq_iff W _ _ x l).mpr ⟨hv, h⟩)) (fun c => c)

/-- **The residue is inhabited.**  An action can land on any atom, so a primitive test
    crossing a single action is undecided *everywhere*: neither constant witness works,
    and the trichotomy's third branch is not empty. -/
theorem action_crossing_undecided :
    bval (fun (_ : Unit) (v : Bool) => v)
        (mustTest (Exp.act () : Exp Unit Unit) (.prim ())) true = false ∧
      bval (fun (_ : Unit) (v : Bool) => v)
        (cannotTest (Exp.act () : Exp Unit Unit) (.prim ())) true = false := by
  constructor
  · exact mustTest_false_of_den (l := [((), false)])
      ⟨[((), false)], [], rfl, ⟨true, false, rfl⟩, rfl, rfl⟩
  · exact cannotTest_false_of_den (l := [((), true)])
      ⟨[((), true)], [], rfl, ⟨true, true, rfl⟩, rfl, rfl⟩

#print axioms region_split
#print axioms post_decided_true
#print axioms post_decided_false
#print axioms pullback_witness_one
#print axioms pullback_witness_zero
#print axioms pullback_trichotomy
#print axioms undecided_residue_branches
#print axioms trichotomy_covers
#print axioms action_crossing_undecided

end GkatDecidedPullback
