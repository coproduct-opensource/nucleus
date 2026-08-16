import GkatGuardedAlgebraProofs

/-!
# Atom transfer and the finite dead-cell test

The null-language argument has to turn a *semantic* fact ("no guarded string of `e`
starts here") into a *syntactic* Boolean expression that the finite axioms can rewrite
with.  Two ingredients are needed.

1. **Atom transfer.**  `den` only inspects the primitive tests occurring in the
   expression, so a witness living in one carrier can be replayed in another as long as
   the relabelling preserves those tests.  `den_relabel` is that statement; it is what
   lets a witness found at *some* atom of a Boolean cell be produced at *this* atom.

2. **The dead cell test.**  Over any finite list of guards `L`, `deadTestOver L e` is
   the disjunction of the cells on which `e` is uniformly empty.  It satisfies the two
   directions the induction needs: it is itself dead for `e` (`deadTestOver_dead`), it
   is implied by every dead assertion whose guard is listed (`deadTestOver_greatest`),
   and outside it a witness exists *at the given atom* (`exists_den_at_atom`).

Nothing here uses any GKAT axiom: this is pure model theory of guarded strings.

Axioms: `[propext, Classical.choice, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatAtomTransfer

open GkatSyntax GkatGS GkatFaithful GkatThompson

variable {A T : Type}

/-! ## Primitive tests occurring in an expression -/

/-- Primitive tests occurring in a Boolean expression. -/
def primTestsB : BExp T → List T
  | .zero => []
  | .one => []
  | .prim t => [t]
  | .and b c => primTestsB b ++ primTestsB c
  | .or b c => primTestsB b ++ primTestsB c
  | .not b => primTestsB b

/-- Primitive tests occurring in a program. -/
def primTests : Exp A T → List T
  | .act _ => []
  | .test b => primTestsB b
  | .seq e f => primTests e ++ primTests f
  | .ite b e f => primTestsB b ++ (primTests e ++ primTests f)
  | .wh b e => primTestsB b ++ primTests e

/-! ## Atom relabelling -/

/-- A relabelling `f` preserves every test in `ts`. -/
def MapAgrees {X Y : Type} (ts : List T) (W : T → X → Bool) (W' : T → Y → Bool)
    (f : X → Y) : Prop :=
  ∀ t ∈ ts, ∀ x : X, W' t (f x) = W t x

theorem MapAgrees.left {X Y : Type} {W : T → X → Bool} {W' : T → Y → Bool}
    {f : X → Y} {ts us : List T} (h : MapAgrees (ts ++ us) W W' f) :
    MapAgrees ts W W' f := by
  intro t ht x
  exact h t (List.mem_append_left _ ht) x

theorem MapAgrees.right {X Y : Type} {W : T → X → Bool} {W' : T → Y → Bool}
    {f : X → Y} {ts us : List T} (h : MapAgrees (ts ++ us) W W' f) :
    MapAgrees us W W' f := by
  intro t ht x
  exact h t (List.mem_append_right _ ht) x

/-- Relabel the atoms of a guarded-string tail. -/
def mapAtoms {X Y : Type} (f : X → Y) : List (A × X) → List (A × Y) :=
  List.map (fun step => (step.1, f step.2))

@[simp] theorem mapAtoms_nil {X Y : Type} (f : X → Y) :
    mapAtoms (A := A) f [] = [] := rfl

@[simp] theorem mapAtoms_cons {X Y : Type} (f : X → Y) (step : A × X)
    (l : List (A × X)) :
    mapAtoms f (step :: l) = (step.1, f step.2) :: mapAtoms f l := rfl

theorem mapAtoms_append {X Y : Type} (f : X → Y) (l₁ l₂ : List (A × X)) :
    mapAtoms f (l₁ ++ l₂) = mapAtoms f l₁ ++ mapAtoms f l₂ := by
  induction l₁ with
  | nil => rfl
  | cons step l ih => simpa [mapAtoms] using ih

theorem lastAtom_mapAtoms {X Y : Type} (f : X → Y) (a : X) (l : List (A × X)) :
    lastAtom (f a) (mapAtoms f l) = f (lastAtom a l) := by
  induction l generalizing a with
  | nil => rfl
  | cons step l ih => exact ih step.2

/-- Boolean evaluation only inspects the primitive tests of the expression. -/
theorem bval_relabel {X Y : Type} {W : T → X → Bool} {W' : T → Y → Bool} {f : X → Y}
    (b : BExp T) (h : MapAgrees (primTestsB b) W W' f) (x : X) :
    bval W' b (f x) = bval W b x := by
  induction b with
  | zero => rfl
  | one => rfl
  | prim t => exact h t (List.Mem.head _) x
  | and b c ihb ihc =>
      change (bval W' b (f x) && bval W' c (f x)) = (bval W b x && bval W c x)
      rw [ihb h.left, ihc h.right]
  | or b c ihb ihc =>
      change (bval W' b (f x) || bval W' c (f x)) = (bval W b x || bval W c x)
      rw [ihb h.left, ihc h.right]
  | not b ih =>
      change (! bval W' b (f x)) = (! bval W b x)
      rw [ih h]

/-- **Atom transfer.**  A guarded string of `e` may be replayed under any relabelling
    that preserves the primitive tests occurring in `e`.  Together with a fresh sum
    carrier this is what moves a witness from the atom where it happened to be found to
    the atom where it is needed. -/
theorem den_relabel {X Y : Type} {W : T → X → Bool} {W' : T → Y → Bool} {f : X → Y}
    (e : Exp A T) (h : MapAgrees (primTests e) W W' f) :
    ∀ (a : X) (l : List (A × X)), den W e (a, l) → den W' e (f a, mapAtoms f l) := by
  induction e with
  | act p =>
      intro a l hden
      obtain ⟨u, v, heq⟩ := hden
      have hl : l = [(p, v)] := congrArg Prod.snd heq
      have ha : a = u := congrArg Prod.fst heq
      subst hl; subst ha
      exact ⟨f a, f v, rfl⟩
  | test b =>
      intro a l hden
      obtain ⟨hb, hl⟩ := hden
      subst hl
      exact ⟨by rw [bval_relabel b h a]; exact hb, rfl⟩
  | seq e g ihe ihg =>
      intro a l hden
      obtain ⟨l₁, l₂, hsplit, he, hg⟩ := hden
      subst hsplit
      refine ⟨mapAtoms f l₁, mapAtoms f l₂, mapAtoms_append f l₁ l₂, ?_, ?_⟩
      · exact ihe h.left a l₁ he
      · have hmapped := ihg h.right (lastAtom a l₁) l₂ hg
        rw [← lastAtom_mapAtoms f a l₁] at hmapped
        exact hmapped
  | ite b e g ihe ihg =>
      intro a l hden
      have hb := bval_relabel b (MapAgrees.left h) a
      rcases hden with ⟨htrue, he⟩ | ⟨hfalse, hg⟩
      · exact Or.inl ⟨by rw [hb]; exact htrue,
          ihe (MapAgrees.left (MapAgrees.right h)) a l he⟩
      · exact Or.inr ⟨by rw [hb]; exact hfalse,
          ihg (MapAgrees.right (MapAgrees.right h)) a l hg⟩
  | wh b e ihe =>
      have hb : ∀ (u : X), bval W' b (f u) = bval W b u :=
        fun u => bval_relabel b (MapAgrees.left h) u
      have key : ∀ gs : GS A X, InLoop W b (den W e) gs →
          InLoop W' b (den W' e) (f gs.1, mapAtoms f gs.2) := by
        intro gs hgs
        induction hgs with
        | exit a hexit =>
            exact InLoop.exit (f a) (by rw [hb a]; exact hexit)
        | step a l₁ rest hstep hden _ ih =>
            have hnext : InLoop W' b (den W' e)
                (lastAtom (f a) (mapAtoms f l₁), mapAtoms f rest) := by
              rw [lastAtom_mapAtoms]
              exact ih
            have := InLoop.step (V := W') (b := b) (dene := den W' e)
              (f a) (mapAtoms f l₁) (mapAtoms f rest)
              (by rw [hb a]; exact hstep)
              (ihe (MapAgrees.right h) a l₁ hden) hnext
            rw [mapAtoms_append]
            exact this
      intro a l hden
      exact key (a, l) hden

/-! ## Elementary `den` shapes -/

theorem den_test_seq_iff {X : Type} (W : T → X → Bool) (b : BExp T) (e : Exp A T)
    (a : X) (l : List (A × X)) :
    den W (.seq (.test b) e) (a, l) ↔ (bval W b a = true ∧ den W e (a, l)) := by
  constructor
  · rintro ⟨l₁, l₂, hsplit, ⟨hb, hl₁⟩, he⟩
    subst hl₁
    simp only [List.nil_append] at hsplit
    subst hsplit
    exact ⟨hb, he⟩
  · rintro ⟨hb, he⟩
    exact ⟨[], l, rfl, ⟨hb, rfl⟩, he⟩

theorem den_seq_test_iff {X : Type} (W : T → X → Bool) (e : Exp A T) (c : BExp T)
    (a : X) (l : List (A × X)) :
    den W (.seq e (.test c)) (a, l) ↔
      (den W e (a, l) ∧ bval W c (lastAtom a l) = true) := by
  constructor
  · rintro ⟨l₁, l₂, hsplit, he, ⟨hc, hl₂⟩⟩
    subst hl₂
    simp only [List.append_nil] at hsplit
    subst hsplit
    exact ⟨he, hc⟩
  · rintro ⟨he, hc⟩
    exact ⟨l, [], (List.append_nil l).symm, he, ⟨hc, rfl⟩⟩

theorem den_seq_of {X : Type} {W : T → X → Bool} {e f : Exp A T}
    {a : X} {l₁ l₂ : List (A × X)}
    (he : den W e (a, l₁)) (hf : den W f (lastAtom a l₁, l₂)) :
    den W (.seq e f) (a, l₁ ++ l₂) :=
  ⟨l₁, l₂, rfl, he, hf⟩

/-! ## The finite dead-cell test -/

/-- The Boolean cells of `L` on which `e` has no guarded string at all. -/
noncomputable def deadCellList (L : List (BExp T)) (e : Exp A T) :
    List (List (BExp T × Bool)) :=
  (guardAssignments L).filter (fun decisions =>
    @decide (UniformExpLempty (Exp.seq (.test (guardCell decisions)) e))
      (Classical.propDecidable _))

/-- The finite Boolean region on which `e` is uniformly empty, as a syntactic guard.
    This is the object that lets a purely semantic deadness fact be *rewritten with*. -/
noncomputable def deadTestOver (L : List (BExp T)) (e : Exp A T) : BExp T :=
  guardsOr ((deadCellList L e).map guardCell)

theorem mem_deadCellList {L : List (BExp T)} {e : Exp A T}
    {decisions : List (BExp T × Bool)} (h : decisions ∈ deadCellList L e) :
    decisions ∈ guardAssignments L ∧
      UniformExpLempty (Exp.seq (.test (guardCell decisions)) e) := by
  simp only [deadCellList, List.mem_filter, decide_eq_true_eq] at h
  exact h

theorem mem_deadCellList_of {L : List (BExp T)} {e : Exp A T}
    {decisions : List (BExp T × Bool)} (hmem : decisions ∈ guardAssignments L)
    (hdead : UniformExpLempty (Exp.seq (.test (guardCell decisions)) e)) :
    decisions ∈ deadCellList L e := by
  simp only [deadCellList, List.mem_filter, decide_eq_true_eq]
  exact ⟨hmem, hdead⟩

/-- A satisfied finite disjunction has a satisfied disjunct. -/
theorem bval_guardsOr_exists {guards : List (BExp T)} {X : Type}
    (W : T → X → Bool) (x : X) (h : bval W (guardsOr guards) x = true) :
    ∃ guard ∈ guards, bval W guard x = true := by
  induction guards with
  | nil => exact absurd h (by simp [guardsOr, bval])
  | cons head guards ih =>
      change (bval W head x || bval W (guardsOr guards) x) = true at h
      cases hhead : bval W head x with
      | true => exact ⟨head, List.Mem.head _, hhead⟩
      | false =>
          rw [hhead, Bool.false_or] at h
          obtain ⟨guard, hguard, hval⟩ := ih h
          exact ⟨guard, List.Mem.tail _ hguard, hval⟩

/-- A cell over `L` decides every guard listed in `L`, uniformly over all carriers. -/
theorem guardCell_decides {L : List (BExp T)} {decisions : List (BExp T × Bool)}
    (hassignment : IsGuardAssignment L decisions) {b : BExp T} (hb : b ∈ L) :
    (∀ (X : Type) (W : T → X → Bool) (x : X),
        bval W (guardCell decisions) x = true → bval W b x = true) ∨
      (∀ (X : Type) (W : T → X → Bool) (x : X),
        bval W (guardCell decisions) x = true → bval W b x = false) := by
  induction hassignment with
  | nil => exact absurd hb (by simp)
  | @cons guards decisions head bit _ ih =>
      rcases List.mem_cons.mp hb with rfl | htail
      · cases bit with
        | true =>
            exact Or.inl (fun X W x hcell =>
              guardCell_positive_implies W x b decisions hcell)
        | false =>
            exact Or.inr (fun X W x hcell =>
              guardCell_negative_implies W x b decisions hcell)
      · rcases ih htail with hpos | hneg
        · exact Or.inl (fun X W x hcell =>
            hpos X W x (guardCell_tail_implies W x (head, bit) decisions hcell))
        · exact Or.inr (fun X W x hcell =>
            hneg X W x (guardCell_tail_implies W x (head, bit) decisions hcell))

/-- **(D1)** The dead region really is dead for `e`. -/
theorem deadTestOver_dead (L : List (BExp T)) (e : Exp A T) :
    UniformExpLempty (Exp.seq (.test (deadTestOver L e)) e) := by
  intro X W gs hden
  obtain ⟨a, l⟩ := gs
  obtain ⟨hz, he⟩ := (den_test_seq_iff W _ e a l).mp hden
  obtain ⟨guard, hguard, hval⟩ := bval_guardsOr_exists W a hz
  obtain ⟨decisions, hdecisions, rfl⟩ := List.mem_map.mp hguard
  exact (mem_deadCellList hdecisions).2 X W (a, l)
    ((den_test_seq_iff W _ e a l).mpr ⟨hval, he⟩)

/-- **(D2)** Every listed guard that is dead for `e` is contained in the dead region.
    In particular the dead region is the greatest such guard among those listed. -/
theorem deadTestOver_greatest {L : List (BExp T)} {e : Exp A T} {b : BExp T}
    (hb : b ∈ L) (hdead : UniformExpLempty (Exp.seq (.test b) e)) :
    GuardImplies b (deadTestOver L e) := by
  intro X W x hx
  obtain ⟨decisions, hmem, hcell⟩ := guardAssignments_exhaustive W x L
  have hdeadCell : UniformExpLempty (Exp.seq (.test (guardCell decisions)) e) := by
    intro X' W' gs' hden'
    obtain ⟨a', l'⟩ := gs'
    obtain ⟨hcell', he'⟩ := (den_test_seq_iff W' _ e a' l').mp hden'
    rcases guardCell_decides (guardAssignments_sound hmem) hb with hpos | hneg
    · exact hdead X' W' (a', l')
        ((den_test_seq_iff W' b e a' l').mpr ⟨hpos X' W' a' hcell', he'⟩)
    · exact absurd hx (by rw [hneg X W x hcell]; exact Bool.noConfusion)
  exact bval_guardsOr_of_mem
    (List.mem_map_of_mem (mem_deadCellList_of hmem hdeadCell)) X W x hcell

/-- **(D3)** Outside the dead region a witness exists *at the given atom*: the carrier
    is extended by a fresh summand and the witness found elsewhere in the same Boolean
    cell is transported onto this atom.  This is the step that makes the finite cell
    decomposition usable as a rewriting device rather than merely a classification. -/
theorem exists_den_at_atom (L : List (BExp T)) (e : Exp A T)
    (hL : ∀ t ∈ primTests e, (BExp.prim t) ∈ L)
    {X : Type} (W : T → X → Bool) (x : X)
    (hx : bval W (deadTestOver L e) x = false) :
    ∃ (Y : Type) (W' : T → Y → Bool) (g : X → Y) (l : List (A × Y)),
      (∀ (t : T) (u : X), W' t (g u) = W t u) ∧ den W' e (g x, l) := by
  classical
  obtain ⟨decisions, hmem, hcell⟩ := guardAssignments_exhaustive W x L
  have hnotdead : ¬ UniformExpLempty (Exp.seq (.test (guardCell decisions)) e) := by
    intro hdead
    have : bval W (deadTestOver L e) x = true :=
      bval_guardsOr_of_mem
        (List.mem_map_of_mem (mem_deadCellList_of hmem hdead)) X W x hcell
    rw [hx] at this
    exact Bool.noConfusion this
  have hwitness : ∃ (X₀ : Type) (W₀ : T → X₀ → Bool) (gs₀ : GS A X₀),
      den W₀ (Exp.seq (.test (guardCell decisions)) e) gs₀ :=
    Classical.byContradiction (fun hcontra =>
      hnotdead (fun X₀ W₀ gs₀ hden => hcontra ⟨X₀, W₀, gs₀, hden⟩))
  obtain ⟨X₀, W₀, gs₀, hden₀⟩ := hwitness
  obtain ⟨a₀, l₀⟩ := gs₀
  obtain ⟨hcell₀, he₀⟩ := (den_test_seq_iff W₀ _ e a₀ l₀).mp hden₀
  refine ⟨Sum X X₀, fun t => Sum.elim (W t) (W₀ t), Sum.inl, ?_, ?_, ?_⟩
  · exact mapAtoms (fun u => if u = a₀ then Sum.inl x else Sum.inr u) l₀
  · intro t u; rfl
  · have hagree : MapAgrees (primTests e) W₀ (fun t => Sum.elim (W t) (W₀ t))
        (fun u => if u = a₀ then Sum.inl x else Sum.inr u) := by
      intro t ht u
      by_cases hu : u = a₀
      · subst hu
        simp only [if_pos rfl, Sum.elim_inl]
        rcases guardCell_decides (guardAssignments_sound hmem) (hL t ht) with
          hpos | hneg
        · have h₁ : bval W (BExp.prim t) x = true := hpos X W x hcell
          have h₂ : bval W₀ (BExp.prim t) u = true := hpos X₀ W₀ u hcell₀
          change W t x = W₀ t u
          rw [show W t x = true from h₁, show W₀ t u = true from h₂]
        · have h₁ : bval W (BExp.prim t) x = false := hneg X W x hcell
          have h₂ : bval W₀ (BExp.prim t) u = false := hneg X₀ W₀ u hcell₀
          change W t x = W₀ t u
          rw [show W t x = false from h₁, show W₀ t u = false from h₂]
      · simp only [if_neg hu, Sum.elim_inr]
    have := den_relabel (W := W₀) (W' := fun t => Sum.elim (W t) (W₀ t))
      (f := fun u => if u = a₀ then Sum.inl x else Sum.inr u) e hagree a₀ l₀ he₀
    simpa only [if_pos rfl] using this

#print axioms den_relabel
#print axioms deadTestOver_dead
#print axioms deadTestOver_greatest
#print axioms exists_den_at_atom

end GkatAtomTransfer
