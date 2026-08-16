import GkatAtomTransferProofs

/-!
# Semantic side conditions for the null-language induction

The two syntactic inductions downstream (`Zero`: a dead assertion is provably `0`;
`Post`: a postcondition that can never fail may be deleted) each dispatch on the shape
of the program.  Every case produces one *semantic* obligation — "this smaller
expression is uniformly empty too".  Those obligations are collected here so the
syntactic files stay pure control-flow arguments.

Two devices recur:

* **fresh sum carriers** — an action edge can join any two atoms, so a witness for the
  continuation found in another carrier can always be spliced onto a witness for the
  prefix (`den_inl`, `den_inr`);
* **the dead-cell test** of `GkatAtomTransfer` — outside it a witness exists at the very
  atom where the prefix ended, which is what makes the sequential and loop cases go
  through without a right-hand case split.

Axioms: `[propext, Classical.choice, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatNullSemantics

open GkatSyntax GkatGS GkatFaithful GkatThompson GkatAtomTransfer

variable {A T : Type}

/-! ## Uniform emptiness, transported -/

/-- Uniform emptiness is invariant under provable equivalence (by soundness). -/
theorem ULempty_congr {e e' : Exp A T} (h : EquivBA e e')
    (hempty : UniformExpLempty e) : UniformExpLempty e' := by
  intro X W gs hden
  exact hempty X W gs ((sound_BA W h gs).mpr hden)

/-- Strengthening the leading assertion preserves uniform emptiness. -/
theorem ULempty_of_guard_implies {b b' : BExp T} {e : Exp A T}
    (himp : GuardImplies b b')
    (hempty : UniformExpLempty (.seq (.test b') e)) :
    UniformExpLempty (.seq (.test b) e) := by
  intro X W gs hden
  obtain ⟨a, l⟩ := gs
  obtain ⟨hb, he⟩ := (den_test_seq_iff W b e a l).mp hden
  exact hempty X W (a, l)
    ((den_test_seq_iff W b' e a l).mpr ⟨himp X W a hb, he⟩)

/-- Reassociation of a three-fold composite. -/
theorem seq_assoc_equiv (e f g : Exp A T) :
    EquivBA (.seq (.seq e f) g) (.seq e (.seq f g)) :=
  EquivBA.base (Equiv.s1 e f g)

/-! ## Fresh sum carriers -/

/-- The valuation on a disjoint union of carriers. -/
def sumVal {X Y : Type} (W : T → X → Bool) (W' : T → Y → Bool) :
    T → Sum X Y → Bool :=
  fun t => Sum.elim (W t) (W' t)

theorem bval_sum_inl {X Y : Type} (W : T → X → Bool) (W' : T → Y → Bool)
    (b : BExp T) (x : X) : bval (sumVal W W') b (Sum.inl x) = bval W b x :=
  bval_relabel (W := W) (W' := sumVal W W') (f := Sum.inl) b
    (fun _ _ _ => rfl) x

theorem bval_sum_inr {X Y : Type} (W : T → X → Bool) (W' : T → Y → Bool)
    (b : BExp T) (y : Y) : bval (sumVal W W') b (Sum.inr y) = bval W' b y :=
  bval_relabel (W := W') (W' := sumVal W W') (f := Sum.inr) b
    (fun _ _ _ => rfl) y

theorem den_sum_inl {X Y : Type} (W : T → X → Bool) (W' : T → Y → Bool)
    (e : Exp A T) (a : X) (l : List (A × X)) (hden : den W e (a, l)) :
    den (sumVal W W') e (Sum.inl a, mapAtoms Sum.inl l) :=
  den_relabel (W := W) (W' := sumVal W W') (f := Sum.inl) e
    (fun _ _ _ => rfl) a l hden

theorem den_sum_inr {X Y : Type} (W : T → X → Bool) (W' : T → Y → Bool)
    (e : Exp A T) (a : Y) (l : List (A × Y)) (hden : den W' e (a, l)) :
    den (sumVal W W') e (Sum.inr a, mapAtoms Sum.inr l) :=
  den_relabel (W := W') (W' := sumVal W W') (f := Sum.inr) e
    (fun _ _ _ => rfl) a l hden

/-! ## Test and conditional cases -/

/-- An assertion followed by a test is the conjoined assertion. -/
theorem ULempty_test_head {b c : BExp T} {f : Exp A T}
    (hempty : UniformExpLempty (.seq (.test b) (.seq (.test c) f))) :
    UniformExpLempty (.seq (.test (.and b c)) f) := by
  intro X W gs hden
  obtain ⟨a, l⟩ := gs
  obtain ⟨hbc, hf⟩ := (den_test_seq_iff W _ f a l).mp hden
  have hb : bval W b a = true := by
    change (bval W b a && bval W c a) = true at hbc
    cases hb' : bval W b a with
    | true => rfl
    | false => rw [hb'] at hbc; exact absurd hbc (by simp)
  have hc : bval W c a = true := by
    change (bval W b a && bval W c a) = true at hbc
    cases hc' : bval W c a with
    | true => rfl
    | false => rw [hc'] at hbc; exact absurd hbc (by simp)
  exact hempty X W (a, l)
    ((den_test_seq_iff W b _ a l).mpr ⟨hb,
      (den_test_seq_iff W c f a l).mpr ⟨hc, hf⟩⟩)

/-- The then-branch obligation of a conditional. -/
theorem ULempty_ite_then {b c : BExp T} {e₁ e₂ f : Exp A T}
    (hempty : UniformExpLempty (.seq (.test b) (.seq (.ite c e₁ e₂) f))) :
    UniformExpLempty (.seq (.test (.and b c)) (.seq e₁ f)) := by
  intro X W gs hden
  obtain ⟨a, l⟩ := gs
  obtain ⟨hbc, hseq⟩ := (den_test_seq_iff W _ (.seq e₁ f) a l).mp hden
  obtain ⟨l₁, l₂, hsplit, he₁, hf⟩ := hseq
  have hb : bval W b a = true := by
    change (bval W b a && bval W c a) = true at hbc
    cases hb' : bval W b a with
    | true => rfl
    | false => rw [hb'] at hbc; exact absurd hbc (by simp)
  have hc : bval W c a = true := by
    change (bval W b a && bval W c a) = true at hbc
    cases hc' : bval W c a with
    | true => rfl
    | false => rw [hc'] at hbc; exact absurd hbc (by simp)
  refine hempty X W (a, l) ((den_test_seq_iff W b _ a l).mpr ⟨hb, ?_⟩)
  exact ⟨l₁, l₂, hsplit, Or.inl ⟨hc, he₁⟩, hf⟩

/-- The else-branch obligation of a conditional. -/
theorem ULempty_ite_else {b c : BExp T} {e₁ e₂ f : Exp A T}
    (hempty : UniformExpLempty (.seq (.test b) (.seq (.ite c e₁ e₂) f))) :
    UniformExpLempty (.seq (.test (.and b (.not c))) (.seq e₂ f)) := by
  intro X W gs hden
  obtain ⟨a, l⟩ := gs
  obtain ⟨hbc, hseq⟩ := (den_test_seq_iff W _ (.seq e₂ f) a l).mp hden
  obtain ⟨l₁, l₂, hsplit, he₂, hf⟩ := hseq
  have hb : bval W b a = true := by
    change (bval W b a && (! bval W c a)) = true at hbc
    cases hb' : bval W b a with
    | true => rfl
    | false => rw [hb'] at hbc; exact absurd hbc (by simp)
  have hc : bval W c a = false := by
    change (bval W b a && (! bval W c a)) = true at hbc
    cases hc' : bval W c a with
    | false => rfl
    | true => rw [hc'] at hbc; exact absurd hbc (by simp)
  refine hempty X W (a, l) ((den_test_seq_iff W b _ a l).mpr ⟨hb, ?_⟩)
  exact ⟨l₁, l₂, hsplit, Or.inr ⟨hc, he₂⟩, hf⟩

/-! ## The action case: an edge can always be spliced -/

/-- If some atom satisfies the leading assertion, a dead `b·(p·f)` forces `f` itself to
    be empty: the action edge joins any two atoms, so a witness for `f` anywhere would
    complete a witness for the whole composite in the disjoint union of the carriers. -/
theorem ULempty_act_continuation {b : BExp T} {p : A} {f : Exp A T}
    {X : Type} {W : T → X → Bool} {x : X} (hb : bval W b x = true)
    (hempty : UniformExpLempty (.seq (.test b) (.seq (.act p) f))) :
    UniformExpLempty f := by
  intro Y W' gs hden
  obtain ⟨c, l⟩ := gs
  refine hempty (Sum X Y) (sumVal W W')
    (Sum.inl x, (p, Sum.inr c) :: mapAtoms Sum.inr l) ?_
  refine (den_test_seq_iff (sumVal W W') b _ _ _).mpr
    ⟨by rw [bval_sum_inl]; exact hb, ?_⟩
  refine ⟨[(p, Sum.inr c)], mapAtoms Sum.inr l, rfl, ⟨Sum.inl x, Sum.inr c, rfl⟩, ?_⟩
  exact den_sum_inr W W' f c l hden

/-- Dual form: if some atom satisfies the leading assertion, a dead `b·(p·¬z)` forces
    `z` to be a tautology. -/
theorem GuardImplies_act_post {b z : BExp T} {p : A}
    {X : Type} {W : T → X → Bool} {x : X} (hb : bval W b x = true)
    (hempty : UniformExpLempty (.seq (.test b) (.seq (.act p) (.test (.not z))))) :
    ∀ (Y : Type) (W' : T → Y → Bool) (y : Y), bval W' z y = true := by
  intro Y W' y
  cases hz : bval W' z y with
  | true => rfl
  | false =>
      exfalso
      refine hempty (Sum X Y) (sumVal W W') (Sum.inl x, [(p, Sum.inr y)]) ?_
      refine (den_test_seq_iff (sumVal W W') b _ _ _).mpr
        ⟨by rw [bval_sum_inl]; exact hb, ?_⟩
      refine ⟨[(p, Sum.inr y)], [], rfl, ⟨Sum.inl x, Sum.inr y, rfl⟩, ?_⟩
      refine ⟨?_, rfl⟩
      change (! bval (sumVal W W') z (Sum.inr y)) = true
      rw [bval_sum_inr, hz]
      rfl

/-! ## The sequential case: the intermediate dead region -/

/-- The list of guards used to split a sequential composite: the leading assertion
    together with every primitive test of the continuation. -/
def splitGuards (b : BExp T) (k : Exp A T) : List (BExp T) :=
  b :: (primTests k).map BExp.prim

theorem mem_splitGuards_head (b : BExp T) (k : Exp A T) :
    b ∈ splitGuards b k := List.Mem.head _

theorem mem_splitGuards_prim (b : BExp T) (k : Exp A T) :
    ∀ t ∈ primTests k, (BExp.prim t) ∈ splitGuards b k := by
  intro t ht
  exact List.Mem.tail _ (List.mem_map_of_mem ht)

/-- **The prefix never ends outside the intermediate dead region.**  This is the
    obligation that a right-hand Boolean case split would otherwise be needed for: it is
    discharged by producing the continuation witness *at the atom where the prefix
    ended*, using the fresh-carrier transport of `exists_den_at_atom`. -/
theorem ULempty_prefix_outside_dead {b : BExp T} {e k : Exp A T} (L : List (BExp T))
    (hL : ∀ t ∈ primTests k, (BExp.prim t) ∈ L)
    (hempty : UniformExpLempty (.seq (.test b) (.seq e k))) :
    UniformExpLempty (.seq (.test b)
      (.seq e (.test (.not (deadTestOver L k))))) := by
  intro X W gs hden
  obtain ⟨a, l⟩ := gs
  obtain ⟨hb, hseq⟩ := (den_test_seq_iff W b _ a l).mp hden
  obtain ⟨he, hdead⟩ := (den_seq_test_iff W e _ a l).mp hseq
  have hfalse : bval W (deadTestOver L k) (lastAtom a l) = false := by
    change (! bval W (deadTestOver L k) (lastAtom a l)) = true at hdead
    cases hv : bval W (deadTestOver L k) (lastAtom a l) with
    | false => rfl
    | true => rw [hv] at hdead; exact absurd hdead (by simp)
  obtain ⟨Y, W', emb, tail, hagree, hden'⟩ :=
    exists_den_at_atom L k hL W (lastAtom a l) hfalse
  have hmap : ∀ (c : BExp T) (u : X), bval W' c (emb u) = bval W c u :=
    fun c u => bval_relabel (W := W) (W' := W') (f := emb) c
      (fun _ _ _ => hagree _ _) u
  have hprefix : den W' e (emb a, mapAtoms emb l) :=
    den_relabel (W := W) (W' := W') (f := emb) e (fun _ _ _ => hagree _ _) a l he
  refine hempty Y W' (emb a, mapAtoms emb l ++ tail) ?_
  refine (den_test_seq_iff W' b _ _ _).mpr ⟨by rw [hmap]; exact hb, ?_⟩
  rw [← lastAtom_mapAtoms emb a l] at hden'
  exact ⟨mapAtoms emb l, tail, rfl, hprefix, hden'⟩

/-! ## The loop case -/

/-- Exiting the loop immediately is a run of the loop, so the exit region of a dead
    loop is dead for the continuation. -/
theorem ULempty_loop_exit {g : BExp T} {p k : Exp A T} {Z : BExp T}
    (hempty : UniformExpLempty (.seq (.test Z) (.seq (.wh g p) k))) :
    UniformExpLempty (.seq (.test (.and Z (.not g))) k) := by
  intro X W gs hden
  obtain ⟨a, l⟩ := gs
  obtain ⟨hZg, hk⟩ := (den_test_seq_iff W _ k a l).mp hden
  have hZ : bval W Z a = true := by
    change (bval W Z a && (! bval W g a)) = true at hZg
    cases hv : bval W Z a with
    | true => rfl
    | false => rw [hv] at hZg; exact absurd hZg (by simp)
  have hg : bval W g a = false := by
    change (bval W Z a && (! bval W g a)) = true at hZg
    cases hv : bval W g a with
    | false => rfl
    | true => rw [hv] at hZg; exact absurd hZg (by simp)
  refine hempty X W (a, l) ((den_test_seq_iff W Z _ a l).mpr ⟨hZ, ?_⟩)
  exact ⟨[], l, rfl, InLoop.exit a hg, hk⟩

/-- **The loop invariant.**  One productive iteration from inside the dead region of a
    dead loop cannot leave that region: otherwise the continuation witness produced at
    the landing atom would extend the iteration to a full run.  This is the fact that
    lets the loop be closed by `W3` alone, with no appeal to global uniqueness. -/
theorem ULempty_loop_step {g : BExp T} {p k : Exp A T} (L : List (BExp T))
    (hL : ∀ t ∈ primTests (Exp.seq (.wh g p) k), (BExp.prim t) ∈ L) :
    UniformExpLempty
      (.seq (.test (.and (deadTestOver L (Exp.seq (.wh g p) k)) g))
        (.seq p (.test (.not (deadTestOver L (Exp.seq (.wh g p) k)))))) := by
  intro X W gs hden
  obtain ⟨a, l⟩ := gs
  obtain ⟨hZg, hseq⟩ := (den_test_seq_iff W _ _ a l).mp hden
  obtain ⟨hp, hout⟩ := (den_seq_test_iff W p _ a l).mp hseq
  have hZ : bval W (deadTestOver L (Exp.seq (.wh g p) k)) a = true := by
    change (bval W (deadTestOver L (Exp.seq (.wh g p) k)) a && bval W g a) = true at hZg
    cases hv : bval W (deadTestOver L (Exp.seq (.wh g p) k)) a with
    | true => rfl
    | false => rw [hv] at hZg; exact absurd hZg (by simp)
  have hg : bval W g a = true := by
    change (bval W (deadTestOver L (Exp.seq (.wh g p) k)) a && bval W g a) = true at hZg
    cases hv : bval W g a with
    | true => rfl
    | false => rw [hv] at hZg; exact absurd hZg (by simp)
  have hfalse : bval W (deadTestOver L (Exp.seq (.wh g p) k)) (lastAtom a l) = false := by
    change (! bval W (deadTestOver L (Exp.seq (.wh g p) k)) (lastAtom a l)) = true at hout
    cases hv : bval W (deadTestOver L (Exp.seq (.wh g p) k)) (lastAtom a l) with
    | false => rfl
    | true => rw [hv] at hout; exact absurd hout (by simp)
  obtain ⟨Y, W', emb, tail, hagree, hden'⟩ :=
    exists_den_at_atom L (Exp.seq (.wh g p) k) hL W (lastAtom a l) hfalse
  have hmap : ∀ (c : BExp T) (u : X), bval W' c (emb u) = bval W c u :=
    fun c u => bval_relabel (W := W) (W' := W') (f := emb) c
      (fun _ _ _ => hagree _ _) u
  have hbody : den W' p (emb a, mapAtoms emb l) :=
    den_relabel (W := W) (W' := W') (f := emb) p (fun _ _ _ => hagree _ _) a l hp
  obtain ⟨lloop, lrest, hsplit, hloop, hk⟩ := hden'
  subst hsplit
  have hstep : InLoop W' g (den W' p) (emb a, mapAtoms emb l ++ lloop) := by
    refine InLoop.step (emb a) (mapAtoms emb l) lloop
      (by rw [hmap]; exact hg) hbody ?_
    rw [lastAtom_mapAtoms]
    exact hloop
  refine deadTestOver_dead L (Exp.seq (.wh g p) k) Y W'
    (emb a, (mapAtoms emb l ++ lloop) ++ lrest) ?_
  refine (den_test_seq_iff W' _ _ _ _).mpr ⟨by rw [hmap]; exact hZ, ?_⟩
  rw [← lastAtom_mapAtoms emb a l, ← lastAtom_append] at hk
  exact ⟨mapAtoms emb l ++ lloop, lrest, rfl, hstep, hk⟩

#print axioms ULempty_congr
#print axioms ULempty_act_continuation
#print axioms GuardImplies_act_post
#print axioms ULempty_prefix_outside_dead
#print axioms ULempty_loop_exit
#print axioms ULempty_loop_step

end GkatNullSemantics
