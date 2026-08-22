import GkatCyclicCoverProofs

/-!
# The degree-`k` cyclic cover

The search gate settled which degree the synthesis needs.  For every crux pullback,

    period(P) = lcm(period e, period f)          273 / 273, at K = 5 and K = 6

so covering the pullback means cyclic-covering `e`'s loop to degree
`lcm(period e, period f) / period e` — computable from the two programs, with no search.
The observed periods are 1, 2, 3 and 6, so **degree 3 occurs**, and degree 3 is exactly what
composition cannot reach: `cyclicCover` composed with itself gives 2, 4, 8, … (see
`GkatCofinality.cyclicCover4`).  Hence this file.

## Where the naive induction fails, and what it actually needs

The obvious route is to induct on the degree with the step

    InitCover (loop g X) (loop g B)  →  InitCover (loop g (X ; (g ? B : 1))) (loop g B)

Working degree 3 out by hand shows the *construction* is fine — the concern that the extra
`(g ? B : 1).initHlt` conjunct breaks the guards is unfounded, because the outer exit block
is always subsumed by an earlier inner one and is unreachable by list ordering, exactly as in
the degree-2 proof.  What fails is the **induction hypothesis**, and for a sharper reason.

`InitCover (loop g X) (loop g B)` constrains `firstMatch` over the *combined* list

    X.core.trans s  ++  X.initTrans.map (and (X.core.hlt s) (and g ·))

— body transitions and back edges together.  The step needs the two blocks *separately*: in
`bodyK (n+1)`, the block that advances from copy `i` to copy `i+1` plays the role of `B`'s
back edge, while the enclosing loop supplies the back edge only for the last copy.  From
`firstMatch (L₁ ++ L₂) = firstMatch (L₁' ++ L₂')` one cannot recover
`firstMatch L₁ = firstMatch L₁'`, so the hypothesis is genuinely too weak.

Strengthening to a cover of the *bodies* does not help either: `X ; (g ? B : 1)` does not
cover `B`, since `hlt (inl u) = B.hlt u ∧ (g ? B : 1).initHlt`.  That is precisely why
`cyclicCover` is stated about the loops.

So the invariant is neither "the loops cover" nor "the bodies cover".  It is the
**parameterized** one: `bodyK g B n` behaves like `B` *relative to an arbitrary continuation*,
with the continuation supplying whatever the enclosing context contributes — the next copy's
entry for the inner copies, the loop's back edge for the last.  That is the same shape as
`ParamSolvesBA` / `eqRHSParam` / `ParametricCanonicalBA` in
`GkatThompsonUniquenessProofs`, which exist because the Thompson certificate needed exactly
this move: a statement about a component that survives being embedded in a context.

Proving the parameterized form settles every degree at once, rather than degree 3 by a
second three-hundred-line replay of the degree-2 argument.
-/

namespace GkatCyclicK
open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatSynthesis GkatCyclicCover
variable {A T : Type}

/-- The state type of the `k`-fold body: index `n` is degree `n+1`. -/
def BodyState (S : Type) : Nat → Type
  | 0 => S
  | (n + 1) => Sum (BodyState S n) (Sum S Empty)

/-- `B ; (g ? B : 1) ; ... ; (g ? B : 1)` with `n` appended copies — degree `n+1`. -/
def bodyK {S : Type} (g : BExp T) (B : InitializedGAut S A T) :
    (n : Nat) → InitializedGAut (BodyState S n) A T
  | 0 => B
  | (n + 1) =>
      seqInitialized (bodyK g B n) (iteInitialized g B (thompsonTest (A := A) BExp.one))

/-- Every copy folds onto the original body. -/
def bodyMap {S : Type} : (n : Nat) → BodyState S n → S
  | 0, s => s
  | (n + 1), Sum.inl u => bodyMap n u
  | (n + 1), Sum.inr (Sum.inl u) => u
  | (n + 1), Sum.inr (Sum.inr z) => nomatch z

/-! ## `firstMatch` helpers (local copies; the originals are private) -/

private theorem fmGuardTo' {S R X : Type} (W : T → X → Bool) (x : X) (P : BExp T)
    (F : S → R) (L : List (BExp T × A × S)) :
    firstMatch W x (L.map (fun t => (BExp.and P t.1, t.2.1, F t.2.2))) =
      if bval W P x then (firstMatch W x L).map (fun o => (o.1, F o.2)) else none := by
  induction L with
  | nil => cases hP : bval W P x <;> simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨q, a, v⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hand : bval W (BExp.and P q) x = (bval W P x && bval W q x) := rfl
      rw [hand, ih]
      cases hP : bval W P x <;> cases hq : bval W q x <;> simp

private theorem fmGuard2To' {S R X : Type} (W : T → X → Bool) (x : X) (P Q : BExp T)
    (F : S → R) (L : List (BExp T × A × S)) :
    firstMatch W x (L.map (fun t => (BExp.and P (BExp.and Q t.1), t.2.1, F t.2.2))) =
      if bval W P x then
        (if bval W Q x then (firstMatch W x L).map (fun o => (o.1, F o.2)) else none)
      else none := by
  induction L with
  | nil => cases hP : bval W P x <;> cases hQ : bval W Q x <;> simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨q, a, v⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hand : bval W (BExp.and P (BExp.and Q q)) x
          = (bval W P x && (bval W Q x && bval W q x)) := rfl
      rw [hand, ih]
      cases hP : bval W P x <;> cases hQ : bval W Q x <;> cases hq : bval W q x <;> simp

private theorem fmGuard2' {S X : Type} (W : T → X → Bool) (x : X) (P Q : BExp T)
    (L : List (BExp T × A × S)) :
    firstMatch W x (L.map (fun t => (BExp.and P (BExp.and Q t.1), t.2))) =
      if bval W P x then (if bval W Q x then firstMatch W x L else none) else none := by
  induction L with
  | nil => cases hP : bval W P x <;> cases hQ : bval W Q x <;> simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨q, a, v⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hand : bval W (BExp.and P (BExp.and Q q)) x
          = (bval W P x && (bval W Q x && bval W q x)) := rfl
      rw [hand, ih]
      cases hP : bval W P x <;> cases hQ : bval W Q x <;> cases hq : bval W q x <;> simp

/-! ## Appending one more copy -/

variable {S Y : Type}

/-- One more copy of `B`, appended to an arbitrary body `X`. -/
private abbrev stepBody (g : BExp T) (B : InitializedGAut S A T) (X : InitializedGAut Y A T) :
    InitializedGAut (Sum Y (Sum S Empty)) A T :=
  seqInitialized X (iteInitialized g B (thompsonTest (A := A) BExp.one))

private theorem stepBody_initTrans (g : BExp T) (B : InitializedGAut S A T)
    (X : InitializedGAut Y A T) :
    (stepBody g B X).initTrans =
      X.initTrans.map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum Y (Sum S Empty)))) ++
      B.initTrans.map (fun t =>
        (BExp.and X.initHlt (BExp.and g t.1), t.2.1,
          (Sum.inr (Sum.inl t.2.2) : Sum Y (Sum S Empty)))) := by
  simp [stepBody, seqInitialized, iteInitialized, thompsonTest, List.map_map, Function.comp]

private theorem stepBody_coreHlt_inl (g : BExp T) (B : InitializedGAut S A T)
    (X : InitializedGAut Y A T) (u : Y) :
    (stepBody g B X).core.hlt (Sum.inl u) =
      BExp.and (X.core.hlt u)
        (BExp.or (BExp.and g B.initHlt) (BExp.and (BExp.not g) BExp.one)) := rfl

private theorem stepBody_coreTrans_inl (g : BExp T) (B : InitializedGAut S A T)
    (X : InitializedGAut Y A T) (u : Y) :
    (stepBody g B X).core.trans (Sum.inl u) =
      (X.core.trans u).map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum Y (Sum S Empty)))) ++
      B.initTrans.map (fun t =>
        (BExp.and (X.core.hlt u) (BExp.and g t.1), t.2.1,
          (Sum.inr (Sum.inl t.2.2) : Sum Y (Sum S Empty)))) := by
  simp [stepBody, seqInitialized, seqGSystem, iteInitialized, thompsonTest,
    List.map_map, Function.comp]

private theorem stepBody_coreTrans_inr (g : BExp T) (B : InitializedGAut S A T)
    (X : InitializedGAut Y A T) (v : S) :
    (stepBody g B X).core.trans (Sum.inr (Sum.inl v)) =
      (B.core.trans v).map (fun t =>
        (t.1, t.2.1, (Sum.inr (Sum.inl t.2.2) : Sum Y (Sum S Empty)))) := by
  simp [stepBody, seqInitialized, seqGSystem, iteInitialized, thompsonTest, sumGSystem,
    List.map_map, Function.comp]

private theorem stepBody_states (g : BExp T) (B : InitializedGAut S A T)
    (X : InitializedGAut Y A T) :
    (stepBody g B X).core.states =
      X.core.states.map (Sum.inl : Y → Sum Y (Sum S Empty)) ++
      B.core.states.map (fun v => (Sum.inr (Sum.inl v) : Sum Y (Sum S Empty))) := by
  simp [stepBody, seqInitialized, seqGSystem, iteInitialized, thompsonTest, sumGSystem,
    List.map_map, Function.comp]

/-- The shape the appended block's guards take once the loop guard is applied on top. -/
private theorem fmG3 {S' R X : Type} (W : T → X → Bool) (x : X) (P Q : BExp T)
    (F : S' → R) (L : List (BExp T × A × S')) :
    firstMatch W x
        (L.map (fun t => (BExp.and P (BExp.and Q (BExp.and P t.1)), t.2.1, F t.2.2))) =
      if bval W P x then
        (if bval W Q x then (firstMatch W x L).map (fun o => (o.1, F o.2)) else none)
      else none := by
  induction L with
  | nil => cases hP : bval W P x <;> cases hQ : bval W Q x <;> simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨q, a, v⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hand : bval W (BExp.and P (BExp.and Q (BExp.and P q))) x
          = (bval W P x && (bval W Q x && (bval W P x && bval W q x))) := rfl
      rw [hand, ih]
      cases hP : bval W P x <;> cases hQ : bval W Q x <;> cases hq : bval W q x <;> simp

/-- The four-deep guard nesting the appended block acquires inside the loop. -/
private theorem fmG4 {S' R Z : Type} (W : T → Z → Bool) (x : Z) (H P Q : BExp T)
    (F : S' → R) (L : List (BExp T × A × S')) :
    firstMatch W x (L.map (fun t =>
        (BExp.and H (BExp.and P (BExp.and Q (BExp.and P t.1))), t.2.1, F t.2.2))) =
      if bval W H x then
        (if bval W P x then
          (if bval W Q x then (firstMatch W x L).map (fun o => (o.1, F o.2)) else none)
        else none)
      else none := by
  induction L with
  | nil => cases bval W H x <;> cases bval W P x <;> cases bval W Q x <;> simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨q, a, v⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hand : bval W (BExp.and H (BExp.and P (BExp.and Q (BExp.and P q)))) x
          = (bval W H x && (bval W P x && (bval W Q x && (bval W P x && bval W q x)))) := rfl
      rw [hand, ih]
      cases bval W H x <;> cases bval W P x <;> cases bval W Q x <;>
        cases bval W q x <;> simp

/-- Both the appended copy and everything before it fold onto the original body. -/
private def stepMap {S Y : Type} (m : Y → S) : Sum Y (Sum S Empty) → S
  | Sum.inl u => m u
  | Sum.inr (Sum.inl v) => v
  | Sum.inr (Sum.inr z) => nomatch z

/-- **The back-edge block corresponds.**  Inside the loop, the block returning to the body's
    entry is built from `stepBody`'s `initTrans`, whose first half is `Xa`'s and whose second
    half is `B`'s.  Under `g` — which is exactly where the block is guarded — `φ.initStep_eq`
    relates the first half to `B.initTrans`, and the second half is then subsumed. -/
private theorem tailBlock (g : BExp T) (B : InitializedGAut S A T) (Xa : InitializedGAut Y A T)
    (φ : InitCover (loopInitialized g Xa) (loopInitialized g B)) (H : BExp T)
    {Z : Type} (W : T → Z → Bool) (x : Z) :
    (firstMatch W x ((stepBody g B Xa).initTrans.map (fun t =>
        (BExp.and H (BExp.and g t.1), t.2)))).map (fun o => (o.1, stepMap φ.map o.2))
      = firstMatch W x (B.initTrans.map (fun t => (BExp.and H (BExp.and g t.1), t.2))) := by
  have hφ := φ.initStep_eq Z W x
  change (firstMatch W x (Xa.initTrans.map (fun t => (BExp.and g t.1, t.2)))).map
      (fun o => (o.1, φ.map o.2))
    = firstMatch W x (B.initTrans.map (fun t => (BExp.and g t.1, t.2))) at hφ
  simp only [firstMatch_map_guard] at hφ
  rw [stepBody_initTrans, List.map_append]
  simp only [List.map_map, Function.comp_def]
  have hQ1 := fmGuard2To' (A := A) W x H g
    (fun u : Y => (Sum.inl u : Sum Y (Sum S Empty))) Xa.initTrans
  have hQ2 := fmG4 (A := A) W x H g Xa.initHlt
    (fun v : S => (Sum.inr (Sum.inl v) : Sum Y (Sum S Empty))) B.initTrans
  have hR := fmGuard2' (A := A) W x H g B.initTrans
  rw [hR]
  cases hh : bval W H x
  · rw [firstMatch_append_none _ _ _ _ (by rw [hQ1]; simp [hh]), hQ2]
    simp [hh]
  · cases hg : bval W g x
    · rw [firstMatch_append_none _ _ _ _ (by rw [hQ1]; simp [hh, hg]), hQ2]
      simp [hh, hg]
    · cases hx : firstMatch W x Xa.initTrans with
      | some o =>
          rw [firstMatch_append_some (x := (o.1, (Sum.inl o.2 : Sum Y (Sum S Empty))))
            _ _ _ _ (by rw [hQ1]; simp [hh, hg, hx])]
          simp [hg, hx] at hφ
          simp [hh, hg, stepMap, hφ]
      | none =>
          rw [firstMatch_append_none _ _ _ _ (by rw [hQ1]; simp [hh, hg, hx]), hQ2]
          simp [hg, hx] at hφ
          simp [hh, hg, ← hφ]

/-- **Appending one copy preserves the cover.**  Given that `loop g Xa` covers `loop g B`,
    so does `loop g (Xa ; (g ? B : 1))`.

    The two things that made this look impossible both dissolve.  The extra
    `(g ? B : 1).initHlt` conjunct on the halt guard vanishes under `¬g`, which is the only
    place the loop's halt is live.  And the appended block's guards are built from
    `B.initTrans` while the hypothesis speaks about `Xa.initTrans` — but `φ.initStep_eq`
    relates exactly those two *under* `g`, which is exactly where both blocks are guarded. -/
def stepCover (g : BExp T) (B : InitializedGAut S A T) (Xa : InitializedGAut Y A T)
    (φ : InitCover (loopInitialized g Xa) (loopInitialized g B)) :
    InitCover (loopInitialized g (stepBody g B Xa)) (loopInitialized g B) where
  map := stepMap φ.map
  initHlt_eq := fun _ _ _ => rfl
  coreHlt_eq := fun s Z W x => by
    cases s with
    | inl u =>
        show bval W (BExp.and ((stepBody g B Xa).core.hlt (Sum.inl u)) (BExp.not g)) x
          = bval W (BExp.and (B.core.hlt (φ.map u)) (BExp.not g)) x
        rw [stepBody_coreHlt_inl]
        have h := φ.coreHlt_eq u Z W x
        change bval W (BExp.and (Xa.core.hlt u) (BExp.not g)) x
          = bval W (BExp.and (B.core.hlt (φ.map u)) (BExp.not g)) x at h
        cases hg : bval W g x <;> simp [bval, hg] at h ⊢ <;> try exact h
    | inr v =>
        cases v with
        | inl w => rfl
        | inr z => exact nomatch z
  initStep_eq := fun Z W x => by
    show (firstMatch W x
        ((stepBody g B Xa).initTrans.map (fun t => (BExp.and g t.1, t.2)))).map
        (fun o => (o.1, stepMap φ.map o.2))
      = firstMatch W x (B.initTrans.map (fun t => (BExp.and g t.1, t.2)))
    have hφ := φ.initStep_eq Z W x
    change (firstMatch W x (Xa.initTrans.map (fun t => (BExp.and g t.1, t.2)))).map
        (fun o => (o.1, φ.map o.2))
      = firstMatch W x (B.initTrans.map (fun t => (BExp.and g t.1, t.2))) at hφ
    rw [stepBody_initTrans, List.map_append]
    simp only [List.map_map, Function.comp_def]
    simp only [firstMatch_map_guard] at hφ ⊢
    have hP1 := fmGuardTo' (A := A) W x g
      (fun u : Y => (Sum.inl u : Sum Y (Sum S Empty))) Xa.initTrans
    have hP2 := fmG3 (A := A) W x g Xa.initHlt
      (fun v : S => (Sum.inr (Sum.inl v) : Sum Y (Sum S Empty))) B.initTrans
    cases hg : bval W g x
    · rw [firstMatch_append_none _ _ _ _ (by simp [hP1, hg]), hP2]
      simp [hg]
    · cases hx : firstMatch W x Xa.initTrans with
      | some o =>
          rw [firstMatch_append_some (x := (o.1, (Sum.inl o.2 : Sum Y (Sum S Empty))))
            _ _ _ _ (by rw [hP1]; simp [hg, hx])]
          simp [hg, hx] at hφ
          simp [hg, stepMap, hφ]
      | none =>
          rw [firstMatch_append_none _ _ _ _ (by rw [hP1]; simp [hg, hx]), hP2]
          simp [hg, hx] at hφ
          simp [hg, ← hφ]
  coreStep_eq := fun s Z W x => by
    cases s with
    | inl u =>
        show (firstMatch W x
            ((stepBody g B Xa).core.trans (Sum.inl u) ++
              (stepBody g B Xa).initTrans.map (fun t =>
                (BExp.and ((stepBody g B Xa).core.hlt (Sum.inl u)) (BExp.and g t.1), t.2)))).map
            (fun o => (o.1, stepMap φ.map o.2))
          = firstMatch W x (B.core.trans (φ.map u) ++
              B.initTrans.map (fun t =>
                (BExp.and (B.core.hlt (φ.map u)) (BExp.and g t.1), t.2)))
        have hφ := φ.coreStep_eq u Z W x
        change (firstMatch W x (Xa.core.trans u ++
            Xa.initTrans.map (fun t =>
              (BExp.and (Xa.core.hlt u) (BExp.and g t.1), t.2)))).map
            (fun o => (o.1, φ.map o.2))
          = firstMatch W x (B.core.trans (φ.map u) ++
              B.initTrans.map (fun t =>
                (BExp.and (B.core.hlt (φ.map u)) (BExp.and g t.1), t.2))) at hφ
        rw [← hφ, stepBody_coreTrans_inl, stepBody_coreHlt_inl, List.append_assoc]
        cases hc : firstMatch W x (Xa.core.trans u) with
        | some o =>
            have hP : firstMatch W x
                ((Xa.core.trans u).map (fun t =>
                  (t.1, t.2.1, (Sum.inl t.2.2 : Sum Y (Sum S Empty)))))
                = some (o.1, Sum.inl o.2) := by
              rw [firstMatch_map_target_to, hc]; rfl
            rw [firstMatch_append_some _ _ _ _ hP, firstMatch_append_some _ _ _ _ hc]
            rfl
        | none =>
            have hP : firstMatch W x
                ((Xa.core.trans u).map (fun t =>
                  (t.1, t.2.1, (Sum.inl t.2.2 : Sum Y (Sum S Empty)))))
                = none := by
              rw [firstMatch_map_target_to, hc]; rfl
            rw [firstMatch_append_none _ _ _ _ hP, firstMatch_append_none _ _ _ _ hc]
            have hL2 := fmGuard2To' (A := A) W x (Xa.core.hlt u) g
              (fun v : S => (Sum.inr (Sum.inl v) : Sum Y (Sum S Empty))) B.initTrans
            have hM2 := fmGuard2' (A := A) W x (Xa.core.hlt u) g Xa.initTrans
            have hT := tailBlock g B Xa φ
              (BExp.and (Xa.core.hlt u)
                (BExp.or (BExp.and g B.initHlt) (BExp.and (BExp.not g) BExp.one))) W x
            have hH := fmGuard2' (A := A) W x
              (BExp.and (Xa.core.hlt u)
                (BExp.or (BExp.and g B.initHlt) (BExp.and (BExp.not g) BExp.one)))
              g B.initTrans
            have hφi := φ.initStep_eq Z W x
            change (firstMatch W x (Xa.initTrans.map (fun t => (BExp.and g t.1, t.2)))).map
                (fun o => (o.1, φ.map o.2))
              = firstMatch W x (B.initTrans.map (fun t => (BExp.and g t.1, t.2))) at hφi
            simp only [firstMatch_map_guard] at hφi
            rw [hM2]
            have hand : ∀ P Q : BExp T,
                bval W (BExp.and P Q) x = (bval W P x && bval W Q x) := fun _ _ => rfl
            cases hh : bval W (Xa.core.hlt u) x
            · rw [firstMatch_append_none _ _ _ _ (by rw [hL2]; simp [hh]), hT, hH]
              simp [hh, hand]
            · cases hg : bval W g x
              · rw [firstMatch_append_none _ _ _ _ (by rw [hL2]; simp [hh, hg]), hT, hH]
                simp [hg]
              · rw [hg] at hφi
                simp only [if_pos rfl] at hφi
                cases hb : firstMatch W x B.initTrans with
                | some p =>
                    rw [firstMatch_append_some
                      (x := (p.1, (Sum.inr (Sum.inl p.2) : Sum Y (Sum S Empty))))
                      _ _ _ _ (by rw [hL2]; simp [hh, hg, hb])]
                    rw [hb] at hφi
                    cases hx : firstMatch W x Xa.initTrans with
                    | none => rw [hx] at hφi; exact absurd hφi (by simp)
                    | some o =>
                        rw [hx] at hφi
                        have hp : p = (o.1, φ.map o.2) := (Option.some.inj hφi).symm
                        subst hp
                        simp [hh, hg, hx, stepMap]
                | none =>
                    rw [firstMatch_append_none _ _ _ _ (by rw [hL2]; simp [hh, hg, hb]), hT, hH]
                    rw [hb] at hφi
                    cases hx : firstMatch W x Xa.initTrans with
                    | some o => rw [hx] at hφi; exact absurd hφi (by simp)
                    | none => simp [hh, hg, hb, hx]
    | inr v =>
        cases v with
        | inl w =>
            show (firstMatch W x
                ((stepBody g B Xa).core.trans (Sum.inr (Sum.inl w)) ++
                  (stepBody g B Xa).initTrans.map (fun t =>
                    (BExp.and ((stepBody g B Xa).core.hlt (Sum.inr (Sum.inl w)))
                      (BExp.and g t.1), t.2)))).map
                (fun o => (o.1, stepMap φ.map o.2))
              = firstMatch W x (B.core.trans w ++
                  B.initTrans.map (fun t =>
                    (BExp.and (B.core.hlt w) (BExp.and g t.1), t.2)))
            rw [stepBody_coreTrans_inr]
            cases hc : firstMatch W x (B.core.trans w) with
            | some o =>
                have hP : firstMatch W x
                    ((B.core.trans w).map (fun t =>
                      (t.1, t.2.1, (Sum.inr (Sum.inl t.2.2) : Sum Y (Sum S Empty)))))
                    = some (o.1, Sum.inr (Sum.inl o.2)) := by
                  rw [firstMatch_map_target_to
                    (F := fun v : S => (Sum.inr (Sum.inl v) : Sum Y (Sum S Empty))), hc]
                  rfl
                rw [firstMatch_append_some _ _ _ _ hP, firstMatch_append_some _ _ _ _ hc]
                rfl
            | none =>
                have hP : firstMatch W x
                    ((B.core.trans w).map (fun t =>
                      (t.1, t.2.1, (Sum.inr (Sum.inl t.2.2) : Sum Y (Sum S Empty)))))
                    = none := by
                  rw [firstMatch_map_target_to
                    (F := fun v : S => (Sum.inr (Sum.inl v) : Sum Y (Sum S Empty))), hc]
                  rfl
                rw [firstMatch_append_none _ _ _ _ hP, firstMatch_append_none _ _ _ _ hc]
                exact tailBlock g B Xa φ (B.core.hlt w) W x
        | inr z => exact nomatch z
  maps := by
    intro s hs
    show stepMap φ.map s ∈ B.core.states
    have hs' : s ∈ (stepBody g B Xa).core.states := hs
    rw [stepBody_states] at hs'
    rcases List.mem_append.mp hs' with h | h
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      exact φ.maps u hu
    · obtain ⟨v, hv, rfl⟩ := List.mem_map.mp h
      exact hv
  onto := by
    intro q hq
    refine ⟨Sum.inr (Sum.inl q), ?_, rfl⟩
    show (Sum.inr (Sum.inl q) : Sum Y (Sum S Empty)) ∈ (stepBody g B Xa).core.states
    rw [stepBody_states]
    exact List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨q, hq, rfl⟩))

/-- Degree 1 is the identity: `bodyK g B 0` is `B` itself. -/
def cyclicCover1 {S : Type} (g : BExp T) (B : InitializedGAut S A T) :
    InitCover (loopInitialized g (bodyK g B 0)) (loopInitialized g B) :=
  InitCover.id _

/-- **The degree-`k` cyclic cover.**  Repeating the loop body `n+1` times refines the loop,
    at every degree — by induction, with `stepCover` appending one copy at a time. -/
def cyclicCoverK (g : BExp T) (B : InitializedGAut S A T) :
    (n : Nat) → InitCover (loopInitialized g (bodyK g B n)) (loopInitialized g B)
  | 0 => InitCover.id _
  | (n + 1) => stepCover g B (bodyK g B n) (cyclicCoverK g B n)

/-- The expression whose Thompson automaton is the degree-`n+1` body. -/
def expK (g : BExp T) (e : Exp A T) : Nat → Exp A T
  | 0 => e
  | (n + 1) => .seq (expK g e n) (.ite g e (.test BExp.one))

/-- The same recursion run directly on `certifiedThompson`, so the source really is the
    automaton of an expression.  `bodyK` and `expK` agree for every literal degree, but for a
    variable `n` they cannot reduce in lockstep, so the bridge is built rather than assumed. -/
def cyclicCoverExp (g : BExp T) (e : Exp A T) :
    (n : Nat) → InitCover (certifiedThompson A T (.wh g (expK g e n))).aut
                          (certifiedThompson A T (.wh g e)).aut
  | 0 => InitCover.id _
  | (n + 1) =>
      stepCover g (certifiedThompson A T e).aut (certifiedThompson A T (expK g e n)).aut
        (cyclicCoverExp g e n)

/-- **Loop repetition is a theorem of the finite axioms, at every degree.**

        while g do e  ≡  while g do (e ; (g ? e : 1) ; … ; (g ? e : 1))

    `loop_doubling_provable` is the case `n = 1`.  The search gate showed degree 3 is
    genuinely needed — `period(P) = lcm(period e, period f)` for every crux pullback, and
    period 3 occurs — and composing the degree-2 cover only ever reaches 2, 4, 8. -/
theorem loop_repeat_provable (g : BExp T) (e : Exp A T) (n : Nat) :
    EquivBA (.wh g e : Exp A T) (.wh g (expK g e n)) :=
  equivBA_of_common_refinement
    (InitCover.id (certifiedThompson A T (.wh g (expK g e n))).aut)
    (cyclicCoverExp g e n)
    (InitCover.id _)

/-- **The target, discharged.**  Repeating the loop body `n+1` times refines the loop, at every degree.

    Degree 2 is `GkatCyclicCover.cyclicCover`, proved; degrees 4, 8, … follow by composing it
    with itself.  What is open is every other degree — 3 first, which the gate shows is
    actually needed. -/
def CyclicCoverK (A T : Type) : Prop :=
  ∀ {S : Type} (g : BExp T) (B : InitializedGAut S A T) (n : Nat),
    Nonempty (InitCover (loopInitialized g (bodyK g B n)) (loopInitialized g B))

theorem cyclicCoverK_holds : CyclicCoverK A T :=
  fun g B n => ⟨cyclicCoverK g B n⟩

#print axioms stepCover
#print axioms cyclicCoverK
#print axioms cyclicCoverK_holds
#print axioms cyclicCoverExp
#print axioms loop_repeat_provable

end GkatCyclicK
