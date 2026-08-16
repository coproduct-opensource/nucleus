import GkatOrderedBAProofs

/-!
# Cyclic proofs → ordered GKAT: the compositional one-cycle bridge

Rooduijn–Kozen–Silva's complete GKAT proof system represents language inclusions by
regular cyclic derivations. This file begins the algebraization programme with the smallest
genuine cyclic fragment: one progressing loop, nested in an arbitrary positive GKAT context.

The finite certificate has two pieces:

* a local body proof `b ? (e·g) : f ⊑ g`, obtained by cutting the cyclic backedge; and
* a positive one-hole context surrounding the cyclic formula.

`FocusedCycleDeriv.compile` compiles the finite SGKAT region, closes its backedge with
ordered star induction, and transports the result through the context. Multiple mutually
dependent cyclic SCCs remain the next layer. The point of this brick is to establish,
without semantic detours, the exact compiler interface that graph extraction must target.

All compiler theorems are axiom-free. The final semantic corollary has the existing
`GkatOrdered.le_sound` footprint (`propext`, `Quot.sound`).
-/

namespace GkatCyclicOrdered

open GkatSyntax GkatGS GkatOrdered
open GkatOrderedBA

variable {A T : Type}

/-! ## The paper-shaped sequent layer (definable atom annotations) -/

/-- The product of a cedent (a list of expressions), with the empty cedent interpreted as
    skip. SGKAT always decomposes the leftmost expression, exactly matching this right fold. -/
def cedent : List (Exp A T) → Exp A T
  | [] => .test .one
  | e :: Γ => .seq e (cedent Γ)

/-- A definably annotated SGKAT sequent. The paper uses an arbitrary set of atoms `B`; here
    `atoms : BExp T` denotes that set. Over a finite free Boolean algebra every atom set is
    definable, but keeping the syntax explicit reveals where Boolean reasoning is required. -/
structure Sequent (A T : Type) where
  ant : List (Exp A T)
  atoms : BExp T
  suc : List (Exp A T)

/-- The antecedent language, restricted to the sequent's atom annotation. -/
def Sequent.left (s : Sequent A T) : Exp A T := .seq (.test s.atoms) (cedent s.ant)

/-- The succedent language. -/
def Sequent.right (s : Sequent A T) : Exp A T := cedent s.suc

/-- Algebraic derivability of a definably annotated sequent. -/
def Sequent.Ordered (s : Sequent A T) : Prop := Leq s.left s.right

/-- Boolean-aware algebraic derivability, used by annotation-sensitive SGKAT rules. -/
def Sequent.OrderedBA (s : Sequent A T) : Prop := LeqBA s.left s.right

/-- Folding a product at the head of a cedent is exactly associativity. -/
theorem cedent_product (e f : Exp A T) (Γ : List (Exp A T)) :
    Equiv (cedent ((.seq e f) :: Γ)) (cedent (e :: f :: Γ)) :=
  Equiv.s1 e f (cedent Γ)

/-- Compile SGKAT's product-left rule. This rule is wholly algebraic: no atom-set reasoning
    is involved. -/
theorem product_left {e f : Exp A T} {Γ Δ : List (Exp A T)} {B : BExp T}
    (h : Sequent.Ordered ⟨e :: f :: Γ, B, Δ⟩) :
    Sequent.Ordered ⟨(.seq e f) :: Γ, B, Δ⟩ :=
  Leq.trans
    (Leq.equiv (Equiv.seq_c (Equiv.refl (.test B)) (cedent_product e f Γ))) h

/-- Compile SGKAT's product-right rule. -/
theorem product_right {e f : Exp A T} {Γ Δ : List (Exp A T)} {B : BExp T}
    (h : Sequent.Ordered ⟨Γ, B, e :: f :: Δ⟩) :
    Sequent.Ordered ⟨Γ, B, (.seq e f) :: Δ⟩ :=
  Leq.trans h (Leq.equiv (Equiv.symm (cedent_product e f Δ)))

/-- Boolean-aware versions of the product rules, used inside annotation-sensitive
    derivations. -/
theorem product_left_BA {e f : Exp A T} {Γ Δ : List (Exp A T)} {B : BExp T}
    (h : Sequent.OrderedBA ⟨e :: f :: Γ, B, Δ⟩) :
    Sequent.OrderedBA ⟨(.seq e f) :: Γ, B, Δ⟩ :=
  LeqBA.trans
    (LeqBA.equiv (Equiv.seq_c (Equiv.refl (.test B)) (cedent_product e f Γ))) h

theorem product_right_BA {e f : Exp A T} {Γ Δ : List (Exp A T)} {B : BExp T}
    (h : Sequent.OrderedBA ⟨Γ, B, e :: f :: Δ⟩) :
    Sequent.OrderedBA ⟨Γ, B, (.seq e f) :: Δ⟩ :=
  LeqBA.trans h (LeqBA.equiv (Equiv.symm (cedent_product e f Δ)))

/-- The full-atom empty identity axiom compiles. (`B = 1` definitionally, so no Boolean
    normalization theorem is needed.) -/
theorem empty_identity : Sequent.Ordered (⟨[], BExp.one, []⟩ : Sequent A T) :=
  Leq.equiv (Equiv.s5 (.test .one))

/-- SGKAT's identity axiom for an arbitrary atom annotation. -/
theorem empty_identity_BA (B : BExp T) :
    Sequent.OrderedBA (⟨[], B, []⟩ : Sequent A T) := by
  apply LeqBA.trans (LeqBA.equiv (Equiv.s5 (.test B)))
  apply LeqBA.test_le
  intro X V x h
  rfl

/-- Compile SGKAT's test-left rule. The premise is annotated by `B ∩ b`; the Boolean-test
    embedding turns the conclusion's sequential tests `test B · test b` into that restricted
    annotation before applying the premise. -/
theorem test_left {b B : BExp T} {Γ Δ : List (Exp A T)}
    (h : Sequent.OrderedBA ⟨Γ, .and B b, Δ⟩) :
    Sequent.OrderedBA ⟨(.test b) :: Γ, B, Δ⟩ := by
  apply LeqBA.trans _ h
  apply LeqBA.trans
    (LeqBA.equiv (Equiv.symm (Equiv.s1 (.test B) (.test b) (cedent Γ))))
  exact LeqBA.seq_mono (LeqBA.test_seq B b) (LeqBA.refl (cedent Γ))

/-- Compile SGKAT's test-right rule. The side condition `B ∩ b = B` is represented as
    Boolean implication: every valuation satisfying the annotation `B` also satisfies `b`.
    It lets us insert `test b` ahead of the already-derived succedent. -/
theorem test_right {b B : BExp T} {Γ Δ : List (Exp A T)}
    (hB : ∀ (X : Type) (V : T → X → Bool) (x : X),
      bval V B x = true → bval V b x = true)
    (h : Sequent.OrderedBA ⟨Γ, B, Δ⟩) :
    Sequent.OrderedBA ⟨Γ, B, (.test b) :: Δ⟩ := by
  let L := cedent Γ
  let D := cedent Δ
  have hBand : ∀ (X : Type) (V : T → X → Bool) (x : X),
      bval V B x = true → bval V (.and b B) x = true := by
    intro X V x hBx
    rw [bval, hB X V x hBx, hBx]
    rfl
  apply LeqBA.trans
    (LeqBA.seq_mono (LeqBA.test_le hBand) (LeqBA.refl L))
  apply LeqBA.trans
    (LeqBA.seq_mono (LeqBA.test_seq_rev b B) (LeqBA.refl L))
  apply LeqBA.trans
    (LeqBA.equiv (Equiv.s1 (.test b) (.test B) L))
  exact LeqBA.seq_mono (LeqBA.refl (.test b)) h

/-- The empty-annotation axiom now compiles for arbitrary cedents. -/
theorem bottom_axiom {Γ Δ : List (Exp A T)} :
    Sequent.OrderedBA ⟨Γ, BExp.zero, Δ⟩ :=
  LeqBA.trans
    (LeqBA.equiv (Equiv.s2 (cedent Γ)))
    (LeqBA.zero_le (cedent Δ))

/-- Compile SGKAT's guarded-choice-left rule from its two atom-restricted premises. The
    only distribution used is `test_ite`: a test prefix is a subidentity and may safely
    split across the branch. No action-prefix pullback or unrestricted left distribution
    is assumed. -/
theorem choice_left {b B : BExp T} {e f : Exp A T} {Γ Δ : List (Exp A T)}
    (he : Sequent.OrderedBA ⟨e :: Γ, .and B b, Δ⟩)
    (hf : Sequent.OrderedBA ⟨f :: Γ, .and B (.not b), Δ⟩) :
    Sequent.OrderedBA ⟨(.ite b e f) :: Γ, B, Δ⟩ := by
  let G := cedent Γ
  let D := cedent Δ
  have he' : LeqBA (.seq (.seq (.test (.and B b)) e) G) D :=
    LeqBA.trans (LeqBA.equiv (Equiv.s1 (.test (.and B b)) e G)) he
  have hf' : LeqBA (.seq (.seq (.test (.and B (.not b))) f) G) D :=
    LeqBA.trans (LeqBA.equiv (Equiv.s1 (.test (.and B (.not b))) f G)) hf
  apply LeqBA.trans
    (LeqBA.equiv (Equiv.symm (Equiv.s1 (.test B) (.ite b e f) G)))
  apply LeqBA.trans
    (LeqBA.seq_mono (LeqBA.test_ite B b e f) (LeqBA.refl G))
  apply LeqBA.trans
    (LeqBA.equiv (Equiv.symm
      (Equiv.u5 b (.seq (.test (.and B b)) e)
        (.seq (.test (.and B (.not b))) f) G)))
  exact LeqBA.trans (LeqBA.ite_mono he' hf') (LeqBA.equiv (Equiv.u1 b D))

/-- Compile SGKAT's guarded-choice-right rule. The annotated source is split into its
    `b`/`¬b` pieces, the two premises are applied, and `U5` fuses the common continuation. -/
theorem choice_right {b B : BExp T} {e f : Exp A T} {Γ Δ : List (Exp A T)}
    (he : Sequent.OrderedBA ⟨Γ, .and B b, e :: Δ⟩)
    (hf : Sequent.OrderedBA ⟨Γ, .and B (.not b), f :: Δ⟩) :
    Sequent.OrderedBA ⟨Γ, B, (.ite b e f) :: Δ⟩ := by
  let L := cedent Γ
  let D := cedent Δ
  have split : LeqBA (.seq (.test B) L)
      (.ite b (.seq (.test (.and B b)) L)
        (.seq (.test (.and B (.not b))) L)) :=
    LeqBA.trans
      (LeqBA.seq_mono (LeqBA.refl (.test B))
        (LeqBA.equiv (Equiv.symm (Equiv.u1 b L))))
      (LeqBA.test_ite B b L L)
  apply LeqBA.trans split
  apply LeqBA.trans (LeqBA.ite_mono he hf)
  exact LeqBA.equiv (Equiv.u5 b e f D)

/-- Compile SGKAT's while-left rule. Its two premises are precisely the guarded-choice
    branches of `W1`: continue with `e, e^(b)` on `b`, or skip on `¬b`. -/
theorem while_left {b B : BExp T} {e : Exp A T} {Γ Δ : List (Exp A T)}
    (hstep : Sequent.OrderedBA ⟨e :: (.wh b e) :: Γ, .and B b, Δ⟩)
    (hexit : Sequent.OrderedBA ⟨Γ, .and B (.not b), Δ⟩) :
    Sequent.OrderedBA ⟨(.wh b e) :: Γ, B, Δ⟩ := by
  let W : Exp A T := .wh b e
  let one : Exp A T := .test .one
  have hstep' : Sequent.OrderedBA ⟨(.seq e W) :: Γ, .and B b, Δ⟩ :=
    product_left_BA hstep
  have hexit' : Sequent.OrderedBA ⟨one :: Γ, .and B (.not b), Δ⟩ := by
    apply LeqBA.trans _ hexit
    exact LeqBA.seq_mono (LeqBA.refl (.test (.and B (.not b))))
      (LeqBA.equiv (Equiv.s4 (cedent Γ)))
  have hchoice : Sequent.OrderedBA
      ⟨(.ite b (.seq e W) one) :: Γ, B, Δ⟩ := choice_left hstep' hexit'
  apply LeqBA.trans _ hchoice
  exact LeqBA.seq_mono (LeqBA.refl (.test B))
    (LeqBA.seq_mono (LeqBA.equiv (Equiv.w1 b e)) (LeqBA.refl (cedent Γ)))

/-- Compile SGKAT's while-right rule. Locally this is also `W1` unfolding; cyclic proof
    fairness becomes relevant only when a finite proof graph connects a descendant back to
    an ancestor. -/
theorem while_right {b B : BExp T} {e : Exp A T} {Γ Δ : List (Exp A T)}
    (hstep : Sequent.OrderedBA ⟨Γ, .and B b, e :: (.wh b e) :: Δ⟩)
    (hexit : Sequent.OrderedBA ⟨Γ, .and B (.not b), Δ⟩) :
    Sequent.OrderedBA ⟨Γ, B, (.wh b e) :: Δ⟩ := by
  let W : Exp A T := .wh b e
  let one : Exp A T := .test .one
  have hstep' : Sequent.OrderedBA ⟨Γ, .and B b, (.seq e W) :: Δ⟩ :=
    product_right_BA hstep
  have hexit' : Sequent.OrderedBA ⟨Γ, .and B (.not b), one :: Δ⟩ :=
    LeqBA.trans hexit (LeqBA.equiv (Equiv.symm (Equiv.s4 (cedent Δ))))
  have hchoice : Sequent.OrderedBA
      ⟨Γ, B, (.ite b (.seq e W) one) :: Δ⟩ := choice_right hstep' hexit'
  exact LeqBA.trans hchoice
    (LeqBA.seq_mono (LeqBA.equiv (Equiv.symm (Equiv.w1 b e)))
      (LeqBA.refl (cedent Δ)))

/-- Compile SGKAT's modal `k` rule. The premise is valid at all atoms; the conclusion may
    restrict the starting atom and prefixes the same primitive action on both sides. -/
theorem modal_k {p : A} {B : BExp T} {Γ Δ : List (Exp A T)}
    (h : Sequent.OrderedBA ⟨Γ, .one, Δ⟩) :
    Sequent.OrderedBA ⟨(.act p) :: Γ, B, (.act p) :: Δ⟩ := by
  let G := cedent Γ
  let D := cedent Δ
  have hGD : LeqBA G D :=
    LeqBA.trans (LeqBA.equiv (Equiv.symm (Equiv.s4 G))) h
  have hB1 : LeqBA (.test B : Exp A T) (.test .one) := by
    apply LeqBA.test_le
    intro X V x hB
    rfl
  apply LeqBA.trans (LeqBA.seq_mono hB1 (LeqBA.refl (.seq (.act p) G)))
  apply LeqBA.trans (LeqBA.equiv (Equiv.s4 (.seq (.act p) G)))
  exact LeqBA.seq_mono (LeqBA.refl (.act p)) hGD

/-- Compile SGKAT's `k₀` rule. If the tail is empty at all atoms, action-prefixing it remains
    empty and therefore lies below every succedent. -/
theorem modal_k0 {p : A} {B : BExp T} {Γ Δ : List (Exp A T)}
    (h : Sequent.OrderedBA ⟨Γ, .one, [(.test .zero)]⟩) :
    Sequent.OrderedBA ⟨(.act p) :: Γ, B, Δ⟩ := by
  let G := cedent Γ
  have hG0 : LeqBA G (.test .zero) := by
    apply LeqBA.trans (LeqBA.equiv (Equiv.symm (Equiv.s4 G)))
    apply LeqBA.trans h
    exact LeqBA.equiv (Equiv.s5 (.test .zero))
  have hB1 : LeqBA (.test B : Exp A T) (.test .one) := by
    apply LeqBA.test_le
    intro X V x hB
    rfl
  apply LeqBA.trans (LeqBA.seq_mono hB1 (LeqBA.refl (.seq (.act p) G)))
  apply LeqBA.trans (LeqBA.equiv (Equiv.s4 (.seq (.act p) G)))
  apply LeqBA.trans (LeqBA.seq_mono (LeqBA.refl (.act p)) hG0)
  exact LeqBA.trans (LeqBA.equiv (Equiv.s3 (.act p))) (LeqBA.zero_le (cedent Δ))

/-! ## Finite SGKAT logical derivations -/

/-- The well-founded fragment of SGKAT, using the exact paper rule shapes. Backedges are
    intentionally kept out of this datatype and will be added by the cyclic graph layer. -/
inductive FinDeriv : Sequent A T → Prop where
  | identity (B : BExp T) : FinDeriv ⟨[], B, []⟩
  | bottom (Γ Δ : List (Exp A T)) : FinDeriv ⟨Γ, .zero, Δ⟩
  | testL {b B : BExp T} {Γ Δ : List (Exp A T)} :
      FinDeriv ⟨Γ, .and B b, Δ⟩ → FinDeriv ⟨(.test b) :: Γ, B, Δ⟩
  | testR {b B : BExp T} {Γ Δ : List (Exp A T)} :
      (∀ (X : Type) (V : T → X → Bool) (x : X),
        bval V B x = true → bval V b x = true) →
      FinDeriv ⟨Γ, B, Δ⟩ → FinDeriv ⟨Γ, B, (.test b) :: Δ⟩
  | productL {e f : Exp A T} {B : BExp T} {Γ Δ : List (Exp A T)} :
      FinDeriv ⟨e :: f :: Γ, B, Δ⟩ → FinDeriv ⟨(.seq e f) :: Γ, B, Δ⟩
  | productR {e f : Exp A T} {B : BExp T} {Γ Δ : List (Exp A T)} :
      FinDeriv ⟨Γ, B, e :: f :: Δ⟩ → FinDeriv ⟨Γ, B, (.seq e f) :: Δ⟩
  | choiceL {b B : BExp T} {e f : Exp A T} {Γ Δ : List (Exp A T)} :
      FinDeriv ⟨e :: Γ, .and B b, Δ⟩ →
      FinDeriv ⟨f :: Γ, .and B (.not b), Δ⟩ →
      FinDeriv ⟨(.ite b e f) :: Γ, B, Δ⟩
  | choiceR {b B : BExp T} {e f : Exp A T} {Γ Δ : List (Exp A T)} :
      FinDeriv ⟨Γ, .and B b, e :: Δ⟩ →
      FinDeriv ⟨Γ, .and B (.not b), f :: Δ⟩ →
      FinDeriv ⟨Γ, B, (.ite b e f) :: Δ⟩
  | whileL {b B : BExp T} {e : Exp A T} {Γ Δ : List (Exp A T)} :
      FinDeriv ⟨e :: (.wh b e) :: Γ, .and B b, Δ⟩ →
      FinDeriv ⟨Γ, .and B (.not b), Δ⟩ →
      FinDeriv ⟨(.wh b e) :: Γ, B, Δ⟩
  | whileR {b B : BExp T} {e : Exp A T} {Γ Δ : List (Exp A T)} :
      FinDeriv ⟨Γ, .and B b, e :: (.wh b e) :: Δ⟩ →
      FinDeriv ⟨Γ, .and B (.not b), Δ⟩ →
      FinDeriv ⟨Γ, B, (.wh b e) :: Δ⟩
  | modalK {p : A} {B : BExp T} {Γ Δ : List (Exp A T)} :
      FinDeriv ⟨Γ, .one, Δ⟩ → FinDeriv ⟨(.act p) :: Γ, B, (.act p) :: Δ⟩
  | modalK0 {p : A} {B : BExp T} {Γ Δ : List (Exp A T)} :
      FinDeriv ⟨Γ, .one, [(.test .zero)]⟩ → FinDeriv ⟨(.act p) :: Γ, B, Δ⟩

/-- **Compile every finite SGKAT logical derivation into ordered GKAT+BA.** The proof is
    structural and delegates each paper rule to its axiom-free local compiler above. -/
theorem FinDeriv.compile {s : Sequent A T} (d : FinDeriv s) : s.OrderedBA := by
  induction d with
  | identity B => exact empty_identity_BA B
  | bottom Γ Δ => exact bottom_axiom
  | testL d ih => exact test_left ih
  | testR hB d ih => exact test_right hB ih
  | productL d ih => exact product_left_BA ih
  | productR d ih => exact product_right_BA ih
  | choiceL de df ihe ihf => exact choice_left ihe ihf
  | choiceR de df ihe ihf => exact choice_right ihe ihf
  | whileL ds dx ihs ihx => exact while_left ihs ihx
  | whileR ds dx ihs ihx => exact while_right ihs ihx
  | modalK d ih => exact modal_k ih
  | modalK0 d ih => exact modal_k0 ih

/-! ## Finite trees with typed backedge leaves -/

/-- An SGKAT derivation cut open at selected sequents. `Open s` classifies exactly the
    sequents permitted as backedge leaves. This is the finite-tree presentation of a regular
    proof before cyclic assumptions are discharged. -/
inductive OpenDeriv (Open : Sequent A T → Prop) : Sequent A T → Type where
  | backedge {s : Sequent A T} : Open s → OpenDeriv Open s
  | identity (B : BExp T) : OpenDeriv Open ⟨[], B, []⟩
  | bottom (Γ Δ : List (Exp A T)) : OpenDeriv Open ⟨Γ, .zero, Δ⟩
  | testL {b B : BExp T} {Γ Δ : List (Exp A T)} :
      OpenDeriv Open ⟨Γ, .and B b, Δ⟩ → OpenDeriv Open ⟨(.test b) :: Γ, B, Δ⟩
  | testR {b B : BExp T} {Γ Δ : List (Exp A T)} :
      (∀ (X : Type) (V : T → X → Bool) (x : X),
        bval V B x = true → bval V b x = true) →
      OpenDeriv Open ⟨Γ, B, Δ⟩ → OpenDeriv Open ⟨Γ, B, (.test b) :: Δ⟩
  | productL {e f : Exp A T} {B : BExp T} {Γ Δ : List (Exp A T)} :
      OpenDeriv Open ⟨e :: f :: Γ, B, Δ⟩ → OpenDeriv Open ⟨(.seq e f) :: Γ, B, Δ⟩
  | productR {e f : Exp A T} {B : BExp T} {Γ Δ : List (Exp A T)} :
      OpenDeriv Open ⟨Γ, B, e :: f :: Δ⟩ → OpenDeriv Open ⟨Γ, B, (.seq e f) :: Δ⟩
  | choiceL {b B : BExp T} {e f : Exp A T} {Γ Δ : List (Exp A T)} :
      OpenDeriv Open ⟨e :: Γ, .and B b, Δ⟩ →
      OpenDeriv Open ⟨f :: Γ, .and B (.not b), Δ⟩ →
      OpenDeriv Open ⟨(.ite b e f) :: Γ, B, Δ⟩
  | choiceR {b B : BExp T} {e f : Exp A T} {Γ Δ : List (Exp A T)} :
      OpenDeriv Open ⟨Γ, .and B b, e :: Δ⟩ →
      OpenDeriv Open ⟨Γ, .and B (.not b), f :: Δ⟩ →
      OpenDeriv Open ⟨Γ, B, (.ite b e f) :: Δ⟩
  | whileL {b B : BExp T} {e : Exp A T} {Γ Δ : List (Exp A T)} :
      OpenDeriv Open ⟨e :: (.wh b e) :: Γ, .and B b, Δ⟩ →
      OpenDeriv Open ⟨Γ, .and B (.not b), Δ⟩ →
      OpenDeriv Open ⟨(.wh b e) :: Γ, B, Δ⟩
  | whileR {b B : BExp T} {e : Exp A T} {Γ Δ : List (Exp A T)} :
      OpenDeriv Open ⟨Γ, .and B b, e :: (.wh b e) :: Δ⟩ →
      OpenDeriv Open ⟨Γ, .and B (.not b), Δ⟩ →
      OpenDeriv Open ⟨Γ, B, (.wh b e) :: Δ⟩
  | modalK {p : A} {B : BExp T} {Γ Δ : List (Exp A T)} :
      OpenDeriv Open ⟨Γ, .one, Δ⟩ → OpenDeriv Open ⟨(.act p) :: Γ, B, (.act p) :: Δ⟩
  | modalK0 {p : A} {B : BExp T} {Γ Δ : List (Exp A T)} :
      OpenDeriv Open ⟨Γ, .one, [(.test .zero)]⟩ → OpenDeriv Open ⟨(.act p) :: Γ, B, Δ⟩

/-- Compile an open derivation given algebraic proofs for its typed backedge leaves. This
    theorem compiles every finite region between backedges; it makes the remaining cyclic
    obligation explicit in the `close` argument. -/
theorem OpenDeriv.compile {Open : Sequent A T → Prop} {s : Sequent A T}
    (d : OpenDeriv Open s) (close : ∀ t, Open t → t.OrderedBA) : s.OrderedBA := by
  induction d with
  | backedge h => exact close _ h
  | identity B => exact empty_identity_BA B
  | bottom Γ Δ => exact bottom_axiom
  | testL d ih => exact test_left ih
  | testR hB d ih => exact test_right hB ih
  | productL d ih => exact product_left_BA ih
  | productR d ih => exact product_right_BA ih
  | choiceL de df ihe ihf => exact choice_left ihe ihf
  | choiceR de df ihe ihf => exact choice_right ihe ihf
  | whileL ds dx ihs ihx => exact while_left ihs ihx
  | whileR ds dx ihs ihx => exact while_right ihs ihx
  | modalK d ih => exact modal_k ih
  | modalK0 d ih => exact modal_k0 ih

/-- Close every typed open leaf with an ordinary finite derivation. This is the syntactic
    counterpart of `OpenDeriv.compile`; graph extraction can first substitute cyclic
    hypotheses, prove the resulting leaves finitely, and then recover a closed SGKAT tree. -/
theorem OpenDeriv.close {Open : Sequent A T → Prop} {s : Sequent A T}
    (d : OpenDeriv Open s) (close : ∀ t, Open t → FinDeriv t) : FinDeriv s := by
  induction d with
  | backedge h => exact close _ h
  | identity B => exact .identity B
  | bottom Γ Δ => exact .bottom Γ Δ
  | testL d ih => exact .testL ih
  | testR hB d ih => exact .testR hB ih
  | productL d ih => exact .productL ih
  | productR d ih => exact .productR ih
  | choiceL de df ihe ihf => exact .choiceL ihe ihf
  | choiceR de df ihe ihf => exact .choiceR ihe ihf
  | whileL ds dx ihs ihx => exact .whileL ihs ihx
  | whileR ds dx ihs ihx => exact .whileR ihs ihx
  | modalK d ih => exact .modalK ih
  | modalK0 d ih => exact .modalK0 ih

/-- Substitute an open derivation for every typed backedge leaf. This is proof-graph
    composition: it expands one regular component into the next while preserving every
    SGKAT rule above the cut. -/
noncomputable def OpenDeriv.bind {Open Open' : Sequent A T → Prop} {s : Sequent A T}
    (d : OpenDeriv Open s) (k : ∀ t, Open t → OpenDeriv Open' t) :
    OpenDeriv Open' s := by
  induction d with
  | backedge h => exact k _ h
  | identity B => exact .identity B
  | bottom Γ Δ => exact .bottom Γ Δ
  | testL d ih => exact .testL ih
  | testR hB d ih => exact .testR hB ih
  | productL d ih => exact .productL ih
  | productR d ih => exact .productR ih
  | choiceL de df ihe ihf => exact .choiceL ihe ihf
  | choiceR de df ihe ihf => exact .choiceR ihe ihf
  | whileL ds dx ihs ihx => exact .whileL ihs ihx
  | whileR ds dx ihs ihx => exact .whileR ihs ihx
  | modalK d ih => exact .modalK ih
  | modalK0 d ih => exact .modalK0 ih

set_option autoImplicit true in
/-- Structural SGKAT fairness for a cut-open finite tree: every path from this node to an
    open backedge leaf crosses a while-left rule. Closed branches are fair vacuously;
    while-right does not count, matching the paper's asymmetric progress condition. -/
inductive OpenDeriv.Fair {Open : Sequent A T → Prop} :
    {s : Sequent A T} → OpenDeriv Open s → Prop where
  | identity : Fair (.identity _)
  | bottom : Fair (.bottom _ _)
  | testL (h : d.Fair) : Fair (.testL d)
  | testR
      (hb : ∀ (X : Type) (V : T → X → Bool) (x : X),
        bval V B x = true → bval V b x = true)
      (h : d.Fair) : Fair (.testR hb d)
  | productL (h : d.Fair) : Fair (.productL d)
  | productR (h : d.Fair) : Fair (.productR d)
  | choiceL (h₁ : d₁.Fair) (h₂ : d₂.Fair) : Fair (.choiceL d₁ d₂)
  | choiceR (h₁ : d₁.Fair) (h₂ : d₂.Fair) : Fair (.choiceR d₁ d₂)
  | whileL {b B : BExp T} {e : Exp A T} {Γ Δ : List (Exp A T)}
      (d₁ : OpenDeriv Open ⟨e :: (.wh b e) :: Γ, .and B b, Δ⟩)
      (d₂ : OpenDeriv Open ⟨Γ, .and B (.not b), Δ⟩) : Fair (.whileL d₁ d₂)
  | whileR (h₁ : d₁.Fair) (h₂ : d₂.Fair) : Fair (.whileR d₁ d₂)
  | modalK (h : d.Fair) : Fair (.modalK d)
  | modalK0 (h : d.Fair) : Fair (.modalK0 d)

set_option autoImplicit true in
/-- Evidence for a path from a derivation node to a backedge that crosses no while-left.
    Binary constructors choose one branch; while-right is transparent and while-left has
    deliberately no constructor. -/
inductive OpenDeriv.Unguarded {Open : Sequent A T → Prop} :
    {s : Sequent A T} → OpenDeriv Open s → Prop where
  | backedge (h : Open s) : Unguarded (.backedge h)
  | testL (h : d.Unguarded) : Unguarded (.testL d)
  | testR
      (hb : ∀ (X : Type) (V : T → X → Bool) (x : X),
        bval V B x = true → bval V b x = true)
      (h : d.Unguarded) : Unguarded (.testR hb d)
  | productL (h : d.Unguarded) : Unguarded (.productL d)
  | productR (h : d.Unguarded) : Unguarded (.productR d)
  | choiceL_left (h : d₁.Unguarded) : Unguarded (.choiceL d₁ d₂)
  | choiceL_right (h : d₂.Unguarded) : Unguarded (.choiceL d₁ d₂)
  | choiceR_left (h : d₁.Unguarded) : Unguarded (.choiceR d₁ d₂)
  | choiceR_right (h : d₂.Unguarded) : Unguarded (.choiceR d₁ d₂)
  | whileR_left (h : d₁.Unguarded) : Unguarded (.whileR d₁ d₂)
  | whileR_right (h : d₂.Unguarded) : Unguarded (.whileR d₁ d₂)
  | modalK (h : d.Unguarded) : Unguarded (.modalK d)
  | modalK0 (h : d.Unguarded) : Unguarded (.modalK0 d)

/-- The structural certificate implies the paper's path formulation of fairness: there is
    no route to a cyclic backedge that avoids a progressing while-left rule. -/
theorem OpenDeriv.Fair.no_unguarded {Open : Sequent A T → Prop} {s : Sequent A T}
    {d : OpenDeriv Open s} (h : d.Fair) : ¬ d.Unguarded := by
  induction h with
  | identity => intro hu; cases hu
  | bottom => intro hu; cases hu
  | testL h ih => intro hu; cases hu with | testL hu => exact ih hu
  | testR hb h ih => intro hu; cases hu with | testR _ hu => exact ih hu
  | productL h ih => intro hu; cases hu with | productL hu => exact ih hu
  | productR h ih => intro hu; cases hu with | productR hu => exact ih hu
  | choiceL h₁ h₂ ih₁ ih₂ =>
      intro hu
      cases hu with
      | choiceL_left hu => exact ih₁ hu
      | choiceL_right hu => exact ih₂ hu
  | choiceR h₁ h₂ ih₁ ih₂ =>
      intro hu
      cases hu with
      | choiceR_left hu => exact ih₁ hu
      | choiceR_right hu => exact ih₂ hu
  | whileL d₁ d₂ => intro hu; cases hu
  | whileR h₁ h₂ ih₁ ih₂ =>
      intro hu
      cases hu with
      | whileR_left hu => exact ih₁ hu
      | whileR_right hu => exact ih₂ hu
  | modalK h ih => intro hu; cases hu with | modalK hu => exact ih hu
  | modalK0 h ih => intro hu; cases hu with | modalK0 hu => exact ih hu

/-- Conversely, the path formulation constructs the structural certificate. Hence the two
    presentations of SGKAT fairness are interchangeable without classical reasoning. -/
theorem OpenDeriv.fair_of_no_unguarded {Open : Sequent A T → Prop} {s : Sequent A T}
    (d : OpenDeriv Open s) (h : ¬ d.Unguarded) : d.Fair := by
  induction d with
  | backedge hopen => exact False.elim (h (.backedge hopen))
  | identity B => exact .identity
  | bottom Γ Δ => exact .bottom
  | testL d ih => exact .testL (ih (fun hu => h (.testL hu)))
  | testR hb d ih => exact .testR hb (ih (fun hu => h (.testR hb hu)))
  | productL d ih => exact .productL (ih (fun hu => h (.productL hu)))
  | productR d ih => exact .productR (ih (fun hu => h (.productR hu)))
  | choiceL d₁ d₂ ih₁ ih₂ =>
      exact .choiceL
        (ih₁ (fun hu => h (.choiceL_left hu)))
        (ih₂ (fun hu => h (.choiceL_right hu)))
  | choiceR d₁ d₂ ih₁ ih₂ =>
      exact .choiceR
        (ih₁ (fun hu => h (.choiceR_left hu)))
        (ih₂ (fun hu => h (.choiceR_right hu)))
  | whileL d₁ d₂ ih₁ ih₂ => exact .whileL d₁ d₂
  | whileR d₁ d₂ ih₁ ih₂ =>
      exact .whileR
        (ih₁ (fun hu => h (.whileR_left hu)))
        (ih₂ (fun hu => h (.whileR_right hu)))
  | modalK d ih => exact .modalK (ih (fun hu => h (.modalK hu)))
  | modalK0 d ih => exact .modalK0 (ih (fun hu => h (.modalK0 hu)))

theorem OpenDeriv.fair_iff_no_unguarded {Open : Sequent A T → Prop}
    {s : Sequent A T} (d : OpenDeriv Open s) : d.Fair ↔ ¬ d.Unguarded :=
  ⟨OpenDeriv.Fair.no_unguarded, d.fair_of_no_unguarded⟩

/-- Executable fairness check. A while-left node guards its complete subtree; all other
    branching rules require both branches to pass, and a bare backedge fails. -/
def OpenDeriv.guarded {Open : Sequent A T → Prop} {s : Sequent A T} :
    OpenDeriv Open s → Bool
  | .backedge _ => false
  | .identity _ => true
  | .bottom _ _ => true
  | .testL d => d.guarded
  | .testR _ d => d.guarded
  | .productL d => d.guarded
  | .productR d => d.guarded
  | .choiceL d₁ d₂ => d₁.guarded && d₂.guarded
  | .choiceR d₁ d₂ => d₁.guarded && d₂.guarded
  | .whileL _ _ => true
  | .whileR d₁ d₂ => d₁.guarded && d₂.guarded
  | .modalK d => d.guarded
  | .modalK0 d => d.guarded

private theorem bool_and_true_elim {a b : Bool} (h : (a && b) = true) :
    a = true ∧ b = true := by
  cases a <;> cases b
  · cases h
  · cases h
  · cases h
  · exact ⟨rfl, rfl⟩

private theorem bool_and_true_intro {a b : Bool}
    (ha : a = true) (hb : b = true) : (a && b) = true := by
  cases ha
  cases hb
  rfl

theorem OpenDeriv.fair_of_guarded {Open : Sequent A T → Prop} {s : Sequent A T}
    (d : OpenDeriv Open s) (h : d.guarded = true) : d.Fair := by
  induction d with
  | backedge hopen => cases h
  | identity B => exact .identity
  | bottom Γ Δ => exact .bottom
  | testL d ih => exact .testL (ih h)
  | testR hb d ih => exact .testR hb (ih h)
  | productL d ih => exact .productL (ih h)
  | productR d ih => exact .productR (ih h)
  | choiceL d₁ d₂ ih₁ ih₂ =>
      have hs := bool_and_true_elim h
      exact .choiceL (ih₁ hs.1) (ih₂ hs.2)
  | choiceR d₁ d₂ ih₁ ih₂ =>
      have hs := bool_and_true_elim h
      exact .choiceR (ih₁ hs.1) (ih₂ hs.2)
  | whileL d₁ d₂ ih₁ ih₂ => exact .whileL d₁ d₂
  | whileR d₁ d₂ ih₁ ih₂ =>
      have hs := bool_and_true_elim h
      exact .whileR (ih₁ hs.1) (ih₂ hs.2)
  | modalK d ih => exact .modalK (ih h)
  | modalK0 d ih => exact .modalK0 (ih h)

theorem OpenDeriv.Fair.guarded {Open : Sequent A T → Prop} {s : Sequent A T}
    {d : OpenDeriv Open s} (h : d.Fair) : d.guarded = true := by
  induction h with
  | identity => rfl
  | bottom => rfl
  | testL h ih => exact ih
  | testR hb h ih => exact ih
  | productL h ih => exact ih
  | productR h ih => exact ih
  | choiceL h₁ h₂ ih₁ ih₂ => exact bool_and_true_intro ih₁ ih₂
  | choiceR h₁ h₂ ih₁ ih₂ => exact bool_and_true_intro ih₁ ih₂
  | whileL d₁ d₂ => rfl
  | whileR h₁ h₂ ih₁ ih₂ => exact bool_and_true_intro ih₁ ih₂
  | modalK h ih => exact ih
  | modalK0 h ih => exact ih

theorem OpenDeriv.fair_iff_guarded {Open : Sequent A T → Prop}
    {s : Sequent A T} (d : OpenDeriv Open s) : d.Fair ↔ d.guarded = true :=
  ⟨OpenDeriv.Fair.guarded, d.fair_of_guarded⟩

/-- Fairness is constructively decidable by evaluating `guarded`. -/
instance OpenDeriv.instDecidableFair {Open : Sequent A T → Prop}
    {s : Sequent A T} (d : OpenDeriv Open s) : Decidable d.Fair :=
  if h : d.guarded = true then
    isTrue (d.fair_of_guarded h)
  else
    isFalse (fun hf => h hf.guarded)

/-- Fairness is stable under arbitrary proof-graph substitution. Every route to an old
    backedge already crossed while-left, whose progress guards the entire inserted tree. -/
theorem OpenDeriv.Fair.bind {Open Open' : Sequent A T → Prop} {s : Sequent A T}
    {d : OpenDeriv Open s} (h : d.Fair)
    (k : ∀ t, Open t → OpenDeriv Open' t) : (d.bind k).Fair := by
  induction h with
  | identity => exact .identity
  | bottom => exact .bottom
  | testL h ih => exact .testL ih
  | testR hb h ih => simpa [OpenDeriv.bind] using OpenDeriv.Fair.testR hb ih
  | productL h ih => exact .productL ih
  | productR h ih => exact .productR ih
  | choiceL h₁ h₂ ih₁ ih₂ => exact .choiceL ih₁ ih₂
  | choiceR h₁ h₂ ih₁ ih₂ => exact .choiceR ih₁ ih₂
  | whileL d₁ d₂ => exact .whileL (d₁.bind k) (d₂.bind k)
  | whileR h₁ h₂ ih₁ ih₂ => exact .whileR ih₁ ih₂
  | modalK h ih => exact .modalK ih
  | modalK0 h ih => exact .modalK0 ih

/-! ## Ordered expansion of regular-proof components -/

/-- An acyclic SCC-elimination schedule. Each step replaces all leaves classified by one
    open predicate with derivations whose leaves belong to the next predicate. The terminal
    predicate describes the backedges left for finite discharge. -/
inductive ExpansionChain (A T : Type) :
    (Sequent A T → Prop) → (Sequent A T → Prop) → Type 1 where
  | done (Open : Sequent A T → Prop) : ExpansionChain A T Open Open
  | step {Open Mid Final : Sequent A T → Prop}
      (expand : ∀ s, Open s → OpenDeriv Mid s)
      (tail : ExpansionChain A T Mid Final) : ExpansionChain A T Open Final

/-- Execute an SCC-elimination schedule by repeated proof-graph substitution. -/
noncomputable def ExpansionChain.apply {Open Final : Sequent A T → Prop}
    (chain : ExpansionChain A T Open Final) {s : Sequent A T}
    (d : OpenDeriv Open s) : OpenDeriv Final s :=
  match chain with
  | .done _ => d
  | .step expand tail => tail.apply (d.bind expand)

/-- Fairness survives an arbitrary acyclic sequence of SCC expansions. -/
theorem ExpansionChain.apply_fair {Open Final : Sequent A T → Prop}
    (chain : ExpansionChain A T Open Final) {s : Sequent A T}
    {d : OpenDeriv Open s} (h : d.Fair) : (chain.apply d).Fair := by
  induction chain with
  | done Open => exact h
  | step expand tail ih => exact ih (h.bind expand)

/-- Expand all scheduled SCCs and close the terminal leaves with finite SGKAT proofs. -/
def ExpansionChain.close {Open Final : Sequent A T → Prop}
    (chain : ExpansionChain A T Open Final) {s : Sequent A T}
    (d : OpenDeriv Open s) (close : ∀ t, Final t → FinDeriv t) : FinDeriv s :=
  (chain.apply d).close close

/-- Algebraic compilation of an entire acyclic SCC schedule. Cyclic work is isolated in
    the supplied expansions; all terminal finite regions compile through `FinDeriv`. -/
theorem ExpansionChain.compile {Open Final : Sequent A T → Prop}
    (chain : ExpansionChain A T Open Final) {s : Sequent A T}
    (d : OpenDeriv Open s) (close : ∀ t, Final t → FinDeriv t) : s.OrderedBA :=
  (chain.close d close).compile

/-- Compile an expansion schedule whose terminal SCCs have already been discharged
    algebraically (for example, by focused star induction). This is the composition point
    between graph expansion and cyclic closure. -/
theorem ExpansionChain.compileOrdered {Open Final : Sequent A T → Prop}
    (chain : ExpansionChain A T Open Final) {s : Sequent A T}
    (d : OpenDeriv Open s) (close : ∀ t, Final t → t.OrderedBA) : s.OrderedBA :=
  (chain.apply d).compile close

/-- A finite regular-proof component: a cut-open derivation plus the SGKAT progress check.
    The next theorem layer will turn this fairness evidence into `star_ind` discharges for
    the component's backedges. -/
structure FairComponent (Open : Sequent A T → Prop) (root : Sequent A T) where
  tree : OpenDeriv Open root
  fair : tree.Fair

/-- A machine-checkable regular-proof component. This is the preferred boundary for an
    eventual graph parser or SCC extractor. -/
structure CheckedComponent (Open : Sequent A T → Prop) (root : Sequent A T) where
  tree : OpenDeriv Open root
  guarded : tree.guarded = true

def CheckedComponent.toFair {Open : Sequent A T → Prop} {root : Sequent A T}
    (component : CheckedComponent Open root) : FairComponent Open root where
  tree := component.tree
  fair := component.tree.fair_of_guarded component.guarded

/-- Expand a fair component through an acyclic SCC schedule, retaining its trace proof. -/
noncomputable def FairComponent.expand {Open Final : Sequent A T → Prop} {root : Sequent A T}
    (component : FairComponent Open root) (chain : ExpansionChain A T Open Final) :
    FairComponent Final root where
  tree := chain.apply component.tree
  fair := chain.apply_fair component.fair

/-- Checked components remain checked after an SCC expansion schedule. -/
noncomputable def CheckedComponent.expand {Open Final : Sequent A T → Prop}
    {root : Sequent A T} (component : CheckedComponent Open root)
    (chain : ExpansionChain A T Open Final) : CheckedComponent Final root where
  tree := chain.apply component.tree
  guarded := (chain.apply_fair
    (component.tree.fair_of_guarded component.guarded)).guarded

variable {Atom : Type}

/-- A compiled sequent has the paper's intended guarded-language inclusion semantics. -/
theorem ordered_sequent_sound (V : T → Atom → Bool) {s : Sequent A T}
    (h : s.Ordered) : ∀ gs, den V s.left gs → den V s.right gs :=
  le_sound V h

/-- Soundness of annotation-sensitive sequents compiled into the Boolean-aware order. -/
theorem orderedBA_sequent_sound (V : T → Atom → Bool) {s : Sequent A T}
    (h : s.OrderedBA) : ∀ gs, den V s.left gs → den V s.right gs :=
  GkatOrderedBA.le_sound V h

/-!
All finite SGKAT rules now compile into `LeqBA`. The remaining frontier is cyclic closure:
turning a fair regular graph into the pre-fixpoint premise consumed by `LeqBA.star_ind`.
The open derivation and fairness certificate above deliberately expose that obligation
without assuming the cyclic hypotheses as axioms.
-/

/-- A positive one-hole GKAT context. Every constructor is monotone in its hole, matching
    the congruence surface of ordered GKAT. -/
inductive PosCtx (A T : Type) where
  | hole
  | seqLeft (C : PosCtx A T) (r : Exp A T)
  | seqRight (l : Exp A T) (C : PosCtx A T)
  | iteThen (b : BExp T) (C : PosCtx A T) (r : Exp A T)
  | iteElse (b : BExp T) (l : Exp A T) (C : PosCtx A T)
  | whBody (b : BExp T) (C : PosCtx A T)

/-- Fill the unique hole of a positive context. -/
def PosCtx.fill : PosCtx A T → Exp A T → Exp A T
  | .hole, x => x
  | .seqLeft C r, x => .seq (C.fill x) r
  | .seqRight l C, x => .seq l (C.fill x)
  | .iteThen b C r, x => .ite b (C.fill x) r
  | .iteElse b l C, x => .ite b l (C.fill x)
  | .whBody b C, x => .wh b (C.fill x)

/-- Positive contexts preserve ordered derivability. This is the finite local-rule compiler
    for the congruence portion of a cyclic proof surrounding its progressing SCC. -/
theorem PosCtx.mono (C : PosCtx A T) {x y : Exp A T} (h : Leq x y) :
    Leq (C.fill x) (C.fill y) := by
  induction C with
  | hole => exact h
  | seqLeft C r ih => exact Leq.seq_mono ih (Leq.refl r)
  | seqRight l C ih => exact Leq.seq_mono (Leq.refl l) ih
  | iteThen b C r ih => exact Leq.ite_mono ih (Leq.refl r)
  | iteElse b l C ih => exact Leq.ite_mono (Leq.refl l) ih
  | whBody b C ih => exact Leq.wh_mono ih

/-- Positive contexts are also monotone in the Boolean-aware ordered theory used by the
    complete SGKAT rule compiler. -/
theorem PosCtx.monoBA (C : PosCtx A T) {x y : Exp A T} (h : LeqBA x y) :
    LeqBA (C.fill x) (C.fill y) := by
  induction C with
  | hole => exact h
  | seqLeft C r ih => exact LeqBA.seq_mono ih (LeqBA.refl r)
  | seqRight l C ih => exact LeqBA.seq_mono (LeqBA.refl l) ih
  | iteThen b C r ih => exact LeqBA.ite_mono ih (LeqBA.refl r)
  | iteElse b l C ih => exact LeqBA.ite_mono (LeqBA.refl l) ih
  | whBody b C ih => exact LeqBA.wh_mono ih

/-- A finite certificate for one progressing cyclic SCC. `body` is what remains after the
    unique backedge is cut: the loop functional, with recursive occurrence interpreted by
    the proposed post-fixpoint `g`, lies below `g`. -/
structure OneCycle (A T : Type) where
  guard : BExp T
  bodyExp : Exp A T
  exit : Exp A T
  post : Exp A T
  context : PosCtx A T
  body : Leq (.ite guard (.seq bodyExp post) exit) post

/-- The source formula denoted by the cyclic certificate: the least loop solution in its
    surrounding positive context. -/
def OneCycle.source (p : OneCycle A T) : Exp A T :=
  p.context.fill (.seq (.wh p.guard p.bodyExp) p.exit)

/-- The target formula denoted by the certificate. -/
def OneCycle.target (p : OneCycle A T) : Exp A T := p.context.fill p.post

/-- **Compile one regular progressing cycle into ordered GKAT.** Star induction discharges
    the cut backedge; context monotonicity compiles every finite congruence step above it. -/
theorem compile_oneCycle (p : OneCycle A T) : Leq p.source p.target :=
  p.context.mono (Leq.star_ind p.body)

/-- A focused progressing SCC whose finite region has already been compiled by the full
    Boolean-aware SGKAT compiler. Unlike `OneCycle`, its pre-fixpoint proof may use test
    restriction, conjunction, and bottom. -/
structure OneCycleBA (A T : Type) where
  guard : BExp T
  bodyExp : Exp A T
  exit : Exp A T
  post : Exp A T
  context : PosCtx A T
  body : LeqBA (.ite guard (.seq bodyExp post) exit) post

def OneCycleBA.source (p : OneCycleBA A T) : Exp A T :=
  p.context.fill (.seq (.wh p.guard p.bodyExp) p.exit)

def OneCycleBA.target (p : OneCycleBA A T) : Exp A T := p.context.fill p.post

/-- **Focused fair-SCC closure for full SGKAT.** The compiled finite region supplies the
    pre-fixpoint premise, `star_ind` closes its progressing backedge, and positivity lifts
    the result through all surrounding program structure. -/
theorem compile_oneCycleBA (p : OneCycleBA A T) : LeqBA p.source p.target :=
  p.context.monoBA (LeqBA.star_ind p.body)

/-- The exact output expected from a focused cyclic-graph extraction pass. The recursive
    occurrence has already been replaced by `post`, leaving an ordinary finite SGKAT
    derivation of the pre-fixpoint premise. Boundary equalities allow the sequent compiler
    to remain independent of any particular normalization convention for cedents. -/
structure FocusedCycleDeriv (A T : Type) where
  guard : BExp T
  bodyExp : Exp A T
  exit : Exp A T
  post : Exp A T
  context : PosCtx A T
  premise : Sequent A T
  tree : FinDeriv premise
  left_eq : premise.left = .ite guard (.seq bodyExp post) exit
  right_eq : premise.right = post

/-- Compile the finite substituted region into the Boolean-aware one-cycle certificate. -/
def FocusedCycleDeriv.toOneCycleBA (p : FocusedCycleDeriv A T) : OneCycleBA A T where
  guard := p.guard
  bodyExp := p.bodyExp
  exit := p.exit
  post := p.post
  context := p.context
  body := by
    have h := p.tree.compile
    change LeqBA p.premise.left p.premise.right at h
    rw [p.left_eq, p.right_eq] at h
    exact h

/-- **End-to-end focused cyclic compilation.** A finite SGKAT proof of the substituted
    loop body is compiled rule-by-rule, its unique progressing cycle is discharged with
    star induction, and the result is lifted through the surrounding positive context. -/
theorem FocusedCycleDeriv.compile (p : FocusedCycleDeriv A T) :
    LeqBA p.toOneCycleBA.source p.toOneCycleBA.target :=
  compile_oneCycleBA p.toOneCycleBA

theorem FocusedCycleDeriv.compile_sound (V : T → Atom → Bool)
    (p : FocusedCycleDeriv A T) : ∀ gs,
      den V p.toOneCycleBA.source gs → den V p.toOneCycleBA.target gs :=
  GkatOrderedBA.le_sound V p.compile

/-- Identifies a paper sequent as the external boundary of a focused cyclic certificate. -/
structure FocusedCycleDeriv.Boundary (p : FocusedCycleDeriv A T)
    (s : Sequent A T) : Prop where
  left_eq : s.left = p.toOneCycleBA.source
  right_eq : s.right = p.toOneCycleBA.target

/-- Turn focused star-induction closure into the algebraic proof expected at an open leaf
    of an enclosing SCC schedule. -/
theorem FocusedCycleDeriv.compile_boundary (p : FocusedCycleDeriv A T)
    {s : Sequent A T} (boundary : p.Boundary s) : s.OrderedBA := by
  change LeqBA s.left s.right
  rw [boundary.left_eq, boundary.right_eq]
  exact p.compile

/-- A sequent is focus-closable when it is the boundary of some extracted one-SCC
    certificate. This hides the internal loop normal form from the graph scheduler. -/
def FocusedClosable (s : Sequent A T) : Prop :=
  ∃ p : FocusedCycleDeriv A T, p.Boundary s

theorem focusedClosable_ordered {s : Sequent A T} (h : FocusedClosable s) :
    s.OrderedBA := by
  rcases h with ⟨p, boundary⟩
  exact p.compile_boundary boundary

/-- **Acyclic multi-SCC compilation.** Expand components in dependency order, then close
    every terminal SCC through its focused star-induction certificate. -/
theorem ExpansionChain.compileFocused {Open Final : Sequent A T → Prop}
    (chain : ExpansionChain A T Open Final) {s : Sequent A T}
    (d : OpenDeriv Open s)
    (close : ∀ t, Final t → FocusedClosable t) : s.OrderedBA :=
  chain.compileOrdered d (fun t ht => focusedClosable_ordered (close t ht))

/-- A complete, independently checkable certificate for a regular cyclic SGKAT proof.
    The root tree carries an executable fairness check; `schedule` expands SCCs in acyclic
    dependency order; every terminal component is closed by focused star induction. -/
structure CheckedCyclicProof (A T : Type) (root : Sequent A T) where
  Open : Sequent A T → Prop
  Final : Sequent A T → Prop
  component : CheckedComponent Open root
  schedule : ExpansionChain A T Open Final
  close : ∀ t, Final t → FocusedClosable t

/-- **Compiler for checked regular cyclic proofs.** -/
theorem CheckedCyclicProof.compile {root : Sequent A T}
    (proof : CheckedCyclicProof A T root) : root.OrderedBA :=
  proof.schedule.compileFocused proof.component.tree proof.close

/-- End-to-end guarded-language soundness of a checked regular cyclic proof. -/
theorem CheckedCyclicProof.sound (V : T → Atom → Bool) {root : Sequent A T}
    (proof : CheckedCyclicProof A T root) : ∀ gs,
      den V root.left gs → den V root.right gs :=
  GkatOrderedBA.le_sound V proof.compile

/-- A focused SCC still presented as a cut-open regular proof. `discharge` is the remaining
    graph-extraction obligation: after replacing each recursive occurrence by `post`, every
    typed backedge leaf must have a finite SGKAT derivation. Fairness records that the
    original component crosses while-left on every route back to an open leaf. -/
structure FocusedOpenCycleDeriv (A T : Type) where
  Open : Sequent A T → Prop
  guard : BExp T
  bodyExp : Exp A T
  exit : Exp A T
  post : Exp A T
  context : PosCtx A T
  premise : Sequent A T
  tree : OpenDeriv Open premise
  fair : tree.Fair
  discharge : ∀ t, Open t → FinDeriv t
  left_eq : premise.left = .ite guard (.seq bodyExp post) exit
  right_eq : premise.right = post

/-- Close the substituted backedges and expose the focused finite certificate expected by
    `FocusedCycleDeriv.compile`. -/
def FocusedOpenCycleDeriv.focus (p : FocusedOpenCycleDeriv A T) :
    FocusedCycleDeriv A T where
  guard := p.guard
  bodyExp := p.bodyExp
  exit := p.exit
  post := p.post
  context := p.context
  premise := p.premise
  tree := p.tree.close p.discharge
  left_eq := p.left_eq
  right_eq := p.right_eq

/-- Compile a fair cut-open focused SCC once its substituted backedges have been discharged. -/
theorem FocusedOpenCycleDeriv.compile (p : FocusedOpenCycleDeriv A T) :
    LeqBA p.focus.toOneCycleBA.source p.focus.toOneCycleBA.target :=
  p.focus.compile

/-- Every older focused certificate embeds into the full SGKAT cyclic target. -/
def OneCycle.toBA (p : OneCycle A T) : OneCycleBA A T where
  guard := p.guard
  bodyExp := p.bodyExp
  exit := p.exit
  post := p.post
  context := p.context
  body := ofLeq p.body

theorem compile_oneCycle_toBA (p : OneCycle A T) :
    LeqBA p.source p.target := by
  exact compile_oneCycleBA p.toBA

/-! ## Non-vacuity: a genuine backedge under nested context -/

/-- The canonical loop unfolding supplies the cut body proof in the reverse direction. -/
def canonicalCycle (C : PosCtx A T) (b : BExp T) (e f : Exp A T) : OneCycle A T where
  guard := b
  bodyExp := e
  exit := f
  post := .seq (.wh b e) f
  context := C
  body := Leq.equiv (Equiv.symm (salomaa_solution_exists b e f))

/-- Compiling the canonical cyclic proof works under an arbitrary positive context. Although
    its conclusion is reflexive after unfolding definitions, its certificate genuinely closes
    a loop backedge via `star_ind`, rather than using `Leq.refl`. -/
theorem canonicalCycle_compiles (C : PosCtx A T) (b : BExp T) (e f : Exp A T) :
    Leq (canonicalCycle C b e f).source (canonicalCycle C b e f).target :=
  compile_oneCycle _

/-- Semantic soundness of the compiled cyclic certificate, inherited from ordered GKAT. -/
theorem compile_oneCycle_sound (V : T → Atom → Bool) (p : OneCycle A T) :
    ∀ gs, den V p.source gs → den V p.target gs :=
  le_sound V (compile_oneCycle p)

#print axioms PosCtx.mono
#print axioms PosCtx.monoBA
#print axioms cedent_product
#print axioms product_left
#print axioms product_right
#print axioms product_left_BA
#print axioms product_right_BA
#print axioms empty_identity
#print axioms empty_identity_BA
#print axioms test_left
#print axioms test_right
#print axioms bottom_axiom
#print axioms choice_left
#print axioms choice_right
#print axioms while_left
#print axioms while_right
#print axioms modal_k
#print axioms modal_k0
#print axioms FinDeriv.compile
#print axioms OpenDeriv.compile
#print axioms OpenDeriv.close
#print axioms OpenDeriv.bind
#print axioms OpenDeriv.Fair.bind
#print axioms OpenDeriv.Fair.no_unguarded
#print axioms OpenDeriv.fair_of_no_unguarded
#print axioms OpenDeriv.fair_iff_no_unguarded
#print axioms OpenDeriv.guarded
#print axioms OpenDeriv.fair_of_guarded
#print axioms OpenDeriv.Fair.guarded
#print axioms OpenDeriv.fair_iff_guarded
#print axioms OpenDeriv.instDecidableFair
#print axioms ExpansionChain.apply
#print axioms ExpansionChain.apply_fair
#print axioms ExpansionChain.close
#print axioms ExpansionChain.compile
#print axioms ExpansionChain.compileOrdered
#print axioms FairComponent.expand
#print axioms CheckedComponent.toFair
#print axioms CheckedComponent.expand
#print axioms ordered_sequent_sound
#print axioms orderedBA_sequent_sound
#print axioms compile_oneCycle
#print axioms compile_oneCycleBA
#print axioms FocusedCycleDeriv.toOneCycleBA
#print axioms FocusedCycleDeriv.compile
#print axioms FocusedCycleDeriv.compile_sound
#print axioms FocusedCycleDeriv.compile_boundary
#print axioms focusedClosable_ordered
#print axioms ExpansionChain.compileFocused
#print axioms CheckedCyclicProof.compile
#print axioms CheckedCyclicProof.sound
#print axioms FocusedOpenCycleDeriv.focus
#print axioms FocusedOpenCycleDeriv.compile
#print axioms compile_oneCycle_toBA
#print axioms canonicalCycle_compiles
#print axioms compile_oneCycle_sound

end GkatCyclicOrdered
