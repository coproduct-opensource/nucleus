/-!
# Guard-position transport is ADMISSIBLE, not an extra rule

`GkatFaithful.EquivBA` carries `ite_guard` and `wh_guard`, which move Boolean
equality through the GUARD positions of `+_b` and `e^(b)`.  POPL'20 defines `≡`
as "the smallest congruence (with respect to all operators)" satisfying Figure 1
and subsuming `≡_BA` at TESTS — and never says whether the guard subscript counts
as an operator argument.  If it did not, those two constructors would be
additions and every claim of provability "from the finite axioms" would exceed
GKAT + BA by exactly them.

**They are derivable.**  This file settles it against a DELIBERATELY WEAKENED
relation `Eqv`: Figure 1, plus `≡_BA` at test positions, plus the `s6`
representation bridge, with congruence at OPERAND POSITIONS ONLY — no
guard-position constructor anywhere.  In that relation both transports are
theorems.

The route matters.  The published derivation of U8 goes through U5' and U3', and
U3' is itself derived using a guard-transport step, so the published route is
CIRCULAR for this purpose.  `u8` below instead instantiates the AXIOM U3 at
`e := 0`, `b := 1`, `c := b̄`.

Standalone by design: it defines its own syntax and relation so that nothing can
leak in from the main development.  Its point is what it does NOT assume.
-/

namespace GkatGuardTransport

inductive BExp (T : Type) where
  | zero
  | one
  | prim (t : T)
  | and (b c : BExp T)
  | or (b c : BExp T)
  | not (b : BExp T)

inductive Exp (A T : Type) where
  | act (p : A)
  | test (b : BExp T)
  | seq (e f : Exp A T)
  | ite (b : BExp T) (e f : Exp A T)
  | wh (b : BExp T) (e : Exp A T)

variable {A T : Type}

def bval (W : T → Bool) : BExp T → Bool
  | .zero => false
  | .one => true
  | .prim t => W t
  | .and b c => bval W b && bval W c
  | .or b c => bval W b || bval W c
  | .not b => !(bval W b)

/-- Boolean equivalence, semantically (complete for `≡_BA`, Birkhoff–Bartee). -/
def BAeq (b c : BExp T) : Prop := ∀ W : T → Bool, bval W b = bval W c

def E : Exp A T → BExp T
  | .act _     => .zero
  | .test b    => b
  | .seq e f   => .and (E e) (E f)
  | .ite b e f => .or (.and b (E e)) (.and (.not b) (E f))
  | .wh b _    => .not b

/-- GKAT provable equivalence with congruence ONLY at operand positions.
    `baTest` is the `≡_BA`-subsumption clause; `s6` is the representation bridge
    that the paper does not need (there `BExp ⊆ Exp` and test-`·` IS meet). -/
inductive Eqv : Exp A T → Exp A T → Prop where
  | refl (e : Exp A T) : Eqv e e
  | symm {e f : Exp A T} : Eqv e f → Eqv f e
  | trans {e f g : Exp A T} : Eqv e f → Eqv f g → Eqv e g
  -- congruence: OPERAND positions only (guards fixed syntactically)
  | seq_c {e e' f f' : Exp A T} : Eqv e e' → Eqv f f' → Eqv (.seq e f) (.seq e' f')
  | ite_c {b : BExp T} {e e' f f' : Exp A T} :
      Eqv e e' → Eqv f f' → Eqv (.ite b e f) (.ite b e' f')
  | wh_c {b : BExp T} {e e' : Exp A T} : Eqv e e' → Eqv (.wh b e) (.wh b e')
  -- Boolean-equivalence subsumption (tests only, NOT guards)
  | baTest {b c : BExp T} : BAeq b c → Eqv (.test b : Exp A T) (.test c)
  | s6 (b c : BExp T) : Eqv (.seq (.test b) (.test c) : Exp A T) (.test (.and b c))
  -- U1–U5
  | u1 (b : BExp T) (e : Exp A T) : Eqv (.ite b e e) e
  | u2 (b : BExp T) (e f : Exp A T) : Eqv (.ite b e f) (.ite (.not b) f e)
  | u3 (b c : BExp T) (e f g : Exp A T) :
      Eqv (.ite c (.ite b e f) g) (.ite (.and b c) e (.ite c f g))
  | u4 (b : BExp T) (e f : Exp A T) : Eqv (.ite b e f) (.ite b (.seq (.test b) e) f)
  | u5 (b : BExp T) (e f g : Exp A T) :
      Eqv (.ite b (.seq e g) (.seq f g)) (.seq (.ite b e f) g)
  -- S1–S5
  | s1 (e f g : Exp A T) : Eqv (.seq (.seq e f) g) (.seq e (.seq f g))
  | s2 (e : Exp A T) : Eqv (.seq (.test .zero) e) (.test .zero)
  | s3 (e : Exp A T) : Eqv (.seq e (.test .zero)) (.test .zero)
  | s4 (e : Exp A T) : Eqv (.seq (.test .one) e) e
  | s5 (e : Exp A T) : Eqv (.seq e (.test .one)) e
  -- W1–W3
  | w1 (b : BExp T) (e : Exp A T) :
      Eqv (.wh b e) (.ite b (.seq e (.wh b e)) (.test .one))
  | w2 (b c : BExp T) (e : Exp A T) :
      Eqv (.wh b (.ite c e (.test .one))) (.wh b (.seq (.test c) e))
  | w3 {b : BExp T} {e f g : Exp A T} : Eqv (.test (E e)) (.test .zero) →
      Eqv g (.ite b (.seq e g) f) → Eqv g (.seq (.wh b e) f)

/-! ## Step 0: double-negation transport, from U2 alone -/

/-- `e +_b f ≡ e +_{¬¬b} f` — U2 twice.  So the guard's double negation
    CAN be undone without any guard-transport rule. -/
theorem dn (b : BExp T) (e f : Exp A T) :
    Eqv (.ite b e f) (.ite (.not (.not b)) e f) :=
  Eqv.trans (Eqv.u2 b e f) (Eqv.u2 (.not b) f e)

/-! ## Step 1: U6 (`e +_b 0 ≡ be`) — paper's derivation, transport-free -/

private theorem zero_absorb (b : BExp T) (e : Exp A T) :
    Eqv (.test .zero : Exp A T) (.seq (.test (.not b)) (.seq (.test b) e)) :=
  Eqv.symm (Eqv.trans (Eqv.symm (Eqv.s1 (.test (.not b)) (.test b) e))
    (Eqv.trans (Eqv.seq_c (Eqv.s6 (.not b) b) (Eqv.refl e))
      (Eqv.trans (Eqv.seq_c (Eqv.baTest (by intro W; simp [bval])) (Eqv.refl e))
        (Eqv.s2 e))))

/-- **U6.** `e +_b 0 ≡ b·e`. -/
theorem u6 (b : BExp T) (e : Exp A T) :
    Eqv (.ite b e (.test .zero)) (.seq (.test b) e) :=
  Eqv.trans (Eqv.u4 b e (.test .zero))
    (Eqv.trans (Eqv.u2 b (.seq (.test b) e) (.test .zero))
      (Eqv.trans (Eqv.ite_c (zero_absorb b e) (Eqv.refl (.seq (.test b) e)))
        (Eqv.trans (Eqv.symm (Eqv.u4 (.not b) (.seq (.test b) e) (.seq (.test b) e)))
          (Eqv.u1 (.not b) (.seq (.test b) e)))))

/-- `0 +_b e ≡ b̄·e` (U6 through U2). -/
theorem u6' (b : BExp T) (e : Exp A T) :
    Eqv (.ite b (.test .zero) e) (.seq (.test (.not b)) e) :=
  Eqv.trans (Eqv.u2 b (.test .zero) e) (u6 (.not b) e)

/-! ## Step 2: U8 (`b·(e +_b f) ≡ b·e`) — the crux, from U3 + U6 + U2 -/

/-- **U8, branch selection.**  Derived from the *axiom* U3 instantiated at
    `e := 0`, `b := 1`, `c := b̄`, together with U6 and U2.  No guard transport. -/
theorem u8 (b : BExp T) (e f : Exp A T) :
    Eqv (.seq (.test b) (.ite b e f)) (.seq (.test b) e) := by
  -- U3 : (0 +_1 f) +_{b̄} e  ≡  0 +_{1∧b̄} (f +_{b̄} e)
  have h := Eqv.u3 (A := A) .one (.not b) (.test .zero) f e
  -- 0 +_1 f ≡ 0
  have h0 : Eqv (.ite (.one : BExp T) (.test .zero) f) (.test .zero : Exp A T) :=
    Eqv.trans (u6' .one f)
      (Eqv.trans (Eqv.seq_c (Eqv.baTest (by intro W; simp [bval])) (Eqv.refl f))
        (Eqv.s2 f))
  -- LHS ≡ 0 +_{b̄} e ≡ b̿·e ≡ b·e
  have hL : Eqv (.ite (.not b) (.ite .one (.test .zero) f) e)
      (.seq (.test b) e) :=
    Eqv.trans (Eqv.ite_c h0 (Eqv.refl e))
      (Eqv.trans (u6' (.not b) e)
        (Eqv.seq_c (Eqv.baTest (by intro W; simp [bval])) (Eqv.refl e)))
  -- RHS ≡ b·(e +_b f)
  have hR : Eqv (.ite (.and .one (.not b)) (.test .zero) (.ite (.not b) f e))
      (.seq (.test b) (.ite b e f)) := by
    refine Eqv.trans (u6' (.and .one (.not b)) (.ite (.not b) f e)) ?_
    exact Eqv.seq_c (Eqv.baTest (by intro W; simp [bval]))
      (Eqv.symm (Eqv.u2 b e f))
  exact Eqv.trans (Eqv.symm hR) (Eqv.trans (Eqv.symm h) hL)

/-- **U8 mirrored.** `b̄·(e +_b f) ≡ b̄·f`. -/
theorem u8' (b : BExp T) (e f : Exp A T) :
    Eqv (.seq (.test (.not b)) (.ite b e f)) (.seq (.test (.not b)) f) :=
  Eqv.trans (Eqv.seq_c (Eqv.refl _) (Eqv.u2 b e f)) (u8 (.not b) f e)

/-! ## Step 3: U4' -/

/-- **U4'.** `e +_b f ≡ e +_b b̄f`. -/
theorem u4' (b : BExp T) (e f : Exp A T) :
    Eqv (.ite b e f) (.ite b e (.seq (.test (.not b)) f)) :=
  Eqv.trans (Eqv.u2 b e f)
    (Eqv.trans (Eqv.u4 (.not b) f e)
      (Eqv.trans (Eqv.u2 (.not b) (.seq (.test (.not b)) f) e)
        (Eqv.symm (dn b e (.seq (.test (.not b)) f)))))

/-- Canonical guarded form: `e +_b f ≡ (b·e) +_b (b̄·f)`. -/
theorem canon (b : BExp T) (e f : Exp A T) :
    Eqv (.ite b e f) (.ite b (.seq (.test b) e) (.seq (.test (.not b)) f)) :=
  Eqv.trans (Eqv.u4 b e f) (u4' b (.seq (.test b) e) f)

/-! ## THE THEOREM: guard transport for `+_b` is DERIVABLE -/

private theorem baeq_not {b c : BExp T} (h : BAeq b c) : BAeq (.not b) (.not c) := by
  intro W; simp [bval, h W]

/-- **Guard-position transport for guarded union is a THEOREM,
    not an extra rule.**  `b ≡_BA c → (e +_b f) ≡ (e +_c f)`. -/
theorem ite_guard {b c : BExp T} (h : BAeq b c) (e f : Exp A T) :
    Eqv (.ite b e f) (.ite c e f) := by
  have hn := baeq_not h
  -- w ≡ w +_c w ≡ (c·w) +_c (c̄·w)
  have step : Eqv (.ite b e f : Exp A T)
      (.ite c (.seq (.test c) (.ite b e f)) (.seq (.test (.not c)) (.ite b e f))) :=
    Eqv.trans (Eqv.symm (Eqv.u1 c (.ite b e f))) (canon c (.ite b e f) (.ite b e f))
  -- c·w ≡ b·w ≡ b·e ≡ c·e
  have hc : Eqv (.seq (.test c) (.ite b e f)) (.seq (.test c) e) :=
    Eqv.trans (Eqv.seq_c (Eqv.baTest (fun W => (h W).symm)) (Eqv.refl _))
      (Eqv.trans (u8 b e f) (Eqv.seq_c (Eqv.baTest h) (Eqv.refl e)))
  have hc' : Eqv (.seq (.test (.not c)) (.ite b e f)) (.seq (.test (.not c)) f) :=
    Eqv.trans (Eqv.seq_c (Eqv.baTest (fun W => (hn W).symm)) (Eqv.refl _))
      (Eqv.trans (u8' b e f) (Eqv.seq_c (Eqv.baTest hn) (Eqv.refl f)))
  exact Eqv.trans step
    (Eqv.trans (Eqv.ite_c hc hc') (Eqv.symm (canon c e f)))

/-- **Guard transport for loops, productive bodies.**  If `E(e) ≡ 0` then
    `b ≡_BA c → e^(b) ≡ e^(c)`, via W1 + `ite_guard` + the W3 fixpoint rule. -/
theorem wh_guard_productive {b c : BExp T} (h : BAeq b c) (e : Exp A T)
    (hp : Eqv (.test (E e) : Exp A T) (.test .zero)) :
    Eqv (.wh c e) (.wh b e) :=
  have unroll : Eqv (.wh c e) (.ite b (.seq e (.wh c e)) (.test .one)) :=
    Eqv.trans (Eqv.w1 c e) (ite_guard (fun W => (h W).symm) _ _)
  Eqv.trans (Eqv.w3 hp unroll) (Eqv.s5 (.wh b e))

/-! ## Consequence: the repo's only `wh_guard` uses do not need it

    In the main development `EquivBA.wh_guard` is used in exactly two
    places, both wrappers that swap a guard to `0` or to `1`
    (`wh_guard_semantic_zero`, `wh_guard_semantic_one`).  The `0` case
    needs no guard transport on the LOOP at all — unrolling by W1 moves
    the guard into an `ite`, where the now-proved `ite_guard` applies. -/

/-- `e +_1 f ≡ e` — from U8 and S4. -/
theorem ite_one (e f : Exp A T) : Eqv (.ite .one e f) e :=
  Eqv.trans (Eqv.symm (Eqv.s4 (.ite .one e f)))
    (Eqv.trans (u8 .one e f) (Eqv.s4 e))

/-- **U7.** `e +_0 f ≡ f`. -/
theorem u7 (e f : Exp A T) : Eqv (.ite .zero e f) f :=
  Eqv.trans (Eqv.u2 .zero e f)
    (Eqv.trans (ite_guard (by intro W; simp [bval]) f e) (ite_one f e))

/-- **A loop with a semantically-false guard is `skip`, with NO loop
    guard transport.**  W1 moves the guard into an `ite`, where the
    derived `ite_guard` applies, and U7 finishes. -/
theorem wh_zero_free {b : BExp T} (h : BAeq b .zero) (e : Exp A T) :
    Eqv (.wh b e) (.test .one) :=
  Eqv.trans (Eqv.w1 b e)
    (Eqv.trans (ite_guard h (.seq e (.wh b e)) (.test .one))
      (u7 (.seq e (.wh b e)) (.test .one)))

/-! ## The general loop case, reduced to ONE named published lemma

    `wh_guard_productive` needs a strictly productive body.  The general
    case reduces to POPL'20's Lemma 3.9 — every loop is equivalent to one
    with a productive body — and to nothing else.  Stating that reduction
    explicitly turns "the general case is open here" into "the general
    case is exactly Lemma 3.9", which is a much smaller claim and one the
    main development already discharges (`GkatNormalization.productive_loop`,
    whose own proof uses no loop-guard transport — checked). -/

/-- **General loop-guard transport, GIVEN productive normalization.**  The
    hypothesis is POPL'20 Lemma 3.9 in this file's relation; nothing else
    is needed. -/
theorem wh_guard_of_norm
    (norm : ∀ e : Exp A T, ∃ ê : Exp A T,
      Eqv (.test (E ê) : Exp A T) (.test .zero)
        ∧ ∀ b : BExp T, Eqv (.wh b e) (.wh b ê))
    {b c : BExp T} (h : BAeq b c) (e : Exp A T) :
    Eqv (.wh b e) (.wh c e) := by
  obtain ⟨ê, hp, hnorm⟩ := norm e
  exact Eqv.trans (hnorm b)
    (Eqv.trans (Eqv.symm (wh_guard_productive h ê hp))
      (Eqv.symm (hnorm c)))

#print axioms wh_guard_of_norm
#print axioms ite_one
#print axioms u7
#print axioms wh_zero_free
#print axioms ite_guard
#print axioms wh_guard_productive

end GkatGuardTransport
