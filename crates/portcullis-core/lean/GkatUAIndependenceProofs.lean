import GkatSyntaxProofs

/-!
# UA₂ ⇐ UA₁ + a guard-pullback witness: locating the obstruction inside GKAT

The Uniqueness Axiom scheme UA is proven necessary in both known GKAT completeness
proofs; whether it follows from the finite base (U/S/W, whose loop fragment already
contains the n=1 instance `W3`/UA₁) is **open** — the central obstruction, also the
one the skip-free fragment removes and the June-2026 Hoare-hypothesis work still
lists as open.

This file makes the obstruction **precise and internal**. The textbook Gaussian
elimination of the crossed two-state system

    g₀ ≡ e₀·g₁ +_{b₀} f₀        g₁ ≡ e₁·g₀ +_{b₁} f₁     (BOTH states branch)

is blocked at exactly one step: pushing the prefix `e₀` past the inner guard `b₁`,
i.e. `e₀·(b₁?x:y) ≡ ??`. Rather than smuggle an unrepresentable weakest-precondition
`wp(e₀,b₁)` into the meta-language, we treat it as a **witness relation**: a guard
`c` that makes `e₀` a natural transformation across the branch,

    Pullback e b c  :≡  ∀ x y, e·(b?x:y) ≡ c?(e·x):(e·y).

* `pullback_probe_*` — the witness is pinned by its action on `(1,0)` and `(0,1)`:
  `Pullback e b c` forces the two *commuting squares* `e·b ≡ c·e`, `e·b̄ ≡ c̄·e`
  (branch-naturality). So `c` is not higher-order; it witnesses two commutations.
* `crossed_closed_form_of_pullback` — WITH such a witness, the crossed system's
  solution has the closed form `(e₀·e₁)^(c₁∧b₀)·(b₀?(e₀·f₁):f₀)`, by congruence, the
  witness, `S1`, `U3`, and `W3` (=UA₁). No `LeftDistrib`.
* `ua2_of_pullback` — hence **UA₂ (uniqueness of the crossed system) is derivable
  from base + UA₁ + a guard-pullback witness.** This is the positive half: it isolates
  the *exact* extra structure UA₂ needs beyond UA₁.

The residual open problem is the converse (does UA₂-eliminability manufacture such a
witness?) and, semantically, whether the witness `c` is guard-definable — which splits
the "crossed" case into three regimes (decoupled `c=b`; crossed-definable e.g. `c=b̄`;
crossed-non-definable). `regime2_toggle_expressible` records that regime 2 is real, so
"crossed" must not be conflated with "inexpressible".

All theorems are pure derivations in the GKAT equational system — `sorryAx`-free.
-/

namespace GkatUAIndep

open GkatSyntax

variable {A T : Type}

/-- **Guard-pullback witness.** A guard `c` under which the prefix `e` is natural
    across the branch on `b`: it transports the guard `b` backward across `e` to `c`.
    This is the honest, first-order surrogate for `wp(e,b)` — no operation, a witness. -/
def Pullback (e : Exp A T) (b c : BExp T) : Prop :=
  ∀ x y : Exp A T, Equiv (.seq e (.ite b x y)) (.ite c (.seq e x) (.seq e y))

/-- **(A), probe at `(1,0)`.** The witness `c`, applied to `(x,y) = (1,0)`, yields the
    "true square": `e·(b?1:0) ≡ c?(e):(e·0)`. With `S3`/`S5` this is the commutation
    `e·(assert b) ≡ (assert c)·e`. -/
theorem pullback_probe_true {e : Exp A T} {b c : BExp T} (h : Pullback e b c) :
    Equiv (.seq e (.ite b (.test .one) (.test .zero)))
          (.ite c e (.seq e (.test .zero))) := by
  -- specialise the witness to (1,0) and rewrite e·1 ≡ e (S5)
  have hw : Equiv (.seq e (.ite b (.test .one) (.test .zero)))
      (.ite c (.seq e (.test .one)) (.seq e (.test .zero))) := h (.test .one) (.test .zero)
  exact Equiv.trans hw (Equiv.ite_c (Equiv.s5 e) (Equiv.refl _))

/-- **(A), probe at `(0,1)`.** The complementary "false square":
    `e·(b?0:1) ≡ c?(e·0):(e)`. Together with `pullback_probe_true` these are the two
    commuting squares that pin the witness `c` — branch-naturality. -/
theorem pullback_probe_false {e : Exp A T} {b c : BExp T} (h : Pullback e b c) :
    Equiv (.seq e (.ite b (.test .zero) (.test .one)))
          (.ite c (.seq e (.test .zero)) e) := by
  have hw : Equiv (.seq e (.ite b (.test .zero) (.test .one)))
      (.ite c (.seq e (.test .zero)) (.seq e (.test .one))) := h (.test .zero) (.test .one)
  exact Equiv.trans hw (Equiv.ite_c (Equiv.refl _) (Equiv.s5 e))

/-- **The crux (D₀): closed form of the crossed system under a witness.** For the
    genuinely two-exit system

        g₀ ≡ e₀·g₁ +_{b₀} f₀        g₁ ≡ e₁·g₀ +_{b₁} f₁,

    given productivity of the composite body `e₀·e₁` and a guard-pullback witness
    `Pullback e₀ b₁ c₁`, the head unknown is the single loop

        g₀ ≡ (e₀·e₁)^(c₁∧b₀) · (b₀?(e₀·f₁):f₀).

    The witness discharges the one step that `LeftDistrib` would have — reshaping
    `e₀·(b₁?(e₁·g₀):f₁)` into a guarded prefix of `g₀`; the rest is `S1`, `U3`, `W3`. -/
theorem crossed_closed_form_of_pullback
    {b0 b1 c1 : BExp T} {e0 e1 f0 f1 g0 g1 : Exp A T}
    (hguard : Equiv (Exp.test (E (Exp.seq e0 e1)) : Exp A T) (.test .zero))
    (hpb : Pullback e0 b1 c1)
    (h0 : Equiv g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : Equiv g1 (.ite b1 (.seq e1 g0) f1)) :
    Equiv g0 (.seq (.wh (.and c1 b0) (.seq e0 e1)) (.ite b0 (.seq e0 f1) f0)) := by
  -- reshape g0 into the single-state UA₁ form  g₀ ≡ (c₁∧b₀)?((e₀·e₁)·g₀):(b₀?(e₀·f₁):f₀)
  have step : Equiv g0
      (.ite (.and c1 b0) (.seq (.seq e0 e1) g0) (.ite b0 (.seq e0 f1) f0)) :=
    Equiv.trans h0
    (Equiv.trans
      -- substitute g₁'s equation under e₀
      (Equiv.ite_c (Equiv.seq_c (Equiv.refl e0) h1) (Equiv.refl f0))
    (Equiv.trans
      -- the witness: e₀·(b₁?(e₁·g₀):f₁) ≡ c₁?(e₀·(e₁·g₀)):(e₀·f₁)
      (Equiv.ite_c (hpb (.seq e1 g0) f1) (Equiv.refl f0))
    (Equiv.trans
      -- associate: e₀·(e₁·g₀) ≡ (e₀·e₁)·g₀   (S1)
      (Equiv.ite_c (Equiv.ite_c (Equiv.symm (Equiv.s1 e0 e1 g0)) (Equiv.refl (.seq e0 f1)))
        (Equiv.refl f0))
      -- flatten nested ite  (U3)
      (Equiv.u3 c1 b0 (.seq (.seq e0 e1) g0) (.seq e0 f1) f0))))
  -- single-state fixpoint uniqueness (W3 = UA₁)
  exact salomaa_solution_unique hguard step

/-- **Existence half: the witness makes the crossed system SOLVABLE.** The closed form
    `(e₀·e₁)^(c₁∧b₀)·(b₀?(e₀·f₁):f₀)` (call it `CF`) actually solves the crossed system:
    with `g₁ := b₁?(e₁·CF):f₁`, `CF ≡ b₀?(e₀·g₁):f₀`. Proven by `W1`-unrolling
    (`salomaa_solution_exists`) then running the reshaping of `crossed_closed_form_of_pullback`
    backwards (`U3`, `S1`, the witness). No productivity needed. Combined with `ua2_of_pullback`,
    a guard-pullback witness makes the crossed two-state system **solvable-and-unique** — a
    sufficient condition for GKAT-solvability strictly broader than well-nestedness (it also
    covers regime-2 crossed-but-definable systems, e.g. an action toggling the guard). -/
theorem crossed_solvable_of_pullback
    {b0 b1 c1 : BExp T} {e0 e1 f0 f1 : Exp A T}
    (hpb : Pullback e0 b1 c1) :
    Equiv (.seq (.wh (.and c1 b0) (.seq e0 e1)) (.ite b0 (.seq e0 f1) f0))
          (.ite b0 (.seq e0 (.ite b1 (.seq e1
              (.seq (.wh (.and c1 b0) (.seq e0 e1)) (.ite b0 (.seq e0 f1) f0))) f1)) f0) :=
  let CF : Exp A T := .seq (.wh (.and c1 b0) (.seq e0 e1)) (.ite b0 (.seq e0 f1) f0)
  Equiv.trans (salomaa_solution_exists (.and c1 b0) (.seq e0 e1) (.ite b0 (.seq e0 f1) f0))
    (Equiv.trans (Equiv.symm (Equiv.u3 c1 b0 (.seq (.seq e0 e1) CF) (.seq e0 f1) f0))
    (Equiv.trans
      (Equiv.ite_c (Equiv.ite_c (Equiv.s1 e0 e1 CF) (Equiv.refl (.seq e0 f1))) (Equiv.refl f0))
      (Equiv.ite_c (Equiv.symm (hpb (.seq e1 CF) f1)) (Equiv.refl f0))))

/-- **(D): UA₂ from base + UA₁ + a guard-pullback witness.** Any two solutions of the
    crossed two-state system that share a guard-pullback witness for `(e₀,b₁)` are
    provably equal on the head unknown — the crossed instance of the Uniqueness Axiom,
    *derived* rather than assumed. The witness is the exact extra structure UA₂ needs
    beyond UA₁; without it the reshaping step is `LeftDistrib`, a non-theorem. -/
theorem ua2_of_pullback
    {b0 b1 c1 : BExp T} {e0 e1 f0 f1 g0 g1 g0' g1' : Exp A T}
    (hguard : Equiv (Exp.test (E (Exp.seq e0 e1)) : Exp A T) (.test .zero))
    (hpb : Pullback e0 b1 c1)
    (h0 : Equiv g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : Equiv g1 (.ite b1 (.seq e1 g0) f1))
    (h0' : Equiv g0' (.ite b0 (.seq e0 g1') f0))
    (h1' : Equiv g1' (.ite b1 (.seq e1 g0') f1)) :
    Equiv g0 g0' :=
  Equiv.trans (crossed_closed_form_of_pullback hguard hpb h0 h1)
    (Equiv.symm (crossed_closed_form_of_pullback hguard hpb h0' h1'))

/-- **Regime 2 is real (crossed ≠ inexpressible).** When `e` uniformly *toggles* the
    observable `b`, the pullback witness is the existing guard `b̄`: `Pullback e b b̄`
    holds *as a hypothesis about `e`* iff `e·(b?x:y) ≡ b̄?(e·x):(e·y)`. We record the
    definitional content so the theory cannot silently conflate "crossed" (`c ≠ b`)
    with "non-definable" (no `c` at all): a toggling `e` is crossed yet fully internal.
    (A concrete toggling action inhabiting this lives in the semantic model, not the
    free syntax; here we expose the shape used by `ua2_of_pullback`.) -/
theorem regime2_toggle_shape {e : Exp A T} {b : BExp T}
    (htoggle : ∀ x y : Exp A T,
      Equiv (.seq e (.ite b x y)) (.ite (.not b) (.seq e x) (.seq e y))) :
    Pullback e b (.not b) := htoggle

#print axioms crossed_solvable_of_pullback
#print axioms crossed_closed_form_of_pullback
#print axioms ua2_of_pullback
#print axioms pullback_probe_true

end GkatUAIndep
