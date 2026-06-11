import MonoidalPermissionProofs

/-!
# ConstructiveSecurity.lean — Maurer's constructive cryptography, abstractly

A Mathlib-free formalization of the composition core of Ueli Maurer's
*Constructive Cryptography — A New Paradigm for Security Definitions and Proofs*
(TOSCA 2011), specialized to the Alice–Bob–Eve setting (paper §5).

## Why this lives in nucleus

Constructive cryptography defines security not as "no adversary wins a game"
but as a **construction**: a protocol constructs an *ideal* resource `S` from a
*real* resource `R`, written `R --(π₁,π₂,ε)--> S`. The whole point is a single
**composition theorem** (Maurer Thm 1) saying these constructions chain, with
the error budgets `ε` simply *adding*. That is exactly the top-level statement
nucleus currently lacks: it has per-component proofs (`MonoidalPermissionProofs`,
`DelegationCategoryProofs`, `FlowProofs`, the exposure monoid) but no theorem
that the *composed enforcement stack* satisfies the conjunction of its parts.

This module supplies that backbone abstractly, then instantiates it concretely
to prove the axioms are satisfiable (non-vacuity).

### The dictionary (constructive crypto ⇄ nucleus)

* **Resource** `Φ`   — an agent-execution channel. The *real* resource bundles
  the assumed-correct isolation boundary (`R_kvm ‖ R_fs`); the *ideal* resource
  is "writes only inside the capability lattice, leaks only declared exposures".
* **Converter** `Σ`  — an enforcement engine attached at an interface: the
  portcullis policy hook (interface `A`), the world/tool boundary (`B`), the
  audit/IFC monitor. *Schemes are converters, not resources* (Maurer): safety is
  an attribute of the constructed channel, not of the policy engine.
* **Interface `E`**   — the adversary (a compromised tool, an injected prompt).
* **`d` / distinguisher** — the leakage/distinguishing-advantage pseudo-metric.
  The `ε = 0` instance already exists as `perfectAdvantage` in `SemanticIFC.lean`;
  its DPI theorem (`learnable_postprocess`) *is* the non-expansion axiom below.
* **`R --(π,ε)--> S`** — "the enforcement stack constructs the ideal channel from
  the assumed isolation primitive, up to leakage ε." "Verified-except-KVM" is
  then not a caveat but the placement of `R_kvm` on the *left* of the arrow,
  where assumed resources belong.

### What is proved here (all kernel-checked, no `sorry`, no Mathlib)

* `serial_compose`   — Maurer Thm 1(i): serial composability; errors add.
* `parallel_compose` — Maurer Thm 1(ii): parallel/monoidal composability.
* `refl_construct`   — Maurer Thm 1(iii): the identity construction (ε = 0).
* Together these make the construction relation a category **enriched over
  `(ℕ, +, ≤)`** — a Lawvere-metric-enriched category, the modern (Broadbent–
  Karvonen 2022) reading of Maurer. `serial_compose` is enriched composition,
  `refl_construct` the zero-cost identity, `parallel_compose` the tensor.
* `xorModel` — a finite, non-degenerate model satisfying every axiom, so the
  theory is not vacuous; `xor_refl_example` exhibits a concrete construction.
* `capModel` — `Φ` instantiated with the **permission lattice** (`CapLevel`/`meet`
  from `MonoidalPermissionProofs`): converters are genuine attenuations and
  non-expansion is the lattice analogue of the data-processing inequality.
  `cap_attenuation_example` is a real `R --(π,0)--> S` over capability objects.

The error budget `ε` is taken in `ℕ` (a commutative ordered monoid under `+`),
which is a valid instance of Maurer's "abstract pseudo-metric"; the proofs use
only `0`, `+`, `≤`, so they transfer verbatim to `ℝ≥0` or a negligibility
quantale once a richer codomain is wanted.
-/

namespace Nucleus.ConstructiveSecurity

/-- The three interfaces of the Alice–Bob–Eve setting (Maurer §5).
`A`, `B` are honest parties; `E` is the adversary interface. -/
inductive Iface where
  | A
  | B
  | E
deriving DecidableEq, Repr

open Iface

/-- A **cryptographic algebra** `⟨Φ, Σ⟩` (Maurer Def 1) together with a
**compatible pseudo-metric** `d` (Maurer Def 2).

`Resource` is `Φ`, `Converter` is `Σ`. `app α i R` is Maurer's `αⁱR`
(attach converter `α` at interface `i` of resource `R`). `comp` is serial
converter composition `αβ`, `parC` is parallel converter composition `α‖β`,
`par` is parallel resource composition `R‖S`. `one` is the neutral converter
`1`, `bot` is the shielding converter `⊥` ("no adversary present" mode).

The `d_*` fields are the pseudo-metric laws; the remaining fields are the
cryptographic-algebra laws and the two compatibility (non-expansion)
inequalities (Maurer eqs (3),(4)). -/
structure CryptoAlgebra where
  Resource  : Type
  Converter : Type
  par   : Resource → Resource → Resource
  app   : Converter → Iface → Resource → Resource
  comp  : Converter → Converter → Converter
  parC  : Converter → Converter → Converter
  one   : Converter
  bot   : Converter
  /-- Distinguishing advantage / abstract error budget `d(R,S) ∈ ℕ`. -/
  d     : Resource → Resource → Nat
  -- pseudo-metric laws ------------------------------------------------------
  d_self : ∀ R, d R R = 0
  d_symm : ∀ R S, d R S = d S R
  d_tri  : ∀ R S T, d R T ≤ d R S + d S T
  -- cryptographic-algebra laws ---------------------------------------------
  /-- Converter application at *different* interfaces commutes (Maurer Def 1.i). -/
  comm     : ∀ (i j : Iface) (α β : Converter) (R : Resource),
               i ≠ j → app α i (app β j R) = app β j (app α i R)
  /-- Serial composition: `(αβ)ⁱR = αⁱ(βⁱR)`. -/
  comp_app : ∀ (α β : Converter) (i : Iface) (R : Resource),
               app (comp α β) i R = app α i (app β i R)
  /-- The neutral converter attaches nothing (Maurer Def 1.ii). -/
  one_app  : ∀ (i : Iface) (R : Resource), app one i R = R
  -- compatibility of the pseudo-metric (Maurer Def 2) -----------------------
  /-- Non-expansion under converter attachment (Maurer eq (4)). -/
  nonexp     : ∀ (α : Converter) (i : Iface) (R S : Resource),
                 d (app α i R) (app α i S) ≤ d R S
  /-- Non-expansion under parallel composition (Maurer eq (3)). -/
  par_compat : ∀ (R R' S S' : Resource),
                 d (par R R') (par S S') ≤ d R S + d R' S'
  /-- Parallel converter acts componentwise: `(α‖β)ⁱ(R‖S) = αⁱR ‖ βⁱS`. -/
  parC_app : ∀ (α β : Converter) (i : Iface) (R S : Resource),
               app (parC α β) i (par R S) = par (app α i R) (app β i S)
  /-- The shielding converter distributes over parallel composition. -/
  bot_par  : ∀ (i : Iface) (R S : Resource),
               app bot i (par R S) = par (app bot i R) (app bot i S)

namespace CryptoAlgebra

/-- **Maurer Def 3**: the protocol `(π₁,π₂)` *securely constructs* `S` from `R`
within `ε`, written `R --(π₁,π₂,ε)--> S`.

Two conditions, exactly as in the paper:
* `availability` — with the adversary absent (`⊥` attached at `E`), the
  protocol on the real resource is `≤ ε`-close to the shielded ideal resource;
* `security` — with the adversary present, there is a **simulator** `σ` at `E`
  making the real protocol `≤ ε`-indistinguishable from the ideal resource.

The simulator is part of the *statement* here for self-containedness; in the
abstract-cryptography framing it is only ever part of a *proof*. -/
structure Constructs (𝓒 : CryptoAlgebra)
    (R S : 𝓒.Resource) (π₁ π₂ : 𝓒.Converter) (ε : Nat) : Prop where
  availability :
    𝓒.d (𝓒.app π₁ A (𝓒.app π₂ B (𝓒.app 𝓒.bot E R))) (𝓒.app 𝓒.bot E S) ≤ ε
  security :
    ∃ σ : 𝓒.Converter,
      𝓒.d (𝓒.app π₁ A (𝓒.app π₂ B R)) (𝓒.app σ E S) ≤ ε

variable (𝓒 : CryptoAlgebra)

/-- Interface distinctness, used to invoke the commutativity axiom. -/
private theorem A_ne_B : (A : Iface) ≠ B := by decide
private theorem A_ne_E : (A : Iface) ≠ E := by decide
private theorem B_ne_E : (B : Iface) ≠ E := by decide

/-- **Maurer Theorem 1(i): serial composability.**
If `(π₁,π₂)` constructs `S` from `R` within `ε`, and `(π₁',π₂')` constructs `T`
from `S` within `ε'`, then the composed protocol `(π₁'π₁, π₂'π₂)` constructs `T`
from `R` within `ε + ε'`. The simulator for the composite is `σ σ'`. -/
theorem serial_compose
    {R S T : 𝓒.Resource} {π₁ π₂ π₁' π₂' : 𝓒.Converter} {ε ε' : Nat}
    (h1 : Constructs 𝓒 R S π₁ π₂ ε)
    (h2 : Constructs 𝓒 S T π₁' π₂' ε') :
    Constructs 𝓒 R T (𝓒.comp π₁' π₁) (𝓒.comp π₂' π₂) (ε + ε') := by
  refine ⟨?_avail, ?_sec⟩
  · -- availability
    -- reshape the composed LHS into π₁'ᴬ π₂'ᴮ (π₁ᴬ π₂ᴮ ⊥ᴱ R)
    have hL :
        𝓒.app (𝓒.comp π₁' π₁) A (𝓒.app (𝓒.comp π₂' π₂) B (𝓒.app 𝓒.bot E R))
          = 𝓒.app π₁' A (𝓒.app π₂' B
              (𝓒.app π₁ A (𝓒.app π₂ B (𝓒.app 𝓒.bot E R)))) := by
      rw [𝓒.comp_app, 𝓒.comp_app,
          𝓒.comm A B π₁ π₂' (𝓒.app π₂ B (𝓒.app 𝓒.bot E R)) A_ne_B]
    -- push the outer protocol converters over the ε-bound from h1
    have step1 :
        𝓒.d (𝓒.app π₁' A (𝓒.app π₂' B
                (𝓒.app π₁ A (𝓒.app π₂ B (𝓒.app 𝓒.bot E R)))))
            (𝓒.app π₁' A (𝓒.app π₂' B (𝓒.app 𝓒.bot E S))) ≤ ε :=
      Nat.le_trans (𝓒.nonexp π₁' A _ _)
        (Nat.le_trans (𝓒.nonexp π₂' B _ _) h1.availability)
    -- triangle through the shared midpoint π₁'ᴬ π₂'ᴮ ⊥ᴱ S
    rw [hL]
    exact Nat.le_trans
      (𝓒.d_tri _ (𝓒.app π₁' A (𝓒.app π₂' B (𝓒.app 𝓒.bot E S))) _)
      (Nat.add_le_add step1 h2.availability)
  · -- security
    obtain ⟨σ, hσ⟩ := h1.security
    obtain ⟨σ', hσ'⟩ := h2.security
    refine ⟨𝓒.comp σ σ', ?_⟩
    -- reshape the composed real LHS
    have hL :
        𝓒.app (𝓒.comp π₁' π₁) A (𝓒.app (𝓒.comp π₂' π₂) B R)
          = 𝓒.app π₁' A (𝓒.app π₂' B (𝓒.app π₁ A (𝓒.app π₂ B R))) := by
      rw [𝓒.comp_app, 𝓒.comp_app,
          𝓒.comm A B π₁ π₂' (𝓒.app π₂ B R) A_ne_B]
    -- d(LHS, M) ≤ ε where M = π₁'ᴬ π₂'ᴮ σᴱ S
    have step1 :
        𝓒.d (𝓒.app π₁' A (𝓒.app π₂' B (𝓒.app π₁ A (𝓒.app π₂ B R))))
            (𝓒.app π₁' A (𝓒.app π₂' B (𝓒.app σ E S))) ≤ ε :=
      Nat.le_trans (𝓒.nonexp π₁' A _ _)
        (Nat.le_trans (𝓒.nonexp π₂' B _ _) hσ)
    -- M = σᴱ (π₁'ᴬ π₂'ᴮ S): slide the simulator out to the E interface
    have hM :
        𝓒.app π₁' A (𝓒.app π₂' B (𝓒.app σ E S))
          = 𝓒.app σ E (𝓒.app π₁' A (𝓒.app π₂' B S)) := by
      rw [𝓒.comm B E π₂' σ S B_ne_E,
          𝓒.comm A E π₁' σ (𝓒.app π₂' B S) A_ne_E]
    -- d(M, (σσ')ᴱ T) ≤ ε'
    have step2 :
        𝓒.d (𝓒.app π₁' A (𝓒.app π₂' B (𝓒.app σ E S)))
            (𝓒.app (𝓒.comp σ σ') E T) ≤ ε' := by
      rw [hM, 𝓒.comp_app σ σ' E T]
      exact Nat.le_trans (𝓒.nonexp σ E _ _) hσ'
    -- triangle
    rw [hL]
    exact Nat.le_trans
      (𝓒.d_tri _ (𝓒.app π₁' A (𝓒.app π₂' B (𝓒.app σ E S))) _)
      (Nat.add_le_add step1 step2)

/-- **Maurer Theorem 1(ii): parallel (monoidal) composability.**
Independent constructions tensor: if `(π₁,π₂)` constructs `S` from `R` within
`ε` and `(π₁',π₂')` constructs `S'` from `R'` within `ε'`, then the parallel
protocol constructs `S ‖ S'` from `R ‖ R'` within `ε + ε'`. The simulator is
`σ ‖ σ'`. Taking `R' = S' = T` and the identity protocol gives Maurer's
*context-insensitivity*: a resource available in parallel cannot invalidate a
construction statement. -/
theorem parallel_compose
    {R R' S S' : 𝓒.Resource} {π₁ π₂ π₁' π₂' : 𝓒.Converter} {ε ε' : Nat}
    (h1 : Constructs 𝓒 R S π₁ π₂ ε)
    (h2 : Constructs 𝓒 R' S' π₁' π₂' ε') :
    Constructs 𝓒 (𝓒.par R R') (𝓒.par S S')
      (𝓒.parC π₁ π₁') (𝓒.parC π₂ π₂') (ε + ε') := by
  refine ⟨?_avail, ?_sec⟩
  · -- availability: distribute ⊥ and the parallel protocol over ‖, then eq (3)
    rw [𝓒.bot_par E R R', 𝓒.parC_app, 𝓒.parC_app, 𝓒.bot_par E S S']
    exact Nat.le_trans (𝓒.par_compat _ _ _ _)
      (Nat.add_le_add h1.availability h2.availability)
  · -- security
    obtain ⟨σ, hσ⟩ := h1.security
    obtain ⟨σ', hσ'⟩ := h2.security
    refine ⟨𝓒.parC σ σ', ?_⟩
    rw [𝓒.parC_app, 𝓒.parC_app, 𝓒.parC_app]
    exact Nat.le_trans (𝓒.par_compat _ _ _ _) (Nat.add_le_add hσ hσ')

/-- **Maurer Theorem 1(iii): the identity construction.**
The trivial protocol `(1,1)` constructs every resource from itself with zero
error. Together with `serial_compose` this makes constructions a category
enriched over `(ℕ, +, ≤)`: `refl_construct` is the identity, `serial_compose`
is composition with additive cost. -/
theorem refl_construct (R : 𝓒.Resource) :
    Constructs 𝓒 R R 𝓒.one 𝓒.one 0 := by
  refine ⟨?_avail, ?_sec⟩
  -- both branches reduce to `0 ≤ 0` after rewriting `one_app` then `d_self`
  · rw [𝓒.one_app, 𝓒.one_app, 𝓒.d_self]; exact Nat.le_refl 0
  · exact ⟨𝓒.one, by
      rw [𝓒.one_app, 𝓒.one_app, 𝓒.one_app, 𝓒.d_self]; exact Nat.le_refl 0⟩

end CryptoAlgebra

/-! ## A concrete, non-degenerate model (non-vacuity)

`Res` is three bits, one per interface. A converter is a bit: `false` is the
identity, `true` is negation. `app c i` flips bit `i` iff `c = true`; serial
and parallel converter composition are both XOR (function composition for these
involutions); `par` is bitwise XOR of resources; the metric is Hamming distance.
Every axiom of `CryptoAlgebra` is discharged by finite case analysis. -/

/-- A resource: one bit per interface. -/
structure Res where
  a : Bool
  b : Bool
  e : Bool
deriving DecidableEq, Repr

/-- A converter: `false` ↦ identity, `true` ↦ negation. -/
abbrev Conv := Bool

/-- Apply a converter (as a bit-flip) to a single bit. -/
def applyC (c : Conv) (x : Bool) : Bool := xor c x

/-- Attach a converter at interface `i`, flipping only that interface's bit. -/
def appR (c : Conv) (i : Iface) (R : Res) : Res :=
  match i with
  | A => { R with a := applyC c R.a }
  | B => { R with b := applyC c R.b }
  | E => { R with e := applyC c R.e }

/-- Bitwise XOR of resources (parallel composition). -/
def parR (R S : Res) : Res := ⟨xor R.a S.a, xor R.b S.b, xor R.e S.e⟩

/-- Hamming distance between resources. -/
def dist (R S : Res) : Nat :=
  (if R.a = S.a then 0 else 1)
    + (if R.b = S.b then 0 else 1)
    + (if R.e = S.e then 0 else 1)

/-- The finite XOR model satisfies every `CryptoAlgebra` axiom. -/
def xorModel : CryptoAlgebra where
  Resource  := Res
  Converter := Conv
  par   := parR
  app   := appR
  comp  := fun c d => xor c d
  parC  := fun c d => xor c d
  one   := false
  bot   := false
  d     := dist
  d_self := by
    intro R; obtain ⟨a, b, e⟩ := R; simp [dist]
  d_symm := by
    intro R S; obtain ⟨a, b, e⟩ := R; obtain ⟨a', b', e'⟩ := S
    cases a <;> cases b <;> cases e <;> cases a' <;> cases b' <;> cases e' <;>
      decide
  d_tri := by
    intro R S T
    obtain ⟨a, b, e⟩ := R; obtain ⟨a', b', e'⟩ := S; obtain ⟨a'', b'', e''⟩ := T
    cases a <;> cases b <;> cases e <;> cases a' <;> cases b' <;> cases e' <;>
      cases a'' <;> cases b'' <;> cases e'' <;> decide
  comm := by
    intro i j c d R h
    obtain ⟨a, b, e⟩ := R
    cases i <;> cases j <;>
      first
        | exact absurd rfl h
        | (cases c <;> cases d <;> cases a <;> cases b <;> cases e <;> rfl)
  comp_app := by
    intro c d i R; obtain ⟨a, b, e⟩ := R
    cases i <;> cases c <;> cases d <;> cases a <;> cases b <;> cases e <;> rfl
  one_app := by
    intro i R; obtain ⟨a, b, e⟩ := R
    cases i <;> cases a <;> cases b <;> cases e <;> rfl
  nonexp := by
    intro c i R S
    obtain ⟨a, b, e⟩ := R; obtain ⟨a', b', e'⟩ := S
    cases i <;> cases c <;> cases a <;> cases b <;> cases e <;>
      cases a' <;> cases b' <;> cases e' <;> decide
  par_compat := by
    intro R R' S S'
    obtain ⟨a, b, e⟩ := R; obtain ⟨a', b', e'⟩ := R'
    obtain ⟨c, d, f⟩ := S; obtain ⟨c', d', f'⟩ := S'
    cases a <;> cases b <;> cases e <;> cases a' <;> cases b' <;> cases e' <;>
      cases c <;> cases d <;> cases f <;> cases c' <;> cases d' <;> cases f' <;>
      decide
  parC_app := by
    intro c d i R S; obtain ⟨a, b, e⟩ := R; obtain ⟨a', b', e'⟩ := S
    cases i <;> cases c <;> cases d <;> cases a <;> cases b <;> cases e <;>
      cases a' <;> cases b' <;> cases e' <;> rfl
  bot_par := by
    intro i R S; obtain ⟨a, b, e⟩ := R; obtain ⟨a', b', e'⟩ := S
    cases i <;> cases a <;> cases b <;> cases e <;>
      cases a' <;> cases b' <;> cases e' <;> rfl

/-- Non-vacuity: a concrete construction holds in the model — every resource is
constructed from itself by the identity protocol with zero error. -/
theorem xor_refl_example (R : Res) :
    CryptoAlgebra.Constructs xorModel R R false false 0 :=
  CryptoAlgebra.refl_construct xorModel R

/-- Non-vacuity of composition: chaining two zero-error identity constructions
yields a zero-error construction (here `0 + 0`), exercising `serial_compose`
against the concrete model. -/
theorem xor_serial_example (R : Res) :
    CryptoAlgebra.Constructs xorModel R R
      (xorModel.comp false false) (xorModel.comp false false) (0 + 0) :=
  CryptoAlgebra.serial_compose xorModel
    (CryptoAlgebra.refl_construct xorModel R)
    (CryptoAlgebra.refl_construct xorModel R)

/-! ## The capability-lattice model (Φ = nucleus's real permission lattice)

This is the instance that connects the abstract theory to nucleus. Resources
carry one `CapLevel` per interface; **converters are genuine attenuations** —
a converter is a capability `c`, and attaching it at interface `i` replaces that
interface's level with `meet · c` (the *same* `meet` proved a bounded
distributive lattice in `MonoidalPermissionProofs`). Serial and parallel
converter composition are `meet`; parallel resource composition is pointwise
`meet`; the metric is the Hamming distance over interfaces.

Non-expansion (Maurer eq (4)) holds because attenuation is monotone — meeting
both sides with the same `c` can only *merge* differing levels, never split
equal ones — which is the permission-lattice analogue of the data-processing
inequality `learnable_postprocess` in `SemanticIFC.lean`. Thus a construction
`R --(π, 0)--> S` reads: *attaching the attenuation protocol `π` to the real
(fully-capable) resource yields exactly the ideal (restricted) resource*. -/

open CapLevel

/-- A capability resource: one capability level per interface (A/B honest, E adv). -/
structure CapRes where
  a : CapLevel
  b : CapLevel
  e : CapLevel
deriving DecidableEq, Repr

/-- A converter is the capability it attenuates to (via `meet`). -/
abbrev CapConv := CapLevel

/-- Attach an attenuation at interface `i`: meet that interface's level with `c`. -/
def appCap (c : CapConv) (i : Iface) (R : CapRes) : CapRes :=
  match i with
  | A => { R with a := meet R.a c }
  | B => { R with b := meet R.b c }
  | E => { R with e := meet R.e c }

/-- Pointwise `meet` of capability resources (parallel composition). -/
def parCap (R S : CapRes) : CapRes := ⟨meet R.a S.a, meet R.b S.b, meet R.e S.e⟩

/-- Hamming distance over the three interfaces. -/
def distCap (R S : CapRes) : Nat :=
  (if R.a = S.a then 0 else 1)
    + (if R.b = S.b then 0 else 1)
    + (if R.e = S.e then 0 else 1)

-- Per-component facts about `meet` and the Hamming metric (3-valued ⇒ `decide`).
private theorem cap_dist_comm (x y : CapLevel) :
    (if x = y then 0 else 1) = (if y = x then (0:Nat) else 1) := by
  cases x <;> cases y <;> decide

private theorem cap_tri_comp (x y z : CapLevel) :
    (if x = z then 0 else 1)
      ≤ (if x = y then 0 else 1) + (if y = z then (0:Nat) else 1) := by
  cases x <;> cases y <;> cases z <;> decide

private theorem cap_nonexp_comp (c x y : CapLevel) :
    (if meet x c = meet y c then 0 else 1) ≤ (if x = y then (0:Nat) else 1) := by
  cases c <;> cases x <;> cases y <;> decide

private theorem cap_par_comp (x x' y y' : CapLevel) :
    (if meet x x' = meet y y' then 0 else 1)
      ≤ (if x = y then 0 else 1) + (if x' = y' then (0:Nat) else 1) := by
  cases x <;> cases x' <;> cases y <;> cases y' <;> decide

private theorem cap_comp_field (x c d : CapLevel) :
    meet x (meet c d) = meet (meet x d) c := by
  cases x <;> cases c <;> cases d <;> decide

private theorem cap_parC_field (x x' c d : CapLevel) :
    meet (meet x x') (meet c d) = meet (meet x c) (meet x' d) := by
  cases x <;> cases x' <;> cases c <;> cases d <;> decide

/-- The permission-lattice model satisfies every `CryptoAlgebra` axiom. -/
def capModel : CryptoAlgebra where
  Resource  := CapRes
  Converter := CapConv
  par   := parCap
  app   := appCap
  comp  := fun c d => meet c d
  parC  := fun c d => meet c d
  one   := Always
  bot   := Always
  d     := distCap
  d_self := by intro R; simp [distCap]
  d_symm := by
    intro R S
    simp only [distCap, cap_dist_comm R.a S.a, cap_dist_comm R.b S.b,
      cap_dist_comm R.e S.e]
  d_tri := by
    intro R S T
    have ha := cap_tri_comp R.a S.a T.a
    have hb := cap_tri_comp R.b S.b T.b
    have he := cap_tri_comp R.e S.e T.e
    simp only [distCap]; omega
  comm := by
    intro i j c d R h
    obtain ⟨a, b, e⟩ := R
    cases i <;> cases j <;> first | exact absurd rfl h | simp [appCap]
  comp_app := by
    intro c d i R; obtain ⟨a, b, e⟩ := R
    cases i <;> simp [appCap, cap_comp_field]
  one_app := by
    intro i R; obtain ⟨a, b, e⟩ := R
    cases i <;> simp [appCap, meet_identity_right]
  nonexp := by
    intro c i R S
    obtain ⟨a, b, e⟩ := R; obtain ⟨a', b', e'⟩ := S
    cases i <;> simp only [appCap, distCap]
    -- bound the single attenuated interface; the other two are unchanged
    · exact Nat.add_le_add (Nat.add_le_add
        (cap_nonexp_comp c a a') (Nat.le_refl _)) (Nat.le_refl _)
    · exact Nat.add_le_add (Nat.add_le_add
        (Nat.le_refl _) (cap_nonexp_comp c b b')) (Nat.le_refl _)
    · exact Nat.add_le_add (Nat.add_le_add
        (Nat.le_refl _) (Nat.le_refl _)) (cap_nonexp_comp c e e')
  par_compat := by
    intro R R' S S'
    obtain ⟨a, b, e⟩ := R; obtain ⟨a', b', e'⟩ := R'
    obtain ⟨c, d, f⟩ := S; obtain ⟨c', d', f'⟩ := S'
    simp only [parCap, distCap]
    -- discharge the three `meet`-terms by defeq, leaving omega only simple atoms
    refine Nat.le_trans (Nat.add_le_add (Nat.add_le_add
      (cap_par_comp a a' c c') (cap_par_comp b b' d d'))
      (cap_par_comp e e' f f')) ?_
    omega
  parC_app := by
    intro c d i R S; obtain ⟨a, b, e⟩ := R; obtain ⟨a', b', e'⟩ := S
    cases i <;> simp [appCap, parCap, cap_parC_field]
  bot_par := by
    intro i R S; obtain ⟨a, b, e⟩ := R; obtain ⟨a', b', e'⟩ := S
    cases i <;> simp [appCap, parCap, meet_identity_right]

/-- A concrete construction over the **real permission lattice**: attenuating
both honest interfaces to `LowRisk` constructs the `LowRisk`-restricted ideal
resource from the fully-capable real resource, with zero error. The simulator
at the adversary interface is the identity (`Always`). This is `R --(π,0)--> S`
where `R`, `S`, and `π` are all genuine capability-lattice objects. -/
theorem cap_attenuation_example :
    CryptoAlgebra.Constructs capModel
      ⟨Always, Always, Always⟩      -- real resource: full capability everywhere
      ⟨LowRisk, LowRisk, Always⟩    -- ideal resource: honest interfaces attenuated
      LowRisk LowRisk 0 := by
  refine ⟨?_avail, Always, ?_sec⟩ <;> decide

end Nucleus.ConstructiveSecurity
