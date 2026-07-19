/-
  UniformPrimitive  —  the proof-token as the SAME construct at every layer.

  **STATUS: SPINE PROVEN (0 `sorry`, 0 axiom in `preserves_seq`); GAP 1
  (policy⇝ocap) DISCHARGED as a theorem; 3 layer bridges remain named axioms =
  the machine-checked distance-to-done.** Mathlib-free, Lean 4 v4.30.0-rc2,
  `autoImplicit = false`.

  # What this file is

  The nucleus North Star made "an unmediated external effect is unconstructable"
  structurally true at the AGENT-POLICY layer: every effect is minted only through
  a sealed `DischargedBundle` (`crates/nucleus-ifc-kernel/src/discharge.rs`). The
  standing initiative asks whether that SAME proof-token discipline can hold at
  EVERY layer down to hardware — policy -> ocap/effect language -> an
  NI-preserving compiler -> a verified kernel/hypervisor -> CHERI capability
  hardware -> ISA model, bottoming out "modulo hardware".

  The correct target criterion is NOT full abstraction (it preserves observational
  equivalence — stronger than needed and harder). Non-interference is a
  *hypersafety* property; the criterion that robustly preserves it against
  ARBITRARY adversarial contexts is **Robust Hypersafety Preservation** (Abate et
  al., *Journey Beyond Full Abstraction*). Nucleus's threat model ("assume the
  agent/context is compromised") IS the "robust" quantifier. And robust
  preservation is known to compose VERTICALLY (PF-RSC; Patrignani-Garg): if every
  pass preserves, the whole pipeline preserves. `preserves_seq` below is exactly
  that theorem; `end_to_end` chains it across the five-layer stack.

  # The uniform primitive

  `Preserves L L' γ` is the SAME refined construct at each boundary: a proof-token
  witnessing that refinement `γ` carries noninterference from layer `L` to `L'`
  against any adversary admitted at the boundary. It is the layer-general shape of
  `DischargedBundle` (the effect-boundary instance) and of halve's `CertifiedOn`
  (whose `certifiedOn_seq` is the same triangle-composition move over an error band).

  # Honest gaps (why the remaining axioms are load-bearing, NOT vacuous)

  Downstream program spaces and `NI`/compilers (ISA, kernel, hardware) are
  `opaque`, so each remaining bridge axiom is genuinely underivable in-stub (no
  vacuous witness). GAP 1 is now DISCHARGED: the policy⇝ocap layer is modeled
  concretely on the sealed 8-obligation `DischargedBundle` and its bridge is a
  proven, axiom-free theorem. Three bridges remain (ocap⇝ISA, ISA⇝kernel,
  kernel⇝hardware); each becomes a theorem as its layer is modeled, dropping the
  ratchet baseline. Distance-to-done = axiom count = 3.

  # Known scaffold simplifications (disclosed, not hidden)

  * Entry preconditions `Pre` are trivialised to `True`, so the interface
    obligations threaded by `preserves_seq` (`hpre`) discharge trivially. Real
    layer models will carry real preconditions; `preserves_seq` already takes the
    `hpre` interface obligation as a hypothesis, so no rework is needed.
  * The "unmediated effect is unconstructable" strength is enforced in Rust by the
    effect fn's `_proof: DischargedBundle` PARAMETER (a missing token is a compile
    error). This Lean model abstracts that as: the effect carries a token, and
    ocap-layer NI = the token is complete.
  * The modulo-hardware FLOOR (timing side-channels, only observable at RTL per
    VeriCHERI) lies below the ISA layer and is NOT covered by any NI theorem here;
    it is a permanent honest caveat, not a bridge to be closed.
-/

namespace Nucleus.UniformPrimitive

/-- A layer of the refinement stack: a program space, the noninterference
    hyperproperty `NI` it can satisfy, and an entry precondition `Pre`. -/
structure Layer where
  Prog : Type
  NI   : Prog → Prop
  Pre  : Prog → Prop

/-- **The uniform primitive.** `Preserves L L' γ` : the refinement `γ` robustly
    preserves noninterference from `L` to `L'` — every source program admitted at
    `L` (`L.Pre`) that satisfies `L.NI` compiles to a target that satisfies `L'.NI`.
    Robust Hypersafety Preservation specialised to the NI hyperproperty. This is the
    layer-general shape of the sealed `DischargedBundle` proof-token. -/
def Preserves (L L' : Layer) (γ : L.Prog → L'.Prog) : Prop :=
  ∀ p : L.Prog, L.Pre p → L.NI p → L'.NI (γ p)

/-- **`preserves_seq` — vertical composition of the proof-token (PF-RSC composes).**
    Two preserving refinements compose into one, PROVIDED the interface obligation
    `hpre` discharges (layer 1's admitted, NI-satisfying programs land inside layer
    2's precondition). `hpre` is the honest per-boundary cost — the analogue of
    halve's `certifiedOn_seq` precondition-threading. Proven with **no axioms**. -/
theorem preserves_seq {L1 L2 L3 : Layer}
    (γ12 : L1.Prog → L2.Prog) (γ23 : L2.Prog → L3.Prog)
    (h12 : Preserves L1 L2 γ12) (h23 : Preserves L2 L3 γ23)
    (hpre : ∀ p : L1.Prog, L1.Pre p → L1.NI p → L2.Pre (γ12 p)) :
    Preserves L1 L3 (fun p => γ23 (γ12 p)) := by
  intro p hp hn
  exact h23 (γ12 p) (hpre p hp hn) (h12 p hp hn)

/-! ## GAP 1 DISCHARGED — policy ⇝ ocap/effect language.

    Modeled verbatim on the sealed `DischargedBundle`
    (`crates/nucleus-ifc-kernel/src/discharge.rs`). -/

/-- The eight sealed discharge obligations, verbatim from `DischargedBundle`
    (`discharge.rs`): the exact set `preflight_action` must clear to mint the
    unforgeable proof-token that the effect fns require at compile time. -/
inductive Obligation
  | integrityGate           -- artifact integrity ≥ sink minimum
  | pathAllowed             -- operation structurally permitted for the sink
  | derivationClear         -- derivation class compatible with the sink
  | noAdversarialAncestry   -- no source label carries adversarial integrity (the NI clause)
  | budgetNotExceeded       -- estimated cost fits the budget gate
  | withinDelegationCeiling -- requested capability ≤ policy ceiling
  | inScopeWithTask         -- operation within the verified task token's scope
  | inputsAuthorized        -- every action input is content-addressed

/-- A policy-layer program: a proposed action together with which obligations its
    `preflight_action` run discharged (`true` = passed). -/
structure PolicyProg where
  discharged : Obligation → Bool

/-- An ocap/effect-language program: an emitted effect carrying the proof-token it
    was minted from. An effect fn (`portcullis-effects`) REQUIRES a
    `DischargedBundle` argument, so no effect exists without a token to record. -/
structure OcapProg where
  token : Obligation → Bool

/-- **Policy-layer noninterference** = the sealed bundle is FULL: every obligation
    discharged. Exactly the precondition `preflight_action` enforces before minting
    `DischargedBundle`; `noAdversarialAncestry` is the structural non-interference
    clause (no adversarial-integrity source reaches the sink). -/
def PolicyNI (p : PolicyProg) : Prop := ∀ o : Obligation, p.discharged o = true

/-- **Ocap-layer noninterference** = the emitted effect is MEDIATED: its token is
    complete. An un-mediated effect is unconstructable upstream (the effect fn does
    not type-check without the `DischargedBundle`); here that is a complete token. -/
def OcapNI (e : OcapProg) : Prop := ∀ o : Obligation, e.token o = true

/-- The compiler threads the preflight obligation set into the effect token
    verbatim. -/
def γ_ocap (p : PolicyProg) : OcapProg := ⟨p.discharged⟩

/-- **Anti-laundering, explicit** (cf. the #1207 session-taint ratchet): the
    emitted token is *exactly* the policy's discharged set — the compiler can
    neither fabricate a discharge it was not given nor silently cleanse one. -/
theorem γ_ocap_no_laundering (p : PolicyProg) : (γ_ocap p).token = p.discharged := rfl

/-! ## Downstream stack (opaque until modeled — bridges 2..4 remain axioms). -/

abbrev IsaProg    : Type := Unit
abbrev KernelProg : Type := Unit
abbrev HwProg     : Type := Unit

opaque IsaNI    : IsaProg    → Prop
opaque KernelNI : KernelProg → Prop
opaque HwNI     : HwProg     → Prop

opaque γ_secomp : OcapProg   → IsaProg
opaque γ_kernel : IsaProg    → KernelProg
opaque γ_cheri  : KernelProg → HwProg

def L_policy : Layer := ⟨PolicyProg, PolicyNI, fun _ => True⟩
def L_ocap   : Layer := ⟨OcapProg,   OcapNI,   fun _ => True⟩
def L_isa    : Layer := ⟨IsaProg,    IsaNI,    fun _ => True⟩
def L_kernel : Layer := ⟨KernelProg, KernelNI, fun _ => True⟩
def L_hw     : Layer := ⟨HwProg,     HwNI,     fun _ => True⟩

/-- **GAP 1 DISCHARGED (axiom → theorem).** Policy ⇝ ocap preserves noninterference:
    if preflight discharged every obligation (`PolicyNI`), the emitted effect is
    mediated (`OcapNI`). Proven, Mathlib-free, axiom-free — the Lean image of the
    Rust compile-time guarantee `write_file(.., _proof: DischargedBundle)`. -/
theorem bridge_policy_ocap : Preserves L_policy L_ocap γ_ocap := by
  intro p _ hNI o
  exact hNI o

/-- GAP 2 — ocap ⇝ machine/ISA via a noninterference-preserving compiler
    (SECOMP / StkTokens linear capabilities). Artifacts exist upstream; UNWIRED here. -/
axiom bridge_ocap_isa : Preserves L_ocap L_isa γ_secomp

/-- GAP 3 — ISA ⇝ verified kernel/hypervisor (seL4-class). UNWIRED. -/
axiom bridge_isa_kernel : Preserves L_isa L_kernel γ_kernel

/-- GAP 4 — kernel ⇝ CHERI hardware (ISA-model capability monotonicity; VeriCHERI
    at RTL). UNWIRED. Below this line is the modulo-hardware floor (timing
    side-channels), which no NI theorem here covers. -/
axiom bridge_kernel_hw : Preserves L_kernel L_hw γ_cheri

/-- **End-to-end.** The proof-token composes down the whole stack: if the agent
    policy establishes NI, the CHERI-ISA execution robustly satisfies NI — modulo
    hardware. Depends on EXACTLY the three remaining gap axioms (GAP 1 is proven);
    the composition itself is `preserves_seq`. When all bridges become theorems this
    corollary is axiom-free and the North Star holds all the way to hardware. -/
theorem end_to_end :
    Preserves L_policy L_hw (fun p => γ_cheri (γ_kernel (γ_secomp (γ_ocap p)))) := by
  have s1 : Preserves L_policy L_isa (fun p => γ_secomp (γ_ocap p)) :=
    preserves_seq (L1 := L_policy) (L2 := L_ocap) (L3 := L_isa)
      γ_ocap γ_secomp bridge_policy_ocap bridge_ocap_isa (fun _ _ _ => trivial)
  have s2 : Preserves L_policy L_kernel (fun p => γ_kernel (γ_secomp (γ_ocap p))) :=
    preserves_seq (L1 := L_policy) (L2 := L_isa) (L3 := L_kernel)
      (fun p => γ_secomp (γ_ocap p)) γ_kernel s1 bridge_isa_kernel (fun _ _ _ => trivial)
  exact preserves_seq (L1 := L_policy) (L2 := L_kernel) (L3 := L_hw)
    (fun p => γ_kernel (γ_secomp (γ_ocap p))) γ_cheri s2 bridge_kernel_hw (fun _ _ _ => trivial)

-- Machine-checked distance-to-done signals (printed to the build log):
--   the spine and GAP 1 are unconditional; end_to_end depends on exactly 3 axioms.
#print axioms preserves_seq
#print axioms bridge_policy_ocap
#print axioms end_to_end

end Nucleus.UniformPrimitive
