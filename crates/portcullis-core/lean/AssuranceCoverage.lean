/-!
# Assurance coverage — the gate suite as a covering family

## Why this file exists

Over one week this repo produced ~15 findings that were all the same finding:
a mechanism exists, a claim is made about it, and nothing joins the claim to the
running path. `check_flow` with no production caller. `ZkFlowInput` with a zkVM
guest, a working verifier and no producer. A CI drift gate skipped on every
recorded run. A mediation lint that could not see one `async fn` body.

The instinct was to add another gate. The vocabulary below says why that instinct
is wrong, and names the number to compute instead.

## Attribution

`Faithful`, `Full` and `not_full_iff_unreached_obligation` are ported from
`coproduct/olog/claim-calculus` (`Claims/Assurance.lean`), which proves the
general theory: claim debt decomposes into missing evidence, vacuity, and
uncovered claims, and a gate suite's defect is **joint surjectivity, not cocycle
agreement**.

They are copied rather than imported. claim-calculus is Lean 4.32.0; this tree is
pinned to 4.30.0-rc2 with Mathlib and Aeneas locked to it, so importing a
ten-line dependency-free vocabulary would mean bumping a lockstep triple and
re-extracting 68 `lean_lib`s. The definitions carry no dependencies and the proof
is pure logic, so the port is faithful; the cost of the alternative is not.

## What this buys, and what it does not

claim-calculus states its own limit and it applies here verbatim: *"No new
checking power. Naming the obstruction tells you which number to compute; it does
not detect anything Lean could not."*

So this file does not detect anything. It (a) fixes the vocabulary, (b) records
which obligations the suite actually reaches, and (c) proves the suite is **not
full** — with the unreached obligation exhibited, not asserted.

**A gate's support must be MEASURED, not declared.** That is the lesson the
mediation lint taught: its declared support was "the mediated crate set"; its
actual support excluded every `async fn` in it. A certificate over declared
supports would be vacuous in exactly the way the tests it failed to replace were.
The measurement is perturbation — a gate's support is the set of claim-violations
that make it go RED.
-/

namespace Nucleus.Assurance

universe u v

/-- **Faithful** — the map does not conflate distinct things. Ported verbatim. -/
def Faithful {A : Sort u} {B : Sort v} (f : A → B) : Prop :=
  ∀ a₁ a₂ : A, f a₁ = f a₂ → a₁ = a₂

/-- **Full**, relative to the obligations that actually exist on the target.

Not plain surjectivity: an assurance edge is not obliged to reach every value of
the target type, only every obligation posed there. Making `Obl` explicit is what
stops "full" from meaning something unachievable and therefore never claimed. -/
def Full {A : Sort u} {B : Sort v} (f : A → B) (Obl : B → Prop) : Prop :=
  ∀ b, Obl b → ∃ a, f a = b

/-- **A fullness failure is an unreached obligation.**

The theorem that makes this vocabulary worth having: it converts "our coverage is
incomplete" — unfalsifiable hand-waving — into "here is a specific obligation no
arrow reaches", which is a thing you can be wrong about. -/
theorem not_full_iff_unreached_obligation {A B : Type} (f : A → B) (Obl : B → Prop) :
    (¬ Full f Obl) ↔ ∃ b, Obl b ∧ ∀ a, f a ≠ b := by
  constructor
  · intro h
    by_cases hex : ∃ b, Obl b ∧ ∀ a, f a ≠ b
    · exact hex
    · refine absurd (fun b hb => ?_) h
      by_cases hpre : ∃ a, f a = b
      · exact hpre
      · exact absurd ⟨b, hb, fun a he => hpre ⟨a, he⟩⟩ hex
  · rintro ⟨b, hb, hno⟩ hfull
    obtain ⟨a, ha⟩ := hfull b hb
    exact hno a ha

/-! ## The obligation space

Claim-bearing mechanisms: something in a doc, a ledger entry or a theorem depends
on each of these running. Deliberately not all ~575 public functions — being
wrong about a formatting helper costs nothing. -/

inductive Obligation where
  /-- Outbound actions are gated on session integrity. -/
  | ifcEgressGate
  /-- Every kernel decision, allow AND refuse, reaches the evidence sink. -/
  | decisionRecording
  /-- Bytes entering a session create a flow node. -/
  | ingestObservation
  /-- Flow nodes carry derivation edges, so lineage is real. -/
  | perNodeLineage
  /-- A session's decisions can be exported for third-party replay. -/
  | zkFlowInputProduction
  /-- Declassification is authenticated, scoped and reachable. -/
  | signedDeclassification
  deriving DecidableEq, Repr

/-! ## The gates that exist -/

inductive Gate where
  | toolProxySuite
  | flowReplayCorpus
  | mediationLint
  | observedLint
  deriving DecidableEq, Repr

/-- What each gate's support ACTUALLY reaches, as measured by perturbation —
each entry below corresponds to a check that has been observed going RED when the
obligation is violated. Entries are not claims about intent. -/
def reaches : Gate → Obligation → Bool
  | .toolProxySuite,   .ifcEgressGate       => true   -- tainted_session_denies_write
  | .toolProxySuite,   .decisionRecording   => true   -- denied_kernel_decision_is_recorded (#2127)
  | .toolProxySuite,   .ingestObservation   => true   -- command_output_taint (#2134)
  | .flowReplayCorpus, .ifcEgressGate       => true   -- the 430-decision corpus (#2129)
  | .observedLint,     .ingestObservation   => true   -- REDs when the observe is deleted (#2137)
  | _, _ => false

/-- The suite covers an obligation iff some gate's support reaches it. This is
`Full` at suite scale — joint surjectivity of the covering family. -/
def Covered (b : Obligation) : Prop := ∃ g : Gate, reaches g b = true

/-- Every obligation in the space is posed. -/
def Posed (_ : Obligation) : Prop := True

/-- Suite-scale fullness. -/
def SuiteFull : Prop := ∀ b, Posed b → Covered b

/-! ## Where the suite actually stands -/

/-- **The suite is NOT full.** Lineage is claimed in documentation and reached by
no gate — because production observes every flow node with no parents, so there
is nothing for a gate to check. Exhibited, not asserted. -/
theorem suite_not_full : ¬ SuiteFull := by
  intro h
  obtain ⟨g, hg⟩ := h .perNodeLineage trivial
  cases g <;> simp [reaches] at hg

/-- And two more, so the gap is not a single stale entry. -/
theorem zk_export_uncovered : ¬ Covered .zkFlowInputProduction := by
  rintro ⟨g, hg⟩; cases g <;> simp [reaches] at hg

theorem declassification_uncovered : ¬ Covered .signedDeclassification := by
  rintro ⟨g, hg⟩; cases g <;> simp [reaches] at hg

/-- **Anti-vacuity.** `suite_not_full` would also hold of a suite that reaches
nothing at all, which would make it worthless as a measurement. Some obligations
ARE covered. -/
theorem suite_covers_something : Covered .ifcEgressGate :=
  ⟨.toolProxySuite, rfl⟩

/-- **The load-bearing negative result, instantiated.**

claim-calculus proves that pairwise agreement of gates does not imply joint
surjectivity. Here is that theorem as it actually happened: before #2138 the
mediation lint and the observed lint were both GREEN and AGREED — and neither
reached `perNodeLineage`. Agreement bought nothing; only a gate whose support
reaches a new obligation does.

This is why "add another gate" was the wrong instinct, and it is checkable rather
than rhetorical. -/
theorem agreement_does_not_imply_coverage :
    (reaches .mediationLint .perNodeLineage = reaches .observedLint .perNodeLineage)
      ∧ ¬ Covered .perNodeLineage := by
  refine ⟨rfl, ?_⟩
  rintro ⟨g, hg⟩; cases g <;> simp [reaches] at hg

end Nucleus.Assurance
