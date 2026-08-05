/-
  Phase 0 — the falsification spike for the reference pod-execution semantics.

  Plan: ~/.claude/plans/graceful-puzzling-beaver.md. The question this file must
  answer, cheaply and in plain Lean, is: does giving nucleus an EXECUTION with an
  emitted EVENT TRACE make observational (two-run) noninterference NON-VACUOUS —
  where the existing extensional decision theorem becomes the per-step unwinding
  lemma — or does it collapse to `rfl` (in which case the whole convergence
  thesis is dead and we stop)?

  The model is COARSE-GRAINED (Vassena–Russo–Garg, POPL'19): the workload is an
  OPAQUE process; we do not model its internals. We model the MONITOR: a
  small-step machine that consumes a stream of material-delivery requests and,
  for each, consults the shipped decision oracle `identity_reaches_workload` to
  decide whether the material is DELIVERED to the workload (a visible event) or
  DROPPED (invisible to it). The workload's low-observable is the sequence of
  delivered materials.

  The payoff: `noninterference` below is a genuine TWO-RUN theorem — two request
  streams that agree on their non-Secret content produce EQUAL delivered traces —
  and it is discharged by `IdentityMaterialNoninterference.
  identity_material_never_reaches_the_workload`, the extracted per-step lemma,
  via `deliverable_excludes_secret`. It is non-vacuous: Public/Ordinary material
  IS delivered, Secret material is NOT, and two streams differing only in which
  Secret material they carry deliver identically (the separating witness).

  Mathlib-free by design (imports only the Aeneas-generated identity oracle), so
  it kernel-checks fast and carries the clean `[propext, Classical.choice,
  Quot.sound]`-or-fewer axiom profile the gates require.
-/

import PortcullisCoreIdentity.Types
import PortcullisCoreIdentity.Funs
import IdentityMaterialNoninterferenceExtracted

open Aeneas Aeneas.Std Result

namespace PodMachineSpike

open nucleus_ifc_kernel

abbrev Material := extracted.identity.MaterialKind

/-! ## The decision oracle, as total Bool predicates

`identity_reaches_workload`/`mat_label` are Aeneas-generated in the `Result`
monad and are total (never `fail`/`div`; see the `*_never_fails` theorems in
`IdentityMaterialNoninterferenceExtracted`). We read them as `Bool` predicates
the machine can branch on. -/

/-- The shipped delivery decision: may this material be delivered to the
    workload? Consults the extracted `identity_reaches_workload` — the universal-
    contract idiom (the semantics is defined OVER the shipped oracle). -/
def deliverable (m : Material) : Bool :=
  match extracted.identity.identity_reaches_workload m with
  | .ok b => b
  | _ => false

/-- Classification: is this material `Secret`? Reads the extracted `mat_label`. -/
def isSecret (m : Material) : Bool :=
  match extracted.identity.mat_label m with
  | .ok .Secret => true
  | _ => false

/-! ## The machine (a coarse-grained monitor LTS)

State = (pending requests, emitted event trace). One step consumes the head
request and emits exactly one event: `delivered` if the oracle admits it,
`dropped` otherwise. The workload sees only `delivered` events. -/

inductive Event where
  | delivered (m : Material)
  | dropped (m : Material)

structure Config where
  pending : List Material
  trace : List Event

/-- Small-step relation. `deliver`/`drop` are mutually exclusive on the head
    (the oracle is a function), so the machine is deterministic. -/
inductive Step : Config → Config → Prop where
  | deliver {m rest tr} (h : deliverable m = true) :
      Step ⟨m :: rest, tr⟩ ⟨rest, tr ++ [Event.delivered m]⟩
  | drop {m rest tr} (h : deliverable m = false) :
      Step ⟨m :: rest, tr⟩ ⟨rest, tr ++ [Event.dropped m]⟩

/-- Reflexive-transitive closure: a run. -/
inductive Steps : Config → Config → Prop where
  | refl (c : Config) : Steps c c
  | step {a b c} : Step a b → Steps b c → Steps a c

/-- The event trace the machine emits running to completion over a request
    stream — the executable unfolding of `Step`. -/
def traceOf : List Material → List Event
  | [] => []
  | m :: rest =>
      (if deliverable m then Event.delivered m else Event.dropped m) :: traceOf rest

/-- The workload's low-observable: the delivered materials, in order. Drops are
    the monitor's private action and are invisible to the workload. -/
def lowObs : List Event → List Material
  | [] => []
  | Event.delivered m :: es => m :: lowObs es
  | Event.dropped _ :: es => lowObs es

/-- What a completed run makes observable. -/
def run (req : List Material) : List Material := lowObs (traceOf req)

/-! ## Adequacy: the LTS relation and the executable trace agree

A run of the `Step` relation to a halted state (`pending = []`) produces exactly
`traceOf` — so `run` is a faithful reading of the small-step machine, not an
unrelated fold. -/

theorem steps_produce_traceOf {req : List Material} {tr acc : List Event}
    (h : Steps ⟨req, acc⟩ ⟨[], tr⟩) : tr = acc ++ traceOf req := by
  induction req generalizing acc with
  | nil =>
    cases h with
    | refl => simp [traceOf]
    | step s _ => cases s
  | cons m rest ih =>
    cases h with
    | step s rest_steps =>
      cases s with
      | deliver hd =>
        have := ih rest_steps
        simp [traceOf, hd, this, List.append_assoc]
      | drop hd =>
        have := ih rest_steps
        simp [traceOf, hd, this, List.append_assoc]

/-- Corollary: from the initial config, a completed run's low-observable is
    `run req`. -/
theorem run_is_lowObs_of_completed {req : List Material} {tr : List Event}
    (h : Steps ⟨req, []⟩ ⟨[], tr⟩) : lowObs tr = run req := by
  have := steps_produce_traceOf h
  simp [run, this]

/-! ## The per-step unwinding condition (from the EXTRACTED theorem)

This is where the shipped extensional theorem does its work: anything the oracle
delivers is provably not `Secret`. -/

/-- **The unwinding condition.** A delivered material is never `Secret` —
    the contrapositive of `identity_material_never_reaches_the_workload`. -/
theorem deliverable_excludes_secret (m : Material) :
    deliverable m = true → isSecret m = false := by
  intro hd
  by_contra hsec
  -- ¬(isSecret m = false)  ⇒  isSecret m = true  ⇒  mat_label m = ok Secret
  have hlab : isSecret m = true := by
    cases hs : isSecret m with
    | true => rfl
    | false => exact absurd hs hsec
  have hmat : extracted.identity.mat_label m
      = ok extracted.ifc_confidentiality.ConfLevel.Secret := by
    unfold isSecret at hlab
    split at hlab
    · assumption
    · simp at hlab
  -- the extracted theorem: Secret ⇒ not delivered
  have hzero := IdentityMaterialNoninterference.identity_material_never_reaches_the_workload m hmat
  -- but hd says it IS delivered
  unfold deliverable at hd
  rw [hzero] at hd
  simp at hd

/-! ## Noninterference (the two-run payoff)

`highErase` drops the Secret materials from a request stream. Two streams with
equal non-Secret content deliver identically — the Secret content (high) cannot
move the workload's observable (low). -/

/-- The non-Secret content of a request stream. -/
def highErase (req : List Material) : List Material :=
  req.filter (fun m => ! isSecret m)

/-- `run` equals filtering by `deliverable`. -/
theorem run_eq_filter (req : List Material) : run req = req.filter deliverable := by
  induction req with
  | nil => simp [run, traceOf, lowObs]
  | cons m rest ih =>
    simp only [run, traceOf, List.filter]
    cases hd : deliverable m with
    | true => simp [lowObs]; exact ih
    | false => simp [lowObs]; exact ih

/-- Delivering ignores the Secret entries entirely: they were going to be dropped
    anyway (by `deliverable_excludes_secret`), so removing them first changes
    nothing. This is the trace-level lift of the per-step condition. -/
theorem run_ignores_secret (req : List Material) : run (highErase req) = run req := by
  simp only [run_eq_filter, highErase, List.filter_filter]
  congr 1
  funext m
  cases hd : deliverable m with
  | true =>
    have hns := deliverable_excludes_secret m hd
    simp [hns]
  | false => simp

/-- **Noninterference.** Two request streams that agree on their non-Secret
    content produce equal delivered (low-observable) traces. A genuine two-run
    theorem, discharged by the extracted per-step lemma via `run_ignores_secret`. -/
theorem noninterference {req₁ req₂ : List Material}
    (h : highErase req₁ = highErase req₂) : run req₁ = run req₂ := by
  rw [← run_ignores_secret req₁, ← run_ignores_secret req₂, h]

/-- The same, phrased over the LTS relation: completed runs from low-equivalent
    initial configs are observationally equal. -/
theorem noninterference_lts {req₁ req₂ : List Material} {tr₁ tr₂ : List Event}
    (hlow : highErase req₁ = highErase req₂)
    (h₁ : Steps ⟨req₁, []⟩ ⟨[], tr₁⟩) (h₂ : Steps ⟨req₂, []⟩ ⟨[], tr₂⟩) :
    lowObs tr₁ = lowObs tr₂ := by
  rw [run_is_lowObs_of_completed h₁, run_is_lowObs_of_completed h₂]
  exact noninterference hlow

/-! ## Non-vacuity — the separating witnesses

If the model were vacuous (nothing delivered, or Secret delivered), these would
be unprovable or trivially false. They pin that the machine does real work AND
that the NI theorem has content. -/

open extracted.identity.MaterialKind in
/-- Ordinary material IS delivered — the system does something. -/
example : run [OrdinaryData] = [OrdinaryData] := by rfl

open extracted.identity.MaterialKind in
/-- A Secret material (the SVID private key) is NOT delivered. -/
example : run [SvidPrivateKey] = [] := by rfl

open extracted.identity.MaterialKind in
/-- The separating witness for NI: two streams differing ONLY in their Secret
    material (SvidCert vs TaskToken, both Secret) deliver IDENTICALLY. Were Secret
    material deliverable, this would be `[SvidCert,…] = [TaskToken,…]`, false. -/
example : run [SvidCert, OrdinaryData] = run [TaskToken, OrdinaryData] := by rfl

end PodMachineSpike
