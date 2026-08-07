/-
  Sink-scoped, one-shot declassification — proven OVER the Aeneas-EXTRACTED
  decision core, not a hand model.

  The chain is the same one FM-5 and the mediation scope proof use:

      crates/nucleus-ifc-kernel/src/extracted/declassify.rs        (real Rust)
        --charon (scoped, --start-from)-->  nucleus_ifc_kernel.llbc
        --aeneas -backend lean -split-files-->
          generated-declass/PortcullisCoreDeclass/{Types,Funs}.lean
        --(this file)-->  the theorems below, over THOSE generated defs.

  This file REPLACES the hand-written `sink_outside_allowlist_denied` in
  DeclassifyProofs.lean, which proved a property of a restriction the shipping
  code did not implement (`allows_sink` had no non-test callers, and
  `FlowGraph::apply_token` raised labels globally). PR #2207 made the shipping
  code enforce the scope via a per-node released VIEW; these theorems are stated
  over the extracted decision functions that view is computed by, and the
  graph↔extracted binding is the pointwise test in
  `portcullis/tests/declassify_scope.rs` plus the exhaustive 2^13 × 13 parity
  sweep in `portcullis-core/src/declassify.rs`.

  # The two properties, and what each buys

  * **Sink scope (O4/O5 — "cannot steer which value").** `declass_release_ok`
    lets released data reach a sink ONLY through an operation the signed mask
    admits; outside the mask the strict pre-declassification level governs. The
    released level and the mask are fields of the governor-signed token — never
    attacker input — so which value is released is fixed by the signature, not
    steerable by the workload. `sink_outside_a_singleton_mask_denied` is the
    concrete "scoped to one sink does not clear another"; the empty-mask family
    generalizes it over every operation.

  * **One-shot burn (O3 — "single-use").** `declass_step` is a 2-state ABSORBING
    machine: applying burns the token forever, and a refusal (bad signature,
    unmet precondition, or already-burned) leaves the state untouched. It is
    deliberately NOT the mediation machine `med_step`, whose `Discharge`
    re-arms — re-arming is exactly what a one-shot token must never do, so
    `no_second_apply` is strictly stronger than the mediation machine's
    `no_replay_without_a_fresh_discharge` (there is no re-arming action at all).

  # Ground truth (Rust↔model parity) and honest scope

  The generated defs mirror the production decision — bound by the exhaustive
  `mask_admits ↔ allows_sink` sweep (106 496 cases) and the two-oracle graph
  binding cited above. What is NOT proved here, stated rather than hidden: the
  full four-run robust-declassification statement over the reference pod-machine
  LTS (attacker inputs varied on both sides) is where `PodMachineSpike` hooks
  in and is a larger add — the executable two-run form ships as a test in
  `declassify_scope.rs`, and the released set's independence from attacker input
  is visible here only as `effective_conf`'s dependence on its
  token-and-graph-derived arguments alone. Charon/Aeneas extraction fidelity and
  rustc's affine-move enforcement remain trusted, as elsewhere in this corpus.
-/

import PortcullisCoreDeclass.Types
import PortcullisCoreDeclass.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

set_option maxHeartbeats 1000000

namespace DeclassifySinkScopeExtracted

open nucleus_ifc_kernel.extracted.declassify
open nucleus_ifc_kernel.extracted.mediation (MedOperation)
open nucleus_ifc_kernel.extracted.ifc_confidentiality (ConfLevel)

/-! ## Totality of the generated decision functions

    Each returns the Aeneas `Result` monad. The theorems below are stated
    against concrete `ok` values, so they would hold vacuously if a function
    could `fail`. These rule that out — and in doing so discharge the `<<<`
    (shift) and `&&&` (bit-and) binds inside `mask_admits`, which the `Result`
    monad does not know are total. -/

/-- `mask_admits` never fails. The shift `1 <<< opcode op` is by 0..=12 < 16,
    so it does not overflow; splitting on the operation makes each shift
    concrete. -/
theorem mask_admits_total (mask : Std.U16) (op : MedOperation) :
    ∃ b : Bool, mask_admits mask op = ok b := by
  unfold mask_admits
  cases op <;>
    simp only [nucleus_ifc_kernel.extracted.mediation.opcode, bind_tc_ok, lift] <;>
    exact ⟨_, rfl⟩

theorem effective_conf_total
    (strict released : ConfLevel) (mask : Std.U16) (op : MedOperation) :
    ∃ c : ConfLevel, effective_conf strict released mask op = ok c := by
  unfold effective_conf
  obtain ⟨b, hb⟩ := mask_admits_total mask op
  rw [hb]
  cases b <;> simp only [bind_tc_ok] <;> exact ⟨_, rfl⟩

theorem declass_release_ok_total
    (strict released : ConfLevel) (mask : Std.U16) (op : MedOperation)
    (sink_cap : ConfLevel) :
    ∃ b : Bool, declass_release_ok strict released mask op sink_cap = ok b := by
  unfold declass_release_ok
  obtain ⟨c, hc⟩ := effective_conf_total strict released mask op
  rw [hc]
  simp only [bind_tc_ok]
  -- cflows_to is a total comparison of two ranks.
  unfold nucleus_ifc_kernel.extracted.ifc_confidentiality.cflows_to
  cases c <;> cases sink_cap <;>
    simp only [nucleus_ifc_kernel.extracted.ifc_confidentiality.crank, bind_tc_ok] <;>
    exact ⟨_, rfl⟩

/-! ## The shadow pick: released inside the mask, strict outside -/

/-- Inside the mask, the node contributes its released level. -/
theorem effective_conf_in_mask
    (strict released : ConfLevel) (mask : Std.U16) (op : MedOperation)
    (hin : mask_admits mask op = ok true) :
    effective_conf strict released mask op = ok released := by
  unfold effective_conf
  rw [hin]; rfl

/-- Outside the mask, the strict (pre-declassification) level governs — this is
    what makes a token scoped to one sink unable to clear its node for any
    other. -/
theorem effective_conf_out_of_mask
    (strict released : ConfLevel) (mask : Std.U16) (op : MedOperation)
    (hout : mask_admits mask op = ok false) :
    effective_conf strict released mask op = ok strict := by
  unfold effective_conf
  rw [hout]; rfl

/-! ## The empty mask admits nothing

    An empty `allowed_sinks` compiles to mask 0; `0 &&& bit = 0`, so no
    operation is admitted. A token with no sinks is inert. -/
theorem empty_mask_admits_nothing (op : MedOperation) :
    mask_admits 0#u16 op = ok false := by
  unfold mask_admits
  cases op <;>
    simp only [nucleus_ifc_kernel.extracted.mediation.opcode, bind_tc_ok, lift] <;>
    rfl

/-! ## No release outside the mask (the O4/O5 headline)

    The extracted replacement for the hand model's `sink_outside_allowlist_denied`.
    Secret data does not reach a sink whose ceiling is below Secret through any
    operation the mask excludes — however the token lowered it. -/

/-- Empty-mask family: with no sinks granted, Secret data is denied at a Public
    ceiling for EVERY operation, whatever the released level. The strict level
    governs because the mask admits nothing. -/
theorem empty_mask_denies_secret_at_public
    (released : ConfLevel) (op : MedOperation) :
    declass_release_ok ConfLevel.Secret released 0#u16 op ConfLevel.Public
      = ok false := by
  unfold declass_release_ok
  rw [effective_conf_out_of_mask ConfLevel.Secret released 0#u16 op
        (empty_mask_admits_nothing op)]
  rfl

/-- The concrete "scoped to one sink does not clear another": a token whose mask
    admits ONLY `WebFetch` (bit 7) does not release Secret data — lowered to
    Public — to `GitPush` (bit 9), whose ceiling is Public. `128 &&& 512 = 0`. -/
theorem sink_outside_a_singleton_mask_denied :
    declass_release_ok ConfLevel.Secret ConfLevel.Public
      (128#u16) MedOperation.GitPush ConfLevel.Public = ok false := by
  unfold declass_release_ok
  have hout : mask_admits (128#u16) MedOperation.GitPush = ok false := by
    unfold mask_admits
    simp only [nucleus_ifc_kernel.extracted.mediation.opcode, bind_tc_ok, lift]
    rfl
  rw [effective_conf_out_of_mask ConfLevel.Secret ConfLevel.Public
        (128#u16) MedOperation.GitPush hout]
  rfl

/-! ## Non-vacuity: the in-mask sink CAN release

    Without this, "denied everywhere" would be satisfied by a function that
    denies everything, and the theorems above would say nothing. The same
    singleton mask that denies `GitPush` admits `WebFetch` and releases. -/
theorem sink_in_the_mask_can_release :
    declass_release_ok ConfLevel.Secret ConfLevel.Public
      (128#u16) MedOperation.WebFetch ConfLevel.Public = ok true := by
  unfold declass_release_ok
  have hin : mask_admits (128#u16) MedOperation.WebFetch = ok true := by
    unfold mask_admits
    simp only [nucleus_ifc_kernel.extracted.mediation.opcode, bind_tc_ok, lift]
    rfl
  rw [effective_conf_in_mask ConfLevel.Secret ConfLevel.Public
        (128#u16) MedOperation.WebFetch hin]
  rfl

/-! ## The one-shot machine (O3)

    `declass_step` is total (no loops, no partial arithmetic), so every theorem
    reduces once the state and inputs are fixed. -/

theorem declass_step_total
    (s : DeclassState) (sig_ok precond_ok : Bool) :
    ∃ r : DeclassStepResult, declass_step s sig_ok precond_ok = ok r := by
  unfold declass_step
  cases s.burned <;> cases sig_ok <;> cases precond_ok <;> exact ⟨_, rfl⟩

/-- `declass_fresh` is the unburned state. -/
theorem declass_fresh_is_unburned : declass_fresh = ok { burned := false } := by
  unfold declass_fresh; rfl

/-- Applying a fresh, validly-signed, precondition-met token SUCCEEDS and burns
    it: the next state has `burned = true`. -/
theorem apply_burns_the_token :
    declass_step { burned := false } true true
      = ok { ok := true, next := { burned := true } } := by
  unfold declass_step
  rfl

/-- A burned token admits NOTHING, ever again — for every possible input. This
    is the absorbing property, and it is why the machine is one-shot: unlike the
    mediation machine, there is no action that takes `burned` back to `false`. -/
theorem no_second_apply (sig_ok precond_ok : Bool) :
    declass_step { burned := true } sig_ok precond_ok
      = ok { ok := false, next := { burned := true } } := by
  unfold declass_step
  rfl

/-- A refusal preserves the token: from a fresh state, any input that is not
    (signed ∧ precondition-met) leaves `burned = false`, so a later valid apply
    still succeeds. This is `runD`'s spend-on-release-never-on-refusal, over the
    extracted machine. -/
theorem refusal_preserves_the_token
    (sig_ok precond_ok : Bool) (h : ¬ (sig_ok = true ∧ precond_ok = true)) :
    ∃ r : DeclassStepResult,
      declass_step { burned := false } sig_ok precond_ok = ok r ∧
      r.ok = false ∧ r.next.burned = false := by
  unfold declass_step
  cases sig_ok <;> cases precond_ok <;>
    first
      | (exact ⟨_, rfl, rfl, rfl⟩)
      | (exact absurd ⟨rfl, rfl⟩ h)

/-- The whole point, as one statement: from a fresh token, the FIRST valid apply
    releases and the SECOND is refused — a single use. -/
theorem single_use :
    (declass_step { burned := false } true true
      = ok { ok := true, next := { burned := true } }) ∧
    (declass_step { burned := true } true true
      = ok { ok := false, next := { burned := true } }) :=
  ⟨apply_burns_the_token, no_second_apply true true⟩

end DeclassifySinkScopeExtracted

-- The axiom audit in aeneas-ifc-scoped.yml reads these from the build log and
-- fails on anything outside {propext, Classical.choice, Quot.sound} — and on
-- their ABSENCE (a build that did not elaborate the theorems says nothing).
open DeclassifySinkScopeExtracted in
#print axioms mask_admits_total
open DeclassifySinkScopeExtracted in
#print axioms declass_release_ok_total
open DeclassifySinkScopeExtracted in
#print axioms empty_mask_denies_secret_at_public
open DeclassifySinkScopeExtracted in
#print axioms sink_outside_a_singleton_mask_denied
open DeclassifySinkScopeExtracted in
#print axioms sink_in_the_mask_can_release
open DeclassifySinkScopeExtracted in
#print axioms apply_burns_the_token
open DeclassifySinkScopeExtracted in
#print axioms no_second_apply
open DeclassifySinkScopeExtracted in
#print axioms refusal_preserves_the_token
open DeclassifySinkScopeExtracted in
#print axioms single_use
