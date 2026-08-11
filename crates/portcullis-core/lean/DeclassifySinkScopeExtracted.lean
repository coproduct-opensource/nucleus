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
    permits; outside the mask the strict pre-declassification level governs. The
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
  binding cited above. The four-run VALUE-robustness statement (Phase 5) — over
  runs that differ only in attacker-controlled inputs, the released value is
  identical (equal to the governor's commitment) or the run denies — is now
  PROVEN below (`## Four-run value robustness`), in the same style as
  `PodMachineSpike`'s coarse-grained delivery machine but on the VALUE axis; the
  executable four-run form ships as a test in `declassify_scope.rs`. What remains
  trusted, stated rather than hidden: the 32-byte `ContentHash` identity is
  modeled as an opaque `u64` tag (bound to the real byte comparison by the
  `declassify_scope.rs` parity test — equal bytes ⇒ equal tag, unequal ⇒ unequal,
  so the width abstraction cannot hide a steer); and Charon/Aeneas extraction
  fidelity plus rustc's affine-move enforcement remain trusted, as elsewhere in
  this corpus.
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
    permits ONLY `WebFetch` (bit 7) does not release Secret data — lowered to
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

/-! ## Value binding (Phase 3, C5): a release names the specific committed value

    `value_authorized` decides whether a declassification release is authorized
    for the SPECIFIC value the governor committed to. It authorizes ONLY when the
    token is bound to a value, the node has a recorded value, and the two
    identities are EQUAL — a pure equality over the value identity. The 32-byte
    SHA-256 identity is modeled as an opaque `u64` tag; the runtime binds its real
    `ContentHash` comparison to this decision in the `apply_token_verified` parity
    test (`portcullis/src/flow_graph_tests.rs`). This is what denies an adversary
    steering WHICH value a signed release clears: the signature fixes the
    identity, and a substituted value has a different identity and is refused. -/

/-- Totality: the value decision never fails. -/
theorem value_authorized_total (cb rp : Bool) (c r : Std.U64) :
    ∃ b : Bool, value_authorized cb rp c r = ok b := by
  unfold value_authorized
  cases cb <;> cases rp <;> exact ⟨_, rfl⟩

/-- Fail-closed: an UNBOUND token authorizes no release — for any recorded flag
    and any identities. -/
theorem unbound_token_never_authorizes (rp : Bool) (c r : Std.U64) :
    value_authorized false rp c r = ok false := by
  unfold value_authorized; rfl

/-- Fail-closed: a node with NO recorded value identity authorizes no release —
    for any token-bound flag and any identities. -/
theorem missing_hash_never_authorizes (cb : Bool) (c r : Std.U64) :
    value_authorized cb false c r = ok false := by
  unfold value_authorized; cases cb <;> rfl

/-- The C5 headline: a value-bound token committing to identity `7` does NOT
    authorize releasing a DIFFERENT recorded identity `9`. A substituted value
    has a different identity and is refused — an adversary cannot ride the
    governor's signature to release a value it did not authorize. -/
theorem substituted_value_refused :
    value_authorized true true 7#u64 9#u64 = ok false := by
  unfold value_authorized; rfl

/-- Non-vacuity: the matching value IS released — the gate is not
    deny-everything. Committing to identity `7` authorizes releasing `7`. -/
theorem committed_value_authorized :
    value_authorized true true 7#u64 7#u64 = ok true := by
  unfold value_authorized; rfl

/-! ## Four-run value robustness (Phase 5, C5): the released VALUE cannot be
    steered by attacker-controlled inputs

    The scalar theorems above (`substituted_value_refused`,
    `committed_value_authorized`) fix the value binding pointwise. This section
    lifts them to the RELATIONAL statement that is the demotion reason for C5:
    over runs that differ only in attacker input, the released value does not
    change — the attacker can force a deny, never a different value.

    A RUN applies a governor-signed declassification token to a node and either
    RELEASES a value or DENIES. The governor SIGNS, and thus FIXES across runs,
    the value commitment `c` (`committed`) and the bound flag `cb`
    (`committed_bound`). The node's recorded content identity `r` (`recorded`)
    and its presence flag `rp` (`recorded_present`) are MONITOR-recorded facts
    derived from the workload — i.e. ATTACKER-CONTROLLED in the threat model.
    `runValue` reads the extracted `value_authorized` decision; on authorization
    it physically egresses the node's RECORDED content (what actually leaves the
    boundary), otherwise it denies. This is the value-axis analogue of
    `PodMachineSpike`'s delivery machine: there the low-observable is the
    delivered material; here it is the released VALUE. -/

/-- The Bool release predicate the run branches on: `bound ∧ present ∧
    (committed == recorded)`. Equal to the extracted `value_authorized` decision
    (next lemma), so the machine below decides through the shipped oracle. -/
def releases (cb rp : Bool) (c r : Std.U64) : Bool := cb && rp && (c == r)

/-- `releases` IS the extracted decision — the machine consults the shipped
    oracle, not a re-implementation. -/
theorem releases_eq_value_authorized (cb rp : Bool) (c r : Std.U64) :
    value_authorized cb rp c r = ok (releases cb rp c r) := by
  unfold value_authorized releases
  -- The fresh Aeneas extraction renders the Rust `committed == recorded` (U64)
  -- as `decide (committed = recorded)`, whereas `releases` uses the `BEq` form
  -- `c == r`: propositionally but NOT definitionally equal, so the old bare
  -- `simp` (and a plain `rfl`) leave the (true,true) branch open and elaborate to
  -- `sorryAx`. Close it with EXPLICIT, drift-stable tactics only (no reliance on
  -- the mutable default `simp` set): collapse the nested Bool `if`s, then per
  -- branch finish by `rfl` (the three deny branches) or by normalizing `==` to
  -- `decide (·=·)` with `Bool.beq_eq_decide_eq` (the release branch).
  cases cb <;> cases rp <;>
    simp only [Bool.false_eq_true, if_false, if_true, reduceCtorEq, reduceIte,
               Bool.true_and, Bool.and_true, ok.injEq] <;>
    first | rfl | rw [Bool.beq_eq_decide_eq]

/-- A run's observable outcome: a released value, or a denial. -/
inductive Outcome where
  | released (v : Std.U64)
  | denied
deriving DecidableEq

/-- One run: apply the governor-signed token (`cb`, `c`) to a node whose recorded
    content `(rp, r)` is attacker-controlled. On authorization the RECORDED
    content is what egresses; otherwise the run denies. -/
def runValue (cb rp : Bool) (c r : Std.U64) : Outcome :=
  if releases cb rp c r then Outcome.released r else Outcome.denied

/-- **The teeth of value-binding.** A run can only RELEASE the governor-committed
    value. Even though the egressed value is the attacker-influenced RECORDED
    content, authorization forces it to equal the commitment — so the released
    value is provably the governor's `c`, never a value the attacker substituted.
    This is where the equality check in `value_authorized` does its work. -/
theorem released_value_is_the_commitment
    (cb rp : Bool) (c r v : Std.U64)
    (h : runValue cb rp c r = Outcome.released v) : v = c := by
  unfold runValue at h
  split at h
  · rename_i hb
    injection h with hrv
    unfold releases at hb
    simp only [Bool.and_eq_true, beq_iff_eq] at hb
    rw [← hrv, ← hb.2]
  · exact absurd h (by simp)

/-- **Four-run value non-steering (relational).** For a FIXED governor-signed
    token (`cb`, `c`), ANY two runs whose attacker inputs `(rp, r)` both RELEASE
    release the SAME value. The attacker cannot make one signed token emit two
    different values by varying its inputs. -/
theorem four_run_value_non_steering
    (cb : Bool) (c : Std.U64)
    (rp₁ rp₂ : Bool) (r₁ r₂ v₁ v₂ : Std.U64)
    (h₁ : runValue cb rp₁ c r₁ = Outcome.released v₁)
    (h₂ : runValue cb rp₂ c r₂ = Outcome.released v₂) :
    v₁ = v₂ := by
  rw [released_value_is_the_commitment cb rp₁ c r₁ v₁ h₁,
      released_value_is_the_commitment cb rp₂ c r₂ v₂ h₂]

/-- **Content mismatch denies.** A run whose recorded content differs from the
    commitment DENIES — for any bound/presence flags. This is the
    `TokenApplyResult::ContentMismatch` deny: an attacker who substitutes a value
    (`r ≠ c`) gets a denial, not a release of the substituted value. -/
theorem content_mismatch_denies (cb rp : Bool) (c r : Std.U64) (h : c ≠ r) :
    runValue cb rp c r = Outcome.denied := by
  unfold runValue releases
  have hcr : (c == r) = false := by simp [h]
  simp [hcr]

/-- **Attacker chooses only WHETHER, never WHICH.** For a fixed governor token,
    every run either releases EXACTLY the committed value `c` or denies. The
    released value is a function of the governor's signature alone; attacker
    input can only toggle liveness (release vs deny). -/
theorem attacker_cannot_steer_the_value (cb rp : Bool) (c r : Std.U64) :
    runValue cb rp c r = Outcome.released c ∨ runValue cb rp c r = Outcome.denied := by
  cases h : runValue cb rp c r with
  | released v =>
    left
    have hvc := released_value_is_the_commitment cb rp c r v h
    rw [hvc]
  | denied => right; rfl

/-- **The four-run robustness theorem.** Four runs of one governor-signed token
    over the 2×2 grid of attacker inputs (presence flag `rpA/rpB` × recorded
    identity `rA/rB`): every one of the four either releases EXACTLY the
    committed value or denies. No attacker-input combination releases any other
    value — the released value is robust against attacker-controlled inputs. -/
theorem four_run_value_robustness
    (cb : Bool) (c : Std.U64)
    (rpA rpB : Bool) (rA rB : Std.U64) :
    (runValue cb rpA c rA = Outcome.released c ∨ runValue cb rpA c rA = Outcome.denied) ∧
    (runValue cb rpA c rB = Outcome.released c ∨ runValue cb rpA c rB = Outcome.denied) ∧
    (runValue cb rpB c rA = Outcome.released c ∨ runValue cb rpB c rA = Outcome.denied) ∧
    (runValue cb rpB c rB = Outcome.released c ∨ runValue cb rpB c rB = Outcome.denied) :=
  ⟨attacker_cannot_steer_the_value cb rpA c rA,
   attacker_cannot_steer_the_value cb rpA c rB,
   attacker_cannot_steer_the_value cb rpB c rA,
   attacker_cannot_steer_the_value cb rpB c rB⟩

/-! ### Non-vacuity — a releasing run and a denying run under varied attacker input

    If the machine denied everything the theorems above would be vacuous. These
    pin that it does real work AND that the deny arm is reachable by varying
    attacker input, so the four-run statement has content. Governor commits `7`:
    the honest node recorded `7` and RELEASES `7`; an attacker that substituted
    `9` makes the SAME signed token DENY (liveness moved, value never could). -/

/-- A run releases the committed value. -/
example : runValue true true 7#u64 7#u64 = Outcome.released 7#u64 := by decide
/-- The SAME token denies under a substituted (attacker-varied) recorded value. -/
example : runValue true true 7#u64 9#u64 = Outcome.denied := by decide
/-- Separating witness: the two runs differ only in attacker input, and their
    outcomes differ (release vs deny) — attacker input DOES move liveness… -/
example : runValue true true 7#u64 7#u64 ≠ runValue true true 7#u64 9#u64 := by decide
/-- …but a run that lowers the presence flag also denies — release requires the
    monitor-recorded value to be present and equal, not attacker assertion. -/
example : runValue true false 7#u64 7#u64 = Outcome.denied := by decide


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
open DeclassifySinkScopeExtracted in
#print axioms value_authorized_total
open DeclassifySinkScopeExtracted in
#print axioms unbound_token_never_authorizes
open DeclassifySinkScopeExtracted in
#print axioms missing_hash_never_authorizes
open DeclassifySinkScopeExtracted in
#print axioms substituted_value_refused
open DeclassifySinkScopeExtracted in
#print axioms committed_value_authorized
open DeclassifySinkScopeExtracted in
#print axioms releases_eq_value_authorized
open DeclassifySinkScopeExtracted in
#print axioms released_value_is_the_commitment
open DeclassifySinkScopeExtracted in
#print axioms four_run_value_non_steering
open DeclassifySinkScopeExtracted in
#print axioms content_mismatch_denies
open DeclassifySinkScopeExtracted in
#print axioms attacker_cannot_steer_the_value
open DeclassifySinkScopeExtracted in
#print axioms four_run_value_robustness
