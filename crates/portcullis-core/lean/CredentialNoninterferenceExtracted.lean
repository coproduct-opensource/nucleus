/-
  FM-1 — a credential never reaches the guest, proven OVER the Aeneas-EXTRACTED
  delivery relation.

  Chain, the same one the egress and mediation theorems use:

      crates/nucleus-ifc-kernel/src/extracted/credential.rs          (real Rust)
        --charon (scoped, --start-from)-->  nucleus_ifc_kernel.llbc
        --aeneas -backend lean -split-files-->
          generated-credential/PortcullisCoreCredential/{Types,Funs}.lean
        --(this file)-->  the theorems, over THOSE generated defs.

  Aeneas reported 0 opaque functions for this slice, and pulled in
  `cflows_to`/`crank` as callees — so the credential property is a COROLLARY of
  the confidentiality axis rather than a parallel model that could drift from it.

  # Why this is the flagship property

  The CB4A broker exists so that a credential never enters the guest. Stated as
  information flow that is ordinary noninterference: what the guest observes
  must not depend on the credential. `nucleus-cred-broker` closes the practical
  routes — no `Serialize`, redacted `Debug`, zeroize on drop — but those are
  properties of one type. This says something about the *relation*: there is no
  label a credential could carry under which delivery to the guest is permitted.

  # The modelling decision, stated so it can be disagreed with

  `sink_ceiling Guest = Public`. That is load-bearing. The guest runs the agent
  the sandbox exists to contain; its `/proc/cmdline` is readable by every
  process in it, and an in-guest peer can reach a vsock listener in its own VM
  (measured, in the Phase 1 work). Anything delivered there is observable by
  untrusted code, so the guest's ceiling is the bottom of the lattice. Assuming
  anything higher would prove a weaker statement while looking identical.

  # What is NOT claimed

  This is about *where a value may be delivered*, not about timing, size, or
  error-message channels. A broker that refuses correctly can still leak through
  how long it takes to refuse. Confinement of that kind is a capacity question
  and is not addressed here.

  Nor does it say the implementation consults this relation — that is the same
  gap `mediated` exists to close for effects, and the credential path has no
  equivalent lint yet.
-/

import PortcullisCoreCredential.Types
import PortcullisCoreCredential.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

namespace CredentialNoninterference

open nucleus_ifc_kernel

abbrev Conf := extracted.ifc_confidentiality.ConfLevel
abbrev Sink := extracted.credential.CredSink

/-! ## Totality

The generated defs live in Aeneas's `Result` monad. Every theorem below is
stated against a concrete `ok` value, so each would be vacuously true if the
function could `fail`. -/

theorem crank_never_fails (l : Conf) :
    ∃ r : Std.U8, extracted.ifc_confidentiality.crank l = ok r := by
  cases l <;> exact ⟨_, rfl⟩

theorem cflows_to_never_fails (a c : Conf) :
    ∃ b : Bool, extracted.ifc_confidentiality.cflows_to a c = ok b := by
  unfold extracted.ifc_confidentiality.cflows_to
  cases a <;> cases c <;> exact ⟨_, rfl⟩

theorem sink_ceiling_never_fails (s : Sink) :
    ∃ c : Conf, extracted.credential.sink_ceiling s = ok c := by
  cases s <;> exact ⟨_, rfl⟩

theorem cred_may_deliver_never_fails (l : Conf) (s : Sink) :
    ∃ b : Bool, extracted.credential.cred_may_deliver l s = ok b := by
  unfold extracted.credential.cred_may_deliver
  cases s <;> cases l <;> exact ⟨_, rfl⟩

/-! ## The property -/

/-- **FM-1.** A credential — `Secret` by definition — is never deliverable to
    the guest.

    Not "is not delivered by the current code": there is no execution of the
    extracted relation in which it is permitted. -/
theorem a_credential_never_reaches_the_guest :
    extracted.credential.credential_may_reach extracted.credential.CredSink.Guest = ok false := by
  rfl

/-- Non-vacuity. The broker is not merely refusing everything — a credential
    still reaches the service it was issued for. Without this, the theorem above
    is satisfied by a broker that never works. -/
theorem a_credential_still_reaches_its_service :
    extracted.credential.credential_may_reach
      extracted.credential.CredSink.ExternalService = ok true := by
  rfl

/-- The guest receives PUBLIC data and nothing else — `Internal` is refused too.
    Its ceiling is the bottom of the lattice, not merely "below secret". -/
theorem the_guest_receives_only_public :
    extracted.credential.cred_may_deliver
        extracted.ifc_confidentiality.ConfLevel.Public
        extracted.credential.CredSink.Guest = ok true
    ∧ extracted.credential.cred_may_deliver
        extracted.ifc_confidentiality.ConfLevel.Internal
        extracted.credential.CredSink.Guest = ok false
    ∧ extracted.credential.cred_may_deliver
        extracted.ifc_confidentiality.ConfLevel.Secret
        extracted.credential.CredSink.Guest = ok false :=
  ⟨rfl, rfl, rfl⟩

/-- **Noninterference, in the low-observer form.**

    Two values whose labels differ are indistinguishable to the guest unless one
    of them is public. So nothing about a value's label beyond *whether it is
    public* is observable there — in particular, `Internal` and `Secret` are
    indistinguishable, which is what makes the guest unable to learn that a
    credential exists at all. -/
theorem the_guest_cannot_distinguish_internal_from_secret :
    extracted.credential.cred_may_deliver
        extracted.ifc_confidentiality.ConfLevel.Internal
        extracted.credential.CredSink.Guest
      = extracted.credential.cred_may_deliver
          extracted.ifc_confidentiality.ConfLevel.Secret
          extracted.credential.CredSink.Guest :=
  rfl

/-- Delivery is exactly `cflows_to` against the sink's ceiling — the credential
    relation is a corollary of the confidentiality axis, not a second model of
    it. If these ever diverge, this is what fails. -/
theorem delivery_is_flows_to_against_the_ceiling (l : Conf) (s : Sink) :
    extracted.credential.cred_may_deliver l s
      = (do
          let c ← extracted.credential.sink_ceiling s
          extracted.ifc_confidentiality.cflows_to l c) := by
  cases s <;> cases l <;> rfl

/-! ## Axiom audit

Every theorem must rest on Lean's three standard axioms and nothing else.

`native_decide` was written first for the two closed ground facts and then
REMOVED: it adds `Lean.ofReduceBool`, a kernel-external evaluation, and putting
that under the flagship credential theorem would undermine the exact claim the
file exists to make. Both reduce by `rfl` — the convenience was not needed, only
reached for. -/

#print axioms a_credential_never_reaches_the_guest
#print axioms a_credential_still_reaches_its_service
#print axioms the_guest_receives_only_public
#print axioms the_guest_cannot_distinguish_internal_from_secret
#print axioms delivery_is_flows_to_against_the_ceiling
#print axioms cred_may_deliver_never_fails
#print axioms cflows_to_never_fails

end CredentialNoninterference
