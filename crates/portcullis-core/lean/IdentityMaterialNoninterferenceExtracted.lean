/-
  FM-5 — the agent workload never sees identity material, proven OVER the
  Aeneas-EXTRACTED delivery relation.

  Chain, the same one the egress, credential and mediation theorems use:

      crates/nucleus-ifc-kernel/src/extracted/identity.rs             (real Rust)
        --charon (scoped, --start-from)-->  nucleus_ifc_kernel.llbc
        --aeneas -backend lean -split-files-->
          generated-identity/PortcullisCoreIdentity/{Types,Funs}.lean
        --(this file)-->  the theorems, over THOSE generated defs.

  Aeneas pulled in `cflows_to`/`crank` as callees — so the workload-boundary
  property is a COROLLARY of the confidentiality axis rather than a parallel
  model that could drift from it.

  # Why this is a posture, not a code comment

  The tool-proxy spawns the workload with `env_clear()` and an explicit overlay
  precisely so that identity material — the SVID and its key, the task token,
  the broker capability, the approval and sandbox secrets, the DLC credentials —
  never reaches the process the sandbox exists to contain. This file states that
  boundary as noninterference: what the workload observes must not depend on
  which identity material exists. The binding tests in
  `nucleus-tool-proxy/src/workload.rs` pin the model to `workload_env`
  pointwise; the theorems here are about the relation itself.

  # The modelling decisions, stated so they can be disagreed with

  `principal_ceiling Workload = Internal`, not `Public`: the workload
  legitimately receives exactly one secret-shaped value — its own proxy HMAC,
  the credential for reaching the one policed interface. Possession buys a
  mediated conversation, not impersonation of the pod, and that is what the
  lattice's middle level means. With the auth secret at `Internal`, the
  delivery relation is EXACTLY `cflows_to` against the ceiling — no exception
  table — and the anti-drift theorem below holds by `rfl`.

  Two different "guests": FM-1's `CredSink.Guest` (ceiling `Public`) is the VM
  as a host-side credential sink. FM-5's `GuestRuntime` (ceiling `Secret`) is
  the trusted runtime INSIDE the VM, which holds the pod's identity by design;
  `Workload` is the agent process it spawns. Different boundaries — the
  ceilings do not contradict.

  `mat_label SvidCert = Secret`: within this boundary the certificate names the
  pod's SPIFFE identity and flows only to the guest runtime. A future
  workload-mTLS design must relabel it deliberately, and this file turning red
  is how that decision is forced into the open.

  # What is NOT claimed

  The filesystem channel (`/etc/nucleus/identity/*`, mode-0600 uid-0 — covered
  by uid distinctness and `reject_credential_readable_workload`), the
  `/proc/cmdline` channel (covered by `snapshot_safety` and the cmdline
  classification gate), `/proc/<pid>/environ` (the uid boundary again), and
  timing/size/error channels are all outside this relation. `Host` and
  `GuestRuntime` share ceiling `Secret`, so host-only material is not separated
  from guest-deliverable material — that is the host↔guest boundary, FM-1's
  territory. Nor does anything here say the spawn path CONSULTS this relation —
  the binding tests pin pointwise agreement, and a reachability lint for
  identity material is future work, the same gap FM-1 discloses for
  credentials.
-/

import PortcullisCoreIdentity.Types
import PortcullisCoreIdentity.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

namespace IdentityMaterialNoninterference

open nucleus_ifc_kernel

abbrev Conf := extracted.ifc_confidentiality.ConfLevel
abbrev Material := extracted.identity.MaterialKind
abbrev Principal := extracted.identity.Principal

/-! ## Totality

The generated defs live in Aeneas's `Result` monad. Every theorem below is
stated against a concrete `ok` value, so each would be vacuously true if the
function could `fail`. -/

theorem mat_label_never_fails (m : Material) :
    ∃ c : Conf, extracted.identity.mat_label m = ok c := by
  cases m <;> exact ⟨_, rfl⟩

theorem principal_ceiling_never_fails (p : Principal) :
    ∃ c : Conf, extracted.identity.principal_ceiling p = ok c := by
  cases p <;> exact ⟨_, rfl⟩

theorem ident_may_deliver_never_fails (m : Material) (p : Principal) :
    ∃ b : Bool, extracted.identity.ident_may_deliver m p = ok b := by
  unfold extracted.identity.ident_may_deliver
  cases m <;> cases p <;> exact ⟨_, rfl⟩

theorem identity_reaches_workload_never_fails (m : Material) :
    ∃ b : Bool, extracted.identity.identity_reaches_workload m = ok b := by
  unfold extracted.identity.identity_reaches_workload
  cases m <;> exact ⟨_, rfl⟩

/-! ## The property -/

/-- **FM-5, quantified.** Any material labelled `Secret` is undeliverable to
    the workload.

    Not "is not delivered by the current spawn code": there is no execution of
    the extracted relation in which delivery is permitted. -/
theorem identity_material_never_reaches_the_workload (m : Material)
    (h : extracted.identity.mat_label m = ok extracted.ifc_confidentiality.ConfLevel.Secret) :
    extracted.identity.identity_reaches_workload m = ok false := by
  cases m <;> simp_all [extracted.identity.mat_label] <;> rfl

/-- **FM-5, as ground facts.** Each of the seven identity materials, refused by
    name.

    Deliberately redundant with the quantified form: if a material is ever
    mislabelled BELOW `Secret`, the quantified theorem goes silently vacuous
    for it — its hypothesis is false — while this conjunction turns red. The
    perturbation protocol flips `BrokerSecret` to `Public` to prove exactly
    that. -/
theorem no_secret_material_is_workload_deliverable :
    extracted.identity.identity_reaches_workload extracted.identity.MaterialKind.SvidCert = ok false
    ∧ extracted.identity.identity_reaches_workload extracted.identity.MaterialKind.SvidPrivateKey = ok false
    ∧ extracted.identity.identity_reaches_workload extracted.identity.MaterialKind.TaskToken = ok false
    ∧ extracted.identity.identity_reaches_workload extracted.identity.MaterialKind.BrokerSecret = ok false
    ∧ extracted.identity.identity_reaches_workload extracted.identity.MaterialKind.ApprovalSecret = ok false
    ∧ extracted.identity.identity_reaches_workload extracted.identity.MaterialKind.SandboxToken = ok false
    ∧ extracted.identity.identity_reaches_workload extracted.identity.MaterialKind.DlcCredentials = ok false :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- Non-vacuity. The boundary is not merely refusing everything — the workload
    still receives its own proxy HMAC, which is how it authenticates to the one
    policed interface at all. Without this, the theorems above are satisfied by
    a spawn path that hands the workload nothing. -/
theorem the_workload_still_authenticates :
    extracted.identity.identity_reaches_workload extracted.identity.MaterialKind.ProxyAuthSecret = ok true := by
  rfl

/-- Non-vacuity for the principal split: the guest runtime is NOT the workload —
    it receives the SVID private key by design. This is what makes the model a
    three-principal statement rather than a relabelled FM-1. -/
theorem the_guest_runtime_still_gets_its_svid :
    extracted.identity.ident_may_deliver extracted.identity.MaterialKind.SvidPrivateKey
      extracted.identity.Principal.GuestRuntime = ok true := by
  rfl

/-- CA verification material flows to every principal — the one material that
    is universally deliverable, pinning that `Public` really is the bottom. -/
theorem the_trust_bundle_reaches_everyone (p : Principal) :
    extracted.identity.ident_may_deliver extracted.identity.MaterialKind.TrustBundle p = ok true := by
  cases p <;> rfl

/-- The workload's ceiling is `Internal`, pinned per level: `Public` and
    `Internal` are deliverable, `Secret` is not. The ceiling sits strictly
    between the lattice's bottom and top — which is the modelling decision the
    header defends. -/
theorem the_workload_receives_at_most_internal :
    extracted.identity.principal_ceiling extracted.identity.Principal.Workload = ok extracted.ifc_confidentiality.ConfLevel.Internal
    ∧ extracted.identity.ident_may_deliver extracted.identity.MaterialKind.OrdinaryData
        extracted.identity.Principal.Workload = ok true
    ∧ extracted.identity.ident_may_deliver extracted.identity.MaterialKind.ProxyAuthSecret
        extracted.identity.Principal.Workload = ok true
    ∧ extracted.identity.ident_may_deliver extracted.identity.MaterialKind.SvidPrivateKey
        extracted.identity.Principal.Workload = ok false :=
  ⟨rfl, rfl, rfl, rfl⟩

/-- **Noninterference, in the low-observer form.**

    Any two Secret-labelled materials are indistinguishable to the workload:
    its view of the delivery relation is constant across all of them. So the
    workload cannot learn WHICH identity material exists — not the key from the
    token, not the token from the broker capability — because the relation
    projects them all to the same refusal. -/
theorem the_workload_cannot_distinguish_which_secrets_exist
    (m₁ m₂ : Material)
    (h₁ : extracted.identity.mat_label m₁ = ok extracted.ifc_confidentiality.ConfLevel.Secret)
    (h₂ : extracted.identity.mat_label m₂ = ok extracted.ifc_confidentiality.ConfLevel.Secret) :
    extracted.identity.identity_reaches_workload m₁
      = extracted.identity.identity_reaches_workload m₂ := by
  cases m₁ <;> cases m₂ <;> simp_all [extracted.identity.mat_label] <;> rfl

/-- Delivery is exactly `cflows_to` against the principal's ceiling — the
    identity relation is a corollary of the confidentiality axis, not a second
    model of it. No exception table exists, including for the one secret the
    workload does receive. If these ever diverge, this is what fails. -/
theorem delivery_is_flows_to_against_the_ceiling (m : Material) (p : Principal) :
    extracted.identity.ident_may_deliver m p
      = (do
          let l ← extracted.identity.mat_label m
          let c ← extracted.identity.principal_ceiling p
          extracted.ifc_confidentiality.cflows_to l c) := by
  cases m <;> cases p <;> rfl

/-! ## Axiom audit

Every theorem must rest on Lean's three standard axioms and nothing else.
No `native_decide` — the FM-1 file records why: it adds `Lean.ofReduceBool`,
kernel-external evaluation, under the exact claim the file exists to make.
Everything here reduces by `rfl` or finite case split. -/

#print axioms identity_material_never_reaches_the_workload
#print axioms no_secret_material_is_workload_deliverable
#print axioms the_workload_still_authenticates
#print axioms the_guest_runtime_still_gets_its_svid
#print axioms the_trust_bundle_reaches_everyone
#print axioms the_workload_receives_at_most_internal
#print axioms the_workload_cannot_distinguish_which_secrets_exist
#print axioms delivery_is_flows_to_against_the_ceiling
#print axioms ident_may_deliver_never_fails
#print axioms mat_label_never_fails

end IdentityMaterialNoninterference
