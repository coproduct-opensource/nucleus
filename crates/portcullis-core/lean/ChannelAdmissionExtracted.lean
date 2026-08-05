/-
  FM-5 phase 2 — no channel delivers identity material to the workload, proven
  OVER the Aeneas-EXTRACTED channel-admission relation.

  Chain, the same one FM-5 and the egress/mediation theorems use:

      crates/nucleus-ifc-kernel/src/extracted/channel.rs               (real Rust)
        --charon (scoped, --start-from)-->  nucleus_ifc_kernel.llbc
        --aeneas -backend lean -split-files-->
          generated-channel/PortcullisCoreChannel/{Types,Funs}.lean
        --(this file)-->  the theorems, over THOSE generated defs.

  Aeneas pulled in `ident_may_deliver`/`mat_label` as callees, so the channel
  relation is a COROLLARY of FM-5 rather than a parallel model that could drift.

  # Why this is the completeness lift

  FM-5 (`IdentityMaterialNoninterferenceExtracted.lean`) proves the
  material×principal decision. What it left tested/structural is the CHANNEL
  ENUMERATION: nothing proved the set of channels closed, so "a new inherited fd
  or socket bypasses the model by never entering the taxonomy" was an argument,
  not a theorem. Here `ChannelKind` enumerates the dimensions the workload child
  inherits and `channel_admits` decides each; the flagship quantifies over ALL
  channels, so a new channel forces an exhaustive match arm and cannot carry
  secret material without failing this file. FM-5's material-dimension guarantee,
  lifted to the channel dimension.

  # The modelling decisions, stated so they can be disagreed with

  `Env` is the only material-carrying channel and its admission IS
  `ident_may_deliver` (anti-drift theorem below). `Argv`/`Cwd` carry public
  operator data only — a future secret-carrying argv would relabel here and turn
  it red first. `Stdio`/`ExtraFd`/`Uid` are material-closed: `ExtraFd = false` is
  the `close_range` structural closure the launch builder installs, stated as a
  theorem.

  # What is NOT claimed

  Mounts are the VM's job (jailer + read-only root + tmpfs), fenced as in FM-5.
  Covert channels are capacity questions, out of scope. And this proves the
  relation over channels, not that the spawn code consults it — the typed
  builder and the reachability lint carry that structurally; the in-guest probe
  of the real child is the named empirical follow-on.
-/

import PortcullisCoreChannel.Types
import PortcullisCoreChannel.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

namespace ChannelAdmission

open nucleus_ifc_kernel

abbrev Conf := extracted.ifc_confidentiality.ConfLevel
abbrev Material := extracted.identity.MaterialKind
abbrev Principal := extracted.identity.Principal
abbrev Channel := extracted.channel.ChannelKind

/-! ## Totality

The generated defs live in Aeneas's `Result` monad. Every theorem below is
stated against a concrete `ok` value, so each would be vacuously true if the
function could `fail`. -/

theorem chanrank_never_fails (c : Channel) :
    ∃ r : Std.U8, extracted.channel.chanrank c = ok r := by
  cases c <;> exact ⟨_, rfl⟩

theorem is_public_never_fails (m : Material) :
    ∃ b : Bool, extracted.channel.is_public m = ok b := by
  unfold extracted.channel.is_public
  cases m <;> exact ⟨_, rfl⟩

theorem channel_admits_never_fails (c : Channel) (m : Material) (p : Principal) :
    ∃ b : Bool, extracted.channel.channel_admits c m p = ok b := by
  unfold extracted.channel.channel_admits
  cases c <;> cases m <;> cases p <;> exact ⟨_, rfl⟩

theorem channel_reaches_workload_never_fails (c : Channel) (m : Material) :
    ∃ b : Bool, extracted.channel.channel_reaches_workload c m = ok b := by
  unfold extracted.channel.channel_reaches_workload
  cases c <;> cases m <;> exact ⟨_, rfl⟩

/-! ## The property -/

/-- **FM-5 phase 2, quantified.** No channel delivers any material labelled
    `Secret` to the workload.

    The completeness lift: this covers ALL channels by quantification, not just
    the env delivery relation FM-5 states. -/
theorem no_channel_delivers_secret_to_the_workload (c : Channel) (m : Material)
    (h : extracted.identity.mat_label m = ok extracted.ifc_confidentiality.ConfLevel.Secret) :
    extracted.channel.channel_reaches_workload c m = ok false := by
  cases c <;> cases m <;>
    simp_all [extracted.channel.channel_reaches_workload, extracted.channel.channel_admits,
              extracted.channel.is_public, extracted.identity.mat_label] <;> rfl

/-- **As ground facts.** The (channel, secret-material) grid, refused by name.

    Deliberately redundant with the quantified form: if a material is ever
    mislabelled BELOW `Secret`, the quantified theorem goes silently vacuous for
    it — its hypothesis is false — while this conjunction turns red. Stated over
    the env channel (the strongest one — it is the only material-carrying
    channel, so if it refuses every secret the material-closed channels do a
    fortiori). -/
theorem the_env_channel_refuses_every_secret :
    extracted.channel.channel_reaches_workload extracted.channel.ChannelKind.Env extracted.identity.MaterialKind.SvidCert = ok false
    ∧ extracted.channel.channel_reaches_workload extracted.channel.ChannelKind.Env extracted.identity.MaterialKind.SvidPrivateKey = ok false
    ∧ extracted.channel.channel_reaches_workload extracted.channel.ChannelKind.Env extracted.identity.MaterialKind.TaskToken = ok false
    ∧ extracted.channel.channel_reaches_workload extracted.channel.ChannelKind.Env extracted.identity.MaterialKind.BrokerSecret = ok false
    ∧ extracted.channel.channel_reaches_workload extracted.channel.ChannelKind.Env extracted.identity.MaterialKind.ApprovalSecret = ok false
    ∧ extracted.channel.channel_reaches_workload extracted.channel.ChannelKind.Env extracted.identity.MaterialKind.SandboxToken = ok false
    ∧ extracted.channel.channel_reaches_workload extracted.channel.ChannelKind.Env extracted.identity.MaterialKind.DlcCredentials = ok false :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- **The `close_range` structural closure, as a theorem.** No material crosses
    an inherited fd, to any principal — the launch builder shuts every fd above
    the child's own stdio before exec. -/
theorem no_fd_carries_anything (m : Material) (p : Principal) :
    extracted.channel.channel_admits extracted.channel.ChannelKind.ExtraFd m p = ok false := by
  rfl

/-- stdio and uid carry no material either — a disposition and a number, not
    `MaterialKind` values. -/
theorem stdio_and_uid_carry_no_material (m : Material) (p : Principal) :
    extracted.channel.channel_admits extracted.channel.ChannelKind.Stdio m p = ok false
    ∧ extracted.channel.channel_admits extracted.channel.ChannelKind.Uid m p = ok false :=
  ⟨rfl, rfl⟩

/-- Non-vacuity. The carrying channels still carry: the env channel delivers the
    workload's own proxy HMAC, and argv carries public data. Without this the
    theorems above are satisfied by a taxonomy that admits nothing anywhere. -/
theorem the_carrying_channels_still_carry :
    extracted.channel.channel_reaches_workload extracted.channel.ChannelKind.Env extracted.identity.MaterialKind.ProxyAuthSecret = ok true
    ∧ extracted.channel.channel_reaches_workload extracted.channel.ChannelKind.Argv extracted.identity.MaterialKind.OrdinaryData = ok true := by
  refine ⟨?_, ?_⟩ <;> rfl

/-- **Anti-drift.** The env channel is EXACTLY the FM-5 relation — the taxonomy
    is a corollary of `ident_may_deliver`, not a second model of it. If these
    ever diverge, this is what fails. -/
theorem env_admission_is_exactly_the_identity_relation (m : Material) (p : Principal) :
    extracted.channel.channel_admits extracted.channel.ChannelKind.Env m p
      = extracted.identity.ident_may_deliver m p := by
  rfl

/-- Delivery is bounded by, and for the material-closed channels independent of,
    the material — the whole relation pinned per channel. -/
theorem admission_is_pinned_per_channel (m : Material) (p : Principal) :
    extracted.channel.channel_admits extracted.channel.ChannelKind.Env m p
        = extracted.identity.ident_may_deliver m p
    ∧ extracted.channel.channel_admits extracted.channel.ChannelKind.ExtraFd m p = ok false
    ∧ extracted.channel.channel_admits extracted.channel.ChannelKind.Stdio m p = ok false
    ∧ extracted.channel.channel_admits extracted.channel.ChannelKind.Uid m p = ok false :=
  ⟨rfl, rfl, rfl, rfl⟩

/-! ## Axiom audit

Every theorem must rest on Lean's three standard axioms and nothing else. No
`native_decide` — the FM-5 files record why. Everything here reduces by `rfl`
or finite case split. -/

#print axioms no_channel_delivers_secret_to_the_workload
#print axioms the_env_channel_refuses_every_secret
#print axioms no_fd_carries_anything
#print axioms stdio_and_uid_carry_no_material
#print axioms the_carrying_channels_still_carry
#print axioms env_admission_is_exactly_the_identity_relation
#print axioms admission_is_pinned_per_channel
#print axioms channel_admits_never_fails
#print axioms is_public_never_fails

end ChannelAdmission
