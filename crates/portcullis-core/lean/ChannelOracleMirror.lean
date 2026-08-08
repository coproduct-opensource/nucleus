/-
  The CHANNEL-ADMISSION oracle, mirrored in plain Lean — Machine v3, gate 2.

  # What this adds to the machine

  v3-1 widened the machine's LABEL (a second, dual axis). This widens the
  DECISION: delivery stops being a one-argument table lookup on the material and
  becomes a three-argument judgement over `(channel, material, principal)`. The
  shipped oracle:

      Env                   -> ident_may_deliver m p        (the one channel carrying values)
      Argv, Cwd, Cmdline    -> is_public m ∧ ident_may_deliver m p   (strictly narrower)
      Stdio, ExtraFd, Uid   -> false                     (material-CLOSED, always)

  Three of the seven channels carry nothing at all, by construction rather than by
  policy — `ExtraFd` because `close_range` shuts every inherited descriptor before
  exec, `Uid` because a uid is not a value. That is a different shape from the
  tables mirrored so far: a whole dimension proved empty, not merely restricted.

  `Cmdline` (the guest kernel command line, `/proc/cmdline`) is world-readable, so
  whatever the node writes there reaches the workload; it is modelled like Argv —
  Public-only — because the node now writes only per-node public config there.

  As with the confidentiality and integrity mirrors, these are plain Lean (no
  Aeneas monad, no Mathlib) so they port to the iris substrate, each carries a
  faithfulness theorem against the shipped extraction, and the copies living in
  `capability-primitive/iris` are checked separately by that repo's Gate 4c.
-/

import PortcullisCoreChannel.Types
import PortcullisCoreChannel.Funs

open Aeneas Aeneas.Std Result

namespace ChannelOracleMirror

open nucleus_ifc_kernel

abbrev Chan := extracted.channel.ChannelKind
abbrev Material := extracted.identity.MaterialKind
abbrev Principal := extracted.identity.Principal

/-- Plain-Lean mirror of `is_public` — the material's label is the bottom. -/
def mirrorIsPublic (m : Material) : Bool :=
  match m with
  | .TrustBundle | .EgressEnv | .OrdinaryData => true
  | _ => false

/-- **Faithfulness of the public predicate.** -/
theorem is_public_faithful (m : Material) :
    ok (mirrorIsPublic m) = extracted.channel.is_public m := by
  cases m <;> rfl

/-- Plain-Lean mirror of the v1/v2 delivery decision, restated here so this file
    stands alone (it agrees with `ConfidentialityOracleMirror.mirrorMayDeliver`
    by construction — both are the extracted `ident_may_deliver`). -/
def mirrorMayDeliver (m : Material) (p : Principal) : Bool :=
  match p with
  | .Host | .GuestRuntime => true
  | .Workload =>
    match m with
    | .TrustBundle | .ProxyAuthSecret | .EgressEnv | .OrdinaryData => true
    | _ => false

/-- Plain-Lean mirror of `channel_admits`. -/
def mirrorChannelAdmits (c : Chan) (m : Material) (p : Principal) : Bool :=
  match c with
  | .Env => mirrorMayDeliver m p
  | .Argv | .Cwd | .Cmdline => mirrorIsPublic m && mirrorMayDeliver m p
  | .Stdio | .ExtraFd | .Uid => false

/-- **Faithfulness of channel admission**, over the full 7 × 11 × 3 product —
    231 cases, all checked by the kernel. -/
theorem channel_admits_faithful (c : Chan) (m : Material) (p : Principal) :
    ok (mirrorChannelAdmits c m p) = extracted.channel.channel_admits c m p := by
  cases c <;> cases m <;> cases p <;> rfl

/-! ## The two structural facts the v3 machine needs -/

/-- **No channel delivers Secret material to the workload.** The machine-level
    analogue of `ChannelAdmissionExtracted.no_channel_delivers_secret_to_the_workload`,
    stated over the portable mirror so the pod machine can carry it across the
    toolchain boundary. Quantified over the channel enum, so a NEW channel forces
    a match arm and cannot silently carry a secret. -/
theorem no_channel_delivers_secret (c : Chan) (m : Material)
    (hsec : mirrorIsPublic m = false) (hnodeliver : mirrorMayDeliver m .Workload = false) :
    mirrorChannelAdmits c m .Workload = false := by
  cases c <;> simp [mirrorChannelAdmits, hsec, hnodeliver]

/-- **Three channels are material-CLOSED** — they admit nothing, for any material
    and any principal. Not "restricted": empty. `ExtraFd` is closed because
    `close_range` shuts every inherited descriptor before exec; `Uid` because a
    uid is not a value; `Stdio` because the dispositions are null/pipe. -/
theorem fd_stdio_uid_carry_nothing (m : Material) (p : Principal) :
    mirrorChannelAdmits .Stdio m p = false
  ∧ mirrorChannelAdmits .ExtraFd m p = false
  ∧ mirrorChannelAdmits .Uid m p = false := by
  refine ⟨rfl, rfl, rfl⟩

/-- **Argv/Cwd are STRICTLY narrower than Env** — anti-vacuity for the channel
    dimension. If every channel admitted the same set, indexing the decision by
    channel would be decoration. `ProxyAuthSecret` is the witness: the workload's
    own credential crosses in the environment (it must — the workload
    authenticates with it) and is refused on the command line, where it would be
    world-readable in the process table. -/
theorem argv_is_strictly_narrower_than_env :
    mirrorChannelAdmits .Env .ProxyAuthSecret .Workload = true
  ∧ mirrorChannelAdmits .Argv .ProxyAuthSecret .Workload = false := by
  constructor <;> rfl

end ChannelOracleMirror
