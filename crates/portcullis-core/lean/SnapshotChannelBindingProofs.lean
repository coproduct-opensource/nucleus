import ChannelAdmissionExtracted

/-!
# Snapshot per-pod keys ↔ the extracted Cmdline noninterference proof

The snapshot clone-safety guard (`nucleus-node/src/snapshot.rs`,
`SnapshotCloneSafetyProofs.lean`) is a String-keyed denylist. Independently,
`ChannelAdmissionExtracted.the_cmdline_delivers_no_secret_to_the_workload` proves
— over Aeneas-EXTRACTED Rust — that the enum-keyed `Cmdline` channel delivers no
`Secret`-labelled IFC material to the workload. This file BINDS the two: it shows
the snapshot per-pod keys that correspond to a `Secret` IFC `MaterialKind` inherit
that machine-checked noninterference guarantee, and it makes the keys that do NOT
correspond a precise, checked boundary rather than an unstated gap.

## The mapping (all nine `PER_POD_SECRET_KEYS`, snapshot.rs:112)

| snapshot key            | MaterialKind      | mat_label | inherited? |
|-------------------------|-------------------|-----------|------------|
| approval_secret         | ApprovalSecret    | Secret    | ✅ |
| sandbox_token           | SandboxToken      | Secret    | ✅ |
| task_token_hex          | TaskToken         | Secret    | ✅ |
| task_token_issuer       | TaskToken (same)  | Secret    | ✅ |
| task_token_nonce        | TaskToken (same)  | Secret    | ✅ |
| auth_secret             | ProxyAuthSecret   | Internal  | ✗ residue (labelled Internal by design) |
| aws_access_key_id       | (no variant)      | —         | ✗ residue (no IFC material) |
| aws_secret_access_key   | (no variant)      | —         | ✗ residue |
| aws_session_token       | (no variant)      | —         | ✗ residue |

Five keys collapse onto three `Secret` materials (`ApprovalSecret`,
`SandboxToken`, `TaskToken`) — exactly the three
`the_cmdline_delivers_no_secret_to_the_workload` is stated over — so they inherit
it verbatim. The four residue keys are handled below.

## The residue is honest, not a hole
- `auth_secret` → `ProxyAuthSecret` is labelled `Internal`, NOT `Secret`
  (`auth_secret_material_is_internal`): it is per-NODE proxy config shared across a
  node's pods (snapshot.rs:61), not per-pod secret material, so it is CORRECTLY
  outside the `Secret`-refusal theorem — and the snapshot denylist still refuses it
  categorically because a snapshot base is a portable artifact.
- The three AWS audit credentials have no IFC `MaterialKind` at all — they ride
  `FETCH_AUDIT_CREDENTIALS` over the workload API, never the cmdline. Making them
  inherit the theorem would require adding an AWS-credential `MaterialKind`
  (labelled `Secret`) to the extracted model — a modelling change (re-extraction),
  tracked, not done here.

`#print axioms` audited at the end.
-/

namespace SnapshotChannelBinding

open Aeneas Aeneas.Std Result
open nucleus_ifc_kernel
open nucleus_ifc_kernel.extracted.identity (MaterialKind mat_label)
open nucleus_ifc_kernel.extracted.channel (ChannelKind channel_reaches_workload)
open nucleus_ifc_kernel.extracted.ifc_confidentiality (ConfLevel)

/-- Each mappable per-pod key's IFC `MaterialKind` is labelled `Secret`. -/
theorem mappable_materials_are_secret :
    mat_label MaterialKind.ApprovalSecret = ok ConfLevel.Secret
    ∧ mat_label MaterialKind.SandboxToken = ok ConfLevel.Secret
    ∧ mat_label MaterialKind.TaskToken = ok ConfLevel.Secret :=
  ⟨rfl, rfl, rfl⟩

/-- **Clone-safety for the mappable keys, INHERITED from the extracted proof.**
    The three IFC materials the five mappable per-pod keys collapse onto never
    reach the workload over the command line. This IS
    `ChannelAdmission.the_cmdline_delivers_no_secret_to_the_workload`, so the
    covered subset of the String-keyed snapshot guard is backed by machine-checked
    noninterference over extracted Rust — not merely by the denylist. -/
theorem mappable_keys_never_reach_workload_via_cmdline :
    channel_reaches_workload ChannelKind.Cmdline MaterialKind.TaskToken = ok false
    ∧ channel_reaches_workload ChannelKind.Cmdline MaterialKind.SandboxToken = ok false
    ∧ channel_reaches_workload ChannelKind.Cmdline MaterialKind.ApprovalSecret = ok false :=
  ChannelAdmission.the_cmdline_delivers_no_secret_to_the_workload

/-- **Residue, made a checked fact.** `auth_secret` maps to `ProxyAuthSecret`,
    labelled `Internal` — so it is (correctly) not covered by the `Secret`-refusal
    theorem: the hypothesis `mat_label = Secret` is false for it. -/
theorem auth_secret_material_is_internal :
    mat_label MaterialKind.ProxyAuthSecret = ok ConfLevel.Internal := rfl

/-- …and `Internal` is genuinely not `Secret`, so the exclusion is real, not a
    mislabel that would make the inherited theorem vacuous for it. -/
theorem internal_is_not_secret : ConfLevel.Internal ≠ ConfLevel.Secret := by
  intro h; exact ConfLevel.noConfusion h

/-- Non-vacuity: the cmdline still carries PUBLIC config to the workload — the
    guard refuses secrets without refusing everything (cites the extracted
    non-vacuity partner). -/
theorem cmdline_still_carries_public :
    channel_reaches_workload ChannelKind.Cmdline MaterialKind.TrustBundle = ok true :=
  ChannelAdmission.the_cmdline_still_carries_public_config

#print axioms mappable_keys_never_reach_workload_via_cmdline
#print axioms mappable_materials_are_secret
#print axioms auth_secret_material_is_internal
#print axioms internal_is_not_secret

end SnapshotChannelBinding
