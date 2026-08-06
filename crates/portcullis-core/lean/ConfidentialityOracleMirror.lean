/-
  The CONFIDENTIALITY oracles, mirrored in plain Lean — the v2 half of the
  toolchain bridge for the reference pod-execution semantics.

  # Why this file exists

  `IdentityOracleMirror` did this for ONE oracle: the machine's v1 guard
  (`identity_reaches_workload`). Machine v2 grew a floating label, and its
  mirrors — the confidentiality lattice, its rank, its join, its flows-to, the
  material label table, and the principal ceiling — were transcribed into the
  iris tree with NOTHING proving they match the shipped extraction. A single
  wrong entry in `matLabel` would have made the v2 noninterference theorem a true
  statement about the wrong system, and no gate would have noticed.

  This file closes that. Each mirror below is plain Lean (no Aeneas monad, no
  Mathlib) so it is portable to the iris v4.32 substrate, and each carries a
  faithfulness theorem against the Aeneas-extracted function that actually ships.
  `cases … <;> rfl` forces agreement: a wrong entry fails to COMPILE.

  What this does and does not buy. It anchors the mirror DEFINITIONS to the
  extraction. It does not, by itself, guarantee that the copies living in
  `capability-primitive/iris` are these definitions — that is a separate control
  (`iris/gate_mirror_parity.py` over there), because a proof here cannot see a
  file in another repository.
-/

import PortcullisCoreIdentity.Types
import PortcullisCoreIdentity.Funs

open Aeneas Aeneas.Std Result

namespace ConfidentialityOracleMirror

open nucleus_ifc_kernel

abbrev Material := extracted.identity.MaterialKind
abbrev Principal := extracted.identity.Principal
abbrev Conf := extracted.ifc_confidentiality.ConfLevel

/-! ## The lattice -/

/-- Plain-Lean mirror of the extracted `ConfLevel` rank. The discriminants ARE
    the confidentiality order (`Public 0 < Internal 1 < Secret 2`). -/
def mirrorCrank : Conf → Nat
  | .Public => 0
  | .Internal => 1
  | .Secret => 2

/- No separate faithfulness theorem for the rank, deliberately. The extracted
   `crank` returns an Aeneas `Std.U8` while a portable mirror must return `Nat`,
   so stating their equality means threading a scalar conversion that adds TCB
   without adding assurance. The rank is an internal helper, and its behaviour is
   fully pinned by the two composites below: `cjoin_faithful` and `cflows_faithful`
   are proved by exhaustive case analysis over ALL argument pairs, so a mirror
   rank that disagreed with the extracted one anywhere it matters would make one
   of them fail to compile. -/

/-- Plain-Lean mirror of the extracted confidentiality JOIN (max by rank:
    combining data raises confidentiality). -/
def mirrorCjoin (a b : Conf) : Conf :=
  if mirrorCrank a ≥ mirrorCrank b then a else b

/-- **Faithfulness of the join.** -/
theorem cjoin_faithful (a b : Conf) :
    ok (mirrorCjoin a b) = extracted.ifc_confidentiality.cjoin a b := by
  cases a <;> cases b <;> rfl

/-- Plain-Lean mirror of the extracted flows-to (BLP no-read-up). -/
def mirrorCflows (a ceiling : Conf) : Bool := mirrorCrank a ≤ mirrorCrank ceiling

/-- **Faithfulness of flows-to.** -/
theorem cflows_faithful (a ceiling : Conf) :
    ok (mirrorCflows a ceiling) = extracted.ifc_confidentiality.cflows_to a ceiling := by
  cases a <;> cases ceiling <;> rfl

/-! ## The tables -/

/-- Plain-Lean mirror of the extracted `mat_label`: identity material is Secret,
    the workload's own proxy HMAC is Internal, verification material and ordinary
    data are Public. THIS is the table a typo would have silently corrupted. -/
def mirrorMatLabel : Material → Conf
  | .SvidCert => .Secret
  | .SvidPrivateKey => .Secret
  | .TrustBundle => .Public
  | .TaskToken => .Secret
  | .BrokerSecret => .Secret
  | .ApprovalSecret => .Secret
  | .SandboxToken => .Secret
  | .DlcCredentials => .Secret
  | .ProxyAuthSecret => .Internal
  | .EgressEnv => .Public
  | .OrdinaryData => .Public

/-- **Faithfulness of the material-label table.** Every one of the eleven
    materials is checked against the shipped extraction. -/
theorem mat_label_faithful (m : Material) :
    ok (mirrorMatLabel m) = extracted.identity.mat_label m := by
  cases m <;> rfl

/-- Plain-Lean mirror of the extracted `principal_ceiling`. Host and GuestRuntime
    hold the pod's identity by design; the workload's ceiling is Internal. -/
def mirrorCeiling : Principal → Conf
  | .Host => .Secret
  | .GuestRuntime => .Secret
  | .Workload => .Internal

/-- **Faithfulness of the principal ceiling.** -/
theorem ceiling_faithful (p : Principal) :
    ok (mirrorCeiling p) = extracted.identity.principal_ceiling p := by
  cases p <;> rfl

/-! ## The delivery decision, as a composite -/

/-- Plain-Lean mirror of `ident_may_deliver` — delivery IS the flow decision
    against the principal's ceiling. -/
def mirrorMayDeliver (m : Material) (p : Principal) : Bool :=
  mirrorCflows (mirrorMatLabel m) (mirrorCeiling p)

/-- **Faithfulness of the delivery decision**, over the full 11 × 3 product. -/
theorem may_deliver_faithful (m : Material) (p : Principal) :
    ok (mirrorMayDeliver m p) = extracted.identity.ident_may_deliver m p := by
  cases m <;> cases p <;> rfl

/-- **The v1 guard is the v2 oracle at the workload's ceiling.** The pod machine's
    `reachesWorkload` and the floating-label machine's flow check are the SAME
    decision — stated here against the extraction rather than asserted in a
    docstring, which is where it lived before. -/
theorem reaches_is_a_flow_faithful (m : Material) :
    ok (mirrorMayDeliver m .Workload) = extracted.identity.identity_reaches_workload m := by
  cases m <;> rfl

end ConfidentialityOracleMirror
