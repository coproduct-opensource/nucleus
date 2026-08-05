/-
  The identity-delivery oracle, MIRRORED in plain Lean — the toolchain bridge for
  the reference pod-execution semantics (plan: graceful-puzzling-beaver.md).

  # Why this file exists

  The reference "pod machine" (an Iris `Language` in the `capability-primitive`
  research tree) must branch, at each step, on whether the runtime may deliver a
  material to the workload — i.e. it needs `identity_reaches_workload`. But that
  shipped oracle is Aeneas-EXTRACTED Lean, and Aeneas hard-depends on Mathlib and
  is pinned to Lean v4.30; the iris-lean substrate is v4.32 with no Mathlib.
  Consuming the extracted oracle directly there drags in all of Mathlib and a
  toolchain conflict.

  So the machine branches instead on `mirrorReachesWorkload` — a bare
  `MaterialKind → Bool` table with NO Aeneas and NO Mathlib, which therefore
  builds under the iris toolchain. `mirror_faithful` below is the trust anchor:
  it proves, over the shipped extracted oracle, that the mirror agrees with it on
  every material. So the refinement chain holds end to end:

      Rust  --Aeneas-->  identity_reaches_workload  --(mirror_faithful)-->
        mirrorReachesWorkload  --(portable)-->  the Iris pod machine's guard.

  The classifications are read off `mat_label` (deliverable to the Workload iff
  `mat_label m ≤ Internal`, the FM-5 ceiling): the four non-Secret materials pass,
  the seven Secret materials are refused. `cases m <;> rfl` forces the table to
  match the extracted decision — a wrong entry fails to compile.
-/

import PortcullisCoreIdentity.Types
import PortcullisCoreIdentity.Funs

open Aeneas Aeneas.Std Result

namespace IdentityOracleMirror

open nucleus_ifc_kernel

abbrev Material := extracted.identity.MaterialKind

/-- Plain-Lean mirror of `identity_reaches_workload` — no Aeneas, no Mathlib, so
    it builds under the iris-lean v4.32 toolchain where the pod machine lives.
    Faithfulness to the shipped oracle is proved by `mirror_faithful`. -/
def mirrorReachesWorkload : Material → Bool
  -- Secret (mat_label = Secret): refused.
  | .SvidCert => false | .SvidPrivateKey => false | .TaskToken => false
  | .BrokerSecret => false | .ApprovalSecret => false | .SandboxToken => false
  | .DlcCredentials => false
  -- Public/Internal (mat_label ≤ Internal): delivered.
  | .TrustBundle => true | .ProxyAuthSecret => true | .EgressEnv => true
  | .OrdinaryData => true

/-- **Faithfulness.** The plain-Lean mirror equals the shipped, Aeneas-extracted
    `identity_reaches_workload` on every material. This is what lets the reference
    pod machine (Iris, Mathlib-free) branch on `mirrorReachesWorkload` while
    remaining refinement-equal to the decision that actually ships. -/
theorem mirror_faithful (m : Material) :
    ok (mirrorReachesWorkload m) = extracted.identity.identity_reaches_workload m := by
  cases m <;> rfl

end IdentityOracleMirror
