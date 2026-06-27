/-
  Confidentiality Noninterference — proven OVER the Aeneas-EXTRACTED enforcement
  core (D1 milestone C1; order-DUAL of IntegrityNoninterferenceExtracted).

  **STATUS: VERIFIED.** The `aeneas-ifc-scoped` CI job extracts the
  confidentiality functions (`EXTRACT_ROOTS` includes
  `ifc_confidentiality::{cflows_to, cjoin, crun_step}`) and builds this file
  (`lake build ConfidentialityNoninterferenceExtracted`, run 28269268454). The
  `#print axioms` audit printed `[propext, Classical.choice, Quot.sound]` — no
  `sorryAx`, no Aeneas `*External` opaque axiom; the clean-axiom gate passed. This
  is the order-dual of the VERIFIED integrity theorem (CI run 26847262070) and
  discharges by the same tactics over the Aeneas-generated defs.

  The chain (dual of integrity):

      crates/nucleus-ifc-kernel/src/extracted/ifc_confidentiality.rs   (real Rust)
        --charon (scoped, --start-from)-->  nucleus_ifc_kernel.llbc
        --aeneas -backend lean -split-files-->
          generated-ifc/PortcullisCoreIFC/{Types,Funs}.lean   (THIS file's deps)
        --(this file)-->  confidentiality noninterference over THOSE generated defs.

  # The duality (why this is NOT a copy of the integrity proof)

  Integrity is CONTRAVARIANT: `imeet` = MIN, taint pulls trust DOWN, the fold is
  ANTITONE, and `iflows_to a c = (rank c ≤ rank a)`. Confidentiality is COVARIANT
  (BLP "no read up → no write down"): `cjoin` = MAX, combining RAISES
  confidentiality, the fold is MONOTONE, and `cflows_to a c = (rank a ≤ rank c)`.
  The main theorem is correspondingly dual: a source MORE confidential than a
  sink's ceiling can never be laundered to that sink, over any op sequence.

  # Ground truth + scope boundary

  The generated defs mirror production by the EXHAUSTIVE parity tests in
  `src/extracted/ifc_confidentiality.rs` (`cjoin`/`cflows_to`/`crank` == the
  confidentiality axis of the real `IFCLabel::join`/`flows_to`). `IFCLabel::flows_to`
  is a six-axis conjunction; this theorem is the CONFIDENTIALITY conjunct only —
  "confidentiality alone blocks ⇒ admission denied" is sound because one false
  conjunct makes the whole `flows_to` false. The fold `crun` is hand-written Lean
  over the GENERATED step (Aeneas does not extract the runtime's slice loop).
-/

import PortcullisCoreIFC.Types
import PortcullisCoreIFC.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

set_option maxHeartbeats 1000000

namespace ConfidentialityNoninterferenceExtracted

/-- Short alias for the Aeneas-generated confidentiality enum (from real Rust). -/
abbrev CL := nucleus_ifc_kernel.extracted.ifc_confidentiality.ConfLevel

theorem crank_pub :
    nucleus_ifc_kernel.extracted.ifc_confidentiality.crank .Public = ok 0#u8 := rfl
theorem crank_int :
    nucleus_ifc_kernel.extracted.ifc_confidentiality.crank .Internal = ok 1#u8 := rfl
theorem crank_sec :
    nucleus_ifc_kernel.extracted.ifc_confidentiality.crank .Secret = ok 2#u8 := rfl

/-- Pure-Lean rank mirroring the generated `crank`'s value, to drive `omega`. -/
def rankN : CL → Nat
  | .Public => 0
  | .Internal => 1
  | .Secret => 2

/-- The generated `cjoin` always succeeds and returns the argument of GREATER-or-
    equal rank (combining RAISES confidentiality) — the MAX. Dual of `imeet_ok`. -/
theorem cjoin_ok (a b : CL) :
    nucleus_ifc_kernel.extracted.ifc_confidentiality.cjoin a b
      = ok (if rankN b ≤ rankN a then a else b) := by
  cases a <;> cases b <;> rfl

/-- **Local step monotonicity**, over the GENERATED `cjoin`. A single fold step
    can only RAISE (never lower) the running confidentiality rank. Dual of
    `istep_antitone`: the result of `cjoin a b` has rank ≥ `rankN a`. -/
theorem cstep_monotone (a b : CL) :
    ∀ r, nucleus_ifc_kernel.extracted.ifc_confidentiality.cjoin a b = ok r → rankN a ≤ rankN r := by
  intro r h
  rw [cjoin_ok] at h
  by_cases hba : rankN b ≤ rankN a
  · simp [hba] at h; subst h; omega
  · simp [hba] at h; subst h; omega

/-- Fold the GENERATED `crun_step` over an operation list, threading the running
    effective confidentiality. The fold is hand-written; each step IS the
    generated-from-Rust `crun_step` (= generated `cjoin`). -/
def crun : List CL → CL → CL
  | [], eff => eff
  | src :: rest, eff =>
      crun rest
        (match nucleus_ifc_kernel.extracted.ifc_confidentiality.crun_step eff src with
         | ok r => r
         | _ => eff)

/-- The generated `crun_step` reduces to the generated `cjoin` result. -/
theorem crun_step_ok (eff src : CL) :
    nucleus_ifc_kernel.extracted.ifc_confidentiality.crun_step eff src
      = ok (if rankN src ≤ rankN eff then eff else src) := by
  unfold nucleus_ifc_kernel.extracted.ifc_confidentiality.crun_step
  rw [cjoin_ok]

/-- One `crun` cons step raises the rank, via the GENERATED step. -/
theorem crun_cons_step_monotone (eff src : CL) :
    rankN eff ≤ rankN (match nucleus_ifc_kernel.extracted.ifc_confidentiality.crun_step eff src with
           | ok r => r | _ => eff) := by
  rw [crun_step_ok]
  show rankN eff ≤ rankN (if rankN src ≤ rankN eff then eff else src)
  split <;> omega

/-- **Global composition** over the GENERATED step. Over ANY operation sequence,
    the running effective confidentiality rank never drops below the starting
    rank — confidentiality only ratchets UP. Dual of `irun_antitone`. -/
theorem crun_monotone :
    ∀ (ops : List CL) (eff : CL), rankN eff ≤ rankN (crun ops eff) := by
  intro ops
  induction ops with
  | nil => intro eff; simp [crun]
  | cons src rest ih =>
      intro eff
      simp only [crun]
      have h_tail := ih (match nucleus_ifc_kernel.extracted.ifc_confidentiality.crun_step eff src with
                         | ok r => r | _ => eff)
      have h_step := crun_cons_step_monotone eff src
      omega

/-- Sink admission, over the GENERATED `cflows_to`: the running effective
    confidentiality flows to the sink's ceiling iff `rankN eff ≤ rankN ceiling`
    (BLP no-read-up). Dual of `iflows_to_ok`. -/
theorem cflows_to_ok (a ceiling : CL) :
    nucleus_ifc_kernel.extracted.ifc_confidentiality.cflows_to a ceiling
      = ok (decide (rankN a ≤ rankN ceiling)) := by
  cases a <;> cases ceiling <;> rfl

/-- Admission holds iff the generated `cflows_to` returns `ok true`. -/
def cadmitted (eff ceiling : CL) : Prop :=
    nucleus_ifc_kernel.extracted.ifc_confidentiality.cflows_to eff ceiling = ok true

/-- **Confidentiality-axis noninterference (main theorem), over the GENERATED
    defs.** If the session's effective confidentiality already dominates a
    joined-in source `L_src` (`rankN L_src ≤ rankN eff`), and that source is
    strictly MORE confidential than the sink's ceiling allows
    (`rankN ceiling < rankN L_src`), then over ANY operation sequence the sink is
    NEVER admitted by the GENERATED `cflows_to`. Dual of
    `integrity_sink_never_admitted`; closed by `omega` over `crun_monotone`. -/
theorem confidentiality_sink_never_admitted
    (L_src eff ceiling : CL) (ops : List CL)
    (h_joined : rankN L_src ≤ rankN eff)
    (h_blocked : rankN ceiling < rankN L_src) :
    ¬ cadmitted (crun ops eff) ceiling := by
  intro h_admit
  unfold cadmitted at h_admit
  rw [cflows_to_ok] at h_admit
  simp only [Result.ok.injEq, decide_eq_true_eq] at h_admit
  -- h_admit : rankN (crun ops eff) ≤ rankN ceiling
  have h_ratchet : rankN eff ≤ rankN (crun ops eff) := crun_monotone ops eff
  -- ceiling < L_src ≤ eff ≤ crun ≤ ceiling  ⇒  contradiction.
  omega

/-- **Instantiation: a secret-tainted session can NEVER reach a public sink**,
    over the GENERATED defs. A session whose effective confidentiality is `Secret`
    (rank 2 — the label credentials/keys carry) is never admitted at a `Public`
    ceiling (rank 0; the ceiling true-egress sinks like HTTPEgress impose), over
    ANY operation sequence. Non-vacuous: `h_joined = 2 ≤ 2`, `h_blocked = 0 < 2`. -/
theorem secret_tainted_never_flows_public (ops : List CL) :
    ¬ cadmitted (crun ops .Secret) .Public := by
  apply confidentiality_sink_never_admitted
    (L_src := .Secret)
    (eff := .Secret)
    (ceiling := .Public)
    (ops := ops)
  · decide
  · decide

end ConfidentialityNoninterferenceExtracted

/-
  Axiom audit (the aeneas-ifc-scoped `Assert clean axiom set` gate reads these).
  EXPECTED, as for the integrity dual: [propext, Quot.sound, Classical.choice].
  Anything else — `sorryAx` (a proof hole) or an Aeneas `*External` opaque axiom
  — MUST fail review. The `extracted/ifc_confidentiality.rs` uses explicit
  `crank(a) <= crank(b)` (not a derived `Ord`), so Aeneas emits a translated body
  with no opaque comparison axiom.
-/
#print axioms ConfidentialityNoninterferenceExtracted.confidentiality_sink_never_admitted
#print axioms ConfidentialityNoninterferenceExtracted.secret_tainted_never_flows_public
