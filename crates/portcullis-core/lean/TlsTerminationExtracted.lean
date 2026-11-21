/-
  ADR 0015 E3: the terminated-handshake decision the proxy will run IS the
  outcome `TlsTermination.lean` journals.

  `extracted.tls.tls_verdict` is Aeneas's translation of
  `crates/nucleus-ifc-kernel/src/extracted/tls.rs` (the same scoped run as the
  link slice, installed in `generated-link/`). This file proves it total, and
  that — fed what the proxy knows (a live CA, the clock, whether the name is
  permitted (`ca.permits`), whether the client accepted the leaf, whether SNI = Host) — it
  yields exactly the outcome `TlsTermination.step` records for that handshake.
  So `decided_only_if`, `untrusting_client_refused`, `fronting_refused` and
  `expired_refused` are about the shipped decision.

  Times: the model's are `Nat`, the code's `U64`; the bridge needs only that
  they denote the same instants (`hnow`, `hna`).
-/

import PortcullisCoreLink.Types
import PortcullisCoreLink.Funs
import TlsTermination

open Aeneas Aeneas.Std Result

namespace TlsTerminationExtracted

open nucleus_ifc_kernel

/-- The model's journal entry for a verdict. -/
def outcomeOf (p : TlsTermination.PodId) (sni host : TlsTermination.Name) :
    extracted.tls.TlsVerdict → TlsTermination.Outcome
  | .Decided => .decided p sni
  | .RefusedExpired => .refusedExpired p
  | .RefusedNameNotPermitted => .refusedNameNotPermitted p sni
  | .RefusedClientRejected => .refusedClientRejected p sni
  | .RefusedFronting => .refusedFronting p sni host

/-- Total: the extracted verdict never fails. -/
theorem tls_verdict_never_fails (live : Bool) (now na : Std.U64) (perm acc sm : Bool) :
    ∃ v, extracted.tls.tls_verdict live now na perm acc sm = ok v := by
  unfold extracted.tls.tls_verdict
  cases live <;> cases perm <;> cases acc <;> cases sm <;> by_cases h : now > na <;> simp [h]

theorem may_issue_leaf_spec (live : Bool) (now na : Std.U64) (perm : Bool) :
    extracted.tls.may_issue_leaf live now na perm =
      ok (live && decide (now.val ≤ na.val) && perm) := by
  unfold extracted.tls.may_issue_leaf
  cases live
  · simp
  · by_cases h : now.val ≤ na.val
    · simp [UScalar.le_equiv, h]
    · simp [UScalar.le_equiv, h]

/-- With a CA for the pod, the extracted verdict is the model's journal entry. -/
theorem tls_verdict_is_step (s : TlsTermination.State) (p : TlsTermination.PodId)
    (sni host : TlsTermination.Name) (trusts : Bool) (ca : TlsTermination.CA)
    (hca : TlsTermination.caOf s.cas p = some ca) (now na : Std.U64)
    (hnow : now.val = s.now) (hna : na.val = ca.notAfter) :
    ∃ v, extracted.tls.tls_verdict true now na (ca.permits sni) trusts
        (sni == host) = ok v ∧
      (TlsTermination.step s (.handshake p sni host trusts)).journal.head? =
        some (outcomeOf p sni host v) := by
  have hgt : (now > na) = (s.now > ca.notAfter) := by
    simp only [GT.gt, UScalar.lt_equiv, hnow, hna]
  unfold extracted.tls.tls_verdict
  simp only [TlsTermination.step, hca]
  by_cases hlate : s.now > ca.notAfter
  · have : now > na := by rw [hgt]; exact hlate
    simp [this, hlate, outcomeOf]
  · have : ¬ now > na := by rw [hgt]; exact hlate
    simp only [this, hlate, if_false, ite_true, Bool.not_eq_true']
    cases hp : ca.permits sni <;> cases trusts <;>
      by_cases hs : sni = host <;> simp [hs, outcomeOf]

/-- Without a CA for the pod, both the code (fed `ca_live = false`) and the model
    refuse as expired. -/
theorem tls_verdict_no_ca (s : TlsTermination.State) (p : TlsTermination.PodId)
    (sni host : TlsTermination.Name) (trusts : Bool)
    (hca : TlsTermination.caOf s.cas p = none) (now na : Std.U64) (perm sm : Bool) :
    extracted.tls.tls_verdict false now na perm trusts sm = ok .RefusedExpired ∧
      (TlsTermination.step s (.handshake p sni host trusts)).journal.head? =
        some (.refusedExpired p) := by
  unfold extracted.tls.tls_verdict
  simp [TlsTermination.step, hca]

end TlsTerminationExtracted

#print axioms TlsTerminationExtracted.tls_verdict_never_fails
#print axioms TlsTerminationExtracted.may_issue_leaf_spec
#print axioms TlsTerminationExtracted.tls_verdict_is_step
#print axioms TlsTerminationExtracted.tls_verdict_no_ca
