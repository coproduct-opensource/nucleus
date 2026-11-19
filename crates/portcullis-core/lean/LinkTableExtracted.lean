/-
  ADR 0017 L3: the link predicates the node will run ARE the decisions
  `LinkTable.lean` reasons about.

  `generated-link/` is Aeneas's translation of
  `crates/nucleus-ifc-kernel/src/extracted/link.rs` (the same scoped Charon run as
  `generated-egress/`). This file proves, for each extracted predicate:

    * totality — it never returns `fail`/`div`, so no proof downstream carries a
      side condition;
    * its exact Boolean meaning, stated over the extracted constant;
    * for `may_link`, `may_cancel` and `may_deliver`, that it computes the same
      decision as `LinkTable.admitLink`, `LinkTable.step (.cancel …)` and
      `LinkTable.step (.request …)` respectively, so the model's theorems
      (`no_cross_tenant_link`, `cancel_refuses_linked`, `request_is_a_decision`)
      are about the shipped decision, not a restatement of it.

  The list half (the table) stays in `LinkTable.lean`, as the egress fold stays
  in `EgressConfinementExtracted.lean`; `crates/nucleus-ifc-kernel/src/links.rs`
  applies these predicates and is held to `LinkTable.step` by tests named after
  its theorems.

  Pod ids: the model's are `Nat`, the code's `U128` (a UUID). The bridge needs
  only that the code's ids are equal exactly when the model's are (`hid`).
-/

import PortcullisCoreLink.Types
import PortcullisCoreLink.Funs
import LinkTable

open Aeneas Aeneas.Std Result

namespace LinkTableExtracted

open nucleus_ifc_kernel

/-! ## Each predicate, exactly -/

theorem link_matches_spec (l : extracted.link.Link) (s d : Std.U128) (p : Std.U32) :
    extracted.link.link_matches l s d p = ok (decide (l.src = s ∧ l.dst = d ∧ l.port = p)) := by
  unfold extracted.link.link_matches
  by_cases h1 : l.src = s <;> by_cases h2 : l.dst = d <;> simp [h1, h2]

theorem names_spec (l : extracted.link.Link) (q : Std.U128) :
    extracted.link.names l q = ok (decide (l.src = q ∨ l.dst = q)) := by
  unfold extracted.link.names
  by_cases h : l.src = q <;> simp [h]

theorem may_link_spec (ms md st : Bool) (a b : Std.U128) (pr : Bool) :
    extracted.link.may_link ms md st a b pr =
      ok (ms && md && decide (a ≠ b) && st && !pr) := by
  unfold extracted.link.may_link
  cases ms <;> cases md <;> cases st <;> cases pr <;> by_cases h : a = b <;> simp [h]

theorem may_unlink_spec (pr ms : Bool) :
    extracted.link.may_unlink pr ms = ok (pr && ms) := by
  unfold extracted.link.may_unlink
  cases pr <;> simp

theorem may_cancel_spec (m lk : Bool) :
    extracted.link.may_cancel m lk = ok (m && !lk) := by
  unfold extracted.link.may_cancel
  cases m <;> cases lk <;> simp

theorem may_deliver_spec (live admits : Bool) :
    extracted.link.may_deliver live admits = ok (live && admits) := by
  unfold extracted.link.may_deliver
  cases live <;> simp

/-! ## The extracted decisions are the model's -/

/-- `may_link`, fed what the node knows, decides exactly `LinkTable.admitLink`. -/
theorem may_link_is_admitLink (s : LinkTable.Scope) (n : LinkTable.Node) (l : LinkTable.Link)
    (a b : Std.U128) (hid : a = b ↔ l.src = l.dst) :
    extracted.link.may_link (LinkTable.manages s n l.src) (LinkTable.manages s n l.dst)
        (LinkTable.tenantOf n.pods l.src == LinkTable.tenantOf n.pods l.dst) a b
        (n.links.contains l) =
      ok (LinkTable.admitLink s n l) := by
  rw [may_link_spec]
  simp only [LinkTable.admitLink]
  have hne : decide (a ≠ b) = (l.src != l.dst) := by
    by_cases h : l.src = l.dst
    · simp [h, hid.mpr h]
    · have : a ≠ b := fun e => h (hid.mp e)
      simp [h, this]
  rw [hne]

/-- `may_cancel`, fed what the node knows, decides exactly whether
    `LinkTable.step (.cancel s p)` succeeds. -/
theorem may_cancel_is_step (s : LinkTable.Scope) (n : LinkTable.Node) (p : LinkTable.PodId) :
    extracted.link.may_cancel (LinkTable.manages s n p) (n.links.any (LinkTable.names p)) =
      ok ((LinkTable.step n (.cancel s p)).2.all (·.ok)) := by
  rw [may_cancel_spec]
  simp only [LinkTable.step]
  split <;> rename_i h <;> simp_all

/-- `may_deliver`, fed the connection's liveness and the host's decision, decides
    exactly whether `LinkTable.step (.request c v)` delivers. -/
theorem may_deliver_is_step (n : LinkTable.Node) (c : LinkTable.Conn) (v : Nat) :
    extracted.link.may_deliver (n.conns.contains c) (n.decide c.link v) =
      ok ((LinkTable.step n (.request c v)).2.all (·.ok)) := by
  rw [may_deliver_spec]
  simp only [LinkTable.step]
  split <;> rename_i h <;> simp_all

end LinkTableExtracted

#print axioms LinkTableExtracted.link_matches_spec
#print axioms LinkTableExtracted.names_spec
#print axioms LinkTableExtracted.may_link_spec
#print axioms LinkTableExtracted.may_unlink_spec
#print axioms LinkTableExtracted.may_cancel_spec
#print axioms LinkTableExtracted.may_deliver_spec
#print axioms LinkTableExtracted.may_link_is_admitLink
#print axioms LinkTableExtracted.may_cancel_is_step
#print axioms LinkTableExtracted.may_deliver_is_step
