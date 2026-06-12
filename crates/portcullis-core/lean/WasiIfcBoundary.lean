import Mathlib.Tactic

/-!
# Soundness of the WASI Information-Flow Boundary Monitor

The Lean side of `crates/portcullis-wasi/src/ifc.rs`. We prove that the
**floating-label monitor** at the WASI import boundary is *sound*: if it admits a
sink, then every source the component read individually satisfies that sink's
policy. No disallowed source's data ever reaches a sink — information-flow
noninterference at the boundary.

This is the formal backing that FIDES (Microsoft Research's IFC-for-agents,
arXiv:2505.23643) explicitly lacks: there the enforcement is a dynamic runtime
monitor with "no formal completeness proofs". Here the same monitor discipline
is kernel-checked.

## The model

A component reads a sequence of labeled sources. The monitor keeps a single
*floating label* `pc` = the join of everything read (`pcAfter`). A sink with
requirement `t` is admitted iff `flowsTo (pc) t`. We use a `Nat`-coded label —
confidentiality covariant (join = max), integrity and authority contravariant
(join = min, Biba) — mirroring `portcullis_core::IFCLabel`'s three lattice-
ordered dimensions. (The Rust label also carries provenance/freshness/derivation;
the boundary's sink requirements leave those at top, so they never bind, and the
finite ordered core is what governs admission.)

## What is proven

- **`join_flowsTo_iff`** — the fundamental lemma: `(a ⊔ b)` flows to a sink iff
  both `a` and `b` do. (Confidentiality max, integrity/authority min.)
- **`pcAfter_flowsTo`** — the floating label admits a sink iff every read does.
- **`monitor_sound`** — the soundness corollary: admission ⇒ every source is
  individually policy-compliant.
- Concrete corollaries mirroring the `portcullis-wasi` host tests:
  `untrusted_blocks_trusted_action`, `secret_blocks_egress`,
  `trifecta_blocks_egress`, `clean_flows_everywhere`.

`join_flowsTo_iff` / `pcAfter_flowsTo` discharge by `omega` + induction; the
concrete corollaries by `decide`. Kernel-checked, no `sorry`.
-/

namespace WasiIfcBoundary

/-- A boundary label over three lattice-ordered dimensions, `Nat`-coded.
    Confidentiality is covariant (higher = more secret); integrity and authority
    are contravariant (higher = more trusted / more authorized). Mirrors the
    ordered core of `portcullis_core::IFCLabel`. -/
structure Label where
  conf : Nat
  integ : Nat
  auth : Nat
deriving DecidableEq, Repr

/-- Join (least upper bound): confidentiality max (covariant), integrity and
    authority min (contravariant — least trusted / least authorized wins). This
    is the floating-label taint step; mirrors `IFCLabel::join`. -/
def join (a b : Label) : Label :=
  { conf := max a.conf b.conf
    integ := min a.integ b.integ
    auth := min a.auth b.auth }

/-- `a` may flow to a sink requiring `t`: confidentiality no higher, integrity
    and authority no lower. Mirrors `IFCLabel::flows_to` on the ordered core. -/
def flowsTo (a t : Label) : Prop :=
  a.conf ≤ t.conf ∧ t.integ ≤ a.integ ∧ t.auth ≤ a.auth

instance : DecidablePred (fun p : Label × Label => flowsTo p.1 p.2) := fun _ =>
  inferInstanceAs (Decidable (_ ∧ _ ∧ _))

instance (a t : Label) : Decidable (flowsTo a t) :=
  inferInstanceAs (Decidable (_ ∧ _ ∧ _))

/-- The least-restrictive label: public, fully trusted, fully authorized.
    Confidentiality bottom (0); integrity/authority top (2 / 3 — the maxima of
    the finite `IntegLevel` / `AuthorityLevel` chains). Having read nothing, a
    component sits here and may perform any action. -/
def bottom : Label := { conf := 0, integ := 2, auth := 3 }

-- ═══════════════════════════════════════════════════════════════════════════
-- Fundamental lemma: join admits a sink iff both operands do
-- ═══════════════════════════════════════════════════════════════════════════

/-- The key compatibility law between `join` and `flowsTo`. Because
    confidentiality joins by `max` and integrity/authority by `min`, the
    accumulated label `a ⊔ b` flows to a sink **exactly when both `a` and `b`
    do**. This is what makes the floating label a faithful summary. -/
theorem join_flowsTo_iff (a b t : Label) :
    flowsTo (join a b) t ↔ (flowsTo a t ∧ flowsTo b t) := by
  simp only [flowsTo, join]
  omega

-- ═══════════════════════════════════════════════════════════════════════════
-- The floating label and monitor soundness
-- ═══════════════════════════════════════════════════════════════════════════

/-- The floating label after reading a sequence of sources: the join of all of
    them (and `bottom`). Mirrors repeated `BoundaryMonitor::stamp`. -/
def pcAfter : List Label → Label
  | [] => bottom
  | r :: rs => join r (pcAfter rs)

/-- The floating label admits a sink **iff** every source read admits it (and
    the vacuous `bottom` case). The monitor is therefore exactly as permissive
    as checking each source individually — neither unsound nor needlessly
    restrictive at the per-source level. -/
theorem pcAfter_flowsTo (reads : List Label) (t : Label) :
    flowsTo (pcAfter reads) t ↔ (flowsTo bottom t ∧ ∀ r ∈ reads, flowsTo r t) := by
  induction reads with
  | nil => simp [pcAfter]
  | cons r rs ih =>
      rw [pcAfter, join_flowsTo_iff, ih, List.forall_mem_cons]
      tauto

/-- **Soundness.** If the boundary monitor admits a sink after a component has
    read `reads`, then every source the component read individually satisfies the
    sink's policy. Equivalently: data from a source that may not flow to a sink
    can never reach that sink. -/
theorem monitor_sound (reads : List Label) (t : Label)
    (h : flowsTo (pcAfter reads) t) : ∀ r ∈ reads, flowsTo r t :=
  ((pcAfter_flowsTo reads t).mp h).2

-- ═══════════════════════════════════════════════════════════════════════════
-- Concrete corollaries — mirror the portcullis-wasi host tests
-- ═══════════════════════════════════════════════════════════════════════════

/-- Adversarial external content: public, adversarial integrity (0), no
    authority (0). -/
def untrustedContent : Label := { conf := 0, integ := 0, auth := 0 }
/-- A local secret: secret confidentiality (2), trusted (2), directive (3). -/
def secret : Label := { conf := 2, integ := 2, auth := 3 }
/-- Trusted, public, authorized data. -/
def trustedPublic : Label := { conf := 0, integ := 2, auth := 3 }

/-- A consequential-action sink: requires trusted (2) integrity and directive
    (3) authority; confidentiality permissive (2). Mirrors `ifc::trusted_action`. -/
def trustedActionReq : Label := { conf := 2, integ := 2, auth := 3 }
/-- A public-egress sink: requires public (0) confidentiality; integrity and
    authority permissive (0). Mirrors `ifc::public_egress`. -/
def publicEgressReq : Label := { conf := 0, integ := 0, auth := 0 }

/-- Reading adversarial content blocks a subsequent trusted action (integrity). -/
theorem untrusted_blocks_trusted_action :
    ¬ flowsTo (pcAfter [untrustedContent]) trustedActionReq := by decide

/-- Reading a secret blocks subsequent public egress (confidentiality). -/
theorem secret_blocks_egress :
    ¬ flowsTo (pcAfter [secret]) publicEgressReq := by decide

/-- The lethal trifecta: untrusted content + a secret + an egress attempt is
    blocked on confidentiality. -/
theorem trifecta_blocks_egress :
    ¬ flowsTo (pcAfter [untrustedContent, secret]) publicEgressReq := by decide

/-- A clean component (reads only trusted-public data) flows to both sinks. -/
theorem clean_flows_everywhere :
    flowsTo (pcAfter [trustedPublic]) trustedActionReq ∧
      flowsTo (pcAfter [trustedPublic]) publicEgressReq := by decide

-- ═══════════════════════════════════════════════════════════════════════════
-- Declassification — the audited escape valve, and its soundness
-- ═══════════════════════════════════════════════════════════════════════════

/-- Lower confidentiality from `frm` to `tgt`, but only when the precondition
    holds (`frm ≤ pc.conf`) and it is a genuine downgrade (`to < frm`); otherwise
    unchanged. Integrity and authority are untouched. The SOLE operation that may
    lower `pc`. Mirrors `DeclassifyAction::LowerConfidentiality` and
    `BoundaryMonitor::declassify`. -/
def declassifyConf (l : Label) (frm tgt : Nat) : Label :=
  if tgt < frm ∧ frm ≤ l.conf then { l with conf := tgt } else l

/-- Declassification can only *lower* confidentiality — never raise it. No datum
    is ever made more secret by declassifying (and combined with `stamp` only
    raising, `pc` confidentiality moves down only through this audited op). -/
theorem declassify_only_lowers_conf (l : Label) (frm tgt : Nat) :
    (declassifyConf l frm tgt).conf ≤ l.conf := by
  unfold declassifyConf
  by_cases h : tgt < frm ∧ frm ≤ l.conf
  · rw [if_pos h]; show tgt ≤ l.conf; omega
  · rw [if_neg h]

/-- Declassifying confidentiality leaves integrity untouched — it cannot launder
    adversarial provenance into trust. -/
theorem declassify_preserves_integ (l : Label) (frm tgt : Nat) :
    (declassifyConf l frm tgt).integ = l.integ := by
  unfold declassifyConf; split <;> rfl

/-- …and likewise authority. -/
theorem declassify_preserves_auth (l : Label) (frm tgt : Nat) :
    (declassifyConf l frm tgt).auth = l.auth := by
  unfold declassifyConf; split <;> rfl

/-- No silent cleansing: when the precondition is unmet the label is unchanged. -/
theorem declassify_noop_when_below (l : Label) (frm tgt : Nat) (h : l.conf < frm) :
    declassifyConf l frm tgt = l := by
  have hcond : ¬ (tgt < frm ∧ frm ≤ l.conf) := by rintro ⟨_, h2⟩; omega
  unfold declassifyConf; rw [if_neg hcond]

/-- **Escape valve works.** After an authorized `Secret → Public` declassification,
    the secret context flows to a public-egress sink — but only via this explicit,
    audited downgrade. -/
theorem declassify_unblocks_egress :
    flowsTo (declassifyConf (pcAfter [secret]) 2 0) publicEgressReq := by decide

/-- **Escape valve is bounded.** Declassifying confidentiality does NOT unblock a
    trusted action that was denied on integrity: after reading adversarial
    content, the trusted-action sink stays denied post-declassify. -/
theorem declassify_preserves_block_on_integrity :
    ¬ flowsTo (declassifyConf (pcAfter [untrustedContent]) 2 0) trustedActionReq := by
  decide

end WasiIfcBoundary
