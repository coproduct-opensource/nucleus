/-
  Scope binding — proven OVER the Aeneas-EXTRACTED enforcement core.

  This is the first component of the complete-mediation property: that a
  discharge authorizes the action it was earned for and NOTHING else. The chain
  is the same one the integrity noninterference theorem uses:

      crates/nucleus-ifc-kernel/src/extracted/mediation.rs        (real Rust)
        --charon (scoped, --start-from)-->  nucleus_ifc_kernel.llbc
        --aeneas -backend lean -split-files-->
          generated-mediation/PortcullisCoreMediation/{Types,Funs}.lean
        --(this file)-->  scope-binding theorems over THOSE generated defs.

  Every theorem below is stated in terms of the GENERATED
  `extracted.mediation.scope_admits`, which returns the Aeneas `Result` monad —
  not a hand-written model of it.

  # Why this property is the security-relevant one

  A `DischargedBundle` is earned for one `(Operation, SinkClass)` pair. If the
  effect layer accepts a bundle without checking that pair, an action whose own
  discharge would FAIL can be performed under a discharge that SUCCEEDED for
  something cheaper — the confused deputy. `scope_admits` is the predicate that
  refuses it, and these theorems say it refuses exactly the right set:

  * `scope_admits_refl`      — a bundle admits its own action (no false denial)
  * `scope_admits_iff_eq`    — it admits ONLY its own action (no confused deputy)
  * `scope_admits_unique`    — at most one pair is admitted (functional)
  * `scope_admits_no_escalation` — a concrete instance: a ReadFiles authority
    does not buy a GitPush. This is the live bug the theorem generalizes.

  # Ground truth (Rust↔model parity)

  The generated defs mirror production `DischargedBundle::authorizes` — see the
  EXHAUSTIVE parity test in `src/extracted/mediation.rs`, which sweeps every
  earnable pair (27 of 247 pass `PathAllowed`) against all 247 attempted pairs,
  6 669 comparisons, the complete domain. Those Rust tests close the model↔code
  gap; THIS file closes the property-over-extracted gap.

  # Scope boundary (the honest caveat)

  This proves the scope PREDICATE is exactly equality on the pair. It does NOT
  prove that every effect path calls it — that is the second half of complete
  mediation, and it is not yet true of the codebase: 10 of 13 effect-trait
  methods take no bundle at all, and the 3 that do take it by reference so a
  correctly-scoped bundle can be replayed. See docs/production-delta.md.

  Nor does it say anything about the other seven obligations; `scope_admits`
  governs which action a bundle speaks for, not whether that action is safe.
-/

import PortcullisCoreMediation.Types
import PortcullisCoreMediation.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

-- The case sweeps below unfold the generated `do`/`Result` binds and reduce
-- concrete `U8` comparisons; 13 × 19 = 247 pairs per side needs headroom.
set_option maxHeartbeats 4000000

namespace MediationScopeExtracted

open nucleus_ifc_kernel.extracted.mediation

/-- Shorthand: the generated predicate, with the `Result` wrapper discharged.
    `scope_admits` is total (no loops, no partial arithmetic), so it always
    returns `ok`. -/
def admits (eo : MedOperation) (es : MedSinkClass)
           (ao : MedOperation) (as_ : MedSinkClass) : Prop :=
  nucleus_ifc_kernel.extracted.mediation.scope_admits eo es ao as_ = ok true

/-! ## Decidable equality on the generated enums

    The Aeneas output does not `deriving DecidableEq`, and the generated files
    are kept as UNMODIFIED Aeneas output, so the instances are supplied here
    rather than by editing them. Each is a finite case sweep (13² and 19²). -/

instance : DecidableEq MedOperation := fun a b => by
  cases a <;> cases b <;>
    first
      | exact isTrue rfl
      | exact isFalse (by intro h; cases h)

instance : DecidableEq MedSinkClass := fun a b => by
  cases a <;> cases b <;>
    first
      | exact isTrue rfl
      | exact isFalse (by intro h; cases h)

/-! ## The generated codes are injective

    Stated and proved separately so the main theorem never needs the 13×13×19×19
    product split — 169 + 361 cases here instead of 61 009 there. -/

theorem opcode_eq_iff (a b : MedOperation) :
    nucleus_ifc_kernel.extracted.mediation.opcode a
      = nucleus_ifc_kernel.extracted.mediation.opcode b ↔ a = b := by
  constructor
  · intro h
    cases a <;> cases b <;>
      simp_all [nucleus_ifc_kernel.extracted.mediation.opcode]
  · rintro rfl; rfl

theorem sinkcode_eq_iff (a b : MedSinkClass) :
    nucleus_ifc_kernel.extracted.mediation.sinkcode a
      = nucleus_ifc_kernel.extracted.mediation.sinkcode b ↔ a = b := by
  constructor
  · intro h
    cases a <;> cases b <;>
      simp_all [nucleus_ifc_kernel.extracted.mediation.sinkcode]
  · rintro rfl; rfl

/-- Once the operations agree, the generated body reduces to the sink
    comparison. Factored out so the main theorem needs 19² cases here rather
    than repeating them under each of the 13 operations. -/
theorem sinkcode_cmp_true_imp_eq (es as_ : MedSinkClass)
    (h : (do
            let i2 ← nucleus_ifc_kernel.extracted.mediation.sinkcode es
            let i3 ← nucleus_ifc_kernel.extracted.mediation.sinkcode as_
            ok (decide (i2 = i3))) = ok true) :
    es = as_ := by
  cases es <;> cases as_ <;>
    simp_all [nucleus_ifc_kernel.extracted.mediation.sinkcode]

/-! ## No false denial -/

/-- A bundle admits the action it was earned for. Without this the runtime
    would refuse correctly-discharged work. -/
theorem scope_admits_refl (op : MedOperation) (sink : MedSinkClass) :
    admits op sink op sink := by
  unfold admits
  cases op <;> cases sink <;> rfl

/-! ## No confused deputy -/

/-- Admission holds EXACTLY when both components agree. This is the theorem the
    live bug violated: the effect layer accepted any bundle, which is the `→`
    direction failing for every mismatched pair. -/
theorem scope_admits_iff_eq
    (eo ao : MedOperation) (es as_ : MedSinkClass) :
    admits eo es ao as_ ↔ (eo = ao ∧ es = as_) := by
  constructor
  · intro h
    by_cases hop : eo = ao
    · subst hop
      refine ⟨rfl, ?_⟩
      unfold admits at h
      -- With the operations equal the `if` takes the true branch, leaving the
      -- sink comparison; `cases eo` only reduces the guard, one `rfl` per op.
      cases eo <;> exact sinkcode_cmp_true_imp_eq es as_ h
    · exfalso
      unfold admits at h
      have hne : nucleus_ifc_kernel.extracted.mediation.opcode eo
               ≠ nucleus_ifc_kernel.extracted.mediation.opcode ao := by
        intro hc; exact hop ((opcode_eq_iff eo ao).mp hc)
      cases eo <;> cases ao <;>
        simp_all [nucleus_ifc_kernel.extracted.mediation.scope_admits,
                  nucleus_ifc_kernel.extracted.mediation.opcode]
  · intro ⟨h1, h2⟩
    subst h1; subst h2
    exact scope_admits_refl eo es

/-- Differing on the OPERATION alone denies — a write authority is not a shell
    authority even at the same sink. -/
theorem scope_admits_discriminates_operation
    (eo ao : MedOperation) (sink : MedSinkClass) (h : eo ≠ ao) :
    ¬ admits eo sink ao sink := by
  intro hadm
  exact h ((scope_admits_iff_eq eo ao sink sink).mp hadm).1

/-- Differing on the SINK alone denies — the same operation against a different
    sink discharges different obligations. -/
theorem scope_admits_discriminates_sink
    (op : MedOperation) (es as_ : MedSinkClass) (h : es ≠ as_) :
    ¬ admits op es op as_ := by
  intro hadm
  exact h ((scope_admits_iff_eq op op es as_).mp hadm).2

/-! ## Functionality -/

/-- A bundle admits at most one pair: if it admits two, they are equal. This is
    the scope counterpart of one-shot use — authority does not fan out. -/
theorem scope_admits_unique
    (eo : MedOperation) (es : MedSinkClass)
    (o₁ o₂ : MedOperation) (s₁ s₂ : MedSinkClass)
    (h₁ : admits eo es o₁ s₁) (h₂ : admits eo es o₂ s₂) :
    o₁ = o₂ ∧ s₁ = s₂ := by
  have e₁ := (scope_admits_iff_eq eo o₁ es s₁).mp h₁
  have e₂ := (scope_admits_iff_eq eo o₂ es s₂).mp h₂
  exact ⟨e₁.1 ▸ e₂.1, e₁.2 ▸ e₂.2⟩

/-! ## The live bug, as a theorem

    `rt.write_file(p, c, rt.preflight_read()?)` returned `Ok(())` and wrote the
    file. `preflight_read` discharges `ReadFiles`/`AuditLogAppend`; the write is
    `WriteFiles`/`WorkspaceWrite`. The predicate refuses it — the defect was that
    the predicate was never consulted. -/

/-- A read authority does not buy a write. -/
theorem read_authority_does_not_buy_a_write :
    ¬ admits MedOperation.ReadFiles MedSinkClass.AuditLogAppend
             MedOperation.WriteFiles MedSinkClass.WorkspaceWrite := by
  intro h
  cases (scope_admits_iff_eq _ _ _ _).mp h with
  | intro hop _ => cases hop

/-- The escalation that matters most: a read authority does not buy a push. -/
theorem scope_admits_no_escalation :
    ¬ admits MedOperation.ReadFiles MedSinkClass.AuditLogAppend
             MedOperation.GitPush MedSinkClass.GitPush := by
  intro h
  cases (scope_admits_iff_eq _ _ _ _).mp h with
  | intro hop _ => cases hop

/-! ## Axiom audit

    Must print only the trusted Lean kernel set — no `sorryAx`, and no Aeneas
    `*External` opaque axiom. The Rust slice compares explicit `u8` ranks rather
    than deriving `PartialEq` precisely so no opaque comparison axiom lands here.
-/

#print axioms scope_admits_refl
#print axioms scope_admits_iff_eq
#print axioms scope_admits_unique
#print axioms scope_admits_no_escalation

end MediationScopeExtracted
