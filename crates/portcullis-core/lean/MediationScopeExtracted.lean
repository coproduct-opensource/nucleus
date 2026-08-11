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

  # What this file now covers, and what it does not

  Two halves, both over the extracted model:

  * the scope PREDICATE (`scope_admits_*`) — a discharge admits exactly its own
    action;
  * the MACHINE (`effect_requires_held`, `effect_consumes_the_authority`,
    `refusal_preserves_the_authority`, `no_replay_without_a_fresh_discharge`) —
    an effect needs a held authority, consumes it, and cannot be replayed.

  Together these are the *conditional* half of global mediation: given that every
  effect entry point consumes a scoped `Authority`, a run cannot contain an
  unmediated or replayed effect.

  **The premise is not proved here, and cannot be.** "Every effect entry point
  consumes an Authority" is a whole-program property over an open program; Lean
  has nothing to quantify over, and the effect layer's real I/O is outside the
  extractable subset anyway. It is discharged mechanically by the `mediated`
  Dylint pass (tools/nucleus-mediation-lint), closed under the call graph, over
  the set defined in docs/architecture/mediated-set.md.

  seL4 has the same shape: it assumes compiler, assembly and hardware
  correctness, and imposes syntactic restrictions — notably no calls through
  function pointers — checked outside Isabelle so the proof has a statically
  known call graph.

  What remains trusted, stated rather than hidden: rustc's enforcement of affine
  moves, the lint's deny-set completeness, and Charon/Aeneas extraction fidelity.

  Nor does any of this say anything about the other seven obligations;
  `scope_admits` governs which action a bundle speaks for, not whether that
  action is safe.
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

/-! ## The mediation machine — the trace half

    Everything above is about the scope PREDICATE. What follows is about the
    machine that uses it, and it is the half that says something about *runs*
    rather than about one comparison.

    The machine is the abstract counterpart of what the Rust types enforce:
    `Discharge` puts an authority in hand, `Effect` succeeds only against a
    matching held authority and CONSUMES it. Consumption is the whole content of
    "by value" — it is why a second effect without a fresh discharge cannot
    succeed, and it is what the `compile_fail` doctest on `FileEffect` pins on
    the Rust side.

    These theorems are stated over the GENERATED `med_step`, not a hand model.
-/

/-! ### Totality of the generated helpers

    `med_step` is a `do`-block over `scope_admits`, which is itself a `do`-block
    over `opcode`/`sinkcode`. None of them can fail — no loops, no partial
    arithmetic — but the `Result` monad does not know that, so the binds must be
    discharged before any theorem about `med_step` can reduce. -/

theorem opcode_total (o : MedOperation) :
    ∃ v, nucleus_ifc_kernel.extracted.mediation.opcode o = ok v := by
  cases o <;> exact ⟨_, rfl⟩

theorem sinkcode_total (k : MedSinkClass) :
    ∃ v, nucleus_ifc_kernel.extracted.mediation.sinkcode k = ok v := by
  cases k <;> exact ⟨_, rfl⟩

/-- The sink comparison the true branch of `scope_admits` reduces to. Proved
    separately (19² cases) so `scope_admits_total` needs only the 13² operation
    split rather than the 61 009-case product. -/
theorem sinkcode_cmp_total (es as_ : MedSinkClass) :
    ∃ b, (do
            let i2 ← nucleus_ifc_kernel.extracted.mediation.sinkcode es
            let i3 ← nucleus_ifc_kernel.extracted.mediation.sinkcode as_
            ok (decide (i2 = i3))) = ok b := by
  cases es <;> cases as_ <;> exact ⟨_, rfl⟩

theorem scope_admits_total (eo ao : MedOperation) (es as_ : MedSinkClass) :
    ∃ b, nucleus_ifc_kernel.extracted.mediation.scope_admits eo es ao as_ = ok b := by
  obtain ⟨b, hb⟩ := sinkcode_cmp_total es as_
  unfold nucleus_ifc_kernel.extracted.mediation.scope_admits
  cases eo <;> cases ao <;>
    simp only [nucleus_ifc_kernel.extracted.mediation.opcode, bind_tc_ok] <;>
    first
      | exact ⟨b, hb⟩
      | exact ⟨_, rfl⟩

/-! ## The mediation machine — the trace half

    Everything above is about the scope PREDICATE. What follows is about the
    machine that uses it, and it is the half that says something about a *run*
    rather than about one comparison.

    The machine is the abstract counterpart of what the Rust types enforce:
    `Discharge` puts an authority in hand; `Effect` succeeds only against a
    matching held authority and CONSUMES it. Consumption is the whole content of
    "by value" — it is why a second effect without a fresh discharge cannot
    succeed, and it is what the `compile_fail` doctest on `FileEffect` pins on
    the Rust side.

    Stated over the GENERATED `med_step`, not a hand model. -/

/-- An effect cannot succeed from the idle state. No authority, no effect —
    complete mediation at the level of a single step. -/
theorem effect_requires_held
    (s : MedState) (o : MedOperation) (k : MedSinkClass) (r : StepResult)
    (hstep : nucleus_ifc_kernel.extracted.mediation.med_step s
              (MedAction.Effect o k) = ok r)
    (hok : r.ok = true) :
    s.held = true := by
  by_cases h : s.held = true
  · exact h
  · exfalso
    simp only [Bool.not_eq_true] at h
    unfold nucleus_ifc_kernel.extracted.mediation.med_step at hstep
    simp only [h, Bool.false_eq_true, if_false] at hstep
    injection hstep with heq
    subst heq
    exact Bool.noConfusion hok

/-- A successful effect CONSUMES the authority: the machine returns to idle.
    Without this, one discharge would authorise unboundedly many effects — the
    replay the by-value cutover removed from the Rust. -/
theorem effect_consumes_the_authority
    (s : MedState) (o : MedOperation) (k : MedSinkClass) (r : StepResult)
    (hstep : nucleus_ifc_kernel.extracted.mediation.med_step s
              (MedAction.Effect o k) = ok r)
    (hok : r.ok = true) :
    r.next.held = false := by
  have hheld : s.held = true := effect_requires_held s o k r hstep hok
  obtain ⟨b, hb⟩ := scope_admits_total s.op o s.sink k
  unfold nucleus_ifc_kernel.extracted.mediation.med_step at hstep
  simp only [hheld, if_true, hb, bind_tc_ok] at hstep
  cases b
  · simp only [Bool.false_eq_true, if_false] at hstep
    injection hstep with heq
    subst heq
    exact absurd hok (by simp)
  · simp only [if_true] at hstep
    injection hstep with heq
    subst heq
    rfl

/-- A REFUSED effect leaves the state untouched, so a wrong-scope attempt cannot
    burn a legitimate authority. A denial that consumed the token would be a
    denial of service on the honest path. -/
theorem refusal_preserves_the_authority
    (s : MedState) (o : MedOperation) (k : MedSinkClass) (r : StepResult)
    (hstep : nucleus_ifc_kernel.extracted.mediation.med_step s
              (MedAction.Effect o k) = ok r)
    (hno : r.ok = false) :
    r.next = s := by
  obtain ⟨b, hb⟩ := scope_admits_total s.op o s.sink k
  unfold nucleus_ifc_kernel.extracted.mediation.med_step at hstep
  by_cases h : s.held = true
  · simp only [h, if_true, hb, bind_tc_ok] at hstep
    cases b
    · simp only [Bool.false_eq_true, if_false] at hstep
      injection hstep with heq
      subst heq
      rfl
    · simp only [if_true] at hstep
      injection hstep with heq
      subst heq
      exact absurd hno (by simp)
  · simp only [Bool.not_eq_true] at h
    simp only [h, Bool.false_eq_true, if_false] at hstep
    injection hstep with heq
    subst heq
    rfl

/-- Discharge always succeeds and holds exactly what it was earned for. -/
theorem discharge_holds_its_own_scope
    (s : MedState) (o : MedOperation) (k : MedSinkClass) (r : StepResult)
    (hstep : nucleus_ifc_kernel.extracted.mediation.med_step s
              (MedAction.Discharge o k) = ok r) :
    r.ok = true ∧ r.next.held = true ∧ r.next.op = o ∧ r.next.sink = k := by
  unfold nucleus_ifc_kernel.extracted.mediation.med_step at hstep
  injection hstep with heq
  subst heq
  exact ⟨rfl, rfl, rfl, rfl⟩

/-! ### No replay, as a two-step corollary

    The composition that matters: after a successful effect the machine is idle,
    and from idle no effect succeeds. So a second effect with no discharge
    between them fails — one authority, one effect. -/

theorem no_replay_without_a_fresh_discharge
    (s : MedState) (o₁ o₂ : MedOperation) (k₁ k₂ : MedSinkClass)
    (r₁ r₂ : StepResult)
    (h₁ : nucleus_ifc_kernel.extracted.mediation.med_step s
            (MedAction.Effect o₁ k₁) = ok r₁)
    (hok₁ : r₁.ok = true)
    (h₂ : nucleus_ifc_kernel.extracted.mediation.med_step r₁.next
            (MedAction.Effect o₂ k₂) = ok r₂) :
    r₂.ok = false := by
  have hidle : r₁.next.held = false :=
    effect_consumes_the_authority s o₁ k₁ r₁ h₁ hok₁
  by_contra hok₂
  simp only [Bool.not_eq_false] at hok₂
  have := effect_requires_held r₁.next o₂ k₂ r₂ h₂ hok₂
  rw [hidle] at this
  exact Bool.noConfusion this

/-! ## Axiom audit

    Must print only the trusted Lean kernel set — no `sorryAx`, and no Aeneas
    `*External` opaque axiom. The Rust slice compares explicit `u8` ranks rather
    than deriving `PartialEq` precisely so no opaque comparison axiom lands here.
-/

#print axioms scope_admits_refl
#print axioms scope_admits_iff_eq
#print axioms scope_admits_unique
#print axioms scope_admits_no_escalation
#print axioms effect_requires_held
#print axioms effect_consumes_the_authority
#print axioms refusal_preserves_the_authority
#print axioms no_replay_without_a_fresh_discharge

/-! ## C6 Tier-A headline — the OUTBOUND analogue of C1

    Everything above establishes the machine's step semantics. This section
    states the C6 Phase-1 Tier-A property in the SAME shape as C1's
    `ChannelAdmissionExtracted.lean#no_channel_delivers_secret_to_the_workload`,
    but for the OUTBOUND effect surface. Over the closed `MedSinkClass` enum —
    the 1:1 mirror of the production 19-variant `SinkClass`, pinned by the Rust
    test `the_mirror_covers_every_production_variant` — no sink is reachable from
    a fresh, un-discharged context: every effect is refused unless a matching
    authority was discharged first.

    C1 needed a Secret/Public SPLIT because some inbound channels legitimately
    carry public material. The outbound machine needs no such split: it demands a
    held authority for EVERY sink class, so the strongest true statement
    quantifies over the WHOLE enum, and the consequential (exfil) sinks are named
    below as witnesses rather than as a weaker restriction.

    Closure: a new sink class forces a `MedSinkClass` variant and a `sinkcode`
    match arm (extraction fails otherwise), and
    `the_mirror_covers_every_production_variant` reds if the mirror drifts from
    production `SinkClass`, so the quantification stays total against the real
    enum. -/

/-- **`no_sink_reachable_without_discharge` — the C6 Tier-A flagship.** From the
    idle state (`med_idle`: nothing discharged), stepping an `Effect` at ANY
    `(operation, sink)` pair is refused. Complete mediation over the closed sink
    enum at a single step — no discharge, no sink — the outbound dual of
    `no_channel_delivers_secret_to_the_workload`. -/
theorem no_sink_reachable_without_discharge
    (o : MedOperation) (k : MedSinkClass) (idle : MedState) (r : StepResult)
    (hidle : nucleus_ifc_kernel.extracted.mediation.med_idle = ok idle)
    (hstep : nucleus_ifc_kernel.extracted.mediation.med_step idle
              (MedAction.Effect o k) = ok r) :
    r.ok = false := by
  have hheld : idle.held = false := by
    unfold nucleus_ifc_kernel.extracted.mediation.med_idle at hidle
    injection hidle with h; subst h; rfl
  cases hro : r.ok with
  | false => rfl
  | true =>
    have hh := effect_requires_held idle o k r hstep hro
    rw [hheld] at hh
    exact Bool.noConfusion hh

/-- **Non-vacuity (the control): a discharged sink IS reachable.** The gate is
    not "refuse everything" — once the matching authority is discharged, the
    effect at that exact `(operation, sink)` succeeds. Without this the flagship
    is satisfied by a machine that admits nothing. -/
theorem a_discharged_sink_is_reachable
    (s : MedState) (o : MedOperation) (k : MedSinkClass)
    (r1 r2 : StepResult)
    (hdis : nucleus_ifc_kernel.extracted.mediation.med_step s
              (MedAction.Discharge o k) = ok r1)
    (heff : nucleus_ifc_kernel.extracted.mediation.med_step r1.next
              (MedAction.Effect o k) = ok r2) :
    r2.ok = true := by
  obtain ⟨_, hheld, hop, hsink⟩ := discharge_holds_its_own_scope s o k r1 hdis
  have hadm : nucleus_ifc_kernel.extracted.mediation.scope_admits
                r1.next.op r1.next.sink o k = ok true := by
    rw [hop, hsink]; exact scope_admits_refl o k
  unfold nucleus_ifc_kernel.extracted.mediation.med_step at heff
  simp only [hheld, if_true, hadm, bind_tc_ok] at heff
  unfold nucleus_ifc_kernel.extracted.mediation.med_idle at heff
  simp only [bind_tc_ok] at heff
  injection heff with heq
  subst heq
  rfl

/-- **Named consequential-sink witnesses.** The exfil vectors — HTTP egress, git
    push, PR/comment write, email, cloud mutation, agent spawn, ticket write (the
    production `SinkClass::is_exfil_vector` set) — each refused from idle. Stated
    redundantly with the quantified flagship: if a sink is ever mislabelled so the
    machine would admit it un-discharged, THIS turns red rather than the flagship
    going silently vacuous. Mirrors C1's `the_env_channel_refuses_every_secret`.
    Holds for every operation, since with nothing held the refusal is independent
    of the attempted pair. -/
theorem the_consequential_sinks_are_refused_from_idle (o : MedOperation)
    (idle : MedState)
    (hidle : nucleus_ifc_kernel.extracted.mediation.med_idle = ok idle) :
    (∀ r, nucleus_ifc_kernel.extracted.mediation.med_step idle
            (MedAction.Effect o MedSinkClass.HTTPEgress) = ok r → r.ok = false)
    ∧ (∀ r, nucleus_ifc_kernel.extracted.mediation.med_step idle
            (MedAction.Effect o MedSinkClass.GitPush) = ok r → r.ok = false)
    ∧ (∀ r, nucleus_ifc_kernel.extracted.mediation.med_step idle
            (MedAction.Effect o MedSinkClass.PRCommentWrite) = ok r → r.ok = false)
    ∧ (∀ r, nucleus_ifc_kernel.extracted.mediation.med_step idle
            (MedAction.Effect o MedSinkClass.EmailSend) = ok r → r.ok = false)
    ∧ (∀ r, nucleus_ifc_kernel.extracted.mediation.med_step idle
            (MedAction.Effect o MedSinkClass.CloudMutation) = ok r → r.ok = false)
    ∧ (∀ r, nucleus_ifc_kernel.extracted.mediation.med_step idle
            (MedAction.Effect o MedSinkClass.AgentSpawn) = ok r → r.ok = false)
    ∧ (∀ r, nucleus_ifc_kernel.extracted.mediation.med_step idle
            (MedAction.Effect o MedSinkClass.TicketWrite) = ok r → r.ok = false) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
    intro r hstep <;>
    exact no_sink_reachable_without_discharge o _ idle r hidle hstep

/-! ### Axiom audit — the C6 Tier-A additions -/

#print axioms no_sink_reachable_without_discharge
#print axioms a_discharged_sink_is_reachable
#print axioms the_consequential_sinks_are_refused_from_idle


end MediationScopeExtracted
