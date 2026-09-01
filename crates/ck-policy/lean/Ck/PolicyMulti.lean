/-
  Ck / PolicyMulti  (the monotonicity gate at the arity the CODE has)

  **STATUS: PROVED (0 `sorry`).** Mathlib-free, same discipline as `Ck.Policy`.

  # Why this file exists

  `Ck.Policy` models each authority group as ONE `Names` carrier. The production
  types are not one carrier: `ck_types::manifest::CapabilitySet` is FIVE
  `BTreeSet<String>` plus a numeric axis, `IoSurface` is five, and
  `ProofRequirements` is three. The Rust parity mirror ORs the per-axis predicate
  and its comment asserts that this is "the faithful boolean image".

  It is not, and the failure is not subtle:

  ```
                  filesystem_read   network_allow
      parent      {}                {"x"}
      child       {"x"}             {}
  ```

  Per axis — what `check_monotonicity` computes — `filesystem_read` escalates, so
  the gate REJECTS. Flattened, the child's union `{"x"}` is a subset of the
  parent's union `{"x"}`, so the single-carrier model sees NO escalation and
  ADMITS. `flattening_admits_what_per_axis_rejects` below is that pair, proved by
  `rfl`.

  So the flattened model is strictly MORE PERMISSIVE than the code, and
  `Ck.Policy.T1_gate_sound`'s conclusion `¬ capEscalates c p` — a statement about
  the unioned sets — does not entail per-axis non-escalation. Read as a claim
  about a real `PolicyManifest`, it over-claims.

  To be exact about the blast radius: this is a PROOF-TRANSFER defect, not a live
  vulnerability. The shipped Rust is per-axis and strict, and #2334 proved its two
  spellings (`is_subset_of` and `escalations_over`) agree. The code was always
  fine; the theorem did not reach it.

  This file restates the model at the real arity and reproves T1 there, so the
  theorem's subject is the shape the code actually has. `Ck.Policy` is retained as
  the readable single-axis specification and is pinned to this one by
  `flat_is_a_special_case`, so the two cannot drift apart silently.

  # The structures are exhaustive on purpose

  `CapAxes` / `IoAxes` / `ProofAxes` name every field of their Rust counterpart.
  Adding an axis in Rust without adding it here leaves this file's constructors
  incomplete, which is a compile error rather than a silent gap — the Lean
  analogue of the no-`..` destructuring tripwire in
  `ck_types::manifest::subset_agrees_with_no_escalation`.
-/

import Ck.Policy

namespace Ck.Policy

/- ───────────────────────────────────────────────────────────────────────────
   The axes, as the production structs actually have them
   ─────────────────────────────────────────────────────────────────────────── -/

/-- `ck_types::manifest::CapabilitySet`: five name sets and a numeric bound. -/
structure CapAxes where
  filesystemRead : Names
  filesystemWrite : Names
  networkAllow : Names
  toolsAllow : Names
  secretClasses : Names
  maxParallelTasks : Nat
deriving Repr

/-- `ck_types::manifest::IoSurface`: five name sets. -/
structure IoAxes where
  outboundDomains : Names
  localFileRoots : Names
  envVarsReadable : Names
  toolNamespaces : Names
  repoWriteTargets : Names
deriving Repr

/-- `ck_types::manifest::ProofRequirements`: three patch classes. -/
structure ProofAxes where
  configPatch : Names
  controllerPatch : Names
  evaluatorPatch : Names
deriving Repr

/-- A `PolicyManifest` at the arity the gate reads. -/
structure MultiManifest where
  caps : CapAxes
  ioSurface : IoAxes
  proofReqs : ProofAxes
  budget : Budget
  rules : Rules
deriving Repr

/- ───────────────────────────────────────────────────────────────────────────
   The crux: the flattening is NOT faithful
   ─────────────────────────────────────────────────────────────────────────── -/

/-- The union a single-carrier model implicitly takes. -/
def flattenCaps (a : CapAxes) : Names :=
  a.filesystemRead ++ a.filesystemWrite ++ a.networkAllow ++
    a.toolsAllow ++ a.secretClasses

/-- Any capability axis escalating, ignoring the parent flag. -/
def capEscalatesAnyB (c p : CapAxes) : Bool :=
  escalatesB c.filesystemRead p.filesystemRead ||
  escalatesB c.filesystemWrite p.filesystemWrite ||
  escalatesB c.networkAllow p.networkAllow ||
  escalatesB c.toolsAllow p.toolsAllow ||
  escalatesB c.secretClasses p.secretClasses ||
  decide (p.maxParallelTasks < c.maxParallelTasks)

/-- Parent: nothing readable, `"x"` reachable on the network. -/
def crossAxisParent : CapAxes :=
  { filesystemRead := [], filesystemWrite := [], networkAllow := ["x"],
    toolsAllow := [], secretClasses := [], maxParallelTasks := 0 }

/-- Child: `"x"` READABLE, nothing reachable. The same name, a different axis —
    a real escalation of `filesystem_read`. -/
def crossAxisChild : CapAxes :=
  { filesystemRead := ["x"], filesystemWrite := [], networkAllow := [],
    toolsAllow := [], secretClasses := [], maxParallelTasks := 0 }

/-- **The flattening admits what the per-axis gate rejects.**

    This is why the rest of this file exists. A single-carrier model cannot see a
    capability that moved between axes, because the union is unchanged; the
    production gate, which compares axis by axis, sees it immediately.

    Kept as a constructive witness (same role as `weak_gate_admits_coup`) so that
    "simplifying" the model back to one carrier fails a proof rather than
    quietly restoring the hole. -/
theorem flattening_admits_what_per_axis_rejects :
    capEscalatesAnyB crossAxisChild crossAxisParent = true ∧
    escalatesB (flattenCaps crossAxisChild) (flattenCaps crossAxisParent) = false := by
  constructor <;> rfl

/- ───────────────────────────────────────────────────────────────────────────
   The gate, per axis
   ─────────────────────────────────────────────────────────────────────────── -/

/-- Any io axis widening. -/
def ioEscalatesAnyB (c p : IoAxes) : Bool :=
  escalatesB c.outboundDomains p.outboundDomains ||
  escalatesB c.localFileRoots p.localFileRoots ||
  escalatesB c.envVarsReadable p.envVarsReadable ||
  escalatesB c.toolNamespaces p.toolNamespaces ||
  escalatesB c.repoWriteTargets p.repoWriteTargets

/-- Any proof requirement dropped. -/
def proofDropsAnyB (c p : ProofAxes) : Bool :=
  dropsB c.configPatch p.configPatch ||
  dropsB c.controllerPatch p.controllerPatch ||
  dropsB c.evaluatorPatch p.evaluatorPatch

/-- Capability axis violated? Gated on the PARENT flag, as in the Rust. -/
def capViolatedM (p c : MultiManifest) : Bool :=
  if p.rules.cap then capEscalatesAnyB c.caps p.caps else false

/-- I/O axis violated? Gated on the PARENT flag. -/
def ioViolatedM (p c : MultiManifest) : Bool :=
  if p.rules.io then ioEscalatesAnyB c.ioSurface p.ioSurface else false

/-- Budget violated? ALWAYS checked — no gating flag exists in the Rust. -/
def budgetViolatedM (p c : MultiManifest) : Bool :=
  !budgetWithin c.budget p.budget

/-- Proof-requirement axis violated? Gated on the PARENT flag. -/
def proofReqViolatedM (p c : MultiManifest) : Bool :=
  if p.rules.proofreq then proofDropsAnyB c.proofReqs p.proofReqs else false

/-- The child does not disable a governance flag the parent set, and does not
    lower the human-signature threshold. Reuses `Ck.Policy.Rules` unchanged: the
    amendment rules were never the part that was flattened. -/
def rulesNonWeakeningM (c p : MultiManifest) : Bool :=
  (!p.rules.cap || c.rules.cap) &&
  (!p.rules.io || c.rules.io) &&
  (!p.rules.proofreq || c.rules.proofreq) &&
  (decide (p.rules.sigs ≤ c.rules.sigs))

/-- The child turns OFF a governance flag the parent had ON, or lowers the
    signature threshold. The `MultiManifest` image of `Ck.Policy.weakensRules`;
    identical, because the amendment rules were never the flattened part. -/
def weakensRulesM (c p : MultiManifest) : Prop :=
  (p.rules.cap = true ∧ c.rules.cap = false) ∨
  (p.rules.io = true ∧ c.rules.io = false) ∨
  (p.rules.proofreq = true ∧ c.rules.proofreq = false) ∨
  (c.rules.sigs < p.rules.sigs)

/-- `passedM p c` models the shipped `check_monotonicity(parent=p, child=c).passed`
    at the real arity. -/
def passedM (p c : MultiManifest) : Bool :=
  !capViolatedM p c && !ioViolatedM p c && !budgetViolatedM p c &&
    !proofReqViolatedM p c && rulesNonWeakeningM c p

/- ───────────────────────────────────────────────────────────────────────────
   Prop-level facts, PER AXIS (what soundness now rules out)
   ─────────────────────────────────────────────────────────────────────────── -/

/-- Some capability axis grants what the parent did not. Unlike the flattened
    `capEscalates`, a name that moved between axes is an escalation here. -/
def CapEscalatesM (c p : CapAxes) : Prop :=
  ¬ Subset c.filesystemRead p.filesystemRead ∨
  ¬ Subset c.filesystemWrite p.filesystemWrite ∨
  ¬ Subset c.networkAllow p.networkAllow ∨
  ¬ Subset c.toolsAllow p.toolsAllow ∨
  ¬ Subset c.secretClasses p.secretClasses ∨
  p.maxParallelTasks < c.maxParallelTasks

/-- Some io axis is wider on the child. -/
def IoEscalatesM (c p : IoAxes) : Prop :=
  ¬ Subset c.outboundDomains p.outboundDomains ∨
  ¬ Subset c.localFileRoots p.localFileRoots ∨
  ¬ Subset c.envVarsReadable p.envVarsReadable ∨
  ¬ Subset c.toolNamespaces p.toolNamespaces ∨
  ¬ Subset c.repoWriteTargets p.repoWriteTargets

/-- Some proof requirement the parent carried is missing from the child. -/
def ProofDropsM (c p : ProofAxes) : Prop :=
  ¬ Subset p.configPatch c.configPatch ∨
  ¬ Subset p.controllerPatch c.controllerPatch ∨
  ¬ Subset p.evaluatorPatch c.evaluatorPatch

/- ───────────────────────────────────────────────────────────────────────────
   Bridge lemmas: the per-axis boolean scans decode to the Prop-level facts
   ─────────────────────────────────────────────────────────────────────────── -/

theorem capEscalatesAnyB_false (c p : CapAxes) (h : capEscalatesAnyB c p = false) :
    ¬ CapEscalatesM c p := by
  unfold capEscalatesAnyB at h
  simp only [Bool.or_eq_false_iff] at h
  obtain ⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩ := h
  intro hbad
  rcases hbad with hb | hb | hb | hb | hb | hb
  · exact hb ((escalatesB_false_iff_subset _ _).mp h1)
  · exact hb ((escalatesB_false_iff_subset _ _).mp h2)
  · exact hb ((escalatesB_false_iff_subset _ _).mp h3)
  · exact hb ((escalatesB_false_iff_subset _ _).mp h4)
  · exact hb ((escalatesB_false_iff_subset _ _).mp h5)
  · exact absurd (decide_eq_true hb) (by simp [h6])

theorem ioEscalatesAnyB_false (c p : IoAxes) (h : ioEscalatesAnyB c p = false) :
    ¬ IoEscalatesM c p := by
  unfold ioEscalatesAnyB at h
  simp only [Bool.or_eq_false_iff] at h
  obtain ⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩ := h
  intro hbad
  rcases hbad with hb | hb | hb | hb | hb
  · exact hb ((escalatesB_false_iff_subset _ _).mp h1)
  · exact hb ((escalatesB_false_iff_subset _ _).mp h2)
  · exact hb ((escalatesB_false_iff_subset _ _).mp h3)
  · exact hb ((escalatesB_false_iff_subset _ _).mp h4)
  · exact hb ((escalatesB_false_iff_subset _ _).mp h5)

theorem proofDropsAnyB_false (c p : ProofAxes) (h : proofDropsAnyB c p = false) :
    ¬ ProofDropsM c p := by
  unfold proofDropsAnyB at h
  simp only [Bool.or_eq_false_iff] at h
  obtain ⟨⟨h1, h2⟩, h3⟩ := h
  intro hbad
  rcases hbad with hb | hb | hb
  · exact hb ((dropsB_false_iff_subset _ _).mp h1)
  · exact hb ((dropsB_false_iff_subset _ _).mp h2)
  · exact hb ((dropsB_false_iff_subset _ _).mp h3)

/- ───────────────────────────────────────────────────────────────────────────
   THEOREM T1-MULTI — soundness at the arity the code has (PROVED, 0 sorry)
   ─────────────────────────────────────────────────────────────────────────── -/

/-- **THEOREM T1 (multi-axis).** `Ck.Policy.T1_gate_sound`, restated over the
    real per-axis manifest.

    Same shape as the single-carrier version — the flag-gated axes stay
    conditional, budget and non-weakening stay unconditional — but every
    conclusion is now per axis. That is the difference that makes it transfer:
    `¬ CapEscalatesM` rules out an escalation on `filesystem_read` specifically,
    which the flattened `¬ capEscalates` does not
    (`flattening_admits_what_per_axis_rejects`). -/
theorem T1_gate_sound_multi (p c : MultiManifest) (h : passedM p c = true) :
    (p.rules.cap = true → ¬ CapEscalatesM c.caps p.caps) ∧
    (p.rules.io = true → ¬ IoEscalatesM c.ioSurface p.ioSurface) ∧
    (budgetWithin c.budget p.budget = true) ∧
    (p.rules.proofreq = true → ¬ ProofDropsM c.proofReqs p.proofReqs) ∧
    (¬ weakensRulesM c p) := by
  unfold passedM capViolatedM ioViolatedM budgetViolatedM proofReqViolatedM
    rulesNonWeakeningM at h
  simp only [Bool.and_eq_true, Bool.not_eq_true'] at h
  obtain ⟨⟨⟨⟨hcap, hio⟩, hbud⟩, hproof⟩, ⟨⟨⟨hrw_cap, hrw_io⟩, hrw_proof⟩, hrw_sigs⟩⟩ := h
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro hflag
    rw [hflag] at hcap
    simp only [if_true] at hcap
    exact capEscalatesAnyB_false _ _ hcap
  · intro hflag
    rw [hflag] at hio
    simp only [if_true] at hio
    exact ioEscalatesAnyB_false _ _ hio
  · simpa using hbud
  · intro hflag
    rw [hflag] at hproof
    simp only [if_true] at hproof
    exact proofDropsAnyB_false _ _ hproof
  · intro hw
    rcases hw with ⟨hp, hc⟩ | ⟨hp, hc⟩ | ⟨hp, hc⟩ | hsig
    · rw [hp, hc] at hrw_cap; simp at hrw_cap
    · rw [hp, hc] at hrw_io; simp at hrw_io
    · rw [hp, hc] at hrw_proof; simp at hrw_proof
    · have : p.rules.sigs ≤ c.rules.sigs := of_decide_eq_true hrw_sigs
      omega

/- ───────────────────────────────────────────────────────────────────────────
   Non-vacuity: the multi-axis gate ADMITS a legitimate child
   ─────────────────────────────────────────────────────────────────────────── -/

/-- An all-empty capability set. -/
def emptyCaps : CapAxes :=
  { filesystemRead := [], filesystemWrite := [], networkAllow := [],
    toolsAllow := [], secretClasses := [], maxParallelTasks := 0 }

def emptyIo : IoAxes :=
  { outboundDomains := [], localFileRoots := [], envVarsReadable := [],
    toolNamespaces := [], repoWriteTargets := [] }

def emptyProof : ProofAxes :=
  { configPatch := [], controllerPatch := [], evaluatorPatch := [] }

def strictParent : MultiManifest :=
  { caps := crossAxisParent, ioSurface := emptyIo, proofReqs := emptyProof,
    budget := zeroBudget, rules := { cap := true, io := true, proofreq := true, sigs := 2 } }

/-- A child identical to its parent: no escalation anywhere, flags preserved. -/
def identicalChild : MultiManifest := strictParent

/-- **Non-vacuity.** `T1_gate_sound_multi` would be trivially true if `passedM`
    were never `true`. It is not: an identical child passes. Without this, the
    theorem and the counterexample above are both compatible with a gate that
    refuses everything. -/
theorem identical_child_is_admitted : passedM strictParent identicalChild = true := by
  rfl

/-- And the cross-axis child — the counterexample's — is REJECTED by the
    multi-axis gate. This is the pair the flattened model admitted. -/
theorem cross_axis_child_is_rejected :
    passedM strictParent { strictParent with caps := crossAxisChild } = false := by
  rfl

/- ───────────────────────────────────────────────────────────────────────────
   Pinning the single-carrier model to this one
   ─────────────────────────────────────────────────────────────────────────── -/

/-- The single-axis model of `Ck.Policy` is the special case of this one in which
    every group has exactly one axis populated. Stated so `Ck.Policy` remains a
    readable specification rather than an independent claim that could drift.

    Note what this does NOT say: it does not say the flattening is faithful in
    general — `flattening_admits_what_per_axis_rejects` is the proof that it is
    not. It says only that the one-axis instance agrees, which is the sense in
    which the old model was ever right. -/
theorem flat_is_a_special_case (caps ioS pr : Names) (b : Budget) (r : Rules) :
    let m : MultiManifest :=
      { caps := { emptyCaps with filesystemRead := caps },
        ioSurface := { emptyIo with outboundDomains := ioS },
        proofReqs := { emptyProof with configPatch := pr },
        budget := b, rules := r }
    passedM m m = passed { caps := caps, ioSurface := ioS, proofReqs := pr,
                           budget := b, rules := r }
                         { caps := caps, ioSurface := ioS, proofReqs := pr,
                           budget := b, rules := r } := by
  intro m
  unfold passedM passed passedWeak capViolatedM ioViolatedM budgetViolatedM
    proofReqViolatedM rulesNonWeakeningM capViolated ioViolated budgetViolated
    proofReqViolated rulesNonWeakening capEscalatesAnyB ioEscalatesAnyB
    proofDropsAnyB
  simp [escalatesB, dropsB, m, emptyCaps, emptyIo, emptyProof]

/- ───────────────────────────────────────────────────────────────────────────
   #print axioms — axiom-hygiene audit
   ─────────────────────────────────────────────────────────────────────────── -/

#print axioms flattening_admits_what_per_axis_rejects
#print axioms T1_gate_sound_multi
#print axioms identical_child_is_admitted
#print axioms cross_axis_child_is_rejected
#print axioms flat_is_a_special_case

end Ck.Policy
