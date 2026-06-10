/-
  CkPolicyAeneas — soundness of the Aeneas-EXTRACTED Constitutional Kernel
  monotonicity-gate CORE (the tier-1 DEDUCTIVE bridge).

  **STATUS: PROVED (0 `sorry`, 0 `native_decide`).**

  Unlike `crates/ck-policy/lean/Ck/Policy.lean` (which proves soundness over a
  HAND-WRITTEN model), every theorem here is proved DIRECTLY over the
  Charon+Aeneas-GENERATED definitions in `generated/CkPolicy/Funs.lean`:
  `ck_policy.extracted.passed_core`, `.cap_violated`, `.io_violated`,
  `.budget_violated`, `.proofreq_violated`, `.subset_u32`, `.dropped_u32`,
  `.budget_within`, `.rules_non_weakening`. Those Lean defs are a mechanical
  Charon (MIR→LLBC) + Aeneas (LLBC→Lean) translation of the real Rust in
  `crates/ck-policy/src/extracted.rs` — NOT a hand transcription.

  ────────────────────────────────────────────────────────────────────────────
  THE THREE HONESTY TIERS (DO NOT CONFLATE)
  ────────────────────────────────────────────────────────────────────────────

  * DEDUCTIVE (tier-1, THIS FILE). Lean theorems proved about the extracted
    model. `T1_extracted_gate_sound` is the analogue of `Ck.Policy.T1_gate_sound`
    but over the GENERATED `passed_core`, decomposing the gate verdict into the
    safe return value of every generated safety scan, and fully DECODING the
    loop-free `rules_non_weakening` into the Prop-level anti-coup guarantee.

  * STATISTICAL (tier-4, sampled). The extracted core is bound to the PRODUCTION
    `ck_policy::check_monotonicity` (over `BTreeSet<String>` manifests — NOT
    extractable) by the parity proptest in
    `crates/ck-policy/tests/policy_aeneas_parity.rs` (≥2048 randomized manifest
    pairs). A proptest is NOT a proof; it narrows the model↔production gap
    probabilistically.

  The honest end-to-end claim: a self-contained, monomorphized core that
  faithfully mirrors the gate's verdict was extracted by Charon+Aeneas AND proven
  sound in Lean; that core is bound to production `check_monotonicity` by a parity
  proptest. It is NOT "the literal `check_monotonicity` was verified": that
  function uses `BTreeSet<String>`/generics the Aeneas Lean backend cannot
  translate.

  TCB caveat — verified Rust != verified binary. These theorems trust Charon,
  Aeneas, the Lean kernel, and rustc (which compiles the production binary). They
  are about the extracted model of the source, not the running machine code.

  ────────────────────────────────────────────────────────────────────────────
  MATHLIB POSTURE (HONEST)
  ────────────────────────────────────────────────────────────────────────────

  The Aeneas Lean STANDARD LIBRARY (`import Aeneas`, supplying `Result`, `U32`,
  `Slice`, `Array`, the `loop` combinator) transitively `require`s Mathlib at the
  pinned commit — UNAVOIDABLE, identical to the `crates/portcullis-core/lean`
  precedent. "Mathlib-free" here is a PROOF-DISCIPLINE claim: the proofs below use
  only structural `cases`/`split_ifs`/`injection`/`Bool` reasoning + Aeneas Std
  bind lemmas — NO Mathlib lemmas, NO `native_decide`, NO `sorry`/`admit`. The
  sibling hand-written package (`crates/ck-policy/lean`) is fully Mathlib-free.
-/

import CkPolicy.Types
import CkPolicy.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

set_option maxHeartbeats 2000000

namespace CkPolicyAeneas

/- ───────────────────────────────────────────────────────────────────────────
   Result-monad plumbing (Mathlib-free)
   ─────────────────────────────────────────────────────────────────────────── -/

/-- A `do`-bind that yields `ok b` decomposes: the bound result was `ok v` for
    some `v`, and the continuation on `v` yields `ok b`. -/
theorem bind_eq_ok {α β} (x : Result α) (f : α → Result β) (b : β)
    (h : (Bind.bind x f) = ok b) : ∃ v, x = ok v ∧ f v = ok b := by
  cases x with
  | ok v => exact ⟨v, rfl, h⟩
  | fail e => simp only [bind_tc_fail] at h; cases h
  | div => simp only [bind_tc_div] at h; cases h

/- ───────────────────────────────────────────────────────────────────────────
   STEP 1 — Structural decomposition of the GENERATED `passed_core` verdict.

   This is pure monadic + if-chain reasoning over the extracted def; NO loop
   induction. It says: the gate passing forces EVERY generated safety scan to
   have returned its safe value.
   ─────────────────────────────────────────────────────────────────────────── -/

/-- **Decomposition lemma (PROVED).** If the GENERATED `passed_core` returns
    `ok true`, then each of the generated component verdicts returned its safe
    value: cap/io/proofreq/budget all `ok false` (not violated), and
    `rules_non_weakening` returned `ok true`. The flag projections from
    `parent_flags` succeeded (`ok` of some bool), and the per-axis violation
    checks were evaluated on EXACTLY those projected flags. -/
theorem passed_core_decomp
    (pf cf : Array Bool 3#usize)
    (pcap ccap pio cio ppr cpr : Slice U32)
    (pb cb : Array U64 8#usize)
    (h : ck_policy.extracted.passed_core pf cf pcap ccap pio cio ppr cpr pb cb = ok true) :
    (∃ f0, pf.index_usize 0#usize = ok f0 ∧
        ck_policy.extracted.cap_violated f0 ccap pcap = ok false) ∧
    (∃ f1, pf.index_usize 1#usize = ok f1 ∧
        ck_policy.extracted.io_violated f1 cio pio = ok false) ∧
    (ck_policy.extracted.budget_violated cb pb = ok false) ∧
    (∃ f2, pf.index_usize 2#usize = ok f2 ∧
        ck_policy.extracted.proofreq_violated f2 cpr ppr = ok false) ∧
    (ck_policy.extracted.rules_non_weakening pf cf = ok true) := by
  unfold ck_policy.extracted.passed_core at h
  obtain ⟨v1, e1, h⟩ := bind_eq_ok _ _ _ h    -- v1 = pf[0]
  obtain ⟨v2, e2, h⟩ := bind_eq_ok _ _ _ h    -- v2 = cap_violated v1
  obtain ⟨v3, e3, h⟩ := bind_eq_ok _ _ _ h    -- v3 = pf[1]
  obtain ⟨v4, e4, h⟩ := bind_eq_ok _ _ _ h    -- v4 = io_violated v3
  obtain ⟨v5, e5, h⟩ := bind_eq_ok _ _ _ h    -- v5 = budget_violated
  obtain ⟨v6, e6, h⟩ := bind_eq_ok _ _ _ h    -- v6 = pf[2]
  obtain ⟨v7, e7, h⟩ := bind_eq_ok _ _ _ h    -- v7 = proofreq_violated v6
  obtain ⟨v8, e8, h⟩ := bind_eq_ok _ _ _ h    -- v8 = rules_non_weakening
  -- The remaining `h` is the nested if-chain forced to `ok true`.
  -- `split_ifs` yields one branch per guard. EVERY violation branch carries
  -- `h : ok false = ok true` (impossible); only the all-passed branch survives,
  -- with each guard `cᵢ : ¬ (vᵢ = true)` and `h : ok v8 = ok true`.
  split_ifs at h with c2 c4 c5 c7
  -- The all-passed branch (`case neg`): every guard discharged its violation.
  case neg =>
    have hv8 : v8 = true := by injection h
    have hv2 : v2 = false := by cases v2 with | false => rfl | true => exact absurd rfl c2
    have hv4 : v4 = false := by cases v4 with | false => rfl | true => exact absurd rfl c4
    have hv5 : v5 = false := by cases v5 with | false => rfl | true => exact absurd rfl c5
    have hv7 : v7 = false := by cases v7 with | false => rfl | true => exact absurd rfl c7
    subst hv8
    refine ⟨⟨v1, e1, ?_⟩, ⟨v3, e3, ?_⟩, ?_, ⟨v6, e6, ?_⟩, e8⟩
    · rw [e2, hv2]
    · rw [e4, hv4]
    · rw [e5, hv5]
    · rw [e7, hv7]
  -- Every other (violation) branch contradicts `ok false = ok true`.
  all_goals (exfalso; cases h)

/- ───────────────────────────────────────────────────────────────────────────
   STEP 2 — Decode the loop-free generated functions to Prop-level guarantees.

   `cap_violated` / `io_violated` / `proofreq_violated` peel off the parent flag
   (an `if parent_flag then <scan> else ok false`); with the flag ON, "not
   violated" forces the underlying GENERATED scan to its safe value. NO loop
   induction is needed for this peel — the scan stays as a generated call.
   ─────────────────────────────────────────────────────────────────────────── -/

/-- With the parent capability flag ON, "cap axis not violated" (the generated
    `cap_violated` returning `ok false`) forces the GENERATED `subset_u32` scan
    of child-over-parent to succeed (`ok true`) — no capability escalation. -/
theorem cap_not_violated_flag_on
    (child parent : Slice U32)
    (h : ck_policy.extracted.cap_violated true child parent = ok false) :
    ck_policy.extracted.subset_u32 child parent = ok true := by
  unfold ck_policy.extracted.cap_violated at h
  simp only [if_true] at h
  obtain ⟨v, ev, h⟩ := bind_eq_ok _ _ _ h
  -- h : ok (¬ v) = ok false  ⇒  v = true (the scan succeeded).
  rw [ev]
  cases v with
  | true => rfl
  | false => simp_all

/-- With the parent io flag ON, "io axis not violated" forces the GENERATED
    `subset_u32` scan to succeed — no io-surface widening. -/
theorem io_not_violated_flag_on
    (child parent : Slice U32)
    (h : ck_policy.extracted.io_violated true child parent = ok false) :
    ck_policy.extracted.subset_u32 child parent = ok true := by
  unfold ck_policy.extracted.io_violated at h
  simp only [if_true] at h
  obtain ⟨v, ev, h⟩ := bind_eq_ok _ _ _ h
  rw [ev]
  cases v with
  | true => rfl
  | false => simp_all

/-- With the parent proofreq flag ON, "proofreq axis not violated" forces the
    GENERATED `dropped_u32` scan to report NO dropped requirement (`ok false`). -/
theorem proofreq_not_violated_flag_on
    (child parent : Slice U32)
    (h : ck_policy.extracted.proofreq_violated true child parent = ok false) :
    ck_policy.extracted.dropped_u32 child parent = ok false := by
  unfold ck_policy.extracted.proofreq_violated at h
  simp only [if_true] at h
  exact h

/-- Budget "not violated" forces the GENERATED `budget_within` scan to succeed
    (`ok true`) — every child bound is within the parent's. Unconditional (no
    gating flag), matching the production gate. -/
theorem budget_not_violated
    (child parent : Array U64 8#usize)
    (h : ck_policy.extracted.budget_violated child parent = ok false) :
    ck_policy.extracted.budget_within child parent = ok true := by
  unfold ck_policy.extracted.budget_violated at h
  obtain ⟨v, ev, h⟩ := bind_eq_ok _ _ _ h
  rw [ev]
  cases v with
  | true => rfl
  | false => simp_all

/- ───────────────────────────────────────────────────────────────────────────
   STEP 3 — FULL DECODE of the loop-free `rules_non_weakening` (the anti-coup
   crux). This generated function is pure array indexing (NO loop), so it decodes
   completely to the Prop-level non-weakening guarantee, which is the T4
   anti-self-weakening property carried by the SHIPPED gate.
   ─────────────────────────────────────────────────────────────────────────── -/

/-- `weakensFlags parent child`: the child DISABLES a governance flag the parent
    had ON, on at least one of the three amendment-rule axes (cap/io/proofreq).
    This is exactly what the unconditional `rules_non_weakening` must forbid. -/
def weakensFlags (parent child : Array Bool 3#usize) : Prop :=
  (parent.val[0]! = true ∧ child.val[0]! = false) ∨
  (parent.val[1]! = true ∧ child.val[1]! = false) ∨
  (parent.val[2]! = true ∧ child.val[2]! = false)

/-- The GENERATED `rules_non_weakening` evaluates (via three literal-index reads
    of length-3 arrays) to the boolean conjunction
    `(¬p0 ∨ c0) ∧ (¬p1 ∨ c1) ∧ (¬p2 ∨ c2)` over the array elements. This pins
    the generated def's value to the elementwise flags it reads. -/
theorem rules_non_weakening_val (parent child : Array Bool 3#usize) :
    ck_policy.extracted.rules_non_weakening parent child =
      ok (((!parent.val[0]! || child.val[0]!) &&
           (!parent.val[1]! || child.val[1]!) &&
           (!parent.val[2]! || child.val[2]!))) := by
  have hp := parent.property
  have hc := child.property
  -- Length-3 arrays: name the three elements of each carrier list.
  obtain ⟨p0, p1, p2, hpe⟩ :
      ∃ p0 p1 p2, parent.val = [p0, p1, p2] := by
    rcases parent with ⟨l, hl⟩
    match l, hl with
    | [a, b, c], _ => exact ⟨a, b, c, rfl⟩
  obtain ⟨c0, c1, c2, hce⟩ :
      ∃ c0 c1 c2, child.val = [c0, c1, c2] := by
    rcases child with ⟨l, hl⟩
    match l, hl with
    | [a, b, c], _ => exact ⟨a, b, c, rfl⟩
  unfold ck_policy.extracted.rules_non_weakening
  simp only [Array.index_usize, hpe, hce]
  -- Reduce the option-indexing and the if-chain; both sides are concrete.
  cases p0 <;> cases p1 <;> cases p2 <;> cases c0 <;> cases c1 <;> cases c2 <;>
    simp_all

/-- **Anti-coup soundness (PROVED), loop-free decode.** If the GENERATED
    `rules_non_weakening parent child` returns `ok true`, then the child does
    NOT weaken any governance flag the parent enabled. This is the deductive
    image, over the EXTRACTED def, of the unconditional non-weakening conjunct
    that closes the two-step coup. -/
theorem rules_non_weakening_sound (parent child : Array Bool 3#usize)
    (h : ck_policy.extracted.rules_non_weakening parent child = ok true) :
    ¬ weakensFlags parent child := by
  rw [rules_non_weakening_val] at h
  have hb : ((!parent.val[0]! || child.val[0]!) &&
             (!parent.val[1]! || child.val[1]!) &&
             (!parent.val[2]! || child.val[2]!)) = true := by injection h
  intro hw
  rcases hw with ⟨hp, hc⟩ | ⟨hp, hc⟩ | ⟨hp, hc⟩ <;>
    rw [hp, hc] at hb <;> simp at hb

/- ───────────────────────────────────────────────────────────────────────────
   THEOREM T1 — soundness of the EXTRACTED gate (PROVED, 0 sorry, 0 native_decide)

   The analogue of `Ck.Policy.T1_gate_sound`, but proved over the GENERATED
   `passed_core`. Combines STEP 1 (decomposition) + STEP 2 (loop-free peels) +
   STEP 3 (full anti-coup decode).
   ─────────────────────────────────────────────────────────────────────────── -/

/-- **THEOREM T1_extracted_gate_sound (PROVED).** If the GENERATED `passed_core`
    returns `ok true`, then:

      1. if the parent capability flag is ON, the generated `subset_u32` scan of
         child-caps over parent-caps SUCCEEDS — no capability escalation;
      2. if the parent io flag is ON, the generated `subset_u32` scan SUCCEEDS —
         no io-surface widening;
      3. the generated `budget_within` scan SUCCEEDS — child budget within parent
         (UNCONDITIONAL, no gating flag);
      4. if the parent proofreq flag is ON, the generated `dropped_u32` scan
         reports NO dropped requirement;
      5. the child does NOT weaken any governance flag the parent enabled
         (`¬ weakensFlags` — UNCONDITIONAL; the anti-coup T4 fix).

    The flag conditions (1,2,4) reference the parent flags at the GENERATED array
    indices `pf[0]/[1]/[2]`. Guarantees (3) and (5) are unconditional, exactly
    as in `Ck.Policy.T1_gate_sound`. -/
theorem T1_extracted_gate_sound
    (pf cf : Array Bool 3#usize)
    (pcap ccap pio cio ppr cpr : Slice U32)
    (pb cb : Array U64 8#usize)
    (h : ck_policy.extracted.passed_core pf cf pcap ccap pio cio ppr cpr pb cb = ok true) :
    (pf.index_usize 0#usize = ok true →
        ck_policy.extracted.subset_u32 ccap pcap = ok true) ∧
    (pf.index_usize 1#usize = ok true →
        ck_policy.extracted.subset_u32 cio pio = ok true) ∧
    (ck_policy.extracted.budget_within cb pb = ok true) ∧
    (pf.index_usize 2#usize = ok true →
        ck_policy.extracted.dropped_u32 cpr ppr = ok false) ∧
    (¬ weakensFlags pf cf) := by
  obtain ⟨⟨f0, e0, hcap⟩, ⟨f1, e1, hio⟩, hbud, ⟨f2, e2, hpr⟩, hrules⟩ :=
    passed_core_decomp pf cf pcap ccap pio cio ppr cpr pb cb h
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · -- capability axis
    intro hflag
    have : f0 = true := by rw [e0] at hflag; injection hflag
    subst this
    exact cap_not_violated_flag_on ccap pcap hcap
  · -- io axis
    intro hflag
    have : f1 = true := by rw [e1] at hflag; injection hflag
    subst this
    exact io_not_violated_flag_on cio pio hio
  · -- budget axis — unconditional
    exact budget_not_violated cb pb hbud
  · -- proof-requirement axis
    intro hflag
    have : f2 = true := by rw [e2] at hflag; injection hflag
    subst this
    exact proofreq_not_violated_flag_on cpr ppr hpr
  · -- amendment-rules non-weakening — UNCONDITIONAL
    exact rules_non_weakening_sound pf cf hrules

/- ───────────────────────────────────────────────────────────────────────────
   #print axioms — kernel-checked axiom-hygiene audit (no sorryAx, no
   native_decide-introduced axioms).
   ─────────────────────────────────────────────────────────────────────────── -/

#print axioms passed_core_decomp
#print axioms rules_non_weakening_sound
#print axioms budget_not_violated
#print axioms T1_extracted_gate_sound

end CkPolicyAeneas
