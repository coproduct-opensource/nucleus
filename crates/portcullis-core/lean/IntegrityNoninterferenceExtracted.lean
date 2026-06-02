/-
  Integrity Noninterference — proven OVER the Aeneas-EXTRACTED enforcement core.

  **STATUS: DRAFT / build-unverified.** The `#print axioms` commands at the
  bottom of this file emit the real axiom set to the CI log when the
  `lean-build` job runs against a v4.30.0-rc2 Mathlib cache. As of commit time
  that build had NOT been run, so the printed axiom set is UNCONFIRMED — do not
  read the expected `[propext, Quot.sound, Classical.choice]` as verified until
  the CI log shows it.

  This is the order-dual integrity-axis noninterference theorem, RE-PROVEN over
  the Aeneas-generated (from real Rust) definitions instead of a hand-written
  model. The chain is:

      crates/portcullis-core/src/extracted/ifc_integrity.rs   (real Rust)
        --charon (scoped, --start-from)-->  portcullis_core.llbc
        --aeneas -backend lean -split-files-->
          generated-ifc/PortcullisCoreIFC/{Types,Funs}.lean    (THIS file's deps)
        --(this file)-->  noninterference theorem over THOSE generated defs.

  The generated functions live in namespace `portcullis_core` and return the
  Aeneas `Result` monad. We prove every theorem in terms of THOSE functions
  (`extracted.ifc_integrity.{irank,imeet,iflows_to,irun_step}`), not a hand
  model. The only hand-written piece is the op-list fold `irun` (Aeneas does
  not extract the runtime's loop — slices are outside the scoped subgraph), and
  each fold step calls the GENERATED `irun_step`/`imeet`.

  # Ground truth this file is proven over (and the Rust↔model parity)

  The generated defs mirror the production enforcement (see the EXHAUSTIVE
  parity tests in `src/extracted/ifc_integrity.rs`, which assert the extracted
  `imeet`/`iflows_to`/`irank` equal the integrity axis of the real
  `IFCLabel::join`/`flows_to` and that `SinkClass::GitPush.required_integrity()
  = Trusted`). Those Rust tests close the model↔code gap; THIS file closes the
  property-over-extracted gap.

  # Scope boundary (the honest single-axis caveat)

  `IFCLabel::flows_to` is a CONJUNCTION over six axes; this theorem is about the
  INTEGRITY conjunct only. Because failure on one conjunct makes the whole
  `flows_to` false, "integrity alone blocks ⇒ admission denied" is sound. This
  is NOT the full multi-axis admission rule. The fold `irun` is hand-written
  Lean over the GENERATED step; the per-step decision and the admission check
  are the generated-from-Rust functions.
-/

import PortcullisCoreIFC.Types
import PortcullisCoreIFC.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

namespace IntegrityNoninterferenceExtracted

/-- Short alias for the Aeneas-generated integrity enum (from real Rust). -/
abbrev IL := portcullis_core.extracted.ifc_integrity.IntegLevel

/-- The generated `irank`, evaluated. Each of the three points reduces to its
    `#[repr(u8)]` discriminant inside the `Result` monad. These are `rfl` (the
    generated `def` is a literal `match`), establishing the rank values we then
    reason about. -/
theorem irank_adv :
    portcullis_core.extracted.ifc_integrity.irank IL.Adversarial = ok 0#u8 := rfl
theorem irank_unt :
    portcullis_core.extracted.ifc_integrity.irank IL.Untrusted = ok 1#u8 := rfl
theorem irank_tru :
    portcullis_core.extracted.ifc_integrity.irank IL.Trusted = ok 2#u8 := rfl

/-- A pure-Lean rank mirroring the generated `irank`'s value (proved equal to
    the generated def in `rank_eq` below). Used to drive `omega`. -/
def rankN : IL → Nat
  | IL.Adversarial => 0
  | IL.Untrusted => 1
  | IL.Trusted => 2

/-- The generated `irank l` is `ok (rankN l)` for every label. Bridges the
    `Result`/`U8` encoding to a plain `Nat` we can feed to `omega`. -/
theorem rank_eq (l : IL) :
    portcullis_core.extracted.ifc_integrity.irank l = ok (UScalar.ofNat .U8 (rankN l)) := by
  cases l <;> rfl

/-- The generated `imeet` always succeeds and returns one of its arguments —
    specifically the one of lesser-or-equal rank (taint pulls trust DOWN).
    Proved by case-splitting all 9 label pairs and reducing the generated
    `do`-block. -/
theorem imeet_ok (a b : IL) :
    portcullis_core.extracted.ifc_integrity.imeet a b
      = ok (if rankN a ≤ rankN b then a else b) := by
  cases a <;> cases b <;> decide

/-- **Local step antitonicity**, over the GENERATED `imeet`. A single fold step
    can only lower (never raise) the running integrity rank. Order-dual of
    `le_join_left`. The result of the generated `imeet` has rank ≤ `rankN a`. -/
theorem istep_antitone (a b : IL) :
    ∀ r, portcullis_core.extracted.ifc_integrity.imeet a b = ok r → rankN r ≤ rankN a := by
  intro r h
  rw [imeet_ok] at h
  -- h : ok (if rankN a ≤ rankN b then a else b) = ok r
  by_cases hab : rankN a ≤ rankN b
  · simp [hab] at h; subst h; omega
  · simp [hab] at h; subst h
    -- r = b, and ¬ (rankN a ≤ rankN b) ⇒ rankN b ≤ rankN a
    omega

/-- Fold the GENERATED `irun_step` over an operation list, threading the running
    effective integrity. Aeneas does not extract the runtime's slice-based loop
    (slices leave the scoped subgraph), so the fold itself is hand-written Lean —
    but each step IS the generated-from-Rust `irun_step` (= generated `imeet`).
    Total because the generated step always returns `ok`. -/
def irun : List IL → IL → IL
  | [], eff => eff
  | src :: rest, eff =>
      irun rest
        (match portcullis_core.extracted.ifc_integrity.irun_step eff src with
         | ok r => r
         | _ => eff)

/-- The generated `irun_step` reduces to the generated `imeet` result. -/
theorem irun_step_ok (eff src : IL) :
    portcullis_core.extracted.ifc_integrity.irun_step eff src
      = ok (if rankN eff ≤ rankN src then eff else src) := by
  unfold portcullis_core.extracted.ifc_integrity.irun_step
  rw [imeet_ok]

/-- One `irun` cons step lowers the rank, via the GENERATED step. -/
theorem irun_cons_step_antitone (eff src : IL) :
    rankN (match portcullis_core.extracted.ifc_integrity.irun_step eff src with
           | ok r => r | _ => eff) ≤ rankN eff := by
  rw [irun_step_ok]
  by_cases h : rankN eff ≤ rankN src <;> simp [h] <;> omega

/-- **Global composition** over the GENERATED step. Over ANY operation
    sequence, the running effective integrity rank never exceeds the starting
    rank — taint only ratchets DOWN. Structural induction; cons step combines
    the IH with `irun_cons_step_antitone`, chained by `omega`. -/
theorem irun_antitone :
    ∀ (ops : List IL) (eff : IL), rankN (irun ops eff) ≤ rankN eff := by
  intro ops
  induction ops with
  | nil => intro eff; simp [irun]
  | cons src rest ih =>
      intro eff
      simp only [irun]
      have h_tail := ih (match portcullis_core.extracted.ifc_integrity.irun_step eff src with
                         | ok r => r | _ => eff)
      have h_step := irun_cons_step_antitone eff src
      omega

/-- Sink admission, over the GENERATED `iflows_to`: the running effective
    integrity flows to the sink's required integrity. With
    `req = SinkClass::GitPush.required_integrity() = Trusted`, this is the EXACT
    integrity conjunct of the production gate. The generated `iflows_to` returns
    `ok true` iff `rankN eff ≥ rankN req`. -/
theorem iflows_to_ok (a ceiling : IL) :
    portcullis_core.extracted.ifc_integrity.iflows_to a ceiling
      = ok (decide (rankN ceiling ≤ rankN a)) := by
  cases a <;> cases ceiling <;> decide

/-- Admission holds iff the generated `iflows_to` returns `ok true`. -/
def iadmitted (eff req : IL) : Prop :=
    portcullis_core.extracted.ifc_integrity.iflows_to eff req = ok true

/-- **Integrity-axis noninterference (main theorem), over the GENERATED defs.**

    If the session's current effective integrity is already no more trusted than
    a joined-in source `L_src` (`rankN eff ≤ rankN L_src`), and that source fails
    the sink's integrity ceiling NON-vacuously (`rankN L_src < rankN req`), then
    over ANY operation sequence the sink is NEVER admitted by the GENERATED
    `iflows_to`. Closed by `omega` transitivity over `irun_antitone`. -/
theorem integrity_sink_never_admitted
    (L_src eff req : IL) (ops : List IL)
    (h_joined : rankN eff ≤ rankN L_src)
    (h_blocked : rankN L_src < rankN req) :
    ¬ iadmitted (irun ops eff) req := by
  intro h_admit
  unfold iadmitted at h_admit
  rw [iflows_to_ok] at h_admit
  -- h_admit : ok (decide (rankN req ≤ rankN (irun ops eff))) = ok true
  have h_flow : rankN req ≤ rankN (irun ops eff) := by
    have : decide (rankN req ≤ rankN (irun ops eff)) = true := by
      injection h_admit
    exact of_decide_eq_true this
  have h_ratchet : rankN (irun ops eff) ≤ rankN eff := irun_antitone ops eff
  omega

/-- **Instantiation: a web-content-tainted session can NEVER git-push**, over
    the GENERATED defs. A session whose effective integrity is `Adversarial`
    (rank 0 — the label web-scraping / public-issue content carries) is never
    admitted at the GitPush sink, whose `required_integrity` is `Trusted`
    (rank 2; see the Rust parity test `gitpush_requires_trusted`), over ANY
    operation sequence. Non-vacuous: `h_joined = 0 ≤ 0`, `h_blocked = 0 < 2`. -/
theorem web_tainted_never_git_pushes (ops : List IL) :
    ¬ iadmitted (irun ops IL.Adversarial) IL.Trusted := by
  apply integrity_sink_never_admitted
    (L_src := IL.Adversarial)
    (eff := IL.Adversarial)
    (req := IL.Trusted)
    (ops := ops)
  · decide
  · decide

end IntegrityNoninterferenceExtracted

/-
  Axiom audit. These commands print the FULL transitive axiom set the kernel
  used to accept each theorem. The CI `lean-build` job captures their real
  output to the log. The EXPECTED set is exactly:

      [propext, Quot.sound, Classical.choice]

  Anything else — in particular `sorryAx` (a proof hole) or any
  Aeneas-emitted opaque `*External` axiom — MUST fail review. The `extracted/`
  Rust deliberately uses an explicit `irank(a) <= irank(b)` comparison rather
  than a derived `Ord`, so Aeneas emits a translated body (no opaque comparison
  axiom); `generated-ifc/` contains no `FunsExternal_Template.lean`, so there
  are no opaque-function holes to leak in here.

  HONESTY NOTE: at the time this file was committed the build had NOT yet run
  on a host with a v4.30.0-rc2 Mathlib cache, so the ACTUAL printed axiom set
  was UNVERIFIED. Do not treat the expected list above as confirmed until the
  CI log shows it.
-/
#print axioms IntegrityNoninterferenceExtracted.integrity_sink_never_admitted
#print axioms IntegrityNoninterferenceExtracted.web_tainted_never_git_pushes
