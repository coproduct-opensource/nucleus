/-
  Authority Noninterference — proven OVER the Aeneas-EXTRACTED enforcement core
  (order-twin of IntegrityNoninterferenceExtracted; the SECOND contravariant
  "trust" axis, and the half of the anti-prompt-injection guarantee that was
  proven over a hand model only until this slice).

  **STATUS: to be verified by CI.** The `aeneas-ifc-scoped` CI job extracts the
  authority functions (`EXTRACT_ROOTS` includes
  `ifc_authority::{aflows_to, ameet, arun_step}`) and builds this file
  (`lake build AuthorityNoninterferenceExtracted`). The `#print axioms` audit at
  the bottom must print, for BOTH theorems:

      [propext, Classical.choice, Quot.sound]

  No `sorryAx`, no Aeneas `*External` opaque axiom — the `Assert clean axiom set`
  gate reads `/tmp/lake-auth-ifc.log` and fails otherwise. This is the order-twin
  of the VERIFIED integrity theorem and discharges by the SAME tactics over the
  Aeneas-generated defs (authority is contravariant exactly like integrity).

  The chain:

      crates/nucleus-ifc-kernel/src/extracted/ifc_authority.rs   (real Rust)
        --charon (scoped, --start-from)-->  nucleus_ifc_kernel.llbc
        --aeneas -backend lean -split-files-->
          generated-ifc/PortcullisCoreIFC/{Types,Funs}.lean   (THIS file's deps)
        --(this file)-->  authority noninterference over THOSE generated defs.

  # Why this is NOT a copy of the integrity proof (same shape, different axis)

  Integrity answers "is this data TRUSTED?"; authority answers "may this data
  DIRECT the agent?". They are distinct conjuncts of `IFCLabel::flows_to`. Both
  are contravariant (`ameet` = MIN, combining LOWERS authority, the fold is
  ANTITONE, `aflows_to a c = rank c ≤ rank a`), so the proof shape matches
  integrity's — but the axis, the 4-point chain, and the instantiation differ.
  The main theorem: web content (`NoAuthority`) can never be laundered into a
  `Directive`-privileged action over any op sequence — indirect prompt injection
  cannot acquire instruction authority.

  # Ground truth + scope boundary

  The generated defs mirror production by the EXHAUSTIVE parity tests in
  `src/extracted/ifc_authority.rs` (`ameet`/`aflows_to`/`arank` == the authority
  axis of the real `IFCLabel::join`/`flows_to`). `IFCLabel::flows_to` is a
  five-axis conjunction; this theorem is the AUTHORITY conjunct only — "authority
  alone blocks ⇒ admission denied" is sound because one false conjunct makes the
  whole `flows_to` false. The fold `arun` is hand-written Lean over the GENERATED
  step (Aeneas does not extract the runtime's slice loop).
-/

import PortcullisCoreIFC.Types
import PortcullisCoreIFC.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

-- The 16-case `rfl` reductions below unfold the generated `do`/`Result` binds
-- and reduce concrete `U8` comparisons in the kernel; give them headroom.
set_option maxHeartbeats 1000000

namespace AuthorityNoninterferenceExtracted

/-- Short alias for the Aeneas-generated authority enum (from real Rust). -/
abbrev AL := nucleus_ifc_kernel.extracted.ifc_authority.AuthorityLevel

/-- The generated `arank`, evaluated. Each of the four points reduces to its
    `#[repr(u8)]` discriminant inside the `Result` monad. These are `rfl` (the
    generated `def` is a literal `match`), establishing the rank values we then
    reason about. -/
theorem arank_no :
    nucleus_ifc_kernel.extracted.ifc_authority.arank .NoAuthority = ok 0#u8 := rfl
theorem arank_inf :
    nucleus_ifc_kernel.extracted.ifc_authority.arank .Informational = ok 1#u8 := rfl
theorem arank_sug :
    nucleus_ifc_kernel.extracted.ifc_authority.arank .Suggestive = ok 2#u8 := rfl
theorem arank_dir :
    nucleus_ifc_kernel.extracted.ifc_authority.arank .Directive = ok 3#u8 := rfl

/-- A pure-Lean rank mirroring the generated `arank`'s value (the generated
    `arank l` reduces to `ok (rankN l)#u8`, see `ameet_ok`/`aflows_to_ok`). Used
    to drive `omega`. -/
def rankN : AL → Nat
  | .NoAuthority => 0
  | .Informational => 1
  | .Suggestive => 2
  | .Directive => 3

/-- The generated `ameet` always succeeds and returns one of its arguments —
    specifically the one of lesser-or-equal rank (combining LOWERS authority).
    Proved by case-splitting all 16 label pairs and reducing the generated
    `do`-block. -/
theorem ameet_ok (a b : AL) :
    nucleus_ifc_kernel.extracted.ifc_authority.ameet a b
      = ok (if rankN a ≤ rankN b then a else b) := by
  -- Each of the 16 concrete pairs: unfold the generated `do`-binds (`arank` →
  -- `ok n#u8`, `Result.bind (ok _)` → iota) and reduce the concrete `U8`
  -- comparison; both sides normalize to the same `ok _`. `rfl` (not `decide`:
  -- `Result` derives only `Repr, BEq`, not `DecidableEq`).
  cases a <;> cases b <;> rfl

/-- **Local step antitonicity**, over the GENERATED `ameet`. A single fold step
    can only lower (never raise) the running authority rank. The result of the
    generated `ameet` has rank ≤ `rankN a`. -/
theorem astep_antitone (a b : AL) :
    ∀ r, nucleus_ifc_kernel.extracted.ifc_authority.ameet a b = ok r → rankN r ≤ rankN a := by
  intro r h
  rw [ameet_ok] at h
  -- h : ok (if rankN a ≤ rankN b then a else b) = ok r
  by_cases hab : rankN a ≤ rankN b
  · simp [hab] at h; subst h; omega
  · simp [hab] at h; subst h
    -- r = b, and ¬ (rankN a ≤ rankN b) ⇒ rankN b ≤ rankN a
    omega

/-- Fold the GENERATED `arun_step` over an operation list, threading the running
    effective authority. Aeneas does not extract the runtime's slice-based loop
    (slices leave the scoped subgraph), so the fold itself is hand-written Lean —
    but each step IS the generated-from-Rust `arun_step` (= generated `ameet`).
    Total because the generated step always returns `ok`. -/
def arun : List AL → AL → AL
  | [], eff => eff
  | src :: rest, eff =>
      arun rest
        (match nucleus_ifc_kernel.extracted.ifc_authority.arun_step eff src with
         | ok r => r
         | _ => eff)

/-- The generated `arun_step` reduces to the generated `ameet` result. -/
theorem arun_step_ok (eff src : AL) :
    nucleus_ifc_kernel.extracted.ifc_authority.arun_step eff src
      = ok (if rankN eff ≤ rankN src then eff else src) := by
  unfold nucleus_ifc_kernel.extracted.ifc_authority.arun_step
  rw [ameet_ok]

/-- One `arun` cons step lowers the rank, via the GENERATED step. -/
theorem arun_cons_step_antitone (eff src : AL) :
    rankN (match nucleus_ifc_kernel.extracted.ifc_authority.arun_step eff src with
           | ok r => r | _ => eff) ≤ rankN eff := by
  rw [arun_step_ok]
  -- `match ok X with | ok r => r | _ => eff` reduces (iota) to `X`; `show` forces it.
  show rankN (if rankN eff ≤ rankN src then eff else src) ≤ rankN eff
  split <;> omega

/-- **Global composition** over the GENERATED step. Over ANY operation sequence,
    the running effective authority rank never exceeds the starting rank —
    authority only ratchets DOWN. Structural induction; cons step combines the
    IH with `arun_cons_step_antitone`, chained by `omega`. -/
theorem arun_antitone :
    ∀ (ops : List AL) (eff : AL), rankN (arun ops eff) ≤ rankN eff := by
  intro ops
  induction ops with
  | nil => intro eff; simp [arun]
  | cons src rest ih =>
      intro eff
      simp only [arun]
      have h_tail := ih (match nucleus_ifc_kernel.extracted.ifc_authority.arun_step eff src with
                         | ok r => r | _ => eff)
      have h_step := arun_cons_step_antitone eff src
      omega

/-- Sink admission, over the GENERATED `aflows_to`: the running effective
    authority flows to the sink's required authority. With `req = Directive`,
    this is the EXACT authority conjunct of the production gate for a
    directive-privileged action. The generated `aflows_to` returns `ok true` iff
    `rankN eff ≥ rankN req`. -/
theorem aflows_to_ok (a ceiling : AL) :
    nucleus_ifc_kernel.extracted.ifc_authority.aflows_to a ceiling
      = ok (decide (rankN ceiling ≤ rankN a)) := by
  -- As with `ameet_ok`: 16 concrete pairs, both sides reduce to the same
  -- `ok true` / `ok false` (the generated `a >= a1` Bool matches the decided
  -- `rankN ceiling ≤ rankN a`). `rfl`, since `Result` lacks `DecidableEq`.
  cases a <;> cases ceiling <;> rfl

/-- Admission holds iff the generated `aflows_to` returns `ok true`. -/
def aadmitted (eff req : AL) : Prop :=
    nucleus_ifc_kernel.extracted.ifc_authority.aflows_to eff req = ok true

/-- **Authority-axis noninterference (main theorem), over the GENERATED defs.**

    If the session's current effective authority is already no more authoritative
    than a joined-in source `L_src` (`rankN eff ≤ rankN L_src`), and that source
    fails the sink's authority ceiling NON-vacuously (`rankN L_src < rankN req`),
    then over ANY operation sequence the sink is NEVER admitted by the GENERATED
    `aflows_to`. Closed by `omega` transitivity over `arun_antitone`. -/
theorem authority_sink_never_admitted
    (L_src eff req : AL) (ops : List AL)
    (h_joined : rankN eff ≤ rankN L_src)
    (h_blocked : rankN L_src < rankN req) :
    ¬ aadmitted (arun ops eff) req := by
  intro h_admit
  unfold aadmitted at h_admit
  rw [aflows_to_ok] at h_admit
  -- h_admit : ok (decide (rankN req ≤ rankN (arun ops eff))) = ok true
  simp only [Result.ok.injEq, decide_eq_true_eq] at h_admit
  -- h_admit : rankN req ≤ rankN (arun ops eff)
  have h_ratchet : rankN (arun ops eff) ≤ rankN eff := arun_antitone ops eff
  -- req ≤ arun ≤ eff ≤ L_src < req  ⇒  contradiction.
  omega

/-- **Instantiation: web content can NEVER direct a privileged action**, over
    the GENERATED defs. A session whose effective authority is `NoAuthority`
    (rank 0 — the label web-scraping / public-issue content carries) is never
    admitted at a sink requiring `Directive` authority (rank 3 — the authority a
    privileged, agent-directing action demands), over ANY operation sequence.
    This is the AUTHORITY half of the anti-prompt-injection guarantee (the
    integrity half is `web_tainted_never_git_pushes`). Non-vacuous:
    `h_joined = 0 ≤ 0`, `h_blocked = 0 < 3`. -/
theorem web_content_never_directs (ops : List AL) :
    ¬ aadmitted (arun ops .NoAuthority) .Directive := by
  apply authority_sink_never_admitted
    (L_src := .NoAuthority)
    (eff := .NoAuthority)
    (req := .Directive)
    (ops := ops)
  · decide
  · decide

end AuthorityNoninterferenceExtracted

/-
  Axiom audit. These commands print the FULL transitive axiom set the kernel
  used to accept each theorem. The CI `lean-build` job captures their real
  output to `/tmp/lake-auth-ifc.log`. The EXPECTED set is exactly:

      [propext, Quot.sound, Classical.choice]

  Anything else — in particular `sorryAx` (a proof hole) or any Aeneas-emitted
  opaque `*External` axiom — MUST fail review. The `extracted/ifc_authority.rs`
  deliberately uses an explicit `arank(a) <= arank(b)` comparison rather than a
  derived `Ord`, so Aeneas emits a translated body (no opaque comparison axiom);
  `generated-ifc/` contains no `FunsExternal_Template.lean`, so there are no
  opaque-function holes to leak in here.
-/
#print axioms AuthorityNoninterferenceExtracted.authority_sink_never_admitted
#print axioms AuthorityNoninterferenceExtracted.web_content_never_directs
