/-
  Ifc / Flow  (IFC label kernel — contravariant-axis flow-soundness proofs)

  **STATUS: PROVED (0 `sorry`).** Mathlib-free: finite inductive enums +
  exhaustive `cases` / `rfl` / `decide`. No Mathlib, no native-decide, no
  `sorry` / `admit` / `axiom`. Lean 4 v4.30.0-rc2, `autoImplicit = false`.
  Same discipline as `Ifc.Lattice` (this crate), `Ck.Policy`
  (`crates/ck-policy/lean`) and `Nucleus.Rubric` (`crates/nucleus-rubric/lean`).

  Companion to `Ifc/Lattice.lean`, which covers the two COVARIANT axes
  (`ConfLevel` = max, `DerivationClass` = the diamond). This file covers the two
  CONTRAVARIANT axes of the same product lattice in
  `crates/nucleus-ifc-kernel/src/ifc_lattice.rs`:

    * `IntegLevel` — the Biba integrity axis (`Adversarial < Untrusted <
      Trusted`) whose join is `min` ("least trusted wins").
    * `AuthorityLevel` — the authority-to-instruct axis (`NoAuthority <
      Informational < Suggestive < Directive`) whose join is `min` ("least
      authority wins"). This is the crate's novel prompt-injection-defense axis.

  and the flagship two-axis anti-injection property the crate's module doc-comment
  states by name (the "Key property", `ifc_lattice.rs` lines 310–312):

      combining a trusted user prompt with web content produces
      `integrity = Adversarial, authority = NoAuthority`. This data cannot
      steer privileged actions.

  # What is proved

  For each contravariant axis (`IntegLevel`, `AuthorityLevel`), whose join is the
  `min`-by-rank transcribed from `IFCLabel::join`
  (`if self.x <= other.x { self.x } else { other.x }`):
    * `join_comm` / `join_assoc` / `join_idem` — bounded meet-semilattice laws
    * `join_top_bot` — `Trusted` / `Directive` is the identity (top for a
      contravariant axis: joining with fully-trusted / fully-authorized data
      never restricts)
    * `join_absorb` — `Adversarial` / `NoAuthority` is absorbing: **once tainted,
      always tainted**. `join Adversarial x = Adversarial` is the Biba core;
      `join NoAuthority x = NoAuthority` is the exact indirect-prompt-injection
      defense (web content, labelled `NoAuthority`, can NEVER acquire authority
      by being combined with anything).
    * `join_glb_left/right` — join is a LOWER bound: `join a b ≤ a` and `≤ b`.
      i.e. combining data can only LOWER integrity/authority, never raise it
      (**no trust escalation, no authority escalation** — the contravariant dual
      of `ConfLevel`'s "no declassification").
    * `join_no_laundering` — the result is maximal (`Trusted` / `Directive`)
      ONLY when BOTH inputs already are: `join a b = ⊤ → a = ⊤ ∧ b = ⊤`. You
      cannot launder an untrusted / unauthorized input into a trusted /
      authorized one by joining. A genuine security invariant, not a tautology.
    * `join_mono_left/right` — join is monotone in each argument.

  For the combined two-axis "instruction fragment" (`InstrFrag`, the
  (integrity, authority) projection of `IFCLabel`):
    * `web_taint_absorbing` — joining ANY fragment with a web-content fragment
      (`⟨Adversarial, NoAuthority⟩`) yields a fragment that is still
      `⟨Adversarial, NoAuthority⟩`. Generalizes the doc-comment's concrete
      example to every possible peer: nothing joined with web content can steer.
    * `user_prompt_join_web` — the doc-comment's exact concrete instance:
      `⟨Trusted, Directive⟩ ⊔ ⟨Adversarial, NoAuthority⟩ = ⟨Adversarial,
      NoAuthority⟩`.

  # EXTRACTION-GAP CAVEAT

  As with `Ifc/Lattice.lean`: these theorems are about the Lean MODEL of the
  join arms of `IFCLabel::join`, a hand-transcription of `ifc_lattice.rs`
  (checked by eye and by the crate's `proptest` suite), NOT an Aeneas extraction.
  A Charon→Aeneas extraction would be needed to close the model↔Rust gap
  deductively; until then treat these as statements about the mirrored model.
-/

namespace Ifc.Flow

/- ───────────────────────────────────────────────────────────────────────────
   IntegLevel — the Biba integrity axis (join = min, "least trusted wins")
   Mirrors `enum IntegLevel` (`Adversarial = 0 < Untrusted = 1 < Trusted = 2`)
   and the integrity arm of `IFCLabel::join`
   (`if self.integrity <= other.integrity { self.integrity } else { other.integrity }`).
   ─────────────────────────────────────────────────────────────────────────── -/

/-- Integrity level — CONTRAVARIANT (Biba: combining trusted with untrusted
    yields untrusted). -/
inductive IntegLevel
  | Adversarial
  | Untrusted
  | Trusted
  deriving DecidableEq, Repr

namespace IntegLevel

/-- Numeric rank, matching the `#[repr(u8)]` discriminants `0 < 1 < 2`. -/
def rank : IntegLevel → Nat
  | Adversarial => 0
  | Untrusted => 1
  | Trusted => 2

/-- `≤` on levels, via the numeric rank (the derived `Ord` in Rust). -/
def le (a b : IntegLevel) : Prop := rank a ≤ rank b

instance (a b : IntegLevel) : Decidable (le a b) :=
  inferInstanceAs (Decidable (rank a ≤ rank b))

/-- Join = min: the integrity arm of `IFCLabel::join`
    (`if self.integrity <= other.integrity { self.integrity } else { other.integrity }`). -/
def join (a b : IntegLevel) : IntegLevel :=
  if rank a ≤ rank b then a else b

theorem join_comm (a b : IntegLevel) : join a b = join b a := by
  cases a <;> cases b <;> decide

theorem join_idem (a : IntegLevel) : join a a = a := by
  cases a <;> decide

theorem join_assoc (a b c : IntegLevel) :
    join (join a b) c = join a (join b c) := by
  cases a <;> cases b <;> cases c <;> decide

/-- `Trusted` is the top / identity for the (contravariant) join: joining with
    fully-trusted data never lowers integrity. -/
theorem join_top_bot (a : IntegLevel) : join Trusted a = a := by
  cases a <;> decide

/-- **Adversarial is absorbing** — the Biba core: any adversarial input taints
    the result. `Adversarial.join(x) = Adversarial` for every `x`. -/
theorem join_absorb (x : IntegLevel) : join Adversarial x = Adversarial := by
  cases x <;> decide

/-- Join is a LOWER bound of `a`: combining data never RAISES integrity
    (**no trust escalation** — the contravariant dual of "no declassification"). -/
theorem join_glb_left (a b : IntegLevel) : le (join a b) a := by
  cases a <;> cases b <;> decide

/-- Join is a lower bound of `b`. -/
theorem join_glb_right (a b : IntegLevel) : le (join a b) b := by
  cases a <;> cases b <;> decide

/-- **No trust laundering** — the result is `Trusted` ONLY if BOTH inputs are
    already `Trusted`. You cannot combine your way up to trust. -/
theorem join_no_laundering {a b : IntegLevel} (h : join a b = Trusted) :
    a = Trusted ∧ b = Trusted := by
  cases a <;> cases b <;> first | (exact ⟨rfl, rfl⟩) | (revert h; decide)

/-- Join is monotone in its left argument. -/
theorem join_mono_left {a a' : IntegLevel} (b : IntegLevel) (h : le a a') :
    le (join a b) (join a' b) := by
  cases a <;> cases a' <;> cases b <;> revert h <;> decide

/-- Join is monotone in its right argument. -/
theorem join_mono_right (a : IntegLevel) {b b' : IntegLevel} (h : le b b') :
    le (join a b) (join a b') := by
  cases a <;> cases b <;> cases b' <;> revert h <;> decide

end IntegLevel

/- ───────────────────────────────────────────────────────────────────────────
   AuthorityLevel — the authority-to-instruct axis (join = min, "least authority
   wins"). Mirrors `enum AuthorityLevel`
   (`NoAuthority = 0 < Informational = 1 < Suggestive = 2 < Directive = 3`) and
   the authority arm of `IFCLabel::join`
   (`if self.authority <= other.authority { self.authority } else { other.authority }`).
   ─────────────────────────────────────────────────────────────────────────── -/

/-- Authority-to-instruct level — CONTRAVARIANT. The crate's novel axis: encodes
    "can this data steer the agent?". -/
inductive AuthorityLevel
  | NoAuthority
  | Informational
  | Suggestive
  | Directive
  deriving DecidableEq, Repr

namespace AuthorityLevel

/-- Numeric rank, matching the `#[repr(u8)]` discriminants `0 < 1 < 2 < 3`. -/
def rank : AuthorityLevel → Nat
  | NoAuthority => 0
  | Informational => 1
  | Suggestive => 2
  | Directive => 3

/-- `≤` on levels, via the numeric rank (the derived `Ord` in Rust). -/
def le (a b : AuthorityLevel) : Prop := rank a ≤ rank b

instance (a b : AuthorityLevel) : Decidable (le a b) :=
  inferInstanceAs (Decidable (rank a ≤ rank b))

/-- Join = min: the authority arm of `IFCLabel::join`
    (`if self.authority <= other.authority { self.authority } else { other.authority }`). -/
def join (a b : AuthorityLevel) : AuthorityLevel :=
  if rank a ≤ rank b then a else b

theorem join_comm (a b : AuthorityLevel) : join a b = join b a := by
  cases a <;> cases b <;> decide

theorem join_idem (a : AuthorityLevel) : join a a = a := by
  cases a <;> decide

theorem join_assoc (a b c : AuthorityLevel) :
    join (join a b) c = join a (join b c) := by
  cases a <;> cases b <;> cases c <;> decide

/-- `Directive` is the top / identity for the (contravariant) join: joining with
    fully-authorized data never lowers authority. -/
theorem join_top_bot (a : AuthorityLevel) : join Directive a = a := by
  cases a <;> decide

/-- **NoAuthority is absorbing** — the exact indirect-prompt-injection defense.
    `NoAuthority.join(x) = NoAuthority` for every `x`: web content (labelled
    `NoAuthority`) can NEVER acquire instruction authority by being combined with
    anything, regardless of what the LLM decides to do with it. -/
theorem join_absorb (x : AuthorityLevel) : join NoAuthority x = NoAuthority := by
  cases x <;> decide

/-- Join is a LOWER bound of `a`: combining data never RAISES authority
    (**no authority escalation**). -/
theorem join_glb_left (a b : AuthorityLevel) : le (join a b) a := by
  cases a <;> cases b <;> decide

/-- Join is a lower bound of `b`. -/
theorem join_glb_right (a b : AuthorityLevel) : le (join a b) b := by
  cases a <;> cases b <;> decide

/-- **No authority laundering** — the result is `Directive` ONLY if BOTH inputs
    are already `Directive`. You cannot combine your way up to full authority. -/
theorem join_no_laundering {a b : AuthorityLevel} (h : join a b = Directive) :
    a = Directive ∧ b = Directive := by
  cases a <;> cases b <;> first | (exact ⟨rfl, rfl⟩) | (revert h; decide)

/-- Join is monotone in its left argument. -/
theorem join_mono_left {a a' : AuthorityLevel} (b : AuthorityLevel) (h : le a a') :
    le (join a b) (join a' b) := by
  cases a <;> cases a' <;> cases b <;> revert h <;> decide

/-- Join is monotone in its right argument. -/
theorem join_mono_right (a : AuthorityLevel) {b b' : AuthorityLevel} (h : le b b') :
    le (join a b) (join a b') := by
  cases a <;> cases b <;> cases b' <;> revert h <;> decide

end AuthorityLevel

/- ───────────────────────────────────────────────────────────────────────────
   InstrFrag — the (integrity, authority) projection of `IFCLabel`.
   The two axes that jointly decide "can this data steer privileged actions?".
   `join` is componentwise, exactly as `IFCLabel::join` does per-field.
   ─────────────────────────────────────────────────────────────────────────── -/

/-- The instruction-relevant fragment of an `IFCLabel`: its integrity and
    authority axes. -/
structure InstrFrag where
  integ : IntegLevel
  auth : AuthorityLevel
  deriving DecidableEq, Repr

namespace InstrFrag

/-- Componentwise join, mirroring the per-field `IFCLabel::join`. -/
def join (a b : InstrFrag) : InstrFrag :=
  { integ := IntegLevel.join a.integ b.integ
    auth := AuthorityLevel.join a.auth b.auth }

/-- A web-content fragment: `⟨Adversarial, NoAuthority⟩` (`IFCLabel::web_content`
    projected onto the two instruction axes). -/
def webContent : InstrFrag :=
  { integ := IntegLevel.Adversarial, auth := AuthorityLevel.NoAuthority }

/-- A user-prompt fragment: `⟨Trusted, Directive⟩` (`IFCLabel::user_prompt`
    projected onto the two instruction axes). -/
def userPrompt : InstrFrag :=
  { integ := IntegLevel.Trusted, auth := AuthorityLevel.Directive }

/-- **Web taint is absorbing across BOTH axes.** Joining ANY fragment `x` with a
    web-content fragment yields a fragment that is still `⟨Adversarial,
    NoAuthority⟩`. This generalizes the module doc-comment's concrete example to
    every possible peer: data combined with web content can neither be trusted
    nor steer the agent — the full indirect-prompt-injection guarantee. -/
theorem web_taint_absorbing (x : InstrFrag) : join x webContent = webContent := by
  cases x with
  | mk i a => cases i <;> cases a <;> decide

/-- The module doc-comment's exact "Key property" instance: a trusted user prompt
    joined with web content produces `⟨Adversarial, NoAuthority⟩`. -/
theorem user_prompt_join_web : join userPrompt webContent = webContent := by
  decide

end InstrFrag

end Ifc.Flow
