/-
  JWT-SVID claims decision — properties proven OVER the Aeneas-EXTRACTED core.

  Aeneas→Lean target #3 in this crate's pipeline (sibling to the OIDC→SPIFFE
  derivation slice in `OidcSpiffeProofs.lean`). The chain:

      crates/nucleus-github-oidc/src/extracted/jwt_svid_claims.rs   (real Rust)
        --charon (scoped, --start-from)-->  nucleus_github_oidc.llbc
        --aeneas -backend lean -split-files-->
          generated/NucleusGithubOidc/{Types,Funs}.lean   (THIS file's deps)
        --(this file)-->  properties proven over THOSE generated defs.

  The production caller is `nucleus-control-plane-server::auth::verify_jwt_svid`
  (#2452): after the EdDSA signature check it CALLS the extracted
  `decide_claims` (with `has_prefix` on the subject and `bytes_eq` per audience
  element) for its claims decision, so every theorem here is about the live
  path, not a mirror of it.

  # The honest trust chain (production ↔ extracted)

  - Production ≡ extracted: `verify_jwt_svid` calls the extracted functions
    (call-through), and the parity proptests in `jwt_svid_claims.rs`
    (`claims_verdict_matches_production*`) check the composed call against the
    pre-refactor inline clause, lifted verbatim as the oracle.
  - Extracted ≡ generated: Aeneas, re-run by CI on every change; the
    `#print axioms` audit below is the evidence the theorems ran.

  # What IS proven sorry-free over the generated `decide_claims`

  * `admit_sound` — an `Admit` verdict implies EVERY predicate held: the
    audience matched, the subject prefix matched, `exp + skew` did not
    overflow and is not below `now`, and if `nbf` is present then `now + skew`
    did not overflow and `nbf` is not above it. No admission without all four.
  * `aud_mismatch_fails_closed` / `sub_mismatch_fails_closed` — a failed
    audience or subject check can never yield `Admit`, whatever the clock says.
  * `admit_complete` — when all four predicates hold the verdict IS `Admit`, so
    the core cannot reject a valid token either (no false 401/403 from the
    decision).
  * `not_yet_valid_has_nbf` — `NotYetValid` is only ever raised with
    `nbf = some _`, which is what licenses the caller's `unwrap_or` when it
    reports the refused `nbf`.
  * `verdict_order` — the first failing predicate, in production's order, is
    the verdict: `Expired` beats `NotYetValid` beats `AudienceMismatch` beats
    `SubjectPrefixMismatch`.

  # Scope boundary (what is NOT claimed)

  - NOT the signature check (`ed25519-dalek`, outside the extractable subset).
  - NOT the audience FOLD: `auds.iter().any(...)` is a nested-borrow slice
    (`&[&[u8]]`), which Aeneas rejects, and the fold itself is the
    `Iterator::fold` axiom. The fold stays in production; the theorems take its
    result as `aud_ok`.
  - NOT the byte loops `bytes_eq` / `has_prefix` as closed theorems: their
    generated form is the Aeneas `loop` combinator (`partial_fixpoint`), the
    same gap `OidcSpiffeProofs.lean` discloses; they are covered by the Rust
    parity proptests (`loops_match_std`) instead.
  - Overflow: the generated `+` is checked. The theorems are stated with the
    no-overflow facts as CONCLUSIONS of `admit_sound` (an admission proves the
    sums were representable) and as HYPOTHESES of `admit_complete`.
-/

import NucleusGithubOidc.Types
import NucleusGithubOidc.Funs
import Aeneas
import Mathlib.Tactic

open Aeneas Aeneas.Std Result

set_option maxHeartbeats 1000000

namespace JwtSvidClaimsProofs

open nucleus_github_oidc.extracted.jwt_svid_claims

/-! ## Soundness: no admission without every predicate -/

/-- **An `Admit` verdict implies every claims predicate held.** -/
theorem admit_sound
    (exp now skew : Std.U64) (nbf : Option Std.U64) (aud_ok sub_ok : Bool)
    (h : decide_claims exp nbf now skew aud_ok sub_ok = ok ClaimsVerdict.Admit) :
    aud_ok = true ∧ sub_ok = true
    ∧ (∃ s, exp + skew = ok s ∧ ¬ s < now)
    ∧ (∀ n, nbf = some n → ∃ t, now + skew = ok t ∧ ¬ n > t) := by
  unfold decide_claims at h
  cases hs : (exp + skew : Result Std.U64) with
  | fail e => simp [hs] at h
  | div => simp [hs] at h
  | ok s =>
    simp only [hs, bind_tc_ok] at h
    split at h
    · simp at h
    · rename_i hlt
      cases nbf with
      | none =>
        simp only [bind_tc_ok] at h
        cases aud_ok <;> cases sub_ok <;> simp_all
      | some n =>
        cases ht : (now + skew : Result Std.U64) with
        | fail e => simp [ht] at h
        | div => simp [ht] at h
        | ok t =>
          simp only [ht, bind_tc_ok] at h
          by_cases hnt : (↑t : ℕ) < ↑n
          · simp [hnt] at h
          · simp [hnt] at h
            cases aud_ok <;> cases sub_ok <;> simp_all

/-! ## Fail-closed: a failed check can never admit -/

/-- **A failed audience check can never yield `Admit`.** -/
theorem aud_mismatch_fails_closed
    (exp now skew : Std.U64) (nbf : Option Std.U64) (sub_ok : Bool) :
    decide_claims exp nbf now skew false sub_ok ≠ ok ClaimsVerdict.Admit := by
  intro h
  have := (admit_sound exp now skew nbf false sub_ok h).1
  simp at this

/-- **A failed subject-prefix check can never yield `Admit`.** -/
theorem sub_mismatch_fails_closed
    (exp now skew : Std.U64) (nbf : Option Std.U64) (aud_ok : Bool) :
    decide_claims exp nbf now skew aud_ok false ≠ ok ClaimsVerdict.Admit := by
  intro h
  have := (admit_sound exp now skew nbf aud_ok false h).2.1
  simp at this

/-! ## Completeness: a valid token is admitted -/

/-- **When every predicate holds, the verdict is `Admit`.** The no-overflow
    facts are hypotheses here (they are conclusions of `admit_sound`). -/
theorem admit_complete
    (exp now skew : Std.U64) (nbf : Option Std.U64)
    (s : Std.U64) (hs : exp + skew = ok s) (hexp : ¬ s < now)
    (hnbf : ∀ n, nbf = some n → ∃ t, now + skew = ok t ∧ ¬ n > t) :
    decide_claims exp nbf now skew true true = ok ClaimsVerdict.Admit := by
  unfold decide_claims
  simp only [hs, bind_tc_ok]
  rw [if_neg hexp]
  cases nbf with
  | none => simp
  | some n =>
    obtain ⟨t, ht, hnt⟩ := hnbf n rfl
    have hnt' : ¬ (↑t : ℕ) < ↑n := hnt
    simp [ht, hnt']

/-! ## Verdict attribution -/

/-- **`NotYetValid` is only raised with `nbf = some _`.** Licenses the caller's
    `nbf.unwrap_or(..)` when it reports the refused `nbf`. -/
theorem not_yet_valid_has_nbf
    (exp now skew : Std.U64) (nbf : Option Std.U64) (aud_ok sub_ok : Bool)
    (h : decide_claims exp nbf now skew aud_ok sub_ok = ok ClaimsVerdict.NotYetValid) :
    ∃ n, nbf = some n := by
  unfold decide_claims at h
  cases hs : (exp + skew : Result Std.U64) with
  | fail e => simp [hs] at h
  | div => simp [hs] at h
  | ok s =>
    simp only [hs, bind_tc_ok] at h
    split at h
    · simp at h
    · cases nbf with
      | none =>
        simp only [bind_tc_ok] at h
        cases aud_ok <;> cases sub_ok <;> simp_all
      | some n => exact ⟨n, rfl⟩

/-! ## Verdict order: the first failing predicate wins -/

/-- **Expiry is reported first**, before any other predicate is consulted. -/
theorem expired_first
    (exp now skew : Std.U64) (nbf : Option Std.U64) (aud_ok sub_ok : Bool)
    (s : Std.U64) (hs : exp + skew = ok s) (hexp : s < now) :
    decide_claims exp nbf now skew aud_ok sub_ok = ok ClaimsVerdict.Expired := by
  have hexp' : (↑s : ℕ) < ↑now := hexp
  unfold decide_claims
  simp [hs, hexp']

/-- **Not-before is reported second**, before the audience and subject checks. -/
theorem not_yet_valid_second
    (exp now skew : Std.U64) (n : Std.U64) (aud_ok sub_ok : Bool)
    (s : Std.U64) (hs : exp + skew = ok s) (hexp : ¬ s < now)
    (t : Std.U64) (ht : now + skew = ok t) (hnt : n > t) :
    decide_claims exp (some n) now skew aud_ok sub_ok = ok ClaimsVerdict.NotYetValid := by
  have hexp' : ¬ (↑s : ℕ) < ↑now := hexp
  have hnt' : (↑t : ℕ) < ↑n := hnt
  unfold decide_claims
  simp [hs, hexp', ht, hnt']

/-- **Audience is reported third**, before the subject check. -/
theorem audience_third
    (exp now skew : Std.U64) (nbf : Option Std.U64) (sub_ok : Bool)
    (s : Std.U64) (hs : exp + skew = ok s) (hexp : ¬ s < now)
    (hnbf : ∀ n, nbf = some n → ∃ t, now + skew = ok t ∧ ¬ n > t) :
    decide_claims exp nbf now skew false sub_ok = ok ClaimsVerdict.AudienceMismatch := by
  unfold decide_claims
  simp only [hs, bind_tc_ok]
  rw [if_neg hexp]
  cases nbf with
  | none => simp
  | some n =>
    obtain ⟨t, ht, hnt⟩ := hnbf n rfl
    have hnt' : ¬ (↑t : ℕ) < ↑n := hnt
    simp [ht, hnt']

/-- **Subject prefix is reported last.** -/
theorem subject_last
    (exp now skew : Std.U64) (nbf : Option Std.U64)
    (s : Std.U64) (hs : exp + skew = ok s) (hexp : ¬ s < now)
    (hnbf : ∀ n, nbf = some n → ∃ t, now + skew = ok t ∧ ¬ n > t) :
    decide_claims exp nbf now skew true false = ok ClaimsVerdict.SubjectPrefixMismatch := by
  unfold decide_claims
  simp only [hs, bind_tc_ok]
  rw [if_neg hexp]
  cases nbf with
  | none => simp
  | some n =>
    obtain ⟨t, ht, hnt⟩ := hnbf n rfl
    have hnt' : ¬ (↑t : ℕ) < ↑n := hnt
    simp [ht, hnt']

end JwtSvidClaimsProofs

/-
  Axiom audit. The CI job captures the real `#print axioms` output and fails on
  `sorryAx` or any Aeneas-emitted opaque axiom. The expected set is a subset of
  `[propext, Classical.choice, Quot.sound]` (the trusted Lean kernel set entered
  via `simp`/`decide`; not proof holes).
-/
#print axioms JwtSvidClaimsProofs.admit_sound
#print axioms JwtSvidClaimsProofs.aud_mismatch_fails_closed
#print axioms JwtSvidClaimsProofs.sub_mismatch_fails_closed
#print axioms JwtSvidClaimsProofs.admit_complete
#print axioms JwtSvidClaimsProofs.not_yet_valid_has_nbf
#print axioms JwtSvidClaimsProofs.expired_first
#print axioms JwtSvidClaimsProofs.not_yet_valid_second
#print axioms JwtSvidClaimsProofs.audience_third
#print axioms JwtSvidClaimsProofs.subject_last
