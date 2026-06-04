/-
  OIDC → SPIFFE derivation — properties proven OVER the Aeneas-EXTRACTED slice.

  This is Aeneas→Lean target #2 (sibling to the portcullis-core integrity-axis
  noninterference target). The chain:

      crates/nucleus-github-oidc/src/extracted/oidc_spiffe.rs   (real Rust)
        --charon (scoped, --start-from)-->  nucleus_github_oidc.llbc
        --aeneas -backend lean -split-files-->
          generated/NucleusGithubOidc/{Types,Funs}.lean   (THIS file's deps)
        --(this file)-->  properties proven over THOSE generated defs.

  The generated functions live in namespace `nucleus_github_oidc` and return the
  Aeneas `Result` monad. Every theorem below is stated in terms of THOSE
  functions (`…oidc_spiffe.{is_spiffe_byte, sanitize_bytes_loop0.body, …}`),
  never a hand model.

  # The honest trust chain (production ↔ extracted)

  The extracted defs are behavior-EQUIVALENT mirrors of the production
  `sanitize_segment` / `derive_spiffe_id` (`claims.rs`). That equivalence is
  established in Rust by the parity PROPTESTS in
  `src/extracted/oidc_spiffe.rs`:
    - `sanitize_bytes_matches_production` — byte-identical to the production
      `char` sanitizer across random strings INCLUDING arbitrary Unicode;
    - `derive_spiffe_bytes_matches_production` — same path bytes as the
      production `format!`;
    - `is_spiffe_byte_matches_production_charset` — EXHAUSTIVE over all 256 byte
      values vs the production `char::is_ascii_alphanumeric() || …` clause.
  Those Rust tests close the production↔extracted gap; THIS file closes the
  property-over-extracted gap.

  # The honest finding: derivation is NOT injective (a SPIFFE-id collision)

  `sanitize_segment` is LOSSY: distinct inputs collapse to the same output —
  e.g. `"refs/heads/x"` and `"refs-heads-x"` both → `"refs-heads-x"`, and
  `"a/b"` and `"a-b"` both → `"a-b"`. So `derive_spiffe_id` is NOT injective:
  distinct claim-sets can mint the SAME SPIFFE id within an owner/repo. A
  SPIFFE-id collision is an authz-confusion / impersonation surface. We do NOT
  fake an injectivity theorem.

  The ROOT of the collision is proven sorry-free HERE over the generated def
  (`collapse_lossy_step`): the generated `sanitize_bytes_loop0.body` maps the
  DISALLOWED byte `/` (47) and the ALLOWED byte `-` (45) — from the same
  starting state — to the IDENTICAL continuation, because a disallowed byte
  collapses to a `-` and the literal `-` is kept verbatim. That single step IS
  the lossy merge that destroys injectivity.

  The FULL end-to-end collision `sanitize_bytes x = sanitize_bytes y` (x ≠ y) is
  pinned + machine-checked in Rust (`collision_distinct_refs_same_spiffe_id`,
  `collision_distinct_repo_segments` in `oidc_spiffe.rs`). Lifting it to a closed
  Lean theorem over the generated `sanitize_bytes` is blocked by Aeneas's `loop`
  combinator being defined via `partial_fixpoint` (its unfolding equation does
  not terminate under `simp`, and the `Result (Vec …)` codomain has no kernel-
  reducible `DecidableEq` for `decide`). We DISCLOSE that gap rather than paper
  over it with a `sorry`: the Lean side proves the per-step root cause; the Rust
  proptest proves the closed end-to-end collision. (See `lean/README` / docs.)

  # What IS proven sorry-free over the extracted defs

  * `is_spiffe_byte_iff` / `is_spiffe_byte_charset` — the extracted byte
    classifier equals the SPIFFE charset predicate `[0-9A-Za-z._-]`,
    EXHAUSTIVELY over all 256 `U8` values. The core security predicate.
  * `collapse_lossy_step` — the generated sanitizer's per-byte step merges a
    disallowed `/` and an allowed `-` to the same state: the machine-checked
    root of the non-injective collision.

  # Scope boundary (what is NOT claimed)

  - NOT collision-freedom (false; see the finding above and the Rust witnesses).
  - NOT "no `--` run" in sanitized output — production does not guarantee it (a
    literal `-` adjacent to a collapsed dash yields `--`; e.g. `"a𖭐-A"` →
    `"a--A"`; production's own test pins `sanitize_segment("a---b")="a---b"`).
    The charset claim is "byte ∈ [A-Za-z0-9._-]" per the classifier.
  - The owner-binding guard (`repository_owner == org(repository)`) and the
    final `CallSpiffeId::parse` live in production `derive_spiffe_id` around the
    extracted renderer; they are equality / parser checks outside the rendered-
    bytes subgraph and are not re-extracted.
-/

import NucleusGithubOidc.Types
import NucleusGithubOidc.Funs
import Aeneas
import Mathlib.Tactic

open Aeneas Aeneas.Std Result ControlFlow

set_option maxHeartbeats 4000000
set_option maxRecDepth 8000

namespace OidcSpiffeProofs

-- Bring the generated functions into scope unqualified.
open nucleus_github_oidc.extracted.oidc_spiffe

-- `Result Bool` (and the loop body's `Result (ControlFlow …)`) carry only a
-- derived `BEq`; `decide` needs `DecidableEq`. These derive it from the
-- structural equality of the underlying types. They add NO new axiom (checked
-- by the `#print axioms` audit below: the theorems stay
-- `[propext, Classical.choice, Quot.sound]`).
deriving instance DecidableEq for Error
deriving instance DecidableEq for ControlFlow
deriving instance DecidableEq for Result

/-! ## The core security predicate: the SPIFFE byte charset -/

/-- Pure-Lean SPIFFE charset predicate: `[0-9A-Za-z._-]` (`0x30-0x39`,
    `0x41-0x5A`, `0x61-0x7A`, `0x2E`, `0x5F`, `0x2D`). -/
def spiffeByte (b : Std.U8) : Bool :=
  (b ≥ 48#u8 && b ≤ 57#u8)      -- 0-9
  || (b ≥ 65#u8 && b ≤ 90#u8)   -- A-Z
  || (b ≥ 97#u8 && b ≤ 122#u8)  -- a-z
  || b = 46#u8                  -- .
  || b = 95#u8                  -- _
  || b = 45#u8                  -- -

/-- The extracted byte classifier equals the SPIFFE charset predicate for EVERY
    `U8` value, stated over the bitvector representation so the 256-way check is
    decidable (`U8 = UScalar .U8` wraps a `BitVec 8`). -/
theorem is_spiffe_byte_all (bv : BitVec 8) :
    is_spiffe_byte ⟨bv⟩ = ok (spiffeByte ⟨bv⟩) := by
  revert bv; decide +kernel

/-- **The extracted byte classifier equals the SPIFFE charset predicate**, for
    every byte. This is the load-bearing security statement: the
    extracted-from-Rust classifier admits exactly `[0-9A-Za-z._-]`. -/
theorem is_spiffe_byte_iff (b : Std.U8) :
    is_spiffe_byte b = ok (spiffeByte b) := by
  obtain ⟨bv⟩ := b; exact is_spiffe_byte_all bv

/-- A byte is admitted by the extracted classifier iff it is in the SPIFFE
    charset. (Corollary of `is_spiffe_byte_iff`.) -/
theorem is_spiffe_byte_charset (b : Std.U8) :
    is_spiffe_byte b = ok true ↔ spiffeByte b = true := by
  rw [is_spiffe_byte_iff]; simp

/-! ## The honest finding: NON-injectivity (the lossy-collapse root) -/

/-- A one-byte slice holding `/` (47, DISALLOWED by the SPIFFE charset). -/
def slSlash : Slice Std.U8 := ⟨[47#u8], by scalar_tac⟩

/-- A one-byte slice holding `-` (45, ALLOWED by the SPIFFE charset).
    DISTINCT byte from `slSlash`. -/
def slDash : Slice Std.U8 := ⟨[45#u8], by scalar_tac⟩

/-- The two single-byte inputs are genuinely DISTINCT. -/
theorem slSlash_ne_slDash : slSlash ≠ slDash := by
  simp only [slSlash, slDash, ne_eq]
  decide

/-- **The lossy-collapse step (root of non-injectivity), over the GENERATED
    def.** From the same starting fold state, the generated sanitizer's per-byte
    loop body maps the DISALLOWED byte `/` (47) and the ALLOWED byte `-` (45) to
    the IDENTICAL continuation: a disallowed byte collapses to a `-`, and the
    literal `-` is copied verbatim — both push byte 45 and set `prev_dash`. This
    single step is the merge that destroys injectivity; distinct inputs
    differing only here yield identical sanitized output (the full end-to-end
    collision is pinned in the Rust proptest — see the file header). -/
theorem collapse_lossy_step :
    sanitize_bytes_loop0.body slSlash 1#usize (alloc.vec.Vec.new Std.U8) false 0#usize
    = sanitize_bytes_loop0.body slDash 1#usize (alloc.vec.Vec.new Std.U8) false 0#usize := by
  unfold sanitize_bytes_loop0.body
  simp only [slSlash, slDash]
  norm_num [Slice.index_usize, is_spiffe_byte, alloc.vec.Vec.push,
            alloc.vec.Vec.new, DASH]

end OidcSpiffeProofs

/-
  Axiom audit. The CI job captures the real `#print axioms` output. The expected
  set is exactly `[propext, Classical.choice, Quot.sound]`. Anything else —
  `sorryAx` (a proof hole) or an Aeneas-emitted opaque `*External` axiom — fails
  review. (`Classical.choice`/`propext`/`Quot.sound` are the trusted Lean kernel
  set, entered via `decide`/`omega`/`simp`; they are not proof holes.)

  VERIFIED locally (macOS, aeneas nightly-2026.05.30 commit 2a12be13…,
  Lean v4.30.0-rc2 + mathlib): all four theorems printed exactly
  `[propext, Classical.choice, Quot.sound]`.
-/
#print axioms OidcSpiffeProofs.is_spiffe_byte_all
#print axioms OidcSpiffeProofs.is_spiffe_byte_iff
#print axioms OidcSpiffeProofs.is_spiffe_byte_charset
#print axioms OidcSpiffeProofs.slSlash_ne_slDash
#print axioms OidcSpiffeProofs.collapse_lossy_step
