import Lake
open Lake DSL

package «nucleusGithubOidc» where
  buildType := .release
  leanOptions := #[
    ⟨`autoImplicit, false⟩,
    ⟨`maxHeartbeats, (1000000 : Nat)⟩
  ]

-- Aeneas standard library (Result monad, scalar types, Vec/Slice, loop combinator).
-- PINNED to the commit that backs the `nightly-2026.06.10` prebuilt aeneas
-- binary used to GENERATE generated/NucleusGithubOidc/{Types,Funs}.lean
-- (`gh api …/git/refs/tags/nightly-2026.06.10` → 2a12be13…). Same commit the
-- sibling portcullis-core/lean lakefile pins.
require aeneas from git
  "https://github.com/AeneasVerif/aeneas.git" @ "5138c03bd39e870abe1ad3a572865cf8c15f43d6" / "backends" / "lean"

-- Mathlib for omega/decide ergonomics; toolchain-matched (v4.30.0-rc2).
require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.30.0-rc2"

-- The Aeneas-generated OIDC→SPIFFE slice (from real Rust:
-- crates/nucleus-github-oidc/src/extracted/oidc_spiffe.rs). UNMODIFIED Aeneas
-- output — Types.lean + Funs.lean exactly as emitted.
lean_lib «NucleusGithubOidc» where
  roots := #[`NucleusGithubOidc.Types, `NucleusGithubOidc.Funs]
  srcDir := "generated"

-- The OIDC→SPIFFE derivation properties, proven OVER the generated defs above.
lean_lib «OidcSpiffeProofs» where
  roots := #[`OidcSpiffeProofs]

-- The JWT-SVID claims-decision properties (soundness / fail-closed /
-- completeness / verdict attribution), proven OVER the generated
-- `extracted.jwt_svid_claims.decide_claims` (#2452). Same generated lib, its
-- own theorem file, so each slice's axiom audit stays separately readable.
lean_lib «JwtSvidClaimsProofs» where
  roots := #[`JwtSvidClaimsProofs]
