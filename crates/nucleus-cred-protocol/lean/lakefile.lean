import Lake
open Lake DSL

package «nucleusCredProtocol» where
  buildType := .release
  leanOptions := #[
    ⟨`autoImplicit, false⟩,
    ⟨`maxHeartbeats, (1000000 : Nat)⟩
  ]

-- Aeneas standard library (Result monad, scalar types, Vec/Slice, loop combinator).
-- PINNED to the commit that backs the `nightly-2026.06.10` prebuilt aeneas
-- binary used to GENERATE generated/NucleusCredProtocol/{Types,Funs}.lean.
-- Same commit the sibling nucleus-github-oidc and portcullis-core lakefiles pin.
require aeneas from git
  "https://github.com/AeneasVerif/aeneas.git" @ "5138c03bd39e870abe1ad3a572865cf8c15f43d6" / "backends" / "lean"

-- Mathlib, toolchain-matched (v4.30.0), as the sibling projects require it.
require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.30.0"

-- The broker's egress decisions, extracted from the production Rust
-- (crates/nucleus-cred-protocol/src/extracted/). UNMODIFIED Aeneas output:
-- Types.lean + Funs.lean exactly as emitted. See README.md.
-- A default target, so a bare `lake build` builds it: with no default target
-- `lake build` completes with "0 jobs" and checks nothing.
@[default_target]
lean_lib «NucleusCredProtocol» where
  roots := #[`NucleusCredProtocol.Types, `NucleusCredProtocol.Funs]
  srcDir := "generated"
