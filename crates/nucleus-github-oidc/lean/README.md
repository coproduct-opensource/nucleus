# `nucleus-github-oidc` Lean proofs — OIDC→SPIFFE derivation

Aeneas→Lean target #2: properties of the GitHub-OIDC → Nucleus-SPIFFE-id
derivation, proven over the Charon→Aeneas extraction of real Rust.

## The honest trust chain

```
crates/nucleus-github-oidc/src/claims.rs                 production sanitize_segment / derive_spiffe_id
        ≡  (byte-identical, proven by parity proptests, incl. random Unicode)
crates/nucleus-github-oidc/src/extracted/oidc_spiffe.rs  Aeneas-subset mirror (no chars()/format!)
        --charon --start-from (scoped)-->  nucleus_github_oidc.llbc
        --aeneas -backend lean -split-files-->
generated/NucleusGithubOidc/{Types,Funs}.lean            UNMODIFIED Aeneas output
        --OidcSpiffeProofs.lean-->                        theorems over the GENERATED defs
```

- `production ≡ extracted` is established in Rust (`src/extracted/oidc_spiffe.rs`
  `#[cfg(test)]`): `sanitize_bytes_matches_production` /
  `derive_spiffe_bytes_matches_production` are byte-identical across random
  strings including arbitrary Unicode; `is_spiffe_byte_matches_production_charset`
  is exhaustive over all 256 byte values.
- `extracted → Lean` is the Aeneas extraction (`generated/` is verbatim output).
- The theorems in `OidcSpiffeProofs.lean` are stated over the generated
  functions, never a hand model.

## What is proven (sorry-free; `#print axioms` = `[propext, Classical.choice, Quot.sound]`)

- `is_spiffe_byte_iff` / `is_spiffe_byte_charset` — the extracted byte classifier
  admits exactly the SPIFFE charset `[0-9A-Za-z._-]`, for every `U8`.
- `collapse_lossy_step` — the per-byte sanitizer step merges the disallowed `/`
  (0x2F) and the allowed `-` (0x2D) to the same continuation: the machine-checked
  root of the non-injective SPIFFE-id collision.

## The honest finding: the derivation is NOT injective

`sanitize_segment` is lossy, so distinct claim-sets can mint the same SPIFFE id
(`"a/b"`≡`"a-b"`, `"refs/heads/x"`≡`"refs-heads-x"`). We do **not** prove
collision-freedom — it is false. The full end-to-end collision is pinned in the
Rust proptests (`collision_distinct_refs_same_spiffe_id`,
`collision_distinct_repo_segments`).

## Disclosed gap (not a `sorry`)

The full end-to-end `sanitize_bytes(x) = sanitize_bytes(y)` collision is proven
in Rust, not yet as a closed Lean theorem: Aeneas emits the loop as an Aeneas
`loop` combinator defined via `partial_fixpoint`, whose unfolding equation does
not terminate under `simp` and whose `Result (Vec …)` codomain has no
kernel-reducible `DecidableEq` for `decide`. So the Lean side proves the per-step
root cause (`collapse_lossy_step`); the closed end-to-end collision lives in the
Rust proptest. No `sorry` claims more than holds.

## Reproducing

Extraction + proofs build on Linux CI (`aeneas-oidc-spiffe.yml`) and locally:

```bash
# 1. scoped Charon→Aeneas extraction (regenerates generated/)
RUSTUP_TOOLCHAIN=nightly-2026-02-07 \
  charon cargo --preset aeneas \
    --start-from nucleus_github_oidc::extracted::oidc_spiffe::sanitize_bytes \
    --start-from nucleus_github_oidc::extracted::oidc_spiffe::derive_spiffe_bytes \
    --start-from nucleus_github_oidc::extracted::oidc_spiffe::is_spiffe_byte
aeneas -backend lean -split-files nucleus_github_oidc.llbc -dest lean/generated/NucleusGithubOidc

# 2. build the proofs + axiom audit
cd lean && lake exe cache get && lake build NucleusGithubOidc OidcSpiffeProofs
```

Pins: aeneas `nightly-2026.05.30` (commit `2a12be13…`), Charon nightly
`nightly-2026-02-07`, Lean `v4.30.0-rc2` + mathlib `v4.30.0-rc2`.
