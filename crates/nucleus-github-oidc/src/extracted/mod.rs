//! Subset-safe, Aeneas-extractable slices of the OIDC→SPIFFE derivation.
//!
//! Aeneas (the Rust→Lean verifier) cannot translate the production
//! [`crate::derive_spiffe_id`] / `sanitize_segment` directly:
//!
//! - `sanitize_segment` folds over the [`str::chars`] *iterator*; Aeneas does
//!   not model `Chars` (iterator-combinator machinery, aeneas#1053/#464).
//! - `derive_spiffe_id` builds its output with `format!` (the `fmt` machinery)
//!   and calls `CallSpiffeId::parse` (drags in the whole lineage parser).
//!
//! The standard Aeneas workflow for that situation is to *scope* the extraction
//! to a dependency-free subgraph and translate only that (the same move
//! `portcullis-core::extracted` makes for the IFC integrity axis). This module
//! hosts `String`/iterator/`format!`-free restatements of the two functions,
//! written so their reachable dependency subgraph stays inside Aeneas's
//! supported safe-Rust subset:
//!
//! - byte classification is a pure `match`/comparison ([`is_spiffe_byte`]);
//! - sanitization is a byte-indexed `while` loop over `&[u8]` producing a
//!   `Vec<u8>` ([`sanitize_bytes`]) — `Vec` + integer indexing IS inside the
//!   Charon/Aeneas subset (unlike `Chars`);
//! - derivation is manual `Vec<u8>` concatenation ([`derive_spiffe_bytes`]),
//!   no `format!`, returning the rendered SPIFFE path as bytes.
//!
//! # Faithfulness (the honest trust chain)
//!
//! Each function here is a behavior-EQUIVALENT mirror of the corresponding
//! production clause, bound to it by the parity proptests in the
//! `#[cfg(test)]` block below:
//!
//! - [`sanitize_bytes`] ≡ production `sanitize_segment` — proven byte-identical
//!   across random strings INCLUDING arbitrary Unicode (multi-byte UTF-8 chars
//!   are all non-ASCII-alphanumeric, so the byte loop collapses each to a
//!   single `-`, exactly as the `char` loop does).
//! - [`derive_spiffe_bytes`] renders the SAME `spiffe://…` path string the
//!   production `format!` does (proven equal across random claim-sets, ahead of
//!   the `CallSpiffeId::parse` step that production layers on top).
//!
//! So: production ≡ this mirror (by inspection + proptest) → this mirror → Lean
//! (by Aeneas). The Lean proofs in `lean/` are stated over the *generated*
//! defs, never a hand model.
//!
//! # The honest scope boundary
//!
//! `sanitize_segment` is **lossy** by design (distinct inputs collapse to the
//! same output: `"a/b"` and `"a-b"` both → `"a-b"`). So the *derivation* is
//! **NOT injective** — distinct claim-sets can mint the SAME SPIFFE id. That is
//! a real finding (a SPIFFE-id collision is an authz-confusion surface within
//! an owner/repo); see the pinned counterexample tests
//! `collision_distinct_refs_same_spiffe_id` / `collision_distinct_repo_segments`
//! below, and `lean/OidcSpiffeProofs.lean` `collapse_lossy_step` for the
//! machine-checked root of the collision over the generated def. We do NOT claim
//! collision-freedom. What we DO prove sorry-free in Lean over the extracted
//! defs is the SPIFFE charset predicate (exhaustive over all 256 bytes) and the
//! lossy-collapse step; idempotence / charset-of-output are corroborated by the
//! Rust proptests here. (See `lean/README.md` for the precise proven set and the
//! disclosed `partial_fixpoint` gap on the full end-to-end collision.)
//!
//! A second honest caveat surfaced by the proptests: the sanitizer does **not**
//! guarantee a `--`-free output. A literal `-` in the input next to a collapsed
//! disallowed-run dash yields `--` (e.g. `"a𖭐-A"` → `"a--A"`; production's own
//! unit test pins `sanitize_segment("a---b") == "a---b"`). So the proven charset
//! theorem is "output ⊆ `[A-Za-z0-9._-]` with no leading/trailing dash" — NOT
//! "no `--` run".
//!
//! The extraction roots live here so the CI extractor can name them with
//! `charon … --start-from nucleus_github_oidc::extracted::oidc_spiffe::<fn>`.

pub mod oidc_spiffe;
