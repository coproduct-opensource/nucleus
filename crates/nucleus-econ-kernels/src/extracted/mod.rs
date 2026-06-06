//! Aeneas-extracted Rust mirrors of the Nucleus Lean specs.
//!
//! These files hold Rust functions whose semantics are intended to be
//! byte-identical to the corresponding Lean definitions in
//! `formal/Nucleus/Auctions/*.lean`. The substrate's correctness story
//! depends on this parity: the Lean theorems certify properties of the
//! Lean definitions, and the parity tests in `tests/lean_model_parity.rs`
//! turn that into a guarantee about the Rust functions the kernel
//! actually executes.
//!
//! # Current status (A4 wedge)
//!
//! Full Aeneas extraction (Charon → LLBC → Aeneas → Lean-extracted Rust
//! mirror) lands in Month 8+. Until then this module holds **manually
//! transcribed** mirrors whose shape is line-for-line faithful to the
//! Lean source, so any divergence is greppable in code review and
//! visibly caught by the parity proptests.
//!
//! When the full Aeneas pipeline goes live, the
//! `coproduct-opensource/aeneas-ci@v1` reusable GHA performs a
//! `git diff --exit-code` regen check that catches Rust↔Lean drift in
//! CI. The CHARON/AENEAS pipeline reference is
//! <https://github.com/AeneasVerif/aeneas>.
//!
//! # Aeneas subset discipline (AE.2)
//!
//! Every function in this module must stay inside the Rust subset Charon +
//! Aeneas can translate, because `scripts/aeneas-extract.sh` extracts these
//! roots to Lean (`formal/extracted/`). The subset, as of the pinned
//! `nightly-2026.05.30` toolchain:
//!   - integer ops only (saturating `u64`/`u128`), no floats;
//!   - simple loops / structural recursion (recursion lowers to Lean
//!     `partial_fixpoint`);
//!   - NO closures, interior mutability, `unsafe`, concurrency, or advanced
//!     generics (`for<'a>` nests).
//!
//! Extraction is scoped with `charon --start-from <root>` so the reachable
//! subgraph never drags in non-subset dependency code (e.g. `hybrid-array`,
//! `typenum`) — a whole-crate `charon cargo` would fail on those. If you add a
//! root here, add a matching `--start-from` in `scripts/aeneas-extract.sh`.

pub mod commons_aeneas;
pub mod pigou_aeneas;
pub mod settlement_aeneas;
pub mod vcg_aeneas;
