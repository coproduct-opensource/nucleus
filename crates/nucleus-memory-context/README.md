# nucleus-memory-context

The pure decision kernel for context-indexed, versioned memory. This is Program B,
milestone M1. It is a dependency-free crate. It does no I/O, and nothing on the live
path calls it yet.

A memory space is an object with a linear history of versions. Each run gets a fresh
**binding** to the space and never inherits one from a parent. A binding holds:

- a **view**: which scope atoms the run sees, and up to which label;
- a pinned base **version**;
- a **mode**;
- an **epoch** and a `not_after`.

The kernel decides:

| Function | Decision |
|---|---|
| `restrict(view, narrower)` | Returns `narrower` only if it is within `view`; otherwise refuses with `None`. It never clips and never widens. |
| `observe(section, view)` | Returns every entry the view can see, unchanged (label included), and nothing else. |
| `compare_on_overlap(a, b)` | Do two local sections agree on every key both write? |
| `assemble_candidate(base, patches)` | Glues patches over a pinned `Snapshot`. If two patches write a key differently, that key is marked conflicted; the later write does not silently win. |
| `validate_candidate(candidate, invariants)` | Checks the **whole** candidate: keyed conflicts, label monotonicity (a stored label never lowers, and an entry is never dropped), and a global additive quota. |
| `History::commit(valid)` | Compare-and-swap. A `ValidCandidate` commits only onto the head it was validated against. |
| `admit(binding, epoch, now)` | Admits only in the current epoch, up to `not_after` inclusive. The refusals are `ForeignEpoch` and `Expired`. |

`Snapshot`, `Candidate`, `ValidCandidate` and `AdmittedOp` all have private
constructors. `ValidCandidate` and `AdmittedOp` are `#[must_use]`, not `Clone`, and
consumed by value. Each one carries the state it is valid against: `generation` for
`ValidCandidate`; `epoch` and `not_after` for `AdmittedOp`.

## The finite domain

The domain is finite, so the parity tests are exhaustive and the Lean model can use
`decide`:

- 3 scope atoms;
- 3 label ranks (`Public < Internal < Secret`);
- 4 keys (`K0`, `K1` in atom 0, `K2` in atom 1, `K3` in atom 2);
- 4 content ids;
- 0–15 quota units per entry;
- 8 versions.

The production stores (M2) and the node (M3) will map real record hashes,
namespaces and schema classes onto this kernel. That mapping is not here.

## What is proved — Lean, hand-written model

`crates/portcullis-core/lean/MemoryContext.lean` is Mathlib-free. It has no `sorry`,
and it closes finite facts with kernel `decide` only, never `native_decide`. It is
built by the `portcullis-core-proven-lean` workflow and audited for axioms there.
The headline theorems depend on at most `propext`, `Classical.choice` and
`Quot.sound`.

- **Restriction:** `restrict_identity`, `restrict_composition`,
  `restrict_through_intermediate`, `restrict_never_widens` (the scope only shrinks
  and the ceiling never rises), and `restrict_refuses_wider`.
- **Observation:**
  - `observe_keeps_entries`: an observed entry is the stored one, so restriction
    never lowers a label;
  - `observe_restrict` and `observe_of_restrict`: observing through a narrower view
    is the same as restricting the observation.
- **Assembly:**
  - `assembly_recovers`: wherever a key is not conflicted, the candidate holds what
    every patch wrote;
  - `assembly_keeps_base`;
  - `two_patch_conflict`: two patches conflict on a key exactly when they disagree on
    it.
- **Validation:**
  - `validate_valid`: a `valid` verdict means no conflict, no lowered or dropped
    label, and the quota holds;
  - `validate_refuses_conflict`;
  - the **6 + 6 > 10 budget counterexample**, as `decide` examples: overlap agreement
    holds and validation still refuses. A validator that checks only overlap
    agreement (`overlapOnly`) accepts it.
- **Versions:** `version_stable`, `version_stable_many` and `commit_refuses_stale`.
- **Admission:** `admission_iff` (admitted iff the epoch is current and `now ≤ not_after`),
  `old_epoch_refused` and `revoke_refuses`.
- **Noninterference:** contextual noninterference by unwinding over the ops
  `bind | propose | publish | revoke`. It rests on three conditions, stated directly
  as in `PodCrossView.lean`:
  - `output_consistency`;
  - `local_respect`: another principal's bind, propose or publish leaves the run's
    context unchanged;
  - `step_consistency`: the run's own propose and publish, and a revocation, keep
    related states related.

  `unwinding` and `contextual_noninterference` follow from these. A run's observation
  after any trace that does not rebind it equals its observation after the same trace
  with every other principal's ops purged.
- **Coarse relation fails:** three `example`s, each showing that a weakened relation
  breaks an unwinding condition:
  - ignoring the epoch;
  - observing the head instead of the pinned version;
  - pinning a version that does not exist yet.

`UnwindingNoninterference.lean`'s `JoinOrder` class is a label order over a DAG
fold, which does not fit a state machine over sections. So the conditions are stated
directly.

### Named and not covered: the publish verdict

`obs` (the run's observation in the Lean model) is the run's pinned view and its own
branch. The **publish verdict** is not part of `obs`. The global quota is computed
over the whole candidate, so a run's publish can be accepted in one state and refused
in another state the run cannot tell apart. The last `example` in the Lean file
demonstrates this: a hidden entry outside the run's scope spends the quota.

This is a declared channel, not a proved-away one. The M5 oracle must treat it that
way.

## What is parity-tested — Rust ↔ Rust, exhaustive

Each slice in `src/extracted/` is a flat restatement of one production decision. A
slice uses only integers, `bool`s and `Copy` structs, and compares on explicit ranks
or fields, never a derived `PartialEq`/`Ord`. `src/parity_tests.rs` binds each slice
to its production function by exhaustive case analysis over the finite domain. Each
loop asserts its case count.

| Slice | Production | Domain |
|---|---|---|
| `view::scope_subset` | `Scope::is_subset_of` | 8 × 8 scopes |
| `view::restrict_admits` | `restrict` | 24 × 24 views |
| `observe::observe_slot` | `observe` | 24 views × 4 keys × 193 slots |
| `overlap::slots_agree` | `compare_on_overlap` | 4 keys × 193 × 193 slots |
| `assemble::step_slot` | `candidate::step_slot` | 193 slots × 4 flag states × 193 slots |
| `validate::slot_check` | `validate_candidate`, per key | 4 keys × 2 × 193 × 193 |
| `validate::add_units`, `quota_admits` | `validate_candidate`, quota | (absent \| 0..=15)⁴ × boundary quotas; 61 × 65 536 |
| `admit::admit_code` | `admit` | every boundary epoch/instant (625 cases), plus proptest over full `u32`/`u64` |
| `commit::commit_code` | `History::commit` | 8 heads × 256 generations |

`admit` is the only slice that is not finite. Its exhaustive set is the boundary
window `{0, 1, 2, MAX−1, MAX}` for each argument, and proptest covers the full range.

`src/laws_tests.rs` checks the Lean laws over the Rust:

- exhaustively, for restriction identity, composition over every view triple, and
  never-widens;
- by seeded proptest, for observation, assembly recovery, whole-candidate validity,
  version stability and admission.

It also has a named test for each counterexample: the budget case, a keyed conflict,
a lowered label, a stale base followed by a rebase, a full history, an old epoch, and
a pinned read that does not move when the head does.

## What is NOT yet extracted

No Charon/Aeneas run consumes `src/extracted/` yet. The Lean model mirrors the Rust
definitions **by hand**, and nothing mechanically checks that correspondence.

- **Rust side:** the parity tests bind the flat slices to production.
- **Lean side:** the model is a hand-written mirror of those slices and of the folds
  over keys and patches.

Extracting the slices to Lean and proving the theorems over the extracted code is a
follow-up. It needs a new extraction workflow: the existing ones extract
`nucleus-ifc-kernel` only.

This crate is not in the wasm-embedded closure of `sdks/verifier-js`.
