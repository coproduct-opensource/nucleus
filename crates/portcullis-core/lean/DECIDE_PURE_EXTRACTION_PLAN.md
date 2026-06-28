# `decide_pure` refinement-proof plan (round 2)

**Status: PLAN ONLY — nothing in this doc is wired into the lake build yet.**
The Aeneas-generated `decide_pure` does **not** exist in this checkout. It is
produced by CI (`.github/workflows/aeneas-decide-pure.yml`, round-1 deliverable),
which runs scoped Charon + Aeneas on a Linux runner and **auto-commits** the
result to `generated-decide/PortcullisCoreDecide/{Types,Funs}.lean` on branch
`feat/aeneas-decide-pure-extract`. Charon/Aeneas cannot run on this machine
(prebuilt binaries are Linux-only; no nix). Adding a `lean_lib` or a proof file
that `import`s the not-yet-generated module would break `lake build` for everyone
until the bot commit lands, so round 2 is sequenced strictly **after** that commit.

This plan is the explicit recipe for round 2. It mirrors the already-VERIFIED
template `IntegrityNoninterferenceExtracted.lean` (kernel-checked, `#print axioms`
audited to exactly `[propext, Classical.choice, Quot.sound]`, zero `sorry`).

---

## 0. Precondition gate (do these in order, do not skip)

1. CI run of `aeneas-decide-pure.yml` on `feat/aeneas-decide-pure-extract` is
   **green** and its bot commit
   (`chore(aeneas): regenerate decide_pure extraction (generated-decide/)`,
   carrying `[skip ci]`) has landed.
2. `git pull` so `crates/portcullis-core/lean/generated-decide/PortcullisCoreDecide/{Types,Funs}.lean`
   are present locally.
3. **Read the `CANONICAL-FUNS`/`CANONICAL-TYPES` log dump** from that CI run
   (the workflow `cat`s both files to the job log). The exact monadic signatures
   and the generated namespace path are the ground truth the proof is written
   against — do NOT guess them from this plan. The names below
   (`nucleus_ifc_kernel.decide_pure`, `nucleus_ifc_kernel.should_gate`, etc.) are the
   **expected** Charon lowering of `nucleus_ifc_kernel::decide_pure`; if Aeneas
   nests them differently (e.g. an intermediate module), update every qualified
   reference in the new proof file to match the dump. This is the single most
   common failure mode (cf. the IFC file's `nucleus_ifc_kernel.extracted.ifc_integrity.*`
   path, which was only confirmable from its own dump).

If the precondition is not met, **stop** — do not author the proof against a
guessed signature.

---

## (a) Importing the regenerated `decide_pure`

### a.1 Register the generated lib in `lakefile.lean`

Add ONE `lean_lib` next to the existing `«PortcullisCoreIFC»` block (line ~39),
matching the round-1 directory/namespace convention
(`generated-decide/PortcullisCoreDecide/{Types,Funs}.lean`, where `Funs.lean`'s
import was sed-retargeted from `PortcullisCore.Types` → `PortcullisCoreDecide.Types`
to avoid colliding with the existing `«PortcullisCore»` lib):

```lean
-- Aeneas-generated decide_pure enforcement core (from real Rust:
-- crates/portcullis-core/src/lib.rs::decide_pure + its exposure closure).
-- Function bodies are UNMODIFIED Aeneas output; only Funs.lean's inter-module
-- import path was retargeted (PortcullisCore.Types → PortcullisCoreDecide.Types)
-- so this lib does not collide with the «PortcullisCore» lib.
lean_lib «PortcullisCoreDecide» where
  roots := #[`PortcullisCoreDecide.Types, `PortcullisCoreDecide.Funs]
  srcDir := "generated-decide"
```

Then add the proof lib (the new file from step b/c):

```lean
-- Refinement proof: the 6 decide_pure safety theorems re-proven OVER the
-- Aeneas-generated decide_pure (from real Rust) instead of the hand model.
lean_lib «DecidePureExtractedProofs» where
  roots := #[`DecidePureExtractedProofs]
```

> **Do NOT make either edit in this round.** Both are listed here only so round 2
> applies them verbatim once the generated files exist. Adding `«PortcullisCoreDecide»`
> now would point `srcDir` at files that do not exist and fail `lake build`.

### a.2 New file header / imports

Create `crates/portcullis-core/lean/DecidePureExtractedProofs.lean` with the same
import + `open` preamble as `IntegrityNoninterferenceExtracted.lean` (lines 51–54):

```lean
import PortcullisCoreDecide.Types
import PortcullisCoreDecide.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

set_option maxHeartbeats 1000000   -- headroom for the case-split rfl reductions
```

The generated functions return the Aeneas `Result` monad and live under the
`nucleus_ifc_kernel` namespace (confirm exact path from the dump — see §0.3).

---

## (b) Stating and proving `decide_pure_refines`

### b.1 The bridge statement

Goal: prove the generated, `Result`-monadic `decide_pure` equals (after stripping
`ok`) the hand model already proven in `DecidePureProofs.lean`. State it so the
RHS is the existing hand model, letting us **transfer** rather than re-derive
(see §c). The generated enums are distinct Lean types from the hand model's
`DecidePureProofs.{CapabilityLevel, ExposureSet, Operation, PureVerdict}`, so the
bridge needs total, structure-preserving maps between them:

```lean
namespace DecidePureExtractedProofs

-- Aliases for the generated (from-Rust) types. Confirm exact paths from the dump.
abbrev GLevel := nucleus_ifc_kernel.CapabilityLevel
abbrev GExp   := nucleus_ifc_kernel.ExposureSet
abbrev GOp    := nucleus_ifc_kernel.Operation
abbrev GVerd  := nucleus_ifc_kernel.PureVerdict

-- Total bijections generated-enum ↔ hand-model enum (one match arm per ctor).
def toLevel : GLevel → DecidePureProofs.CapabilityLevel
  | .Never => .Never | .LowRisk => .LowRisk | .Always => .Always
def toOp : GOp → DecidePureProofs.Operation
  | .ReadFiles => .ReadFiles | .WriteFiles => .WriteFiles | …   -- all 13 arms
def toExp : GExp → DecidePureProofs.ExposureSet
  | { private_data := p, untrusted_content := u, exfil_vector := e } => ⟨p, u, e⟩
def toVerd : GVerd → DecidePureProofs.PureVerdict
  | .Allow => .Allow | .DenyCapability => .DenyCapability
  | .RequiresApproval => .RequiresApproval | .GateExfil => .GateExfil
```

> Generated field/ctor names are the expected Charon lowering of the Rust
> identifiers (`private_data`, `untrusted_content`, `exfil_vector`; the 13
> `Operation` variants `ReadFiles … SpawnAgent`; the 4 `PureVerdict` variants).
> Reconcile against the dump before writing — a renamed field is a compile error,
> not a soundness hole.

The refinement theorem:

```lean
/-- The Aeneas-generated `decide_pure` (Result-monadic, from real Rust) refines
    the hand-written model: it always returns `ok`, and the carried verdict is
    exactly the model's verdict on the mapped arguments. -/
theorem decide_pure_refines (level : GLevel) (exp : GExp) (op : GOp) :
    nucleus_ifc_kernel.decide_pure level exp op
      = ok (fromVerd (DecidePureProofs.decide_pure (toLevel level) (toExp exp) (toOp op))) := …
```

where `fromVerd : DecidePureProofs.PureVerdict → GVerd` is the inverse of `toVerd`
(needed because the generated function's `ok` payload is a `GVerd`). Equivalently,
state it as `(decide_pure …).map toVerd = ok (DecidePureProofs.decide_pure …)`,
whichever reduces more cleanly against the actual generated body — decide from the
dump.

### b.2 Proof strategy (Result/ok monad handling)

Follow the three-pillar pattern proven in the template:

1. **Read-discriminant `rfl` lemmas** (template lines 69–74, 88–95). The generated
   `==` on `CapabilityLevel` lowers to
   `read_discriminant self = read_discriminant other` (this is exactly the
   mechanism documented in `DecidePureProofs.lean` lines 13–16, referencing
   `generated/Funs.lean`'s
   `CapabilityLevel.Insts.CoreCmpPartialEqCapabilityLevel.eq`). The generated
   `decide_pure` body is a chain of `do`-binds: `level == .Never` → `ok bool`,
   `Result.bind (ok _)` reduces by iota, then the next branch. Each concrete
   triple normalizes in the kernel.

2. **Bind lemmas — exhaustive case split + `rfl`** (template line 95:
   `cases a <;> cases b <;> rfl`). Here:

   ```lean
   theorem decide_pure_refines (level : GLevel) (exp : GExp) (op : GOp) : … := by
     -- ExposureSet is 3 bools; Operation is 13 ctors; CapabilityLevel is 3 ctors.
     -- Splitting all of them makes every `do`-bind, every read_discriminant `==`,
     -- and `should_gate`/`project_exposure`/`classify_operation` reduce to a
     -- concrete `ok _` on BOTH sides; they match definitionally.
     cases level <;>
       (cases exp with | mk pd uc ev =>
         cases pd <;> cases uc <;> cases ev <;>
         cases op <;> rfl)
   ```

   Use `rfl` (NOT `decide`): the Aeneas `Result` type derives only `Repr, BEq`,
   not `DecidableEq` (template lines 93–94, 167). If a particular arm does not
   close by `rfl` because Aeneas emitted a non-`do` shape (e.g. a `match` on the
   `==` Bool rather than a bind), fall back to
   `simp only [nucleus_ifc_kernel.decide_pure, nucleus_ifc_kernel.should_gate,
   nucleus_ifc_kernel.project_exposure, nucleus_ifc_kernel.classify_operation,
   Result.bind, …]` then `rfl` — model the simp set on what the dump shows.

   Cost note: the split is `3 × 2³ × 13 = 312` kernel-`rfl` goals. That is why
   `maxHeartbeats 1000000` is set (matches the template's headroom rationale,
   lines 56–58). If it is slow, narrow with `cases op <;> cases level <;> …` or
   prove an intermediate `should_gate_refines` lemma first (see b.3).

3. **Helper refinement lemmas** for the exposure closure, if the monolithic split
   is unwieldy — each proven the same `cases … <;> rfl` way over `Result`:

   ```lean
   theorem classify_operation_refines (op : GOp) :
       nucleus_ifc_kernel.classify_operation op = ok (DecidePureProofs.classify_exfil (toOp op)) := by
     cases op <;> rfl
   theorem project_exposure_refines (exp : GExp) (op : GOp) :
       nucleus_ifc_kernel.project_exposure exp op
         = ok (fromExp (DecidePureProofs.project_exposure (toExp exp) (toOp op))) := by
     cases exp with | mk p u e => cases op <;> rfl
   theorem should_gate_refines (exp : GExp) (op : GOp) :
       nucleus_ifc_kernel.should_gate exp op = ok (DecidePureProofs.should_gate (toExp exp) (toOp op)) := by
     -- unfold generated should_gate; rw [project_exposure_refines, classify_operation_refines];
     -- the Result-binds collapse, leaving the same Bool && on both sides.
     …
   ```

   Then `decide_pure_refines` rewrites with these (cf. template `irun_step_ok`
   lines 125–129: `unfold … ; rw [imeet_ok]`).

   > **Watch item carried from round 1:** `ExposureSet::set(&mut self)` and the
   > `let mut projected = *current; projected.set(label)` pattern in
   > `project_exposure` (`src/lib.rs`). If Aeneas lowered `set` to an opaque
   > `*External` function, `project_exposure_refines` will fail to reduce and the
   > axiom audit (§c.3) will show a `*External` axiom. Fix in that case: refactor
   > the Rust to a pure struct-update `ExposureSet { private_data: …, .. *current }`,
   > re-run the CI extraction, then re-prove. Mark with
   > `-- TODO(aeneas): pure struct-update if set() lowered to *External` if it bites.

### b.3 Stripping `ok` / `decide` at use sites

The two `Result`/`decide` unwrap lemmas from the template are reused verbatim when
transferring the iff-shaped theorems (§c):

- `Result.ok.injEq` — strips the `ok` constructor (template line 191).
- `decide_eq_true_eq` — strips a `decide` wrapper to the underlying `Prop`
  (template line 191). Only needed if a generated comparison surfaces as
  `ok (decide P)`; `decide_pure` returns an enum verdict, not a Bool, so this is
  mainly for any `should_gate`-derived `ok bool` equalities.

---

## (c) Transferring the 6 theorems onto the generated def

The six properties already proven in `DecidePureProofs.lean` (all kernel-checked,
no holes) are:

| # | Theorem (hand model) | Lines |
|---|----------------------|-------|
| 1 | `never_always_denies` | 101 |
| 2 | `lowrisk_always_requires_approval` | 106 |
| 3 | `allow_requires_always_and_no_gate` | 112 |
| 4 | `gate_exfil_iff` | 117 |
| 5 | monotonicity (`decide_monotone` + the 3 pairwise lemmas) | 133–169 |
| 6 | exhaustiveness (`decide_pure_exhaustive`) | 176 |

(plus the two gate-soundness corollaries `empty_exposure_no_gate` /
`non_exfil_no_gate`, which transfer the same way — include them for completeness.)

### c.1 Transfer pattern (preferred): rewrite through `decide_pure_refines`

Each generated-side theorem is stated over `nucleus_ifc_kernel.decide_pure`, then
discharged by `rw [decide_pure_refines]` (collapsing the generated call to
`ok (fromVerd (DecidePureProofs.decide_pure …))`), `simp only [Result.ok.injEq]`
to strip `ok`, and `exact`/`rw` the corresponding hand-model theorem. Example for
#1:

```lean
theorem g_never_always_denies (exp : GExp) (op : GOp) :
    nucleus_ifc_kernel.decide_pure .Never exp op = ok .DenyCapability := by
  rw [decide_pure_refines]
  -- ok (fromVerd (decide_pure .Never (toExp exp) (toOp op))) = ok .DenyCapability
  simp only [Result.ok.injEq]
  rw [DecidePureProofs.never_always_denies]   -- model: = .DenyCapability
  rfl   -- fromVerd .DenyCapability = .DenyCapability
```

For the iff-shaped #3/#4, after `rw [decide_pure_refines]` and stripping `ok`
(`Result.ok.injEq`) plus mapping `fromVerd`/`toVerd` injectivity, the goal becomes
the model iff, closed by the model theorem (`allow_requires_always_and_no_gate` /
`gate_exfil_iff`) — but with `should_gate` replaced by the generated
`nucleus_ifc_kernel.should_gate` via `should_gate_refines` so the RHS is genuinely
about the generated function.

For #5 monotonicity, restate using
`(toVerd (carried verdict)).restriction` — i.e. map the generated verdict back to
the model enum, then invoke `decide_monotone`; the `restriction` ordering is a
model-side function, and `decide_pure_refines` guarantees the carried verdict
matches, so the inequality transfers by `rw [decide_pure_refines] at *`/`simp`.

For #6 exhaustiveness, `rw [decide_pure_refines]` then `rcases
DecidePureProofs.decide_pure_exhaustive …` and map each disjunct through `fromVerd`.

### c.2 Alternative (restate directly)

If, after reading the dump, the generated body is simple enough that the
case-split closes each property directly (`cases level <;> cases exp … <;> cases op
<;> simp [nucleus_ifc_kernel.decide_pure, …]`), it is acceptable to **restate and
re-prove directly** over the generated def WITHOUT going through
`decide_pure_refines` — exactly as `IntegrityNoninterferenceExtracted.lean` proves
its properties directly over the generated `imeet`/`iflows_to` rather than bridging
to a model. Choose whichever yields a shorter, hole-free proof; the refinement
route (c.1) is preferred because it reuses the already-VERIFIED hand-model proofs
and makes the model↔extracted correspondence an explicit, audited theorem.

### c.3 Zero `sorry` + axiom audit (non-negotiable)

End the file with the SAME audit block shape as the template (lines 215–233):

```lean
end DecidePureExtractedProofs

/-
  Axiom audit. EXPECTED set for every theorem below is exactly:
      [propext, Quot.sound, Classical.choice]
  Anything else — `sorryAx` (a proof hole) or any Aeneas-emitted `*External`
  opaque axiom — MUST fail review. (Classical.choice enters via omega/by_cases;
  it is part of the trusted Lean/Mathlib kernel set, not a hole.)
-/
#print axioms DecidePureExtractedProofs.decide_pure_refines
#print axioms DecidePureExtractedProofs.g_never_always_denies
#print axioms DecidePureExtractedProofs.g_lowrisk_always_requires_approval
#print axioms DecidePureExtractedProofs.g_allow_requires_always_and_no_gate
#print axioms DecidePureExtractedProofs.g_gate_exfil_iff
#print axioms DecidePureExtractedProofs.g_decide_monotone
#print axioms DecidePureExtractedProofs.g_decide_pure_exhaustive
```

- **No `sorry`, no `admit`, no `native_decide`.** The CI reject-`sorry` grep
  (the IFC/OIDC jobs grep proof files and fail on a match) will catch any hole;
  `native_decide` is banned because it adds `Lean.ofReduceBool` to the axiom set,
  breaking the `[propext, Quot.sound, Classical.choice]` assertion. Use `decide`
  only on `DecidableEq` model types (never on `Result`), and `rfl`/`omega`/`simp`
  elsewhere — matching how the template stays within the three trusted axioms.
- A surfacing `*External` axiom means an opaque generated function leaked in (the
  `set()` risk in b.2) — that is a real gap to fix in Rust + re-extract, not to
  paper over.

---

## CI wiring (round 2, after the proof compiles)

Add to `aeneas-decide-pure.yml` (mirroring the `aeneas-ifc-scoped` / OIDC jobs)
a post-extraction step sequence:

1. `lake build PortcullisCoreDecide` (the generated lib).
2. `lake build DecidePureExtractedProofs` (the proof).
3. **Reject-sorry gate:** `grep -rn 'sorry\|admit\|native_decide' DecidePureExtractedProofs.lean`
   → fail on any hit.
4. **Axiom-audit gate:** capture the `#print axioms` output and assert each line is
   a subset of `{propext, Quot.sound, Classical.choice}`; fail on `sorryAx` or any
   `*External`.

Use the SAME Mathlib/Aeneas toolchain cache as the existing `lean-build` job
(v4.30.0-rc2; the `lake build (Nucleus formal)` 504 elan flake is known — rerun
`--failed` if it hits, per repo memory).

---

## Housekeeping after the bot commit lands

Once CI has auto-committed `generated-decide/PortcullisCoreDecide/{Types,Funs}.lean`
and the proof is in place, update the **header comment of `DecidePureProofs.lean`**
(currently lines 11–22) which still says `decide_pure` and its exposure
dependencies "were left OUTSIDE the Charon extraction scope" and the model is used
"instead". Change it to record that `decide_pure` is now genuinely Aeneas-extracted
(under `generated-decide/PortcullisCoreDecide/`), that the refinement is proven in
`DecidePureExtractedProofs.lean` via `decide_pure_refines`, and that this hand model
is retained only as the proof-convenience RHS of that refinement (not as a
standalone substitute). Keep the cross-reference to
`docs/handoffs/aeneas-decide-pure-extraction.md`.

---

## Summary of round-2 edits (NONE applied in this round)

| File | Edit | When |
|------|------|------|
| `lakefile.lean` | add `lean_lib «PortcullisCoreDecide»` + `lean_lib «DecidePureExtractedProofs»` | after bot commit lands |
| `DecidePureExtractedProofs.lean` | NEW — refinement + 6 transferred theorems + axiom audit | after bot commit lands |
| `aeneas-decide-pure.yml` | add `lake build` + reject-sorry + axiom-audit steps | after proof compiles |
| `DecidePureProofs.lean` | update header comment: `decide_pure` now extracted | after proof compiles |

Until the generated files exist, **none of these are made** — this plan is the
sole round-2 deliverable.
