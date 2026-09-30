# Obligation-Vocabulary Reconciliation (Brick 1, Focus Area A)

Status: APPROVED (approach) — sequencing ruled 2026-07-17; sealed-vocabulary change
still lands as one dedicated review-gated PR (the widening in §5).
Decision context: Brandon ruled (a) LIFT the 3 upstream-only obligations into the
sealed bundle ("proof IS the token"); (b) frame = LAYER (discharge set canonical,
`action_term` set = upstream derivation); (c) **sequencing = PLUMB-FIRST, WIDEN ONCE
(2026-07-17)** — thread every witness's inputs to the effect site first, then widen
the sealed vocabulary 5→8 in a single PR (no interim 6-witness bundle). This spec
makes that sound.

## 0. The two vocabularies (as they exist today)

| | `nucleus-ifc-kernel/src/discharge.rs` (5-set) | `portcullis/src/action_term.rs` (6-set) |
|---|---|---|
| Mechanism | **Sealed typestate**: `Discharged<O>` (ZST + private `Seal`), `DischargedBundle`, minted **only** by `preflight_action` (discharge.rs:430,484,791) | **Runtime data**: `enum ProofObligation` in a `Vec` field, derived by `derive_obligations()` (:255), checked into a `PreflightVerdict` (:551–670) |
| Consumed by | `portcullis-effects/runtime.rs:30` — every effect fn requires `_proof: DischargedBundle` | not consumed by the effect API |
| `ActionTerm` shape | `{operation, sink_class, source_labels, artifact_label, subject, estimated_cost_micro_usd}` (discharge.rs:534) | `{task: Option<TaskRef>, action, inputs: Vec<ActionInput>, authority: CapabilityRequest, proposed_effect, obligations}` (action_term.rs:223) |

**Canonical = the sealed discharge set** (it is what the migration binds effect sites
to, and the only one with compile-time teeth). The `action_term` set is the **upstream
data layer** whose satisfaction is a precondition to constructing the discharge term.

## 1. Canonical vocabulary — WIDENED 5 → 8

Existing 5 (unchanged): `IntegrityGate`, `PathAllowed` (operation↔sink coherence),
`DerivationClear`, `NoAdversarialAncestry`, `BudgetNotExceeded`.

Add 3 sealed obligations, each a `struct X; impl ObligationSealed for X {} impl
ProofObligation for X {}` (mirroring discharge.rs:375–410), with a new
`Discharged<X>` field in `DischargedBundle`:

### 1a. `WithinDelegationCeiling`
- **Predicate:** the operation's requested capability level does not exceed the
  policy/session ceiling for that operation.
- **Upstream reference check** (action_term.rs:628–643): `let available =
  ctx.permissions.capabilities.level_for(term.operation()); requested_level >
  available → Deny`.
- **Discharge inputs needed on `ActionTerm`:** (i) the operation (already present);
  (ii) the **capability ceiling** = the runtime's `PermissionLattice`
  (`ctx.permissions.capabilities`); (iii) the **requested level**.
- **Where inputs come from at the effect site:** the ceiling is the runtime's own
  policy — `NucleusRuntime` already holds a policy (see `PolicyEnforced`,
  lib.rs:368+); it must be threaded into `build_term`. The "requested level" is the
  level the operation itself demands (the effect site knows which effect it is
  performing), compared against the ceiling. Cross-check against the live delegation
  path: kernel `decide()` enforces delegation **depth** for `SpawnAgent`
  (kernel.rs ~:1174–1556) and `create_sub_pod` enforces `delegation_ceiling` +
  `check_manage_pods` (pod_mgmt.rs:57,98) — the effect-site witness must be
  **consistent with** (not weaker than) those.
- **Mintability today: PLUMBABLE.** Requires threading the runtime PermissionLattice
  into `build_term`; no new provenance. Land first among the 3.

### 1b. `InputsAuthorized`
- **Predicate:** every input the action depends on is content-addressed (non-empty
  `source_hash`).
- **Upstream reference check** (action_term.rs:593): `term.inputs.iter().any(|i|
  i.source_hash.trim().is_empty()) → Deny`.
- **Discharge inputs needed:** a list of **content-addressed inputs**
  (`ActionInput { source_hash, … }`).
- **Where inputs come from at the effect site:** ⚠️ **NOWHERE TODAY.** `build_term`
  has `source_labels: Vec<IFCLabel>` from the FlowTracker (runtime.rs:723–729) —
  IFC *labels*, **not** content-addressed `ActionInput`s with hashes. There is no
  `source_hash` at the effect site.
- **Mintability today: NOT SOUNDLY MINTABLE.** See §5 (gap G1).

### 1c. `InScopeWithTask`
- **Predicate:** the operation ∈ `task.allowed_operations` and any action path ∈
  `task.allowed_paths`.
- **Upstream reference check** (action_term.rs:554–588): consults
  `term.task: Option<TaskRef>` fields `allowed_operations`, `allowed_paths`.
- **Discharge inputs needed:** a structured `TaskRef` (with allowed_operations /
  allowed_paths).
- **Where inputs come from at the effect site:** ⚠️ `build_term` sets `subject:
  self.task.clone()` (runtime.rs:746) — a **`String`**, not a `TaskRef`. No
  allowed_operations/allowed_paths reach the effect site.
- **Mintability today: NOT SOUNDLY MINTABLE.** See §5 (gap G2).

## 2. Seam resolutions

1. **`PathAllowed` name collision (RESOLVE by rename upstream).** discharge
   `PathAllowed` = operation↔sink structural coherence (`operation_allowed_for_sink`,
   discharge.rs:846). Upstream `PathAllowed` = filesystem path-lattice access
   (`ctx.permissions.paths.can_access`, action_term.rs:647). **Rename the upstream
   variant `PathAllowed → FsPathAllowed`**; keep discharge `PathAllowed` (it is the
   sealed canonical vocabulary referenced by type across crates + `nucleus-code`).
   `FsPathAllowed` stays an **upstream** obligation; it is separately enforced at the
   effect site by `check_path_allowed` (runtime.rs:772) against `allowed_write_paths`
   — it is **not** lifted into the bundle (documented layering, not a gap).
2. **`DerivationClear` / `VerifiedSinkCompatible` overlap (COLLAPSE).** Both encode
   "a verified sink admits only Deterministic/HumanPromoted derivation" (discharge
   `DerivationClear`: artifact label, discharge.rs:745; upstream
   `VerifiedSinkCompatible`: inputs, action_term.rs:661–669). **One source of truth:**
   `VerifiedSinkCompatible` is defined as *witnessed at the effect site by*
   `Discharged<DerivationClear>`. The upstream variant remains a derivation trigger
   but delegates its guarantee to the sealed witness; no second implementation.
3. **`NoAdversarialAncestry` (UNIFY).** Same name, same intent both sides (no
   adversarial/non-deterministic ancestry). Canonical semantics = discharge's: **no
   source label carries `Adversarial` integrity** (discharge.rs:762). Upstream's
   provenance-derivation trigger (action_term.rs:267–277) is the derivation rule that
   *requires* the obligation; the *check* is the sealed one.

### Post-resolution mapping (upstream 6 → canonical)
| upstream `action_term` | canonical outcome |
|---|---|
| `NoAdversarialAncestry` | unified → `Discharged<NoAdversarialAncestry>` |
| `InputsAuthorized` | lifted → `Discharged<InputsAuthorized>` (⚠ G1) |
| `WithinDelegationCeiling` | lifted → `Discharged<WithinDelegationCeiling>` (plumbable) |
| `InScopeWithTask` | lifted → `Discharged<InScopeWithTask>` (⚠ G2) |
| `PathAllowed` → `FsPathAllowed` | upstream + effect-site `check_path_allowed`; **not** in bundle |
| `VerifiedSinkCompatible` | witnessed by `Discharged<DerivationClear>` (collapse) |

## 3. One-way derivation (the layering)

```
UPSTREAM (portcullis::action_term)                CANONICAL (portcullis_core::discharge)
──────────────────────────────────                ──────────────────────────────────────
ActionTerm{task, inputs, authority,               ActionTerm{operation, sink_class,
          proposed_effect}                                   source_labels, artifact_label,
        │                                                    + task_ref, + capability/ceiling,
        │ derive_obligations()                               + content_addressed_inputs, cost}
        ▼                                                          │
  Vec<ProofObligation>  ──checks(551–670)──►  satisfied?          │ preflight_action()
        │                                          │              ▼
        └── satisfied facts + IFC labels ──────────┴──►  mints 8 sealed Discharged<O>
                                                          = DischargedBundle (widened)
                                                                   │
                                                                   ▼
                                              effect_fn(&args, _proof: DischargedBundle)
                                                   (compile error without the bundle)
```

The upstream layer is a **precondition** that supplies the structured inputs
(`task_ref`, `capability request`, `content-addressed inputs`) the widened discharge
term needs. It never itself authorizes an effect — only the sealed bundle does.

## 4. Regression guards (land with the implementation)

- **(a) Cross-layer consistency (property test).** For a corpus of representative
  actions, `derive_obligations()` + upstream checks "all satisfied" ⇔
  `preflight_action(discharge_term)` = `Allowed`, on the shared/lifted obligations.
  Guards against the two layers drifting apart.
- **(b) Single sealed admission type (compile-fail / trybuild).** Extend the existing
  `compile_fail` doc-test (discharge.rs:456). Assert: (i) an effect fn cannot be
  called without the **widened** `DischargedBundle`; (ii) a `DischargedBundle`
  literal missing **any** of the 8 sealed fields fails to compile (all witnesses
  mandatory); (iii) no second admission type is accepted. Reintroducing a bypass or
  re-colliding names fails the build.
- **(c) No-vacuous-witness (unit test — THE soundness guard).** Constructing a
  discharge `ActionTerm` whose task_ref / capability / content-addressed-inputs are
  **absent** must `Deny` (not mint) the corresponding witness — a witness is minted
  **only** when its real input was present and checked. Directly prevents the G1/G2
  unsoundness.

## 5. Honest flags (for Brandon)

- **G1 — `InputsAuthorized` has no effect-site input.** The effect path carries IFC
  labels, not content-addressed `ActionInput{source_hash}`. Lifting this witness is
  sound **only after** the effect path threads content-addressed input provenance to
  `build_term`. Until then it must **not** be a bundle field (a vacuously-minted
  `Discharged<InputsAuthorized>` would be a false proof).
- **G2 — `InScopeWithTask` has no effect-site task witness.** `build_term` has a
  `String` subject, not a `TaskRef`. Same conclusion: thread a structured `TaskRef`
  first, or the witness is vacuous. (Defining what constitutes a trustworthy task
  witness on the agent path has a small threat-model surface — flagged.)
- **Plumbable:** `WithinDelegationCeiling` is soundly mintable once the runtime's
  `PermissionLattice` is threaded into `build_term`; no new provenance.
- **Sequencing = PLUMB-FIRST, WIDEN ONCE (ruled 2026-07-17).** Do NOT widen the sealed
  vocabulary incrementally. First thread every witness's input to the effect site —
  **(P1)** the runtime `PermissionLattice` (ceiling), **(P2)** content-addressed
  `ActionInput{source_hash}` inputs (resolves G1), **(P3)** a structured `TaskRef`
  replacing the `String` subject (resolves G2, gated on the task-witness threat model
  below). Each plumbing step is its own low-risk PR that changes NO sealed type — it
  only enriches `build_term`'s inputs and its callers — so it rides the normal
  auto-merge CI loop. **(W)** ONLY after P1–P3 land does the single vocabulary-widening
  PR extend `discharge.rs::ActionTerm` + `preflight_action` + `DischargedBundle` 5→8 at
  once, with all three §4 regression guards. The bundle never exists in a 6- or
  7-witness intermediate state; it grows exactly when it can honestly mean "all
  admission proven." **First effect-class migration after W = spawn** (Brick 0 backstop
  live; C-1 lineage; smallest agent-path set — `nucleus::Executor` command.rs +
  `mcp-guard` proxy.rs), because spawn (`RunBash`/`SpawnAgent`) exercises delegation +
  task scope and validates the widened bundle end-to-end.
- **OPEN owner-decision surfaced by P3 (task-witness threat model).** The `TaskRef`
  threaded into `build_term` becomes a load-bearing security input (its
  `allowed_operations`/`allowed_paths` will gate `InScopeWithTask`). Before P3, decide:
  what is the trusted source of that `TaskRef` on the agent path, and is it forgeable by
  a compromised/adversarial agent? If an agent can supply or mutate its own task scope,
  `InScopeWithTask` proves nothing. This is escalated to Brandon, not the proxy.

---
*Prior art (soundness of witness minting): F* "Recalling a Witness" monotonic-state witnessed tokens (arXiv:1707.02466); SecRef* (arXiv:2503.00404).*
