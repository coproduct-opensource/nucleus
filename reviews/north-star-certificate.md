# North Star terminal certificate

The honest, machine-checkable stop condition for the North Star terminal push.
This document names the invariant, the exact set of CI assertions that together
mean DONE, the PR trail that is the audit record, and the caveats that keep the
claim honest. It is a point-in-time certificate, not a build input.

---

## The invariant

> **An unmediated external effect is unconstructable.**

A consequential agent effect — process spawn (sync and async), network egress,
filesystem write — cannot be performed without first passing the fail-closed
discharge preflight (`portcullis_core` / `nucleus_ifc_kernel::discharge` →
`preflight_action` → a sealed `DischargedBundle`). This is now **type-enforced on
the live agent path**: every sealed effect fn takes a trailing
`_proof: &DischargedBundle`, the bundle has no constructor other than a
successful preflight, and every raw effect primitive has been relocated behind
that gate into a single sealed home. An un-preflighted effect is a **compile
error**, not a runtime check.

The claim this certificate makes is precise: **the structural invariant is closed
and ratcheted.** It is NOT "the system is secure" (see caveats).

---

## The machine-checkable certificate

DONE ≡ all six assertions below hold simultaneously. Each maps to the concrete
gate or test that enforces it. All are wired into `.github/workflows/ci.yml`.

### (i) Mediation gate green — spawn allowlist EMPTY, net infra-only
- **Enforces:** no raw agent-path effect primitive bypasses the discharge-gated
  effect API.
- **Gate:** `scripts/check-mediation.sh` (CI job `mediation-gate`), scoped to the
  agent effect path (`crates/nucleus/src`, `crates/nucleus-tool-proxy/src`,
  `crates/nucleus-mcp/src`).
- **State:** `scripts/mediation-allowlist.txt` (spawn) is **EMPTY** — every
  agent-path process spawn has been relocated; a new one fails with nothing to
  allowlist it. `scripts/mediation-net-allowlist.txt` exempts only INFRA egress,
  by-file (`node_client.rs` control plane) and by-line (audit S3 / webhook
  operator sinks) — no agent session/token.

### (ii) No raw agent-path spawn/net primitive (the repo grep)
- **Enforces:** the same as (i), stated as a raw-primitive grep: `Command::new`
  (subsumes sync `std::process` and async `tokio::process`) and reqwest
  `.send()` do not appear on the agent path outside the sealed API.
- **Gate:** `scripts/check-mediation.sh` — it IS the repo grep (literal-match,
  `#[cfg(test)]`-stripped).

### (iii) Every effect class unconstructable without a `DischargedBundle`
- **Enforces:** the type-level gate for each effect class. Verified by
  `cargo test --doc` (the `compile_fail` doctests) and `cargo build` (the fn
  signatures that require the proof).
- **`compile_fail` doctests (named):**
  - **Sealed-bundle seal** — `nucleus_ifc_kernel::discharge`, on
    `DischargedBundle` (`crates/nucleus-ifc-kernel/src/discharge.rs`): no external
    struct literal compiles (the `_seal` field is private and `Discharged::mint()`
    is private), so the bundle is unconstructable except via `preflight_action`.
  - **Sync spawn** — `nucleus::Executor::run_args`
    (`crates/nucleus/src/command.rs`): the doctest omits the trailing
    `&DischargedBundle` and does **not** compile.
  - **Filesystem write** — `nucleus::Sandbox::write`
    (`crates/nucleus/src/sandbox.rs`): the doctest omits the proof and does
    **not** compile.
- **Async spawn + net (type-level, by signature — no dedicated doctest):**
  - **Async spawn** — `Executor::run_with_timeout` / `run_with_timeout_approved`
    and the sealed home `AsyncShellSpawnEffect::run_argv_async` all require
    `proof: &DischargedBundle`; the trait's `async fn` is not dyn-compatible, so
    the concrete `PolicyEnforced<RealEffects>` handle is the only reachable path
    and it still demands the bundle.
  - **Net** — `NetEffect::fetch` requires `_proof: &DischargedBundle`; the
    tool-proxy web_fetch/web_search handlers must mint the bundle
    (`preflight_web`) before they may call it.
  These two are the SAME compile-time guarantee as the doctests (the bundle in
  the signature is unconstructable per the seal doctest above), enforced by the
  signature rather than by a dedicated `compile_fail` block.

### (iv) Ingest gate green (content-addressing)
- **Enforces:** every agent-path input observe is content-addressed (hashed) at
  ingest — the `InputsAuthorized` obligation has real evidence to discharge
  against.
- **Gate:** `scripts/check-ingest-hashed.sh` (CI job `ingest-hash-gate`).

### (v) `DischargedBundle` proves 8/8 obligations
- **Enforces:** the sealed bundle carries a typed witness for **all eight** policy
  obligations; `preflight_action` mints it only when every one discharges.
- **The eight** (`crates/nucleus-ifc-kernel/src/discharge.rs`): `IntegrityGate`,
  `PathAllowed`, `DerivationClear`, `NoAdversarialAncestry`, `BudgetNotExceeded`,
  `WithinDelegationCeiling`, `InScopeWithTask`, `InputsAuthorized`.

### (vi) Sealed-home integrity gate green (this brick, B7)
- **Enforces:** the relocation did not open a NEW hole — inside the sealed home
  crate `crates/portcullis-effects/src`, a raw effect primitive
  (`Command::new` / reqwest `.send()`) appears ONLY on the known sealed-home
  lines. A new helper fn, method, or second sink is an un-gated leak and fails
  the build.
- **Gate:** `scripts/check-sealed-home.sh` + `scripts/sealed-home-allowlist.txt`
  (CI job `sealed-home-gate`). The allowlist is the exact trimmed source lines of
  the raw primitives inside `impl … for RealEffects` (the crate's sole
  I/O-capable, externally-unconstructable type): the three `_proof`-gated
  sealed-fn sites (`run_argv`, `run_argv_async`, `fetch`) plus the pre-existing
  policy-gated `ShellEffect::run` and `GitEffect::{commit, push}` legacy methods.

Gates (i), (iv), (vi) are the complementary pair-plus: (i) proves the agent
crates are clean; (vi) proves the sealed home they relocated INTO is clean; (iv)
proves inputs are witnessed. Together with the type-level gates (iii)/(v) they
close the loop.

---

## The PR trail (audit record)

The North Star push, in order. #2029 opened the backstop; this brick (B7) closes
and certifies it.

| PR | Brick | What it landed |
|----|-------|----------------|
| #2029 | brick 0 | Mediation backstop gate — forbid raw agent-path spawns |
| #2030 | Focus-A brick 1 | Obligation-vocabulary reconciliation spec |
| #2033 | — | Thread verified `TaskRef` capability tokens into `NucleusRuntime` |
| #2035 | WIDEN PR-B | Widen sealed `DischargedBundle` 5 → 7 obligations |
| #2038 | — | Gate live `RunBash` on the sealed 7-witness `DischargedBundle` |
| #2039 | — | Route all three sync Executor spawns through `spawn_checked` |
| #2040 | PR-2 | Gate the sync Executor spawn on a `&DischargedBundle` proof |
| #2041–#2044 | InputsAuthorized 1–5 | Content-address agent inputs; ingest ratchet gate; widen bundle 7 → 8 with `InputsAuthorized` |
| #2045 | B1 | Widen `ShellEffect` with the sealed `run_argv` spawn (sealed home) |
| #2046 | B2 | Relocate sync Executor spawn into the sealed home — delete allowlist entry 1 |
| #2047 | B3 | Relocate async Executor spawn into the sealed home — delete allowlist entry 2 |
| #2048 | B4 | Reclassify mcp-guard spawn as infra — spawn allowlist now EMPTY |
| #2049 | B5 | Relocate agent NET egress behind the sealed `_proof` effect + net mediation gate |
| #2050 | B6 | Gate agent FILESYSTEM-WRITE behind the sealed `_proof` `DischargedBundle` |
| this | **B7** | **Sealed-home integrity gate + this terminal certificate** |

---

## Honest caveats (do NOT overclaim)

- **Dual-stack, not replacement.** The sealed `DischargedBundle` runs
  ALONGSIDE the legacy kernel/guard (the existing `DecisionToken` and cap-std
  root confinement are retained, additive). The proof does not yet replace them;
  consolidating to a single stack is deferred to Focus-C.
- **`WithinDelegationCeiling` is dormant.** It is a real obligation in the 8/8
  bundle, but on the current wiring requested == ceiling, so its check does not
  yet constrain anything. It is a placeholder discharged trivially today.
- **Base discharge checks are vacuous on a clean session.** The obligation checks
  are wired to real taint/flow evidence and BITE on an adversarial session, but
  on a clean session with no adversarial ancestry / no budget pressure they
  discharge trivially. The guarantee is "fail-closed structure," not "proven
  non-vacuous on every input."
- **Net infra is exempted by-file/by-line.** The mediation net gate permits infra
  egress (control-plane `node_client.rs`; audit S3 / webhook operator sinks) —
  operator/host authority, no agent session/token. These are permanent
  exemptions, not shrinking debt.
- **Filesystem is 0-raw via cap-std, bundle-gated — not relocated.** The fs write
  path is confined by cap-std (0 raw `std::fs` on the agent write path) and gated
  on the `DischargedBundle` at `Sandbox::write`; it was not relocated into
  `RealEffects` the way spawn/net were.
- **mcp-guard reclassified as infra.** `nucleus-mcp-guard`'s one spawn launches
  the downstream MCP server named on the operator's guard CLI (operator-provided,
  never agent-controlled), so it is infra, not an agent effect. It is out of the
  mediation gate's scope. Re-scope it if it ever spawns from an agent-controlled
  value.
- **Kani-pinned MSRV floor 1.93.** The workspace `rust-version` is pinned to 1.93
  because `cargo kani`'s bundled nightly (kani-verifier 0.67.0) is rustc 1.93 and
  has no `--ignore-rust-version`. The BMC job would refuse to compile above it.
  Raise only when Kani's bundled nightly catches up.

**The claim, stated plainly:** the structural invariant ("an unmediated external
effect is unconstructable") is **closed and ratcheted** on the live agent path.
This is a statement about structure and enforcement — NOT a claim that the system
is secure.

---

## What remains — Focus-C (human-elective, not North-Star-terminating)

None of the following blocks the terminal certificate above; they are elective
follow-ups.

- **Dual-stack consolidation** — collapse the sealed bundle and the legacy
  kernel/guard into a single stack.
- **The recurring `git_commit_allowed_by_codegen_profile` test-footgun** — a
  recurring flaky/footgun test to stabilize.
- **Open audit findings C-3 / C-4 / #16.**
- **SPIFFE binding.**
- **Unreadable-nonce hardening.**
