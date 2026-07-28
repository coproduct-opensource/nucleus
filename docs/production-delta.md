# Production Delta

What must be true before Nucleus can be called enterprise-ready. This page consolidates gaps from [SECURITY_TODO.md](../SECURITY_TODO.md), [FORMAL_METHODS.md](../FORMAL_METHODS.md), and [Verified Claims](verified-claims.md) into one checklist.

## Hardening

| Item | Status | Detail |
|------|--------|--------|
| Command exfiltration detection beyond program-name | Partial | `bash -c 'curl ...'` bypasses. Default command lattice blocks common flags; broader coverage and fuzzing pending. Firecracker network policy is the backstop. |
| Path sandboxing: unicode + symlink races | Partial | Symlink escape test added for `work_dir`; unicode NFC/NFKC normalization and Windows path edge cases not fuzzed. `cap-std` provides defense-in-depth. |
| Budget enforcement atomicity | Partial | Pre-exec reservation works. Post-exec cost accounting and output-based charges not implemented. A process can run even if budget is exhausted. |
| Approval tokens: anti-automation | Done (type-level) | `ApprovalToken` required for gated ops. Callbacks only mint tokens. No structured proof-of-human (e.g., signed challenge) yet. |
| Discharge scope binding | Done | Every mediated `NucleusRuntime` method checks the bundle's `(Operation, SinkClass)` against its own, and `write_file` re-checks the path allowlist. Previously the bundle was accepted unread, so a read bundle authorized a write and could redirect it outside `allowed_write_paths`. The predicate is now proved over the Aeneas-extracted Rust ([claim 8a](verified-claims.md)) with a clean axiom set. |
| Enforcement completeness (#1216) | Done (effect layer) | **All 13 effect-trait methods take an `Authority` by value** — scoped, and one-shot by move semantics, so replay is a compile error. Before this work 10 of 13 took no obligation token at all and 3 took a `&DischargedBundle` that could be replayed. Ownership is threaded through `nucleus::Executor` (10 signatures) and `nucleus-tool-proxy`. Residual, out of scope here: the `nucleus::Sandbox` surface, tracked in its own row below. |
| Effect receipts (witness) | Partial | Every mediation decision through `PolicyEnforced` appends a leaf to an RFC 6962 Merkle log naming the `(Operation, SinkClass)` and the outcome. Supports **inclusion** proofs (`O(log n)`), **consistency** proofs, an Ed25519-signed checkpoint, and a **witness** verification core (C2SP `tlog-witness` checks) that refuses to cosign a checkpoint which is not a provable append-only extension — closing split-view/fork detection. Append-only by construction. **Coverage is all 13 effect methods.** The receipt is written by `Authority::spend` rather than at the gate, so the three that spend further down — `run_argv`, `run_argv_async`, `NetEffect::fetch` — are witnessed where they consume the authority; previously process execution and network egress were the only effects *absent* from the log. Because `Authority` is affine and `spend` is the only way to consume one, "the authority was exercised" and "a receipt exists" are the same event. **Open:** a receipt records an authorised spend, not a completed effect — `Allowed` is written upstream of the syscall, and splitting *authorised* from *committed* needs a post-effect event that is not implemented; attaching the witness is still a call the mediation layer makes, so a new forwarding method that omitted it would enforce correctly but log nothing (guarded by `the_deferred_spend_methods_are_witnessed_where_they_spend`, whose dependence was established by perturbation); the witness is a verification core, not a running service (no HTTP, no persistence, no origin multiplexing); no public anchoring; the signing key is caller-supplied and **not bound to a measured binary**. |
| `Sandbox` mediation | Done | All 22 `DecisionToken`-taking `Sandbox` methods now require an owned `Authority` and spend it against the operation they declare — reads against `(ReadFiles, AuditLogAppend)`, edits and writes against `WorkspaceWrite`. Previously only `write`/`write_approved` took a discharge and both ignored it (`_proof`, zero reads), so any bundle authorized a write and `remove_file` deleted with no discharge at all. The HTTP and MCP read paths had no discharge either; both now mint one via `run_gate::preflight_read_fs`. Not covered: `exists`/`exists_approved` return `bool` with no error channel, so mediating them is a signature change rather than a check; and `read_to_string_for_search` takes no `DecisionToken`. |
| `NucleusRuntime::effects()` escape hatch (#1248) | Open | Returns raw `PolicyEnforced` bundle without obligation discharge or FlowTracker update. |
| Type-level IFC not composed into runtime API (#1249) | Open | `read_file()` returns `Vec<u8>`, not `Labeled<Vec<u8>>`. Runtime and compile-time IFC are independently correct but not wired together. |

## Validation

| Item | Status | Detail |
|------|--------|--------|
| Lean proofs cover the full state space | Done | 165 theorems, zero `sorry`. Unbounded for lattice algebra. |
| Kani BMC for decision logic | Done | 112 harnesses. Bounded — covers full 3-element, 13-dimension state space for lattice; string/path checks are bounded approximations. |
| Monotonicity & boundary invariants | Done | Proven via Lean 4 + Kani — exposure monotonicity, trace monotonicity, denial monotonicity, auth boundary, capability coverage, budget monotonicity, delegation ceiling. (Verus was evaluated and removed; verification consolidated on Lean 4 + Kani.) |
| Fuzz targets in CI | Done | 3 targets (command, path, permission serde) with 30s budget each. Required merge check. |
| Aeneas-generated Lean code is stale | Open | Committed `Types.lean` has 12 `CapabilityLattice` fields; Rust source has 13 (`spawn_agent` added). CI re-extracts and checks, but committed files need updating. |
| Exposure tracker Lean model is hand-written | Acknowledged | `include_str!` tests enforce structural correspondence. Semantic correspondence is not machine-verified. Aeneas cannot currently translate `ExposureSet`. |
| Receipt chain append-only property | Open | Hash chaining and Ed25519 signing tested, but append-only guarantee not formally proved (#427). |
| Hook I/O boundary unverified | Acknowledged | stdin/stdout JSON parsing is a trusted edge. `hook_adapter` extracts pure decision logic; I/O wrapper remains unverified. |

## Operational

| Item | Status | Detail |
|------|--------|--------|
| SPIFFE identity deployment | Implemented | Code exists for mTLS + cert management. No SPIRE deployment or integration testing. |
| Firecracker in production | Tested | Real jailer invocation + iptables. Linux+KVM only. Not deployed to production infrastructure. |
| Audit log S3 sink | Implemented | HMAC-SHA256 chain with optional S3 append-only sink. Not production-tested. |
| Fleet lockdown (`nucleus lockdown`) | Tested | Drops agents to read-only via gRPC streaming (sub-second). Not deployed. |
| `--local` vs Firecracker isolation gap | Documented | `--local` mode has weaker isolation. Tier 2 (Firecracker) required for high-security workloads. |

## External Review

| Item | Status | Detail |
|------|--------|--------|
| Independent security audit | Not started | No third-party review of the codebase. |
| Design partner case study | Not started | No external organization has deployed Nucleus in production. |
| Red team by external researchers | Not started | Internal red team covers 162 scenarios (OWASP LLM Top 10 + DPI flow attacks). No external red team. |
| AgentDojo benchmark comparison | Not started | Adversarial materials exist but no published baseline comparison (Nucleus vs no-Nucleus). |

## How to Read This Page

- **Done**: implemented, tested, CI-gated.
- **Partial**: works for common cases, known gaps documented.
- **Implemented**: code exists, minimal testing.
- **Open**: tracked in a GitHub issue, not yet addressed.
- **Acknowledged**: known limitation with no current plan to close (e.g., Aeneas toolchain limitation).
- **Not started**: no work has been done.

This page is updated with each release. If you find a gap not listed here, please [file an issue](https://github.com/coproduct-opensource/nucleus/issues).
