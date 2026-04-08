# Production Delta

What must be true before Nucleus can be called enterprise-ready. This page consolidates gaps from [SECURITY_TODO.md](../SECURITY_TODO.md), [FORMAL_METHODS.md](../FORMAL_METHODS.md), and [Verified Claims](verified-claims.md) into one checklist.

## Hardening

| Item | Status | Detail |
|------|--------|--------|
| Command exfiltration detection beyond program-name | Partial | `bash -c 'curl ...'` bypasses. Default command lattice blocks common flags; broader coverage and fuzzing pending. Firecracker network policy is the backstop. |
| Path sandboxing: unicode + symlink races | Partial | Symlink escape test added for `work_dir`; unicode NFC/NFKC normalization and Windows path edge cases not fuzzed. `cap-std` provides defense-in-depth. |
| Budget enforcement atomicity | Partial | Pre-exec reservation works. Post-exec cost accounting and output-based charges not implemented. A process can run even if budget is exhausted. |
| Approval tokens: anti-automation | Done (type-level) | `ApprovalToken` required for gated ops. Callbacks only mint tokens. No structured proof-of-human (e.g., signed challenge) yet. |
| Enforcement completeness (#1216) | Open | 146 call sites in `nucleus-claude-hook` and `nucleus-mcp` call `std::fs`/`std::process::Command`/`reqwest` directly, bypassing `PolicyEnforced`. |
| `NucleusRuntime::effects()` escape hatch (#1248) | Open | Returns raw `PolicyEnforced` bundle without obligation discharge or FlowTracker update. |
| Type-level IFC not composed into runtime API (#1249) | Open | `read_file()` returns `Vec<u8>`, not `Labeled<Vec<u8>>`. Runtime and compile-time IFC are independently correct but not wired together. |

## Validation

| Item | Status | Detail |
|------|--------|--------|
| Lean proofs cover the full state space | Done | 165 theorems, zero `sorry`. Unbounded for lattice algebra. |
| Kani BMC for decision logic | Done | 112 harnesses. Bounded — covers full 3-element, 13-dimension state space for lattice; string/path checks are bounded approximations. |
| Verus SMT proofs | Done | 297 VCs for exposure monotonicity, trace monotonicity, denial monotonicity, auth boundary, capability coverage, budget monotonicity, delegation ceiling. |
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
