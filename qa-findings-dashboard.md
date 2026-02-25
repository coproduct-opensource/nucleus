# QA Findings: Test-Deploy-Verify (scope=dashboard)

Date: 2026-02-24
Branch: agent/qa-2e7a55a5-20260224-235632
Role: QA

---

## CRITICAL: Task Specification Mismatch

The six verification checks in the task spec reference a **web-based dashboard that does not exist** in this codebase. Nucleus is a Rust TUI + gRPC server system with no web frontend, no JavaScript, no SSE endpoints, no "Orbit" queue, and no `recover_stale_items()` function.

| Check | Status | Finding |
|-------|--------|---------|
| All dashboard tabs load without JS console errors | ✗ N/A | TUI-only (ratatui). No browser/JS involved. |
| SSE connection establishes and streams events | ✗ N/A | No SSE endpoint in any crate. |
| Orbit enqueue form submits successfully | ✗ N/A | "Orbit" undefined in codebase. |
| Queue depth API returns valid counts | ✗ N/A | No queue depth API endpoint. |
| `recover_stale_items()` dead-letters exhausted items | ✗ N/A | Function does not exist. |
| No infinite retry loops in Agent Turn History | ✗ N/A | No Agent Turn History component. |

**Recommendation**: Task spec targets a different orchestrator/UI system, not the Nucleus runtime.

---

## Vendor Neutrality Violations (CLAUDE.md Policy)

CLAUDE.md states: *"NEVER include in nucleus: Anthropic/Claude-specific code or references"*

### High Priority — Production Code

**`crates/nucleus-cli/src/run.rs`**:
- Line 121: `/// Claude model to use` — vendor-specific doc comment
- Line 122: `default_value = "claude-sonnet-4-20250514"` — hard-coded Claude model
- Line 381: `"Spawning Claude Code (enforced MCP mode)"` — vendor-specific log message
- Lines 385, 539: `run_claude_mcp()` function name — vendor-specific
- Line 547: `Command::new("claude")` — spawns Claude binary directly
- Line 566: error: `"failed to spawn claude"` — vendor-specific error message

**`crates/nucleus-mcp/src/main.rs`**:
- Line 15: `"MCP server that bridges Claude Code to nucleus-tool-proxy"` — vendor-specific description

### Lower Priority — Test/Example Code

CLAUDE.md says tests should use `LLM_API_TOKEN` not vendor names:
- `crates/nucleus-tool-proxy/tests/mtls_integration.rs:44`: `Identity::new(trust_domain, "agents", "claude")`
- `crates/nucleus-identity/tests/security_gauntlet.rs:1276,1306,1357`: `Identity::new("nucleus.local", "agents", "claude")`
- `crates/nucleus-identity/src/manager.rs:656,664,675,690`: identity "claude" and `starts_with("claude-")`

---

## Code Quality Findings

### 1. Dead Code: Unimplemented CRLF Handling in PEM Decoder

**File**: `crates/nucleus-tool-proxy/src/sandbox_proof.rs:289-296`

```rust
let body_start = start + header_end + 6; // skip "-----\n"
if pem_str.as_bytes().get(start + header_end + 5) == Some(&b'\r') {
    // handle \r\n
}
```

The empty `if` block was never implemented. For `\r\n` PEM files, `body_start` is off by one (points to the trailing `\n` instead of the base64 data). This is harmless because whitespace is stripped later, but the empty block is dead code and misleading. It should be removed or implemented.

**Missing test**: no test exercises CRLF PEM input.

### 2. Token Format: Dot-Separator Contract Not Enforced

**File**: `crates/nucleus-client/src/lib.rs:304-308` (`generate_sandbox_token`)

Token format: `sandbox-proof.{pod_id}.{spec_hash}.{timestamp}.{hmac}`

If `pod_id` or `spec_hash` contain dots (e.g., `pod.abc.k8s`), `verify_sandbox_token` returns a "wrong number of parts" error. `generate_sandbox_token` does not validate inputs, so a token with dots in pod_id is silently generated but will always fail verification.

**Missing tests**:
- pod_id with embedded dots → generates token that fails verification
- spec_hash with embedded dots → same issue
- No documented API contract against dot characters in inputs

### 3. `should_halt()` Can Never Return `true` with Current Constants

**File**: `crates/nucleus-permission-market/src/market.rs`

With `K = 3.0` and utilization clamped to `[0.0, 1.0]`:
- `λ_max = exp(3 × 1.0) − 1 ≈ 19.09`
- `CRITICAL_LAMBDA_THRESHOLD = 100.0`

The halt threshold (100.0) is unreachable: `should_halt()` will always return `false`. The existing test `should_halt_at_extreme_utilization` explicitly asserts `!market.should_halt()` and notes this in a comment, suggesting this is intentional — but the mechanism is then permanently disabled.

**Recommendation**: Either raise K (e.g., K=5 → λ_max ≈ 147 at 100%), lower `CRITICAL_LAMBDA_THRESHOLD` to something reachable (e.g., 15), or document that halt is future functionality.

---

## Follow-Up Work Items

1. **[Vendor Neutrality]** Refactor `nucleus-cli/src/run.rs` to be LLM-agnostic: rename `run_claude_mcp`, replace `Command::new("claude")` with a configurable binary path, remove Claude model default value.
2. **[Vendor Neutrality]** Update `nucleus-mcp/src/main.rs` description to generic language.
3. **[Vendor Neutrality]** Replace `"claude"` agent identity in tests with `"llm-agent"` or `"test-agent"`.
4. **[Bug/Dead Code]** Remove empty CRLF if-block in `decode_pem_to_der`, or implement it; add CRLF PEM test.
5. **[API Contract]** Validate that `pod_id`/`spec_hash` don't contain dots in `generate_sandbox_token`, or switch to a non-ambiguous separator (e.g., `:`).
6. **[Design]** Reconcile `should_halt()` with `CRITICAL_LAMBDA_THRESHOLD` — either the constant is wrong or the clamp range should be wider.
7. **[Task Spec]** Clarify the scope of "dashboard" testing — this task spec targets a different system.

---

## Rust Test Suite Status

No Rust toolchain available in this environment (`cargo` not found). Tests could not be executed. All findings above are from static code analysis.
