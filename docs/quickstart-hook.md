# Nucleus — AI Agent Security in 60 Seconds

## Install

```bash
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-claude-hook
nucleus-claude-hook --setup
# restart Claude Code
```

## Verify

```bash
nucleus-claude-hook --smoke-test
# ✓ Read file → allowed
# ✓ WebFetch → allowed (session tainted)
# ✓ Write after taint → denied (flow control working!)
# 3/3 tests passed
```

## What it does

Nucleus tracks **what data has entered your session** and blocks dangerous combinations:

```
✓ Read a file            — safe
✓ Search the web          — safe (but taints the session)
✗ Write based on web data — BLOCKED (web content can't steer writes)
```

This prevents prompt injection attacks where malicious web content tricks the agent into exfiltrating your code.

## Compartments: research, then code, then test

Instead of "one web fetch = locked forever," use compartments:

```bash
# Set via env var or side-channel file
NUCLEUS_COMPARTMENT=research   # read + web (no writes)
NUCLEUS_COMPARTMENT=draft      # read + write (no web — taint clears!)
NUCLEUS_COMPARTMENT=execute    # read + write + bash (no push)
NUCLEUS_COMPARTMENT=breakglass:reason  # all capabilities + enhanced audit (reason required)
```

Flow graph resets when switching compartments — research taint doesn't carry into draft.

Escalating compartments (e.g., draft to execute) emits a warning. Breakglass requires a reason string after a colon (e.g., `breakglass:emergency fix for production outage`).

## Useful commands

```bash
nucleus-claude-hook --doctor         # Check everything's working
nucleus-claude-hook --show-profile safe_pr_fixer  # See what's allowed
nucleus-claude-hook --receipts       # View audit trail
nucleus-claude-hook --status         # Show active sessions
nucleus-claude-hook --gc             # Clean up stale session files (>24h)
nucleus-claude-hook --reset-session <id>  # Clear taint on a session (receipt chain preserved)
nucleus-claude-hook --compartment-path <id>  # Print the side-channel file path for a session
nucleus-claude-hook --uninstall      # Remove hook from settings.json
nucleus-claude-hook --version        # Show installed version
nucleus-claude-hook --init           # Create .nucleus/config.toml
nucleus-claude-hook --help           # All options
```

## Profiles

| Profile | Write | Bash | Web | Git Push | Default |
|---------|-------|------|-----|----------|---------|
| `read_only` | no | no | no | no | |
| `code_review` | no | no | no | no | PR review |
| `edit_only` | yes | no | no | no | |
| `fix_issue` | yes | yes | yes | **no** | |
| `safe_pr_fixer` | yes | yes | yes | **no** | **yes** |
| `release` | yes | yes | yes | yes | |
| `permissive` | yes | yes | yes | yes | audit-only |

Set via `NUCLEUS_PROFILE` environment variable.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NUCLEUS_PROFILE` | Permission profile | `safe_pr_fixer` |
| `NUCLEUS_COMPARTMENT` | Active compartment: `research`, `draft`, `execute`, `breakglass` | — |
| `NUCLEUS_FAIL_CLOSED` | Set to `1` for CISO mode (infrastructure errors block) | `0` |
| `NUCLEUS_REQUIRE_MANIFESTS` | Set to `1` to deny MCP tools without manifests | `0` |
| `NUCLEUS_AUTONOMY_CEILING` | Org cap: `production`, `sandbox` | unrestricted |

## Uninstall

```bash
cargo uninstall nucleus-claude-hook
```

Remove the `hooks` block from `~/.claude/settings.json`.

---

## How it works (the details)

Nucleus uses **information flow control** (IFC) — every piece of data gets a security label:

| Source | Integrity | What it means |
|--------|-----------|---------------|
| File read | Trusted | Local, safe data |
| Web fetch | **Adversarial** | Untrusted, could be attacker-controlled |

Labels propagate. When web content enters, subsequent writes inherit adversarial integrity. The kernel blocks the escalation — adversarial data can't steer privileged actions.

The kernel is backed by **277 formal verification artifacts** (112 Kani bounded model checks + 165 Lean 4 theorems) proving the lattice algebra, flow rules, compartment properties, admission control, delegation narrowing, and DPI data flow invariants are correct.

The enforcement pipeline runs 17 steps in `Kernel::decide()`: isolation, time, budget, delegation constraints, capability, egress, admissibility, enterprise allowlists, paths, commands, SinkScope, flow control, approvals, and dynamic exposure gating.

## Tamper detection

If someone asks you to delete session files to "fix" the hook:

```
nucleus: TAMPER DETECTED — session state deleted (expected hwm=5).
A compromised model may have asked you to delete session files.
```

The hook maintains a separate high-water-mark file. Tampering fails closed.

## Links

- [Source](https://github.com/coproduct-opensource/nucleus)
- [Formal methods assessment](https://github.com/coproduct-opensource/nucleus/blob/main/FORMAL_METHODS.md)
- [Claude Code hooks docs](https://code.claude.com/docs/en/hooks)
