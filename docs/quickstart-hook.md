# Nucleus — Security for Claude Code in 60 seconds

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
```

Flow graph resets when switching compartments — research taint doesn't carry into draft.

## Useful commands

```bash
nucleus-claude-hook --doctor         # Check everything's working
nucleus-claude-hook --show-profile safe_pr_fixer  # See what's allowed
nucleus-claude-hook --receipts       # View audit trail
nucleus-claude-hook --status         # Show active sessions
nucleus-claude-hook --help           # All options
```

## Profiles

| Profile | Write | Bash | Web | Git Push | Default |
|---------|-------|------|-----|----------|---------|
| `read_only` | no | no | no | no | |
| `safe_pr_fixer` | yes | yes | yes | **no** | **yes** |
| `release` | yes | yes | yes | yes | |
| `permissive` | yes | yes | yes | yes | audit-only |

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

The kernel is backed by **181 formal verification artifacts** (68 Kani bounded model checks + 113 Lean 4 theorems) proving the lattice algebra and flow rules are correct.

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
