# Nucleus Permissions Guide

## TL;DR for AI Assistants

```
You have a permission profile. Check it before acting.

- "Never" = blocked, don't try
- "LowRisk" = allowed for safe operations
- "Always" = always allowed

If you have read_files + web access + git push all enabled,
exfiltration actions (git push, create PR, bash) require human approval.
This is the "trifecta protection" - it prevents prompt injection attacks
from stealing secrets.
```

---

## The Problem: Lethal Trifecta

When an AI agent has all three of these capabilities at autonomous levels:

| Capability | Example | Risk |
|------------|---------|------|
| **Private data access** | Reading files, credentials | Sees secrets |
| **Untrusted content** | Web search, fetching URLs | Prompt injection vector |
| **External communication** | Git push, create PR, bash | Exfiltration channel |

...a single prompt injection can exfiltrate your SSH keys, API tokens, or source code.

**Nucleus automatically detects this combination and requires human approval for exfiltration actions.**

---

## Permission Levels

Each tool capability has one of three levels:

```
Never     →  Blocked entirely
    ↓
LowRisk   →  Auto-approved for safe operations
    ↓
Always    →  Always auto-approved
```

### Example

```yaml
capabilities:
  read_files: always      # Can always read files
  write_files: low_risk   # Can write to safe locations
  run_bash: never         # Cannot run shell commands
  web_fetch: low_risk     # Can fetch approved URLs
  git_push: low_risk      # Can push (but may need approval)
```

---

## Built-in Profiles

### `filesystem-readonly`
Read-only with sensitive paths blocked.

```
read_files: always    web_search: never     git_push: never
write_files: never    web_fetch: never      create_pr: never
edit_files: never     git_commit: never     run_bash: never
```

### `read-only`
Safe for exploration. No writes, no network, no git.

```
read_files: always    web_search: never     git_push: never
write_files: never    web_fetch: never      create_pr: never
edit_files: never     git_commit: never
```

### `network-only`
Web-only access, no filesystem or execution.

```
read_files: never     web_search: low_risk  git_push: never
write_files: never    web_fetch: low_risk   create_pr: never
edit_files: never     git_commit: never     run_bash: never
```

### `web-research`
Read + web search/fetch, no writes or exec.

```
read_files: low_risk  web_search: low_risk  git_push: never
write_files: never    web_fetch: low_risk   create_pr: never
edit_files: never     git_commit: never     run_bash: never
```

### `code-review`
Read code, search web for context, but no modifications.

```
read_files: always    web_search: low_risk  git_push: never
write_files: never    web_fetch: never      create_pr: never
edit_files: never     git_commit: never
```

### `edit-only`
Write + edit without shell or web.

```
read_files: always    web_search: never     git_push: never
write_files: low_risk web_fetch: never      create_pr: never
edit_files: low_risk  git_commit: never     run_bash: never
```

### `local-dev`
Local development workflow without web access.

```
read_files: always    web_search: never     git_push: never
write_files: low_risk web_fetch: never      create_pr: never
edit_files: low_risk  git_commit: low_risk  run_bash: low_risk
```

### `fix-issue`
Full development workflow with trifecta protection.

```
read_files: always    web_search: low_risk  git_push: low_risk*
write_files: low_risk web_fetch: low_risk   create_pr: low_risk*
edit_files: low_risk  git_commit: low_risk
run_bash: low_risk

* Requires approval due to trifecta detection
```

### `release`
Release/publish workflow with approvals on exfiltration.

```
read_files: always    web_search: low_risk  git_push: low_risk*
write_files: low_risk web_fetch: low_risk   create_pr: low_risk*
edit_files: low_risk  git_commit: low_risk  run_bash: low_risk

* Requires approval
```

### `database-client`
Database CLI access only (psql/mysql/redis).

```
read_files: never     web_search: never     git_push: never
write_files: never    web_fetch: never      create_pr: never
edit_files: never     git_commit: never     run_bash: low_risk
```

### `demo`
For live demos - blocks shell interpreters.

```
read_files: always    web_search: low_risk  git_push: low_risk
write_files: low_risk web_fetch: low_risk   create_pr: low_risk
edit_files: low_risk  git_commit: low_risk
run_bash: low_risk    (blocked: python, node, bash, etc.)
```

---

## Workflow Profiles (Orchestrated Agents)

These profiles are designed for multi-agent workflows where different agents have
specialized roles. They're optimized for security through architectural constraints.

### `pr-review` (alias: `pr_review`)
For automated PR review agents. Read-only + web access, no exfiltration.

```
read_files: always    web_search: low_risk  git_push: never
write_files: never    web_fetch: low_risk   create_pr: never
edit_files: never     git_commit: never     run_bash: never
```

**Trifecta status**: NOT vulnerable (no exfiltration capability)

Use case: Review PRs, post comments via GitHub API, analyze diffs.
Note: run_bash is disabled because it's an exfil vector when combined with web access.

### `codegen`
For isolated code generation agents. Full dev capabilities, NO network access.

```
read_files: always    web_search: never     git_push: never
write_files: low_risk web_fetch: never      create_pr: never
edit_files: low_risk  git_commit: low_risk  run_bash: low_risk
```

**Trifecta status**: NOT vulnerable (no untrusted content exposure)

Use case: Implement features in a Firecracker microVM, run tests, commit locally.
Network isolation prevents prompt injection attacks from web content.

### `pr-approve` (alias: `pr_approve`)
For automated PR approval agents. Can merge PRs after CI verification.

```
read_files: always    web_search: low_risk  git_push: low_risk*
write_files: never    web_fetch: low_risk   create_pr: never
edit_files: never     git_commit: never     run_bash: low_risk*

* Requires approval (trifecta-gated)
```

**Trifecta status**: VULNERABLE → git_push and run_bash require approval

Use case: Verify CI status via GitHub API, then merge approved PRs.
The trifecta protection means git_push is gated on human/CI approval.

---

## Trifecta Detection

When nucleus detects the lethal trifecta, it **automatically adds approval obligations** to exfiltration vectors:

```
Your permissions:
  read_files: always     ← Private data access ✓
  web_fetch: low_risk    ← Untrusted content ✓
  git_push: low_risk     ← Exfiltration vector ✓

Trifecta detected! Adding approval requirement:
  git_push: requires approval
  create_pr: requires approval
  run_bash: requires approval
```

This happens automatically. You don't configure it. You can't disable it (even via malicious JSON payloads - the constraint is enforced on deserialization).

---

## For AI Assistants: How to Check Permissions

### Before Taking Action

```python
# Pseudocode for AI tool execution
if action.type == "git_push":
    if permissions.requires_approval("git_push"):
        return "I need approval to push. Shall I proceed?"
    else:
        execute(action)
```

### Understanding Your Profile

When you receive a permission profile, check:

1. **What level is each capability?**
   - `never` = don't attempt
   - `low_risk` = safe operations okay
   - `always` = go ahead

2. **Is trifecta active?**
   - If `read_files >= low_risk` AND `web_* >= low_risk` AND `git_push >= low_risk`
   - Then `git_push`, `create_pr`, `run_bash` need approval

3. **Check path restrictions**
   - `allowed_paths`: only these directories
   - `blocked_paths`: never touch these (e.g., `**/.env`, `**/*.pem`)

4. **Check budget**
   - `max_cost_usd`: spending limit
   - `max_tokens`: token limits

5. **Check time**
   - `valid_until`: when permissions expire

---

## Path Restrictions

```yaml
paths:
  allowed:
    - "/workspace/**"           # Only workspace
    - "/home/user/project/**"   # Or specific project
  blocked:
    - "**/.env"                 # No .env files
    - "**/.env.*"               # No .env.local, etc.
    - "**/secrets.*"            # No secrets files
    - "**/*.pem"                # No private keys
    - "**/*.key"                # No key files
```

---

## Command Restrictions

```yaml
commands:
  blocked:
    - program: "bash"           # No bash
      args: ["*"]
    - program: "python"         # No python interpreter
      args: ["*"]
    - program: "curl"           # No curl to arbitrary URLs
      args: ["*"]
  allowed:
    - program: "git"            # Git is okay
      args: ["status", "*"]
    - program: "cargo"          # Cargo is okay
      args: ["build", "*"]
```

---

## Budget Limits

```yaml
budget:
  max_cost_usd: 5.00           # $5 spending cap
  max_input_tokens: 100000     # 100k input tokens
  max_output_tokens: 10000     # 10k output tokens
```

---

## Time Limits

```yaml
time:
  valid_from: "2024-01-01T00:00:00Z"
  valid_until: "2024-01-01T01:00:00Z"  # 1 hour session
```

---

## Delegation (Sub-agents)

When delegating to a sub-agent, permissions can only go **down**, never up:

```
Parent: read_files=always, write_files=low_risk
Child request: write_files=always

Result: write_files=low_risk (capped at parent level)
```

This is enforced mathematically via lattice meet operation.

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│                    PERMISSION LEVELS                        │
├─────────────────────────────────────────────────────────────┤
│  never     Blocked. Don't attempt.                          │
│  low_risk  Allowed for safe operations.                     │
│  always    Always allowed.                                  │
├─────────────────────────────────────────────────────────────┤
│                    TRIFECTA RULE                            │
├─────────────────────────────────────────────────────────────┤
│  IF   read_files ≥ low_risk                                 │
│  AND  (web_fetch OR web_search) ≥ low_risk                  │
│  AND  (git_push OR create_pr OR run_bash) ≥ low_risk        │
│  THEN exfiltration actions require approval                 │
├─────────────────────────────────────────────────────────────┤
│                    BUILT-IN PROFILES                        │
├─────────────────────────────────────────────────────────────┤
│  filesystem-readonly  Read + search; blocks sensitive paths │
│  read-only            Explore only, no writes               │
│  network-only         Web-only access                       │
│  web-research         Read + web search/fetch               │
│  code-review          Read + web search, no modifications   │
│  edit-only            Write/edit, no exec or web            │
│  local-dev            Write + shell, no web                 │
│  fix-issue            Full dev workflow, trifecta protected │
│  release              Push/PR with approvals                │
│  database-client      DB CLI only                           │
│  demo                 For demos, blocks interpreters        │
│  permissive           Everything allowed (trusted only)     │
│  restrictive          Minimal permissions                   │
├─────────────────────────────────────────────────────────────┤
│                   WORKFLOW PROFILES                         │
├─────────────────────────────────────────────────────────────┤
│  pr-review            Read + web, NO exfil (safe)           │
│  codegen              Write + bash, NO network (isolated)   │
│  pr-approve           Read + web + push (CI-gated approval) │
└─────────────────────────────────────────────────────────────┘
```
