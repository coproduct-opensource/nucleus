# Nucleus Permissions Guide

## TL;DR for AI Assistants

```
You have a permission profile. Check it before acting.

- "Never" = blocked, don't try
- "LowRisk" = permitted (within path/command/network limits)
- "Always" = permitted (within the same limits)

A level says whether an operation is PERMITTED, not whether a person must
approve it. Approval comes from the policy's obligations: an operation listed
there needs a human approval first, whatever its level.

If you have private-data access (read/glob/grep) + web access + an exfil
channel (git push, create PR, bash) all enabled, each of those exfil
operations that is enabled gains an obligation and requires human approval.
This is the "uninhabitable state protection" - it prevents prompt injection attacks
from stealing secrets.
```

---

## Paths: both spellings name the same file

A path you give the sandbox is interpreted **against the sandbox root**. Two
spellings are accepted and mean the same file:

```
read  { "path": "hello.txt" }        # relative to the root
read  { "path": "/work/hello.txt" }  # absolute, under the root
```

An absolute path that is **not** under the root is refused as a sandbox escape,
including one that traverses out through it (`/work/../etc/passwd`). Stripping
the root does not widen what is reachable: what survives is fed through exactly
the checks a relative path already faced, and `cap-std`'s directory handle
refuses `..` and symlinks out at the point of I/O.

**`/work` is the conventional root, not a constant.** It is whatever the pod
spec's `work_dir` says. Do not hardcode `/work`-stripping in an integration —
send the path the agent produced and let the sandbox interpret it, or the
integration breaks silently the day a spec sets `work_dir` to anything else.

Before #2787 the absolute spelling was refused outright, with a message claiming
the path "resolves outside sandbox root" — which was untrue, because the root
was never consulted. Both spellings work now; the refusal text is only used when
the root really was consulted and the path really was outside it.

---

## The Problem: Uninhabitable State

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
LowRisk   →  Permitted
    ↓
Always    →  Permitted
```

The level is **permission**, not **consent**. When the kernel decides an
operation it reads the level only to tell `Never` from permitted; `LowRisk`
and `Always` differ in the lattice order (how `meet`, `join` and delegation
narrow a policy), not in whether a person is asked. Whether a person is asked
is decided by the policy's `obligations` — see
[Permission and consent](#permission-and-consent).

### Permission and consent

Two separate questions are answered for every operation:

1. **Is it permitted?** The capability level. `never` refuses it; `low_risk`
   and `always` permit it, still subject to the path, command, network and
   flow (IFC) checks.
2. **Must a human approve it first?** The policy's `obligations`. An operation
   in that set is held until a matching approval exists
   (`Kernel::decide` reads `obligations.requires(op)`); an operation not in it
   runs without asking anyone, **even when its level is `low_risk`**.

Obligations come from two places today:

- the policy itself (a profile's `obligations:` list, or an inline policy's
  obligation set), and
- the uninhabitable-state (trifecta) rule: when private-data access
  (`read_files`, `glob_search` or `grep_search` ≥ `low_risk`), untrusted
  content (`web_fetch` or `web_search` ≥ `low_risk`) and an exfiltration
  channel (`git_push`, `create_pr` or `run_bash` ≥ `low_risk`) are all
  present, normalization adds an obligation for each of `git_push`,
  `create_pr` and `run_bash` that is permitted. It only ever adds
  obligations; it never removes one.

So a policy that sets `write_files: low_risk` and lists no obligation for it
lets the agent write without approval. If you want a person in the loop, list
the operation under `obligations`.

**This is changing.** Consent is implicit today: an operation that is
permitted and not obligated is autonomous by omission. A later release makes
consent an explicit per-operation declaration (autonomous or requires
approval) for every permitted operation, and refuses a policy that leaves one
undeclared. That is a breaking change for inline policies and will be called
out in the release notes and `docs/STABILITY.md`.

### Example

```yaml
capabilities:
  read_files: always      # Can always read files
  write_files: low_risk   # Can write (within path limits); no approval unless obligated
  run_bash: never         # Cannot run shell commands
  web_fetch: low_risk     # Can fetch (within host limits)
  git_push: low_risk      # Can push; needs approval if obligated (e.g. by the trifecta rule)
```

---

## Built-in Profiles

The tables below give each profile's capability **levels**. A `*` marks an
operation that requires approval (an obligation, declared or added by the
uninhabitable-state rule); a `low_risk` operation without a `*` runs without
asking anyone. See [Permission and consent](#permission-and-consent).

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
read_files: always    web_search: low_risk* git_push: never
write_files: never    web_fetch: never      create_pr: never
edit_files: never     git_commit: never

* Requires approval (declared obligation)
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
Full development workflow with uninhabitable state protection.

```
read_files: always    web_search: low_risk* git_push: low_risk*
write_files: low_risk web_fetch: low_risk*  create_pr: low_risk*
edit_files: low_risk  git_commit: low_risk*
run_bash: low_risk*

* Requires approval: web_search, web_fetch, git_commit, git_push and
  create_pr are declared obligations; run_bash is added by the
  uninhabitable-state rule. Unmarked operations need no approval.
```

### `release`
Release/publish workflow with approvals on exfiltration.

```
read_files: always    web_search: low_risk  git_push: low_risk*
write_files: low_risk web_fetch: low_risk   create_pr: low_risk*
edit_files: low_risk  git_commit: low_risk  run_bash: low_risk*

* Requires approval: git_push and create_pr are declared obligations;
  run_bash is added by the uninhabitable-state rule (read + web + exfil).
  Unmarked operations need no approval.
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
read_files: always    web_search: low_risk  git_push: low_risk*
write_files: low_risk* web_fetch: low_risk  create_pr: low_risk*
edit_files: low_risk* git_commit: low_risk
run_bash: low_risk*   (blocked: python, node, bash, etc.)

* Requires approval: write_files and edit_files are declared obligations;
  git_push, create_pr and run_bash are added by the uninhabitable-state rule.
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

** Uninhabitable state status**: NOT vulnerable (no exfiltration capability)

Use case: Review PRs, post comments via GitHub API, analyze diffs.
Note: run_bash is disabled because it's an exfil vector when combined with web access.

### `codegen`
For isolated code generation agents. Full dev capabilities, NO network access.

```
read_files: always    web_search: never     git_push: never
write_files: low_risk web_fetch: never      create_pr: never
edit_files: low_risk  git_commit: low_risk  run_bash: low_risk
```

** Uninhabitable state status**: NOT vulnerable (no untrusted content exposure)

No obligations: the effective obligation set is empty, so writes, edits,
shell commands and local commits run **without approval**. `low_risk` here
means permitted, not "asks first".

Use case: Implement features in a Firecracker microVM, run tests, commit locally.
Network isolation prevents prompt injection attacks from web content.

### `pr-approve` (alias: `pr_approve`)
For automated PR approval agents. Can merge PRs after CI verification.

```
read_files: always    web_search: low_risk  git_push: low_risk*
write_files: never    web_fetch: low_risk   create_pr: never
edit_files: never     git_commit: never     run_bash: low_risk*

* Requires approval (uninhabitable state-gated)
```

** Uninhabitable state status**: VULNERABLE → git_push and run_bash require approval

Use case: Verify CI status via GitHub API, then merge approved PRs.
The uninhabitable state protection means git_push is gated on human/CI approval.

---

##  Uninhabitable state Detection

When nucleus detects the uninhabitable state, it **automatically adds approval obligations** to exfiltration vectors:

```
Your permissions:
  read_files: always     ← Private data access ✓
  web_fetch: low_risk    ← Untrusted content ✓
  git_push: low_risk     ← Exfiltration vector ✓

 Uninhabitable state detected! Adding an obligation to each permitted
exfil operation (git_push, create_pr, run_bash) — here only git_push:
  git_push: requires approval
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
   - `low_risk` = permitted
   - `always` = permitted
   - A level does not tell you whether approval is needed — see step 2.

2. **Which operations need approval?**
   - Any operation listed in the policy's `obligations`.
   - Plus, if the uninhabitable state is active — (`read_files` OR `glob_search` OR
     `grep_search`) `>= low_risk` AND `web_* >= low_risk` AND (`git_push` OR
     `create_pr` OR `run_bash`) `>= low_risk` — each of `git_push`, `create_pr`,
     `run_bash` that is permitted needs approval

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

## Running by goal

You do not have to pick a profile. State the outcome and nucleus compiles it into
the minimum authority the task needs, shows it in plain language, and runs after
one confirmation:

```
$ nucleus run --goal "fix the failing CI build" --ceiling safe-pr-fixer --dry-run
Goal:    fix the failing CI build
Can:     read and search workspace files · read git history and status · read CI logs and workflow runs · edit workspace files · run the test suite · commit changes locally
Cannot:  push to remote branches · open or merge pull requests · reach hosts other than api.github.com · spawn agents or pods
Limits:  $5.00 · 2h · api.github.com only · no .aws, .env, .ssh
Risk:    all 3 exposure legs present → the kernel asks for approval before run_bash
```

How it is derived, and why it cannot be wider than you allow:

1. The repository is probed (ecosystem, CI system, git remotes, MCP configs) and a
   rule table maps goal phrases to **semantic effects** (below). Every rule that
   fired is recorded in the grant (`--explain policy-trace`).
2. The effects are lowered to the 13 capability dimensions, sinks and hosts.
3. The result is **met with the `--ceiling` profile** (default `codegen`), so the
   grant is never wider than the ceiling. An effect the ceiling does not admit is
   listed under *Cannot* with the reason, never silently dropped or granted.
4. Without a TTY the run refuses unless you pass `--yes`; `--dry-run` only shows the
   grant; `--save-grant PATH` seals the accepted grant for reuse (below);
   `--explain technical` adds the grid;
   `--effects github/read-issue,web/search` adds effects the goal did not imply.

A goal nothing recognises is an error naming the remedy. It never falls back to a
permissive profile.

An orchestrator may supply its own proposer with `--proposer PROGRAM` (JSON on
stdin, `{"effects": [...]}` on stdout). Its answer is validated against the catalog
and clamped under the ceiling like everything else, so it can only narrow.

### Reusing a grant: zero prompts for a task you already approved

The confirmation is the approval, so it should be given once. `--save-grant PATH`
seals the grant you accept into a signed file, and `--grant PATH` runs it again
without asking (a run launches the agent named by `--agent` or `NUCLEUS_AGENT`;
see [examples/agents/](../examples/agents/README.md)):

```
$ nucleus run --goal "run the tests" --save-grant tests.grant     # confirm once: [R]un · [s]eal only
$ nucleus run --grant tests.grant                                 # no prompt
grant 6f1c… verified: sealed by nucleus://grant-approver/laptop/ada (3b9e0a1c…), 3 effects, 1h58m left, no confirmation needed
Goal:    run the tests
Can:     read and search workspace files · read git history and status · run the test suite
…
```

`nucleus grant seal --goal "…" -o FILE` seals without running (for a grant a CI job
will use), and `nucleus grant show FILE` verifies and renders one.

What a sealed grant is: the five lines you read, and beside them a root
certificate whose permissions are the grant's lattice **plus one `effect/<plugin>/<id>`
key per granted effect** plus keys binding the grant id, the goal digest and the
repository digest — signed with the Ed25519 grant key nucleus creates at
`~/.config/nucleus/keys/grant-signer.pem` on first use. `--grant` refuses, before
anything runs, when:

- the signer is not this host's key (or a `--grant-signer HEX` you trust — this is
  how a CI job holds only the public half of a key a person sealed with);
- the certificate does not verify (signature, expiry, proof of possession);
- the readable grant no longer re-lowers to the signed permissions — editing the
  goal, the effects, the lattice, the limits or the expiry in the file is detected;
- the repository's context digest (ecosystem, CI system, remotes, MCP configs) is
  not the one the grant was compiled against: `re-run with --goal to approve it again`.

A certificate delegated from a sealed grant can drop effects but never add one:
the `effect/` keys follow the tool-surface rule (`min(absent, Always) = Never`), a
silent child inherits the parent's set, and a child that sheds the dimension is
refused.

**What the `effect/` keys enforce.** A `--goal` or `--grant` run hands the sealed
certificate to the tool proxy (`--pod-cert`), and a pod whose certificate carries
the effect dimension is bounded per effect, not just per host:

- `web_fetch` and credentialed egress: the request's method, host and path must be
  vouched for by a granted effect's `http` shapes (or its host list, for host-level
  effects such as `git/push-branch`). A grant of `github/read-ci-logs` admits
  `GET api.github.com/repos/*/actions/*` and refuses `POST …/pulls` with
  `EFFECT_NOT_GRANTED`, naming the effect that would admit it.
- MCP tools (`mcp-guard`): a served tool no granted effect names is blocked with
  `MCP_TOOL_OUTSIDE_EFFECTS`, above the tool surface and the signed manifests.
- Shell commands stay bounded by the command lattice; the effects' command prefixes
  are what attributes them afterwards.

A pod whose certificate carries no effect dimension (one that did not run under a
grant) is unconstrained by this layer and bounded by everything else as before:
the gate adds refusals, never allowances.

### Two numbers every run reports: ρ and C(T)

The exit report (`.nucleus-exit-report.json`, written by the tool proxy), the MCP
server's `session_summary` trace line, and the line a `--goal` / `--grant` run
ends with all carry the same `authority` summary, computed from the kernel's
effective lattice and its decision trace:

```
authority: 3 of 6 granted dimensions used · ρ = 2.00 · C(T) = 1 (1 confirmation, 0 approvals during the run) · 41 allowed · 1 denied
```

- **ρ (authority overhead)** = granted dimensions ÷ used dimensions. ρ → 1 is
  the goal; it is undefined, not infinite, when nothing was used.
- **C(T) (delegation clicks)** = confirmations before the run (1 for a new goal,
  0 for a sealed grant) + approvals the kernel asked for during it. Every click
  beyond one is either ceremony or a boundary the task needed moved, and the
  proposals below say which.

A pod spec may name the grant it runs under (`metadata.task_grant_id`); `--goal`
and `--grant` runs set it, and the exit report carries it back.

### When something is denied: every denial is a proposal

A denial answers four questions, not one: what the agent tried, why exactly it
was refused, the least authority that would have allowed it, and what that
authority would change. Each `--goal` / `--grant` run prints one proposal per
distinct denial after the usage lines; `nucleus grant propose --grant FILE
--input trace.jsonl` prints them for any trace (`--json` for the structured
form):

```
denied:  git_commit `-m fix` — the grant holds git_commit at never
minimum: git/commit (commit changes locally) · git_commit: never → low_risk
risk:    medium → medium
grant:   nucleus grant widen --grant tests.grant --effects git/commit   (one confirmation, same ceiling)
         or for this run only: an approver may escalate it for 118m (needs a node with an escalation policy; not in --local)

denied:  git_push `origin main` — the grant holds git_push at never
minimum: git/push-branch (push a branch to the remote) · git_push: never → low_risk · hosts github.com
risk:    medium → uninhabitable: adds an exfiltration vector; all three legs present, the kernel will ask before each git_push
outside: git/push-branch is outside ceiling safe-pr-fixer — a wider ceiling is a separate decision (--ceiling …)
```

The proposal is bounded by the same ceiling as the grant. Three outcomes:

- **grantable**: an effect vouches for the attempt and the ceiling admits it.
  `nucleus grant widen` recompiles the goal with that effect added and re-seals
  after the same single confirmation a new goal would ask for (`C(T) = 1`).
  What the ceiling still clips is named and left out, never granted.
- **outside the ceiling**: nothing is offered. Widening the ceiling is a
  separate decision, and the line says so.
- **repair, not authority**: information-flow denials, blocked secret paths,
  expired or exhausted grants, and layers below the grant (isolation,
  enterprise policy, delegation, Cedar) get a repair line instead of a grant
  command, because more authority would not help and might make the flow worse.

The risk line is the uninhabitable-state analysis before and after: which
exposure leg the minimum adds, and whether the kernel will start asking for
approval because all three legs would then be present.

### Learning from a run: the grant is the ceiling, the trace is the proposal

Every `--goal` and `--grant` run leaves a kernel trace
(`~/.config/nucleus/traces/<grant id>.jsonl` unless `--kernel-trace` names one)
and ends with what the run actually used of what it was granted:

```
authority: used 3 of 7 effects · ρ = 2.00 (3 of 6 granted dimensions used) · 41 allowed · 1 denied
  used:    read and search workspace files (12) · run the test suite (2) · read CI logs and workflow runs (1)
  unused:  edit workspace files · commit changes locally · build the project · read git history and status
  denied:  git_push origin main (1)

Save a profile with the unused authority removed? name (empty to skip): ci-tests
profile 'ci-tests' installed at ~/.config/nucleus/profiles/ci-tests.yaml (4 effects and 3 dimensions removed)
```

ρ is the **authority overhead**, granted ÷ used, over the 13 core dimensions;
ρ → 1 is the goal, and it is the number a plugin's effect vocabulary is judged
by. The same report without a terminal, or after the fact:

```
nucleus observe --grant ci.grant --input trace.jsonl            # the report
nucleus observe --grant ci.grant --input trace.jsonl --narrow ci-tests --save
```

Narrowing is bounded on both sides by the grant: an unused dimension goes to
`never`, a used one keeps the level the grant gave it (even when no effect
explains it, since the run needed it), and paths, commands, budget and time are
untouched. The result is `≤` the grant by construction, so the threshold problem
of observed-usage tools (encode noise as permission, or refuse the next
legitimate run) cannot widen anything: at worst the next run is denied
something and says so.

Profiles in `~/.config/nucleus/profiles/*.yaml` resolve like canonical ones,
for `--profile` and for `--ceiling`. A user profile may carry a canonical name
only if it is not wider than the canonical one; a wider shadow is ignored with a
warning, so a file on disk cannot quietly change what `--ceiling codegen` means.

## Semantic effects

An effect is the unit of authority a person reads. Each lowers to core dimensions,
sinks and hosts, and carries how it is recognised (MCP tool names, command
prefixes, HTTP method+host+path), which is what later attributes a run's receipts
back to the effects that authorised it. The built-in catalog:

| Effect | Means | Lowers to |
|---|---|---|
| `fs/read-workspace` | Read and search workspace files | `read_files`, `glob_search`, `grep_search` (always) |
| `fs/edit-workspace` | Edit workspace files | `write_files`, `edit_files` |
| `shell/run-tests` | Run the test suite | `run_bash` (`cargo test`, `npm test`, `pytest`, …) |
| `shell/run-build` | Build the project | `run_bash` (`cargo build`, `npm run build`, …) |
| `shell/run-lint` | Run formatters and linters | `run_bash` (`cargo clippy`, `ruff`, …) |
| `git/read-history` | Read git history and status | `run_bash` (`git status`, `git log`, `git diff`, …) |
| `git/commit` | Commit changes locally | `git_commit` |
| `git/push-branch` | Push a branch to the remote | `git_push`, host `github.com` |
| `web/package-registry-crates` | Download Rust dependencies | `web_fetch`, hosts `crates.io`, `static.crates.io`, `index.crates.io` |
| `web/package-registry-npm` | Download JavaScript dependencies | `web_fetch`, host `registry.npmjs.org` |
| `web/package-registry-pypi` | Download Python dependencies | `web_fetch`, hosts `pypi.org`, `files.pythonhosted.org` |
| `web/search` | Search the web | `web_search` |
| `github/read-issue` | Read issues | `web_fetch`, `GET api.github.com/repos/*/issues*` |
| `github/read-ci-logs` | Read CI logs and workflow runs | `web_fetch`, `GET api.github.com/repos/*/actions/*` |
| `github/read-pull-request` | Read pull requests and reviews | `web_fetch`, `GET api.github.com/repos/*/pulls*` |
| `github/comment` | Comment on issues and pull requests | `create_pr`, `POST …/comments` |
| `github/open-pr` | Open a pull request | `create_pr`, `git_push`, `POST api.github.com/repos/*/pulls` |
| `github/merge-pr` | Merge a pull request | `git_push`, `PUT api.github.com/repos/*/pulls/*/merge` |

A repository adds its own under `.nucleus/effects/*.toml` (same format as
`crates/portcullis/effects/`). In this milestone an effect is enforced by the
lattice it lowers to, the host list, and the command prefixes it vouches for; an
agent that reaches a host with `curl` rather than an MCP tool is bounded by host,
not by method and path. See `docs/adr/0004-delegation-compiler.md` for the
milestones that close that gap.

## Decisions

An owner decision is a signed answer to a question: "of these options, the owner chose this
one", with a structured scope and a validity window (`crates/nucleus-signed-decision`). A spec
can make an effect it is already allowed run only when the call cites one:

```yaml
spec:
  credentialed_egress:
    - name: forge
      upstream: https://forge.invalid/api
      # ...
  requires_decision:
    - create_pr:forge   # a pull request opened through the upstream named `forge`
```

Each entry is `<effect>:<upstream>`, and that string is exactly the capability an owner's
decision must list in `scope.capabilities`. The effects that can be gated are the two the
credentialed-egress classifier labels: `create_pr` and `git_push`. A requirement only ever
restricts, and a sub-pod keeps every requirement its parent holds for an upstream it keeps.

The node's operator configures `nucleus-node --decision-trust-roots <file> --decision-tenant
<tenant> --decision-bundles <dir>`. All three are checked at startup, and a bad value refuses
the node's start by the flag's name. Each pod's tool-proxy receives the roots and the tenant's
bundles: the node's files on the local driver, read-only bind mounts on the container driver,
and the `FETCH_POD_SPEC` reply on Firecracker, which guest-init writes under
`/run/nucleus/decisions`. The bundles are untrusted until the tool-proxy verifies them.

A gated call cites its decision in the `x-nucleus-decision` header, which is never forwarded
upstream. The effect runs only when all of these hold. Otherwise it is refused by name:

| Checked | Refused as |
|---|---|
| a decision is cited, as 64 hex | none cited, or not an id |
| a bundle for that id verifies against a pinned root, canonical, for this tenant, its options and question unaltered | the verifier's reason (unknown kid, bad signature, options not the ones shown, ...) |
| `now` is inside its window | expired, not yet valid |
| no bundle the pod holds supersedes it | superseded |
| the capability is in its scope, and every path the effect writes | out of scope |
| this proxy can read the write set | cannot be shown to cover (a push today: its pack is not read) |
| a one-shot decision was not spent in this pod | already spent; the first use spends it, by value |

The tool-proxy writes `owner_decision` to its signed audit log, naming the capability and the
decision id (`cited <id>` or `spent <id>`), before the effect runs. The receipt's audit tail
hash pins that record.

A spec that requires a decision is refused at create when the node has no trust roots, when a
requirement names an upstream the spec does not declare, on an unmediated container, and on a
guest known to predate the capability (`GuestCapability::DecisionGatedSinks`, in no published
release yet, so the pinned 2.7.0 guest is refused by name). A Firecracker pod whose guest the
node cannot identify is handed out only after its tool-proxy prints `NUCLEUS_DECISION_GATE:
ARMED` naming every requirement. Pods that require no decision are unchanged on every guest.

**What is not enforced yet.** Single use is per pod: a one-shot decision cited in two pods is
spent once in each. Fleet-wide single use is the merge gate's job. Supersession covers the
bundles a pod was given, so a superseding decision filed after a pod started is unseen there
until its window closes. No log inclusion proof is checked, and there is no fleet-wide
revocation: removing a root from the node's file stops new pods from trusting it, not running
ones. Whether a change is "breaking" or "picks between designs" is semantic, and no proxy
detects it; that half is a convention.

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
│  low_risk  Permitted. Approval only if obligated.           │
│  always    Permitted. Approval only if obligated.           │
├─────────────────────────────────────────────────────────────┤
│                    uninhabitable state RULE                            │
├─────────────────────────────────────────────────────────────┤
│  IF   (read_files OR glob/grep_search) ≥ low_risk           │
│  AND  (web_fetch OR web_search) ≥ low_risk                  │
│  AND  (git_push OR create_pr OR run_bash) ≥ low_risk        │
│  THEN each permitted exfil action gains an obligation       │
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
│  fix-issue            Full dev workflow, uninhabitable state protected │
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
