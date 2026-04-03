# nucleus-cli

CLI for running AI agents under Nucleus permission enforcement.

## Install

```bash
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-cli
```

## Interactive Shell

Launch an AI coding session where every tool call flows through the permission lattice:

```bash
nucleus shell                                    # default codegen profile
nucleus shell --profile safe_pr_fixer --dir ~/repo
nucleus shell --profile code_review --max-cost 5.00
nucleus shell --env LLM_API_TOKEN=your-token
nucleus shell --kernel-trace ./trace.jsonl        # record decisions
```

**What happens:** Nucleus spawns `nucleus-tool-proxy` with your chosen profile, generates an MCP config routing all tools through the proxy, and launches the AI assistant with only sandboxed tools visible.

## Run Tasks

```bash
nucleus run --local --profile safe_pr_fixer "Fix issue #123"
nucleus run --profile codegen --timeout 600 "Add unit tests for auth.rs"
```

## Permission Profiles

```bash
nucleus profiles   # list all available profiles
```

Canonical profiles: `safe-pr-fixer`, `doc-editor`, `test-runner`, `triage-bot`, `code-review`, `codegen`, `release`, `research-web`, `read-only`, `local-dev`.

## Other Commands

| Command | Purpose |
|---------|---------|
| `shell` | Interactive AI session with lattice enforcement |
| `run` | Run a task with enforced permissions |
| `profiles` | List available permission profiles |
| `lockdown` | Drop all agents to read-only (sub-second via gRPC) |
| `audit` | Inspect audit trails |
| `token` | Manage attenuation tokens |
| `manifest` | Sign and verify PodSpec manifests |
| `observe` | Watch agent activity in real-time |
| `setup` | Configure nucleus for first use |
| `doctor` | Diagnose configuration issues |

## Trust Ladder

| Tier | Mode | Isolation |
|------|------|-----------|
| 0 | `nucleus-audit scan` | Static analysis only, no runtime |
| 1 | `nucleus run --local` | Tool-proxy lattice enforcement, no VM |
| 2 | `nucleus run` | Firecracker microVM + netns + default-deny egress |
