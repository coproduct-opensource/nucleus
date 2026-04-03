# nucleus-audit

Static analysis and verification CLI for AI agent configurations and audit trails.

## Install

```bash
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-audit
```

## Scan Agent Configs

Detect dangerous permission combinations before deployment:

```bash
nucleus-audit scan --auto                              # auto-discover configs
nucleus-audit scan --claude-settings .claude/settings.json
nucleus-audit scan --mcp-config .mcp.json
nucleus-audit scan --pod-spec agent.yaml
```

### Supported Formats

| Format | File | What It Checks |
|--------|------|----------------|
| PodSpec | `*.yaml` | Uninhabitable state, credentials, network, isolation, timeout, permissions |
| Claude Code settings | `settings.json` | Uninhabitable state via allow/deny projection, Bash propagation, exfil patterns |
| MCP config | `.mcp.json` | Server classification, `npx -y` supply chain risk, credentials, auth headers |

### CI Integration

Exit code is non-zero on critical or high findings:

```bash
nucleus-audit scan --pod-spec agent.yaml --format json   # JSON for pipelines
nucleus-audit scan --auto --format sarif                  # SARIF for GitHub
```

## Verify Audit Trails

```bash
nucleus-audit verify --log agent.jsonl                    # HMAC + hash chain
nucleus-audit verify-chain --log portcullis.jsonl          # hash chain only
nucleus-audit verify-receipts --log receipts.jsonl         # Ed25519 receipt chain
```

## Provenance Commands

```bash
nucleus-audit verify-provenance --output provenance-output.json
nucleus-audit verify-c2pa --output provenance-output.json --receipts chain.jsonl
nucleus-audit provenance-log --output provenance-output.json
nucleus-audit diff-provenance --old v1.json --new v2.json
```

## All Subcommands

| Command | Purpose |
|---------|---------|
| `scan` | Static analysis of agent configs (PodSpec, Claude settings, MCP) |
| `verify` | Verify tool-proxy JSONL audit log (HMAC + hash chain) |
| `verify-chain` | Verify portcullis permission audit log |
| `verify-receipts` | Verify Ed25519-signed receipt chain |
| `verify-provenance` | Verify provenance output schema + derivation chains |
| `verify-c2pa` | Cross-check C2PA sidecar with receipt chain |
| `provenance-log` | Navigate session DAG (jj-style log) |
| `diff-provenance` | Diff two provenance outputs |
| `rebase-witnesses` | Check if parser update changes outputs |
| `trace` | Multi-agent provenance DAG (Graphviz DOT output) |
| `summary` | Audit event summary grouped by identity |
| `export` | Export as JSON/JSONL/SOC2 compliance report |
| `assurance` | Aggregate verification evidence into assurance case |

See [`examples/`](../../examples/) for scannable configurations.
