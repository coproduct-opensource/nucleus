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
nucleus-audit scan --agent-settings <tool>/settings.json
nucleus-audit scan --mcp-config .mcp.json
nucleus-audit scan --pod-spec agent.yaml
```

### Supported Formats

| Format | File | What It Checks |
|--------|------|----------------|
| PodSpec | `*.yaml` | Uninhabitable state, credentials, network, isolation, timeout, permissions |
| Agent tool settings | `settings.json` | Uninhabitable state via allow/deny projection, Bash propagation, exfil patterns |
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

## Verify workload evidence

Prepare expectations from separately retained admission metadata, an independently
pinned executor public key and the intended environment inputs. `prepare-execution`
prints the expected-record JSON; the receipt being checked supplies none of those
expectations. The validity deadline applies when consuming verification results
as well as to receipt issuance.

```sh
nucleus-audit prepare-execution --admission admission.json \
  --signer-key-hex "$PINNED_EXECUTOR_PUBLIC_KEY" \
  --environment-inputs intended-env.json \
  --valid-until-micros "$DEADLINE_MICROS" > expectations.json

nucleus-audit verify-execution --receipt receipt.json \
  --expectations expectations.json

nucleus-audit verify-logs --receipt receipt.json \
  --expectations expectations.json --stdout stdout.bin --stderr stderr.bin
```

Save the exact logs with `nucleus node workload POD_ID logs stdout --output
stdout.bin` and the corresponding stderr command before cancelling the pod.
`verify-logs` checks both raw streams against the authenticated receipt through
the shared verifier. Empty streams need empty files; text conversion can change
the bytes. Each file is limited to the node's 16 MiB retention bound. The JSON
report includes verified byte counts and the original execution claim. A verified
nonzero workload exit remains nonzero in that claim: the verifier's successful
exit means the evidence matched, not that the workload's tests passed.

For declared artifacts, pass the selected name/path JSON with `--artifacts` when
preparing expectations, then verify the collected bundle:

```sh
nucleus-audit verify-artifacts --bundle bundle.json \
  --expectations expectations.json --output-dir verified-files
```

The optional output directory must be new. Verified bytes are saved using artifact
names as filenames with private, non-executable permissions. Retain the original
bundle and expectations alongside the files; extracted bytes are not a signed
receipt by themselves.

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
| `scan` | Static analysis of agent configs (PodSpec, agent settings, MCP) |
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
