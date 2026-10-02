# nucleus-mcp

A [Model Context Protocol](https://modelcontextprotocol.io/) server that bridges
MCP-compatible clients to the nucleus tool-proxy, so every tool call an agent
makes is checked against the [portcullis](../portcullis) permission lattice
before it executes.

[![docs.rs](https://img.shields.io/docsrs/nucleus-mcp)](https://docs.rs/nucleus-mcp)

## What it does

The bridge speaks MCP over stdio. It advertises a set of tools (`web_fetch`,
`glob`, `grep`, …), and for each `tools/call` it:

1. maps the tool to a portcullis `Operation`,
2. asks the portcullis `Kernel` for a `Verdict` (allow / deny / approval-required),
3. forwards allowed calls to the tool-proxy with HMAC-signed headers,
4. on approval-required operations, optionally prompts on `/dev/tty` using a
   **separate** approval secret (privilege separation from regular tool calls),
5. records each kernel `Decision` to a JSONL trace for audit correlation.

Tools the loaded `PodSpec` does not grant are not advertised at all, so the
client never sees a capability the policy would deny.

## Usage

```bash
nucleus-mcp \
  --proxy-url http://127.0.0.1:12345 \
  --auth-secret "$NUCLEUS_MCP_AUTH_SECRET" \
  --spec agent.podspec.yaml \
  --kernel-trace /var/log/nucleus/mcp-decisions.jsonl
```

| Flag | Env | Purpose |
|---|---|---|
| `--proxy-url` | `NUCLEUS_MCP_PROXY_URL` | tool-proxy URL: `http://host:port`, or `unix:///<socket>` (falls back to `NUCLEUS_TOOL_PROXY_URL`) |
| `--auth-secret` | `NUCLEUS_MCP_AUTH_SECRET` | HMAC secret for signing tool calls (TCP only) |
| `--signed-upstream` | `NUCLEUS_MCP_SIGNED_UPSTREAM` | a signing proxy in front of a TCP tool-proxy signs instead (TCP only) |
| `--approval-secret` | `NUCLEUS_MCP_APPROVAL_SECRET` | separate secret for `/v1/approve` |
| `--actor` | `NUCLEUS_MCP_ACTOR` | actor id used in HMAC signatures |
| `--spec` | `NUCLEUS_MCP_SPEC` | PodSpec used to filter visible tools |
| `--session-id` | `NUCLEUS_MCP_SESSION_ID` | UUID v7 for audit correlation (auto if unset) |
| `--kernel-trace` | `NUCLEUS_MCP_KERNEL_TRACE` | JSONL path for per-call kernel decisions |

Run `nucleus-mcp --help` for the full list.

A TCP proxy needs `--auth-secret` or `--signed-upstream`; the bridge refuses to
start with neither. Inside a pod the bridge ships in the guest layer at
`/usr/local/bin/nucleus-mcp` and needs no flags: the runtime sets
`NUCLEUS_TOOL_PROXY_URL=unix:///run/nucleus-door/workload.sock`, the workload
door, which admits the workload by its uid. There it holds no secret (it refuses
one), and an operation held for approval is returned to the agent with its
reason, because approvals are the host's decision.

## Why a bridge

MCP clients expect to call tools directly. Putting nucleus-mcp in between means
the policy decision happens out-of-band from the client: the client cannot widen
its own capabilities, because the advertised tool set and every verdict are
derived from the PodSpec + portcullis kernel, not from the client's request.

## License

MIT
