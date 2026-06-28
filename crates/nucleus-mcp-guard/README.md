# Trifecta Gate (`mcp-guard`)

**See what your AI agent can exfiltrate — before an attacker does.**

`mcp-guard` is a drop-in [MCP](https://modelcontextprotocol.io) proxy that watches
an agent session and flags every moment the agent holds the **lethal trifecta**:

> **private data** + **exposure to untrusted content** + **an outbound channel**

When those three co-occur, a prompt-injection hidden in the untrusted content can
turn your agent into an exfiltration tool. `mcp-guard` makes that risk *visible* —
zero agent changes, runs in dev or CI.

The detection isn't a regex guess. The actual decision is a **formally-modelled
information-flow gate** (`nucleus-ifc`): the proxy maps each MCP tool to an IFC
data class, accumulates session taint, and asks the gate whether an outbound call
is safe given everything the agent has seen.

## Quick start

Wrap your MCP server (stdio) — it's transparent to both the agent and the server:

```bash
mcp-guard proxy -- npx -y @your/mcp-server
```

The agent talks to `mcp-guard` exactly as it would the server. On any risky
egress you get, on **stderr** (stdout stays the clean MCP channel):

```
[trifecta-gate] /!\ egress flagged: `send_email` while holding [file_read + web_content] — ...
```

and a session report when the session ends.

### Try it offline (no server needed)

Replay a recorded tool sequence to produce the artifact:

```bash
mcp-guard analyze examples/exfil_session.json
```

```
== Trifecta Gate — MCP session report ==

Tools observed:        3
Data classes in scope: file_read, web_content
Egress points flagged: 1

  /!\  EXFILTRATION POSSIBLE
       This agent reached an external sink while holding the lethal
       trifecta (private data + untrusted content + outbound channel).
       ...
    - via `send_email` (counterparty) over [file_read + web_content]
      reason: ...
```

`mcp-guard analyze` (and the proxy) exit **non-zero** when exfiltration is
possible — drop it into CI as an agent-safety gate. Add `--json` for a
machine-readable report.

## Customising the tool→risk mapping

Defaults are conservative (an *unknown* tool's output is treated as untrusted, and
only recognised tools are egress sinks). Override with `--config rules.json`:

```json
{
  "rules": [
    { "contains": "read_customer_record", "role": { "kind": "source", "input": "secret" } },
    { "contains": "notify_webhook",       "role": { "kind": "sink",   "public": false } }
  ]
}
```

Set `"replace_defaults": true` to start from scratch.

## What this is (and isn't)

- **Free / observe-only.** This tool *reports*; it does not block. The enforcement
  tier (hard-blocking on a denied verdict + signed, recomputable audit receipts
  mapped to SOC2 / OWASP LLM Top 10) is the commercial layer above it.
- **Model-level.** The verdict is over the data classes a session is *observed* to
  touch via MCP tool traffic. Coverage is the honest limit: a channel the agent
  uses outside MCP is a channel the gate doesn't see. It does **not** claim to
  prove exfiltration is impossible — it shows when it's *possible*.

Built on the `nucleus-ifc` lethal-trifecta gate.
