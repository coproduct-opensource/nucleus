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

- **Enforces by default, observes on request.** A denied call is answered with
  a JSON-RPC error and never reaches the server. Pass `--observe` to report and
  forward anyway — assessment mode, for seeing what a session *would* have been
  blocked from without changing it. (The former `--enforce` flag is accepted
  and inert: it names the default.)
- **It vets `tools/list`, not just `tools/call`.** MCP carries instructions and
  data in one channel, so a tool description has as much influence over the agent
  as the system prompt does. Schemas are pinned on first sight (`--pin-file` to
  persist across sessions) and re-checked on every later listing; a tool that
  redefines itself after approval is refused, and metadata that isn't vouched for
  is treated as adversarial ingest.
- **A `notifications/tools/list_changed` makes the catalogue stale.** The
  server has said the tools it advertised are no longer the ones it serves, so
  until a fresh `tools/list` is vetted every pinned digest may be out of date;
  calls are refused (enforce) or reported (observe) until then. A silent
  mutation, with no notification, is still caught at the next listing.
- **Signed manifests, when you have them.** `--manifests DIR` loads
  `.nucleus/manifests/*.toml`, verified under the publisher keys in
  `.nucleus/trust/*.pub`; each manifest pins the descriptor digest it vouches
  for (`schema_hash`). A served tool that matches no signed manifest is refused
  as `MCP_TOOL_UNVERIFIED`, on the first listing too — the publisher's
  signature, not first sight, is the trust. An empty trust store is a startup
  error, never a check that accepts everything.
- **The task's own tool surface, from the pod certificate.** When the node
  delivered a pod certificate (`NUCLEUS_POD_CERT`, verified against the pinned
  `NUCLEUS_CERT_ROOT_PUBKEY`) that approves a tool surface, every served tool
  must be on it at its approved descriptor digest or it is refused as
  `MCP_TOOL_UNAPPROVED`. The surface is a signed, narrow-only dimension of the
  certificate: a child pod can drop tools, never add them. A certificate with
  no surface constrains nothing; an invalid one is a startup error.
- **The pod's compartment, from the same certificate.** When the certificate
  names a compartment (`research` < `draft` < `execute` < `breakglass`, a
  signed dimension a child pod can only lower), a tool whose signed manifest
  lists `allowed_compartments` is refused outside them as
  `MCP_TOOL_WRONG_COMPARTMENT` — at listing, and therefore at call.
- **Pinning is trust-on-first-use.** That is a real bound and worth stating
  plainly: TOFU defends the *rug-pull* — benign at approval, mutated later — and
  the metadata-tainting is what covers a server that was hostile from the start.
- **Model-level.** The verdict is over the data classes a session is *observed* to
  touch via MCP tool traffic. Coverage is the honest limit: a channel the agent
  uses outside MCP is a channel the gate doesn't see. It does **not** claim to
  prove exfiltration is impossible — it shows when it's *possible*, and can stop
  it at the points it sees.

Built on the `nucleus-ifc` lethal-trifecta gate.
