# OpenClaw Nucleus Plugin

Routes OpenClaw tool calls through `nucleus-tool-proxy` so every file, command, and network operation executes inside a Nucleus sandbox with policy enforcement, HMAC-signed audit logging, and approval gating.

## Install

```bash
openclaw plugins install -l ./examples/openclaw-nucleus-plugin
```

## Dual Architecture: SKILL.md + Plugin

This plugin uses a **skill + plugin** split:

- **`SKILL.md`** (behavioral rules) — Tells the LLM agent to always prefer `nucleus_*` tools over built-in equivalents. This is a prompt-level instruction that the agent follows voluntarily.
- **Plugin** (tool routing) — Registers 8 tools that POST JSON to `nucleus-tool-proxy` endpoints with HMAC-signed headers. This is the enforcement layer: even if the agent tried to use a built-in tool, the sandbox prevents direct filesystem/network access.

Together they provide defense in depth: the skill steers the agent toward the safe path, and the plugin + sandbox enforce it.

## Complementary: SecureClaw

[SecureClaw](https://github.com/anthropics/secureclaw) provides OWASP-style audit checks (51 rules covering injection, path traversal, SSRF, etc.) at the **prompt/response** layer. Nucleus provides **runtime isolation** (VM sandbox, policy lattice, network allowlists) at the OS layer.

They are complementary:
- SecureClaw catches unsafe patterns *before* execution (static analysis of tool calls)
- Nucleus prevents harm *during* execution (sandboxed runtime with capability enforcement)

Use both for defense in depth: SecureClaw as a pre-flight check, Nucleus as the execution sandbox.

## Tools

All 8 tools are registered as **optional** — you can allowlist a subset in your OpenClaw settings.

### `nucleus_read`

Read a file inside the sandbox.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | `string` | yes | File path relative to sandbox root |

**Endpoint:** `POST /v1/read`

### `nucleus_write`

Write a file inside the sandbox. Requires write permission in the active policy.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | `string` | yes | File path relative to sandbox root |
| `contents` | `string` | yes | File contents to write |

**Endpoint:** `POST /v1/write`

### `nucleus_run`

Run a command inside the sandbox. Uses array-based args to prevent shell injection.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `args` | `string[]` | yes | Command as argument array, e.g. `["ls", "-la"]` |
| `stdin` | `string` | no | Input to pass to command stdin |
| `directory` | `string` | no | Working directory (relative to sandbox root) |
| `timeout_seconds` | `number` | no | Timeout in seconds (clamped to policy limit) |

**Endpoint:** `POST /v1/run`

### `nucleus_web_fetch`

Fetch a URL through the nucleus network proxy. Respects network allowlist policy.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | `string` | yes | URL to fetch |
| `method` | `string` | no | HTTP method (default `GET`) |
| `headers` | `object` | no | Request headers (`{key: value}`) |
| `body` | `string` | no | Request body |

**Endpoint:** `POST /v1/web_fetch`

### `nucleus_glob`

Search for files by glob pattern inside the sandbox.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pattern` | `string` | yes | Glob pattern (e.g. `**/*.rs`, `src/*.json`) |
| `directory` | `string` | no | Directory to search in (relative to sandbox root) |
| `max_results` | `number` | no | Maximum number of results |

**Endpoint:** `POST /v1/glob`

### `nucleus_grep`

Search file contents by regex pattern inside the sandbox.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pattern` | `string` | yes | Regex pattern to search for |
| `path` | `string` | no | File path to search in |
| `glob` | `string` | no | Glob pattern to filter files |
| `context_lines` | `number` | no | Context lines before/after match |
| `max_matches` | `number` | no | Maximum number of matches |
| `case_insensitive` | `boolean` | no | Case-insensitive search |

**Endpoint:** `POST /v1/grep`

### `nucleus_web_search`

Search the web through the nucleus network proxy. Respects network allowlist policy.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | `string` | yes | Search query |
| `max_results` | `number` | no | Maximum number of results |

**Endpoint:** `POST /v1/web_search`

### `nucleus_approve`

Pre-approve a pending operation. Uses the approval secret (higher privilege) when configured.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `operation` | `string` | yes | Operation identifier to approve |
| `count` | `number` | no | Number of times to approve (default 1) |

**Endpoint:** `POST /v1/approve`

When `approvalSecret` is configured, the plugin automatically attaches a nonce and expiry timestamp, signing the request with the approval secret instead of the regular auth secret.

## Configure

Add to `~/.openclaw/settings.json` (or your profile settings):

```json
{
  "plugins": {
    "entries": {
      "nucleus": {
        "enabled": true,
        "config": {
          "proxyUrl": "http://127.0.0.1:8080",
          "authSecret": "<shared-secret>",
          "approvalSecret": "<approval-secret>",
          "approvalTtlSecs": 300,
          "actor": "openclaw",
          "timeoutMs": 30000
        }
      }
    }
  }
}
```

### HMAC Authentication

Every request to `nucleus-tool-proxy` is HMAC-SHA256 signed. The signature covers:

```
HMAC-SHA256(secret, "{timestamp}.{actor}.{body}")
```

Headers sent:
- `X-Nucleus-Timestamp` — Unix epoch seconds
- `X-Nucleus-Signature` — Hex-encoded HMAC digest
- `X-Nucleus-Actor` — Actor identifier (for audit logs)

The tool-proxy validates the signature and rejects requests with clock skew beyond the configured maximum (default 60 seconds).

### Approval Secret

The `approvalSecret` is a **separate, higher-privilege** secret used only for `nucleus_approve` calls. This allows you to:

1. Give agents a low-privilege `authSecret` for read/run operations
2. Gate destructive operations behind approval with a separate key
3. Set a TTL (`approvalTtlSecs`, max 300s) so approvals auto-expire

If `approvalSecret` is empty, approvals use the regular `authSecret`.

### Config Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `proxyUrl` | `string` | `http://127.0.0.1:8080` | Base URL of `nucleus-tool-proxy` |
| `authSecret` | `string` | `""` | HMAC shared secret for request signing |
| `approvalSecret` | `string` | `""` | Separate HMAC secret for approval operations |
| `approvalTtlSecs` | `number` | `300` | Approval expiry in seconds (max 300) |
| `actor` | `string` | `""` | Actor identifier for audit trail |
| `timeoutMs` | `number` | `30000` | Request timeout in milliseconds |

## Permission Market Integration

When the `nucleus-permission-market` crate is active on the tool-proxy, this plugin includes permission bid headers with each request:

- `X-Nucleus-Permission-Bid` — JSON-encoded bid with `skill_id`, `dimensions`, `value_estimate`, and `trust_tier`

The market evaluates each bid against current Lagrange multiplier prices per permission dimension. Permissions with price exceeding the bid value are denied. See the `nucleus-permission-market` crate for details.
