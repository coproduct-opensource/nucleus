# OpenClaw Nucleus Adapter (Plugin)

This plugin routes OpenClaw tool calls through `nucleus-tool-proxy` so side effects are enforced by Nucleus.

## Install (local)

```bash
openclaw plugins install -l ./examples/openclaw-nucleus-plugin
```

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
          "approvalSecret": "<optional-approval-secret>",
          "approvalTtlSecs": 300,
          "actor": "openclaw",
          "timeoutMs": 30000
        }
      }
    }
  }
}
```

## Tools exposed

- `nucleus_read` (path)
- `nucleus_write` (path, contents)
- `nucleus_run` (command)
- `nucleus_approve` (operation, count?)

Each tool is **optional**, so you can allowlist them explicitly in your OpenClaw profile.
