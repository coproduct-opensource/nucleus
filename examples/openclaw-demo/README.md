# OpenClaw + Nucleus Demo

This demo routes OpenClaw tool calls through `nucleus-tool-proxy` and shows enforced sandboxing, approvals, and command gating.

## 1) Start the tool proxy

```bash
cargo run -p nucleus-tool-proxy -- \
  --spec examples/openclaw-demo/pod.yaml \
  --listen 127.0.0.1:8080 \
  --auth-secret demo-secret \
  --audit-log /tmp/nucleus-demo-audit.log
```

## 2) Install the OpenClaw adapter

```bash
openclaw plugins install -l ./examples/openclaw-nucleus-plugin
```

## 3) Configure OpenClaw

Copy `examples/openclaw-demo/settings.json` to your OpenClaw settings path.

## 4) Demo script (copy into OpenClaw)

Ask the agent to call the tools directly:

```
1) nucleus_read {"path":"README.md"}
2) nucleus_read {"path":".env"}
3) nucleus_write {"path":"/tmp/nucleus-demo.txt","contents":"demo write"}
4) nucleus_run {"command":"git status"}
5) nucleus_run {"command":"bash -c 'echo hi'"}
6) nucleus_run {"command":"git push"}
7) nucleus_approve {"operation":"git push"}
8) nucleus_run {"command":"git push"}
```

## Expected outcomes

- `README.md` read succeeds.
- `.env` read is blocked (sensitive path).
- Writes require approval (obligation).
- `bash -c` is blocked by structured command rules.
- `git push` requires approval; after `nucleus_approve`, it runs (or fails by git config, but enforcement allows it).
- Audit log records each action and approval.
