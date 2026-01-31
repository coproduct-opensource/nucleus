# OpenClaw + Nucleus Demo

This demo routes OpenClaw tool calls through `nucleus-tool-proxy` and shows enforced sandboxing, approvals, and command gating.

Network policy is **default deny** inside the VM; see `net.allow` and `net.deny`.

## 1) Start the tool proxy

```bash
cargo run -p nucleus-tool-proxy -- \
  --spec examples/openclaw-demo/pod.yaml \
  --listen 127.0.0.1:8080 \
  --auth-secret demo-secret \
  --audit-log /tmp/nucleus-demo-audit.log
```

## (Optional) Firecracker demo path

This runs the proxy inside a Firecracker VM and exposes a local HTTP bridge.

### Build artifacts

```bash
# Build static proxy (inside the host)
cargo build -p nucleus-tool-proxy --release --target x86_64-unknown-linux-musl

# Build scratch image
./scripts/firecracker/build-scratch.sh

# Build rootfs (Debian slim via Docker export by default)
./scripts/firecracker/build-rootfs.sh
```

To bake in the tool-proxy auth secret (for signed proxy mode):

```bash
TOOL_PROXY_AUTH_SECRET=demo-secret \
  ./scripts/firecracker/build-rootfs.sh
```

To include a network allow/deny list in the image:

```bash
NET_ALLOW=./examples/openclaw-demo/net.allow \
NET_DENY=./examples/openclaw-demo/net.deny \
  ./scripts/firecracker/build-rootfs.sh
```

Provide a kernel at `./build/firecracker/vmlinux` (pinned, known-good).

### Start nucleus-node in Firecracker mode

```bash
cargo run -p nucleus-node -- \
  --driver firecracker \
  --listen 127.0.0.1:8081 \
  --proxy-auth-secret demo-secret
```

### Create a Firecracker pod

```bash
curl -sS -X POST --data-binary @examples/openclaw-demo/firecracker-pod.yaml \
  http://127.0.0.1:8081/v1/pods
```

Use the returned `proxy_addr` as the OpenClaw plugin `proxyUrl`. When using
`--proxy-auth-secret`, the signed proxy injects auth headers so the OpenClaw
plugin can omit `authSecret`.

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
