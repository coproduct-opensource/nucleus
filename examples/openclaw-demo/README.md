# OpenClaw + Nucleus Demo

This demo routes OpenClaw tool calls through `nucleus-tool-proxy` and shows enforced sandboxing, approvals, and command gating.

Network policy is **default deny** and enforced in the host netns (iptables) when `spec.network` is set; `net.allow`/`net.deny` are optional guest defense-in-depth.
Allow/deny entries must be IP/CIDR with optional `:port` (no hostnames).
The node provisions tap + guest IP when `spec.network` is set.

## 1) Start the tool proxy

```bash
cargo build -p nucleus-cli -p nucleus-tool-proxy -p nucleus-mcp --release
./target/release/nucleus shell --profile demo --print-config
```

This starts a tool proxy for the current directory and keeps it running until
Ctrl+C. It serves on a peer-verified Unix socket (the `Tool-proxy:` line) and
proves its sandbox with an identity minted for the run, so there is no shared
secret to choose or pass (#2446).

Note: The `demo` profile has the uninhabitable state (read + web + bash), so all bash commands
require approval. This is the secure default when an agent has access to both
private data and untrusted web content.

## (Optional) Firecracker demo path

This runs the proxy inside a Firecracker VM and exposes a local HTTP bridge.

### Build artifacts

```bash
# Build static proxy (inside the host)
cargo build -p nucleus-tool-proxy --release --target x86_64-unknown-linux-musl

# Build guest init
cargo build -p nucleus-guest-init --release --target x86_64-unknown-linux-musl

# Build TCP probe
cargo build -p nucleus-net-probe --release --target x86_64-unknown-linux-musl

# Build scratch image
./scripts/firecracker/build-scratch.sh

# Build rootfs (Debian slim via Docker export by default)
./scripts/firecracker/build-rootfs.sh
```

No secret is baked into the image: the node reaches the proxy over vsock, which
admits only the host, and approvals are verified against the node's public key.

To include a network allow/deny list in the image (optional guest defense):

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
  --artifacts-root ./build/firecracker \
  --scratch-root ./build/firecracker \
  --firecracker-netns
```

(`--firecracker-netns` is default; pass `--firecracker-netns=false` to disable.)

The node admits a pod's `kernel_path`/`rootfs_path` only from `--artifacts-root`
and its `scratch_path` only from `--scratch-root` (default: the provisioned
`/var/lib/nucleus/artifacts` and `<state-dir>/scratch`), so the two flags point
both at the dev build directory the example specs name.

### Create a Firecracker pod

```bash
curl -sS -X POST --data-binary @examples/openclaw-demo/firecracker-pod.yaml \
  http://127.0.0.1:8081/v1/pods
```

Use the returned `proxy_addr` as the OpenClaw plugin `proxyUrl`. The node's
proxy forwards over vsock, which authenticates it to the guest, and signs
approvals with the node's Ed25519 key, so the OpenClaw plugin holds no secret.

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
