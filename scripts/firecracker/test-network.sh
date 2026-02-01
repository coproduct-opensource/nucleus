#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT_DIR"
NODE_ADDR=${NODE_ADDR:-127.0.0.1:8090}
NODE_PID=""
CHECK_CONNECTIVITY=${CHECK_CONNECTIVITY:-0}
SPEC_FILE=""

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

cleanup() {
  if [ -n "${SPEC_FILE}" ] && [ -f "${SPEC_FILE}" ]; then
    rm -f "${SPEC_FILE}"
  fi
  if [ -n "${NODE_PID}" ]; then
    kill "${NODE_PID}" >/dev/null 2>&1 || true
    wait "${NODE_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [ "$(uname -s)" != "Linux" ]; then
  echo "network test requires Linux" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root (iptables, netns, tap)" >&2
  exit 1
fi

require ip
require iptables
require nsenter
require curl
require jq
require firecracker

KERNEL=${KERNEL:-${ROOT_DIR}/build/firecracker/vmlinux}
ROOTFS=${ROOTFS:-${ROOT_DIR}/build/firecracker/rootfs.ext4}
SCRATCH=${SCRATCH:-${ROOT_DIR}/build/firecracker/scratch.ext4}

if [ ! -f "$KERNEL" ] || [ ! -f "$ROOTFS" ] || [ ! -f "$SCRATCH" ]; then
  echo "missing Firecracker artifacts; build with scripts/firecracker/build-rootfs.sh" >&2
  exit 1
fi

SPEC_FILE=$(mktemp)
cat >"$SPEC_FILE" <<'YAML'
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: net-policy-test
spec:
  work_dir: /work
  timeout_seconds: 600
  policy:
    type: profile
    name: demo
  network:
    allow:
      - 1.1.1.1:443
    deny:
      - 8.8.8.8:443
  image:
    kernel_path: ./build/firecracker/vmlinux
    rootfs_path: ./build/firecracker/rootfs.ext4
    read_only: true
    scratch_path: ./build/firecracker/scratch.ext4
  vsock:
    guest_cid: 3
    port: 5005
  seccomp:
    mode: default
YAML

echo "starting nucleus-node..."
RUST_LOG=info cargo run -p nucleus-node -- \
  --driver firecracker \
  --listen "${NODE_ADDR}" \
  --proxy-auth-secret test-secret \
  --firecracker-netns >/tmp/nucleus-node-net.log 2>&1 &
NODE_PID=$!

sleep 1

RESP=$(curl -sS -X POST --data-binary @"$SPEC_FILE" "http://${NODE_ADDR}/v1/pods")
POD_ID=$(echo "$RESP" | jq -r '.id')
PROXY_ADDR=$(echo "$RESP" | jq -r '.proxy_addr')

if [ -z "$POD_ID" ] || [ "$POD_ID" = "null" ] || [ -z "$PROXY_ADDR" ] || [ "$PROXY_ADDR" = "null" ]; then
  echo "failed to create pod: $RESP" >&2
  exit 1
fi

echo "pod id: $POD_ID"
echo "proxy: $PROXY_ADDR"

echo "waiting for proxy health..."
for _ in $(seq 1 40); do
  if curl -fsS "${PROXY_ADDR}/v1/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

AUDIT_CONTENT=$(curl -sS -X POST "${PROXY_ADDR}/v1/read" \
  -H 'content-type: application/json' \
  -d '{"path":"/work/audit/nucleus-audit.log"}' | jq -r '.contents')
if [ -z "$AUDIT_CONTENT" ] || [ "$AUDIT_CONTENT" = "null" ]; then
  AUDIT_CONTENT=$(curl -sS -X POST "${PROXY_ADDR}/v1/read" \
    -H 'content-type: application/json' \
    -d '{"path":"/tmp/nucleus-audit.log"}' | jq -r '.contents')
fi

BOOT_LINE=$(echo "$AUDIT_CONTENT" | jq -R 'fromjson? | select(.event=="boot")' | tail -n 1)
if [ -z "$BOOT_LINE" ]; then
  echo "boot audit entry missing" >&2
  exit 1
fi

BOOT_SUBJECT=$(echo "$BOOT_LINE" | jq -r '.subject')
NET_ADDR=$(echo "$BOOT_SUBJECT" | jq -r '.net_addr')
if [ -z "$NET_ADDR" ] || [ "$NET_ADDR" = "null" ]; then
  echo "boot report missing net_addr" >&2
  exit 1
fi

SHORT_ID=$(echo "$POD_ID" | cut -c1-8)
NETNS="nuc-${SHORT_ID}"
echo "netns: $NETNS"

RULES=$(ip netns exec "$NETNS" iptables -S)
echo "$RULES" | grep -q "FORWARD.*1.1.1.1/32" || {
  echo "allow rule missing for 1.1.1.1/32" >&2
  exit 1
}
echo "$RULES" | grep -q "FORWARD.*8.8.8.8/32" || {
  echo "deny rule missing for 8.8.8.8/32" >&2
  exit 1
}

if [ "$CHECK_CONNECTIVITY" = "1" ]; then
  echo "checking connectivity from guest..."
  ALLOW_RESP=$(curl -sS -X POST "${PROXY_ADDR}/v1/run" \
    -H 'content-type: application/json' \
    -d '{"command":"nucleus-net-probe 1.1.1.1:443"}')
  if [ "$(echo "$ALLOW_RESP" | jq -r '.success')" != "true" ]; then
    echo "allowlist connection failed: $ALLOW_RESP" >&2
    exit 1
  fi

  DENY_RESP=$(curl -sS -X POST "${PROXY_ADDR}/v1/run" \
    -H 'content-type: application/json' \
    -d '{"command":"nucleus-net-probe 8.8.8.8:443"}')
  if [ "$(echo "$DENY_RESP" | jq -r '.success')" = "true" ]; then
    echo "denylist connection unexpectedly succeeded: $DENY_RESP" >&2
    exit 1
  fi
  echo "denylist connection blocked"
fi

echo "network policy test passed"
