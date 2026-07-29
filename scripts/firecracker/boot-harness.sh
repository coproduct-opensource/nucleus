#!/usr/bin/env bash
# Boot a REAL nucleus pod through a REAL nucleus-node, on a host with KVM.
#
# # Why this exists
#
# `smoke-test.sh` boots a STOCK Ubuntu rootfs to prove Firecracker works. It
# never runs `nucleus-guest-init` or `nucleus-tool-proxy`, so it cannot catch
# anything about how nucleus actually starts a pod.
#
# That gap hid five production-blocking defects behind a fully green test suite:
#
#   * the tool-proxy panicked as PID 1 because a Debian-slim rootfs has no CA
#     store and drand's client build `.expect()`ed;
#   * `build-rootfs.sh` installed no CA bundle at all;
#   * the workload API bridge started AFTER the health check that needed it, so
#     an identity-bearing pod could never prove itself;
#   * `guest-init` fetched the SVID and never told the proxy where it was, so
#     Tier 1/2 reported "no identity cert" with the cert on disk;
#   * the health budget was 5s, set before the guest did host round-trips during
#     startup.
#
# Every one of those needed a pod that boots. None of them needed a debugger.
#
# # What this does NOT do
#
# It does not build the guest artifacts — that needs a Linux toolchain with a
# musl cross-linker, and on a macOS workstation the natural place is a container.
# See "Building the inputs" below. This script takes the artifacts as given and
# exercises the part that only a KVM host can run.
set -euo pipefail

FC_DIR="${FC_DIR:-$HOME/fc}"
KERNEL="${KERNEL:-$FC_DIR/vmlinux}"
ROOTFS="${ROOTFS:-$FC_DIR/rootfs.ext4}"
NODE_BIN="${NODE_BIN:-$FC_DIR/nucleus-node}"
STATE_DIR="${STATE_DIR:-$FC_DIR/state}"
NODE_ADDR="${NODE_ADDR:-127.0.0.1:9900}"
AUTH_SECRET="${AUTH_SECRET:-harness-node-secret}"
PROXY_AUTH_SECRET="${PROXY_AUTH_SECRET:-harness-proxy-secret}"

die() { echo "boot-harness: $*" >&2; exit 1; }

for f in "$KERNEL" "$ROOTFS" "$NODE_BIN"; do
    [ -s "$f" ] || die "missing $f (see 'Building the inputs' in this script)"
done
[ -e /dev/kvm ] || die "no /dev/kvm — this must run on a Linux host with KVM"
command -v firecracker >/dev/null || die "firecracker is not on PATH"

# A leftover Firecracker holds the fixed API socket and every subsequent launch
# fails in a way that reads like something else entirely: first "vsock socket not
# found", then a seccomp-mode-0 verification failure (the node reads the mode of
# a process that already died). Both cost real debugging time before the cause
# was understood, so the harness clears them rather than letting them recur.
sudo pkill -f nucleus-node 2>/dev/null || true
sudo pkill -x firecracker 2>/dev/null || true
sudo rm -rf "$STATE_DIR" /run/firecracker.socket
mkdir -p "$STATE_DIR"

echo "boot-harness: starting nucleus-node"
# Seccomp verification stays ON. It is a real control and it passes here —
# measured: a node-launched Firecracker reports `Seccomp: 2, Seccomp_filters: 1`.
# If it ever fails, check first whether Firecracker actually started; the node
# reads the seccomp mode of a process that may already be gone.
sudo -b env RUST_LOG="${RUST_LOG:-info}" \
    NUCLEUS_FIRECRACKER_PATH="$(command -v firecracker)" \
    NUCLEUS_FIRECRACKER_NETNS=false \
    NUCLEUS_FIRECRACKER_JAILER=false \
    "$NODE_BIN" \
    --listen "$NODE_ADDR" \
    --state-dir "$STATE_DIR" \
    --auth-secret "$AUTH_SECRET" \
    --proxy-auth-secret "$PROXY_AUTH_SECRET" \
    --proxy-approval-secret harness-approval-secret \
    --identity-workload-api-socket "$FC_DIR/wapi.sock" \
    > "$FC_DIR/node.log" 2>&1
sleep 5
pgrep -f nucleus-node >/dev/null || { tail -20 "$FC_DIR/node.log"; die "node did not start"; }

cat > "$FC_DIR/harness-pod.json" <<JSON
{"apiVersion":"nucleus/v1","kind":"Pod",
 "metadata":{"name":"boot-harness"},
 "spec":{"work_dir":"/work","timeout_seconds":120,
   "policy":{"type":"profile","name":"codegen"},
   "image":{"kernel_path":"$KERNEL","rootfs_path":"$ROOTFS","read_only":false},
   "vsock":{"guest_cid":3,"port":5005}}}
JSON

echo "boot-harness: creating a pod"
python3 - "$FC_DIR/harness-pod.json" "$AUTH_SECRET" "$NODE_ADDR" <<'PY'
import hmac, hashlib, sys, time, urllib.request, urllib.error
spec, secret, addr = sys.argv[1], sys.argv[2].encode(), sys.argv[3]
body = open(spec, "rb").read()
ts, actor = str(int(time.time())), "boot-harness"
# The node signs HMAC(secret, "{timestamp}.{actor}.{body}") — see nucleus_node::auth.
sig = hmac.new(secret, ts.encode() + b"." + actor.encode() + b"." + body, hashlib.sha256).hexdigest()
req = urllib.request.Request(
    f"http://{addr}/v1/pods", data=body, method="POST",
    headers={"content-type": "application/json", "x-nucleus-timestamp": ts,
             "x-nucleus-actor": actor, "x-nucleus-signature": sig})
try:
    print("boot-harness: CREATE", urllib.request.urlopen(req, timeout=120).status)
except urllib.error.HTTPError as e:
    print("boot-harness: CREATE", e.code, e.read().decode()[:400]); sys.exit(1)
PY

echo
echo "boot-harness: what the guest did"
FCLOG="$(find "$STATE_DIR" -name firecracker.log | head -1)"
sudo grep -aE "fetched|FATAL|panicked|naked" "$FCLOG" 2>/dev/null | head -6 || true
echo
echo "boot-harness: node log -> $FC_DIR/node.log ; guest log -> $FCLOG"
echo "boot-harness: NOTE the node uses a fixed /run/firecracker.socket, so only"
echo "              one pod launches at a time without the jailer."

# ── Building the inputs ────────────────────────────────────────────────────
#
# On a macOS workstation, build in a container and copy only the artifacts in —
# no Rust toolchain is needed on the KVM host:
#
#   docker run --rm -v "$PWD":/w -w /w rust:1.93-slim bash -c '
#     apt-get update -qq && apt-get install -y -qq musl-tools e2fsprogs ca-certificates
#     # Ubuntu/Debian ship `musl-gcc`; .cargo/config.toml wants the target-prefixed
#     # name. On a NATIVE aarch64 host these are the same compiler, so the symlink
#     # is correct — it would NOT be when cross-compiling.
#     ln -sf "$(command -v musl-gcc)" /usr/local/bin/aarch64-linux-musl-gcc
#     rustup target add aarch64-unknown-linux-musl
#     cargo build --release --target aarch64-unknown-linux-musl \
#       -p nucleus-guest-init -p nucleus-tool-proxy -p nucleus-net-probe
#     # DEBIAN_TARBALL avoids needing Docker inside the container. ROOTFS_DIR must
#     # be on the container filesystem, NOT a bind mount: mke2fs -d calls
#     # llistxattr on every file and those syscalls fail over virtiofs, with an
#     # error that reads like a dangling symlink ("while listing attributes of awk").
#     DEBIAN_TARBALL=/out/debian.tar.gz ROOTFS_DIR=/build/rootfs \
#       ROOTFS_IMG=/build/rootfs.ext4 bash scripts/firecracker/build-rootfs.sh'
#
# The kernel can come from the same place smoke-test.sh uses:
#   https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/<arch>/vmlinux-6.1.141
#
# Then copy `rootfs.ext4`, `vmlinux` and a Linux-built `nucleus-node` to $FC_DIR
# on the KVM host and run this script.
