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
PROXY_AUTH_SECRET="${PROXY_AUTH_SECRET:-harness-proxy-secret}"

# The node's API is mTLS with SPIFFE, and this harness has to speak it.
#
# It used to sign requests with HMAC and pass the node `--auth-secret`. Move B
# deleted that tier — `crates/nucleus-node/src/auth.rs` says so plainly: "mTLS
# with SPIFFE is the only authentication method left" — and this script was not
# updated, so it has been failing at its first step ever since, on an argument
# the node no longer accepts. Nothing noticed because no workflow runs it; it is
# named only in `docs/production-delta.md`, which still lists it Done and
# Verified. A harness that exists to stop defects hiding behind a green suite
# spent that time being one.
#
# The fix needs no new trust: the node mints its own CA into the state dir at
# startup, so the harness signs itself a client certificate with it and presents
# the `ns/system/sa/cli` identity — the same one `nucleus setup` provisions, and
# an EXACT match in `auth.rs`, not a prefix.
CLI_SPIFFE="${CLI_SPIFFE:-spiffe://nucleus.local/ns/system/sa/cli}"

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
    NUCLEUS_FIRECRACKER_API_BOOT="${NUCLEUS_FIRECRACKER_API_BOOT:-false}" \
    "$NODE_BIN" \
    --listen "$NODE_ADDR" \
    --state-dir "$STATE_DIR" \
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

# Sign the harness a client identity with the node's own CA.
#
# The node writes `ca/ca-{cert,key}.pem` into the state dir as it starts, so this
# has to come after the node is up, not before. The SAN is what matters: the node
# reads the SPIFFE ID out of the URI SAN, not the subject.
echo "boot-harness: minting a client identity"
CA_DIR="$STATE_DIR/ca"
sudo test -s "$CA_DIR/ca-key.pem" || die "the node did not write a CA into $CA_DIR"
sudo cp "$CA_DIR/ca-cert.pem" "$CA_DIR/ca-key.pem" "$FC_DIR/"
sudo chown "$(id -u)" "$FC_DIR/ca-cert.pem" "$FC_DIR/ca-key.pem"
cat > "$FC_DIR/san.cnf" <<CNF
[req]
distinguished_name=dn
[dn]
[v3]
subjectAltName=URI:$CLI_SPIFFE
extendedKeyUsage=clientAuth
CNF
openssl genrsa -out "$FC_DIR/client-key.pem" 2048 2>/dev/null
openssl req -new -key "$FC_DIR/client-key.pem" -subj "/CN=cli/OU=system" \
    -out "$FC_DIR/client.csr" 2>/dev/null
openssl x509 -req -in "$FC_DIR/client.csr" -CA "$FC_DIR/ca-cert.pem" \
    -CAkey "$FC_DIR/ca-key.pem" -CAcreateserial -days 1 \
    -extfile "$FC_DIR/san.cnf" -extensions v3 -out "$FC_DIR/client-cert.pem" 2>/dev/null
[ -s "$FC_DIR/client-cert.pem" ] || die "could not sign a client certificate"

echo "boot-harness: creating a pod"
# `-k` skips verifying the SERVER, whose certificate is a SPIFFE URI SAN with no
# `127.0.0.1` in it — correct for SPIFFE and unverifiable by hostname. The client
# half is real: without `--cert`/`--key` the node closes the connection.
CODE=$(curl -sk --cert "$FC_DIR/client-cert.pem" --key "$FC_DIR/client-key.pem" \
    -X POST "https://$NODE_ADDR/v1/pods" -H "content-type: application/json" \
    --data-binary @"$FC_DIR/harness-pod.json" \
    -o "$FC_DIR/create.out" -w "%{http_code}" --max-time 120) || true
echo "boot-harness: CREATE $CODE"
if [ "$CODE" != "200" ] && [ "$CODE" != "201" ]; then
    head -c 400 "$FC_DIR/create.out"; echo; die "pod creation failed"
fi

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
# On a macOS workstation you can build everything NATIVELY — no Docker, no Linux
# VM for the build itself. Verified on Apple Silicon:
#
#   brew install e2fsprogs                      # mke2fs; keg-only, so:
#   export PATH="$(brew --prefix e2fsprogs)/sbin:$PATH"
#   cargo install cargo-zigbuild && brew install zig
#   rustup target add aarch64-unknown-linux-musl
#   cargo zigbuild --target aarch64-unknown-linux-musl --release \
#     -p nucleus-guest-init -p nucleus-tool-proxy -p nucleus-net-probe \
#     -p nucleus-workload-probe -p nucleus-egress-probe \
#     -p nucleus-podlist-probe -p nucleus-adversary-probe
#   ARCH=aarch64 DEBIAN_TARBALL=/path/to/debian-arm64.tar.gz \
#     bash scripts/firecracker/build-rootfs.sh
#
# Two things make this work. `mke2fs -d` populates the image from a directory
# without a loop mount, so no Linux kernel is needed to WRITE an ext4; and zig
# supplies the musl cross-linker, so no musl-gcc is needed to BUILD for Linux.
#
# The Debian base needs no Docker either — the layer is a gzipped tar in a
# registry, and its sha256 is the manifest digest, so the download is verifiable:
#
#   TOK=$(curl -fsSL "https://auth.docker.io/token?service=registry.docker.io\
#   &scope=repository:arm64v8/debian:pull" | jq -r .token)
#   # ...fetch the index, select platform.architecture == "arm64", GET that
#   # manifest, then GET .layers[0].digest from /v2/<repo>/blobs/<digest>.
#
# Do NOT put ROOTFS_DIR on a bind mount / virtiofs share: `mke2fs -d` calls
# llistxattr on every file and those syscalls fail there, with an error that
# reads like a dangling symlink ("while listing attributes of awk"). A native
# macOS path is fine; inside a container, use the container filesystem.
#
# The container route below still works and is what CI effectively does:
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
