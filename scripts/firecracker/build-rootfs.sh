#!/usr/bin/env bash
set -euo pipefail

ROOTFS_DIR=${ROOTFS_DIR:-./build/firecracker/rootfs}
ROOTFS_IMG=${ROOTFS_IMG:-./build/firecracker/rootfs.ext4}
POD_SPEC=${POD_SPEC:-./examples/openclaw-demo/firecracker-pod.yaml}
INIT_SRC=${INIT_SRC:-./scripts/firecracker/guest-init.sh}
PROXY_BIN=${PROXY_BIN:-./target/x86_64-unknown-linux-musl/release/nucleus-tool-proxy}
DEBIAN_IMAGE=${DEBIAN_IMAGE:-debian:bookworm-slim}
NET_ALLOW=${NET_ALLOW:-}
NET_DENY=${NET_DENY:-}
TOOL_PROXY_AUTH_SECRET=${TOOL_PROXY_AUTH_SECRET:-}
AUDIT_LOG_PATH=${AUDIT_LOG_PATH:-}

mkdir -p "$ROOTFS_DIR"
mkdir -p "$(dirname "$ROOTFS_IMG")"

if [ ! -f "$PROXY_BIN" ]; then
  echo "missing $PROXY_BIN (build with: cargo build -p nucleus-tool-proxy --release --target x86_64-unknown-linux-musl)" >&2
  exit 1
fi

if [ ! -f "$POD_SPEC" ]; then
  echo "missing $POD_SPEC" >&2
  exit 1
fi

if [ ! -f "$INIT_SRC" ]; then
  echo "missing $INIT_SRC" >&2
  exit 1
fi

if [ ! -f "./scripts/firecracker/guest-net.sh" ]; then
  echo "missing ./scripts/firecracker/guest-net.sh" >&2
  exit 1
fi

rm -rf "$ROOTFS_DIR"/*
TMP_TAR=$(mktemp)
cleanup() {
  rm -f "$TMP_TAR"
}
trap cleanup EXIT

if [ -n "${DEBIAN_TARBALL:-}" ]; then
  tar -xzf "$DEBIAN_TARBALL" -C "$ROOTFS_DIR"
else
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker not found; set DEBIAN_TARBALL to a Debian rootfs tarball instead." >&2
    exit 1
  fi
  CID=$(docker create "$DEBIAN_IMAGE" /bin/sh)
  docker export "$CID" -o "$TMP_TAR"
  docker rm "$CID" >/dev/null
  tar -xf "$TMP_TAR" -C "$ROOTFS_DIR"
fi

mkdir -p "$ROOTFS_DIR/etc/nucleus" "$ROOTFS_DIR/usr/local/bin" "$ROOTFS_DIR/work"
cp "$POD_SPEC" "$ROOTFS_DIR/etc/nucleus/pod.yaml"
if [ -f "$NET_ALLOW" ]; then
  cp "$NET_ALLOW" "$ROOTFS_DIR/etc/nucleus/net.allow"
fi
if [ -f "$NET_DENY" ]; then
  cp "$NET_DENY" "$ROOTFS_DIR/etc/nucleus/net.deny"
fi
if [ -n "$TOOL_PROXY_AUTH_SECRET" ]; then
  printf "%s" "$TOOL_PROXY_AUTH_SECRET" >"$ROOTFS_DIR/etc/nucleus/auth.secret"
  chmod 600 "$ROOTFS_DIR/etc/nucleus/auth.secret"
fi
if [ -n "$AUDIT_LOG_PATH" ]; then
  printf "%s" "$AUDIT_LOG_PATH" >"$ROOTFS_DIR/etc/nucleus/audit.path"
  chmod 600 "$ROOTFS_DIR/etc/nucleus/audit.path"
fi
cp "$PROXY_BIN" "$ROOTFS_DIR/usr/local/bin/nucleus-tool-proxy"
cp "$INIT_SRC" "$ROOTFS_DIR/init"
cp "./scripts/firecracker/guest-net.sh" "$ROOTFS_DIR/usr/local/bin/guest-net.sh"
chmod +x "$ROOTFS_DIR/init" "$ROOTFS_DIR/usr/local/bin/nucleus-tool-proxy"
chmod +x "$ROOTFS_DIR/usr/local/bin/guest-net.sh"

# Build ext4 image from directory
rm -f "$ROOTFS_IMG"
MKE2FS_OPTS=${MKE2FS_OPTS:-"-d $ROOTFS_DIR -t ext4 -m 0 -F"}
# shellcheck disable=SC2086
mke2fs $MKE2FS_OPTS "$ROOTFS_IMG" 256M

echo "rootfs image written to $ROOTFS_IMG"
