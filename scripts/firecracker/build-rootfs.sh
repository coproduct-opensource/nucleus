#!/usr/bin/env bash
# Build ext4 rootfs image for Firecracker microVMs
# Supports both aarch64 (Apple Silicon) and x86_64 (Intel) architectures
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Architecture detection: default to host architecture
detect_arch() {
    local host_arch
    host_arch=$(uname -m)
    case "$host_arch" in
        arm64|aarch64)
            echo "aarch64"
            ;;
        x86_64|amd64)
            echo "x86_64"
            ;;
        *)
            echo "x86_64"  # Default fallback
            ;;
    esac
}

ARCH="${ARCH:-$(detect_arch)}"

# Set architecture-specific defaults
case "$ARCH" in
    aarch64)
        TARGET="aarch64-unknown-linux-musl"
        DEBIAN_IMAGE="${DEBIAN_IMAGE:-arm64v8/debian:bookworm-slim}"
        ;;
    x86_64)
        TARGET="x86_64-unknown-linux-musl"
        DEBIAN_IMAGE="${DEBIAN_IMAGE:-debian:bookworm-slim}"
        ;;
    *)
        echo "Unsupported architecture: $ARCH" >&2
        echo "Supported: aarch64, x86_64" >&2
        exit 1
        ;;
esac

# Configurable paths
ROOTFS_DIR="${ROOTFS_DIR:-$ROOT_DIR/build/firecracker/$ARCH/rootfs}"
ROOTFS_IMG="${ROOTFS_IMG:-$ROOT_DIR/build/firecracker/$ARCH/rootfs.ext4}"
POD_SPEC="${POD_SPEC:-$ROOT_DIR/examples/openclaw-demo/firecracker-pod.yaml}"
GUEST_INIT_BIN="${GUEST_INIT_BIN:-$ROOT_DIR/target/$TARGET/release/nucleus-guest-init}"
INIT_SRC="${INIT_SRC:-$SCRIPT_DIR/guest-init.sh}"
PROXY_BIN="${PROXY_BIN:-$ROOT_DIR/target/$TARGET/release/nucleus-tool-proxy}"
NET_PROBE_BIN="${NET_PROBE_BIN:-$ROOT_DIR/target/$TARGET/release/nucleus-net-probe}"
NET_ALLOW="${NET_ALLOW:-}"
NET_DENY="${NET_DENY:-}"
TOOL_PROXY_AUTH_SECRET="${TOOL_PROXY_AUTH_SECRET:-}"
AUDIT_LOG_PATH="${AUDIT_LOG_PATH:-}"
APPROVAL_SECRET="${APPROVAL_SECRET:-}"

# Image size (in MB)
ROOTFS_SIZE_MB="${ROOTFS_SIZE_MB:-256}"

print_usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Build ext4 rootfs image for Firecracker microVMs.

Options:
    --arch ARCH             Architecture: aarch64 or x86_64 (default: auto-detect)
    --output PATH           Output rootfs.ext4 path (default: build/firecracker/ARCH/rootfs.ext4)
    --pod-spec PATH         Pod spec YAML file (default: examples/openclaw-demo/firecracker-pod.yaml)
    --auth-secret SECRET    Tool proxy auth secret (required)
    --approval-secret SECRET  Approval secret (required)
    --net-allow PATH        Network allow list file
    --net-deny PATH         Network deny list file
    --audit-path PATH       Audit log path inside VM
    --size MB               Rootfs image size in MB (default: 256)
    --verify                Verify required binaries exist without building
    -h, --help              Show this help message

Environment Variables:
    ARCH                    Architecture (aarch64 or x86_64)
    TOOL_PROXY_AUTH_SECRET  Auth secret for tool proxy
    APPROVAL_SECRET         Secret for approval requests
    DEBIAN_TARBALL          Path to Debian rootfs tarball (skips Docker)

Examples:
    # Build for current architecture
    $(basename "$0") --auth-secret \$AUTH --approval-secret \$APPROVAL

    # Build for specific architecture
    $(basename "$0") --arch x86_64 --auth-secret \$AUTH --approval-secret \$APPROVAL

    # Verify binaries exist
    $(basename "$0") --verify --arch aarch64
EOF
}

VERIFY_ONLY=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            ARCH="$2"
            # Re-derive target from new ARCH
            case "$ARCH" in
                aarch64)
                    TARGET="aarch64-unknown-linux-musl"
                    DEBIAN_IMAGE="${DEBIAN_IMAGE:-arm64v8/debian:bookworm-slim}"
                    ;;
                x86_64)
                    TARGET="x86_64-unknown-linux-musl"
                    DEBIAN_IMAGE="${DEBIAN_IMAGE:-debian:bookworm-slim}"
                    ;;
                *)
                    echo "Unsupported architecture: $ARCH" >&2
                    exit 1
                    ;;
            esac
            # Update paths with new arch/target
            ROOTFS_DIR="${ROOTFS_DIR:-$ROOT_DIR/build/firecracker/$ARCH/rootfs}"
            ROOTFS_IMG="${ROOTFS_IMG:-$ROOT_DIR/build/firecracker/$ARCH/rootfs.ext4}"
            GUEST_INIT_BIN="${GUEST_INIT_BIN:-$ROOT_DIR/target/$TARGET/release/nucleus-guest-init}"
            PROXY_BIN="${PROXY_BIN:-$ROOT_DIR/target/$TARGET/release/nucleus-tool-proxy}"
            NET_PROBE_BIN="${NET_PROBE_BIN:-$ROOT_DIR/target/$TARGET/release/nucleus-net-probe}"
            shift 2
            ;;
        --output)
            ROOTFS_IMG="$2"
            ROOTFS_DIR="${ROOTFS_IMG%.ext4}_rootfs"
            shift 2
            ;;
        --pod-spec)
            POD_SPEC="$2"
            shift 2
            ;;
        --auth-secret)
            TOOL_PROXY_AUTH_SECRET="$2"
            shift 2
            ;;
        --approval-secret)
            APPROVAL_SECRET="$2"
            shift 2
            ;;
        --net-allow)
            NET_ALLOW="$2"
            shift 2
            ;;
        --net-deny)
            NET_DENY="$2"
            shift 2
            ;;
        --audit-path)
            AUDIT_LOG_PATH="$2"
            shift 2
            ;;
        --size)
            ROOTFS_SIZE_MB="$2"
            shift 2
            ;;
        --verify)
            VERIFY_ONLY=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            print_usage
            exit 1
            ;;
    esac
done

# Verify mode: just check if binaries exist
if [ "$VERIFY_ONLY" = true ]; then
    echo "Verifying binaries for $ARCH ($TARGET)..."
    missing=0
    for bin in "$PROXY_BIN" "$NET_PROBE_BIN"; do
        if [ ! -f "$bin" ]; then
            echo "  MISSING: $bin"
            missing=1
        else
            echo "  OK: $bin"
        fi
    done
    if [ ! -f "$GUEST_INIT_BIN" ] && [ ! -f "$INIT_SRC" ]; then
        echo "  MISSING: $GUEST_INIT_BIN (and no fallback $INIT_SRC)"
        missing=1
    else
        if [ -f "$GUEST_INIT_BIN" ]; then
            echo "  OK: $GUEST_INIT_BIN"
        else
            echo "  FALLBACK: $INIT_SRC (shell script init)"
        fi
    fi
    exit $missing
fi

# Validate required inputs
if [ ! -f "$PROXY_BIN" ]; then
    echo "Missing $PROXY_BIN" >&2
    echo "Build with: scripts/cross-build.sh --arch $ARCH" >&2
    exit 1
fi

if [ ! -f "$NET_PROBE_BIN" ]; then
    echo "Missing $NET_PROBE_BIN" >&2
    echo "Build with: scripts/cross-build.sh --arch $ARCH" >&2
    exit 1
fi

if [ ! -f "$POD_SPEC" ]; then
    echo "Missing $POD_SPEC" >&2
    exit 1
fi

if [ ! -f "$GUEST_INIT_BIN" ] && [ ! -f "$INIT_SRC" ]; then
    echo "Missing $GUEST_INIT_BIN" >&2
    echo "Build with: scripts/cross-build.sh --arch $ARCH" >&2
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/guest-net.sh" ]; then
    echo "Missing $SCRIPT_DIR/guest-net.sh" >&2
    exit 1
fi

if [ -z "$TOOL_PROXY_AUTH_SECRET" ]; then
    echo "TOOL_PROXY_AUTH_SECRET is required to build a secure rootfs." >&2
    echo "Set via --auth-secret or TOOL_PROXY_AUTH_SECRET env var" >&2
    exit 1
fi

if [ -z "$APPROVAL_SECRET" ]; then
    echo "APPROVAL_SECRET is required to build a secure rootfs." >&2
    echo "Set via --approval-secret or APPROVAL_SECRET env var" >&2
    exit 1
fi

echo "Building rootfs for architecture: $ARCH"
echo "  Target: $TARGET"
echo "  Output: $ROOTFS_IMG"
echo "  Size: ${ROOTFS_SIZE_MB}MB"

mkdir -p "$ROOTFS_DIR"
mkdir -p "$(dirname "$ROOTFS_IMG")"

rm -rf "${ROOTFS_DIR:?}"/*
TMP_TAR=$(mktemp)
cleanup() {
    rm -f "$TMP_TAR"
}
trap cleanup EXIT

# Extract Debian base
if [ -n "${DEBIAN_TARBALL:-}" ]; then
    echo "Using Debian tarball: $DEBIAN_TARBALL"
    tar -xzf "$DEBIAN_TARBALL" -C "$ROOTFS_DIR"
else
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker not found. Set DEBIAN_TARBALL to a Debian rootfs tarball instead." >&2
        exit 1
    fi
    echo "Extracting base from Docker image: $DEBIAN_IMAGE"
    CID=$(docker create "$DEBIAN_IMAGE" /bin/sh)
    docker export "$CID" -o "$TMP_TAR"
    docker rm "$CID" >/dev/null
    tar -xf "$TMP_TAR" -C "$ROOTFS_DIR"
fi

# Create nucleus directories
mkdir -p "$ROOTFS_DIR/etc/nucleus" "$ROOTFS_DIR/usr/local/bin" "$ROOTFS_DIR/work"

# Copy pod spec
cp "$POD_SPEC" "$ROOTFS_DIR/etc/nucleus/pod.yaml"

# Copy network policy files if provided
if [ -n "$NET_ALLOW" ] && [ -f "$NET_ALLOW" ]; then
    cp "$NET_ALLOW" "$ROOTFS_DIR/etc/nucleus/net.allow"
fi
if [ -n "$NET_DENY" ] && [ -f "$NET_DENY" ]; then
    cp "$NET_DENY" "$ROOTFS_DIR/etc/nucleus/net.deny"
fi

# Write secrets with restricted permissions
printf "%s" "$TOOL_PROXY_AUTH_SECRET" >"$ROOTFS_DIR/etc/nucleus/auth.secret"
chmod 600 "$ROOTFS_DIR/etc/nucleus/auth.secret"
printf "%s" "$APPROVAL_SECRET" >"$ROOTFS_DIR/etc/nucleus/approval.secret"
chmod 600 "$ROOTFS_DIR/etc/nucleus/approval.secret"

# Write audit path if configured
if [ -n "$AUDIT_LOG_PATH" ]; then
    printf "%s" "$AUDIT_LOG_PATH" >"$ROOTFS_DIR/etc/nucleus/audit.path"
    chmod 600 "$ROOTFS_DIR/etc/nucleus/audit.path"
fi

# Copy binaries
cp "$PROXY_BIN" "$ROOTFS_DIR/usr/local/bin/nucleus-tool-proxy"
cp "$NET_PROBE_BIN" "$ROOTFS_DIR/usr/local/bin/nucleus-net-probe"

# Copy init binary (prefer Rust binary, fall back to shell script)
if [ -f "$GUEST_INIT_BIN" ]; then
    cp "$GUEST_INIT_BIN" "$ROOTFS_DIR/init"
    echo "Using Rust init binary"
else
    cp "$INIT_SRC" "$ROOTFS_DIR/init"
    echo "Using shell script init (fallback)"
fi

# Copy network setup script
cp "$SCRIPT_DIR/guest-net.sh" "$ROOTFS_DIR/usr/local/bin/guest-net.sh"

# Set executable permissions
chmod +x "$ROOTFS_DIR/init"
chmod +x "$ROOTFS_DIR/usr/local/bin/nucleus-tool-proxy"
chmod +x "$ROOTFS_DIR/usr/local/bin/nucleus-net-probe"
chmod +x "$ROOTFS_DIR/usr/local/bin/guest-net.sh"

# Build ext4 image from directory
rm -f "$ROOTFS_IMG"
MKE2FS_OPTS="${MKE2FS_OPTS:-"-d $ROOTFS_DIR -t ext4 -m 0 -F"}"
# shellcheck disable=SC2086
mke2fs $MKE2FS_OPTS "$ROOTFS_IMG" "${ROOTFS_SIZE_MB}M"

echo ""
echo "Rootfs image written to: $ROOTFS_IMG"
echo "Architecture: $ARCH"

# Print binary info
echo ""
echo "Included binaries:"
for bin in init usr/local/bin/nucleus-tool-proxy usr/local/bin/nucleus-net-probe; do
    if [ -f "$ROOTFS_DIR/$bin" ]; then
        size=$(du -h "$ROOTFS_DIR/$bin" | cut -f1)
        echo "  /$bin ($size)"
    fi
done
