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
WORKLOAD_PROBE_BIN="${WORKLOAD_PROBE_BIN:-$ROOT_DIR/target/$TARGET/release/nucleus-workload-probe}"
EGRESS_PROBE_BIN="${EGRESS_PROBE_BIN:-$ROOT_DIR/target/$TARGET/release/nucleus-egress-probe}"
PODLIST_PROBE_BIN="${PODLIST_PROBE_BIN:-$ROOT_DIR/target/$TARGET/release/nucleus-podlist-probe}"
ADVERSARY_PROBE_BIN="${ADVERSARY_PROBE_BIN:-$ROOT_DIR/target/$TARGET/release/nucleus-adversary-probe}"
NET_ALLOW="${NET_ALLOW:-}"
NET_DENY="${NET_DENY:-}"
# NOTE: Secrets are now injected at runtime via kernel command line (nucleus.auth_secret, nucleus.approval_secret)
# The guest-init binary reads these from /proc/cmdline and sets them as environment variables.
# This removes the security risk of secrets being baked into the rootfs image.
AUDIT_LOG_PATH="${AUDIT_LOG_PATH:-}"

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
    --legacy-secrets        Bake secrets into rootfs (deprecated, insecure)
    --net-allow PATH        Network allow list file
    --net-deny PATH         Network deny list file
    --audit-path PATH       Audit log path inside VM
    --size MB               Rootfs image size in MB (default: 256)

Environment:
  OVERLAY_DIR             Directory copied over the rootfs after the nucleus
                          binaries, for a workload runtime or agent CLI. Opaque
                          to nucleus. Paths that would shadow the mediating
                          runtime (/init, nucleus-tool-proxy, nucleus-net-probe,
                          guest-net.sh) are restored and the attempt reported.
    --verify                Verify required binaries exist without building
    -h, --help              Show this help message

Environment Variables:
    ARCH                    Architecture (aarch64 or x86_64)
    DEBIAN_TARBALL          Path to Debian rootfs tarball (skips Docker)

Secrets are injected at runtime via kernel command line by nucleus-node.
This is more secure than baking secrets into the rootfs image.

Examples:
    # Build for current architecture
    $(basename "$0")

    # Build for specific architecture
    $(basename "$0") --arch x86_64

    # Verify binaries exist
    $(basename "$0") --verify --arch aarch64
EOF
}

VERIFY_ONLY=false
LEGACY_SECRETS=false
TOOL_PROXY_AUTH_SECRET=""
APPROVAL_SECRET=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --legacy-secrets)
            LEGACY_SECRETS=true
            shift
            ;;
        --auth-secret)
            # Legacy option - only used with --legacy-secrets
            TOOL_PROXY_AUTH_SECRET="$2"
            shift 2
            ;;
        --approval-secret)
            # Legacy option - only used with --legacy-secrets
            APPROVAL_SECRET="$2"
            shift 2
            ;;
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
WORKLOAD_PROBE_BIN="${WORKLOAD_PROBE_BIN:-$ROOT_DIR/target/$TARGET/release/nucleus-workload-probe}"
EGRESS_PROBE_BIN="${EGRESS_PROBE_BIN:-$ROOT_DIR/target/$TARGET/release/nucleus-egress-probe}"
PODLIST_PROBE_BIN="${PODLIST_PROBE_BIN:-$ROOT_DIR/target/$TARGET/release/nucleus-podlist-probe}"
ADVERSARY_PROBE_BIN="${ADVERSARY_PROBE_BIN:-$ROOT_DIR/target/$TARGET/release/nucleus-adversary-probe}"
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
    for bin in "$PROXY_BIN" "$NET_PROBE_BIN" "$WORKLOAD_PROBE_BIN" "$EGRESS_PROBE_BIN"; do
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
    exit 1
fi
if [ ! -f "$WORKLOAD_PROBE_BIN" ]; then
    echo "Missing $WORKLOAD_PROBE_BIN" >&2
    echo "Build with: scripts/cross-build.sh --arch $ARCH" >&2
    exit 1
fi
if [ ! -f "$EGRESS_PROBE_BIN" ]; then
    echo "Missing $EGRESS_PROBE_BIN" >&2
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

# Legacy secrets mode validation
if [ "$LEGACY_SECRETS" = true ]; then
    if [ -z "$TOOL_PROXY_AUTH_SECRET" ]; then
        echo "TOOL_PROXY_AUTH_SECRET is required with --legacy-secrets." >&2
        echo "Set via --auth-secret or TOOL_PROXY_AUTH_SECRET env var" >&2
        exit 1
    fi
    if [ -z "$APPROVAL_SECRET" ]; then
        echo "APPROVAL_SECRET is required with --legacy-secrets." >&2
        echo "Set via --approval-secret or APPROVAL_SECRET env var" >&2
        exit 1
    fi
    echo "WARNING: --legacy-secrets is deprecated. Secrets should be injected at runtime." >&2
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
    # Map ARCH to Docker platform for cross-architecture builds (e.g., aarch64 on x86_64 CI)
    case "$ARCH" in
        aarch64) DOCKER_PLATFORM="linux/arm64" ;;
        x86_64)  DOCKER_PLATFORM="linux/amd64" ;;
        *)       DOCKER_PLATFORM="linux/amd64" ;;
    esac
    echo "Extracting base from Docker image: $DEBIAN_IMAGE (platform: $DOCKER_PLATFORM)"
    CID=$(docker create --platform "$DOCKER_PLATFORM" "$DEBIAN_IMAGE" /bin/sh)
    docker export "$CID" -o "$TMP_TAR"
    docker rm "$CID" >/dev/null
    tar -xf "$TMP_TAR" -C "$ROOTFS_DIR"
fi

# Create nucleus directories
mkdir -p "$ROOTFS_DIR/etc/nucleus" "$ROOTFS_DIR/usr/local/bin" "$ROOTFS_DIR/work"

# Copy pod spec
cp "$POD_SPEC" "$ROOTFS_DIR/etc/nucleus/pod.yaml"

# CA certificates. The tool-proxy builds an HTTPS client at startup when drand is
# enabled (the default), and a Debian slim base ships NO system CA store — so
# without this the proxy cannot construct that client. It is PID 1 in the guest,
# so the failure took down the whole microVM.
#
# Found by booting a pod built from this script on real KVM, not by review: every
# unit test passes on a host that happens to have a CA store.
#
# Copied from the build host rather than apt-installed, so the rootfs build stays
# offline and needs no package manager inside the target tree.
if [ -d /etc/ssl/certs ] && [ -s /etc/ssl/certs/ca-certificates.crt ]; then
    mkdir -p "$ROOTFS_DIR/etc/ssl/certs"
    cp /etc/ssl/certs/ca-certificates.crt "$ROOTFS_DIR/etc/ssl/certs/ca-certificates.crt"
    echo "Installed CA bundle from build host"
else
    echo "WARNING: no CA bundle at /etc/ssl/certs/ca-certificates.crt on the build host." >&2
    echo "         The guest tool-proxy will refuse to start with drand enabled." >&2
    echo "         Install ca-certificates on the build host, or build with drand off." >&2
fi

# Copy network policy files if provided
if [ -n "$NET_ALLOW" ] && [ -f "$NET_ALLOW" ]; then
    cp "$NET_ALLOW" "$ROOTFS_DIR/etc/nucleus/net.allow"
fi
if [ -n "$NET_DENY" ] && [ -f "$NET_DENY" ]; then
    cp "$NET_DENY" "$ROOTFS_DIR/etc/nucleus/net.deny"
fi

# Write secrets only if legacy mode is enabled (deprecated)
if [ "$LEGACY_SECRETS" = true ]; then
    echo "Writing secrets to rootfs (DEPRECATED - use runtime injection instead)"
    printf "%s" "$TOOL_PROXY_AUTH_SECRET" >"$ROOTFS_DIR/etc/nucleus/auth.secret"
    chmod 600 "$ROOTFS_DIR/etc/nucleus/auth.secret"
    printf "%s" "$APPROVAL_SECRET" >"$ROOTFS_DIR/etc/nucleus/approval.secret"
    chmod 600 "$ROOTFS_DIR/etc/nucleus/approval.secret"
fi

# Write audit path if configured
if [ -n "$AUDIT_LOG_PATH" ]; then
    printf "%s" "$AUDIT_LOG_PATH" >"$ROOTFS_DIR/etc/nucleus/audit.path"
    chmod 600 "$ROOTFS_DIR/etc/nucleus/audit.path"
fi

# Copy binaries
cp "$PROXY_BIN" "$ROOTFS_DIR/usr/local/bin/nucleus-tool-proxy"
cp "$NET_PROBE_BIN" "$ROOTFS_DIR/usr/local/bin/nucleus-net-probe"
cp "$WORKLOAD_PROBE_BIN" "$ROOTFS_DIR/usr/local/bin/nucleus-workload-probe"
cp "$EGRESS_PROBE_BIN" "$ROOTFS_DIR/usr/local/bin/nucleus-egress-probe"
# Only the C2 podlist boot lane builds this probe; the default probe-pod boot
# does not, so bake it only when it was built (an absent binary is not an error).
[ -f "$PODLIST_PROBE_BIN" ] && cp "$PODLIST_PROBE_BIN" "$ROOTFS_DIR/usr/local/bin/nucleus-podlist-probe"
# The adversary probe is baked for the probe-pod boot lane (which builds it and
# runs it as the workload); guarded like podlist so lanes that do not build it
# skip cleanly rather than error.
[ -f "$ADVERSARY_PROBE_BIN" ] && cp "$ADVERSARY_PROBE_BIN" "$ROOTFS_DIR/usr/local/bin/nucleus-adversary-probe"

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

# Overlay: an operator-supplied directory copied over the rootfs.
#
# This is how a workload gets into the image — a language runtime, an agent CLI,
# whatever the pod is meant to run. Nucleus deliberately does not know what that
# is: the overlay is opaque, and nothing vendor-specific belongs in this script
# or anywhere else in the repo.
#
# Copied AFTER the nucleus binaries on purpose. An overlay that shadowed
# `nucleus-tool-proxy` or `/init` would replace the mediating runtime with
# whatever the operator shipped, so those paths are restored below and the
# attempt is reported rather than silently honoured.
if [ -n "${OVERLAY_DIR:-}" ]; then
    if [ ! -d "$OVERLAY_DIR" ]; then
        echo "ERROR: OVERLAY_DIR=$OVERLAY_DIR is not a directory" >&2
        exit 1
    fi
    echo "Applying overlay from $OVERLAY_DIR"
    cp -a "$OVERLAY_DIR/." "$ROOTFS_DIR/"

    # Restore anything the overlay shadowed. Checked by re-copying rather than
    # by scanning the overlay for names: a scan has to enumerate every path that
    # matters and will miss the one added next year.
    for guarded in \
        "usr/local/bin/nucleus-tool-proxy" \
        "usr/local/bin/nucleus-net-probe" \
        "usr/local/bin/nucleus-workload-probe" \
        "usr/local/bin/nucleus-egress-probe" \
        "usr/local/bin/guest-net.sh"; do
        if [ -e "$OVERLAY_DIR/$guarded" ]; then
            echo "WARNING: overlay shadowed $guarded; restoring the nucleus binary" >&2
        fi
    done
    cp "$PROXY_BIN" "$ROOTFS_DIR/usr/local/bin/nucleus-tool-proxy"
    cp "$NET_PROBE_BIN" "$ROOTFS_DIR/usr/local/bin/nucleus-net-probe"
    cp "$WORKLOAD_PROBE_BIN" "$ROOTFS_DIR/usr/local/bin/nucleus-workload-probe"
    cp "$EGRESS_PROBE_BIN" "$ROOTFS_DIR/usr/local/bin/nucleus-egress-probe"
    # Conditional for the same reason as the primary copy above (podlist probe is
    # built only by the C2 boot lane).
    [ -f "$PODLIST_PROBE_BIN" ] && cp "$PODLIST_PROBE_BIN" "$ROOTFS_DIR/usr/local/bin/nucleus-podlist-probe"
# The adversary probe is baked for the probe-pod boot lane (which builds it and
# runs it as the workload); guarded like podlist so lanes that do not build it
# skip cleanly rather than error.
[ -f "$ADVERSARY_PROBE_BIN" ] && cp "$ADVERSARY_PROBE_BIN" "$ROOTFS_DIR/usr/local/bin/nucleus-adversary-probe"
    cp "$SCRIPT_DIR/guest-net.sh" "$ROOTFS_DIR/usr/local/bin/guest-net.sh"
    if [ -e "$OVERLAY_DIR/init" ]; then
        echo "WARNING: overlay shadowed /init; restoring the nucleus init" >&2
    fi
    if [ -f "$GUEST_INIT_BIN" ]; then
        cp "$GUEST_INIT_BIN" "$ROOTFS_DIR/init"
    else
        cp "$INIT_SRC" "$ROOTFS_DIR/init"
    fi
fi

# Set executable permissions
chmod +x "$ROOTFS_DIR/init"
chmod +x "$ROOTFS_DIR/usr/local/bin/nucleus-tool-proxy"
chmod +x "$ROOTFS_DIR/usr/local/bin/nucleus-net-probe"
chmod +x "$ROOTFS_DIR/usr/local/bin/nucleus-workload-probe"
chmod +x "$ROOTFS_DIR/usr/local/bin/nucleus-egress-probe"
[ -f "$ROOTFS_DIR/usr/local/bin/nucleus-adversary-probe" ] && chmod +x "$ROOTFS_DIR/usr/local/bin/nucleus-adversary-probe"
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
for bin in init usr/local/bin/nucleus-tool-proxy usr/local/bin/nucleus-net-probe usr/local/bin/nucleus-workload-probe usr/local/bin/nucleus-egress-probe usr/local/bin/nucleus-adversary-probe; do
    if [ -f "$ROOTFS_DIR/$bin" ]; then
        size=$(du -h "$ROOTFS_DIR/$bin" | cut -f1)
        echo "  /$bin ($size)"
    fi
done
