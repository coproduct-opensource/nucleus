#!/usr/bin/env bash
# Cross-compile nucleus binaries for Firecracker rootfs
# Builds static musl binaries for aarch64 and x86_64 Linux
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

# Default to both architectures
ARCH="${ARCH:-all}"
# Use 'cross' tool by default, fall back to 'cargo' if cross isn't available
USE_CROSS="${USE_CROSS:-auto}"

# Packages to build for the rootfs — DERIVED, never hand-listed.
#
# This used to be a literal array, and it was missing nucleus-adversary-probe
# (#2377). build-rootfs.sh only hard-requires five of the seven binaries and
# copies the rest with `[ -f ]`, so a rootfs built from the short list came out
# exit-0 and simply had no adversary probe in it. build-rootfs.sh even points
# users HERE ("Build with: scripts/cross-build.sh --arch $ARCH") four separate
# times, so following the instructions produced the broken image.
#
# That is #2366 in the local path: release.yml had the same two-lists-in-two-
# files shape and shipped a v2.1.0 rootfs with no egress probe.
#
# So there is now ONE list. build-rootfs.sh's `*_BIN` defaults name every binary
# the rootfs wants, and both this script and ci/release-builds-rootfs-inputs.sh
# read that same expression. Adding a probe to build-rootfs.sh is now sufficient;
# nothing here has to be remembered.
ROOTFS_SH="$ROOT_DIR/scripts/firecracker/build-rootfs.sh"
if [ ! -f "$ROOTFS_SH" ]; then
    echo "cross-build: cannot find $ROOTFS_SH to derive the package list from" >&2
    exit 1
fi

# Read into the array with a while-read loop, NOT `mapfile`: mapfile is a bash 4
# builtin and macOS ships bash 3.2, so `mapfile` would fail on exactly the local
# build path this issue is about.
ROOTFS_PACKAGES=()
while IFS= read -r pkg; do
    [ -n "$pkg" ] && ROOTFS_PACKAGES+=("$pkg")
done < <(grep -oE 'release/nucleus-[a-z-]+' "$ROOTFS_SH" | sed 's|release/||' | sort -u)

# Non-vacuity. An empty or tiny list would make this script "succeed" while
# building nothing — the same silent shape the derivation exists to remove.
if [ "${#ROOTFS_PACKAGES[@]}" -lt 5 ]; then
    echo "cross-build: derived only ${#ROOTFS_PACKAGES[@]} package(s) from $ROOTFS_SH;" >&2
    echo "  the parse is broken rather than the rootfs having shrunk." >&2
    exit 1
fi

# `--list-packages` exists so the CI gate can compare what this script WOULD
# build against what the rootfs needs, rather than pattern-matching the source.
if [ "${1:-}" = "--list-packages" ]; then
    printf '%s\n' "${ROOTFS_PACKAGES[@]}"
    exit 0
fi

# Targets
AARCH64_TARGET="aarch64-unknown-linux-musl"
X86_64_TARGET="x86_64-unknown-linux-musl"

# Colors (if terminal supports it)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

detect_build_tool() {
    if [ "$USE_CROSS" = "cross" ]; then
        if command -v cross &>/dev/null; then
            echo "cross"
        else
            log_error "cross not found. Install with: cargo install cross"
            exit 1
        fi
    elif [ "$USE_CROSS" = "cargo" ]; then
        echo "cargo"
    else
        # Auto-detect
        if command -v cross &>/dev/null; then
            echo "cross"
        else
            log_warn "cross not found, falling back to cargo (may require musl toolchain)"
            echo "cargo"
        fi
    fi
}

build_target() {
    local target="$1"
    local tool="$2"

    log_info "Building for target: $target using $tool"

    for package in "${ROOTFS_PACKAGES[@]}"; do
        log_info "  Building $package..."
        $tool build --release --target "$target" -p "$package"
    done

    # Show built binaries
    log_info "Built binaries for $target:"
    for package in "${ROOTFS_PACKAGES[@]}"; do
        local bin_name
        bin_name=$(echo "$package" | tr '-' '_')
        # Handle binary name variations
        local bin_path="target/$target/release/$package"
        if [ -f "$bin_path" ]; then
            local size
            size=$(du -h "$bin_path" | cut -f1)
            log_info "    $bin_path ($size)"
        fi
    done
}

verify_binaries() {
    local target="$1"
    local missing=0

    for package in "${ROOTFS_PACKAGES[@]}"; do
        local bin_path="target/$target/release/$package"
        if [ ! -f "$bin_path" ]; then
            log_error "Missing: $bin_path"
            missing=1
        fi
    done

    return $missing
}

print_usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Cross-compile nucleus binaries for Firecracker rootfs.

Options:
    --arch ARCH     Architecture to build: aarch64, x86_64, or all (default: all)
    --cross         Force use of 'cross' tool
    --cargo         Force use of 'cargo' (requires musl toolchain)
    --verify        Only verify that binaries exist
    -h, --help      Show this help message

Examples:
    # Build for both architectures (default)
    $(basename "$0")

    # Build only for Apple Silicon (aarch64)
    $(basename "$0") --arch aarch64

    # Build only for Intel (x86_64)
    $(basename "$0") --arch x86_64

    # Verify binaries exist
    $(basename "$0") --verify
EOF
}

VERIFY_ONLY=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --cross)
            USE_CROSS="cross"
            shift
            ;;
        --cargo)
            USE_CROSS="cargo"
            shift
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
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

if [ "$VERIFY_ONLY" = true ]; then
    exit_code=0
    if [ "$ARCH" = "all" ] || [ "$ARCH" = "aarch64" ]; then
        log_info "Verifying aarch64 binaries..."
        if ! verify_binaries "$AARCH64_TARGET"; then
            exit_code=1
        fi
    fi
    if [ "$ARCH" = "all" ] || [ "$ARCH" = "x86_64" ]; then
        log_info "Verifying x86_64 binaries..."
        if ! verify_binaries "$X86_64_TARGET"; then
            exit_code=1
        fi
    fi
    exit $exit_code
fi

BUILD_TOOL=$(detect_build_tool)
log_info "Using build tool: $BUILD_TOOL"

case "$ARCH" in
    all)
        build_target "$AARCH64_TARGET" "$BUILD_TOOL"
        build_target "$X86_64_TARGET" "$BUILD_TOOL"
        ;;
    aarch64)
        build_target "$AARCH64_TARGET" "$BUILD_TOOL"
        ;;
    x86_64)
        build_target "$X86_64_TARGET" "$BUILD_TOOL"
        ;;
    *)
        log_error "Unknown architecture: $ARCH"
        print_usage
        exit 1
        ;;
esac

log_info "Build complete!"
log_info ""
log_info "Next steps:"
log_info "  1. Build rootfs: scripts/firecracker/build-rootfs.sh --arch $ARCH"
log_info "  2. Run setup:    nucleus setup"
