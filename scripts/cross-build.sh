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

# Packages to build for rootfs
ROOTFS_PACKAGES=(
    "nucleus-guest-init"
    "nucleus-tool-proxy"
    "nucleus-net-probe"
)

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
