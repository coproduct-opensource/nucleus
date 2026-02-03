#!/usr/bin/env bash
# Nucleus One-Line Installer for macOS
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/coproduct-opensource/nucleus/main/scripts/install.sh | bash
#
# Environment variables:
#   NUCLEUS_VERSION    - Version to install (default: latest)
#   NUCLEUS_NO_MODIFY_PATH - Set to 1 to skip PATH modification
#   NUCLEUS_SKIP_VM    - Set to 1 to skip Lima VM setup
#
set -euo pipefail

# Configuration
GITHUB_REPO="coproduct-opensource/nucleus"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${HOME}/.config/nucleus"
ARTIFACTS_DIR="${CONFIG_DIR}/artifacts"
LIMA_VM_NAME="nucleus"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} ${BOLD}$1${NC}"; }

# Detect platform
detect_platform() {
    local os arch chip macos_version

    os=$(uname -s)
    if [ "$os" != "Darwin" ]; then
        log_error "This installer is for macOS only. Detected: $os"
        log_info "For Linux, install nucleus-node directly from GitHub releases."
        exit 1
    fi

    arch=$(uname -m)
    case "$arch" in
        arm64|aarch64)
            ARCH="aarch64"
            TARGET="aarch64-apple-darwin"
            LINUX_TARGET="aarch64-unknown-linux-musl"
            ;;
        x86_64)
            ARCH="x86_64"
            TARGET="x86_64-apple-darwin"
            LINUX_TARGET="x86_64-unknown-linux-musl"
            ;;
        *)
            log_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac

    # Get macOS version
    macos_version=$(sw_vers -productVersion)
    MACOS_MAJOR=$(echo "$macos_version" | cut -d. -f1)

    # Detect Apple chip for nested virt support
    if [ "$ARCH" = "aarch64" ]; then
        chip=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown")
        if [[ "$chip" == *"M3"* ]] || [[ "$chip" == *"M4"* ]]; then
            CHIP_SERIES="M3/M4"
            NESTED_VIRT_SUPPORTED=true
        elif [[ "$chip" == *"M1"* ]] || [[ "$chip" == *"M2"* ]]; then
            CHIP_SERIES="M1/M2"
            NESTED_VIRT_SUPPORTED=false
        else
            CHIP_SERIES="Apple Silicon"
            NESTED_VIRT_SUPPORTED=false
        fi
    else
        CHIP_SERIES="Intel"
        NESTED_VIRT_SUPPORTED=false
    fi

    log_info "Detected: macOS $macos_version ($ARCH) - $CHIP_SERIES"

    # Warn about nested virt
    if [ "$NESTED_VIRT_SUPPORTED" = true ] && [ "$MACOS_MAJOR" -ge 15 ]; then
        log_info "Hardware-accelerated Firecracker supported (M3/M4 + macOS 15+)"
    elif [ "$ARCH" = "aarch64" ]; then
        log_warn "Firecracker will use emulation (slower). For best performance:"
        log_warn "  - Use M3/M4 Mac with macOS 15 (Sequoia)"
    else
        log_warn "Intel Mac detected. Firecracker will use QEMU emulation (slowest)."
    fi
}

# Check and install prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."

    # Check for Homebrew
    if ! command -v brew &>/dev/null; then
        log_error "Homebrew is required but not installed."
        log_info "Install Homebrew: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        exit 1
    fi

    # Check/install Lima
    if ! command -v limactl &>/dev/null; then
        log_info "Installing Lima..."
        brew install lima
    else
        # Check Lima version
        lima_version=$(limactl --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        lima_major=$(echo "$lima_version" | cut -d. -f1)
        if [ "$lima_major" -lt 2 ]; then
            log_warn "Lima $lima_version detected. Upgrading to Lima 2.0+ for nested virt support..."
            brew upgrade lima
        else
            log_info "Lima $lima_version OK"
        fi
    fi

    # Check for curl
    if ! command -v curl &>/dev/null; then
        log_error "curl is required but not installed."
        exit 1
    fi
}

# Get latest release version
get_latest_version() {
    if [ -n "${NUCLEUS_VERSION:-}" ]; then
        VERSION="$NUCLEUS_VERSION"
        log_info "Using specified version: $VERSION"
    else
        log_info "Fetching latest release..."
        VERSION=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | \
            grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [ -z "$VERSION" ]; then
            log_error "Failed to fetch latest version. Set NUCLEUS_VERSION manually."
            exit 1
        fi
        log_info "Latest version: $VERSION"
    fi
    # Strip 'v' prefix if present for artifact names
    VERSION_NUM="${VERSION#v}"
}

# Download release artifacts
download_artifacts() {
    log_step "Downloading nucleus artifacts..."

    mkdir -p "$ARTIFACTS_DIR"
    local base_url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}"

    # Download CLI binary for macOS
    local cli_artifact="nucleus-cli-${VERSION_NUM}-${TARGET}.tar.gz"
    log_info "Downloading CLI: $cli_artifact"
    if ! curl -fsSL "${base_url}/${cli_artifact}" -o "/tmp/${cli_artifact}" 2>/dev/null; then
        # Fallback: try nucleus-node artifact naming
        cli_artifact="nucleus-node-${VERSION_NUM}-${TARGET}.tar.gz"
        log_info "Trying alternate name: $cli_artifact"
        curl -fsSL "${base_url}/${cli_artifact}" -o "/tmp/${cli_artifact}"
    fi
    tar -xzf "/tmp/${cli_artifact}" -C /tmp

    # Install CLI
    if [ -f /tmp/nucleus ]; then
        sudo mv /tmp/nucleus "$INSTALL_DIR/nucleus"
    elif [ -f /tmp/nucleus-node ]; then
        # nucleus-node can also serve as CLI for now
        sudo mv /tmp/nucleus-node "$INSTALL_DIR/nucleus"
    fi
    sudo chmod +x "$INSTALL_DIR/nucleus"
    log_info "Installed: $INSTALL_DIR/nucleus"

    # Download nucleus-node for Linux (to run in Lima VM)
    local node_artifact="nucleus-node-${VERSION_NUM}-${LINUX_TARGET}.tar.gz"
    log_info "Downloading node binary: $node_artifact"
    if curl -fsSL "${base_url}/${node_artifact}" -o "/tmp/${node_artifact}" 2>/dev/null; then
        tar -xzf "/tmp/${node_artifact}" -C "$ARTIFACTS_DIR"
        log_info "Downloaded: $ARTIFACTS_DIR/nucleus-node"
    else
        log_warn "nucleus-node for Linux not found in release. Will need to build from source."
    fi

    # Download pre-built rootfs (if available)
    local rootfs_artifact="nucleus-rootfs-${VERSION_NUM}-${ARCH}.ext4.gz"
    log_info "Downloading rootfs: $rootfs_artifact"
    if curl -fsSL "${base_url}/${rootfs_artifact}" -o "/tmp/${rootfs_artifact}" 2>/dev/null; then
        gunzip -c "/tmp/${rootfs_artifact}" > "$ARTIFACTS_DIR/rootfs.ext4"
        log_info "Downloaded: $ARTIFACTS_DIR/rootfs.ext4"
    else
        log_warn "Pre-built rootfs not found. Will need to build with scripts/firecracker/build-rootfs.sh"
    fi

    # Clean up
    rm -f /tmp/nucleus-*.tar.gz /tmp/nucleus-rootfs-*.ext4.gz
}

# Setup Lima VM
setup_lima_vm() {
    if [ "${NUCLEUS_SKIP_VM:-}" = "1" ]; then
        log_info "Skipping Lima VM setup (NUCLEUS_SKIP_VM=1)"
        return
    fi

    log_step "Setting up Lima VM..."

    # Check if VM already exists
    if limactl list -q 2>/dev/null | grep -q "^${LIMA_VM_NAME}$"; then
        log_info "Lima VM '${LIMA_VM_NAME}' already exists"

        # Check if running
        if limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | grep -q "^${LIMA_VM_NAME} Running"; then
            log_info "VM is already running"
        else
            log_info "Starting VM..."
            limactl start "$LIMA_VM_NAME"
        fi
    else
        # Download Lima template
        local template_url="https://raw.githubusercontent.com/${GITHUB_REPO}/main/scripts/lima/nucleus-${ARCH}.yaml"
        log_info "Downloading Lima template..."
        curl -fsSL "$template_url" -o "/tmp/nucleus-lima.yaml"

        # Create and start VM
        log_info "Creating Lima VM (this may take a few minutes)..."
        limactl create --name "$LIMA_VM_NAME" "/tmp/nucleus-lima.yaml"
        limactl start "$LIMA_VM_NAME"
        rm -f /tmp/nucleus-lima.yaml
    fi

    # Copy artifacts to VM
    if [ -f "$ARTIFACTS_DIR/nucleus-node" ]; then
        log_info "Installing nucleus-node in VM..."
        limactl cp "$ARTIFACTS_DIR/nucleus-node" "${LIMA_VM_NAME}:/tmp/nucleus-node"
        limactl shell "$LIMA_VM_NAME" -- sudo mv /tmp/nucleus-node /usr/local/bin/nucleus-node
        limactl shell "$LIMA_VM_NAME" -- sudo chmod +x /usr/local/bin/nucleus-node
    fi

    if [ -f "$ARTIFACTS_DIR/rootfs.ext4" ]; then
        log_info "Installing rootfs in VM..."
        limactl cp "$ARTIFACTS_DIR/rootfs.ext4" "${LIMA_VM_NAME}:/tmp/rootfs.ext4"
        limactl shell "$LIMA_VM_NAME" -- sudo mv /tmp/rootfs.ext4 /var/lib/nucleus/artifacts/rootfs.ext4
    fi

    # Verify KVM support
    log_info "Checking KVM support in VM..."
    if limactl shell "$LIMA_VM_NAME" -- test -c /dev/kvm 2>/dev/null; then
        log_info "KVM available - hardware-accelerated Firecracker!"
    else
        log_warn "KVM not available - Firecracker will use emulation (slower)"
    fi
}

# Setup secrets in macOS Keychain
setup_secrets() {
    log_step "Setting up secrets..."

    # Check if secrets already exist
    if security find-generic-password -s nucleus-auth -w &>/dev/null; then
        log_info "Secrets already configured in Keychain"
        return
    fi

    # Generate random secrets
    local auth_secret approval_secret
    auth_secret=$(openssl rand -hex 32)
    approval_secret=$(openssl rand -hex 32)

    # Store in Keychain
    security add-generic-password -a "$USER" -s nucleus-auth -w "$auth_secret" -U
    security add-generic-password -a "$USER" -s nucleus-approval -w "$approval_secret" -U

    log_info "Secrets stored in macOS Keychain"
}

# Create config file
setup_config() {
    log_step "Setting up configuration..."

    mkdir -p "$CONFIG_DIR"

    if [ ! -f "$CONFIG_DIR/config.toml" ]; then
        cat > "$CONFIG_DIR/config.toml" <<EOF
# Nucleus configuration
# Generated by install.sh

[vm]
name = "$LIMA_VM_NAME"
auto_start = true
cpus = 4
memory_gib = 8

[node]
url = "http://127.0.0.1:8080"
metrics_url = "http://127.0.0.1:9080"

[budget]
max_cost_usd = 5.0
max_input_tokens = 100000
max_output_tokens = 10000
EOF
        log_info "Created: $CONFIG_DIR/config.toml"
    else
        log_info "Config already exists: $CONFIG_DIR/config.toml"
    fi
}

# Verify installation
verify_installation() {
    log_step "Verifying installation..."

    local errors=0

    # Check CLI
    if command -v nucleus &>/dev/null; then
        log_info "CLI: $(nucleus --version 2>/dev/null || echo 'installed')"
    else
        log_error "CLI not found in PATH"
        errors=$((errors + 1))
    fi

    # Check Lima VM
    if [ "${NUCLEUS_SKIP_VM:-}" != "1" ]; then
        if limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | grep -q "^${LIMA_VM_NAME} Running"; then
            log_info "Lima VM: running"
        else
            log_warn "Lima VM: not running"
        fi
    fi

    # Check config
    if [ -f "$CONFIG_DIR/config.toml" ]; then
        log_info "Config: $CONFIG_DIR/config.toml"
    fi

    return $errors
}

# Print success message
print_success() {
    echo ""
    echo -e "${GREEN}${BOLD}Nucleus installed successfully!${NC}"
    echo ""
    echo "Quick start:"
    echo "  nucleus doctor          # Check system status"
    echo "  nucleus start           # Start nucleus-node"
    echo "  nucleus run 'uname -a'  # Run a command in a microVM"
    echo ""
    echo "Documentation: https://github.com/${GITHUB_REPO}#readme"
    echo ""

    if [ "$NESTED_VIRT_SUPPORTED" = true ] && [ "$MACOS_MAJOR" -ge 15 ]; then
        echo -e "${GREEN}You have hardware-accelerated Firecracker support!${NC}"
    fi
}

# Main
main() {
    echo ""
    echo -e "${BOLD}Nucleus Installer${NC}"
    echo "=================="
    echo ""

    detect_platform
    check_prerequisites
    get_latest_version
    download_artifacts
    setup_lima_vm
    setup_secrets
    setup_config
    verify_installation
    print_success
}

main "$@"
