#!/usr/bin/env bash
# Nucleus Claude Code Hook — One-Line Installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/coproduct-opensource/nucleus/main/scripts/install-hook.sh | bash
#
# What it does (in ~10 seconds):
#   1. Downloads pre-built nucleus-claude-hook binary
#   2. Installs to ~/.local/bin/
#   3. Configures Claude Code settings.json
#   4. Done — restart Claude Code to activate
#
# Environment variables:
#   NUCLEUS_VERSION   - Version to install (default: latest)
#   NUCLEUS_PROFILE   - Permission profile (default: develop)
#   INSTALL_DIR       - Binary install location (default: ~/.local/bin)
#
set -euo pipefail

GITHUB_REPO="coproduct-opensource/nucleus"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"
BINARY_NAME="nucleus-claude-hook"

# Colors (skip if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BOLD='' DIM='' NC=''
fi

info()  { echo -e "${GREEN}>${NC} $1"; }
warn()  { echo -e "${YELLOW}>${NC} $1"; }
error() { echo -e "${RED}>${NC} $1" >&2; }
step()  { echo -e "${BOLD}$1${NC}"; }

# Detect platform
detect_platform() {
    local os arch
    os=$(uname -s)
    arch=$(uname -m)

    case "$os" in
        Darwin)
            case "$arch" in
                arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
                x86_64)        TARGET="x86_64-apple-darwin" ;;
                *)             error "Unsupported architecture: $arch"; exit 1 ;;
            esac
            ;;
        Linux)
            case "$arch" in
                x86_64)        TARGET="x86_64-unknown-linux-musl" ;;
                aarch64)       TARGET="aarch64-unknown-linux-musl" ;;
                *)             error "Unsupported architecture: $arch"; exit 1 ;;
            esac
            ;;
        *)
            error "Unsupported OS: $os (need macOS or Linux)"
            exit 1
            ;;
    esac

    info "Platform: ${os} ${arch} (${TARGET})"
}

# Get latest release version
get_version() {
    if [ -n "${NUCLEUS_VERSION:-}" ]; then
        VERSION="$NUCLEUS_VERSION"
    else
        VERSION=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
            | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [ -z "$VERSION" ]; then
            error "Failed to fetch latest version. Set NUCLEUS_VERSION=v0.x.y"
            exit 1
        fi
    fi
    VERSION_NUM="${VERSION#v}"
    info "Version: ${VERSION}"
}

# Download and install binary
install_binary() {
    local url artifact tmp
    artifact="${BINARY_NAME}-${VERSION_NUM}-${TARGET}.tar.gz"
    url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${artifact}"
    tmp=$(mktemp -d)

    step "Downloading ${BINARY_NAME}..."
    if ! curl -fsSL "$url" -o "${tmp}/${artifact}"; then
        error "Download failed. Check that ${VERSION} has pre-built binaries."
        error "URL: ${url}"
        error ""
        error "Fallback: install from source with:"
        error "  cargo install --git https://github.com/${GITHUB_REPO} ${BINARY_NAME}"
        rm -rf "$tmp"
        exit 1
    fi

    mkdir -p "$INSTALL_DIR"
    tar -xzf "${tmp}/${artifact}" -C "$tmp"
    mv "${tmp}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    rm -rf "$tmp"

    info "Installed: ${INSTALL_DIR}/${BINARY_NAME}"

    # Ensure INSTALL_DIR is in PATH
    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
        warn "${INSTALL_DIR} is not in your PATH"
        warn "Add to your shell profile:"
        warn "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    fi
}

# Configure Claude Code settings.json
configure_claude_code() {
    local settings_dir settings_file profile binary_path

    # Find Claude Code settings
    if [ -d "${HOME}/.claude" ]; then
        settings_dir="${HOME}/.claude"
    else
        settings_dir="${HOME}/.claude"
        mkdir -p "$settings_dir"
    fi
    settings_file="${settings_dir}/settings.json"
    binary_path="${INSTALL_DIR}/${BINARY_NAME}"
    profile="${NUCLEUS_PROFILE:-develop}"

    step "Configuring Claude Code..."

    # Check if settings.json exists
    if [ -f "$settings_file" ]; then
        # Check if hook is already configured
        if grep -q "nucleus-claude-hook" "$settings_file" 2>/dev/null; then
            info "Hook already configured in ${settings_file}"
            info "Updating binary path..."
        fi
    fi

    # Use Python/Node to safely modify JSON (available on macOS and most Linux)
    if command -v python3 &>/dev/null; then
        python3 - "$settings_file" "$binary_path" "$profile" <<'PYEOF'
import json, sys, os

settings_file = sys.argv[1]
binary_path = sys.argv[2]
profile = sys.argv[3]

# Load existing settings or create new
if os.path.exists(settings_file):
    with open(settings_file) as f:
        settings = json.load(f)
else:
    settings = {}

# Set up hook command
if profile != "develop":
    command = f"NUCLEUS_PROFILE={profile} {binary_path}"
else:
    command = binary_path

# Configure PreToolUse hook
settings.setdefault("hooks", {})
settings["hooks"]["PreToolUse"] = [
    {
        "matcher": "",
        "hooks": [
            {
                "type": "command",
                "command": command
            }
        ]
    }
]

with open(settings_file, 'w') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')

PYEOF
        info "Configured hook in ${settings_file}"
        info "Profile: ${profile}"
    else
        warn "python3 not found — manual setup required:"
        warn "  ${binary_path} --setup"
    fi
}

# Print success
print_success() {
    echo ""
    echo -e "${GREEN}${BOLD}Nucleus Claude Code Hook installed!${NC}"
    echo ""
    echo "  Restart Claude Code to activate the hook."
    echo ""
    echo "  The hook will:"
    echo "    - Track information flow across tool calls"
    echo "    - Block writes after web content taints the session"
    echo "    - Produce signed receipts for every security decision"
    echo ""
    echo -e "  ${DIM}Profile: ${NUCLEUS_PROFILE:-develop}${NC}"
    echo -e "  ${DIM}Binary:  ${INSTALL_DIR}/${BINARY_NAME}${NC}"
    echo -e "  ${DIM}Config:  ~/.claude/settings.json${NC}"
    echo ""
    echo "  Profiles:  nucleus-claude-hook --help"
    echo "  Status:    nucleus-claude-hook --status"
    echo "  Uninstall: rm ${INSTALL_DIR}/${BINARY_NAME}"
    echo ""
}

main() {
    echo ""
    echo -e "${BOLD}Nucleus Claude Code Hook Installer${NC}"
    echo ""

    detect_platform
    get_version
    install_binary
    configure_claude_code
    print_success
}

main "$@"
