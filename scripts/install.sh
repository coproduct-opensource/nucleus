#!/usr/bin/env bash
# Nucleus one-line installer for macOS.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/coproduct-opensource/nucleus/main/scripts/install.sh | bash
#
# Environment variables:
#   NUCLEUS_VERSION         - Version to install (default: latest release)
#   NUCLEUS_NO_MODIFY_PATH  - Set to 1 to skip PATH modification
#   NUCLEUS_SKIP_SETUP      - Set to 1 to install the binary and stop
#
# WHAT THIS SCRIPT DOES, AND WHY IT IS SHORT NOW
#
# It installs the `nucleus` binary and then runs `nucleus setup`. That is all.
#
# It used to be a second, independent provisioner: it created its own Lima VM
# from a downloaded template, downloaded its own rootfs and node binary, and
# copied them into the VM its own way — while `nucleus setup` did the same job
# differently and the checked-in Lima templates did it a third way. The three
# disagreed on the Firecracker version, the kernel URL, the gRPC port and the
# artifacts directory; the template's kernel URL had been returning HTTP 404 for
# an unknown length of time, and nothing noticed because nothing in CI booted a
# microVM.
#
# Provisioning lives in one place now — `nucleus setup`, which installs
# everything from the digests pinned in `nucleus_spec::tier2_artifacts` and
# finishes by booting a real pod. An installer that reimplemented any of that
# would simply be the fourth answer.
set -euo pipefail

GITHUB_REPO="coproduct-opensource/nucleus"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Scratch directory for the downloaded tarball, cleaned up on EXIT rather than
# on RETURN from the function that creates it.
#
# It was a `trap 'rm -rf "$tmp"' RETURN` on a `local tmp` inside `install_cli`.
# A RETURN trap is not scoped to the function that set it: it stayed armed and
# fired again when `main` returned, by which point `tmp` was out of scope, and
# `set -u` turned that into `tmp: unbound variable` and exit 1 — AFTER the
# install and the pod boot had both fully succeeded. The advertised one-liner
# therefore reported failure on every successful run.
#
# EXIT also covers the `exit 1` error paths inside `install_cli`, which the
# RETURN trap never reached.
CLI_TMP=""
cleanup() {
    if [ -n "$CLI_TMP" ]; then
        rm -rf "$CLI_TMP"
    fi
}
trap cleanup EXIT

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

detect_platform() {
    local os arch
    os=$(uname -s)
    if [ "$os" != "Darwin" ]; then
        log_error "This installer is for macOS. Detected: $os"
        log_info "On Linux, download nucleus-cli from the releases page and run: nucleus setup"
        exit 1
    fi

    arch=$(uname -m)
    case "$arch" in
        arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
        x86_64)        TARGET="x86_64-apple-darwin" ;;
        *) log_error "Unsupported architecture: $arch"; exit 1 ;;
    esac
    log_info "Platform: macOS ${arch}"
}

check_prerequisites() {
    command -v curl >/dev/null || { log_error "curl is required."; exit 1; }
    command -v tar  >/dev/null || { log_error "tar is required."; exit 1; }

    # Lima is NOT installed here. `nucleus setup --install-deps` does it on
    # explicit request; installing software on someone's machine unasked is not
    # this script's call to make, and duplicating the logic would be a second
    # answer to a question that already has one.
    if ! command -v limactl >/dev/null; then
        log_warn "Lima is not installed. Tier 2 needs it."
        log_warn "  brew install lima     (or: nucleus setup --install-deps)"
    fi
}

resolve_version() {
    if [ -n "${NUCLEUS_VERSION:-}" ]; then
        VERSION="${NUCLEUS_VERSION#v}"
    else
        VERSION=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" |
                  grep '"tag_name"' | head -1 | sed -E 's/.*"v?([^"]+)".*/\1/')
    fi
    [ -n "$VERSION" ] || { log_error "Could not determine the latest version."; exit 1; }
    log_info "Version: ${VERSION}"
}

install_cli() {
    local asset url
    asset="nucleus-cli-${VERSION}-${TARGET}.tar.gz"
    url="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/${asset}"
    CLI_TMP=$(mktemp -d)

    log_step "Downloading ${asset}"
    curl -fsSL "$url" -o "${CLI_TMP}/${asset}" ||
        { log_error "Download failed: ${url}"; exit 1; }
    tar -xzf "${CLI_TMP}/${asset}" -C "$CLI_TMP"
    [ -f "${CLI_TMP}/nucleus" ] || { log_error "${asset} does not contain a 'nucleus' binary."; exit 1; }

    log_step "Installing to ${INSTALL_DIR}/nucleus"
    if [ -w "$INSTALL_DIR" ]; then
        mv "${CLI_TMP}/nucleus" "${INSTALL_DIR}/nucleus"
    else
        sudo mv "${CLI_TMP}/nucleus" "${INSTALL_DIR}/nucleus"
    fi
    chmod +x "${INSTALL_DIR}/nucleus" 2>/dev/null || sudo chmod +x "${INSTALL_DIR}/nucleus"
}

maybe_modify_path() {
    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*) return ;;
    esac
    if [ "${NUCLEUS_NO_MODIFY_PATH:-0}" = "1" ]; then
        log_warn "${INSTALL_DIR} is not on your PATH; add it yourself."
        return
    fi
    local rc="${HOME}/.zshrc"
    [ -n "${BASH_VERSION:-}" ] && rc="${HOME}/.bashrc"
    echo "export PATH=\"${INSTALL_DIR}:\$PATH\"" >> "$rc"
    log_info "Added ${INSTALL_DIR} to PATH in ${rc}; open a new shell to pick it up."
}

main() {
    echo
    echo "Nucleus installer"
    echo "================="
    echo

    detect_platform
    check_prerequisites
    resolve_version
    install_cli
    maybe_modify_path

    if [ "${NUCLEUS_SKIP_SETUP:-0}" = "1" ]; then
        log_info "Binary installed. Next: nucleus setup"
        return
    fi

    log_step "Running nucleus setup"
    echo
    # `setup` installs Firecracker, the kernel, the rootfs, nucleus-node and its
    # secrets, then boots a real pod to prove Tier 2 works. If that last step
    # fails, so does this script — reporting success on a machine where no pod
    # can boot is the exact failure this rewrite exists to remove.
    "${INSTALL_DIR}/nucleus" setup
}

main "$@"
