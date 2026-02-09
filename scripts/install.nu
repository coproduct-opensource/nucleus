#!/usr/bin/env nu
# Nucleus One-Line Installer for macOS
#
# Usage:
#   nu install.nu
#
# Environment variables:
#   NUCLEUS_VERSION    - Version to install (default: latest)
#   NUCLEUS_NO_MODIFY_PATH - Set to 1 to skip PATH modification
#   NUCLEUS_SKIP_VM    - Set to 1 to skip Lima VM setup

const GITHUB_REPO = "coproduct-opensource/nucleus"
const LIMA_VM_NAME = "nucleus"

def log-info [msg: string] {
    print $"(ansi green)[INFO](ansi reset) ($msg)"
}

def log-warn [msg: string] {
    print -e $"(ansi yellow)[WARN](ansi reset) ($msg)"
}

def log-error [msg: string] {
    print -e $"(ansi red)[ERROR](ansi reset) ($msg)"
}

def log-step [msg: string] {
    print $"(ansi blue)[STEP](ansi reset) (ansi bold)($msg)(ansi reset)"
}

def require [cmd: string] {
    if (which $cmd | is-empty) {
        log-error $"($cmd) is required but not installed."
        exit 1
    }
}

# Detect platform, return record with arch info
def detect-platform [] {
    let os = (^uname -s | str trim)
    if $os != "Darwin" {
        log-error $"This installer is for macOS only. Detected: ($os)"
        log-info "For Linux, install nucleus-node directly from GitHub releases."
        exit 1
    }

    let host_arch = (^uname -m | str trim)
    let arch_info = match $host_arch {
        "arm64" | "aarch64" => {
            { arch: "aarch64", target: "aarch64-apple-darwin", linux_target: "aarch64-unknown-linux-musl" }
        }
        "x86_64" => {
            { arch: "x86_64", target: "x86_64-apple-darwin", linux_target: "x86_64-unknown-linux-musl" }
        }
        _ => {
            log-error $"Unsupported architecture: ($host_arch)"
            exit 1
        }
    }

    let macos_version = (^sw_vers -productVersion | str trim)
    let macos_major = ($macos_version | split row "." | first | into int)

    # Detect chip series for nested virt support
    mut chip_series = "Intel"
    mut nested_virt = false

    if $arch_info.arch == "aarch64" {
        let chip = (do { ^sysctl -n machdep.cpu.brand_string } | complete)
        let chip_name = if $chip.exit_code == 0 { $chip.stdout | str trim } else { "Unknown" }

        if ($chip_name | str contains "M3") or ($chip_name | str contains "M4") {
            $chip_series = "M3/M4"
            $nested_virt = true
        } else if ($chip_name | str contains "M1") or ($chip_name | str contains "M2") {
            $chip_series = "M1/M2"
        } else {
            $chip_series = "Apple Silicon"
        }
    }

    log-info $"Detected: macOS ($macos_version) \(($arch_info.arch)\) - ($chip_series)"

    if $nested_virt and $macos_major >= 15 {
        log-info "Hardware-accelerated Firecracker supported (M3/M4 + macOS 15+)"
    } else if $arch_info.arch == "aarch64" {
        log-warn "Firecracker will use emulation (slower). For best performance:"
        log-warn "  - Use M3/M4 Mac with macOS 15 (Sequoia)"
    } else {
        log-warn "Intel Mac detected. Firecracker will use QEMU emulation (slowest)."
    }

    {
        arch: $arch_info.arch
        target: $arch_info.target
        linux_target: $arch_info.linux_target
        macos_major: $macos_major
        chip_series: $chip_series
        nested_virt: $nested_virt
    }
}

def check-prerequisites [] {
    log-step "Checking prerequisites..."

    require "brew"

    if (which limactl | is-empty) {
        log-info "Installing Lima..."
        ^brew install lima
    } else {
        let lima_ver = (do { ^limactl --version } | complete)
        let version_str = ($lima_ver.stdout | parse --regex '(\d+\.\d+\.\d+)' | get -o 0.capture0 | default "0.0.0")
        let major = ($version_str | split row "." | first | into int)

        if $major < 2 {
            log-warn $"Lima ($version_str) detected. Upgrading to Lima 2.0+ for nested virt support..."
            ^brew upgrade lima
        } else {
            log-info $"Lima ($version_str) OK"
        }
    }

    require "curl"
}

def get-latest-version [] {
    let specified = ($env.NUCLEUS_VERSION? | default "")
    if ($specified | is-not-empty) {
        log-info $"Using specified version: ($specified)"
        return { version: $specified, version_num: ($specified | str replace -r '^v' '') }
    }

    log-info "Fetching latest release..."
    let result = (do { ^curl -fsSL $"https://api.github.com/repos/($GITHUB_REPO)/releases/latest" } | complete)

    if $result.exit_code != 0 {
        log-error "Failed to fetch latest version. Set NUCLEUS_VERSION manually."
        exit 1
    }

    let version = ($result.stdout | from json | get tag_name)
    log-info $"Latest version: ($version)"
    { version: $version, version_num: ($version | str replace -r '^v' '') }
}

def download-artifacts [platform: record, ver: record] {
    log-step "Downloading nucleus artifacts..."

    let install_dir = ($env.INSTALL_DIR? | default "/usr/local/bin")
    let config_dir = $"($env.HOME)/.config/nucleus"
    let artifacts_dir = $"($config_dir)/artifacts"
    mkdir $artifacts_dir

    let base_url = $"https://github.com/($GITHUB_REPO)/releases/download/($ver.version)"

    # Download CLI binary for macOS — try nucleus-cli first, then nucleus-node
    let cli_name = $"nucleus-cli-($ver.version_num)-($platform.target).tar.gz"
    let node_name = $"nucleus-node-($ver.version_num)-($platform.target).tar.gz"
    log-info $"Downloading CLI: ($cli_name)"

    let cli_result = (do { ^curl -fsSL $"($base_url)/($cli_name)" -o $"/tmp/($cli_name)" } | complete)
    let cli_artifact = if $cli_result.exit_code != 0 {
        log-info $"Trying alternate name: ($node_name)"
        ^curl -fsSL $"($base_url)/($node_name)" -o $"/tmp/($node_name)"
        $node_name
    } else {
        $cli_name
    }
    ^tar -xzf $"/tmp/($cli_artifact)" -C /tmp

    # Install CLI
    if ("/tmp/nucleus" | path exists) {
        ^sudo mv /tmp/nucleus $"($install_dir)/nucleus"
    } else if ("/tmp/nucleus-node" | path exists) {
        ^sudo mv /tmp/nucleus-node $"($install_dir)/nucleus"
    }
    ^sudo chmod +x $"($install_dir)/nucleus"
    log-info $"Installed: ($install_dir)/nucleus"

    # Download nucleus-node for Linux (to run in Lima VM)
    let node_artifact = $"nucleus-node-($ver.version_num)-($platform.linux_target).tar.gz"
    log-info $"Downloading node binary: ($node_artifact)"
    let node_result = (do { ^curl -fsSL $"($base_url)/($node_artifact)" -o $"/tmp/($node_artifact)" } | complete)
    if $node_result.exit_code == 0 {
        ^tar -xzf $"/tmp/($node_artifact)" -C $artifacts_dir
        log-info $"Downloaded: ($artifacts_dir)/nucleus-node"
    } else {
        log-warn "nucleus-node for Linux not found in release. Will need to build from source."
    }

    # Download pre-built rootfs
    let rootfs_artifact = $"nucleus-rootfs-($ver.version_num)-($platform.arch).ext4.gz"
    log-info $"Downloading rootfs: ($rootfs_artifact)"
    let rootfs_result = (do { ^curl -fsSL $"($base_url)/($rootfs_artifact)" -o $"/tmp/($rootfs_artifact)" } | complete)
    if $rootfs_result.exit_code == 0 {
        ^gunzip -c $"/tmp/($rootfs_artifact)" out> $"($artifacts_dir)/rootfs.ext4"
        log-info $"Downloaded: ($artifacts_dir)/rootfs.ext4"
    } else {
        log-warn "Pre-built rootfs not found. Will need to build with scripts/firecracker/build-rootfs.sh"
    }

    # Clean up
    rm -f /tmp/nucleus-*.tar.gz /tmp/nucleus-rootfs-*.ext4.gz

    $artifacts_dir
}

def setup-lima-vm [platform: record, artifacts_dir: string] {
    if ($env.NUCLEUS_SKIP_VM? | default "") == "1" {
        log-info "Skipping Lima VM setup (NUCLEUS_SKIP_VM=1)"
        return
    }

    log-step "Setting up Lima VM..."

    # Check if VM already exists
    let vms = (do { ^limactl list -q } | complete)
    if ($vms.stdout | lines | any { |l| $l == $LIMA_VM_NAME }) {
        log-info $"Lima VM '($LIMA_VM_NAME)' already exists"

        let status = (do { ^limactl list --format "{{.Name}} {{.Status}}" } | complete)
        if ($status.stdout | str contains $"($LIMA_VM_NAME) Running") {
            log-info "VM is already running"
        } else {
            log-info "Starting VM..."
            ^limactl start $LIMA_VM_NAME
        }
    } else {
        let template_url = $"https://raw.githubusercontent.com/($GITHUB_REPO)/main/scripts/lima/nucleus-($platform.arch).yaml"
        log-info "Downloading Lima template..."
        ^curl -fsSL $template_url -o /tmp/nucleus-lima.yaml

        log-info "Creating Lima VM (this may take a few minutes)..."
        ^limactl create --name $LIMA_VM_NAME /tmp/nucleus-lima.yaml
        ^limactl start $LIMA_VM_NAME
        rm -f /tmp/nucleus-lima.yaml
    }

    # Copy artifacts to VM
    let node_bin = ($artifacts_dir | path join "nucleus-node")
    if ($node_bin | path exists) {
        log-info "Installing nucleus-node in VM..."
        ^limactl cp $node_bin $"($LIMA_VM_NAME):/tmp/nucleus-node"
        ^limactl shell $LIMA_VM_NAME -- sudo mv /tmp/nucleus-node /usr/local/bin/nucleus-node
        ^limactl shell $LIMA_VM_NAME -- sudo chmod +x /usr/local/bin/nucleus-node
    }

    let rootfs = ($artifacts_dir | path join "rootfs.ext4")
    if ($rootfs | path exists) {
        log-info "Installing rootfs in VM..."
        ^limactl cp $rootfs $"($LIMA_VM_NAME):/tmp/rootfs.ext4"
        ^limactl shell $LIMA_VM_NAME -- sudo mv /tmp/rootfs.ext4 /var/lib/nucleus/artifacts/rootfs.ext4
    }

    # Verify KVM support
    log-info "Checking KVM support in VM..."
    let kvm = (do { ^limactl shell $LIMA_VM_NAME -- test -c /dev/kvm } | complete)
    if $kvm.exit_code == 0 {
        log-info "KVM available - hardware-accelerated Firecracker!"
    } else {
        log-warn "KVM not available - Firecracker will use emulation (slower)"
    }
}

def setup-secrets [] {
    log-step "Setting up secrets..."

    let existing = (do { ^security find-generic-password -s nucleus-auth -w } | complete)
    if $existing.exit_code == 0 {
        log-info "Secrets already configured in Keychain"
        return
    }

    let auth_secret = (^openssl rand -hex 32 | str trim)
    let approval_secret = (^openssl rand -hex 32 | str trim)

    ^security add-generic-password -a $env.USER -s nucleus-auth -w $auth_secret -U
    ^security add-generic-password -a $env.USER -s nucleus-approval -w $approval_secret -U

    log-info "Secrets stored in macOS Keychain"
}

def setup-config [] {
    log-step "Setting up configuration..."

    let config_dir = $"($env.HOME)/.config/nucleus"
    mkdir $config_dir

    let config_file = ($config_dir | path join "config.toml")
    if not ($config_file | path exists) {
        $"# Nucleus configuration
# Generated by install.nu

[vm]
name = \"($LIMA_VM_NAME)\"
auto_start = true
cpus = 4
memory_gib = 8

[node]
url = \"http://127.0.0.1:8080\"
metrics_url = \"http://127.0.0.1:9080\"

[budget]
max_cost_usd = 5.0
max_input_tokens = 100000
max_output_tokens = 10000
" | save $config_file
        log-info $"Created: ($config_file)"
    } else {
        log-info $"Config already exists: ($config_file)"
    }
}

def verify-installation [platform: record] {
    log-step "Verifying installation..."

    mut errors = 0

    if (which nucleus | is-not-empty) {
        let ver = (do { ^nucleus --version } | complete)
        log-info $"CLI: ($ver.stdout | str trim | default 'installed')"
    } else {
        log-error "CLI not found in PATH"
        $errors = $errors + 1
    }

    if ($env.NUCLEUS_SKIP_VM? | default "") != "1" {
        let status = (do { ^limactl list --format "{{.Name}} {{.Status}}" } | complete)
        if ($status.stdout | str contains $"($LIMA_VM_NAME) Running") {
            log-info "Lima VM: running"
        } else {
            log-warn "Lima VM: not running"
        }
    }

    let config_dir = $"($env.HOME)/.config/nucleus"
    if (($config_dir | path join "config.toml") | path exists) {
        log-info $"Config: ($config_dir)/config.toml"
    }

    $errors
}

def print-success [platform: record] {
    print ""
    print $"(ansi green)(ansi bold)Nucleus installed successfully!(ansi reset)"
    print ""
    print "Quick start:"
    print "  nucleus doctor          # Check system status"
    print "  nucleus start           # Start nucleus-node"
    print "  nucleus run 'uname -a'  # Run a command in a microVM"
    print ""
    print $"Documentation: https://github.com/($GITHUB_REPO)#readme"
    print ""

    if $platform.nested_virt and $platform.macos_major >= 15 {
        print $"(ansi green)You have hardware-accelerated Firecracker support!(ansi reset)"
    }
}

def main [] {
    print ""
    print $"(ansi bold)Nucleus Installer(ansi reset)"
    print "=================="
    print ""

    let platform = (detect-platform)
    check-prerequisites
    let ver = (get-latest-version)
    let artifacts_dir = (download-artifacts $platform $ver)
    setup-lima-vm $platform $artifacts_dir
    setup-secrets
    setup-config
    let errors = (verify-installation $platform)
    if $errors == 0 {
        print-success $platform
    }
}
