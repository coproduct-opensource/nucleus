#!/usr/bin/env nu
# Cross-compile nucleus binaries for Firecracker rootfs.
# Builds static musl binaries for aarch64 and x86_64 Linux.

# Packages to build for rootfs
const ROOTFS_PACKAGES = ["nucleus-guest-init", "nucleus-tool-proxy", "nucleus-net-probe"]
const AARCH64_TARGET = "aarch64-unknown-linux-musl"
const X86_64_TARGET = "x86_64-unknown-linux-musl"

def log-info [msg: string] {
    print $"(ansi green)[INFO](ansi reset) ($msg)"
}

def log-warn [msg: string] {
    print -e $"(ansi yellow)[WARN](ansi reset) ($msg)"
}

def log-error [msg: string] {
    print -e $"(ansi red)[ERROR](ansi reset) ($msg)"
}

def detect-build-tool [use_cross: string] {
    match $use_cross {
        "cross" => {
            if (which cross | is-not-empty) {
                "cross"
            } else {
                log-error "cross not found. Install with: cargo install cross"
                exit 1
            }
        },
        "cargo" => "cargo",
        _ => {
            # Auto-detect
            if (which cross | is-not-empty) {
                "cross"
            } else {
                log-warn "cross not found, falling back to cargo (may require musl toolchain)"
                "cargo"
            }
        }
    }
}

def build-target [target: string, tool: string] {
    log-info $"Building for target: ($target) using ($tool)"

    for package in $ROOTFS_PACKAGES {
        log-info $"  Building ($package)..."
        ^$tool build --release --target $target -p $package
    }

    # Show built binaries
    log-info $"Built binaries for ($target):"
    for package in $ROOTFS_PACKAGES {
        let bin_path = $"target/($target)/release/($package)"
        if ($bin_path | path exists) {
            let size = (ls $bin_path | get 0.size)
            log-info $"    ($bin_path) \(($size)\)"
        }
    }
}

def verify-binaries [target: string] {
    mut missing = false

    for package in $ROOTFS_PACKAGES {
        let bin_path = $"target/($target)/release/($package)"
        if not ($bin_path | path exists) {
            log-error $"Missing: ($bin_path)"
            $missing = true
        }
    }

    not $missing
}

def main [
    --arch: string = "all"   # Architecture: aarch64, x86_64, or all
    --cross                  # Force use of 'cross' tool
    --cargo                  # Force use of 'cargo' (requires musl toolchain)
    --verify                 # Only verify that binaries exist
] {
    # Resolve to root dir
    let script_dir = ($env.FILE_PWD? | default $env.PWD)
    let root_dir = ($script_dir | path join ".." | path expand)
    cd $root_dir

    let use_cross = if $cross { "cross" } else if $cargo { "cargo" } else { "auto" }

    if $verify {
        mut exit_code = 0
        if $arch == "all" or $arch == "aarch64" {
            log-info "Verifying aarch64 binaries..."
            if not (verify-binaries $AARCH64_TARGET) { $exit_code = 1 }
        }
        if $arch == "all" or $arch == "x86_64" {
            log-info "Verifying x86_64 binaries..."
            if not (verify-binaries $X86_64_TARGET) { $exit_code = 1 }
        }
        if $exit_code != 0 { exit 1 }
        return
    }

    let build_tool = (detect-build-tool $use_cross)
    log-info $"Using build tool: ($build_tool)"

    match $arch {
        "all" => {
            build-target $AARCH64_TARGET $build_tool
            build-target $X86_64_TARGET $build_tool
        },
        "aarch64" => { build-target $AARCH64_TARGET $build_tool },
        "x86_64" => { build-target $X86_64_TARGET $build_tool },
        _ => {
            log-error $"Unknown architecture: ($arch)"
            exit 1
        }
    }

    log-info "Build complete!"
    log-info ""
    log-info "Next steps:"
    log-info $"  1. Build rootfs: scripts/firecracker/build-rootfs.sh --arch ($arch)"
    log-info "  2. Run setup:    nucleus setup"
}
