#!/usr/bin/env nu
# Build ext4 rootfs image for Firecracker microVMs.
# Supports both aarch64 (Apple Silicon) and x86_64 (Intel) architectures.

def log-info [msg: string] {
    print $"(ansi green)[INFO](ansi reset) ($msg)"
}

def log-warn [msg: string] {
    print -e $"(ansi yellow)[WARN](ansi reset) ($msg)"
}

def log-error [msg: string] {
    print -e $"(ansi red)[ERROR](ansi reset) ($msg)"
}

def detect-arch [] {
    match (^uname -m | str trim) {
        "arm64" | "aarch64" => "aarch64"
        "x86_64" | "amd64" => "x86_64"
        _ => "x86_64"
    }
}

def arch-config [arch: string] {
    match $arch {
        "aarch64" => {
            {
                target: "aarch64-unknown-linux-musl"
                debian_image: ($env.DEBIAN_IMAGE? | default "arm64v8/debian:bookworm-slim")
            }
        }
        "x86_64" => {
            {
                target: "x86_64-unknown-linux-musl"
                debian_image: ($env.DEBIAN_IMAGE? | default "debian:bookworm-slim")
            }
        }
        _ => {
            log-error $"Unsupported architecture: ($arch)"
            log-error "Supported: aarch64, x86_64"
            exit 1
        }
    }
}

def main [
    --arch: string = ""               # Architecture: aarch64 or x86_64 (default: auto-detect)
    --output: string = ""             # Output rootfs.ext4 path
    --pod-spec: string = ""           # Pod spec YAML file
    --legacy-secrets                  # Bake secrets into rootfs (deprecated, insecure)
    --auth-secret: string = ""        # Auth secret (only with --legacy-secrets)
    --approval-secret: string = ""    # Approval secret (only with --legacy-secrets)
    --net-allow: string = ""          # Network allow list file
    --net-deny: string = ""           # Network deny list file
    --audit-path: string = ""         # Audit log path inside VM
    --size: int = 256                 # Rootfs image size in MB
    --verify                          # Verify required binaries exist without building
] {
    let script_dir = ($env.FILE_PWD? | default $env.PWD)
    let root_dir = ($script_dir | path join "../.." | path expand)

    let arch = if ($arch | is-empty) { ($env.ARCH? | default (detect-arch)) } else { $arch }
    let cfg = (arch-config $arch)
    let target = $cfg.target
    let debian_image = $cfg.debian_image

    # Configurable paths
    let rootfs_dir = ($env.ROOTFS_DIR? | default ($root_dir | path join $"build/firecracker/($arch)/rootfs"))
    let rootfs_img = if ($output | is-not-empty) {
        $output
    } else {
        ($env.ROOTFS_IMG? | default ($root_dir | path join $"build/firecracker/($arch)/rootfs.ext4"))
    }
    let pod_spec = if ($pod_spec | is-not-empty) { $pod_spec } else {
        ($env.POD_SPEC? | default ($root_dir | path join "examples/openclaw-demo/firecracker-pod.yaml"))
    }
    let guest_init_bin = ($env.GUEST_INIT_BIN? | default ($root_dir | path join $"target/($target)/release/nucleus-guest-init"))
    let init_src = ($env.INIT_SRC? | default ($script_dir | path join "guest-init.sh"))
    let proxy_bin = ($env.PROXY_BIN? | default ($root_dir | path join $"target/($target)/release/nucleus-tool-proxy"))
    let net_probe_bin = ($env.NET_PROBE_BIN? | default ($root_dir | path join $"target/($target)/release/nucleus-net-probe"))
    let audit_log_path = if ($audit_path | is-not-empty) { $audit_path } else { ($env.AUDIT_LOG_PATH? | default "") }

    # Verify mode
    if $verify {
        print $"Verifying binaries for ($arch) \(($target)\)..."
        mut missing = 0

        for bin in [$proxy_bin $net_probe_bin] {
            if ($bin | path exists) {
                print $"  OK: ($bin)"
            } else {
                print $"  MISSING: ($bin)"
                $missing = $missing + 1
            }
        }

        if ($guest_init_bin | path exists) {
            print $"  OK: ($guest_init_bin)"
        } else if ($init_src | path exists) {
            print $"  FALLBACK: ($init_src) \(shell script init\)"
        } else {
            print $"  MISSING: ($guest_init_bin) \(and no fallback ($init_src)\)"
            $missing = $missing + 1
        }

        if $missing != 0 { exit 1 }
        return
    }

    # Validate required inputs
    if not ($proxy_bin | path exists) {
        log-error $"Missing ($proxy_bin)"
        log-error $"Build with: scripts/cross-build.sh --arch ($arch)"
        exit 1
    }
    if not ($net_probe_bin | path exists) {
        log-error $"Missing ($net_probe_bin)"
        log-error $"Build with: scripts/cross-build.sh --arch ($arch)"
        exit 1
    }
    if not ($pod_spec | path exists) {
        log-error $"Missing ($pod_spec)"
        exit 1
    }
    if not ($guest_init_bin | path exists) and not ($init_src | path exists) {
        log-error $"Missing ($guest_init_bin)"
        log-error $"Build with: scripts/cross-build.sh --arch ($arch)"
        exit 1
    }

    let guest_net_sh = ($script_dir | path join "guest-net.sh")
    if not ($guest_net_sh | path exists) {
        log-error $"Missing ($guest_net_sh)"
        exit 1
    }

    # Legacy secrets validation
    let tool_proxy_auth_secret = if ($auth_secret | is-not-empty) { $auth_secret } else { ($env.TOOL_PROXY_AUTH_SECRET? | default "") }
    let approval_secret_val = if ($approval_secret | is-not-empty) { $approval_secret } else { ($env.APPROVAL_SECRET? | default "") }

    if $legacy_secrets {
        if ($tool_proxy_auth_secret | is-empty) {
            log-error "TOOL_PROXY_AUTH_SECRET is required with --legacy-secrets."
            exit 1
        }
        if ($approval_secret_val | is-empty) {
            log-error "APPROVAL_SECRET is required with --legacy-secrets."
            exit 1
        }
        log-warn "WARNING: --legacy-secrets is deprecated. Secrets should be injected at runtime."
    }

    log-info $"Building rootfs for architecture: ($arch)"
    log-info $"  Target: ($target)"
    log-info $"  Output: ($rootfs_img)"
    log-info $"  Size: ($size)MB"

    mkdir $rootfs_dir
    mkdir ($rootfs_img | path dirname)

    # Clean rootfs dir
    if ($rootfs_dir | path exists) {
        rm -rf $rootfs_dir
        mkdir $rootfs_dir
    }

    let tmp_tar = (^mktemp | str trim)

    # Extract Debian base
    let debian_tarball = ($env.DEBIAN_TARBALL? | default "")
    if ($debian_tarball | is-not-empty) {
        log-info $"Using Debian tarball: ($debian_tarball)"
        ^tar -xzf $debian_tarball -C $rootfs_dir
    } else {
        if (which docker | is-empty) {
            log-error "Docker not found. Set DEBIAN_TARBALL to a Debian rootfs tarball instead."
            exit 1
        }
        log-info $"Extracting base from Docker image: ($debian_image)"
        let cid = (^docker create $debian_image /bin/sh | str trim)
        ^docker export $cid -o $tmp_tar
        ^docker rm $cid out> /dev/null
        ^tar -xf $tmp_tar -C $rootfs_dir
    }
    rm -f $tmp_tar

    # Create nucleus directories
    mkdir ($rootfs_dir | path join "etc/nucleus")
    mkdir ($rootfs_dir | path join "usr/local/bin")
    mkdir ($rootfs_dir | path join "work")

    # Copy pod spec
    cp $pod_spec ($rootfs_dir | path join "etc/nucleus/pod.yaml")

    # Copy network policy files if provided
    if ($net_allow | is-not-empty) and ($net_allow | path exists) {
        cp $net_allow ($rootfs_dir | path join "etc/nucleus/net.allow")
    }
    if ($net_deny | is-not-empty) and ($net_deny | path exists) {
        cp $net_deny ($rootfs_dir | path join "etc/nucleus/net.deny")
    }

    # Legacy secrets (deprecated)
    if $legacy_secrets {
        log-warn "Writing secrets to rootfs (DEPRECATED - use runtime injection instead)"
        $tool_proxy_auth_secret | save -f ($rootfs_dir | path join "etc/nucleus/auth.secret")
        ^chmod 600 ($rootfs_dir | path join "etc/nucleus/auth.secret")
        $approval_secret_val | save -f ($rootfs_dir | path join "etc/nucleus/approval.secret")
        ^chmod 600 ($rootfs_dir | path join "etc/nucleus/approval.secret")
    }

    # Write audit path if configured
    if ($audit_log_path | is-not-empty) {
        $audit_log_path | save -f ($rootfs_dir | path join "etc/nucleus/audit.path")
        ^chmod 600 ($rootfs_dir | path join "etc/nucleus/audit.path")
    }

    # Copy binaries
    cp $proxy_bin ($rootfs_dir | path join "usr/local/bin/nucleus-tool-proxy")
    cp $net_probe_bin ($rootfs_dir | path join "usr/local/bin/nucleus-net-probe")

    # Copy init binary (prefer Rust binary, fall back to shell script)
    if ($guest_init_bin | path exists) {
        cp $guest_init_bin ($rootfs_dir | path join "init")
        log-info "Using Rust init binary"
    } else {
        cp $init_src ($rootfs_dir | path join "init")
        log-info "Using shell script init (fallback)"
    }

    # Copy network setup script
    cp $guest_net_sh ($rootfs_dir | path join "usr/local/bin/guest-net.sh")

    # Set executable permissions
    ^chmod +x ($rootfs_dir | path join "init")
    ^chmod +x ($rootfs_dir | path join "usr/local/bin/nucleus-tool-proxy")
    ^chmod +x ($rootfs_dir | path join "usr/local/bin/nucleus-net-probe")
    ^chmod +x ($rootfs_dir | path join "usr/local/bin/guest-net.sh")

    # Build ext4 image from directory
    rm -f $rootfs_img
    let mke2fs_opts = ($env.MKE2FS_OPTS? | default $"-d ($rootfs_dir) -t ext4 -m 0 -F")
    ^mke2fs ...($mke2fs_opts | split row " ") $rootfs_img $"($size)M"

    print ""
    log-info $"Rootfs image written to: ($rootfs_img)"
    log-info $"Architecture: ($arch)"

    # Print binary info
    print ""
    log-info "Included binaries:"
    for bin in ["init" "usr/local/bin/nucleus-tool-proxy" "usr/local/bin/nucleus-net-probe"] {
        let bin_path = ($rootfs_dir | path join $bin)
        if ($bin_path | path exists) {
            let size_info = (ls $bin_path | get 0.size)
            log-info $"  /($bin) \(($size_info)\)"
        }
    }
}
