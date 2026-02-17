#!/usr/bin/env nu
# Network policy integration test for Firecracker microVMs.
# Verifies allowlist/denylist iptables rules and optional connectivity checks.
#
# Must be run as root on Linux (requires iptables, netns, tap).

def log-info [msg: string] {
    print $"(ansi green)[INFO](ansi reset) ($msg)"
}

def log-error [msg: string] {
    print -e $"(ansi red)[ERROR](ansi reset) ($msg)"
}

def require [cmd: string] {
    if (which $cmd | is-empty) {
        log-error $"missing required command: ($cmd)"
        exit 1
    }
}

def main [
    --node-addr: string = "127.0.0.1:8090"  # Nucleus node listen address
    --check-connectivity                      # Also test actual network connectivity from guest
] {
    let root_dir = ($env.FILE_PWD? | default $env.PWD) | path join "../.." | path expand
    let check_connectivity = ($env.CHECK_CONNECTIVITY? | default (if $check_connectivity { "1" } else { "0" }))
    let node_addr = ($env.NODE_ADDR? | default $node_addr)

    # Platform checks
    if (^uname -s | str trim) != "Linux" {
        log-error "network test requires Linux"
        exit 1
    }

    if (^id -u | str trim) != "0" {
        log-error "run as root (iptables, netns, tap)"
        exit 1
    }

    for cmd in [ip iptables nsenter curl jq firecracker] {
        require $cmd
    }

    let kernel = ($env.KERNEL? | default ($root_dir | path join "build/firecracker/vmlinux"))
    let rootfs = ($env.ROOTFS? | default ($root_dir | path join "build/firecracker/rootfs.ext4"))
    let scratch = ($env.SCRATCH? | default ($root_dir | path join "build/firecracker/scratch.ext4"))

    for artifact in [$kernel $rootfs $scratch] {
        if not ($artifact | path exists) {
            log-error $"missing Firecracker artifacts; build with scripts/firecracker/build-rootfs.sh"
            exit 1
        }
    }

    # Write pod spec to temp file
    let spec_file = (^mktemp | str trim)
    "apiVersion: nucleus/v1
kind: Pod
metadata:
  name: net-policy-test
spec:
  work_dir: /work
  timeout_seconds: 600
  policy:
    type: profile
    name: demo
  network:
    allow:
      - 1.1.1.1:443
    deny:
      - 8.8.8.8:443
  image:
    kernel_path: ./build/firecracker/vmlinux
    rootfs_path: ./build/firecracker/rootfs.ext4
    read_only: true
    scratch_path: ./build/firecracker/scratch.ext4
  vsock:
    guest_cid: 3
    port: 5005
  seccomp:
    mode: default
" | save -f $spec_file

    # Start nucleus-node in background
    log-info "starting nucleus-node..."
    let node_log = "/tmp/nucleus-node-net.log"
    $env.RUST_LOG = "info"

    # We need to use shell background process
    ^bash -c $"cd ($root_dir) && cargo run -p nucleus-node -- --driver firecracker --listen ($node_addr) --proxy-auth-secret test-secret --firecracker-netns >($node_log) 2>&1 &"

    sleep 1sec

    # Create pod
    let resp_result = (do { ^curl -sS -X POST --data-binary $"@($spec_file)" $"http://($node_addr)/v1/pods" } | complete)
    let resp = ($resp_result.stdout | from json)
    let pod_id = ($resp | get -o id | default "")
    let proxy_addr = ($resp | get -o proxy_addr | default "")

    # Cleanup spec file
    rm -f $spec_file

    if ($pod_id | is-empty) or $pod_id == "null" or ($proxy_addr | is-empty) or $proxy_addr == "null" {
        log-error $"failed to create pod: ($resp_result.stdout)"
        exit 1
    }

    log-info $"pod id: ($pod_id)"
    log-info $"proxy: ($proxy_addr)"

    # Wait for proxy health
    log-info "waiting for proxy health..."
    for _ in 1..40 {
        let health = (do { ^curl -fsS $"($proxy_addr)/v1/health" } | complete)
        if $health.exit_code == 0 { break }
        sleep 250ms
    }

    # Read audit log
    let audit_resp = (do {
        ^curl -sS -X POST $"($proxy_addr)/v1/read" -H "content-type: application/json" -d '{"path":"/work/audit/nucleus-audit.log"}'
    } | complete)
    mut audit_content = ($audit_resp.stdout | from json | get -o contents | default "")

    if ($audit_content | is-empty) or $audit_content == "null" {
        let fallback = (do {
            ^curl -sS -X POST $"($proxy_addr)/v1/read" -H "content-type: application/json" -d '{"path":"/tmp/nucleus-audit.log"}'
        } | complete)
        $audit_content = ($fallback.stdout | from json | get -o contents | default "")
    }

    # Find boot audit entry
    let boot_lines = ($audit_content | lines | where { |line|
        try { $line | from json | get -o event | default "" } catch { "" } | $in == "boot"
    })

    if ($boot_lines | is-empty) {
        log-error "boot audit entry missing"
        exit 1
    }

    let boot_line = ($boot_lines | last | from json)
    let boot_subject = ($boot_line | get subject)
    let net_addr = (try { $boot_subject | from json | get -o net_addr | default "" } catch { "" })

    if ($net_addr | is-empty) or $net_addr == "null" {
        log-error "boot report missing net_addr"
        exit 1
    }

    let short_id = ($pod_id | str substring 0..8)
    let netns = $"nuc-($short_id)"
    log-info $"netns: ($netns)"

    # Check iptables rules
    let rules = (^ip netns exec $netns iptables -S | str trim)

    if not ($rules | str contains "1.1.1.1/32") {
        log-error "allow rule missing for 1.1.1.1/32"
        exit 1
    }
    if not ($rules | str contains "8.8.8.8/32") {
        log-error "deny rule missing for 8.8.8.8/32"
        exit 1
    }

    # Optional connectivity check
    if $check_connectivity == "1" {
        log-info "checking connectivity from guest..."

        let allow_resp = (^curl -sS -X POST $"($proxy_addr)/v1/run"
            -H "content-type: application/json"
            -d '{"command":"nucleus-net-probe 1.1.1.1:443"}' | from json)

        if ($allow_resp | get -o success | default false) != true {
            log-error $"allowlist connection failed: ($allow_resp)"
            exit 1
        }

        let deny_resp = (^curl -sS -X POST $"($proxy_addr)/v1/run"
            -H "content-type: application/json"
            -d '{"command":"nucleus-net-probe 8.8.8.8:443"}' | from json)

        if ($deny_resp | get -o success | default false) == true {
            log-error $"denylist connection unexpectedly succeeded: ($deny_resp)"
            exit 1
        }
        log-info "denylist connection blocked"
    }

    log-info "network policy test passed"
}
