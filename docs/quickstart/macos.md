# macOS Quickstart

This guide walks you through setting up Nucleus on macOS with full Firecracker microVM isolation.

## Prerequisites

### All Macs

- **macOS 13+** (macOS 15+ recommended for nested virtualization)
- **Lima** (`brew install lima`)
- **Docker** (for building rootfs images)
- **Rust toolchain** (for building nucleus binaries)
- **cross** (`cargo install cross`) for cross-compiling Linux binaries

### Intel Mac Additional Requirements

Intel Macs require QEMU for the Lima VM (Apple Virtualization.framework only supports ARM64):

```bash
# Install QEMU
brew install qemu

# Fix cross-rs toolchain issue (required for cross-compilation)
rustup toolchain install stable-x86_64-unknown-linux-gnu --force-non-host
```

**Note**: Intel Macs cannot use hardware-accelerated nested virtualization. Firecracker microVMs will run via QEMU emulation, which is slower but fully functional.

### Optimal Setup (Apple Silicon)

For the best experience with native nested virtualization:
- **Apple M3 or M4** chip
- **macOS 15 (Sequoia)** or newer

This combination provides hardware-accelerated KVM inside the Lima VM, giving near-native performance for Firecracker microVMs.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  macOS Host                                                     │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  Lima VM (Apple Virtualization.framework)                 │ │
│  │  ┌─────────────────────────────────────────────────────┐ │ │
│  │  │  nucleus-node (orchestrator)                        │ │ │
│  │  │    ↓                                                │ │ │
│  │  │  ┌─────────────┐  ┌─────────────┐                  │ │ │
│  │  │  │ Firecracker │  │ Firecracker │  ... (microVMs)  │ │ │
│  │  │  │ ┌─────────┐ │  │ ┌─────────┐ │                  │ │ │
│  │  │  │ │guest-   │ │  │ │guest-   │ │                  │ │ │
│  │  │  │ │init →   │ │  │ │init →   │ │                  │ │ │
│  │  │  │ │tool-    │ │  │ │tool-    │ │                  │ │ │
│  │  │  │ │proxy    │ │  │ │proxy    │ │                  │ │ │
│  │  │  │ └─────────┘ │  │ └─────────┘ │                  │ │ │
│  │  │  └─────────────┘  └─────────────┘                  │ │ │
│  │  └─────────────────────────────────────────────────────┘ │ │
│  │  /dev/kvm (nested virtualization)                        │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Install Dependencies

```bash
# Install Lima
brew install lima

# Install cross for cross-compilation
cargo install cross
```

### 2. Setup Environment

```bash
# Run setup (creates Lima VM, secrets, config)
nucleus setup
```

This will:
- Detect your Mac's chip (Intel vs Apple Silicon)
- Create a Lima VM with the appropriate architecture
- Download Firecracker and kernel for that architecture
- Generate secrets in macOS Keychain
- Create configuration at `~/.config/nucleus/config.toml`

### 3. Build Rootfs

```bash
# Cross-compile binaries for the rootfs
./scripts/cross-build.sh

# Get secrets from Keychain
AUTH_SECRET=$(security find-generic-password -s nucleus-auth -w)
APPROVAL_SECRET=$(security find-generic-password -s nucleus-approval -w)

# Build rootfs in Lima VM (has Docker)
limactl shell nucleus -- /host/path/to/nucleus/scripts/firecracker/build-rootfs.sh \
  --auth-secret "$AUTH_SECRET" \
  --approval-secret "$APPROVAL_SECRET"
```

### 4. Install nucleus-node

```bash
# Option A: Copy cross-compiled binary
limactl cp target/aarch64-unknown-linux-musl/release/nucleus-node nucleus:/usr/local/bin/

# Option B: Build inside VM (slower)
limactl shell nucleus -- cargo build --release -p nucleus-node
limactl shell nucleus -- sudo cp target/release/nucleus-node /usr/local/bin/
```

### 5. Start Nucleus

```bash
# Start nucleus-node service
nucleus start

# Output:
# Nucleus is running!
# HTTP API: http://127.0.0.1:8080
# Metrics:  http://127.0.0.1:9080
```

### 6. Run Tasks

```bash
# Run a task with enforced permissions
nucleus run "Review the code in src/main.rs"
```

### 7. Stop Nucleus

```bash
# Stop nucleus-node (keeps VM running)
nucleus stop

# Stop nucleus-node AND the VM (saves resources)
nucleus stop --stop-vm
```

## Platform Support

| Platform | VM Type | KVM | Performance |
|----------|---------|-----|-------------|
| M3/M4 + macOS 15+ | vz (native) | Nested | Fast |
| M1/M2 + macOS 15+ | vz (native) | Emulated | Medium |
| M1-M4 + macOS <15 | vz (native) | Emulated | Medium |
| Intel Mac | QEMU (x86_64) | Emulated | Slow |

## Security Model

Nucleus provides **two layers of VM isolation**:

### Layer 1: Lima VM
- Apple Virtualization.framework (Apple Silicon) or QEMU (Intel)
- Isolates the Firecracker orchestrator from macOS
- Managed by Lima with port forwarding

### Layer 2: Firecracker microVMs
- Minimal device model (5 virtio devices)
- Each task runs in its own microVM
- Read-only rootfs with scratch volume

### Network Security
- Default-deny iptables policy
- DNS allowlist for controlled outbound access
- No direct internet access without explicit policy

### Security Claims

| Layer | Isolation | Escape Difficulty |
|-------|-----------|-------------------|
| macOS ↔ Lima | Apple vz / QEMU | VM escape (high) |
| Lima ↔ Firecracker | KVM + jailer | VM escape (high) |
| Firecracker ↔ Agent | Minimal virtio | Kernel exploit (high) |
| Agent ↔ Network | iptables + allowlist | Policy bypass (medium) |

## Troubleshooting

### "KVM not available"

This warning appears when nested virtualization isn't working. Causes:
- **M1/M2 Macs**: Don't support nested virt (works via emulation, slower)
- **macOS < 15**: Upgrade to macOS Sequoia for nested virt support
- **Intel Macs**: Use QEMU emulation (slowest)

### Intel Mac: "QEMU binary not found"

Install QEMU:
```bash
brew install qemu
```

### Intel Mac: cross-rs "toolchain may not be able to run on this system"

This error occurs when cross-compiling for Linux on Intel Mac:
```
error: toolchain 'stable-x86_64-unknown-linux-gnu' may not be able to run on this system
```

Fix by installing the toolchain with the `--force-non-host` flag:
```bash
rustup toolchain install stable-x86_64-unknown-linux-gnu --force-non-host
```

See: [cross-rs/cross#1687](https://github.com/cross-rs/cross/issues/1687)

### "Lima VM failed to start"

```bash
# Check VM status
limactl list

# View VM logs
limactl shell nucleus -- journalctl -xe

# Delete and recreate
nucleus setup --force
```

### "nucleus-node not found"

You need to install the nucleus-node binary in the VM:

```bash
# Cross-compile for the correct architecture
./scripts/cross-build.sh --arch aarch64  # or x86_64 for Intel

# Copy to VM
limactl cp target/aarch64-unknown-linux-musl/release/nucleus-node nucleus:/usr/local/bin/
```

### Port forwarding issues

If `http://127.0.0.1:8080` doesn't respond:

```bash
# Verify port forwarding
limactl list --format '{{.Name}} {{.Status}} {{.SSHLocalPort}}'

# Check if nucleus-node is listening
limactl shell nucleus -- ss -tlnp | grep 8080

# View nucleus-node logs
limactl shell nucleus -- journalctl -u nucleus-node -f
```

## Commands Reference

| Command | Description |
|---------|-------------|
| `nucleus setup` | Initial setup (Lima VM, secrets, config) |
| `nucleus setup --force` | Recreate VM and config |
| `nucleus start` | Start nucleus-node service |
| `nucleus start --no-wait` | Start without health check |
| `nucleus stop` | Stop nucleus-node |
| `nucleus stop --stop-vm` | Stop nucleus-node AND Lima VM |
| `nucleus doctor` | Diagnose issues |
| `nucleus run "task"` | Run a task |

## Advanced Configuration

### Custom VM Resources

```bash
nucleus setup --vm-cpus 8 --vm-memory-gib 16 --vm-disk-gib 100
```

### Rotate Secrets

```bash
nucleus setup --rotate-secrets
```

### Skip VM Setup (manual Lima management)

```bash
nucleus setup --skip-vm
```

### Configuration File

Edit `~/.config/nucleus/config.toml`:

```toml
[vm]
name = "nucleus"
auto_start = true
cpus = 4
memory_gib = 8

[node]
url = "http://127.0.0.1:8080"

[budget]
max_cost_usd = 5.0
max_input_tokens = 100000
max_output_tokens = 10000
```
