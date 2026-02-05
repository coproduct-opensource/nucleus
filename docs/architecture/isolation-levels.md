# Isolation Levels and Security Model

This document describes nucleus's isolation architecture, driver options, and security tradeoffs for different deployment scenarios.

## Isolation Hierarchy

Nucleus supports multiple isolation levels depending on the deployment environment:

| Level | Driver | Isolation | Boot Time | Network Control | Use Case |
|-------|--------|-----------|-----------|-----------------|----------|
| 4 | `firecracker` | Hardware VM (KVM) | ~125ms | Per-pod iptables | Production, untrusted code |
| 3 | `lima` (planned) | Full VM (QEMU/vz) | ~2-20s | VM-level | Development, macOS |
| 2 | `gvisor` (planned) | Syscall filtering | ~ms | gVisor stack | Semi-trusted workloads |
| 1 | `local` | Process only | ~ms | None | Trusted code, testing |

## Driver Security Properties

### Firecracker Driver (Level 4) - Recommended for Production

**Security boundaries:**
- Separate Linux kernel per pod (hardware-enforced via KVM)
- Minimal attack surface (~5 virtio devices)
- Read-only rootfs with scratch-only writes
- Per-pod network namespace with iptables enforcement
- Seccomp filtering on VMM process

**Network isolation:**
- Default-deny egress (no NIC unless `spec.network` specified)
- DNS allowlisting with pinned resolution
- Iptables drift detection (fail-closed on policy changes)
- No shared host interfaces (per-pod tap device)

**Requirements:**
- Linux host with `/dev/kvm`
- Apple Silicon M3/M4 + macOS 15+ (via Lima nested virtualization)
- **Not supported**: Intel Macs, older Apple Silicon, cloud VMs without nested virt

### Local Driver (Level 1) - Development Only

**Security boundaries:**
- Process-level isolation only
- Shared host kernel
- Full network access (no isolation)
- Trifecta guard still enforces approval requirements

**What's enforced:**
- Command lattice (blocked commands like `gh auth`)
- Approval obligations (trifecta constraint)
- Budget limits
- Path restrictions (via cap-std)

**What's NOT enforced:**
- Network egress (dns_allow ignored)
- VM-level isolation
- Kernel separation

**Use cases:**
- Local development and testing
- Trusted first-party code
- Validating policy logic without VM overhead

```bash
# Explicitly opt-in to local driver (unsafe for untrusted code)
nucleus-node --driver local --allow-local-driver
```

## Lima VM as Development Environment

For macOS users without firecracker support (Intel Macs, M1/M2), Lima provides a development-grade sandbox:

### Lima Security Properties

| Property | Lima VM | Firecracker |
|----------|---------|-------------|
| Kernel isolation | Yes (separate Linux) | Yes (per-pod) |
| Per-pod isolation | No (shared VM) | Yes |
| Network control | VM-level only | Per-pod iptables |
| Boot time | ~2-20s | ~125ms |
| Escape difficulty | VM escape (high) | VM escape (high) |

### Lima Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  macOS Host                                                  │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Lima VM (QEMU/vz)                                     │ │
│  │  ┌──────────────────────────────────────────────────┐  │ │
│  │  │  nucleus-node (local driver)                     │  │ │
│  │  │    ↓                                             │  │ │
│  │  │  nucleus-tool-proxy (per-pod process)            │  │ │
│  │  │    - Policy enforcement                          │  │ │
│  │  │    - Command lattice                             │  │ │
│  │  │    - Trifecta guard                              │  │ │
│  │  └──────────────────────────────────────────────────┘  │ │
│  │  /workspace (mounted from host)                        │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Lima Configuration

```yaml
# ~/.lima/nucleus/lima.yaml
mounts:
  - location: "/path/to/workspace"
    mountPoint: "/workspace"
    writable: true

provision:
  - mode: system
    script: |
      # Install musl toolchain for static binaries
      apt-get install -y musl-tools musl-dev
      # ... (Rust setup)
```

### Lima Limitations

- **No per-pod network isolation**: All pods share VM's network
- **No dns_allow enforcement**: Network policy requires firecracker
- **Shared kernel attack surface**: All pods share Lima's kernel
- **Not suitable for untrusted code in production**

## NVIDIA's Mandatory Security Controls

Based on [NVIDIA's guidance for agentic sandboxing](https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/):

### 1. Network Egress Controls (Firecracker only)

```yaml
spec:
  network:
    dns_allow:
      - "api.github.com"
      - "github.com"
    # All other egress blocked by default
```

### 2. Workspace Write Restrictions

Nucleus enforces via:
- Read-only rootfs
- Scratch-only write paths
- cap-std path sandboxing

### 3. Configuration File Protection

Command lattice blocks:
- `gh auth *`, `gh config *` (credential manipulation)
- Writes to `.git/hooks`, `.claude/`, etc.

## Trifecta Guard

Regardless of driver, nucleus enforces the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) constraint:

When all three capabilities are present at autonomous levels:
1. **Private data access** (read_files)
2. **Untrusted content exposure** (web_fetch)
3. **External communication** (git_push, api_call)

Exfiltration operations gain **approval obligations** - requiring human confirmation before execution.

```
# Even with "permissive" profile:
$ gh pr create
{"error": "approval required", "operation": "gh pr create"}
```

This is defense-in-depth: even if network/VM isolation fails, the agent cannot autonomously exfiltrate data.

## Platform Recommendations

| Platform | Recommended Driver | Notes |
|----------|-------------------|-------|
| Linux + KVM | `firecracker` | Full production support |
| M3/M4 Mac + macOS 15+ | `firecracker` (via Lima) | Native KVM in nested VM |
| M1/M2 Mac | `local` (in Lima) | No KVM, use Lima for kernel isolation |
| Intel Mac | `local` (in Lima) | No KVM, Lima provides VM boundary |
| Cloud VM (no nested virt) | `local` or `gvisor` (planned) | Consider PVM if available |

## Defense-in-Depth Layers

```
Layer 5: Approval obligations (trifecta guard)
Layer 4: Command lattice (blocked commands)
Layer 3: Path sandboxing (cap-std)
Layer 2: Network isolation (iptables/dns_allow) [firecracker only]
Layer 1: VM isolation (KVM/QEMU)
Layer 0: Host kernel
```

Even when lower layers are unavailable (e.g., local driver), higher layers still provide meaningful security:
- Command blocking prevents `gh auth login`
- Path sandboxing prevents writes outside workspace
- Trifecta guard requires approval for exfiltration

## References

- [How to Sandbox AI Agents in 2026](https://northflank.com/blog/how-to-sandbox-ai-agents) - Isolation technology comparison
- [NVIDIA Sandboxing Guidance](https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/) - Mandatory controls
- [Lima v2.0 for AI Workflows](https://www.cncf.io/blog/2025/12/11/lima-v2-0-new-features-for-secure-ai-workflows/) - Lima security features
- [The Lethal Trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) - Original threat model
