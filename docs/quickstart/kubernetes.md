# Kubernetes Quickstart

Deploy Firecracker-isolated AI agent sandboxes on Kubernetes with fine-grained permission control.

## Why Nucleus on Kubernetes?

| Feature | Google Agent Sandbox | Nucleus |
|---------|---------------------|---------|
| Isolation | gVisor (syscall filter) | Firecracker (hardware VM) |
| Attack surface | ~300 syscalls exposed | ~50K lines Rust, KVM-backed |
| Permission model | Pod RBAC only | Lattice-guard with uninhabitable state detection |
| Startup time | <1s (warm pool) | <125ms (Firecracker) |
| Memory overhead | ~50MB | ~5MB per microVM |

Nucleus provides **hardware-level isolation** with a **mathematical permission model** that automatically detects dangerous capability combinations (the "uninhabitable state").

---

## Prerequisites

- Kubernetes cluster with Linux nodes (kernel 5.10+)
- Nodes with `/dev/kvm` access (nested virt or bare metal)
- `kubectl` configured

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │  nucleus-node   │  │  nucleus-node   │  (DaemonSet)      │
│  │  ┌───────────┐  │  │  ┌───────────┐  │                   │
│  │  │Firecracker│  │  │  │Firecracker│  │                   │
│  │  │  microVM  │  │  │  │  microVM  │  │                   │
│  │  │┌─────────┐│  │  │  │┌─────────┐│  │                   │
│  │  ││tool-    ││  │  │  ││tool-    ││  │                   │
│  │  ││proxy    ││  │  │  ││proxy    ││  │                   │
│  │  │└─────────┘│  │  │  │└─────────┘│  │                   │
│  │  └───────────┘  │  │  └───────────┘  │                   │
│  └─────────────────┘  └─────────────────┘                   │
│           │                    │                             │
│           └────────┬───────────┘                             │
│                    ▼                                         │
│  ┌─────────────────────────────────────┐                    │
│  │         nucleus-controller          │  (Deployment)      │
│  │  - Watches NucleusSandbox CRDs      │                    │
│  │  - Schedules pods to nodes          │                    │
│  │  - Enforces permission lattice      │                    │
│  └─────────────────────────────────────┘                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Deploy

### 1. Create Namespace

```bash
kubectl create namespace nucleus-system
```

### 2. Deploy nucleus-node DaemonSet

```yaml
# nucleus-node-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: nucleus-node
  namespace: nucleus-system
spec:
  selector:
    matchLabels:
      app: nucleus-node
  template:
    metadata:
      labels:
        app: nucleus-node
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: nucleus-node
        image: ghcr.io/coproduct-opensource/nucleus-node:latest
        securityContext:
          privileged: true  # Required for Firecracker + KVM
        env:
        - name: NUCLEUS_NODE_LISTEN
          value: "0.0.0.0:8080"
        - name: NUCLEUS_NODE_DRIVER
          value: "firecracker"
        - name: NUCLEUS_NODE_FIRECRACKER_NETNS
          value: "true"
        volumeMounts:
        - name: dev-kvm
          mountPath: /dev/kvm
        - name: pods
          mountPath: /var/lib/nucleus/pods
        ports:
        - containerPort: 8080
          hostPort: 8080
      volumes:
      - name: dev-kvm
        hostPath:
          path: /dev/kvm
      - name: pods
        hostPath:
          path: /var/lib/nucleus/pods
          type: DirectoryOrCreate
      nodeSelector:
        nucleus.io/kvm: "true"
```

```bash
# Label nodes with KVM support
kubectl label nodes <node-name> nucleus.io/kvm=true

# Deploy
kubectl apply -f nucleus-node-daemonset.yaml
```

### 3. Create a Sandbox

```yaml
# sandbox.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: agent-sandbox-spec
  namespace: nucleus-system
data:
  pod.yaml: |
    apiVersion: nucleus.io/v1
    kind: PodSpec
    metadata:
      name: code-review-agent
    spec:
      profile: code-review
      work_dir: /workspace
      timeout_seconds: 3600

      # Permission overrides
      capabilities:
        read_files: always
        write_files: never
        edit_files: never
        run_bash: never
        web_search: low_risk
        web_fetch: never
        git_commit: never
        git_push: never
        create_pr: never

      # Network policy
      network:
        dns_allow:
          - "api.anthropic.com:443"
          - "api.openai.com:443"
```

### 4. Launch Agent via API

```bash
# Port-forward to nucleus-node
kubectl port-forward -n nucleus-system daemonset/nucleus-node 8080:8080 &

# Create sandbox
curl -X POST http://localhost:8080/v1/pods \
  -H "Content-Type: application/yaml" \
  -d @sandbox.yaml
```

---

## Permission Profiles

Nucleus includes built-in profiles for common agent patterns:

| Profile | Use Case | Capabilities |
|---------|----------|--------------|
| `read-only` | Code exploration | Read files, no writes/network |
| `code-review` | PR review agents | Read + web search for context |
| `fix-issue` | Bug fix agents | Full dev workflow, uninhabitable state protected |
| `demo` | Live demos | Blocks shell interpreters |

###  Uninhabitable state Protection

When an agent has all three dangerous capabilities:
1. **Private data access** (read_files ≥ low_risk)
2. **Untrusted content** (web_fetch OR web_search ≥ low_risk)
3. **Exfiltration channel** (git_push OR create_pr OR run_bash ≥ low_risk)

Nucleus **automatically requires human approval** for exfiltration actions. This protects against prompt injection attacks that could steal secrets.

```
Agent requests: git push origin main
┌─────────────────────────────────────────┐
│  ⚠️  uninhabitable state PROTECTION TRIGGERED      │
│                                         │
│  This agent has:                        │
│  ✓ Read access to files                 │
│  ✓ Web access (prompt injection risk)   │
│  ✓ Git push capability                  │
│                                         │
│  Approve this operation? [y/N]          │
└─────────────────────────────────────────┘
```

---

## Comparison with Agent Sandbox

### Security Model

**Google Agent Sandbox** uses gVisor, which intercepts syscalls in userspace:
```
App → Sentry (Go) → Host Kernel
         ↓
    Filters ~300 syscalls
```

**Nucleus** uses Firecracker with full hardware virtualization:
```
App → Guest Kernel → Firecracker VMM → KVM → Host Kernel
                          ↓
                   ~50K lines Rust
                   Minimal device model
```

### When to Choose Nucleus

Choose Nucleus when you need:
- **Hardware isolation**: Defense against kernel exploits
- **Permission governance**: Fine-grained capability control beyond RBAC
- **Compliance**: SOC2, HIPAA, NIST frameworks requiring VM-level isolation
- **Prompt injection defense**: Automatic uninhabitable state detection

Choose Agent Sandbox when you need:
- **Faster iteration**: Lighter weight for development
- **GKE integration**: Native warm pools and pod snapshots
- **Higher density**: More sandboxes per node

---

## Roadmap: Native CRDs

We're working on native Kubernetes CRDs to match Agent Sandbox ergonomics:

```yaml
# Coming soon
apiVersion: nucleus.io/v1
kind: NucleusSandbox
metadata:
  name: my-agent
spec:
  profile: fix-issue
  workDir: /workspace
  image: python:3.12-slim

  # Lattice-guard permissions
  permissions:
    capabilities:
      read_files: always
      run_bash: low_risk
    paths:
      allowed: ["/workspace/**"]
      blocked: ["**/.env", "**/*.pem"]
    budget:
      max_cost_usd: 5.00
---
apiVersion: nucleus.io/v1
kind: NucleusSandboxClaim
metadata:
  name: agent-session
spec:
  templateRef: my-agent
  ttl: 1h
```

Track progress: [GitHub Issues](https://github.com/coproduct-opensource/nucleus/issues)

---

## Next Steps

- [Permission Model Deep Dive](../permissions.md)
- [Threat Model](../architecture/threat-model.md)
- [Enterprise Use Cases](../use-cases/enterprise-ai-agents.md)
