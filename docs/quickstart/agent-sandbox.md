# Agent Sandbox Integration

Run AI agent sandboxes on Kubernetes using [Agent Sandbox](https://github.com/kubernetes-sigs/agent-sandbox) with Firecracker isolation via Kata Containers.

## Overview

[Agent Sandbox](https://github.com/kubernetes-sigs/agent-sandbox) is a CNCF/Kubernetes SIG Apps project that provides Kubernetes-native primitives for running AI agents in isolated environments. It supports pluggable runtimes via the standard `runtimeClassName` field.

This guide covers two paths:

| Path | Runtime | KVM Required | Use Case |
|------|---------|--------------|----------|
| **Local (gVisor)** | `runsc` | No | Validate workflow on macOS/Windows |
| **Cloud (kata-fc)** | Firecracker | Yes | Production with hardware VM isolation |

## Comparison: Agent Sandbox vs Nucleus

| Feature | Agent Sandbox + gVisor | Agent Sandbox + kata-fc | Nucleus |
|---------|------------------------|-------------------------|---------|
| Isolation | Syscall filter | Firecracker VM | Firecracker VM |
| Memory overhead | ~50MB | ~130MB | ~5MB |
| Startup time | <1s | ~1-2s | <125ms |
| Permission model | Pod RBAC only | Pod RBAC only | Lattice-guard |
| Trifecta detection | No | No | Yes |
| Budget enforcement | No | No | Yes |

Use Agent Sandbox + kata-fc when you need:
- Standard Kubernetes CRD workflow
- Firecracker isolation without custom controllers
- Compatibility with existing k8s tooling (Argo CD, Flux)

Use Nucleus directly when you need:
- Fine-grained permission policies (lattice-guard)
- Automatic trifecta detection (prompt injection defense)
- Lower memory footprint and faster startup

---

## Local Testing: gVisor on kind (Intel Mac / No KVM)

This path validates the Agent Sandbox workflow without requiring KVM. Useful for development on Intel Macs or any system without nested virtualization.

### Prerequisites

- Docker Desktop running
- `kubectl` configured
- `kind` installed (`brew install kind`)

### Step 1: Download gVisor Binaries

```bash
# Create directory for gVisor binaries
mkdir -p /tmp/gvisor

# Download runsc (gVisor runtime)
curl -sL https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/runsc \
  -o /tmp/gvisor/runsc
chmod +x /tmp/gvisor/runsc

# Download containerd shim
curl -sL https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/containerd-shim-runsc-v1 \
  -o /tmp/gvisor/containerd-shim-runsc-v1
chmod +x /tmp/gvisor/containerd-shim-runsc-v1
```

### Step 2: Create kind Cluster

```bash
# Create kind config
cat > /tmp/kind-gvisor.yaml << 'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: /tmp/gvisor
    containerPath: /opt/gvisor
EOF

# Create cluster
kind create cluster --name agent-sandbox-test --config /tmp/kind-gvisor.yaml
```

### Step 3: Install gVisor in kind Node

```bash
# Copy binaries into the kind node
docker cp /tmp/gvisor/runsc agent-sandbox-test-control-plane:/usr/local/bin/runsc
docker cp /tmp/gvisor/containerd-shim-runsc-v1 agent-sandbox-test-control-plane:/usr/local/bin/containerd-shim-runsc-v1

# Configure containerd to use gVisor
docker exec agent-sandbox-test-control-plane bash -c '
cat >> /etc/containerd/config.toml << EOF

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
EOF
'

# Restart containerd
docker exec agent-sandbox-test-control-plane systemctl restart containerd

# Create RuntimeClass
kubectl apply -f - << 'EOF'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
EOF
```

### Step 4: Install Agent Sandbox

```bash
# Install Agent Sandbox CRDs and controller
kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v0.1.0/manifest.yaml

# Wait for controller to be ready
kubectl wait --for=condition=Ready pod -l app=agent-sandbox-controller \
  -n agent-sandbox-system --timeout=120s
```

### Step 5: Create Test Sandbox

```bash
kubectl apply -f - << 'EOF'
apiVersion: agents.x-k8s.io/v1alpha1
kind: Sandbox
metadata:
  name: gvisor-test
spec:
  podTemplate:
    spec:
      runtimeClassName: gvisor
      containers:
      - name: agent
        image: busybox:latest
        command: ["sleep", "infinity"]
EOF

# Watch for Ready status
kubectl wait --for=condition=Ready sandbox/gvisor-test --timeout=60s
```

### Step 6: Verify gVisor Isolation

```bash
# Confirm runtimeClassName
kubectl get pod gvisor-test -o jsonpath='{.spec.runtimeClassName}'
# Output: gvisor

# Verify gVisor kernel (look for "Starting gVisor...")
kubectl exec gvisor-test -- dmesg | head -5
# Output:
# [   0.000000] Starting gVisor...
# [   0.533579] Gathering forks...
# ...
```

### Cleanup

```bash
kubectl delete sandbox gvisor-test
kind delete cluster --name agent-sandbox-test
```

---

## Cloud Testing: Firecracker on KVM Cluster

This path provides hardware VM isolation using Firecracker via Kata Containers.

### Prerequisites

- Kubernetes cluster with KVM-enabled nodes (bare metal or nested virt)
  - GKE: Use `n2-standard-*` with nested virtualization enabled
  - EKS: Use metal instances (`m5.metal`, `c5.metal`)
  - On-prem: Nodes with `/dev/kvm` accessible
- `kubectl` configured
- Helm 3.x installed

### Step 1: Label KVM-Capable Nodes

```bash
# Identify nodes with KVM support
for node in $(kubectl get nodes -o name); do
  if kubectl debug $node -it --image=busybox -- test -c /dev/kvm 2>/dev/null; then
    echo "$node has KVM"
    kubectl label $node katacontainers.io/kata-runtime=true --overwrite
  fi
done
```

### Step 2: Install Kata Containers with Firecracker

```bash
# Add Kata Containers Helm repo
helm repo add kata-containers https://kata-containers.github.io/kata-containers
helm repo update

# Install Kata with Firecracker hypervisor
helm install kata-fc kata-containers/kata-deploy \
  --namespace kata-system --create-namespace \
  --set hypervisor=fc \
  --set runtimeClasses[0].name=kata-fc \
  --set runtimeClasses[0].handler=kata-fc

# Wait for DaemonSet rollout
kubectl rollout status daemonset/kata-deploy -n kata-system --timeout=300s

# Verify RuntimeClass exists
kubectl get runtimeclass kata-fc
```

### Step 3: Install Agent Sandbox

```bash
# Install Agent Sandbox CRDs and controller
kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v0.1.0/manifest.yaml

# Wait for controller
kubectl wait --for=condition=Ready pod -l app=agent-sandbox-controller \
  -n agent-sandbox-system --timeout=120s
```

### Step 4: Create Firecracker-Isolated Sandbox

```bash
kubectl apply -f - << 'EOF'
apiVersion: agents.x-k8s.io/v1alpha1
kind: Sandbox
metadata:
  name: firecracker-test
spec:
  podTemplate:
    spec:
      runtimeClassName: kata-fc
      containers:
      - name: agent
        image: python:3.12-slim
        command: ["sleep", "infinity"]
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
EOF

# Wait for Ready
kubectl wait --for=condition=Ready sandbox/firecracker-test --timeout=120s
```

### Step 5: Verify Firecracker Isolation

```bash
# Confirm kata-fc runtime
kubectl get pod firecracker-test -o jsonpath='{.spec.runtimeClassName}'
# Output: kata-fc

# Check for VM indicators in /proc/cpuinfo
kubectl exec firecracker-test -- cat /proc/cpuinfo | grep -E "(model name|hypervisor)"
# Should show hypervisor or QEMU-style CPU

# Verify Firecracker process on host (from node)
NODE=$(kubectl get pod firecracker-test -o jsonpath='{.spec.nodeName}')
kubectl debug node/$NODE -it --image=busybox -- ps aux | grep firecracker
```

---

## Agent Sandbox CRD Reference

### Sandbox

The core resource for creating isolated agent environments.

```yaml
apiVersion: agents.x-k8s.io/v1alpha1
kind: Sandbox
metadata:
  name: my-agent
spec:
  # Standard PodSpec template
  podTemplate:
    spec:
      runtimeClassName: kata-fc  # or gvisor
      containers:
      - name: agent
        image: my-agent:latest
        command: ["python", "agent.py"]
        env:
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: agent-secrets
              key: openai-key
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "2"

  # Persistent storage (survives restarts)
  volumeClaimTemplates:
  - metadata:
      name: workspace
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi

  # Lifecycle management
  shutdownPolicy: Delete  # or Retain
```

### SandboxTemplate (Extensions)

Reusable templates for common agent configurations.

```bash
# Install extensions
kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v0.1.0/extensions.yaml
```

```yaml
apiVersion: agents.x-k8s.io/v1alpha1
kind: SandboxTemplate
metadata:
  name: python-agent
spec:
  podTemplate:
    spec:
      runtimeClassName: kata-fc
      containers:
      - name: agent
        image: python:3.12-slim
        resources:
          requests:
            memory: "512Mi"
          limits:
            memory: "2Gi"
```

### SandboxClaim

Request a sandbox from a template.

```yaml
apiVersion: agents.x-k8s.io/v1alpha1
kind: SandboxClaim
metadata:
  name: my-session
spec:
  templateRef:
    name: python-agent
  ttl: 1h
```

---

## Troubleshooting

### Pod stuck in ContainerCreating

**gVisor**: Check for missing shim binary.
```bash
kubectl describe pod <pod-name> | grep -A5 Events
# Look for: "containerd-shim-runsc-v1": file does not exist
```

Fix: Ensure both `runsc` and `containerd-shim-runsc-v1` are in `/usr/local/bin/`.

**kata-fc**: Check for KVM access.
```bash
kubectl debug node/<node> -it --image=busybox -- ls -la /dev/kvm
# Should show: crw-rw---- 1 root kvm 10, 232 ...
```

### Sandbox stuck in Pending

Check if the controller is running:
```bash
kubectl get pods -n agent-sandbox-system
kubectl logs -n agent-sandbox-system -l app=agent-sandbox-controller
```

### RuntimeClass not found

Verify the RuntimeClass exists:
```bash
kubectl get runtimeclass
```

For gVisor, create manually:
```bash
kubectl apply -f - << 'EOF'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
EOF
```

---

## Next Steps

- [Kubernetes Quickstart](./kubernetes.md) - Deploy Nucleus directly on Kubernetes
- [Permission Model](../permissions.md) - Understanding lattice-guard policies
- [Threat Model](../architecture/threat-model.md) - Security analysis

## References

- [Agent Sandbox GitHub](https://github.com/kubernetes-sigs/agent-sandbox)
- [gVisor Documentation](https://gvisor.dev/docs/)
- [Kata Containers](https://katacontainers.io/)
- [Firecracker](https://firecracker-microvm.github.io/)
