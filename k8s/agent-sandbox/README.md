# Agent Sandbox Kubernetes Manifests

Kubernetes manifests for integrating [Agent Sandbox](https://github.com/kubernetes-sigs/agent-sandbox) with different runtime isolation options.

## Quick Start

### Option 1: gVisor (No KVM Required)

For local development or environments without KVM support:

```bash
# 1. Install Agent Sandbox controller
kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v0.1.0/manifest.yaml

# 2. Create gVisor RuntimeClass
kubectl apply -f gvisor-runtimeclass.yaml

# 3. Deploy example Sandbox
kubectl apply -f sandbox-gvisor-example.yaml

# 4. Verify
kubectl get sandbox gvisor-example
kubectl exec gvisor-example -- dmesg | head -3
# Should show: Starting gVisor...
```

### Option 2: Firecracker via Kata Containers (KVM Required)

For production environments with hardware VM isolation:

```bash
# 1. Label KVM-capable nodes
kubectl label nodes <node-name> katacontainers.io/kata-runtime=true

# 2. Install Kata Containers with Firecracker
helm repo add kata-containers https://kata-containers.github.io/kata-containers
helm install kata-fc kata-containers/kata-deploy \
  --namespace kata-system --create-namespace \
  --set hypervisor=fc

# 3. Install Agent Sandbox controller
kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v0.1.0/manifest.yaml

# 4. Create kata-fc RuntimeClass (if not created by Helm)
kubectl apply -f kata-fc-runtimeclass.yaml

# 5. Deploy example Sandbox
kubectl apply -f sandbox-firecracker-example.yaml

# 6. Verify
kubectl get sandbox firecracker-example
kubectl get pod firecracker-example -o jsonpath='{.spec.runtimeClassName}'
# Should show: kata-fc
```

## Files

| File | Description |
|------|-------------|
| `gvisor-runtimeclass.yaml` | RuntimeClass for gVisor (syscall filtering) |
| `kata-fc-runtimeclass.yaml` | RuntimeClass for Kata + Firecracker (hardware VM) |
| `sandbox-gvisor-example.yaml` | Example Sandbox using gVisor |
| `sandbox-firecracker-example.yaml` | Example Sandbox using Firecracker |
| `kustomization.yaml` | Kustomize config for environment overlays |

## Runtime Comparison

| Feature | gVisor | Kata + Firecracker |
|---------|--------|-------------------|
| Isolation type | Syscall filter | Hardware VM |
| KVM required | No | Yes |
| Memory overhead | ~50MB | ~130MB |
| Startup time | <1s | ~1-2s |
| Security level | Medium | High |
| Use case | Development | Production |

## Troubleshooting

### RuntimeClass not found

```bash
# Check if RuntimeClass exists
kubectl get runtimeclass

# Verify handler matches containerd config
kubectl describe runtimeclass gvisor
```

### Pod stuck in ContainerCreating

```bash
# Check events
kubectl describe pod <pod-name>

# Common issues:
# - "containerd-shim-runsc-v1 not found" -> Install gVisor shim
# - "kata-fc handler not found" -> Install Kata Containers
# - "/dev/kvm: no such file" -> Node doesn't have KVM support
```

### Sandbox not reaching Ready state

```bash
# Check Agent Sandbox controller logs
kubectl logs -n agent-sandbox-system -l app=agent-sandbox-controller

# Check Sandbox status
kubectl describe sandbox <name>
```

## See Also

- [Agent Sandbox Quickstart](../../docs/quickstart/agent-sandbox.md)
- [Kubernetes Quickstart](../../docs/quickstart/kubernetes.md)
- [Agent Sandbox GitHub](https://github.com/kubernetes-sigs/agent-sandbox)
