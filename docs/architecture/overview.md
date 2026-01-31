# Architecture Overview (25k plan)

## Goals
- Enforce all side effects via a policy-aware proxy inside a Firecracker VM.
- Default network egress to deny; explicit allowlists only.
- Approvals require signed tokens issued by an external authority.
- Provide verifiable audit logs for every operation.

## Trust Boundaries

```
Agent / Tool Adapter
  |  (signed HTTP)
  v
Host Control Plane (nucleus-node + approval authority)
  |  (vsock, no TCP)
  v
Firecracker VM (nucleus-tool-proxy + enforcement runtime)
  |  (cap-std, Executor)
  v
Side effects (filesystem/commands)
```

### Boundary 1: Agent -> Control Plane
- All requests are signed (HMAC or asymmetric in later phases).
- Control plane validates signatures and forwards only to the VM proxy.

### Boundary 2: Control Plane -> VM
- Use vsock only (no guest NIC by default).
- The guest sees only proxy traffic, not host network.

### Boundary 3: VM -> Host
- No host filesystem access except mounted scratch.
- Rootfs is read-only; scratch is per-pod and limited.

## Components

### nucleus-node (host)
- Pod lifecycle (Firecracker + resources).
- Starts vsock bridge to the proxy.
- Applies cgroups/seccomp to the VMM process.

### approval authority (host, separate process)
- Issues signed approval tokens.
- Logs approvals with signatures.
- Enforces replay protection and expiration.

### nucleus-tool-proxy (guest)
- Enforces permissions (Sandbox + Executor).
- Requires approval tokens for gated ops.
- Writes signed audit log entries.

### policy model (shared)
- Capability lattice + obligations.
- Normalization (nu) enforces trifecta constraints.

## Data Flows

### Tool call
1. Adapter signs request.
2. Control plane validates signature.
3. Proxy enforces policy and executes side effect.
4. Audit log records action + signature.

### Approval
1. Agent requests approval (signed).
2. Authority validates and issues token.
3. Token is presented to proxy for gated op.

## Non-goals (initial)
- Multi-tenant scheduling across hosts.
- Full UI control plane.
- Zero-knowledge attestation.
