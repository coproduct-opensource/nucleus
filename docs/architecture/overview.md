# Architecture Overview (25k plan)

## Goals
- Enforce all side effects via a policy-aware proxy inside a Firecracker VM (Firecracker driver).
- Default network egress to deny; explicit allowlists only (guest iptables).
- Approvals require signed tokens issued by an external authority (roadmap).
- Provide verifiable audit logs for every operation (optional signing today).

## Trust Boundaries

```
Agent / Tool Adapter
  |  (optional signed HTTP)
  v
Host Control Plane (nucleus-node + optional signed proxy)
  |  (vsock bridge, no guest TCP)
  v
Firecracker VM (nucleus-tool-proxy + enforcement runtime)
  |  (cap-std, Executor)
  v
Side effects (filesystem/commands)
```

### Boundary 1: Agent -> Control Plane
- If enabled, requests are signed (HMAC; asymmetric is roadmap).
- Control plane forwards only to the VM proxy.

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
- Optionally starts a signed proxy on 127.0.0.1.

### approval authority (host, separate process, roadmap)
- Issues signed approval tokens.
- Logs approvals with signatures.
- Enforces replay protection and expiration.

### nucleus-tool-proxy (guest)
- Enforces permissions (Sandbox + Executor).
- Requires approvals for gated ops (counter-based today; tokens are roadmap).
- Writes audit log entries (optional signing).

### policy model (shared)
- Capability lattice + obligations.
- Normalization (nu) enforces trifecta constraints.

## Data Flows

### Tool call
1. Adapter signs request (if enabled).
2. Signed proxy injects auth headers (if enabled).
3. Proxy enforces policy and executes side effect.
4. Audit log records action (and optional signature).

### Approval
1. Agent requests approval.
2. Proxy records approval count for the operation.
3. Approval count is consumed for gated ops.

## Non-goals (initial)
- Multi-tenant scheduling across hosts.
- Full UI control plane.
- Zero-knowledge attestation.

## Invariants (current + intended)
- Side effects should only happen inside `nucleus-tool-proxy` (host should not perform side effects).
- Firecracker driver should only expose the signed proxy address to adapters.
- Guest rootfs is read-only and scratch is writable when configured in the image/spec.
- Network egress is denied by default when `net.allow`/`net.deny` are present in the image.
