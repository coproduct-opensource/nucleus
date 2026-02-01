# Architecture Overview (25k plan)

## Goals
- Enforce all side effects via a policy-aware proxy inside a Firecracker VM (Firecracker driver).
- Treat permission state as a static envelope around a dynamic agent.
- Default network egress to deny; explicit allowlists only (host netns iptables + guest defense).
- The node provisions a per-pod netns, tap interface, and guest IP; guest init configures eth0 from kernel args.
- Netns setup enables bridge netfilter (`br_netfilter`) so iptables can enforce guest egress.
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
- Use vsock only by default; guest NIC requires an explicit network policy and host enforcement.
- Host enforcement uses `nsenter` + `iptables` inside the Firecracker netns (Linux only).
- By default the guest sees only proxy traffic; optional network egress is allowlisted.

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
- Guest init (Rust) configures networking from kernel args and then `exec`s the proxy.
- Guest init emits a boot report into the audit log on startup.

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

## Progress Snapshot (Current)

**Working today**
- Enforced CLI path via MCP + `nucleus-tool-proxy` (read/write/run).
- Runtime gating for approvals, budgets, and time windows.
- Firecracker driver with default‑deny egress in a dedicated netns (Linux).
- Immutable network policy drift detection (fail‑closed on iptables changes).
- Audit log with hash chaining (tamper‑evident).

**Partial / in progress**
- Web/search tools not yet wired in enforced mode.
- Approvals are runtime tokens; signed approvals are planned.
- Kani proofs exist; CI gating and formal proofs are planned.

**Not yet**
- DNS allowlisting and IPv6 egress controls.
- Audit signature verification tooling.

## Invariants (current + intended)
- Side effects should only happen inside `nucleus-tool-proxy` (host should not perform side effects).
- Firecracker driver should only expose the signed proxy address to adapters.
- Guest rootfs is read-only and scratch is writable when configured in the image/spec.
- Network egress is denied by default for Firecracker pods when `--firecracker-netns=true`;
  if no `network` policy is provided, the guest has no NIC and iptables still default-denies.
- **Monotone security posture**: permissions and isolation guarantees should only tighten
  (or the pod is terminated), never silently relax after creation.
  - Seccomp is fixed at Firecracker spawn.
  - Network policy is applied once and verified for drift (fail‑closed monitor).
  - Permission states are normalized via ν and only tightened after creation.
