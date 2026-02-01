# Acceptance Tests (25k plan)

## Enforcement (current)
- Any filesystem access outside sandbox root is denied (cap-std sandbox).
- Any command not in allowlist (or structured rules) is denied.
- Approval-gated operation fails without a recorded approval.
- Approval grants expire (default TTL, enforced when auth is enabled).
- Approval requests can be gated by a separate approval secret and nonce.
- Budget exhaustion blocks further side effects.
- Time window expiry blocks execution.

## Trifecta (current)
- When private data + untrusted content + exfil path are all enabled, approvals are required for exfil operations.

## Network (current)
- Host netns iptables enforces default-deny egress for Firecracker pods when `--firecracker-netns=true` (even without `spec.network`).
- Host monitors iptables drift and fails closed by terminating pods on deviation.
- Allowlisted egress only for IP/CIDR with optional port (no hostnames).
- Guest init configures eth0 from kernel args (`nucleus.net=...`) when a network policy is present.
- Node provisions tap + bridge inside the pod netns only when `spec.network` is set (guest NIC is otherwise absent).
- Integration: `scripts/firecracker/test-network.sh` boots a VM and verifies cmdline + iptables rules.
- Optional connectivity test uses `nucleus-net-probe` via the tool proxy (`CHECK_CONNECTIVITY=1`).

## Audit (current)
- Every tool call produces an audit log record (optional signing).
- Audit entries are hash-chained; tampering breaks the chain.
- Approval events are logged with operation name and count.
- Guest init emits a boot report entry on startup.

## VM Isolation (current)
- Rootfs is read-only when configured in the image/spec.
- Scratch is mounted when configured.
- Proxy starts via init with no extra services.

## Roadmap Tests
- Approval tokens must be signed, bounded to op + expiry + nonce.
- Audits must include cryptographic signatures and issuer identity.
- Network egress should be enforced via cgroup/eBPF filters (beyond iptables).
