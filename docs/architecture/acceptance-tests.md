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
- Default: no network egress from the VM when `net.allow`/`net.deny` are present.
- Allowlisted egress only when explicitly configured.

## Audit (current)
- Every tool call produces an audit log record (optional signing).
- Approval events are logged with operation name and count.

## VM Isolation (current)
- Rootfs is read-only when configured in the image/spec.
- Scratch is mounted when configured.
- Proxy starts via init with no extra services.

## Roadmap Tests
- Approval tokens must be signed, bounded to op + expiry + nonce.
- Audits must include cryptographic signatures and issuer identity.
- Network egress must be enforced via cgroup/eBPF filters (not just guest iptables).
