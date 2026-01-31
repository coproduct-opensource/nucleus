# Acceptance Tests (25k plan)

## Enforcement
- Any filesystem access outside sandbox root is denied.
- Any command not in allowlist (or structured rules) is denied.
- Any approval-gated operation fails without a valid token.
- Budget exhaustion blocks further side effects.
- Time window expiry blocks execution.

## Trifecta
- When private data + untrusted content + exfil path are all enabled, approvals are required for exfil operations.

## Network
- Default: no network egress from the VM.
- Allowlisted egress only when explicitly configured.

## Audit
- Every tool call produces a signed audit log record.
- Approval tokens are logged with issuer + expiry.

## VM Isolation
- Rootfs is read-only.
- Scratch is mounted and size-limited.
- Proxy starts via init with no extra services.
