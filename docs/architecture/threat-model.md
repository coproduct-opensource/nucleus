# Threat Model (25k plan)

## Assets
- Host filesystem and secrets.
- Pod data (inputs, outputs, logs).
- Approval decisions and audit trail.
- Policy grants and enforcement state.

## Trust Assumptions
- Firecracker provides VM isolation from the host kernel.
- Host kernel is not compromised.
- Cryptographic primitives are implemented correctly.

## Adversaries
- Malicious prompt injection within agent inputs.
- Untrusted tool output or external content.
- Compromised adapter or malformed requests.
- Accidental operator misconfiguration.

## Threats by Boundary

### Agent -> Control Plane
- Replay of tool requests.
- Forged approvals.
- Tool call parameter tampering.

Mitigations
- Signed requests, nonce/timestamp with max skew.
- Approval tokens bound to operation + expiry.

### Control Plane -> VM
- VM proxy spoofing.
- Traffic interception.

Mitigations
- Vsock-only transport.
- VM-unique secret provisioned at boot.

### VM -> Host
- Escapes via shared filesystem.
- Excessive resource usage.

Mitigations
- Read-only rootfs, scratch-only write.
- Cgroup CPU/memory limits.
- Seccomp on VMM.

## Non-goals
- Side-channel resistance.
- Host kernel compromise.
- Zero-knowledge verification.
