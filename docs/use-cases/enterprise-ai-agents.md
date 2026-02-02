# Enterprise AI Agents

> Compliance-ready AI agent execution with audit trails and NIST-aligned security.

## Enterprise Requirements

| Requirement | Challenge | Nucleus Solution |
|-------------|-----------|------------------|
| **Audit trails** | Prove what agent did and when | Cryptographic hash-chained logs |
| **Data isolation** | PII/PHI can't leak to LLM providers | Execution in air-gapped VM |
| **Least privilege** | Agents shouldn't have admin access | Capability-based permissions |
| **Secret management** | API keys must be rotated, protected | Keychain integration, 90-day rotation |
| **Incident response** | Forensic analysis after breach | Verifiable audit logs |

## Compliance Alignment

### SOC 2

| Control | Nucleus Feature |
|---------|-----------------|
| CC6.1 - Logical access | Lattice-guard permission boundaries |
| CC6.6 - System boundaries | Firecracker VM isolation |
| CC7.2 - Security events | nucleus-audit logging |

### HIPAA

| Safeguard | Nucleus Feature |
|-----------|-----------------|
| Access controls | Per-agent permission profiles |
| Audit controls | Cryptographic log verification |
| Integrity controls | Read-only rootfs, signed requests |
| Transmission security | HMAC-SHA256 request signing |

### NIST SP 800-57 (Key Management)

| Requirement | Implementation |
|-------------|----------------|
| Key generation | 32-byte cryptographically random secrets |
| Key storage | macOS Keychain (hardware-backed on Apple Silicon) |
| Key rotation | 90-day tracking with warnings |
| Key destruction | Secure deletion via Keychain API |

## Architecture: Enterprise Deployment

```
┌─────────────────────────────────────────────────────────────────┐
│  Enterprise Network                                              │
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐    │
│  │   AI Agent   │────▶│ nucleus-node │────▶│  Firecracker │    │
│  │  (internal)  │     │   cluster    │     │   VM pool    │    │
│  └──────────────┘     └──────────────┘     └──────────────┘    │
│         │                    │                    │             │
│         │                    ▼                    │             │
│         │             ┌──────────────┐            │             │
│         │             │ nucleus-audit│            │             │
│         │             │    (SIEM)    │            │             │
│         │             └──────────────┘            │             │
│         │                    │                    │             │
│         ▼                    ▼                    ▼             │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                     Audit Log Store                         ││
│  │  • Immutable append-only                                    ││
│  │  • SHA-256 hash chain                                       ││
│  │  • 7-year retention                                         ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Audit Log Format

```json
{
  "timestamp": "2026-01-31T14:23:45.123Z",
  "sequence": 1847,
  "previous_hash": "a3f2b1c4...",
  "event": {
    "type": "tool_execution",
    "agent_id": "agent-prod-047",
    "tool": "file_read",
    "target": "/workspace/report.csv",
    "result": "success",
    "bytes_returned": 4523
  },
  "signature": "hmac-sha256:e7d4a2f1..."
}
```

Verify log integrity:

```bash
nucleus-audit verify /var/log/nucleus/audit.log
# ✓ 1847 entries verified
# ✓ Hash chain intact
# ✓ No gaps detected
```

## Deployment Options

### On-Premises

```bash
# Kubernetes deployment
helm install nucleus nucleus/nucleus-node \
  --set replicas=3 \
  --set audit.storage=s3://company-audit-logs \
  --set secrets.backend=vault
```

### Cloud (AWS/GCP/Azure)

Nucleus runs on any Linux VM with KVM support:
- AWS: metal instances or Nitro-based (`.metal` suffix)
- GCP: N2 with nested virtualization enabled
- Azure: DCsv2/DCsv3 with nested virtualization

## Getting Started

1. **Security review**: Share [architecture docs](../architecture/overview.md) with InfoSec
2. **Pilot deployment**: Single agent, non-production data
3. **Audit integration**: Connect nucleus-audit to SIEM
4. **Production rollout**: Gradual migration with monitoring

Contact: security@coproduct.dev for enterprise support.
