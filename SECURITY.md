# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in nucleus, please report it responsibly.

### How to Report

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Email security concerns to: security@coproduct.dev
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: Within 48 hours of your report
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 7 days
  - Medium: 30 days
  - Low: 90 days

### Scope

The following are in scope for security reports:

- **nucleus-node**: The Firecracker VM orchestrator
- **nucleus-cli**: The command-line interface
- **lattice-guard**: Permission and capability enforcement
- **nucleus-tool-proxy**: Request signing and validation
- **nucleus-audit**: Audit log integrity

### Out of Scope

- Vulnerabilities in dependencies (report to upstream maintainers)
- Social engineering attacks
- Physical attacks
- Denial of service via resource exhaustion (unless trivially exploitable)

## Security Design

Nucleus implements defense-in-depth:

1. **Firecracker microVMs**: Hardware-isolated sandboxes with minimal attack surface
2. **HMAC-SHA256 signing**: All requests between components are cryptographically signed
3. **Capability-based access**: Filesystem access restricted via cap-std
4. **Lattice permissions**: Mathematical enforcement of permission boundaries
5. **Audit logging**: Cryptographically chained logs for forensic analysis

See [docs/architecture/security.md](docs/architecture/security.md) for detailed security architecture.
