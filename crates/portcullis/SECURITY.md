# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in portcullis, please report it responsibly.

**Email**: security@coproduct.one

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

## Security Model

Portcullis enforces the **uninhabitable state constraint**: certain capability combinations (private data access + untrusted content + exfiltration) are automatically gated behind approval obligations. This constraint:

- Is **always enforced on deserialization** (cannot be bypassed via malicious JSON)
- Is **private in production builds** (the `uninhabitable_constraint` field is `pub(crate)`)
- Can only be disabled via the `testing` feature (which should NEVER be enabled in production)

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full adversarial analysis.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| < 1.0   | No        |
