# Objective

## Primary goals
1. Developer ergonomics
2. Strong mathematical security formalization
3. Practical real-world hardening (seccomp, Firecracker, etc.)

## Ancillary goals
1. Demonstrate modern Rust best practices for security-oriented systems
2. Enable secure execution of untrusted code/agents while preventing the lethal trifecta
3. Provide a theoretical basis for running Clawdbot securely

## Mandates
1. Keep the license allowlist narrow; avoid dependencies that require OpenSSL or CDLA-Permissive-2.0 (e.g., removing the optional network stack until a compliant alternative exists).
