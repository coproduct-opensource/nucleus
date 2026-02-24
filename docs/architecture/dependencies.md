# Dependency Architecture

Nucleus maintains strict architectural principles for dependency selection, ensuring vendor neutrality, security, and long-term maintainability.

## Selection Criteria

All Nucleus dependencies must satisfy:

1. **Vendor Neutrality**: No Anthropic, OpenAI, or vendor-specific SDKs
2. **Security**: Active maintenance, strong audit history, no known CVEs
3. **Open Standards**: gRPC, Protobuf, X.509, SPIFFE, CEL (not proprietary protocols)
4. **Pure Rust**: Cryptographic libraries avoid C FFI when possible
5. **Stable APIs**: Minimize breaking changes in patch releases
6. **Minimal Dependencies**: Prefer crates with shallow dependency trees

## Core Security Libraries

These libraries form the cryptographic foundation and are heavily audited:

### TLS & Cryptography

| Crate | Version | Purpose | Rationale |
|-------|---------|---------|-----------|
| `rustls` | 0.23.36 | TLS 1.2/1.3 implementation | Pure Rust, no OpenSSL, audited by Mozilla |
| `ring` | 0.17.14 | AEAD, hashing, key derivation | Well-audited cryptographic primitives |
| `sha2` | 0.10.9 | SHA-256/512 hashing | RustCrypto project, standard algorithm |
| `hmac` | 0.12.1 | HMAC signing | RustCrypto, used for request signatures |
| `zeroize` | 1.8.2 | Memory wiping | Prevents secrets from leaking in memory dumps |
| `hex` | 0.4.3 | Hex encoding | Standard library for binary representations |

### Identity & Certificates

| Crate | Version | Purpose | Rationale |
|-------|---------|---------|-----------|
| `x509-parser` | 0.18.1 | X.509 certificate parsing | Nom-based parser, `verify` feature enabled for validation |
| `rustls-pki-types` | 1.10.1 | PKI type definitions | Standard Rustls types for certificates |
| `rustls-pemfile` | 2.2.0 | PEM file parsing | Standard library for certificate files |

### JSON & Serialization

| Crate | Version | Purpose | Rationale |
|-------|---------|---------|-----------|
| `serde` | 1.0.228 | Serialization framework | Industry standard, zero-copy design |
| `serde_json` | 1.0.132 | JSON support | Essential for gRPC JSON transcoding |
| `serde_yaml` | 0.9.36 | YAML support | Configuration parsing |
| `toml` | 0.8.19 | TOML support | Cargo.toml compatibility |
| `prost` | 0.14 | Protobuf serialization | Rust-native Protobuf implementation |

## Protocol & API Libraries

### gRPC & HTTP

| Crate | Version | Purpose | Rationale |
|-------|---------|---------|-----------|
| `tonic` | 0.14.4 | gRPC framework | Tokio-integrated, uses rustls for TLS |
| `tonic-prost` | 0.14 | Tonic/Prost bridge | Generated code support |
| `axum` | 0.8.8 | Web framework | Composable middleware, minimal overhead |
| `reqwest` | 0.12 | HTTP client | Feature-rich, rustls support |
| `hyper` | 1.8 | HTTP primitives | Foundation for tonic, axum, reqwest |

### Data Formats

| Crate | Version | Purpose | Rationale |
|-------|---------|---------|-----------|
| `uuid` | 1.21 | UUID generation | Includes cryptographically secure v4 |
| `chrono` | 0.4.41 | Date/time handling | Industry standard time library |
| `rust_decimal` | 1.40 | Precise decimals | Financial calculations without floating point |

## Async Runtime

| Crate | Version | Purpose | Rationale |
|-------|---------|---------|-----------|
| `tokio` | 1.49 | Async runtime | Industry standard, production-proven |
| `tokio-rustls` | 0.26 | Tokio + rustls integration | Native async TLS |
| `tokio-test` | 0.4 | Testing utilities | Deterministic async testing |

## Utility Libraries

| Crate | Version | Purpose | Rationale |
|-------|---------|---------|-----------|
| `clap` | 4.5 | CLI parsing | Derive macros, environment variable support |
| `tracing` | 0.1 | Structured logging | Composable subscriber system |
| `tracing-subscriber` | 0.3 | Tracing subscribers | JSON output for audit trails |
| `anyhow` | 1.0.101 | Error handling | Ergonomic error propagation |
| `thiserror` | 2.0 | Typed errors | Compile-time error definitions |
| `cap-std` | 4.0.2 | Capability-based I/O | Path traversal prevention |
| `shell-words` | 1.1 | Shell parsing | Safe command line argument handling |
| `regex` | 1.12 | Pattern matching | PCRE-compatible, optimized DFA |

## Special Dependencies

### AWS-LC Integration

```
aws-lc-rs 1.15.4
  ↓ (used only for cryptographic primitives)
  ↓ (via jsonwebtoken, not for AWS API integration)
  ├─ SPIFFE certificate validation
  ├─ X.509 verification
  └─ NOT for AWS service communication
```

**Architectural Note**: AWS-LC is used exclusively for its cryptographic algorithm implementations. Nucleus does not use AWS APIs or integrate with AWS services. The choice of FIPS-validated algorithms reflects security hardening, not AWS-specific concerns.

### CEL (Common Expression Language)

```
cel-parser 0.4 + celest 0.1
```

**Architectural Rationale**: CEL is a vendor-neutral policy language used by:
- Google (Kubernetes, gRPC)
- OWASP (authorization policies)
- IAM standards

CEL is NOT:
- Proprietary to any vendor
- Tied to OpenAI, Anthropic, or other LLM providers
- Limited to AI use cases

Policies written in CEL can be evaluated by any CEL runtime, ensuring portability.

## Dependency Audit Results (February 2026)

### Security Status

✅ **No Known CVEs**: All dependencies are at current versions with no active security advisories.

✅ **All Libraries Maintained**: Active maintainers across all critical dependencies.

✅ **Pure Rust Foundation**: Cryptographic core avoids C FFI, eliminating entire classes of vulnerabilities.

### Version Status

| Category | Status |
|----------|--------|
| Major versions | Current (within 1 major version of latest) |
| Security updates | All applied |
| Breaking changes | None in critical dependencies (patch-level only) |
| Deprecations | None pending for next 12 months |

### Testing Infrastructure

```
cargo-deny        → License and vulnerability scanning
cargo-audit       → CVE database integration
cargo-clippy      → Linting and code quality
proptest          → Property-based testing
```

## Vendor Neutrality Verification

### ✅ PASS: Credential Handling

```rust
// Nucleus: Vendor-agnostic
pub struct CredentialsSpec {
    pub env: BTreeMap<String, String>,  // Any key-value pairs
}

// NOT in Nucleus: Vendor-specific
// pub claude_api_key: Option<String>,
// pub openai_api_key: Option<String>,
```

### ✅ PASS: Permission System

```rust
// Work-type based policies (vendor-agnostic)
["codegen", "research", "review"]

// NOT: Vendor-specific policy names
// ["claude_coding_policy", "openai_tool_use"]
```

### ✅ PASS: Protocols & Standards

```
Used in Nucleus:           NOT in Nucleus:
├─ gRPC                    ├─ Anthropic APIs
├─ Protobuf                ├─ OpenAI APIs
├─ SPIFFE mTLS             ├─ Vendor SDKs
├─ X.509 certificates      └─ Proprietary formats
├─ CEL policies
└─ OpenID Connect
```

## Maintenance Strategy

### Update Cadence

| Level | Frequency | Process |
|-------|-----------|---------|
| **Security patches** | Immediate | Critical PR, direct merge after review |
| **Minor updates** | Monthly | Batch updates, test suite verification |
| **Major updates** | Quarterly | Planned, breaking change assessment |
| **Deprecations** | Annual | Planned migration, 6-month notice |

### Breaking Change Policy

For dependencies in the `[workspace.dependencies]` section:

1. **Patch versions** (0.x.y → 0.x.z): Automatically compatible
2. **Minor versions** (0.x → 0.y): API-compatible, internal changes only
3. **Major versions** (x → y): Full review required, coordinated upgrade across all crates

### Testing Before Update

```bash
# Before upgrading a dependency:
1. Check changelog for breaking changes
2. Run full test suite locally
3. Verify MSRV (Minimum Supported Rust Version)
4. Test with miri for undefined behavior
5. Build all workspace crates
```

## Adding New Dependencies

### Approval Checklist

Before adding a dependency, ensure:

- [ ] **Necessity**: Is this truly required? Consider writing 20 lines of code instead.
- [ ] **Alternatives**: Have alternatives been evaluated?
- [ ] **Vendor Neutrality**: Does it reference Anthropic, OpenAI, or other vendors?
- [ ] **Maintenance**: Is the crate actively maintained (commits in last 6 months)?
- [ ] **Security**: No known CVEs or security advisories
- [ ] **Size**: Minimal dependency tree (`cargo tree --depth 3`)
- [ ] **License**: MIT, Apache-2.0, or compatible
- [ ] **MSRV**: Compatible with our minimum Rust version (1.80)

### Adding to Workspace

```toml
# Add to [workspace.dependencies]
new_crate = "1.0"

# Then reference in individual crates
[dependencies]
new_crate.workspace = true
```

This ensures:
- Version pinning at one location
- Preventing duplicate versions in dependency tree
- Coordinated updates across all crates

## Security Scanning

### Local Scanning

```bash
# Check for known CVEs
cargo audit

# Check licenses
cargo-deny check licenses

# Check for deprecated dependencies
cargo tree --depth 1 | grep deprecated
```

### CI/CD Integration

Every pull request:
1. Runs `cargo audit` against current CVE database
2. Validates all transitive dependencies
3. Checks for license compliance
4. Builds with MSRV (1.80)

## References

- [Cargo Security Advisories](https://rustsec.org/)
- [RustCrypto Crates](https://docs.rs/releases/search?query=rustcrypto)
- [Tokio Ecosystem](https://tokio.rs)
- [SPIFFE Specification](https://spiffe.io/)
- [CEL Language](https://github.com/google/cel-spec)
