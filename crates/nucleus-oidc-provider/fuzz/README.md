# nucleus-oidc-provider — fuzz harness

`cargo-fuzz` + `libfuzzer-sys` targets covering every untrusted-input
parsing boundary the OP exposes. Each target wraps a single parser in
a `fuzz_target!(|data: &[u8]| ...)` body whose only job is to never
panic — any crash uncovered is a directly exploitable DoS against the
public `/oauth/token` or the operator-supplied federation rules file.

## Targets

| Target | Boundary | Exploit class if it crashes |
|---|---|---|
| `form_body` | `serde_urlencoded` on the `/oauth/token` POST body | Public-endpoint DoS |
| `federation_toml` | `toml::from_str` → `FederationRules` | Deploy-time DoS (SIGHUP reload) |
| `jwk_json` | `serde_json` → `Jwk` → `public_key()` | Trust-bundle ingestion DoS |
| `spiffe_uri` | `CallSpiffeId::parse` + `from_wimse_uri` | DoS via subject_token `sub` claim |

## Requirements

- Nightly Rust toolchain (libfuzzer-sys requires `-Z` flags)
- `cargo install cargo-fuzz`
- LLVM toolchain (libFuzzer is upstream)

## Running

```bash
cd crates/nucleus-oidc-provider

# Quick smoke (10 seconds)
cargo +nightly fuzz run form_body -- -max_total_time=10

# Production cadence — 10 minutes per target on each PR touching the crate (acceptance b)
for t in form_body federation_toml jwk_json spiffe_uri; do
  cargo +nightly fuzz run "$t" -- -max_total_time=600
done

# Or with the seeded corpus only (smoke test with no random input)
cargo +nightly fuzz run form_body fuzz/corpus/form_body -- -runs=0
```

## Corpus

Each target ships with a seed corpus under `fuzz/corpus/<target>/`,
mirroring the KAT vectors in
`crates/nucleus-oidc-provider/tests/aims_interop.rs`. The fuzzer
mutates these seeds to find inputs that crash or hang.

Crashing inputs land in `fuzz/artifacts/<target>/crash-*` — report
those as security issues with full reproducers.

## CI integration (acceptance d)

Add to the OIDC provider CI workflow:

```yaml
- name: Fuzz token-exchange parser
  run: |
    cargo install cargo-fuzz
    cd crates/nucleus-oidc-provider
    for t in form_body federation_toml jwk_json spiffe_uri; do
      cargo +nightly fuzz run "$t" -- -max_total_time=600
    done
```

10-minute runs per target per PR. The workspace's existing nightly
toolchain CI track (used elsewhere for `cargo +nightly build`) is the
intended host.
