# Public certificate-verifier publication prerequisites, 2026-11-09

The initial mandatory root audit refused publication with three vulnerabilities
and an unmaintained dependency warning. No audit policy or advisory ignore was
changed. The updated 1,072-package lockfile reports zero vulnerabilities and no
warnings against advisory database commit
`d9cb059f3217db87aeccd190b81eaffe8cc29cb9` (1,430 advisories).

- MCP consumers use rmcp 3.9 rather than 2.2, covering RUSTSEC-2026-0457 and
  RUSTSEC-2026-0462. The API alias is now `ServerConfig`. The exact wire-shape
  test failed on the added `resultType: "complete"`; it now pins that completed
  result discriminator alongside the unchanged content/error fields. The full
  ctf-server, ctf-mcp and tool-proxy all-features test invocation passes, including
  665 tool-proxy tests and its integration tests. Four existing tests remain
  ignored; no test was newly ignored or filtered for this upgrade.
- Released SQLx 0.9.0 excludes the patched libsqlite3-sys release. SQLx is pinned
  to upstream `ae659a0ca4e5e6708e589abc216f734deddb8e29`, whose actual fetched
  sqlx-sqlite manifest permits `>=0.30.1, <0.40.0`; the lock selects patched
  libsqlite3-sys 0.39.1 for RUSTSEC-2026-0459. All 51 public verifier-service
  tests pass. This is the existing public Nucleus service, not a Gatehouse
  persistence implementation or exception to Gatehouse's SQLite ban.
- Updating compatible AWS SDK releases (S3 1.158.0, config 1.13.1 and their
  Smithy dependencies) removes pin-utils entirely. Updating Smithy HTTP/runtime
  alone did not select their newer family; updating the SDK consumers did.

Primary upstream sources: [SQLx pinned manifest](https://github.com/launchbadge/sqlx/blob/ae659a0ca4e5e6708e589abc216f734deddb8e29/sqlx-sqlite/Cargo.toml),
[rmcp release](https://crates.io/crates/rmcp/3.9.0), and
[AWS release notes](https://github.com/awslabs/aws-sdk-rust/releases).

## Host validation finding

Rust 1.96.1 on this Mac with Apple ld 27106.1 and debug info disabled linked
the SQLx macro into a dylib dyld rejected with `mis-aligned LINKEDIT string
pool, fileOffset=0x00650C64`. Cleaning/rebuilding the package reproduced it;
selecting the classic linker did not fix it. Keeping that procedural macro
unstripped (`-C strip=none`) did. The local Rust compiler wrapper passes through
the pinned compiler and every argument, adding only those two arguments when
`--crate-type proc-macro` is present. It changes neither test selection nor
application code. This is a measured host workaround, not a claim about every
Mac or Linux release build. Source and logs are retained in the local evidence
directory and operating-context record.

Evidence under `/private/tmp/studio-proof`: `public-root-audit-clean.json`,
`public-rmcp-{check,tests,tests-restored}.log`,
`public-sqlx-{tests-restored,tests-classic,tests-unstripped}.log`, and the Rust
`classic_proc_macro_linker.rs` source (the final executable is named
`unstripped-proc-macro-linker`; the earlier classic-linker experiment failed).

Publication still requires the complete mandatory `cargo xtask prepush` result.
These targeted results do not establish a green workspace or deployment. The
certificate implementation still covers Equipment identity migrations only;
Keep, other app families and further migration classes remain open.
