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
  libsqlite3-sys 0.39.1 for RUSTSEC-2026-0459. Its 56 library, one binary and
  51 integration tests pass. This is the existing public Nucleus service, not a Gatehouse
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

The complete prepush then passed audit, scorecard, strict line limits and fmt.
It exposed a signature-metric false positive and exhausted local disk while
compiling workspace-wide affected tests (the root lockfile correctly selects
the entire workspace). The metric counted the extracted P-256 `.verify` as an
Ed25519 permissive call, although ECDSA has no `verify_strict` API. The baseline
remains eleven. The AST classifier recognizes only an explicitly qualified,
immutable, uniquely bound `::p256::ecdsa::VerifyingKey`; aliases, mutable or
shadowed bindings, parse failures and opaque binding macros remain unknown and
counted. The conservation guard still counts the P-256 verification. Real
prepush evidence before the correction is red at twelve. Scoreboard tests retain
Ed25519 and unknown-call detection. This is conservative source syntax analysis,
not a Rust type checker or a proof of cryptographic correctness.

The classifier touches a guardrail and therefore requires the owner's normal
signed approval for merge. No signature is fabricated by the agent.

The full task-runner suite also refused the two new standalone workspaces and
the unlisted public nanoda source. They are now registered in the existing
satellite/public-upstream tables, alongside the pinned upstream SQLx family.
The suite then passed 669 unit and two CLI tests. While extending that table,
the graph's old `starts_with` URL comparison was found to admit repositories
such as an enumerated URL plus `-private`. A new test fails (exit 101) on that
exact old comparison and passes with exact repository matching after removing
Cargo's rev/commit suffix. The crate name must still match. This strengthens
source identity; it does not infer that a repository will stay public forever.
The success message now names the enumerated public-source allowance rather
than claiming that every dependency is crates.io or in-tree.

## Existing embedded SDK prerequisite

All-features tests also require the existing verifier SDK's generated package.
A local wasm-pack 0.15/no-opt build did not match either accepted artifact;
the pins were not changed. The documented canonical inputs reproduced both
accepted CI bytes in an isolated Apple container: Rust 1.96.1 on cached
`rust:1.96.1-bookworm` (image index
`sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663`),
official wasm-pack 0.13.1, source at `/home/runner/_work/nucleus/nucleus`,
Cargo home `/home/runner/.cargo`, and the existing gate's x86 host-metadata
normalization while the compiler executes on arm64. wasm-bindgen's official
release and wasm-opt are selected by that pinned wasm-pack, as in the gate.
The build completed in 34.20s, yielding:

```
55ec10a781572a9c0d75379dc1c4491063ac3a84b05e8da1677be522d051f825  nucleus_verifier_wasm_bg.wasm
8d29fea6bd0827ae40c6d058f5a1a76397eaf57cfe5a4d43d8df5f4119ad81ad  nucleus_verifier_wasm.js
```

These digests were computed from generated files and compared with the existing
pins; no new accepted digest was added. The temporary builder was stopped and
deleted; the pre-existing builder inspected during discovery was returned to
its stopped state. The cached `gatehouse-builder:2` image contains janitor tools,
not Rust/gate-tools; its name was insufficient evidence to select a builder.
The old documented public verifier domain did not resolve, so it supplied no
artifact. Canonical source/build provenance, not an unverified download, supplied
the accepted bytes. Evidence: `public-sdk-canonical-linux.log` and the generated
ignored `sdks/verifier-js/pkg`.

Workspace-wide prepush still exhausted this Mac's remaining disk during native
test linking, despite debug info and incrementality already being off. A fresh
task-only cache with native test symbols stripped is the next validation mode;
it retains the same pinned compiler, features, test selection and SDK pins.
Procedural macros remain unstripped for the measured host loader issue above.
This is storage management, not a successful prepush result.

Publication still requires the complete mandatory `cargo xtask prepush` result.
These targeted results do not establish a green workspace or deployment. The
certificate implementation still covers Equipment identity migrations only;
Keep, other app families and further migration classes remain open.
