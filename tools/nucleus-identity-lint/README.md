# nucleus-identity-lint

The `workload_identity_isolation` dylint pass — **FM-5's reachability leg**.

Nothing reachable from a workload-spawn root (`spawn_workload`, `workload_env`,
`start_if_configured`, `workload_egress_env`) may name identity material
(`SessionTaskToken`, `BrokerCapability`, `WorkloadCertificate`, `PrivateKey`,
`SandboxProof`, …). Closed forward under the call graph, the same machinery as
the sibling `nucleus-cb4a-lint`; calls that defeat static resolution are
reported, never skipped.

The three FM-5 legs compose and none is sufficient alone:

1. The Lean theorems (`IdentityMaterialNoninterferenceExtracted.lean`) prove
   the extracted delivery relation refuses identity material at the workload.
2. The binding tests (`nucleus-tool-proxy/src/workload.rs`) pin the model to
   `workload_env` pointwise, and the real-child test covers the map→child gap.
3. This pass keeps identity material out of the spawn path's call graph
   entirely, so a violating refactor fails CI before it fails a guest.

## Running it

Linux (the CI path — see `.github/workflows/dylint-separation.yml`):

```sh
cd tools/nucleus-identity-lint
cargo build --release
mv target/release/libnucleus_identity_lint.so \
   "target/release/libnucleus_identity_lint@nightly-2026-04-16-$(rustc -vV | grep host | cut -d' ' -f2).so"
cd ../..
DYLINT_LIBRARY_PATH=$PWD/tools/nucleus-identity-lint/target/release \
  cargo dylint --lib nucleus_identity_lint -p nucleus-tool-proxy
```

`cargo dylint` exits 0 even when a `Warn` lint fires; CI counts matches of
`reachable from a workload-spawn root` and fails on any — the same
exit-status trap the cb4a job documents.

## Pins

The lockstep triple (`nightly-2026-04-16`, `clippy_utils` rev `f6d3106…`,
`dylint 6.0.1`) is shared with every sibling lint. Do not bump one pin alone.

## UI tests

`tests/ui.rs` is `#[ignore]`d for the macOS SIP reason the siblings document;
no fabricated `ui/main.stderr` baseline is committed. On Linux, generate one
with `cargo test --test ui -- --ignored` and drop the ignore.
