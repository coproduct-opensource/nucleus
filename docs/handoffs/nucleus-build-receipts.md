# Nucleus builds and GitHub receipt trust — implementation progress

Objective: execute the full 2026-09-12 review in
`scratchpad/nucleus-on-nucleus-review-2026-09-12.md` in the primary checkout.
Implementation branch: `feat/nucleus-build-receipts`, based on receipt-store PR
#2878 (`5eecd8fe2`). The existing GitHub merge queue remains authoritative.

## Implemented and checked

- `nucleus-ci-verdict::verify` authenticates against a controller-supplied key,
  checks issuer/session, exact action/context/tree/pod and an issuance window,
  and refuses inconsistent success/exit-status claims.
- `VerifiedCiVerdict` has a private constructor and is neither deserializable
  nor clonable. It is intended to be consumed by the future publisher.
- 12 unit/integration tests and one compile-fail doctest pass. All-target,
  all-feature Clippy passes with warnings denied.
- Removing the run-binding comparisons made
  `signed_claims_for_another_run_are_refused` fail against a signed claim for
  another action. Restoring them made the suite pass (A-19).

This is a consumer boundary, not yet a production caller or build attestation.
The controller still needs a complete environment identity and authoritative
execution observation. No receipt is being published as a GitHub check yet.

## Execution finding, 2026-09-12

`nucleus-tool-proxy::start_and_drain_workload` starts a child and drains its
stdout/stderr. Both serving branches hold the child in `_workload`; neither
waits for its result. Guest execution calls `bound.serve(app).await` and writes
the exit report only after server shutdown. Consequently the next change must
observe workload completion explicitly. The VMM's exit status is not the build
command's exit status. Signing the node's existing `Built.exit_code` would not
close this gap.

The mediator already launches through `WorkloadLaunch::admit` and
`spawn_admitted`, with cleared environment, separate uid/gid and dropped
capabilities. Preserve that path. Investigate an authenticated completion
channel from this protected supervisor to the host; the workload must not be
able to forge a successful report by writing a file or contacting vsock itself.

## Remaining acceptance work (none complete yet)

1. Protected supervisor observation, output/log hashing and a host-signed typed
   CI receipt bound to source commit/tree, gate, environment and architecture.
   Demonstrate a real `cargo build --locked -p nucleus-node` in a microVM,
   including negative cases and measured cold/warm wall time.
2. Nucleus execution backend and explicit receipt conversion in gatehouse;
   verifier-backed informational `nucleus/build` checks for PR updates and
   `merge_group.checks_requested`, with exact-SHA and retry/cancellation tests.
3. After live red/green proof, bind the required check to the App ID and update
   repository pins together. Existing checks and GitHub queue remain in place.
4. Run a subsequent build using the verified first build's executor artifact,
   with explicit bootstrap/toolchain/image digests.
5. Connect miss/run/verify/store, then earn cross-tree reuse through host-derived
   read restrictions and complete resolved environment binding. Demonstrate
   unrelated-edit hits and relevant-input misses and sample hits by rerunning.
   Reconcile runbooks and prepare queue-ownership options and rollback only
   after these prerequisites; do not silently transfer merge ownership.

Public nucleus execution and base receipt verification must remain usable
without private gatehouse. Optional certificates must stay optional.
