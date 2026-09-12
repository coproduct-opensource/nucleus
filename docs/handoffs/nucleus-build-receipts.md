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

## Supervisor observation implemented, 2026-09-12

The proxy now owns and waits for its admitted child on both serving transports,
draining both pipes concurrently and hashing every raw byte with SHA-256.
Signals, incomplete reads, missing pipes and unfinished workloads cannot be
represented as a successful exit. Dropping the server guard aborts observation
and drops the kill-on-drop child. Only the observer task can update the result.

The authenticated read-only `/v1/workload/result` route is exposed through the
node's lineage-checked `/v1/pods/{id}/workload-result` bridge. The node rejects
HTTP failures, malformed bodies and responses exceeding 16 KiB. This is unsigned
observation data; the future issuer must separately establish the execution
boundary and expected inputs before signing it.

Live local-driver evidence: a workload wrote a fake successful
`.nucleus-exit-report.json` and then exited 23; the node returned 23. A second
workload exited 0 and returned 0. Both hashes matched the actual `out` and `err`
streams. Both correctly reported `unconfined` on macOS. Their authority-inventory
launch hashes matched despite different commands; their program digests differed.
Program identity hashes declared inputs and is not proof of host measurement:
data/scratch pin completeness must still be checked by the CI admission path.

Validation: full proxy all-feature suite passed (449 unit tests plus integration
suites); the final five supervisor tests include invalid UTF-8 across multiple
buffer reads. The node's HTTP-error test, all-target/all-feature Clippy for both
crates, formatting and the line ratchet pass. Local sockets required sandbox
escalation. Temporary pods were cancelled and the test node stopped.

The existing quickstart boot workflow uses Ubuntu x86_64 runners with explicit
KVM/vhost-vsock checks. This is a concrete route for real microVM validation;
local-driver evidence does not satisfy that acceptance criterion.

## Remaining acceptance work (milestones not yet complete)

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
