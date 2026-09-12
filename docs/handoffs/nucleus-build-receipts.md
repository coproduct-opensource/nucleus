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

This authenticates the existing gate-verdict format. The execution body below
now also has a production node signer. A complete build verdict still needs
source/environment and artifact bindings. No receipt is published as a GitHub
check yet.

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
suites); the final six supervisor tests include invalid UTF-8 across multiple
buffer reads and preservation of boot-probe sentinels across split reads.
Console rendering retains ordinary lines and bounds oversized ones to 8192 bytes,
independently of the raw-byte hash. The node's HTTP-error test, all-target/all-feature Clippy for both
crates, formatting and the line ratchet pass. Local sockets required sandbox
escalation. Temporary pods were cancelled and the test node stopped.

The existing quickstart boot workflow uses Ubuntu x86_64 runners with explicit
KVM/vhost-vsock checks. This is a concrete route for real microVM validation;
local-driver evidence does not satisfy that acceptance criterion.

Before extending the signer, account for these existing seams: the node's
`image_identity::verify` measures placed kernel/rootfs/data pins just before
launch (only pins actually present are checked). Its `trust_gate` already owns
a persistent host-only Ed25519 executor signing key compatible with the shared
receipt envelope. `PodHandle::driver_state` records the actual spawned backend;
request labels are not evidence for it. `WorkloadLaunch::build` resolves four
inherited variables before admission, so the declared program digest alone is
not the resolved environment identity. The eventual build verifier must bind
that environment, require complete image/data pins and validate output hashes.

## Host-signed execution implemented, 2026-09-12

`GET /v1/pods/{id}/execution-receipt` now signs a completed supervisor result
with the existing persistent host-only executor key. Its versioned
`nucleus.execution.v1` CI body uses the existing `nucleus-receipt` envelope.
It binds pod, program identity, actual host driver, architecture, installed uid
boundary, normal/signal exit, raw output hashes and authority-inventory hash.
It has no build-success conclusion and does not claim source/environment/output
artifact evidence that has not been collected.

The node refuses unfinished observations and disagreement between host and
supervisor program identities. Firecracker receipts additionally require an
explicit read-only rootfs and complete kernel/rootfs/data/supplied-scratch pins;
the existing Firecracker spawn path measures those pins against placed bytes.
The public verifier authenticates against controller-supplied expectations and
refuses local, container and non-isolated guest results. Its private witness and
the earlier CI verdict witness now enforce a consumption deadline. They do not
constitute a build-publication right. Removing the microVM boundary check made
the signed-local refusal test fail, and restoring it made the suite pass.

The live mTLS local-driver path signed actual exit 23 for the fake-success-file
case and actual exit 0 for the successful case. OpenSSL independently verified
both signatures using the host's public key; changing the signed exit broke
verification. Both bodies explicitly identify local/unconfined execution.
Temporary pods were cancelled and the test node stopped.

That live test first caught a real identity defect: certificate verification
recomputes equivalent policy provenance, and command/path HashSets serialized in
arbitrary order. Policy serialization now orders those sets, and program identity
uses the existing semantic policy checksum. The domain is bumped to
`nucleus.pod-program.v2`; old program/snapshot identities intentionally miss.
An existing command-digest mutation test had changed between constructors with
identical commands and passed only because of random ordering. It now changes
an actual blocked command and checks that the policy changed.

Validation: all-feature suites pass for node (515 unit tests), proxy (451),
Portcullis (1273), spec, both receipt crates, and their integration/doc tests.
Clippy with warnings denied passes for node, proxy, spec and both receipt crates.
The scorecard now measures 3 bounded affine rights out of 9 and its floor has
ratcheted upward to 33.33%; the exemplar scoreboard also passes. Receipt
verification's explicit `verify_strict` spelling delegates to the same strict
Ed25519 implementation as the compatibility `verify` spelling.

For the real microVM build, use an image without a baked PodSpec. Guest init
already fetches the host spec over the workload API but intentionally prefers a
baked spec when one exists. A mismatched template should remain a signing refusal,
not be treated as the requested program. Resolved environment, artifact capture,
source materialization and actual build timings remain the next acceptance work.

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
