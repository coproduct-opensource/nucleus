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

## Resolved environment bound, 2026-09-12

The admitted launch now hashes the exact environment map passed after
`env_clear`, including resolved PATH/HOME/LANG/TZ. Its `inputs_sha256` omits only
the two values the mediator overwrites (`NUCLEUS_TOOL_PROXY_URL` and
`NUCLEUS_TOOL_PROXY_AUTH_SECRET`); `complete_sha256` commits every entry for the
individual attempt. Other runtime-looking names, including arbitrary
`NUCLEUS_EGRESS_*` keys, remain inputs. Values are never emitted in either
receipt. Both hashes travel through the supervisor result into the signed
execution body; verification requires the controller's independently derived
input digest. This is not cache-reuse permission: a workload can observe the
injected bindings, so ignoring their per-attempt differences additionally needs
a demonstrated noninterference boundary (for example a pinned build launcher
that omits them from the compiler's environment).

A test through build/admit/spawn compares the commitment with a real
`/usr/bin/env` child's output. Input-value, boundary-ambiguity and fake-runtime-name
tests pass, as does refusal of a signed execution with another environment input
digest. Spec/CI-verdict suites, the node projection tests and all-target,
all-feature Clippy for the affected runtime crates pass.

The next artifact step should use the existing sandbox's binary `open`/`read`
operations with a redeemed read decision and discharged authority, as the HTTP
text reader already does. Snapshot bounded artifact bytes after workload exit,
hash those same bytes on the host and bind the requested artifact manifest before
signing a complete build result. Do not replace this with a privileged arbitrary
file read. An offline ext4 reader was considered, but additionally requires
guest filesystem flush/finalization and a new host parsing/access boundary.

The existing x86_64 real-pod boot job passed for the draft; this does not yet
demonstrate a nucleus compile in that pod. The rootfs builder accepts a Debian
container base (`DEBIAN_IMAGE`), which can carry a pinned Rust toolchain. It
always bakes a PodSpec, so the build-image preparation must explicitly arrange
for the host-fetched spec to be used, rather than accidentally compiling the
image's template job.

## Artifact capture implemented, 2026-09-12

`POST /v1/pods/{id}/execution-receipt` accepts an artifact manifest such as
`{"artifacts":{"nucleus-node":"target/debug/nucleus-node"}}`. It establishes
pod lineage, checks that each selected name/path was declared in
`spec.workload.artifacts` at launch, and requires completed execution before
calling the proxy's mediated binary
reader. The response bundles standard-base64 artifact bytes with the shared
signed receipt; the execution body commits each name, relative path, byte count
and SHA-256 computed by the host from those exact bytes. Collection must finish
before signing. Missing files or failed reads never yield an empty success.

`Sandbox::read_bounded` consumes both a matching read decision and discharged
authority, applies capability/path checks through cap-std, opens nonblocking,
rejects non-regular files, and bounds the read even if the file grows. The proxy
also records the read outcome and treats output bytes as untrusted tool data.
Each artifact and the complete bundle are limited to 256 MiB of decoded bytes;
the node checks response length and streamed chunks. At most eight named relative
workspace outputs can be requested. No ambient privileged file-reading route or
disk mount was introduced.

`verify_artifacts` verifies execution against controller expectations, matches
the entire requested manifest, and checks every returned artifact's size and
digest. It alone constructs the private, deadline-bound `VerifiedArtifacts`.
Checking just the receipt cannot construct that witness. It proves the captured
bytes, not that the build passed: the observed exit remains part of the claim.

Live mTLS/local-driver evidence: binary output containing NUL and invalid UTF-8
survived collection unchanged. OpenSSL independently verified the host signature,
and independently computed size/hash matched the signed descriptor. Symlink
escape, parent traversal, absolute paths, missing files and FIFO collection all
returned refusals; the FIFO returned in 0.01 s. Pods were cancelled and the test
node stopped. This remains local integration evidence, not the required microVM
compile.

Validation: full all-feature suites passed for nucleus (80 unit tests), node
(515), proxy (452) and CI verdict, plus their integrations/docs. Two final node
tests additionally check manifests and an oversized chunked upstream response.
All-target/all-feature Clippy, formatting, strict line ratchet and scorecard pass.
The scorecard ratchets to 173/174 covered boundaries and 4/10 bounded affine
rights. Removing only the digest comparison let same-length altered bytes pass
and made the negative test fail; restoring it made the verifier suite pass.

Next priority is the real build harness: materialize the exact Git source into
declared pinned inputs, run the pinned toolchain with a declared environment in
a microVM, collect the nucleus binary through this API, and record cold/warm
timings. Source commit/tree and gate metadata still need an explicit signed
binding and controller verification. Do not mistake the green boot probe for
that build or the captured-artifact witness for GitHub publication authority.

Authority review tightened collection before completion of this step: receipt
readers may select only creator-declared exports, not arbitrary workspace paths.
The declaration is included in program identity; changing an exported path
changes the digest. Empty declarations preserve existing program identities and
export no files. A second live run collected the declared binary and refused
an existing undeclared file, a renamed export, a declared symlink escape and a
declared FIFO. Selection tests, 21 identity tests and Clippy pass after this change.

## Exact-tree build image preparation

`cargo xtask build-image` prepares a read-only root image containing the pinned
official Rust 1.96.1 linux/amd64 image, an exact Git commit export, vendored
dependencies and separately supplied bootstrap guest binaries. It records the
source commit/tree/archive hash, immutable OCI manifest, bootstrap hashes and
placed kernel/rootfs hashes in `inputs.json`. The kernel defaults to the existing
public Tier 2 pin; a custom kernel requires an explicit matching digest.
Preparation refuses branch names, abbreviated IDs, submodules and an existing
output directory. Cargo vendoring runs outside the source checkout with an
explicit toolchain, so repository Cargo configuration cannot select a host
compiler wrapper. No subject build script runs during preparation.

The initial exact-tree path puts source/vendor data in the root image because
guest init does not currently mount the host-supported read-only data disk.
The image has no baked pod spec: the host-fetched spec must select the build.
The existing quickstart workflow has a manual image-preparation lane; that lane
is not a compilation or execution-verification result. Local materialization
and config-relocation tests, Clippy and strict line ratchet pass. A Linux image
preparation run passed in Actions run `34713561240`: source commit
`1a921a3c161b5da6b6c1f985ae3ee8c56295aa1f`, tree
`41ecd661ff089b603b5b61dd5a2958926908f0ce`, rootfs SHA-256
`527772c41226e983460ae43b8ae2913eaecd0ec052d4642384a0c2d7ac69f3d3`.
Image preparation took 4m23s after the bootstrap binaries compiled. This is
image evidence, not a successful in-guest compilation.

`build-run` now launches two real builds (cold, then a new VM using the same
compiler-cache disk), derives expected program/environment identity before
launch, verifies signed exits and artifacts, and cancels each VM before reusing
its disk. The source commit/tree/archive and gate name are labels committed by
the program digest; command, image pins and explicit environment are committed
by that same digest. An operator-supplied signer key remains independent of the
receipt. The prepared image and controller record are trusted inputs; they are
not reconstructed from a returned claim. A failed build is preserved as a
signed failure, even if an old output exists on the cache disk.

The manual workflow runs this through `build-bootstrap`, which starts a
disposable node, mints its mTLS client identity, records the bootstrap node/VMM
hashes and public key, and kills/reaps the node after the experiment. The
Firecracker archive is pinned to a measured release digest. `build-evidence`
exports named public results and host console logs; it never recursively copies
the node state or its keys. Local request-binding/export tests and Clippy pass;
the real cold/warm experiment remains to be observed. No GitHub check publisher
or cache-hit authority is implied by these development commands.

The gatehouse review now names a separate `Substrate::Nucleus` with a
`NodeAttested` verifier ceiling and a typed exact-SHA event for PR
synchronization and `merge_group.checks_requested`. Its backend intentionally
refuses execution until the nucleus receipt schema adapter is implemented.

Admission also records requested/enforced/backend isolation labels. The build
controller must predict those before hashing its expected spec. Their rendering
now lives in `PodSpec::record_isolation`, used by both node admission and the
controller with the public enforcement resolver. The receipt cannot supply the
expected program identity. Node backend-clamp tests pass after this extraction.

Execution claims now carry explicit `source_commit`, `source_tree`, and `gate`
fields. The verifier compares all three to controller expectations in addition
to the program digest, making source provenance visible in the signed body.

Executor promotion must require a controller-approved, protected source and
artifact digest. A valid receipt for an arbitrary PR-produced executable is
not authority to run that executable with the production signer or App secrets.
Experiments with the draft can use disposable keys and explicit bootstrap
provenance; production executor trust stays pinned.

## Remaining acceptance work (milestones not yet complete)

Measured on 2026-09-12: self-build run `34715671237` failed during pod admission
because `br_netfilter` was not loaded. The refusal body named the missing
`/proc/sys/net/bridge/bridge-nf-call-iptables` file. Its separate KVM enforcement
lane passed. The workflow now loads that module along with `vhost_vsock`;
run `34716636960` exercises the correction. A module-setup pass is not evidence
that the self-build workload launched or returned a binary.

Run `34716636960` passed the separate KVM enforcement lane but its build guest
panicked during spec delivery. Downloaded `node.log` repeatedly reports
`path must be shorter than SUN_LEN`; the versioned Firecracker executable name
was incorporated into the jailer path and overflowed Linux's Unix-socket path
limit. The harness now copies the pinned executable to the short `firecracker`
basename and checks its longest socket path before starting the node. Five
build-image tests pass, including the failed layout's length and the corrected
one. A subsequent live build must still demonstrate guest startup and completion.

The controller now saves `expected-execution.json` before retrieving any receipt
and includes it in the named public evidence export. It contains only expected
bindings and the executor public key, never signing material. A consumer must
load that record from its trusted attempt store and independently pin the
executor key; receiving a matching expectation beside an untrusted receipt is
not sufficient to establish trust.

The next executor path is now implemented as `cargo xtask build-successor
--predecessor <protected-stage-one-directory> --source-commit <approved-commit>
--executor-public-key <independent-pin> --output <new-short-directory>`. It checks
the saved expectations, authenticates the artifact-bearing receipt, requires
exit zero and copies only verified bytes into an owner-only executable directory.
It rechecks the predecessor deadline immediately before launching the new node.
The successor receives fresh disposable node keys, and its public evidence export
includes `successor-provenance.json` linking the binary digest and predecessor
receipt root. It never imports the first node's signing material.

The owned `RecordedExecution` and borrowed verifier expectations now share one
field definition; round-trip and unknown-field tests cover the controller record
wire format. Six build-image tests (including successor refusal cases) and all
25 CI-verdict tests/doctests pass; strict Clippy passes for both crates. This is
implementation evidence only. A live predecessor build and successor execution
must still pass before milestone 4 can be claimed.

Run `34717924790` at `7b6e4bf15` completed with the self-build job failing.
The guest reached PID 1, received a reset while announcing the snapshot barrier,
failed to fetch its pod spec and exited. The node opened the workload API only
after starting the VMM and computing the image's launch attestation. A small
probe image had hidden this ordering problem; the 8 GiB build image did not.
The log does not yet establish the individual hashing durations.

`pod_boot_identity::prepare` now completes registration, attestation and the
workload API listener before the guarded VMM spawn. Listener failure refuses
launch. The preparation guard owns listener, certificate, registry and
attestation cleanup until ownership transfers to the running pod; ordinary
spawn failures and cancelled preparation release those resources. This follows
C-4 (consume ownership at transfer) and D-1 (prepare services before the effect).
The startup regression retrieves the host spec over a real Unix socket before
attempting spawn, then verifies cleanup after a missing VMM executable. A second
case refuses an unbindable API path. The full all-feature node suite passes
(521 unit tests and 3 integration tests), and strict all-target/all-feature
Clippy passes for node and xtask. Linux cross-checking on this Mac was blocked
by the missing GNU cross compiler; the Zig substitute could not accept a build
dependency's target flags. Linux CI and another real microVM run remain required.
The experiment now enables INFO logs so existing boot-stage timings are exported.

The bootstrap already called both kill and wait before propagating its build
result. Reordering the `?` operations did not add cleanup; it only changed error
precedence. Preserve the original build error after both cleanup calls so an
already-exited node does not replace the useful failure with a kill error.

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

The first manifest gate on `cffbb336f3` refused ratchet slack, not a new dropped
witness: `cargo xtask bound --measure` reports net D=174, B=173, dropped=1
(99.42%) against the previous 99.41% floor. The floor and declared-site minimum
are raised to the measured values. The existing dropped-site debt remains one.

Run `34719599559` at `cffbb336f3` proves the repaired startup path: the guest
fetched its spec, SVID and per-pod material (21 ms total handshake), started the
supervised workload, and ran Cargo. It did not complete the build. The node
refused admission because `/usr/local/bin/nucleus-egress-probe` was missing;
the image included `nucleus-net-probe`, which is a different executable. Cargo
also reported EACCES reading `vendor/fnv-1.0.7/.travis.yml`. The locally cached
copy of that crate file is mode 0640, unreadable to the workload's other uid.

Image preparation now requires, hashes and places the egress probe alongside
the other guest binaries, and normalizes exported source/vendor directories to
0755 and files to 0644 (0755 for executables). It preserves content and executable
status and never follows symlinks while changing modes. The rootfs remains
read-only and the workload remains unprivileged. Seven build-image tests pass,
including restrictive hidden vendor metadata and an outside symlink target.

The node's boot trace measured 32,927 ms for creation, including 10,353 ms for
launch-attestation hashing; the bootstrap spent more than seven minutes before
that node call. The controller now logs each input hash's byte count and elapsed
time so a later optimization can address a measured component. No cold/warm
build timing or artifact receipt has been produced by this failed run.


## Copy-on-write build cache and measured controller cost

The web-researched design is in [build-cache-design.md](../build-cache-design.md).
The experiment now uses a separate writable scratch inode per phase, with an
exact-tree seed promoted only after successful artifact verification and confirmed
VM shutdown. Promotion checks the ext4 journal; warm scratch uses Linux reflink or
APFS clonefile, with a measured sparse fallback. Every clone is hashed before
publication, and the new execution must still verify. No shared remote cache or
cross-tree receipt reuse is enabled.

On this Mac, a synthetic 512 MiB image with 3 MiB allocated measured:

| Controller / copy method | Copy | Source + clone verification | Total |
|---|---:|---:|---:|
| Debug / sparse extent copy | 7.9 ms | 5.188 s | 5.196 s |
| Release / sparse extent copy | 8.3 ms | 0.402 s | 0.410 s |
| Release / native APFS clone | 4.7 ms | 0.393 s | 0.398 s |

These are local storage probes, not build times or Linux reflink measurements.
The workflow now uses the optimized controller for preparation, execution and
public evidence export. `cargo xtask build-cache-probe` exposes the same storage
path for host measurements; `cache.json` and phase timing expose copy, hashing,
preparation, execution and checkpoint costs in later real builds.

Ten build-image tests pass, including native clone write isolation, sparse-copy
holes, corrupt-seed rejection and destination collision refusal. Strict xtask
Clippy, the line ratchet and workflow actionlint pass. The actual cache module also
cross-checks for Linux with rustix; this is compilation evidence, not a live
Linux COW result. Experiment 34720923251 was dispatched immediately after pushing f1cbac5fe,
but GitHub recorded its actual head as cffbb336f and ran that older workflow and
source. Its terminal failure repeated the missing egress sentinel and unreadable
vendor file; it tested neither the image repairs nor these cache changes. Compare
the dispatched run's `headSha` with the intended full commit before accepting a
new experiment as validation; reading the branch ref alone did not establish it.


## First successful cold/warm self-build and successor wiring

[Run 34721798028](https://github.com/coproduct-opensource/nucleus/actions/runs/34721798028)
ran the confirmed exact commit `9260327c8f654f59276ed5fa27846e71b6824d65`
(tree `74a1f37677ae3ebf709768e471ed360c4d911bf5`). Both Firecracker workloads
passed egress enforcement, ran Cargo as the unprivileged workload, and returned
execution and artifact receipts accepted by the controller and an independent
verifier. Wrong source, wrong key, corrupt binary bytes, and an expired acceptance
window were refused on the real bundle. The informational
[`nucleus/build` check](https://github.com/coproduct-opensource/nucleus/runs/103631402105)
was published for that exact SHA; its returned App identity and check binding were
verified. No required-check or production executor settings changed.

| Phase | Cargo console time | Launch through verified artifact and cancellation | Total with preparation/checkpoint |
|---|---:|---:|---:|
| Cold | 2m53s | 211.967 s | 225.740 s |
| Warm | 41.71s | 79.243 s | 88.779 s |

Both binaries are 58,545,208 bytes with SHA-256
`53d2dcf2326aa634231ee9940d250214daaee41ee2dcfd45b1148cb0175abe83`.
The warm clone reported sparse-copy fallback because Linux returned EOPNOTSUPP;
copying took 2.946 s and verifying the clone 6.589 s. The roughly 2.54x total
improvement is real exact-tree compiler-cache reuse. Linux reflink acceleration,
shared remote cache trust, and cross-tree receipt reuse remain unproved.

The manual workflow now requests `build-bootstrap --successor-output`. After
verifying both first-stage builds and stopping/reaping the bootstrap node, the
controller carries its own minted public key directly into successor verification.
The successor path executes a protected copy of the authenticated predecessor
binary, with new executor keys and explicit predecessor provenance. It cannot
recursively request another successor. Public evidence for both stages is exported
separately. This wiring passes the ten build-image tests, strict xtask Clippy and
actionlint; its real successor run remains the next experiment.


## Successor chain observed (2026-09-12)

[Run 34723000387](https://github.com/coproduct-opensource/nucleus/actions/runs/34723000387)
completed successfully at `58d894f18b891eccfacb5ee8ecf85a7ea63aa11a`, tree
`802e893ac6b66ed2aa58c33b349b2962b0e11e58`. Both bootstrap and both successor
Firecracker builds returned independently verified execution/artifact bundles.
The successor runtime's node digest equals the first verified output; its
provenance binds the first receipt root and its fresh executor key differs from
the bootstrap key. All four binaries are 58,545,208 bytes and have SHA-256
`53d2dcf2326aa634231ee9940d250214daaee41ee2dcfd45b1148cb0175abe83`.

Bootstrap cold/warm totals: 224.773/90.455 s. Successor cold/warm totals:
226.490/89.695 s, with Cargo console times 2m51s/39.42s. The warm scratch disk
again used sparse-copy fallback (3.018 s copying and 7.174 s verifying).

Informational [`nucleus/build` check 103634804793](https://github.com/coproduct-opensource/nucleus/runs/103634804793)
was published from the verified successor warm bundle for that exact source.
App ID 4853870 and returned head/attempt/conclusion were independently confirmed.
A live attempt with a different PR subject was refused before check creation;
the accepted attempt reconciled PR 2884's current head immediately before sending.
Required checks and production signer policy were not changed.

The self-built successor is now observed evidence, not just wiring. Still open:
the automatic leased execution worker and live webhook delivery, live red and
merge-group checks, required-check App pinning after acceptance, native Linux
reflink measurements, checkpoint quiescence, and production cache/result-store
integration. Do not infer any of these from the successful successor experiment.
