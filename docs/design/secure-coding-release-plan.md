# Secure coding release implementation plan

Authorized order, 2026-10-04. The release outcome is a fresh installation that
runs a vendor-neutral agent harness inside a pod, fixes a repository, runs its
tests, obtains an action-bound approval, opens a PR through mediated egress, and
produces evidence an external verifier can inspect. Two distinct harnesses must
complete this journey. Gatehouse control-plane implementation stays outside this
repository.

Publication direction updated (2026-10-04): continue working toward the full
release goal until **2026-10-05 08:00 America/New_York (12:00 UTC)**, then open
the implementation PR and pursue its merge through Gatehouse. The user explicitly
authorized this deadline and publication. At that point report the actual journey
and verification status in the PR; do not count harness startup or fixture calls
as completed coding journeys, and do not bypass required merge checks. This
supersedes the earlier instruction to wait for both journeys before opening a PR.

Current execution scope: implement the design and validate ordinary supported
workflows. Red-teaming, adversarial probes and attack evaluations are paused at
the user's direction. Historical evidence below remains a record of completed
work, not an instruction to repeat those exercises. Continue with shared outbound
accounting and normal integration checks; complete the two coding journeys once
model endpoint configuration is available.

## Release checkpoint: implementation and remaining work

[Implementation PR #3184](https://github.com/coproduct-opensource/nucleus/pull/3184)
was opened at the authorized 8 AM Eastern cutoff. Merge checks remain in progress.

This is an implementation milestone, not a completed release journey. The latest
local checkpoint has 902 passing node unit tests, three node integrations,
351 CLI unit tests and 16 integrations, and the earlier 580-test all-feature proxy
suite plus integrations. Tests cover different source checkpoints as recorded
below; the final PR and merge-group checks must still run.

| Outcome | Implemented and exercised | Still required |
|---|---|---|
| Host-owned effects | Shared authority, effect-bound one-shot approval, bounded staging, revocation and fixed tariffs; operator review/grant/refuse | Durable runtime history, variable charging, broader certificate revocation |
| Coding workflow | Matched local Apple image, fresh setup, saved host selection, workspace transfer, managed adapter, independent receipt/log/artifact verification and public-key enrollment | **Two model-driven coding journeys: zero completed**; endpoint/model/credential configuration and a published release image |
| Outbound accounting and audit credentials | Shared Firecracker direct-packet and broker upload allowance; paced replay; scoped Unix audit minter protocol | Physical broker wire overhead, other drivers, provider integration and credential refresh |
| Resource admission and lifecycle | Aggregate CPU/memory/swap admission, cgroup ancestry, bounded queue/probe waits, owned launch tasks and confirmed cleanup before release | Durable recovery across node termination; network-allocation recovery across restart |
| Persistent memory | Owner-scoped labeled JSONL storage and verified replay for local/mediated-container drivers | VM transport, durable declassification and compaction |
| Evaluation | Existing regression evidence retained | AgentDojo/red-team work remains paused at the user's direction |

The source-built Apple image is a local validation artifact. Its harness startup
and fixture preflight are not model sessions. The merge milestone requires the
normal Gatehouse and repository checks; no skipped or cancelled manual mutation
run is counted as a passing result.

Paced broker replay now reserves the complete upload volume once and admits
body slices at HTTP consumption through the same fixed window as direct packet
reservations. Staging and effect hashes remain unchanged. Initial path and
content-type accounting waits before credential resolution; the body owns the
reservation through transport cancellation. One finite deadline covers the pace
wait, upload and response headers for STREAM. PERFORM uses the same body
consumer with a deadline covering credential retrieval, upload and response.
Broker accounting covers body plus guest path lengths (and guest content-type
length for STREAM), not physical HTTP/TLS wire bytes. See the paced replay
validation entries below.

## Review entry points

The branch spans several runtime boundaries. Start with the operator behavior,
then follow the owner of each state transition:

| Area | Operator contract | Implementation entry points |
|---|---|---|
| Effect approval | [Review and grant the exact staged request](../host-effect-approvals.md) | [Shared pod authority](../../crates/nucleus-node/src/pod_authority.rs), [effect decisions](../../crates/nucleus-node/src/host_decide/effects.rs), [staged dispatch](../../crates/nucleus-node/src/broker_stream/staged.rs) |
| Apple workflow | [Install, start, diagnose, seed and collect](../quickstart/apple-container.md) | [Host lifecycle](../../crates/nucleus-cli/src/microvm_host/lifecycle.rs), [operator commands](../../crates/nucleus-cli/src/microvm_host/operator.rs), [setup verification](../../crates/nucleus-cli/src/microvm_host/verification.rs) |
| Independent evidence | [Receipt enrollment and verification](../handoffs/nucleus-build-receipts.md) | [Admission expectations](../../crates/nucleus-spec/src/workload_admission.rs), [execution verifier CLI](../../crates/nucleus-audit/src/verify_execution.rs), [raw log collection](../../crates/nucleus-cli/src/node/workload/collection.rs) |
| Outbound accounting | [Scoped audit credential service](audit-credential-service.md) | [Shared egress meter](../../crates/nucleus-node/src/egress_meter.rs), [paced HTTP body](../../crates/nucleus-node/src/egress_meter/body.rs), [audit minter socket](../../crates/nucleus-node/src/audit_credential_socket.rs) |
| Resource lifecycle | Admission before launch; release after confirmed cleanup | [Capacity reservation](../../crates/nucleus-node/src/node_capacity.rs), [owned launch handoff](../../crates/nucleus-node/src/pod_launch.rs), [expiry and cleanup](../../crates/nucleus-node/src/pod_reaper.rs) |
| Persistent memory | [Owner namespace and journal behavior](memory-journal.md) | [Node provisioning](../../crates/nucleus-node/src/memory_provisioning.rs), [proxy journal](../../crates/nucleus-tool-proxy/src/memory_store.rs) |

The checkpoint table above is the completion ledger. Historical sections below
retain failed attempts and earlier measurements so later success does not erase
their scope or imply that every checkpoint used the final source revision.

## 1. Host-authoritative enforcement (P0)

Issues: #2702, #3114, #3115, #3116, #3117.

Current baseline: the decision-channel protocol remains shadow-only. Broker
PERFORM and streaming now require host decisions over shared pod policy, with
operator approval bound to the resolved effect when required. Streams stage the
complete bounded upload before authorization and upstream I/O. The compromised-guest socket conformance table now holds for
observed taint, absent/reused approval, and zero remaining budget. Guest signing
key delivery is retired in the working tree; guest claims are separated from
host authorization evidence. The full table has local host tests; selected
PERFORM cases now also have compromised-guest Tier-2 evidence (see below).

Implementation sequence:

1. Bind host-issued decisions and approval reservations to the checked action.
   Consume by value against the host-computed digest of the effect. Cover
   argument substitution, approval redemption, replay and foreign epochs.
   **Implemented and locally verified:** ledger binding and shadow-channel
   callers; the shadow digest still covers operation and subject only, not the
   complete effect arguments.
2. Define the complete canonical effect representation shared by decision and
   execution. Include upstream, method, path and payload for credentialed calls;
   streamed payload authorization must explicitly account for what is known at
   admission and what is checked while forwarding. Never trust a guest-supplied
   digest without recomputing it from the effect.
   **Implemented locally for credentialed broker calls:** PERFORM and streaming
   share a derived canonical binding over operation, resolved upstream name/URL,
   HTTP method, credential header name, content type, payload SHA-256 and length.
   The hash is computed from the complete host-owned payload; never from a
   guest assertion. Method and content type are shared with
   the HTTP caller. The retry ledger rejects substitutions both while a call
   is in flight and after settlement; audit justification is deliberately not
   part of the effect. This binding now names the one-shot host approval and
   execution permit. Streams upload into anonymous temporary files bounded by
   the operator's per-call limit, then replay only that owned payload. Response
   streaming is unchanged; upload staging adds local disk I/O and latency.
3. Move enforceable state to the pod lifetime. Connection replacement cannot
   reset observed taint, spent budget or revocation. Concurrent channels must
   share the applicable limits. Host-delivered observations raise host taint
   independently of guest reports.
   **In progress:** pod authority owns one kernel and taint shared by the broker
   and decision service, including across listener replacement. Protocol
   sequence/decision epochs remain per channel. Broker PERFORM and streaming
   responses raise host taint before delivery, without relying on guest reports.
   A policy panic refuses observations, decisions and new broker I/O. State is
   in memory; restored certificates without recovered runtime history cannot
   obtain a clean policy or start a broker. Teardown and authority release now
   revoke shared policy and cancel live broker requests. Fixed operator tariffs
   now debit the shared authority ledger for both broker paths and delegation. Variable usage charging,
   broader certificate/fleet revocation, and durable runtime recovery remain open.
4. Connect host decisions to both PERFORM and streaming effects. The executable
   effect requires a consumed, matching host decision. Missing, stale, foreign,
   replayed and mismatched decisions refuse before credentials or upstream I/O.
   Recheck current pod taint, expiry, revocation and budget when committing the
   effect: another channel may change them after an earlier decision was issued.
   **In progress:** both broker paths check actual WebFetch authority plus the
   requested operation before credential access and again after async minting,
   immediately before execution. Private non-cloneable permits are required to
   construct either upstream call. Pod-lifetime revocation now vetoes final
   authorization; fixed tariffs debit the conserved authority ledger. Broader certificate
   revocation and variable/terminal cost settlement remain.
5. Wire authenticated host approval, expiry and one-shot consumption. Preserve
   legitimate approved work; denying every approval-gated operation is not done.
   **In progress:** operator-only mTLS routes list and grant/refuse pending host
   effects. Approvals expire after five minutes and are consumed at final
   authorization, not preflight. Failed minting does not consume them. Operator CLI list/grant/refuse commands now expose this path. Exact request review is available through the operator CLI. Streamed workload
   requests can now pause for operator approval and resume the staged request;
   complete harness journeys remain to be demonstrated.
6. Keep receipt and exit-report authority outside the guest. Distinguish host
   observations from guest assertions in signed evidence.
   **In progress:** no mediation signing seed exists in boot material, and the
   legacy fetch command always refuses. Uploaded mediation claims have a separate
   log and an explicit guest provenance acknowledgment. Plain and legacy-signed
   exit reports become typed guest claims; neither is independent outcome
   evidence. Host-signed broker transport observations are implemented in the
   working tree; remote action semantics, guest execution outcomes, and terminal
   completeness remain open.
7. Validate supported effects, reconnects, concurrency and real Tier-2 guest
   traffic through ordinary functional integration. Record which implementation
   properties have live evidence. Compromised-guest conformance work is paused.

## 2. Supported coding workflow (P0, alongside enforcement)

Issues: #2791, #2696, #2698. Reconcile existing workload-door, MCP and streaming
implementation before adding replacements. Bundle required runtime helpers;
align quickstarts, artifacts and versions. Verify the complete release journey
above on a supported host, including intelligible refusals and approval prompts.
Do not equate the algebra demo or an isolated proof pod with useful agent work.

## 3. Egress accounting and scoped credentials (P1)

Issues: #2905, #3160. Broker egress metering already exists. Complete accounting
for every permitted outbound path, preserving a shared pod budget. Validate
normal uploads and concurrent calls against the configured byte allowance.
Give audit uploaders short-lived credentials restricted to the
resolved bucket/prefix, without ambient credentials in workload or uploader
environments. Keep provider implementations behind the vendor-neutral boundary.

**In progress:** Firecracker direct IP packets now reserve from the broker's
ledger before kernel acceptance, including the optional fixed-window allowance.
This replaces counter sampling. Broker request-body and direct IP byte accounting
remain distinct units; broker transport overhead, other drivers and review of
the remaining outbound paths are still open.

## 4. Resource admission (P1)

Issue: #3153. Reserve aggregate host memory/vCPU capacity before admitting pods;
release on failed launch and exit. Bound swap where supported, clean development
cgroups, and test concurrent admission against an operator capacity plus host
reserve. Per-pod ceilings alone do not establish this property.

## 5. Evaluation through production enforcement (P1)

Paused under the current execution scope. Issue: #2699. The deferred design is
to restore the AgentDojo integration through the real kernel/runtime,
not the removed Python policy mirror. Report attack success alongside benign
completion, false refusals and approval burden across multiple models. Pin the
artifacts and configuration needed to reproduce each result.

## 6. Governed persistent memory (P2)

Issue: #3100. Wire persistence into the runtime with labels and provenance intact
across restart. Exercise poisoning, authority escalation attempts, isolation and
recovery. A serializable library object alone is not this deliverable.

## Verification and completion

Owner direction (2026-10-04): prioritize design implementation and the supported
coding workflow; stop the active red-team work. Outstanding adversarial cases
below remain unverified, but do not drive the current work queue. Continue with
ordinary workload execution, artifact collection and approval UX.

Validate implementation changes with ordinary functional and regression checks.
Follow repository prepush gates before every push. Protocol consumers include
the node and the tool proxy with all features. Real guest behavior needs a
supported Tier-2 host; macOS unit tests do not prove the Linux launch path.

The overall work remains incomplete until all six outcomes have current
implementation and verification evidence. Marketplace/economic expansion and
unrelated protocol or proof breadth are deferred; existing proof gates remain.

### Guest signing-key retirement (2026-10-04)

Boot material can no longer contain a mediation signing seed. The guest init
does not fetch one, and legacy fetch requests always refuse, including the first
request and concurrent requests. Guest mediation uploads are retained separately
in `guest-mediation-claims.jsonl` and acknowledged as `guest_reported`. Plain and
legacy-signed exit reports retain that same provenance in signed v2 receipts.

A real admitted-pod socket test exercises a legitimate broker call, verifies its
durable authorization under the host root, then uploads a forged guest receipt
and confirms the host authorization journal is unchanged. The signing rows now
hold for withheld keys and separation of claims. This does not establish truthful
guest output, host-measured execution outcomes, or session completeness.

Validation: 809 node unit tests and three integration tests pass (one unit test
ignored), as do 14 proxy exit-report tests and 16 transcript tests. Node and
guest-init cross-build for Linux ARM64 musl. Clippy for all five affected crates
passes with warnings denied; all four prepush gates pass. Reintroducing key
delivery and removing guest provenance independently make their regression tests
fail at runtime, rather than at compilation. Real Tier-2 validation remains open.

### Host broker transport outcomes (2026-10-04)

PERFORM and streaming consume the authorization permit into an executable right
and a non-cloneable outcome observer. The observer signs a separate, durable
`host-effect-outcomes.jsonl` record linked to the exact authorization record hash.
It records response status, observed body hash/length, completeness, and the
termination category. No credential or response body is written to this log.
Cancellation records interruption with any partial observations. Host death can
leave no outcome; absence remains unknown. A storage failure latches refusal of
subsequent effects, and an explicit finish cannot be reported as successful when
its evidence write failed. Appends currently synchronize under the pod mutex.

Streaming completion requires an explicit EOF from the upstream reader, not
merely closure of its channel. PERFORM's response interface does not attest EOF,
so its observed body is conservatively marked incomplete. Neither HTTP status nor
body completeness establishes the requested remote action's semantic success.

`nucleus-audit verify-host-effects --log <authorizations> --outcomes <outcomes>
--pod <id> --host-pubkey <independent-pin>` checks both chains, the host signatures,
pod, and authorization linkage. Duplicate/foreign outcomes, tampering, and torn
records refuse. It explicitly reports authorizations with missing outcomes. A
valid prefix remains a prefix: terminal session checkpoints, guest process and
artifact evidence, and recovery are still required.

Validation: the full node suite passes 815 unit tests (one ignored) and three
integration tests; audit passes 129 unit tests and four integration tests,
including the shipped CLI with an independent key. Actual broker socket tests
check host-signed outcome linkage and reject guest uploads as outcome evidence.
Real local HTTP/SSE tests cover complete and truncated responses, cancellation,
and a disappeared reader. Storage failure latches refusal after repair. Bypassing
outcome signature verification and accepting channel closure as EOF each make
their regression fail. Linux ARM64 musl compilation and all four prepush gates
pass. Clippy completes with `-D warnings`, retaining the existing configuration
warnings about unreachable reqwest blocking methods. This is local evidence;
real Tier-2 execution remains unverified.

### Pod-lifetime revocation and cancellation (2026-10-04)

Shared pod policy now carries an irreversible revocation signal. Authority
release revokes previously issued policy references; listener shutdown/drop and
Firecracker identity cleanup revoke before waiting on teardown. Both preflight
and final effect authorization refuse revoked state, including previously
approved effects. Existing and replacement decision channels also refuse it.
An already authorized request may have reached its upstream; cancellation does
not claim to reverse a remote effect.

Broker connections observe revocation while awaiting frames, credentials,
upstream work, or guest writes. The listener owns their task set and cancels and
drains it on shutdown. Waiting for a connection slot no longer hides the shutdown
signal. Response streaming now owns the HTTP reader directly instead of spawning
a detached reader; dropping a serving future drops its upstream response.
Interrupted calls retain the host outcome journal's interruption classification.

The node suite passes 821 unit tests (one ignored) and three integration tests.
Real socket tests fill all 16 connection slots and prove that shutdown drains the
calls, while direct policy revocation cancels them without waiting for shutdown.
A real HTTP server proves that a partially read, stalled response closes when
its owner drops. Tests also cover stale approvals, retained authority references,
and replacement decision channels. Linux ARM64 musl compilation and all four
prepush gates pass. Clippy completes with warnings denied, retaining the existing
unreachable reqwest blocking-method configuration warnings.

Restoring the detached reader, the shutdown-blind semaphore wait, and release
without policy revocation independently makes each corresponding regression fail
at runtime. Restoring the implementation passes the affected suites.

This establishes pod-lifetime revocation locally. Broader certificate/fleet
revocation, descendant propagation guarantees, durable recovery, and live Tier-2
validation remain open, as do cost charging and settlement.

### Host accounting for operator tariffs (2026-10-04)

The upstream registry accepts `call_charge_micro_usd`: an exact nonnegative
integer charge for an authorized dispatch attempt. Only the operator supplies
it. An omitted tariff refuses PERFORM and streaming before credential access;
an explicit zero is a declared free attempt. This changes existing unpriced
registry behavior and requires operator configuration before calls resume.

Both paths check affordability before credential access and again under the pod
policy mutex at final authorization, then debit the kernel and durably record the
charge before issuing an executable permit. Concurrent calls share the same
remaining budget. Failed minting and missing credentials do not debit; a failed
authorization journal write refunds its local debit and latches evidence failure.
Committed attempts remain charged on ambiguous failures and cancellation. Cached
PERFORM retries neither execute nor debit again. This is a fixed tariff, not a
reservation whose amount depends on guest-reported usage.

The charge appears in approval views, effect binding v3, and host authorization
schema v2 with a new signing domain. Tariff changes invalidate old retry and
approval bindings. The updated verifier expects v2 authorization records; prior
v1 journals are not silently interpreted as priced records. This branch does not
yet recover live runtime history from either journal format.

Variable provider pricing, observed execution cost, complete terminal spend
evidence, unused-allocation credit, and composition with child allocations remain
required. A declared tariff must not be reported as a verified provider bill.

Validation: 826 node unit tests (one ignored), 129 audit unit tests, and seven
integration tests pass. Broker tests cover a paid call, a cached retry, concurrent
budget exhaustion, listener replacement, ambiguous transport failure, missing
credentials, unpriced refusal, and streamed charging. A real token endpoint
confirms that unaffordable calls do not mint and failed minting leaves budget for
a successful retry. The signed-record verifier rejects charge tampering. Linux
ARM64 musl compilation, Clippy with warnings denied (apart from the existing
reqwest configuration diagnostics), and all four prepush gates pass.
Removing the host debit and removing the tariff from the effect digest each make
their corresponding regression fail at runtime; the restored broker and real
federation tests pass.

### Action-binding evidence (2026-10-04)

- Protocol tests with all features: 34 pass, including generated substitutions
  before and after approval redemption.
- Host decision-channel tests: 14 pass; guest decision-channel tests: 9 pass,
  both with all features. Local socket tests require execution outside the
  filesystem/network sandbox.
- Removing the ledger's argument comparison makes
  `a_decision_is_bound_to_the_host_checked_action` fail. Restoring it passes.
- Clippy for the protocol, node and tool proxy, all targets and all features:
  passes with warnings denied. All four `cargo xtask prepush` checks pass.

These checks establish action binding within the current shadow protocol. They
do not establish host-enforced effects, full-argument authorization, host-owned
signing, or real Tier-2 execution; those remain required above.

### Non-streamed effect-binding evidence (2026-10-04)

The broker suite passes 92 tests with all features, including real local socket
transport and streaming regressions. New controls reject changed operation,
upstream, resolved URL, header, path and payload under an existing retry key;
genuine retries still return the original result without another upstream call.
In-flight and settled bindings are both checked. Removing the effect comparison
makes `a_retry_key_cannot_name_a_different_effect` fail; restoring it passes.
These are retry-integrity results, not proof of host-authoritative policy.

### Pod policy lifetime evidence (2026-10-04)

The decision-channel suites pass 16 host and 9 guest tests with all features.
A real socket test establishes that an observation on one channel affects an
already-open peer and a newly connected replacement, even when they report clean
state. A separate test charges the host kernel directly, reopens the channel,
and observes budget exhaustion; it then poisons the policy lock and verifies
refusal. This does not claim broker charging is connected. Reintroducing a fresh
kernel per connection makes the budget-history test fail.

`cargo zigbuild -p nucleus-node --all-features --target
aarch64-unknown-linux-musl` succeeds, compiling the Linux-only production startup
as well as the shared implementation. This is cross-build evidence, not a guest
boot or a node-restart recovery test.

### Broker observation evidence (2026-10-04)

Pod authority now owns the shared runtime policy. Broker and decision listeners
obtain the same handle, and replacing either listener does not create clean
history. PERFORM, cached PERFORM replies and streamed responses cross a host
observation boundary before delivery. Faulted policy state refuses new broker
I/O. A restored certificate without runtime history is explicitly unavailable;
newly admitted pods after restart remain usable.

The full node run passed 796 unit tests (one ignored) and three integration
checks. After the final fault-path additions, 94 broker tests and the 17 host / 9
guest decision tests pass. Removing host observation makes both the PERFORM
regression and the real HTTP/SSE streaming regression fail. The Linux ARM64 musl
build, consumer Clippy checks and all four prepush gates pass.

This establishes host-owned observations and shared state, not host-authoritative
effects. Full effect decision consumption, approvals, charging, revocation,
durable runtime recovery and host-only signing remain required.

### Non-streamed host enforcement (2026-10-04)

The host checks WebFetch for the real HTTP effect even when a guest labels it
ReadFiles. It also checks the declared operation. This does not infer remote API
semantics: trusted upstream action mapping is still needed before claiming that
a guest cannot mislabel a remote write. Streaming authorization was completed
locally in the following increment.

Operator routes are `GET /v1/pods/{id}/effect-approvals` and
`POST /v1/pods/{id}/effect-approvals/{approval}` with JSON `"grant"` or `"refuse"`.
Only the configured root-minter SPIFFE identity can use them. Listings currently
show operation, resolved subject, effect digest, expiry and status; a complete
human review surface for request content remains open. Approval state is local
to the pod's shared host policy. It cannot transfer between pods or survive a
node restart as a fresh grant.

Tests cover exact-action matching, expiry, refusal, repeated decisions,
cross-pod IDs, simultaneous preflights with one successful commit, budget changes
between preflight and commit, and real credential minting raced against a host
taint observation. The conformance reuse row first executes a legitimate
operator-approved request through the broker socket, then refuses its reuse.
Independent approval tests exercise consumption without relying on response taint.

Validation: all-feature node suite passed 804 unit tests (one ignored) and three
integration tests. Restored targeted effect tests passed 11/11 after negative
controls: disabling approval consumption or the real WebFetch capability check
made the corresponding regression fail. Clippy with warnings denied, the Linux
ARM64 musl cross-build, and all four `cargo xtask prepush` gates passed. Socket
fixtures require an execution environment that permits local listener binding.

### Staged streaming authorization (2026-10-04)

Streaming now reads the complete request into an anonymous temporary file,
checks its per-call bound, and hashes the bytes before requesting any credential
or calling an upstream. Only fixed-size chunks occupy memory. Final policy and
approval checks run after token retrieval; the executable call consumes the same
host permit type as PERFORM. The file is closed on all exits and has no guest
pathname. The upstream receives only bytes replayed from that owned file.

Canonical effect version 2 is shared across PERFORM and streaming and includes
the payload SHA-256 and byte count. HTTP method is shared with both real callers.
Changing a late payload byte, path or media type cannot use an existing approval.
A new stream nonce permits retrying an approved effect, but cannot reuse the
spent grant. Nonces and retry keys do not alter the effect's identity.

The full upload plus guest-controlled path/media-type bytes are reserved on the
pod's shared egress meter before token retrieval. A policy refusal or insufficient
balance sends no upstream request and charges no bytes. After committing to HTTP,
all reserved bytes count as sent because transport failure or an early upstream
response is ambiguous. This is conservative accounting, not an observed wire-byte
measurement. Responses remain bounded, streamed and observed by host taint before
delivery, including SSE. Aggregate staging-disk admission remains part of #3153.

Validation: the full node suite passed 809 unit tests (one ignored) plus three
integration tests. After adding cross-transport approval coverage and updating
the response observation timestamp, all 100 broker tests passed. Removing the
payload hash from the canonical binding made the late-byte substitution test
fail; restoring it passed. The Linux ARM64 musl build passed.

At this checkpoint, paced egress admission treated the complete staged upload as one batch;
a body larger than the configured rate window is refused instead of replayed at
a throttled rate. Preserve this limitation in the P1 egress work: useful large
uploads under a paced policy need explicit paced replay with conserved total
reservations. Default unpaced uploads remain bounded by per-call and pod ceilings.
Clippy with warnings denied and all four repository prepush gates also passed.

### Host-signed authorization journal (2026-10-04)

Every committed broker authorization now appends a signed record to
`<state-dir>/pods/<pod-id>/host-effect-authorizations.jsonl` before the private
execution permit can be constructed. The node certificate-root key signs this
capability decision with a distinct domain separator. That key stays in host
memory and node key storage; it is not part of guest PodMaterial. The same
mandatory journal sits under both PERFORM and streaming gates. Idempotent result
replay adds no second authorization.

Records bind pod UUID, sequence, resolved effect digest, operation, subject,
authorization time and the previous signed record's hash. The existing
`nucleus-jsonl` durable append proof gates permit issuance. A failed/ambiguous
append latches refusal; an existing journal is never truncated or silently
reinitialized. A pod is bounded to 65,536 authorization records and refuses
further commits when full. Production requires a durable sink; the memory-only
sink is compiled exclusively for tests.

External verification:

```
nucleus-audit verify-host-effects --log host-effect-authorizations.jsonl \
  --pod <admitted-pod-uuid> --host-pubkey <independently-pinned-node-root-key>
```

The command requires a pinned key and pod, checks every signature and chain link,
and refuses empty or torn evidence. It verifies an authorized prefix. It does
not prove successful execution, a truthful guest result, or session completeness;
a separately trusted terminal checkpoint and outcome records remain to be added.
Guest-produced mediation/exit reports have not been promoted to host observations.
The two #3114 conformance gaps remain open until their guest-key paths are retired
and replaced by useful host evidence. Node restart still refuses policy history
recovery; this journal alone is not a recovered policy or budget ledger.

Durable append currently runs synchronously under the pod policy lock so no
permit can escape before storage succeeds. Moving I/O to a worker requires a
pending-commit protocol that preserves ordering and rechecks, not fire-and-forget
logging. Approval already consumed before a storage failure remains consumed.

Validation: 814 node unit tests (one ignored), 128 audit unit tests, and both
packages' existing integration suites passed. The added shipped-CLI integration
also passed with an independently supplied key and rejected a guest key. The
storage-failure negative control reached the forbidden upstream callback when
persistence refusal was removed; the four restored evidence tests passed.
Linux ARM64 musl cross-build and all four prepush gates passed. Clippy completed
with `-D warnings`; the combined feature graph emitted existing configuration
warnings about unreachable reqwest blocking-method entries in `clippy.toml`.

### Signed exit-report provenance (2026-10-04)

Pod receipts now emit version 2 with `report_provenance = guest_reported`.
The label is included in the node signature's tagged preimage and applies to
report-derived workspace/audit hashes, counters, usage, cost and report time.
The node assigns it independently of fields a guest includes in its report.
The node-observed pod identity and manifest remain separate host metadata.

HTTP and gRPC carry the same signed provenance. gRPC adds field 18, without
renumbering existing fields; the Rust SDK preserves provenance, signature and
signer public key. An absent provenance value from an older node remains
unspecified. The legacy content hash remains available for compatibility, but
recomputing that hash is not authentication or proof of the report's truth.
Trust-report payloads and hash registration also carry the provenance label;
external consumers must honor it before treating report fields as observations.

This separates claims while preserving useful receipts. It does not retire
`FETCH_MEDIATION_KEY`, replace the guest exit-report producer, or close either
#3114 conformance gap. Host authorization journals are already independent of
that guest key; host outcome evidence and guest-key removal remain required.

Validation: the full node suite passed 814 unit tests (one ignored) and three
integration tests; the SDK passed 33 tests and seven doc tests. After adding the
injected-provenance regression, all 24 receipt tests passed. Removing provenance
from the signed preimage made the tamper regression fail; restoration passed.
The strict guest-report parser rejects injected provenance/version fields, while
a valid report still yields a useful signed receipt labeled `guest_reported`.
Linux ARM64 musl build and all four prepush gates passed. Clippy completed with
`-D warnings`, with the existing reqwest blocking-method configuration warnings.

### Retiring guest-authorized allocation credit (2026-10-04)

The reaper no longer supplies a receipt-derived spend number to authority
release. The release API accepts only the pod identity; an exited pod consumes
its full allocation until host-authoritative terminal settlement exists. A
private release-state enum distinguishes this from an unspawned reservation,
whose owned launch guard can still return the entire unused allocation.

Legacy spend signatures authenticate a key historically held by the guest.
Even a complete seal and recomputable clearing inputs cannot prove the guest
reported every charge. Those records remain inspectable as guest-reported
claims, but cannot restore authority. The regression constructs a valid legacy
zero-spend seal, confirms that its claimed total verifies, then checks that it
cannot fund a new sibling beyond the parent's remaining allocation. A smaller
sibling using the genuinely unallocated balance remains allowed.

This closes the guest-claim credit path. It does not yet compose parent broker
spending with child reservations, provide variable usage settlement, or recover
runtime budget history after restart. Those release requirements remain open.

Validation: 826 node unit tests and three integration tests pass (one unit test
ignored). Reintroducing zero-spend credit from the legacy guest seal makes the
regression fail at runtime by admitting the oversized sibling; restoring the
fix passes. Unspawned refunds and restart accounting remain covered. Linux
ARM64 musl compilation, Clippy with warnings denied, and all four prepush gates
pass; Clippy retains the existing reqwest configuration diagnostics. The final
regression also asserts that the guest claim was durably stored before release.

### Shared budget for effects and delegation (2026-10-04)

A pod's authority ledger is now shared with its runtime policy. Child admission
and final broker charging serialize against the same available balance. The
kernel receives a derived budget view for decisions; it no longer maintains an
independent runtime-spending balance. Final charging rechecks affordability after
preflight, so a child admitted during credential retrieval can cause refusal
before dispatch. Both broker transports use this path.

The host persists a pod-bound consumption checkpoint after authorization evidence
and before releasing the executable permit. On restart, the greater consumption
from that checkpoint and the authority record is restored before allocating live
children. This prevents stale authority snapshots from refunding runtime charges
and avoids counting the same consumption twice. Missing checkpoints alongside
legacy runtime history, corrupt checkpoints, and unreconstructable child
allocations refuse delegated admission. This restores the budget only; runtime
taint and approval history still cannot be recovered for renewed broker service.

Checkpoint storage failure latches refusal for spending and child admission.
Failed evidence writes do not debit. Unspawned reservations return their balance;
exited children continue to consume their entire allocation. Durable checkpoint
writes currently synchronize under the budget mutex, adding disk latency to
broker authorization. Variable provider billing, trusted terminal refunds,
broader revocation, and real Tier-2 validation remain open.

Validation: the full node suite passes 834 unit tests (one ignored) and three
integration tests. The final five conservation regressions also pass, including
the subsequently added preflight/admission case and both checkpoint-versus-
authority snapshot orderings. Detaching the runtime balance and suppressing
checkpoint recovery each cause their regression to fail at runtime; restoring
the implementation passes. Four ledger tests cover failed evidence, checkpoint
failure, malformed/missing history, and poison. Linux ARM64 musl compilation,
Clippy with warnings denied, and all four prepush gates pass. Clippy retains
the existing reqwest configuration diagnostics. Real Tier-2 evidence is pending.

### Operator CLI for host approvals (2026-10-04)

`nucleus node effect-approvals <pod> list|grant|refuse` exposes the host approval
routes through the configured operator's mTLS identity. Grants require an
explicit expected effect SHA-256. The CLI fetches current review metadata before
settlement and refuses unknown, expired, already-decided, duplicated, or
hash-mismatched entries before posting. The server still decides expiry, status,
and operator identity. HTTP errors cannot report a successful grant; the CLI
requires the server's 204 acknowledgment. HMAC credentials cannot substitute for
mTLS, and node mTLS management requests no longer follow redirects.

Node and CLI share the approval wire types in `nucleus-spec`. List output is
JSON, including operation, resolved destination, effect digest, fixed charge,
expiry, and status. UUID parsing prevents path substitution. The command and
its limitations are documented in `docs/host-effect-approvals.md`.

This enables operator settlement but is not complete request review: the host's
current API does not expose payload contents. A hash alone cannot explain remote
semantics. Full payload review and harness retry/pause integration remain part
of the supported coding workflow, as do both end-to-end harness demonstrations.

Validation: 307 CLI unit tests and 16 integration tests pass; hardware-dependent
and explicitly ignored tests remain skipped. All 159 specification tests, the
host operator-route test, and six host effect-approval tests pass. Five new CLI
regressions cover real mTLS list/grant/refuse traffic, exact route and body
selection, stale/expired/ambiguous/digest-mismatched reviews, redirect refusal,
server errors, parser requirements, and rejection of HMAC-only clients. Removing
digest matching or enabling redirects independently makes the relevant regression
fail at runtime; restored code passes. CLI and node cross-build for Linux ARM64
musl. Clippy for all three changed crates with warnings denied and all four
prepush gates pass. The built CLI's help exposes the documented commands.

### Exact host request review (2026-10-04)

Buffered and streamed broker refusals now retain the exact host-owned payload
for pending action-bound approvals. The review metadata is the same canonical
v3 request representation used by effect hashing, moved into `nucleus-spec`
without changing its encoding. Review attachment rechecks the complete body
hash and length against that request and the approval digest. Incorrect bindings
or retained-payload exhaustion refuse the approval. Retention is bounded at
64 MiB per pod; expired entries are inaccessible and pruned on subsequent
approval access. Streamed allowed requests still
replay their temporary files without retaining complete bodies in memory.

The operator-only GET approval route returns the request and base64 payload;
`nucleus node effect-approvals <pod> review <approval>` verifies body length,
body hash, canonical digest, destination, price, and approval identity before
rendering JSON. UTF-8 payloads are also JSON-escaped text; binary payloads remain
base64. Injected credential values are never retained in review metadata.
These are temporary review data, not durable outcome evidence or a claim about
the remote API's semantic success. Harness pause/retry integration, both complete
coding journeys, and Tier-2 validation remain open.

Validation: 838 node unit tests (one ignored), three node integration tests,
160 specification tests, and all seven operator CLI tests pass. A golden digest
checks compatibility with the existing v3 encoding. Real buffered and streaming
broker tests recover exact payloads, exclude injected credentials, and execute
approved retries. The operator route refuses guest review requests; the CLI's
real mTLS fixture verifies retrieval and safe text rendering. Removing host body
verification, the aggregate retention limit, or CLI body verification each makes
its regression fail at runtime; restored code passes. CLI/node Linux ARM64 musl
builds, Clippy with warnings denied, and all four prepush gates pass. The built
CLI help exposes `review`. This remains local evidence, not Tier-2 validation.

### Bounded workload approval pause and resume (2026-10-04)

Stream requests can explicitly request a host approval wait, capped at 120
seconds and the approval's remaining lifetime. The workload proxy defaults to
that pause after its own gates pass; `x-nucleus-approval-wait-seconds` can select
0–120 seconds. Zero/omitted protocol values preserve immediate refusal. This
requires coordinated proxy/host versions because older strict decoders reject
the new nonzero field.

The host retains the original staged upload, exposes its review, and awaits
operator settlement without holding the policy mutex. Grant resumes that upload
through fresh preflight and final authorization, consuming one approval and one
upstream dispatch. Refusal, timeout, revocation, and broker disconnect stop the
pending call. No credentials or upstream I/O occur while it waits. Other policy
failures retain their original refusal messages. A timed-out request's review
remains available until expiry for a later explicit retry.

This is an approval pause on an undispatched request, not automatic retry after
an ambiguous remote effect. Buffered PERFORM calls keep explicit retry behavior.
Local proxy permission/IFC gates still apply. Client timeouts must accommodate
the pause; complete demonstrations with both supported harnesses and real Tier-2
execution are still required.

Validation: 842 node unit tests, 573 proxy unit tests with all features (including
MCP), 24 credential-protocol tests, and 22 integration tests pass; existing ignored
cases remain skipped. Four real broker/upstream wait tests cover grant, refusal,
exact resumed payload hash/length, single dispatch, timeout, review retention,
broker disconnect, revocation, and preservation of unrelated policy refusals.
Protocol tests retain legacy zero/omitted behavior; proxy tests cover the default,
immediate refusal, and invalid wait settings. Bypassing the pause or omitting the
staged-file rewind makes the resume regression fail at runtime; restored code
passes. Node/proxy Linux ARM64 musl builds, strict Clippy for all three changed
crates, and all four prepush gates pass. Broker clients opting into this pause
must keep the upload half open after END; EOF is cancellation.

### First live branch validation: enforcing launch is not wired (2026-10-04)

Measured against `59baa46ac` on the local M5 Pro, Lima VZ/aarch64, Ubuntu
6.8.0-142, and Firecracker/jailer 1.17.0. Both `/dev/kvm` and
`/dev/vhost-vsock` exist. An isolated node at port 18080 used its own state and
CA, a copy of the installed kernel/rootfs, and this checkout's ARM64 musl node,
guest-init, proxy, and four probe binaries. Its mTLS health answered successfully.
This was a manually assembled validation image, not a fresh-install proof.

The guest booted, fetched its SPIFFE identity and host spec over vsock, and
reported `NUCLEUS_EGRESS_PROBE: PASS`. Pod creation then refused
`--broker-enforcing`: `start_broker_for_pod` still calls
`check_enforcement_is_honest(rollout, false)`. Host spec delivery exists, but the
credential split has no launch call site, and guest-init prefers a baked spec
when one exists. The local broker tests therefore do not establish an available
enforcing Firecracker workflow. Do not remove this refusal without establishing
credential-free host spec delivery and guest selection of that spec.

The refusal occurs after VMM spawn and drift-monitor creation. The rejected pod
`ae30ebed-b12e-45e7-bfbc-2fd70ca4c533` left Firecracker PID 1988 running, even
after the isolated node service stopped. This is a confirmed launch-error cleanup
gap; validation terminated that exact process. Broker readiness/refusal must
precede guest execution, with owned cleanup through every subsequent failure.

Two validation setup errors were resolved without disabling gates: long jail
paths exceeded Unix socket limits (use `/srv/nbv` for this isolated setup), and
the jailer needed an absolute Firecracker executable path. The latter surfaced
misleadingly as a seccomp-mode failure because verification inspected the exited
launcher. The old installed rootfs also lacked required egress/podlist probes;
adding current probe binaries allowed boot checks to reach the enforcing refusal.

The next P0 milestone is production launch wiring and rollback, followed by
live approved/denied broker effects and the two complete harness journeys.
`nucleus run` still selects a single external harness in `constants::AGENT_CLI_BIN`;
it is not evidence of the required vendor-neutral two-harness workflow.

### Broker readiness before guest execution (2026-10-04)

The observed launch leak is fixed by moving broker preparation before the VMM
spawn. A private `PreparedPod` can only be constructed after identity preparation
and broker admission/binding; its spawn method marks the child to terminate on
drop. Failed preparation drops identity services and uses the existing network
and jail rollback. Successful preparation transfers the broker to the running
pod by value. Enforcing mode still refuses until credential-free host spec
delivery is connected; this change does not remove that safeguard.

Live reproduction on the same local VM now refuses before any guest console
output, with no remaining Firecracker process, network namespace, or jail. The
positive control, pod `41ea9962-d560-4b00-900b-da5eafe483d5`, successfully booted
with broker listen mode, then cancelled through the mTLS API; its VMM and broker
socket disappeared. No confinement checks were disabled.

Local regressions exercise pre-spawn refusal and identity cleanup, failed spawn,
and an actual child process dropped during launch. Disabling child cleanup makes
the latter fail at runtime by leaving its process alive; restored code passes.
The full node run passed 843 unit tests, with one existing ignored case and one
source-order test failing on the renamed preparation variable; that test passes
after updating its reference. All three integration tests, the final Linux ARM64
musl build, strict Clippy, and all four prepush gates pass. The final Linux binary
was also rechecked against the live enforcing refusal with no VMM or jail left
behind. Credential-free spec delivery and complete agent journeys remain open.

### Enforced host-spec delivery and a real workload (2026-10-04)

Firecracker enforcing mode now prepares the served spec by stripping every
`credentials.env` value from a copy. Serialization failure refuses preparation.
A private withholding witness is retained only after the workload API is ready;
broker preparation requires that witness before it can claim enforcement. The
broker still obtains credentials from the operator registry's host environment
or federation, never by substituting caller-supplied credential values.

The node adds `nucleus.host_spec=required` to enforced boots. Updated guest-init
requires the fetched spec and selects it even when the image has a baked spec;
missing delivery and invalid/repeated mode arguments refuse. Legacy/listen mode
retains its existing precedence. Before admitting an enforcing pod as running,
the node requires guest-init's compatibility acknowledgment as well as the
existing health and confinement checks. That guest acknowledgment is not
independent execution evidence. Unsupported drivers refuse `--broker-enforcing`
at startup instead of silently using legacy delivery.

The real local VM rejected the previous guest-init for missing acknowledgment.
With updated guest-init, enforcing pod
`017817ee-ca7b-4632-b981-a57d0f28ada6` booted from the same image, which still
contained its old baked spec. Its host-selected generic workload reported
`HOST_SPEC_WORKLOAD_PASS` after checking the credential environment value was
absent. It was subsequently cancelled through the mTLS API. This is a useful
live launch/workload control, not a complete harness journey or host-authoritative
proof of workload output. The image remains manually assembled for validation.

The workload-API socket regression fails on the previous delivery path because
the literal canary credential reaches the guest. Restored delivery passes while
preserving workload command/arguments and legacy behavior. Bypassing required
host selection makes its regression fail by choosing the baked spec. The full
node run passes 845 unit tests and three integrations; guest-init passes 50
unit tests and four doctests, with existing ignored cases retained. Subsequent
focused checks cover the startup-driver refusal and final preparation witness.
Linux ARM64 production builds, strict Clippy, and all four prepush gates pass.

The next live milestone is approved and denied broker effects from this guest,
with independently verified host journals, followed by the two full harness
journeys. Secrets deliberately baked into an image or placed in arbitrary
workload arguments/files are not scrubbed by `credentials.env` preparation.

### Real workload broker access (2026-10-04)

A UID-1000 workload in the enforcing Firecracker guest could not connect to its
workload door: guest-init's restrictive umask made newly created socket parent
folders mode 0700 despite `DirBuilder::mode(0755)`. The `/run` tmpfs root also
used the kernel's default 0777. New door folders now receive explicit 0755
permissions without widening existing private ancestors. Tmpfs mount policy
explicitly selects root-owned runtime mode 0755 or shared temporary mode 1777.
An isolated subprocess regression exercises the real restrictive umask; the
mount regression rejects omitted mode options. Both failed against their
respective old implementations before passing with the fixes.

The rebuilt production guest-init and all-feature proxy were installed into an
isolated local ARM64 validation image. Real pod
`590ab208-bdab-4015-aae2-0fef8d86a394` reported `/run` and `/run/nucleus-door` as
root-owned 0755. Its unprivileged workload received HTTP 200 through the broker;
the local upstream observed the exact fixture payload and host-supplied test
credential. The independent audit CLI verified one host authorization and one
linked transport outcome, with zero unknown outcomes, using a public key derived
separately from the node's persisted certificate-root key. The pod was cancelled
after validation. This proves a legitimate baseline broker call from a real
guest, not the approval-gated path, a fresh installation, or a coding harness
journey. The upstream was a local fixture, not an external provider.

Validation: 574 proxy unit tests and 51 guest-init unit tests passed, alongside
their integration/doc tests (existing ignored tests remain ignored). Linux ARM64
musl builds and strict Clippy passed for the affected crates.

### Guest approval handoff to the enforcing broker (2026-10-04)

Real approval pod `88bf0502-28b5-45c7-b5bc-e66e1583e83e` exposed a second
integration failure after socket access was fixed: the proxy returned its own
approval-required 403 before the host saw the request. The host approval list
stayed empty, so operator approval could not make progress.

Broker mediation now returns a private submission witness, not an approved
execution token. It records the actual local decision, preserves hard capability
and IFC denials, and forwards approval deferrals as `require_approval` in the
signed stream OPEN. Guest-local grants do not discharge that requirement. The
host applies its own policy and this additional restriction at preflight and
final commit. Operator review and the canonical effect digest include the flag;
the false/absent field preserves the existing v3 digest. Older hosts fail closed
on the new stream field. Buffered PERFORM retains its existing host policy path.

Real enforcing pod `25150e77-e567-41b8-9e67-59a9deaa3a89` staged its request
and appeared as pending without any upstream call. Review exposed the exact
fixture payload and the additional approval requirement; independently
recomputing the canonical digest matched the pending effect. Granting through
the operator's mTLS API resumed the original request, returned HTTP 200 to the
UID-1000 workload, and produced exactly one authenticated upstream call. The
approval became spent. The offline audit CLI verified one host authorization
and one linked outcome with zero unknown outcomes under the independently pinned
node public key. Refusal-control pod `a4aeaae0-3f77-49db-a8f6-4bde813dd840`
returned an explicit host-operator refusal, made no upstream call, and left both
execution journals empty. Both pods used the isolated local ARM64 image and a
loopback fixture upstream, not a released image or an external provider.

Regression tests cover submission without a fabricated guest grant, preserved
capability/poisoned-flow denials, grant/refusal when only the guest requires
approval, payload review, and digest binding. Dropping the guest deferral or
ignoring it at the host independently failed the corresponding runtime tests;
restoring the fixes passed. Full affected suites passed: 846 node, 576 proxy,
309 CLI, 160 spec, and 24 credential-protocol unit tests, plus integration/doc
tests; existing ignored tests remain ignored. Strict Clippy, Linux ARM64 musl
node/proxy builds, and all four prepush gates passed.

This establishes a real approved and refused broker journey with host evidence.
Fresh installation, the two complete coding harness journeys, full compromised-
guest validation, and the remaining release workstreams are still required.

### Preparing ordinary HTTP harness clients (2026-10-04)

The existing generic workload spec and in-guest MCP bridge provide the launch
and tool surfaces. `nucleus run` still launches its selected assistant on the
host; it is not the path for the two in-pod acceptance runs. Aider and Continue
are provisional external harness candidates. Their official documentation
supports configurable API bases and noninteractive coding runs:
[Aider endpoint configuration](https://aider.chat/docs/llms/openai-compat.html),
[Continue headless mode](https://docs.continue.dev/cli/headless-mode), and
[Continue configuration](https://docs.continue.dev/reference). Provider-specific
configuration belongs in the external harness, not the runtime.

Ordinary HTTP clients need an adapter to the Unix workload door. Before adding
that adapter, a real UID-1000 TCP loopback round trip in pod
`41d40570-5546-4afe-af13-c2f1017d8180` failed with `Network unreachable`:
guest-init never brought up `lo`. The same probe passed in pod
`4a0a11d5-92d2-4e98-94bc-f8a3b0fcc904` after enabling loopback through the
existing Rust netlink encoder and acknowledgement handling. This adds no external
address or route. The boot's external egress probes still refused both public
IPv4 destinations and reported PASS. Loopback setup failure aborts boot before
workloads launch. The shipped workload probe now exposes `--loopback` for
repeating a bounded TCP round trip without a custom probe binary. That shipped
stage passed in real pod `9ab0450f-42ec-4225-9867-b55a7b2fd1b5`, alongside
the external egress denials. All probe pods were cancelled after validation.

Guest-init's existing unit/doc tests and the workload probe's 17 tests pass.
Portable strict Clippy and Linux-only guest-init Clippy pass; production
Linux ARM64 musl builds pass. This establishes localhost availability only.
Fresh image installation and both coding-to-PR acceptance runs remain to be
implemented and demonstrated.

### Ordinary HTTP adapter validation (2026-10-04)

The unprivileged `nucleus-egress-http` companion now maps a loopback HTTP
listener to one configured upstream through the Unix workload door. It holds
no upstream credentials and cannot select external TCP transport. It streams
uploads and responses, forwards only explicitly supported headers, refuses
unsupported method/path/query syntax, and disables redirects and retries.
Its current protocol limits and launch instructions are in the tool-proxy
README. Release image packaging and harness supervision remain open.

Real Firecracker pod `87b66b51-1d19-4b5e-af05-21a5330fa952` ran the adapter
and a TCP HTTP client as workload UID 1000. The guest received HTTP 200 and
`LIVE_HTTP_ADAPTER_PASS`; the fixture observed `/http`, the exact 17-byte
payload, and the host-injected disposable credential instead of the client's
dummy header. The boot probes still denied direct public IPv4 connections.
An external verifier using the independently pinned host public key verified
one authorization and one transport outcome, with zero unknown outcomes.
This proves the transport path and authorized journal prefix, not a harness
journey, remote action semantics, or complete session evidence.

Six adapter tests cover a 2 MiB streamed upload, incremental SSE, header
stripping, status preservation, redirect refusal, invalid routes/listeners,
missing Unix transport, and cancellation both before headers and during the
response. Negative controls enabling redirects or bypassing path validation
fail their tests. Restored tests, strict all-feature Clippy, and the Linux
ARM64 musl build pass. The existing proxy suite also passed with all features.
All four prepush gates pass after tightening the measured suppression ratchet.
The disposable validation pod was cancelled and its isolated services stopped.

### Apple Container acceptance host (2026-10-04)

Use Apple Container in preference to Lima for further local work. A fresh
default-kernel probe with `--virtualization` has neither `/dev/kvm` nor
`/dev/vhost-vsock`. The existing custom L1 kernel from
`docker/Containerfile.l1-kernel`, digest
`7f1beb7167f70b031a73f731fc2c28af403e4fda064e3d3cacc989a9927a020d`,
exposes both devices and tun when supplied per container with `--kernel`.
No system-wide kernel setting was changed.

The current enforcing node and HTTP adapter journey passed in nested
Firecracker pod `b4879187-5f5f-46d6-abab-2b0e0d69a876`, hosted by Apple
Container 1.4.1 with that kernel and NET_ADMIN, SYS_ADMIN, and SYS_PTRACE.
Fresh node state minted its own identities; no Lima private keys were copied.
The UID-1000 client received HTTP 200, and the fixture observed the exact
17-byte payload and host-injected credential. Independent verification with
the new host's public key passed for one authorization and one outcome, with
zero unknown outcomes. The pod was cancelled after evidence collection.

The first launch exposed a host setup prerequisite: cgroup controllers cannot
be enabled while processes occupy this container's cgroup root. The jailer's
actual error was `cgroup.subtree_control: Resource busy`; the node surfaced it
as a seccomp verification failure. Moving the disposable host processes into
a child cgroup allowed the next launch, with seccomp verification still on.
Production host setup and diagnostics must handle this before fresh-install
acceptance can be claimed.

This experiment used read-only mounted copies of existing validation binaries
and a patched guest image. It is not fresh-image packaging or either complete
harness acceptance run. The local dependency image build succeeded after
reclaiming regenerable incremental Rust cache and restarting the builder;
disk exhaustion had caused I/O errors and a read-only builder filesystem.

### Automatic container cgroup preparation (2026-10-04)

`nucleus-hostctl run-node` is now the microVM host image's entrypoint. It
requires Linux PID 1 at the unified cgroup root, moves only itself into
`nucleus-host`, checks that the root is empty, and consumes that preparation
witness to exec the fixed node binary with the supplied arguments. It neither
evacuates other processes nor disables resource controls. Children inherit
the leaf; the jailer can enable controllers for its sibling pod hierarchy.
This follows the kernel's [cgroup v2 no-internal-process rule](https://docs.kernel.org/admin-guide/cgroup-v2.html#no-internal-process-constraint).

The preceding direct-start experiment failed with `Resource busy`. A fresh
Apple Container using this entrypoint launched pod
`8ebb726b-6e81-4d8b-8b4a-eec21806d651` without manual cgroup writes. PID 1
was observed in `/nucleus-host`; the root was empty; CPU, memory, and PID
controllers were enabled after launch. The HTTP adapter probe passed, and
the independent verifier accepted one authorization and one outcome with
zero unknown outcomes. The pod was cancelled and its container stopped.
This validates startup preparation, not aggregate admission or either full
harness journey. The dedicated host used mounted current binaries and the
existing patched validation guest image; a fresh packaged release remains open.

The host crate's 44 library tests and two CLI tests pass, including refusal
outside container PID 1, refusal of an occupied root, and unchanged forwarding
of node arguments. Portable and Linux-target strict Clippy and the Linux ARM64
musl build pass.
All four prepush gates pass for the entrypoint change.

### Two harnesses packaged and booted (2026-10-04)

Apple Container built an external acceptance image containing Aider 0.86.2
and Continue CLI 1.5.47, with Python 3.11.2 and Node 22.23.3. Both version
commands and help commands ran as UID 1000. The base image is pinned to
`sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c`;
the resulting harness image index is
`sha256:4ae98061c558d578e4933db0c6df8865ebc09cc6982b1bf0ce20835b4c9ca3fd`.
No model credentials were installed. The external recipe is local at
`/tmp/nucleus-harness-context/Containerfile`; vendor configuration stays out
of the runtime.

`nucleus image import --oci-archive` verified that image for linux/arm64 and
produced normalized rootfs tar
`sha256:9a69ef84f0e880477245528dc850df3df54917665d62e21a5961d3e8495c679c`
(1,153,532,416 bytes). The existing rootfs builder consumed that imported
filesystem with current guest binaries and an explicit HTTP-adapter overlay.
The new 2 GiB ext4 artifact is
`sha256:253b6ad6336b3d331d2204bbcbbe010a53d31b0d8260201d5dcb051844874b9e`,
locally at `/tmp/nucleus-apple-acceptance/artifacts/harness.ext4`.

Separate Firecracker pods on the automatically prepared Apple Container host
ran each harness as UID 1000 with this read-only guest image:

| Harness | Pod | Observed guest output |
| --- | --- | --- |
| Aider | `98c40da5-c47b-4c32-979c-0f5f756a55c8` | `aider 0.86.2` |
| Continue | `87a7e7a1-4abd-4880-9f70-59ff4a4ef4cb` | `1.5.47` |

Both produced exit reports, and the guest external-network denial probes
passed. Both pods were cancelled; the validation host and builder were stopped.
This proves packaging and guest startup compatibility only. Full model
requests, coding/tests, scoped approval, PR creation, and independent evidence
verification remain open for both harnesses. A model endpoint/model and host
credential reference have been requested; no secret value is needed in chat.
The adapter still needs ordinary release-image inclusion rather than the
explicit acceptance overlay, and the published fresh-install journey remains
unverified.

### HTTP adapter included in guest packaging (2026-10-04)

The guest manifest now distinguishes a Cargo package from its executable
targets. `nucleus-egress-http` is the ninth guest binary, built by the existing
tool-proxy package. The release workflow uploads it for rootfs assembly; the
legacy rootfs builder requires it beside `PROXY_BIN`, includes it in its
`--verify` input list, and copies it after overlays. The deterministic Rust
guest-layer builder reads and checks the companion separately from the proxy.
No new shell branching or gate logic was added: the existing input list was
extended and assembly uses unconditional copy/chmod commands.

Regression tests refuse a missing companion even when the proxy exists,
a release omitting its upload, and a release selecting only the proxy binary.
Changing binary lookup or upload verification back to package-name lookup
made those tests fail; restored tests pass. Actual rootfs build and `--verify`
invocations also refuse the missing adapter. A new harness ext4 image built
without any overlay contains a byte-identical adapter. The deterministic
guest-layer tar assembled from current prebuilt binaries also contains that
exact executable (SHA-256
`96623e9a1243813b255829125647ef2044404faa7b1d0622d716d9c754d97611`).

All 13 guest-layer tests and 160 spec tests pass, as do strict Clippy and the
existing release-input shell check. The spec suite also exposed and corrected
an assertion still expecting the pre-cgroup-preparation container entrypoint.
This completes adapter inclusion in the source packaging paths, not a published
release, fresh user installation, or either full harness journey.

### Compromised-guest PERFORM conformance (2026-10-04)

Real Firecracker pod `337861be-81ef-4842-b8f4-041ac9e64950` ran a disposable
root-level wrapper in place of the mediating proxy. It launched the ordinary
proxy for the control-plane listener, but submitted its own signed PERFORM
frames directly over vsock, using the delivered pod broker capability without
calling the guest kernel or spending a guest authority. This tests the host
against a guest that bypasses its own checks, not just a confined workload.
The external probe source is `/tmp/nucleus-compromised-broker-probe/src/main.rs`,
SHA-256 `1cf267a7feb2f8f6da3fac617cb486e316a46882a1de593e2fa9492b1bf116bb`.

The node used an inline network-only policy with a $0.002 budget and the
fixture upstream's fixed $0.001 call tariff. Observed results:

| Direct guest request | Host result | Additional upstream calls |
| --- | --- | --- |
| Forbidden GitPush | Refused | 0 |
| WebFetch with an invalid signature | Refused | 0 |
| Allowed WebFetch | HTTP 200 | 1 |
| Identical retry with the same idempotency key, on a new connection | Cached result | 0 |
| Changed payload under that key | Effect mismatch refusal | 0 |
| Eight concurrent unique calls with one charge remaining | Exactly one grant; seven budget refusals | 1 |
| New call after reconnect at exhausted budget | Refused | 0 |

The independent fixture log grew by exactly two calls, both authenticated
with the disposable host credential. External verification against the host's
public key accepted exactly two authorizations and two transport outcomes,
with zero unknown outcomes. Each signed authorization recorded a 1,000-micro-USD
charge. The pod was cancelled and the Apple Container host stopped.

This promotes these PERFORM properties to real compromised-guest evidence.
Raw streaming approval/replay/taint cases, foreign pod/epoch attempts, durable
recovery, and the rest of the full conformance matrix remain open. No production
policy or transport enforcement was disabled; only the disposable guest image
was replaced to act as the adversary.

### Streaming approval expiry found by the guest probe (2026-10-04)

Compromised Firecracker pod `ac8ca38f-98a1-404f-bed0-6980f9a9a9e9`
submitted a raw STREAM with `require_approval=false` under a host policy that
requires WebFetch approval. The host retained the exact 23-byte payload for
operator review and sent nothing upstream before the grant. After the grant,
the guest received `not permitted`; its remaining replay cases did not run.
This is a failed acceptance run, not streaming conformance evidence.

A regression reproduced that refusal by granting after 61 seconds. The
credential PDP witness expires after 60 seconds, while operator review may
wait 120 seconds. The stream retained its initial witness across staging and
review, then tried to retrieve credentials using that expired authorization.
The fix reruns the existing resolver after staging and review using the same
immutable request, identity, policy and registry. It does not extend an old
witness's expiry. Shared host policy is still checked before credential access
and at final effect commitment, where the exact operator grant is consumed.

The new expiry regression failed before the fix and passed afterward. The
full node binary suite passed 847 tests (one ignored), Clippy with warnings
denied completed successfully, and all four tree prepush gates passed. A clean
default-feature test check also exposed a route-test module that used the
local-driver fixture without its feature guard; matching that guard restores
default-feature test compilation.

The live adversarial follow-up was stopped at the operator's request. Current
work focuses on design implementation and ordinary functional integration;
the preceding test results do not claim that stopped live run completed.

### Managed HTTP adapter workload (2026-10-04)

The adapter now accepts `-- command args...`. It binds the loopback listener
before spawning that command, supplies `NUCLEUS_EGRESS_HTTP_URL`, and preserves
the direct child's exit status. Both processes run inside the already admitted
workload's UID and containment, with its filtered environment and captured
standard streams. A child exit closes the listener; adapter termination kills
and reaps the direct child. The pod supervisor retains responsibility for
descendant cleanup. Standalone listener mode remains available.

All eight adapter tests passed, including endpoint delivery, exit status,
listener shutdown and direct-child reaping. An actual CLI invocation with an
ephemeral listener and ordinary shell workload preserved exit code 7. Clippy
with warnings denied passed. This implements managed launch; a complete coding
session and artifact/approval UX still remain to be exercised.

### Workload output CLI (2026-10-04)

`nucleus node workload <pod> result|logs|collect` now exposes the existing
node APIs using the provisioned mTLS identity. Logs go to exact-byte files;
collection exports either the execution receipt or the receipt and declared
artifact bundle. Output publication never overwrites an existing file. The
CLI preserves node refusal details and distinguishes a workload's exit status
from failure of the management request. Collection does not itself verify the
signature or execution expectations. Usage and the artifact selection format
are documented in `docs/handoffs/nucleus-build-receipts.md`.

The CLI suite passed 311 tests (two ignored), including binary output
preservation and artifact selection, and Clippy and all four prepush gates
passed. These checks do not complete the two live coding-harness journeys.

### Execution evidence verification CLI (2026-10-04)

`nucleus-audit verify-execution` and `verify-artifacts` now consume exported
receipts/bundles and a separate trusted `RecordedExecution` file. They call the
existing shared verifier for signer, run binding, protected Firecracker execution,
issuance window and artifact identities, and recheck the deadline at consumption.
The JSON report preserves the observed workload exit code; verification success
does not claim a successful build. Receipt-only verification explicitly reports
no artifact-byte verification. Usage and expectation provenance are documented
alongside collection in `docs/handoffs/nucleus-build-receipts.md`.

All 134 audit tests passed, including a CLI integration that verifies a signed
receipt and binary artifact while preserving nonzero workload exit status.
Clippy and all four repository gates passed. The full coding journeys remain open.

### Aggregate node capacity admission (2026-10-04)

The node now reserves pod memory (including 128 MiB VMM overhead) and vCPUs
against one shared pool before launch. Booting pods count against the pool;
failed or cancelled creates return their reservation. A registered pod retains
it until successful teardown. Capacity exhaustion returns HTTP 503 with the
requested and available amounts. Per-pod ceilings remain independent.

Operator capacity and host reserve flags are documented in the node README.
Linux memory detection is capped by visible cgroup-v2 ancestor limits. Other
hosts require an explicit memory capacity; cgroup-v1 deployments should also
configure capacity explicitly. Ordinary concurrency and lifecycle tests cover
pool conservation, host reserves, cancelled creates and completed teardown.
The full node suite passed 850 tests (one ignored). Linux ARM64 builds, Clippy
and all four repository gates passed.

This implements process-lifetime aggregate admission, not the entire resource
priority. Reconciling external containers surviving a node restart remains open;
the subsequent staging reservation implementation is recorded below.

### Pod swap bounds (2026-10-04)

Firecracker cgroup v2 limits now include `memory.swap.max=0`; v1 includes a
combined memory-plus-swap ceiling equal to the VMM memory allowance, with the
required memory-before-combined write order. Spec overrides cannot increase
either bound. Hosts must expose the applicable control; unsuccessful writes
prevent launch. Container memory/swap settings already bound their combined
allowance. This does not claim swap-free behavior for v1's combined controller.

All six resource tests and 36 Firecracker configuration tests passed, including
the actual jailer argument path. A disposable cgroup on the Apple Container host
accepted and read back `memory.max=671088640` and `memory.swap.max=0`, then was
removed. Clippy passed. Subsequent ordinary artifact workloads booted and
completed on the updated node with these defaults (see admission export below).

### Development cgroup lifecycle (2026-10-04)

Direct-spawn placement now returns an owned handle for a newly created cgroup
leaf and carries it into the Firecracker pod handle. Successful teardown removes
the leaf after stopping the VMM. Cancelled or failed launch drops retry a busy
leaf for up to one second, reporting cleanup failure. Existing directories are
borrowed, never deleted, and parent hierarchies are preserved. A normal teardown
failure retains the pod's aggregate capacity reservation for a later retry.

Eight focused tests passed, including ownership-preserving cleanup and a busy
leaf becoming removable after cancellation. Clippy, the Linux ARM64 build and
all four repository gates passed. These are ordinary filesystem/lifecycle tests;
abrupt node termination and stale cgroup reconciliation remain separate work.

### Shared upload staging reservations (2026-10-04)

All production pod brokers now share one node-owned payload-storage budget.
`--egress-staging-max-bytes` defaults to 256 MiB. An upload reserves its full
configured per-call maximum before creating a temporary file; the reservation
stays with the body through approval and replay and returns on release, error or
cancellation. With default 32 MiB requests this permits eight concurrent staging
reservations. Exhaustion refuses before credential access or upstream I/O, and
startup refuses a capacity smaller than one maximum request. This conservative
reservation avoids accepting partial uploads that later run out of shared space.

The budget bounds reserved payload bytes, not filesystem metadata, unrelated
temporary files or physical free space. Egress accounting remains upload-only
as designed; response limits are separate. Direct-network accounting and the
other egress paths still need integration into the pod's shared outbound budget.

All 26 streaming tests passed, including shared staging capacity, body release,
malformed-upload cleanup and the timed approval lifecycle. Clippy, the Linux
ARM64 build and all four repository gates passed.

### Admission export and ordinary workflow verification (2026-10-04)

`nucleus node workload <pod> admission --output admitted.json` now saves the
host's effective program identity, source labels, artifact declarations and
public executor identity through the authenticated node API. This fills a gap
between pod creation and independent verification: admission replaces requested
policy with an effective inline policy, so the requested spec alone does not
necessarily identify the executed program. The response reads host state without
contacting the guest and exports neither environment values nor private keys.
Controllers still supply their expected resolved environment and freshness window,
and compare the public key with their configured enrollment pin.

A normal shell workload ran at UID 1000 inside Firecracker on Apple Container,
produced two files and exited zero. The CLI exported admission metadata before
collecting its bundle. A separately read host public key matched the admission
key; the environment-input digest was computed from the explicitly declared
environment, not from the receipt. The existing `nucleus-audit verify-artifacts`
command then verified the signature, run bindings and both artifacts' bytes.
The earlier ordinary run also retrieved exact stdout via the CLI. Both pods
were cancelled after collection. This is a file-producing workflow check, not
a model-driven repository edit or a completed coding-harness journey.

All ten workload API tests and the CLI suite (311 unit tests, two ignored, plus
integration tests) passed. Clippy, Linux ARM64 node/CLI builds and all four
repository gates passed. Usage and expectation construction are documented in
`docs/handoffs/nucleus-build-receipts.md`.

### Managed adapter guest integration (2026-10-04)

The current managed adapter was cross-built for Linux ARM64 and installed in a
disposable copy of the packaged harness rootfs. A Firecracker pod on Apple
Container launched the adapter at UID 1000 with an ephemeral loopback listener.
Its Python child started both installed harness version commands successfully,
then used the supplied listener URL for one ordinary POST through the enforcing
broker. The fixture recorded the expected request body and host authentication;
the child wrote the harness versions, response and UID to its declared artifact.
The adapter and supervised workload exited zero.

The CLI saved admission metadata before collecting the bundle. Expectations
used the separately pinned executor key and an environment digest derived from
the declared values plus the runtime's known upstream URL binding. Independent
artifact verification passed for the program, environment, receipt signature
and artifact bytes. The pod was cancelled after collection. Evidence is local
under `/tmp/nucleus-apple-acceptance/managed-{admission,expectations,bundle,verified-report}.json`.

This validates managed launch, harness startup, ordinary brokered HTTP and
verified output together. It does not establish model compatibility, repository
editing, a complete coding session, or fresh release-image assembly; the image
used a disposable binary replacement. Model endpoint configuration remains
needed for the two complete coding journeys. The tool-proxy README now shows
the managed workload spec and explains how a launcher passes the local URL into
its harness configuration.

### Container teardown retains resources until confirmed (2026-10-04)

While investigating restart reconciliation, ordinary teardown was found to ignore
Docker removal errors and release the pod's concurrency slot and aggregate
capacity anyway. Container teardown now requires successful removal or Docker's
explicit not-found response. Other errors retain both reservations and reach the
cancel caller. The reaper now retries failed cleanup on subsequent passes; it
records exit and releases authority only after cleanup succeeds. Container
lifecycle code was extracted from the node entrypoint to keep this path together.

Two Docker API fixture tests exercise a temporary removal error followed by
success, one-time exit recording, capacity return and already-absent cleanup.
The full node suite passed 856 tests (one ignored), plus three integration tests.
The Linux ARM64 build and all four repository gates passed. Clippy completed
with the existing configuration warnings about unreachable blocking-client paths.
This is registered-pod teardown coverage. Cancellation during unfinished Docker
create/start and discovery of containers surviving a node restart remain open.

### Startup container reconciliation (2026-10-04)

The node now holds an exclusive state-directory file lock from startup until
exit. This prevents two current node processes from managing the same state.
The lock file remains on disk; its existence alone does not imply a live owner.
Upgrades from versions without locking must stop the old process first.

Container startup inventories the configured Docker daemon before API listeners
are opened. It removes containers labelled for this canonical state directory,
including unfinished launches with those labels. Older unlabelled containers
are matched by their exact pod-directory bind and existing spec. Other state
directories and unrelated containers are left alone. Confirmed removals preserve
bind-mounted host files, record a recovery event and release restored authority
allocations. An unconfirmed removal stops startup so capacity is not treated as
available. Runtime authorization history is not resumed; leftover workloads are
stopped rather than attached to a new policy and budget.

Three focused tests passed for lock lifetime, owned/legacy container recovery,
host-file preservation and removal retry. The Linux ARM64 node started on Apple
Container and answered mTLS health; a second process using the same state
directory exited with the explicit lock error. Clippy completed with existing
configuration warnings, and all four repository gates passed. Docker recovery
was exercised through its real client against an HTTP fixture, not a live daemon.
In-process interrupted launch cleanup remains open, including remote creates
that are still in flight when a process exits. Recovery requires the same state
directory, Docker daemon and container driver.

### Container launch survives request cancellation (2026-10-04)

HTTP and gRPC container creation now run the existing admission/launch path in
a node-owned task. Cancelling the request future no longer drops reservations
while Docker is processing create/start. The result has an owned handoff: if the
request task never accepts a successful launch, the node cancels the registered
pod and retries removal while retaining resources. This covers a receiver dropped
before send and a queued delivery dropped before acceptance. Other drivers keep
their existing creation path.

Failed starts and post-start setup errors now remove the created container before
returning launch reservations. Every create has a unique node-generated Docker
name. After an uncertain create transport failure, cleanup waits for that name
to appear and be removed; an initial 404 cannot establish that the remote create
will not complete later. A name-conflict response does not authorize removing
the pre-existing container. An unresolved transport outcome conservatively holds
capacity in the current process and reports pending cleanup in the node log.

Four ordinary Docker API fixture tests cover delayed create cancellation,
successful handoff, failed-start rollback and a late container appearing after
an initial not-found response. Capacity and concurrency slots remain held until
confirmed cleanup. The full node suite passed 863 tests (one ignored), plus
three integration tests. Linux ARM64 build and all four repository gates passed;
Clippy completed with the existing blocking-client configuration warnings.
This is request-task cancellation handling, not proof that the remote client
received a response. Durable pending-create reconciliation across node process
termination remains open; startup inventory alone cannot settle a late remote
create that appears after that inventory.

### Durable container create records (2026-10-04)

The node now writes and syncs a launch record before sending Docker a create
request. It reuses the existing atomic, file-and-directory-synced record writer.
Records distinguish an unresolved request, a returned Docker response and an
observed container ID. A concrete ID is persisted before start or removal;
record deletion is synced before normal teardown returns capacity.

Startup reconciles these records before inventory and before opening API
listeners. A pending create that is absent remains unsettled and prevents
startup, identifying the retained record. Once a late container appears, its
ownership labels are checked and its ID persisted before removal. A crash
after removal but before clearing the record is recoverable: absence of the
recorded ID settles it. Confirmed cleanup releases restored authority and records
a lifecycle event. Workspace files are preserved. If an unresolved create never
appears, operator reconciliation remains necessary; an empty inventory alone is
not evidence that a remote request cannot finish later.

The container-focused suite passed 24 tests (one ignored), including reconstruction
from disk, a late create after restart, the checkpoint-before-delete ordering,
already-removed recovery and existing cancellation/rollback behavior. Linux ARM64
build and all four repository gates passed. Clippy completed with existing
configuration warnings. Docker behavior was exercised with HTTP fixtures, not a
live daemon or a filesystem power-loss experiment. Broader release acceptance
and the two model-driven coding journeys remain open.

### Live Docker lifecycle and resource readback (2026-10-04)

A real Docker 20.10.24 daemon (API 1.41) ran inside the Apple Container validation
host using vfs storage and disabled bridge/IP-forwarding configuration. A separate
node used the container driver and explicit unmediated mode for an ordinary
shell fixture. This is container-driver lifecycle evidence, not mediation or
microVM execution evidence. The small fixture image produced a workspace file
and remained running so cancellation and restart behavior could be observed.

The first create exposed a real configuration gap: Docker accepted the request
but rewrote the requested combined memory/swap limit to `-1`, emitting a warning.
The node now inspects accepted HostConfig before starting the container and
requires the admitted memory, swap, CPU and process limits. Missing or rewritten
values trigger the existing launch rollback with a named resource error. A
regression fixture verifies that rewritten swap never reaches Docker's start
endpoint and that cleanup returns reservations. This readback establishes the
daemon's accepted configuration; kernel enforcement still belongs to the host.

On a subsequent live create, Docker retained all limits. The actual cgroup read
back `memory.max=536870912`, `memory.swap.max=0`, `cpu.max=100000 100000` and
`pids.max=4096`. Pod `d4b9c437-9213-447e-b01b-604a65f88615` remained running
after the separate node process was killed. Restarting that node recovered the
observed-ID journal, removed the surviving container, cleared the launch record,
recorded `pod_recovered_stopped`, preserved the workspace file and served mTLS
health. A new pod was then admitted and cancelled successfully. All test
containers were removed and the extra node and Docker daemon were stopped.

The container-focused suite passed 26 tests (one ignored). Linux ARM64 build
and all four repository gates passed; Clippy completed with existing configuration
warnings. The late-create/unknown-outcome cases still have fixture coverage,
not a live interrupted Docker-create demonstration. The full release goal remains
open, including the two complete model-driven coding journeys.

### Shared Firecracker link and broker accounting (2026-10-04)

Historical sampled implementation, superseded by packet admission below.

Pod preparation now creates the egress ledger and passes the same Arc to both
broker paths and the direct-link monitor. The link reader must initialize before
VMM spawn. It samples the host veth's RX counter every 100 ms: namespace uploads,
including packet overhead, retransmissions and setup traffic. Host broker
requests use a different route and are not counted twice. Download bodies are
not charged; outgoing acknowledgments are.

The spawn API is only available on the completed preparation type: broker
readiness alone cannot spawn a VMM without an explicit network-accounting step
(ADR 0007 D-1). Shared meter ownership follows G-1; an unavailable counter refuses
new accounting instead of becoming a zero observation (A-2).

Exhaustion closes the link without modifying the iptables drift baseline.
Counter read failure or reset makes the shared ledger unavailable to subsequent
broker admissions. Normal teardown closes and samples before removing network
resources. A failed close is retried; teardown returns an error after six seconds
while retaining the monitor for the reaper. Cancelling that wait also retains
ownership. The final lifecycle record names the observed link byte count even
when the ledger has clamped at its ceiling.

The ordinary Linux namespace test ran inside Apple Container with the production
sysfs reader and cutoff. A UDP payload was received and 189 outgoing link bytes
were charged. A broker-style reservation consumed the remainder of the same
allowance; the kernel link then became administratively down. A separate
Firecracker pod, `b101bb26-393b-44fc-b860-c326cb73c127`, completed the normal
file-producing workflow with exit code zero. Cancellation succeeded and recorded
726 link bytes. The container's default read-only `/proc/sys` initially prevented
network setup; the temporary node used a private mount namespace with that mount
writable. The temporary node was stopped after validation, and the original
node still answered mTLS health.

The full node suite passed 872 unit tests (one ignored) and three integration
tests. Eleven focused tests passed, including shared reservations and refunds, final
sampling, counter availability, close retry and cancellation ownership. The
Linux ARM64 build, Clippy and four repository gates passed. This is sampled
accounting and eventual cutoff, not a strict packet ceiling: bytes can leave
between samples or during cutoff retries, and direct-link pacing is still open.
The unmediated container/local drivers are not covered by this link monitor.
The broader egress milestone and two complete coding journeys remain open.

### Kernel packet admission and ordinary paced uploads (2026-10-04)

Periodic link sampling is replaced by namespace-local NFQUEUE admission.
IPv4 and IPv6 POSTROUTING rules queue packets leaving the peer veth after the
namespace's filter policy. The node reserves the kernel-reported IP length from
the same ledger used by both broker paths before issuing ACCEPT. The transport
requires the reservation by value (C-4/H-1); packet handles also receive one
consumed verdict. GSO is disabled on the queue so the kernel segments before
admission. A total refusal drops the packet and closes the receiver; pace
refusals drop packets while retaining the receiver for later windows.

The netlink socket is close-on-exec, uses async readiness, and is created on a
dedicated OS thread inside the pod namespace. That thread terminates after
socket creation rather than changing a reused executor thread's namespace.
Binding and configuration acknowledgments precede rule installation and VM
spawn. No queue-bypass or fail-open flags are enabled. Shutdown closes the
binding before removing the namespace; pending packets and later packets cannot
be accepted without a listener. The existing cancelled-teardown ownership rule
is preserved. Kernel queue support is an explicit launch requirement and is
retained in the Apple Container kernel fragment.

Ordinary Linux checks ran in Apple Container. A 15-byte UDP upload charged 43 IP
bytes alongside 100 broker bytes. A 4096-byte download consumed no upload
allowance. A subsequent 128-byte IP packet could not fit the 200-byte total and
was not delivered; closing the listener preserved that refusal. A separate
78-byte-per-two-second allowance accepted the first upload, dropped the next,
and accepted another after the window advanced. A 128 KiB TCP upload completed
in 3.84 seconds under a 32 KiB-per-second allowance, charging 135,916 IP bytes.
These are normal traffic and functional budget checks, not red-team exercises.

The first live attempt exposed valid kernel metadata without trailing alignment
padding. The decoder now accepts that framing, with a focused Linux test.
The full node suite passed 871 unit tests (one ignored) and three integration
tests; four packet-ledger/ownership tests, three live network checks and the
Linux decoder test passed. A production Firecracker pod,
`97df55a6-81d2-41b5-9111-3440acf70a8c`, completed the ordinary file-producing
workflow with exit code zero. Cancellation recorded 168 accepted IP bytes and
zero receiver refusals. The temporary node was stopped and its links removed;
the original node remains healthy.

This bounds IP bytes at the queue, not physical wire bytes. Ethernet/ARP and
framing added after queue admission are separate, and broker accounting still
counts request bodies rather than HTTP/TLS overhead. Direct pacing is a
fixed-window policer: it drops excess packets and relies on transport retries,
not a smooth shaper. At this checkpoint broker staged uploads still had to fit within one window;
the unmediated container/local drivers remain outside this packet gate. The
broader egress milestone and complete coding journeys remain open.


### Paced staged broker replay (2026-10-04)

STREAM now reserves the complete staged charge once, then consumes the shared
fixed-window allowance as HTTP polls the body. The producer can buffer file
chunks, but those chunks receive no pace admission until the consumer yields
them. A non-clone upload token limits the sum of all yielded slices and stays
bound to its original ledger. Total-ceiling refusal of another request does not
invalidate volume this upload already reserved; accounting faults still stop
further slices. Direct packets and other uploads share that same window.

The counted path/content-type metadata waits before credentials are resolved.
After that wait, the credential checker runs again, and host effect authorization
still commits against the complete staged payload hash and current policy.
Failures before HTTP handoff explicitly refund the total reservation; dropping
the body after handoff conservatively charges the complete reservation. The
existing 300-second upload/response-head deadline includes pacing time. Very
slow policies can therefore still time out, and PERFORM remains batch-admitted.
This measures application body plus path/content-type lengths, not HTTP/TLS wire
bytes or injected credentials.

Ordinary loopback HTTP validation sent a 250-byte body through 100-byte windows:
it took at least two seconds, completed, and arrived with its SHA-256 unchanged.
Cancellation while waiting retained the full charge and closed the staging
channel. All 28 stream regressions and 15 egress-ledger tests passed; the Linux
ARM64 production build and node Clippy passed. The full node suite passed 873
unit tests (one ignored) and three integration tests. After making the upload
token's ledger epoch explicit, both paced-upload checks and the ledger tests
passed again. All four repository gates passed; the lifecycle floor rose from
13/20 to 14/21 bounded affine rights. These checks do not establish the two
outstanding model-driven coding journeys or cover unmediated drivers.

### Live paced broker upload on Apple Container (2026-10-04)

The node built from `16bcb9204` ran in the existing Apple Container host with
nested Firecracker. Pod `74b7773b-15f9-42cf-9812-07d55272d81a` used the managed
HTTP adapter at UID 1000 to send an ordinary 25,000-byte request under an
8,192-byte-per-second allowance and a 100,000-byte total ceiling. The request
completed in 3.3567 seconds, returned HTTP 200, and the workload exited zero.
The independently hashed upstream payload matched the declared fixture:
`007640a3670f168e43174aa9a9e76aae86612bde6daf21eadb0c24b81b8fac78`.
The host lifecycle record reported 25,000 uploaded body bytes and 11 downloaded
response bytes. Cancellation closed the packet queue with 280 accepted IP bytes
and zero rejected packets; those IP bytes share the pod ledger with the broker.

The CLI collected stdout, host admission metadata, and a signed artifact bundle.
`nucleus-audit verify-artifacts` verified the execution signature and the bytes
of `workflow.json`. Expectations came from host admission, a separately read
executor public-key pin, a finite time window, and the environment computed from
the pod spec plus its declared local upstream address. They were not copied
from the execution receipt. The local records are retained under
`/tmp/nucleus-apple-acceptance/paced-{admission,bundle,expectations,verified-report}.json`.

The completed pod was cancelled, the temporary node and upstream fixture were
stopped, and only the host's original loopback/Ethernet links remained. The
original node still returned healthy over mTLS. This is normal live upload and
artifact verification, not a completed model-driven coding journey. PERFORM
batch pacing, transport-overhead accounting, and unmediated drivers remain open.


### Shared pacing for buffered PERFORM requests (2026-10-04)

PERFORM now reserves its whole body-plus-path allowance once, then hands its
bounded buffered payload to the same paced HTTP body consumer as STREAM.
The shared implementation lives in `egress_meter/body.rs`; staging continues to
feed STREAM through its bounded channel, while PERFORM supplies its already
buffered bytes. Both consume the same pod ledger and neither producer can
pre-admit buffered body slices ahead of HTTP consumption.

After initial path accounting waits, PERFORM resolves credential authorization
again over its unchanged request inputs. Final host authorization still binds
the resolved destination and complete payload before transport handoff. One
300-second deadline bounds the pace wait, credential retrieval and upstream
request/response. An upstream timeout records an ambiguous failure under the
idempotency key; a repeated request returns that result without dispatching or
charging again. Response observation and settled-key timestamps use completion
time rather than the pre-wait timestamp. Cancellation retains the whole upload
charge and its unresolved retry key.

Ordinary HTTP validation sent 250 unchanged bytes through 100-byte windows and
completed after at least two seconds. A completed retry made no upstream call
and spent no additional egress budget. Separate functional checks verified
cancellation after the first slice and bounded upstream timeout settlement.
All 36 PERFORM regressions passed after adding the deadline check. This extends
host-side PERFORM transport; the managed guest HTTP adapter continues using
STREAM. Wire-overhead accounting and unmediated drivers remain open.

The first full-suite run exposed a credential-cache test whose supplied time
assumed no elapsed-time refresh before credential retrieval. Its boundary now
accounts for the conservative one-second rounding already used for final host
authorization. All 16 federated-credential broker checks passed, followed by a
full run of 876 node unit tests (one ignored) and three integration tests. The
Linux ARM64 build, Clippy and all four repository gates passed. No guest image
or cloud service was changed for this host-side implementation.

### Verify the container's selected network mode before start (2026-10-04)

The container driver defaults to `none` and refuses structured network policy.
Its Docker pre-start inspection now checks that the stored network mode matches
the mode selected by node configuration (or the pod's permitted narrowing to
`none`), alongside the admitted resource limits. Missing or changed configuration
uses the existing launch rollback: remove the container, clear its journal, and
return reserved capacity without sending a start request. This verifies the
requested topology; it does not meter traffic on operator-enabled networks.

All 28 container-focused checks passed (one ignored), including ordinary launch
handoff and cleanup on configuration mismatch. The Linux ARM64 build and Clippy
passed. Live Docker validation ran inside the existing Apple Container host:
pod `212a456a-e290-4346-85cc-3b70eafc936a` started with `NetworkMode=none`, exposed
only `lo` inside the container, and wrote its ordinary workspace output after
startup. Cancellation removed it successfully. The temporary node and daemon
were stopped; the original node remained healthy over mTLS.

Network-enabled container and local-driver accounting still need implementation.
Their launch topology differs from Firecracker's pre-created private namespace;
attaching a meter only after starting a workload would leave an unaccounted
interval and is not the intended design.

### Coding journey repository preflight (2026-10-04)

Added `examples/coding-journey/`: an intentionally incomplete, standard-library
usage-record summarizer with nine ordinary functional tests and a bounded repair
task. Two independent local checkouts start at commit
`e67eaa9b63e4a7f80e517d9554eb6614b679d8c8`; a separate retained test copy supports
verification. The baseline tests fail as expected. No scripted repair or model
stub has been substituted for a harness run.

Apple Container hosted Firecracker pod
`ac57ecef-5e20-4333-9d97-05f3e33f9d95` cloned the baseline Git bundle with
`--branch main`, checked the commit and input hashes, ran the failing baseline
tests, and successfully invoked both installed harness help commands as UID 1000.
The preflight wrapper exited zero. An earlier clone without an explicit branch
failed because the branch-only bundle did not advertise a default HEAD; selecting
the branch corrected the checkout.

The independent artifact verifier accepted the execution and all four artifacts
using host admission metadata, the separately pinned executor public key, expected
environment inputs, and an issuance window. Evidence is retained locally under
`/tmp/nucleus-coding-journeys/checkout-{bundle,admission,expectations,verified-report}.json`.
The pod was cancelled, the temporary node stopped, and the primary node remained
healthy.

Model calls: zero. Completed coding journeys: zero. The next dependency is the
operator's model endpoint, model identifier, and existing host credential reference;
no model credential environment variable or endpoint configuration was available
in the inspected local configuration. After configuration, each harness must do
the actual edit, pass the retained tests, exercise scoped approval, and produce
independently verified evidence before the authorized PR and Gatehouse merge.

### Aggregate CPU admission respects delegated quotas (2026-10-04)

Node capacity now reads cgroup v2 `cpu.max` alongside `memory.max` across
visible ancestors. The tightest finite CPU quota caps both explicit and detected
vCPU capacity before the host reserve is deducted. Fractional capacity rounds
down because pod requests use whole vCPUs; less than one available CPU refuses
startup. Malformed quota data and read errors refuse rather than become unlimited
capacity (ADR 0007 A-2). Missing controller files remain distinct from read errors.

Four focused capacity tests pass, including concurrent reservation conservation
and a delegated hierarchy whose 1.5-CPU ancestor permits one default pod despite
an operator setting of eight CPUs and sufficient memory for several pods. The
reservation returns on drop. Linux ARM64 musl builds and scoped Clippy passes.
A live Apple Container check placed the rebuilt node in a separate cgroup with
`cpu.max=50000 100000`: startup refused with no pod CPU capacity despite
`--node-vcpus 8`. The temporary cgroup was removed afterward.

This observes visible cgroup v2 quotas at startup, not ongoing changes to host
allocation or invisible ancestor limits. Cgroup v1 CPU quota detection is not
added by this change. Coding journeys still await model configuration.

### Configurable host audit credential service (2026-10-04)

The node now accepts `--audit-minter-socket` (or
`NUCLEUS_NODE_AUDIT_MINTER_SOCKET`) for an operator-provided host Unix service.
The adapter sends admission's resolved scope and requested lifetime, and passes
the returned temporary credential through the existing expiry/key checks before
constructing an uploader grant. Provider authentication and restricted policy
issuance stay outside Nucleus. No configured minter still refuses audit sinks;
service failures never fall back to ambient credentials.

The versioned request protocol is documented in
[`audit-credential-service.md`](audit-credential-service.md). Each call uses a
fresh connection, a ten-second end-to-end deadline and a 16 KiB reply limit.
Errors omit response bytes and parser diagnostics. Scope serialization derives
from the admitted type (ADR 0007 F); the existing admission consumes the mint
witness before handing the grant to a driver (C-4).

Twenty-one focused audit tests pass, including real local Unix-socket exchanges
that check scope/TTL delivery, uploader configuration, refusal, expiry, malformed
or incomplete replies, service absence, and timeout connection cleanup. Linux
ARM64 musl builds and scoped Clippy passes. These are adapter tests, not evidence
that a real provider has issued a restricted credential. Production provider
integration and once-per-pod credential refresh remain open, alongside the two
model-driven coding journeys.

### Live audit minter configuration and refusal path (2026-10-04)

The Linux ARM64 node built from `58f9c6715` ran inside the existing Apple
Container host with an operator sink file and `--audit-minter-socket`. A disposable
Rust socket fixture received two real mTLS pod-create requests. The captured
requests carried `operator-audit/nucleus/journey-a` and
`operator-audit/nucleus/journey-b`, respectively, each with the expected
900-second minimum lifetime. The fixture explicitly refused both scopes; the
node returned the named mint refusal before launching a pod. After the fixture
exited, another request returned a service-connection failure. Pod inventory
remained empty. The initial request had correctly stopped earlier at image-path
admission until the temporary node was configured with its artifact root.

Evidence: `/tmp/nucleus-audit-minter-live/api-results.txt`, plus captured
`/srv/audit-minter-requests.jsonl` in the validation container. The temporary node
and socket were cleaned up, and the original node remained healthy. This is live
configuration/admission evidence; the fixture issued no credentials and proves
no provider-side policy enforcement. The implementation's full node run also
passed 884 unit tests (one ignored) and three integration tests.

A follow-up search of the inspected Nucleus/Gatehouse repository configuration
found no model endpoint for the coding journeys; the Gatehouse API-base matches
were GitHub routing. Model endpoint/model/credential-reference input remains
necessary to perform either real model-driven journey.

### Durable proxy memory journal (2026-10-04)

The tool proxy now wires an operator-configured memory journal into startup and
the live write/recall handlers. `--memory-store` and `--memory-namespace` select
a private file outside the workspace. The process holds an exclusive file lock;
startup checks the namespace and replays records through provenance validation
in original admission order rather than accepting a serialized trusted set.
Accepted writes spend authority, append, flush and sync before publishing their
candidate state. A failed or cancelled write leaves the store unavailable for
reads and writes until restart. Duplicate records remain idempotent.

Focused ordinary tests cover restart retention of values/labels/derivations,
parent-before-derived replay, duplicate writes, exclusive ownership, namespace
mismatch, workspace-path refusal, incomplete-write recovery refusal and I/O
failure without publishing candidate state. The I/O fixture exposed the need to
explicitly flush Tokio's buffered write before sync; that is now required. The
full proxy suite also found a duplicate Clap argument-group name, corrected by
naming the new flattened group `MemoryStoreArgs`. Final validation passes 580
proxy unit tests with all features, scoped Clippy, and Linux ARM64 musl build.
Prepared writes exclusively borrow their original store until consumed by commit
(ADR 0007 C-4/D), preventing stale or cross-store publication.

See [`memory-journal.md`](memory-journal.md) for format, limits and recovery
behavior. This is runtime persistence for a provisioned proxy directory; node
provisioning across pod lifetimes, host-mediated memory authority, compaction
and durable declassification burn history remain open. Real process-restart
validation is recorded below. Neither this change nor the audit service completes
the two model-driven coding journeys.

### Live memory HTTP persistence across proxy restart (2026-10-04)

`tests/memory_persistence.rs` now launches the actual tool-proxy binary with a
fixture orchestrator token, separately signed session scope and an explicit
unsandboxed development opt-in. The test issues an ordinary signed HTTP write of
a project note through `/v1/memory/write`, terminates and waits for the process,
then starts a fresh proxy against the same private journal and namespace.
`/v1/memory/recall` returns the same value and label with `declassified=false`;
the stored record retains its derivation. This tests the handlers and restart
wiring, beyond the in-process store tests.

The process test passes on macOS and as an ARM64 musl test binary inside the
existing Apple Container Linux host. The Linux run uses the freshly built proxy
through the test's explicit `NUCLEUS_TEST_PROXY_BIN` override; normal Cargo runs
use Cargo's binary path. Both child processes and temporary directories are owned
by the fixture and cleaned up. The original node remains healthy over mTLS.
Evidence: `/tmp/nucleus-memory-process-{test,linux,clippy}.log`.

This establishes an ordinary proxy process restart with operator-provisioned
storage. It does not establish durable storage across Firecracker pod replacement,
shared multi-tenant memory, or host-authoritative memory admission. Those remain
part of the broader memory outcome.

### Owner-bound memory across local pod and node replacement (2026-10-04)

The node's `--memory-root` now provisions explicit
`nucleus.io/memory-namespace` requests for the local and mediated container
drivers. Requests name a namespace, not a path. Only after authority admission
does the node derive the storage directory and journal namespace from the issued
root-owner identity. The operator root is private and disjoint from the configured
workspace root. Local launches clear ambient memory settings; container launches
receive an admitted bind and environment. Unsupported drivers and missing node
configuration refuse before launch. Container environment assembly moved out of
`main.rs`, and reads the node's mediation setting directly (ADR 0007 G-1).

Live Apple Container evidence: pod `ab94a366-eb90-4329-ba55-4a8627957ad2`
accepted a normal project note under `project-a`. After cancelling that pod and
stopping/restarting the node, replacement pod
`e6aa060e-2a7a-48f7-af8d-1ff61f9a6bd2` recalled the same content hash
`af250b233a8dc30f6c45293897fbeff34752814c82bc355d0291e97d71472bdf`, value and
label, with `declassified=false`. This used real mTLS pod admission and the
node's signed proxy with the development local driver, not a microVM memory
transport. The replacement pod and temporary node were stopped; the primary
node remained healthy. Evidence lives under `/tmp/nucleus-memory-provision-live/`.

The full node suite passed 887 unit tests (one ignored) and three integration
tests. Focused provisioning checks cover namespace validation, owner separation,
backend support, ambient-setting removal, root permissions/separation, and the
container environment. Live container storage, Firecracker transport and
host-authoritative memory effects remain open. The broader release goal and
model-driven coding journeys are not complete.

### Mediated container memory across node replacement (2026-10-05)

The ordinary live container check found two startup defects: Unix-mode proxies
had no bootstrap identity, and their spec named the host workspace even though
Docker mounts it at `/workspace`. The node now issues the pod an ordinary SVID
from its persistent CA, creates its identity directory/key privately from the
start, and translates the container spec's workspace path. Local orchestrator
pods share the same identity-file provisioning. This identity does not claim
microVM attestation. A proxy that exits, cannot be inspected, or times out before
announcing readiness now fails launch and goes through confirmed container
rollback; it no longer returns success with a null proxy address.

Inside the existing Apple Container host, mediated Docker pod
`d57b24e5-1b2e-4e40-835c-86378e280c38` wrote the project note under namespace
`container-project`. After cancellation and a node restart, replacement pod
`0d9b9612-d67f-4ca6-bb29-8b06c78343f3` recalled the same record hash
`af250b233a8dc30f6c45293897fbeff34752814c82bc355d0291e97d71472bdf`, value and
label, with `declassified=false`, through the node's signed proxy. The minimal
validation image needed the host CA bundle for its HTTPS client initialization.
Both pods were cancelled, no Docker containers remained, and the temporary node
and Docker daemon were stopped. The primary node remained healthy over mTLS.
Evidence: `/tmp/nucleus-container-memory-live/{pod-a,pod-b,write,recall}.json`.

Validation: 891 node unit tests passed (one ignored); after workspace translation,
31 focused container tests passed (one ignored). Scoped Clippy and the ARM64 Linux
build passed. Regression checks cover the issued certificate's identity and CA
chain, private key/directory modes, workspace translation and preservation of raw
extension fields, and rollback/resource release after an exited proxy.
Firecracker memory transport and host-authoritative memory effects remain open;
this check is not one of the two outstanding model-driven coding journeys.

### Apple Container host CLI and live startup diagnosis (2026-10-05)

`nucleus microvm-host up/status` now exposes the existing backend. `up` requires
an explicit local image and L1 kernel with its build config, selects installation
or isolated development names, prepares identity/state, probes KVM and checks the
published node URL over mTLS. It returns connection metadata only after readiness.
`status` is read-only and explicitly reports `health_checked=false` for a running
container. Blocking backend calls run outside Tokio's worker threads. The new
Apple Container quickstart distinguishes this explicit path from Lima `setup` and
from unpublished image/guest release work.

The live CLI check found that the old backend added `--init`, conflicting with
`nucleus-hostctl run-node` requiring PID 1 for cgroup preparation. Launch now omits
that flag and configuration observation recognizes an init-enabled owned host as
drifted, allowing replacement while preserving its volume. Tests cover this
configuration change and the CLI's readiness/status distinction.

After replacement, KVM probing passed and the node answered a real mTLS request
at its container IP. Its client certificate verified against the running node's
CA. Published loopback connections were reset, and Apple Container's service log
reported `backend - connect failed: No route to host` in container-runtime-linux.
Both IPv4-only and dual-stack node listeners showed the same result. The upstream
[Apple Container report](https://github.com/apple/container/issues/2029) describes
a matching Local Network permission pattern; that is a diagnostic lead, not a
confirmed local permission diagnosis. `up` correctly exited nonzero and did not
claim readiness. The error now includes a forwarding/Local Network diagnostic.
A successful fresh host CLI journey remains unverified until the published port
works. No system privacy settings or shared container service were changed.

Evidence is under `/tmp/nucleus-host-command-live/` (status, readiness error, CA
verification input, service log and local image inputs). The isolated development
host was stopped, retaining its volume and identity for follow-up. The existing
acceptance node stayed healthy. Validation: 313 CLI unit tests passed, two ignored;
32 focused host tests passed, one ignored; scoped Clippy passed. This adds a usable
command surface and fixes startup wiring, not automatic shell/run host selection,
a published artifact set, or either outstanding model-driven coding journey.

### Apple host identity reuse and renewal (2026-10-05)

Host `up` now uses setup's existing client identity validation instead of treating
an existing certificate filename as proof of usable credentials. Complete, current
credentials remain byte-identical; missing/invalid credentials and certificates
within 30 days of expiry are renewed under the existing root. A partial CA pair
is refused before either half is written, preserving the remaining recovery
material. The shared CLI minter stages each identity file privately, syncs it,
renames it into place and syncs its parent directory. This is per-file atomicity;
an interrupted three-file renewal is validated and repaired at the next startup.

The CLI suite passed 315 tests with two ignored before the additional near-expiry
case; that focused case also passed. Tests exercise idempotent reuse, a missing
client key, renewal of a one-hour certificate, preservation of both partial-CA
shapes, unchanged node secrets/root and owner-only replacement key permissions.
These checks use actual generated certificates and the real client identity
validator. This change does not resolve the separately recorded Apple Container
published-port forwarding problem or the missing model configuration.

### Explicit local host image assembly and packaged workload (2026-10-05)

`cargo xtask microvm-host-context` stages exactly six ARM64 Linux executables
(node, hostctl, CLI, MCP, Firecracker and jailer), the pinned guest kernel and an
operator-selected guest rootfs. It checks static ELF architecture, the kernel
digest and the rootfs superblock, records byte lengths/SHA-256 in a manifest, and
publishes a new context only after validation. Sparse zero extents are retained
so large mostly empty guest images do not require their full logical size on disk.
The new local Containerfile consumes these inputs, installs the manifest, supplies
no baked authentication secrets and enables host enforcement. It downloads no
replacement runtime artifacts. The manifest records input bytes, not provenance
or a claim that arbitrary guest/runtime versions are compatible.

Live assembly exposed two necessary corrections. Apple Container 1.4.1 on this
host omitted nested files for a directory-only COPY; a small nested/flat fixture
reproduced that behavior. The final recipe uses a flat context and explicit file
names. All eight staged artifacts were read back from the first corrected image
with matching digests. The initial recipe also started the node in legacy mode,
allowing a baked guest command to outrank the requested workload. Enabling host
enforcement makes the guest select the admitted host spec instead. The kernel
feature table now includes the three NFQUEUE options already in the committed
fragment, so build requirements and host preflight agree.

Final image `nucleus-local-host:enforcing-7e4987e34` was built from the staged
inputs and started on the isolated Apple Container development host. Pinned
Firecracker pod `c8f13b0f-ad3a-4e43-a654-92a4160aae5c` ran the requested ordinary
shell workload, exited 0 and returned `packaged host workload completed` on stdout.
The result reported a bound executable digest and UID isolation. A signed execution
bundle was collected, but has not yet been independently verified. The pod was
cancelled and the development host stopped and removed to reclaim its writable
filesystem; the image, state volume and identity remain. The original acceptance
node stayed healthy. Published-port readiness still fails
with the previously recorded forwarding issue; this run used the container's IP
with mTLS, not a successful `microvm-host up` readiness claim.

Evidence: `/tmp/nucleus-host-context-enforcing-{pod-result,workload-result,bundle}.json`,
`/tmp/nucleus-host-context-enforcing-stdout.txt`, the staged input manifest and
`/tmp/nucleus-host-context-image-enforcing.log`. Validation: three context tests,
13 guest-layer tests, 17 microVM-host spec tests and scoped Clippy passed. Disk
exhaustion interrupted intermediate builds; confirmed failed attempts were retried
after removing superseded validation copies/images and cleaning the cross-target
Cargo cache (11.7 GiB reclaimed). Final image import completed successfully.
The original model-driven journeys and published fresh-install release remain open.

### Packaged execution verification and command declarations (2026-10-05)

A second packaged workload with explicit HOME, PATH, LANG and TZ completed as
pod `c794589e-a11d-419d-ba96-7649b84adf63`. The standalone `nucleus-audit
verify-execution` accepted its receipt against a separately saved mTLS admission
record, including the node's public signer, and an environment hash computed from
the intended inputs. The issuance window starts at admission and allows five
minutes after the verification attempt; the verifier also applies that upper
bound to claim consumption. The accepted claim records Firecracker, UID isolation,
exit 0 and stdout SHA-256
`51a6423be91449746ce54076582bc316945eeb120ff55011ea64308e382f4237`.
No artifact bytes were selected or verified. This is an ordinary packaged
execution check, not either required model-driven journey.

The initial verification expectation incorrectly treated an empty declared env
as an empty effective env; HOME and selected inherited variables make that false.
Pinning all four inputs makes this check reproducible without deriving expected
values from the receipt. Evidence is saved under
`/tmp/nucleus-package-evidence-pinned-{spec,pod,admission,receipt,expectations,verified}.json`.
The pod was cancelled after verification. Published-port forwarding remains open;
the authenticated node calls used the development container's direct IP.

The command grammar gate now traverses the nested workload and approval groups
and classifies their actual leaves, plus host up/status. All ten commands declare
the reach band because they make node calls or execute the container client.
The previously failing gate now reports 66 declared leaves; all four focused
command grammar tests and scoped xtask Clippy pass.

### Offline execution expectation preparation (2026-10-05)

`nucleus-audit prepare-execution` now replaces manual expectation JSON assembly.
It reads a separately retained admission record and intended environment map,
requires an independently enrolled public signer pin, checks that pin against
admission, and requires an explicit future Unix-microsecond validity deadline.
The lower bound comes from admission. It never accepts a receipt as input and
prints only expectations, including the environment hash rather than its values.
Default artifact selection is empty; an optional name/path selection must match
admission. Controllers may continue supplying their own RecordedExecution record.

The build-receipt handoff now documents explicit HOME/PATH/LANG/TZ inputs, the
runtime bindings excluded from input identity, artifact selection and the fact
that the deadline also applies when consuming a verified claim. Verifier error
messages retain nested parse causes. The prepared expectations successfully
verified saved Firecracker execution `c794589e-a11d-419d-ba96-7649b84adf63` using
the separately retained node pin, with no receipt-derived expectations. Evidence:
`/tmp/nucleus-package-evidence-pinned-prepared-{expectations,verified}.json`.
This improves the supported verification workflow; it does not complete either
model-driven journey or establish fresh-install publication readiness.

### Explicit run identity selection (2026-10-05)

`nucleus run --identity-dir` (also `NUCLEUS_IDENTITY_DIR`) now accepts the separate
identity directory returned by Apple host startup. Explicit selection requires
all three files and valid TLS material; it does not fall back to another identity
or HMAC when loading fails. The shared provisioned client loader retains the
SPIFFE node identity check. The selector conflicts with local mode.

A dry run using the development host's actual identity exposed a legacy Keychain
lookup even after mTLS was successfully selected. Run now resolves legacy HMAC
credentials only when mTLS is unavailable, so that unrelated Keychain failure no
longer blocks an authenticated configuration. The same dry run subsequently
passed. This is configuration evidence, not a newly launched coding workload.
The existing real mTLS handshake test now exercises the production directory
loader, and the selection test covers generated credentials, missing key files,
Keychain-enabled configuration and the local-mode conflict.

The next Apple run integration step is to retain a per-session relay: node pod
creation currently returns a container-local proxy address. Explicit identity
selection alone does not wire automatic host startup or make that address
reachable. The Apple quickstart records that limitation.

### Run pod teardown before relay integration (2026-10-05)

The existing run path discarded the admitted pod ID and never cancelled its pod
when the agent finished or failed. It now retains that ID, executes the session,
and sends cancellation through the selected node authentication after every
ordinary return path, including a missing proxy address, MCP configuration,
agent startup and output errors. Cancellation has a 30-second request deadline.
A cleanup failure is an error even after a successful run; simultaneous run and
cleanup failures retain both causes and identify the pod for recovery. Cancellation
stops resources but does not remove the node's retained pod registry entry.

The real mTLS run test now checks creation, exact cancellation routing, a service
unavailable response, and cleanup after a created pod has no proxy address. The
full CLI suite passes 318 tests with two ignored; scoped Clippy passes. This
closes the ordinary teardown gap needed before holding an Apple relay for the
session. It does not yet wire that relay, export receipts before teardown, or
provide crash/SIGKILL cleanup guarantees. Pod timeout remains relevant when the
CLI cannot execute its cleanup path.

### Explicit Apple host selection and run relay lifetime (2026-10-05)

`nucleus run --apple-host-config host.json` now uses the same host settings as
`microvm-host up`, starts/checks the selected host off the async worker, and takes
its mTLS identity and node URL only from the readiness witness. Normal profile,
goal and grant execution share this dispatch. Configuration cannot be mixed with
another node URL/identity, legacy node credentials, hook mode or local mode.
Dry-run validates the file but creates no state or host. The assembled image's
standard kernel/rootfs paths are the defaults for Apple runs.

After pod admission the run opens a published relay to the pod's loopback proxy.
It retains the slot through normal execution and cancellation, including the
cleanup error path. Inspection found a normal slot-reuse race: the prior relay
may still occupy the port after its file lock is released. The current hostctl
now accepts a new readiness file and writes the bound listener and target only
after binding succeeds. Each relay attempt uses a unique filename; the CLI checks
that exact acknowledgement before accepting forwarded health. Occupied ports or
old hostctl binaries therefore cannot borrow another relay's health response.
A failed setup still follows the new pod cancellation path.

Validation: 321 CLI tests passed with two ignored, 45 host library tests passed,
and scoped Clippy passed. The built CLI's dry-run with real local image/kernel
settings created no host state. The built native hostctl refused an occupied
port without a readiness file, announced its actual fresh listener/target, and
exited after that target closed. Evidence is under
`/tmp/nucleus-apple-run-{settings.json,dry-run.log}` and
`/tmp/nucleus-apple-relay-start-evidence.json`. Full Apple relay use has not been
revalidated with a rebuilt host image; published-port forwarding remains the
previously documented local failure. This option connects the existing host-side
agent/MCP run mode. It adds neither workspace transfer nor an in-guest model
harness, and does not collect evidence before teardown. Those remain release work.

### Verified direct container-IP connection (2026-10-05)

Apple host settings now expose an explicit connection choice:
`published-loopback` remains the default; `container-ip` reads the owned host's
current IPv4 assignment on the default container network. The latter requires
exactly one usable assignment and does not substitute a remembered IP. Both
routes still require host preflight, KVM probing and SPIFFE/mTLS node health.
The readiness witness carries the checked node address, and relay endpoints use
the same selected network with the appropriate container or published port.
The host supervisor also checks and restarts through the configured route.
There is no automatic fallback and the published-port failure remains unfixed.

Live `microvm-host up --connection container-ip` succeeded on the isolated
`nucleus-dev-microvm-host` with the previously packaged enforcing image, returning
`state: ready` and `https://192.168.64.129:8080`. This is the first successful
readiness result from the public host command on this machine; earlier direct-IP
checks bypassed the command while its published-port probe failed. Evidence:
`/tmp/nucleus-direct-host-up.json` and `/tmp/nucleus-direct-host-up.log`.
The development host was stopped/deleted after validation, retaining its named
volume and identity. The obsolete, already stopped session validation container
`nucleus-branch-acceptance` was also deleted to recover 1.8 GiB; its image and
bind-mounted evidence remain. The active acceptance host was not changed.

Validation: 322 CLI tests passed with two ignored, scoped Clippy passed, and the
additional node/relay endpoint mapping assertion passed. The running fixture
covers the observed default-network address and a missing assignment without
breaking published-loopback selection. A current Linux hostctl/image and complete
Apple relay run still need live validation. Neither host readiness nor route
selection completes a model-driven coding journey.

### Live Apple run/MCP relay and guest workspace correction (2026-10-05)

The current Linux hostctl was cross-built successfully (SHA-256
`1795327a368d32c79003bbfaea95ce8345026ffe64be04a1c4b8a66cbb795cec`). The successful
flat host image is `nucleus-local-host:relay-flat-12db36eba`, manifest-list digest
`e16caceab3475af40db89e383e2b9b0a3d6a1a83bed7af6ab7590d5c428e1b1c`. Its installed
helper matches its updated input manifest. An intermediate derived image imported
but failed an independent boot check without a state volume and was removed;
the proven explicit flat recipe was used for the retained image.

Live run validation exposed a real workspace error: the host canonicalized `/tmp`
to `/private/tmp` and sent that host path into the guest. The proxy failed opening
its workspace before health. A root-directory diagnostic run instead produced
an explicit audit-log/workspace overlap refusal. Apple runs now default their
guest workspace to the shared `/work` constant while retaining the host directory
for the agent process. `--guest-work-dir` selects another absolute guest path;
it conflicts with local/hook mode. This does not transfer any host files.

Two ordinary protocol-fixture runs then succeeded through the public `run` path:
KVM/mTLS readiness, actual Firecracker pod admission, fresh relay acknowledgement,
relay health, the real native MCP binary and a guest glob call. The second used
the default vsock setting and reused the relay slot. Both returned success and
exit 0; the first pod was `62dc8474-243c-4aed-a046-b3ef28f5ac23`. After execution,
the node reported exited pods and no relay process remained. This fixture made
no model calls and is not a completed coding journey. Evidence:
`/tmp/nucleus-relay-functional-{fixed,defaults}.json`,
`/tmp/nucleus-relay-functional-{first-evidence,evidence}.json`,
`/tmp/nucleus-relay-after-runs-pods.json`, and
`/tmp/nucleus-relay-installed-helper.json`.

Storage recovery was necessary. Native tool binaries were retained under
`/tmp/nucleus-current-tools` before cleaning the 3.4 GiB native cache, and the
Linux cache was cleaned after saving the helper. Superseded/failed local images
were removed. The duplicate packaged guest rootfs was retired only after its
hash matched the retained image input manifest; recovery location is recorded in
`/tmp/nucleus-retired-packaged-rootfs.json`. Failed pod copies had left the ext4
state volume physically large after deletion: fstrim reduced it from 3.9 GiB to
38 MiB without deleting state. Disk exhaustion also left the builder and later
the idle development root in emergency read-only mode; they were restarted only
after space recovery. The quickstart now documents unused-block reclamation.
Validation: 323 CLI tests passed, two ignored; scoped Clippy passed. The complete
model-driven journeys, workspace transfer and evidence export before run teardown
remain open.

### Pre-publication integration and CI check (2026-10-05 05:27 UTC)

Fetched upstream main; it remains `7f240fe66`, with no commits missing from this
branch. At implementation commit `1ac6b8d77` the branch has 69 commits above main
and changes 184 files (+20,038/-2,357 lines). These are diff measurements, not a
completion claim. The validated branch was pushed without opening or enqueueing
a PR; PR publication remains scheduled for the recorded 08:00 Eastern deadline.
The existing Coverage Matrix workflow was dispatched at that exact code commit:
https://github.com/coproduct-opensource/nucleus/actions/runs/37267840622 .
It includes full workspace coverage and the workflow's ordinary mutation tests;
its result was pending when dispatched. Local targeted tests do not substitute
for the workspace coverage floor.

The live GitHub merge queue now matches `ci/merge-queue.toml` at one concurrent
build entry, resolving the previously recorded configuration drift. The latest
main Gatehouse required check succeeded on October 4. A current controller
health request failed to connect, and GCP inventory confirms the controller and
all six lanes are stopped; the lane-waker scheduler is paused too. The stop audit
attributes the controller stop to the owner's account. Fly-based GitHub coverage
runners are independently active. Preserve the stopped/paused deployment during
implementation; the authorized Gatehouse merge will need deliberate controller
and worker recovery, not an assumption that queued jobs wake these lanes today.
The deployment SPIFFE wrapper currently requires interactive sudo; the existing
user gcloud login was sufficient for read-only inventory and audit queries.
No infrastructure or queue policy was changed in this review.

### Bounded workload evidence collection (2026-10-05 05:38 UTC)

`node workload collect --wait-secs N` now waits for a supervised workload to
finish before requesting its signed receipt or selected artifact bundle. The
explicit bound is 1–86400 seconds and includes observation requests and poll
delays; the final collection request retains its existing request timeout.
Unavailable, missing or failed observations remain errors. Waiting neither
cancels the pod nor treats a failed/signalled workload as successful. The
existing immediate collection behavior remains the default. The legacy
host-side agent `run` creates no supervised guest workload, so this change does
not add execution evidence for that host process.

Live Apple-host pod `e24ccf18-3920-4914-875b-555194d5f746` ran a pinned ordinary
shell workload with a 20-second delay and exit 23. A one-second wait timed out
without creating an output file; the next observation still reported Running.
A subsequent 60-second wait collected the receipt in 19.3 seconds. Independent
verification using the previously enrolled node key, separately saved admission,
and intended environment confirmed Firecracker/UID isolation and exit 23. The
saved stdout hash matched the signed claim. The pod was then cancelled and unused
state-volume blocks trimmed. Evidence is retained under
`/tmp/nucleus-collection-wait-live/`, including `summary.json`, `admission.json`,
`receipt.json`, `expectations.json`, `verified.json` and raw stdout.

The first live creation ran out of host disk while copying the rootfs and did
not launch a workload. Current native tools were preserved in
`/tmp/nucleus-current-tools`, cargo clean reclaimed 2.7 GiB and volume trim
recovered the failed copy's unused blocks before the successful retry.
Validation: 328 CLI unit tests passed, two ignored, and the CLI integration
suites passed; scoped Clippy and all four prepush gates passed. The dispatched
CI run has passed its detector and proof ratchet; coverage and mutation jobs
were still queued at this check. Actual model-driven journeys remain zero.

### Workspace image package compatibility (2026-10-05)

Both Apple host recipes installed bookworm's e2fsprogs 1.47.0, while the existing
workspace seeder requires tar-capable 1.47.1–1.47.x. The running development
host's actual `seed` command reproduced the version refusal. Both recipes now
pin e2fsprogs and its matching libext2fs2 to Debian bookworm-backports
`1.47.2-3~bpo12+1` and explicitly install runtime-loaded `libarchive13`.
Pinning e2fsprogs alone first failed package resolution because apt selected the
old library; the matching library pin resolves that measured build failure.
Package source: https://packages.debian.org/bookworm-backports/e2fsprogs .

The exact revised package layer plus the retained Linux hostctl built as
`nucleus-workspace-package-check:a125a6c43` (manifest-list digest
`6d9f166551ae8a00d5f6c5a76d8b3b20e0bb7f1151aca2fbd2bb57fa1e2f59ca`). An isolated
Apple container ran two real seed operations on the same nested tree, producing
byte-identical images with SHA-256
`9485bbd165edbd47352faec3356cfe77bae8b981a8d88c56d568f908aa4af896`. The disk file
was owned by jailer 65534:65534 with mode 0600; debugfs confirmed guest files
owned by workload 1000:1000. Harvest preserved both regular files and the
relative symlink. Provenance recorded mke2fs 1.47.2 and tar input. The temporary
container was automatically removed. Its context remains at
`/tmp/nucleus-workspace-package-context`.

The full matched runtime image then built as
`nucleus-local-host:workspace-a125a6c43`, manifest-list digest
`74f1d513b45d3429d7a4b9bab4badc550c09f1fdc96f6bd5006e9546a518352a`. All retained
runtime inputs matched their manifest; only the package recipe changed. After
confirming its three registered pods were exited, the development container was
replaced with this image, retaining its state volume and identity. The supported
`microvm-host up` passed KVM/mTLS readiness at `https://192.168.64.161:8080`.
The primary acceptance container was untouched. The full build log and readiness
report are `/tmp/nucleus-workspace-full-build.log` and
`/tmp/nucleus-workspace-host-up.json`; updated settings are
`/tmp/nucleus-workspace-run-settings.json`.

On the revised host, a seed owned by workload 1000:1000 was handed to the node's
jailer 123:100 and admitted with its measured scratch digest. Firecracker pod
`f837301e-0595-4fbb-b0e6-063914bc8cf4` copied a seeded input, appended an ordinary
edit, deleted the original, synced and exited zero. Independent artifact
verification accepted the execution plus the declared 27-byte output; readback
after cancellation confirmed both the edit and deletion persisted. Evidence is
under `/tmp/nucleus-workspace-seed-live-evidence`, including the spec, separate
admission, selected outputs, bundle, expectations and verified report. The
cancelled pod's unused volume blocks were trimmed, and the duplicate rootfs used
for staging was removed only after successful import; both images retain it.

All three context-staging tests and four prepush gates passed. Public CLI
workspace transfer and actual model-driven harness execution remain open. The
existing mutation CI job is now running; the workspace coverage job is still
queued.

### Public Apple workspace seeding (2026-10-05)

`microvm-host seed --host-config host.json TREE` now connects the selected
directory to the existing Linux filesystem builder through checked KVM/mTLS
host readiness. It requires explicit workload and node-jailer UID/GID, creates
a uniquely named scratch disk under `/srv/state/scratch`, and reports its path
and parsed digest for PodSpec admission. Complete directory transfer includes
hidden files. Source mutation during copying is not a supported snapshot
protocol; callers must keep their selected tree stable. Success removes the
private staging copy. Failure names staging and disk paths for inspection;
transfer and image construction each have a ten-minute process deadline.

Live validation found an Apple copy mount-path limitation: copies into the
mounted `/srv` state volume reported success but were invisible to the running
container. Both a single-file and directory copy into the root filesystem were
visible. The command therefore stages under a private UUID directory in `/tmp`
and lets hostctl write the final disk into the state volume. It invokes each
command as arguments, without a shell. No archive implementation was needed.

The public command copied `/tmp/nucleus workspace cli source`, including its
nested file and `.fixture`, and produced scratch digest
`d41c0b7074ef206acfc4ffb598cffced770e2ef20743d485afe0219aed6359da`.
Pod `0b38c00a-f92c-4cea-8102-1e42022acb53` admitted that exact disk, read both
inputs, wrote a 40-byte edited output, deleted the original guest file, synced
and exited zero. Independent verification accepted the execution and declared
artifact, whose hash matched the intended bytes. After cancellation, readback
confirmed persisted edits and deletion; the original Mac source remained
unchanged and successful staging was absent. Evidence:
`/tmp/nucleus-cli-workspace-seed.json` and
`/tmp/nucleus-cli-workspace-evidence/{spec,admission,bundle,expectations,verified}.json`.

Validation: 330 CLI unit tests passed, two ignored; integration suites, scoped
Clippy and all four prepush gates passed. The older relay-flat host image was
removed after its replacement's successful validation, reclaiming 4.03 GB;
the rootfs recovery record now points to `nucleus-local-host:workspace-a125a6c43`.
This command exposes source transfer for explicit PodSpecs. It does not yet
connect `run --dir` to an in-guest harness or automate output collection, and
no actual model-driven coding journey has completed.

### Export independently verified artifacts (2026-10-05)

`nucleus-audit verify-artifacts --output-dir NEW_DIRECTORY` now materializes
checked bytes for local review. Export consumes `VerifiedArtifacts` with its
deadline check before creating output, uses artifact names as single filenames
rather than guest workspace paths, and requires a new directory. Unix output
is private (0700 directory, 0600 non-executable files). Each file is created
without overwriting, written completely and synced before success is reported.
An I/O error reports the potentially partial directory. This is a checked copy,
not an additional signed receipt; retain the original bundle and expectations.

The real bundle from pod `0b38c00a-f92c-4cea-8102-1e42022acb53` exported to
`/tmp/nucleus-cli-workspace-evidence/exported/updated`. Its exact 40 bytes and
SHA-256 matched both intended output and the authenticated artifact identity.
Directory/file modes were 0700/0600. The retained report is
`/tmp/nucleus-cli-workspace-evidence/export-report.json`.

All 137 audit unit/integration tests passed, including export of binary bytes,
preserving an existing destination, and preserving a failed workload exit as
data. Scoped Clippy and all four prepush gates passed. Workspace coverage on
the previously dispatched implementation commit is still queued; its mutation
job remains active. Actual model-driven journeys remain incomplete.

### Remove the observed CI capacity stall (2026-10-05 06:15 UTC)

The coverage job remained queued while the runner manager repeatedly reported
one waiting build job and started nothing. Authoritative inventory showed 63
stopped Fly workers and one started build worker whose GitHub runner was busy
with mutation testing. The planner subtracted every live machine from queued
demand, treating that occupied worker as capacity for another job. It could also
count an idle online registration and its matching machine twice.

Commit `41e8e6226` correlates a machine with its current runner ID: busy runners
do not cover queued demand, known idle registrations count once, and booting
registrations retain their reservation across polls. The regression reproduced
the observed stall before the fix, then passed with all 37 runner tests. Scoped
Clippy and all four prepush gates passed. No pool limit or worker size changed.

A tracked-only export of that commit was deployed to the existing Fly manager
with its configured secrets retained. Manager version 36 became healthy at
06:15:21 UTC, running image digest
`6667c925b6722f279ef5db75f7e9c6292ff6f7b360711481ea6a34fe70a9159e`.
The same coverage job `111628402898` started at 06:15:32, while mutation testing
continued. Its result is still pending; this is scheduling recovery, not a
coverage pass. Workflow: https://github.com/coproduct-opensource/nucleus/actions/runs/37267840622 .
Deployment evidence is `/tmp/nucleus-runner-capacity-{deploy.log,deployed.json}`;
the prior image reference is retained in
`/tmp/nucleus-runner-capacity-rollback.json`. GCP Gatehouse controller/lanes and
its paused scheduler were unchanged. A fresh fetch still finds upstream main at
`7f240fe66` with no commits missing from this branch.


### Interruptible host-agent cleanup (2026-10-05)

The legacy host-side agent wait now runs asynchronously and handles Ctrl-C by
stopping and reaping its immediate child before returning through the existing
pod-cancellation path. Ordinary output and nonzero exit statuses are preserved.
Local-driver runs also stop their proxy before propagating an agent wait error.
This handles interruption while waiting for the agent; it does not promise
cleanup after SIGKILL, a host crash, or for arbitrary detached descendants.

A protocol fixture performed a real MCP glob through the Apple relay before a
SIGINT was sent to the CLI. The CLI returned the interruption error, the agent
PID was gone, pod `e0a6a365-777f-4452-83f7-db92f8da41d0` was Exited, and the
relay endpoint was unavailable. Evidence is `/tmp/nucleus-interrupt-live.json`,
`/tmp/nucleus-interrupt-protocol-evidence.json` and
`/tmp/nucleus-interrupt-pods.json`. This was not a model-driven journey.

Validation: 332 CLI unit tests passed, two ignored; ordinary integration suites,
scoped Clippy and all four prepush gates passed. The earlier workspace coverage
run failed before measuring coverage: the compile-time read population grew
from its ceiling of 12 to 13. That separate dependency regression is being
resolved; its failure cancelled the workflow's mutation job.


### Keep the local host recipe inside its build dependency (2026-10-05)

The coverage workflow's compile-time read ratchet reproduced locally: the new
xtask include of `docker/Containerfile.microvm-host-local` raised escaping reads
to 13 against a ceiling of 12. The canonical recipe now belongs to
`nucleus-spec/assets/Containerfile.microvm-host-local` and is exposed by the
shared host-spec module. xtask already depends on that crate, so its recipe is
inside the derived dependency closure. No duplicate recipe, runtime lookup or
higher ceiling was introduced. The recipe bytes and staged Containerfile are
unchanged; the existing local host image remains valid.

The formerly failing population test now passes with the unchanged ceiling.
All action-key and spec tests and the three context-staging tests passed.


### Verify retained workload logs (2026-10-05)

`nucleus-audit verify-logs --receipt receipt.json --expectations expected.json
--stdout stdout.bin --stderr stderr.bin` now exposes the existing shared log
verifier. It authenticates execution against independent expectations, checks
both exact byte streams, and consumes the log and execution witnesses with a
fresh deadline check. No manual hash comparison or text decoding is required.
Both files are required, including an empty file for an empty stream, and reads
are bounded by the node's 16 MiB per-stream retention limit. The report contains
byte counts and the original signed claim; a workload's nonzero exit remains
a nonzero exit in that claim.

Live Firecracker pod `c4689517-8bba-46c0-858b-f0abd701f82e` wrote 19 bytes of
stdout including NUL, invalid UTF-8 and CRLF, plus 20 diagnostic stderr bytes,
then exited 23. The public collection commands saved both streams and a receipt.
Expectations used separately retained admission, the previously enrolled executor
key and intended environment inputs. Verification accepted the exact bytes and
preserved exit 23; the pod was then cancelled. Evidence is retained under
`/tmp/nucleus-verify-logs-live/`. This is ordinary execution validation, not a
model-driven journey. All 137 audit tests, scoped Clippy and four prepush gates
passed. Current workspace coverage/mutation run `37272836266` remains active.


### Apple host selection for operator commands (2026-10-05)

`nucleus node --apple-host-config host.json ...` now resolves the ready Apple
host's current node address and complete mTLS identity for create/cancel,
workload evidence, and approval commands. It shares the same configuration and
readiness path with `run`, including KVM and authenticated health checks. Explicit
URL, identity or legacy-secret flags conflict with the selection. No global CLI
configuration is changed and missing selected identity files cannot fall back to
another installation. An owned stopped host may be started; `microvm-host status`
remains the read-only container observation command.

The public path created pod `ca5e8a3a-f38d-4a75-96f8-1fedcde6b366`, saved its
admission, waited for completion, collected its receipt and raw binary logs, and
cancelled it using only the host configuration selector. Independent verification
accepted the exact 19/20 stdout/stderr bytes and preserved exit 23. Evidence is
under `/tmp/nucleus-node-apple-live/`. All 334 CLI unit tests passed, two ignored;
integration suites, scoped Clippy and all four prepush gates passed. This does
not yet select Apple automatically for legacy setup or shell, and no actual
model-driven journey has completed.


### Separate the unprivileged HTTP adapter package (2026-10-05)

The broader merge preflight found that the raw-effect gate counted the HTTP
adapter's managed child and Unix client as privileged proxy effects because it
was packaged under `nucleus-tool-proxy/src`. The adapter now has its own
`nucleus-egress-http` crate: it remains a workload-UID client with a loopback
listener, fixed Unix-door transport, no provider credentials, and the same host
broker approval path. Its eight existing protocol/lifecycle tests moved with it.
The proxy's raw-effect gate and its allowlists were not widened. The adapter
retains the same scoped I/O lint restrictions in its own checked configuration.

The new crate explicitly enables its Tokio process, signal and runtime features
rather than obtaining them through the proxy's dependency graph. All seven
production totality lints are denied: response construction now uses typed
status/header mutation and signal exit conversion uses checked addition. The
measured totality floor rises from 34/91 (37.36%) to 35/92 (38.04%); the suppression
population and floor remain unchanged. Release and guest-layer builders now
build the independent package. `build-rootfs.sh` accepts its explicit
`EGRESS_HTTP_BIN` input; the existing cross-build inventory derives all nine
required guest packages.

The door's existing tests were extracted into an explicitly test-only module,
removing a raw-effect scanner false positive caused by braces in test strings.
Extraction also exposed a stale source assertion: its router search had found
its own test string. It now names the actual `pub(crate) fn router` declaration.
All 18 door tests and 13 guest-layer/release checks pass, along with the eight
adapter tests and scoped Clippy. Both the original mediation script and its Rust
counterpart pass. A Linux ARM64 build ran at UID 1000 inside the Apple host,
provided its bound endpoint to its declared child and preserved exit 7. This was
a host-container utility check, not another model journey or a new guest image.
Evidence: `/tmp/nucleus-adapter-standalone-linux.json`.

Workspace CI run `37272836266` completed coverage on commit `72b58a9fa` at
83.59% lines (227404 measured, 37311 missed), and portcullis at 90.42% lines.
The repository's current pinned workspace floor is 82.5%, despite older guidance
and workflow summary text saying 83%; neither threshold was changed here.
Mutation testing is still running. Later changes require their own final-head CI.


### Consume upload reservations at each pacing step (2026-10-05)

The merge preflight found one new borrowed affine parameter:
`EgressLedger::pace_upload` took `&mut EgressUploadHold`. It now consumes the
reservation and returns the updated owned reservation with the pace decision,
including wait and complete results (ADR 0007 C-4). The node transfers its hold
into each call and retains only the returned handle. A ledger refusal loses the
handle and conservatively retains its allocation; it does not refund unknown
transport work. Byte ceilings and window calculations are unchanged.

The convergence gate returned from five borrowed sites to its unchanged ceiling
of four. Fifteen ledger tests, two meter tests and five ordinary broker pacing,
cancellation and deadline tests passed. Scoped Clippy and all four prepush gates
passed. The separate bound-enforcement ratchet was raised to the measured
196/197 (99.49%) and population 197; its previous 193-site pin predated the
combined implementation. No enforcement floor or debt ceiling was loosened.

The additional local merge checks also pass for strict signature APIs, trusted
base pins, fail-closed verifier structure, north-star evidence, extracted call
sites, offline task compiler, hashed ingest, sealed effect home, governor-key
construction and Kani divergence. Manifest checks passed for command grammar,
workspace membership, dependency visibility, self-pins, shared pins, runner pools,
push authentication, workflow deadlines/pipelines, shell portability and action
inputs. Existing release checks find all nine required guest packages built and
uploaded. Linux dependency-hygiene run `37274887141` passed on `d7053913a`;
custom-lint run `37274884233` remains active on that same commit.


### Collect raw logs with execution evidence (2026-10-05)

`node workload collect --logs-dir DIR` now fetches both exact raw streams before
publishing the requested receipt file. The directory is new and private (0700 on
Unix), its files are private (0600), and empty streams remain empty files. Failed
log requests do not publish a receipt; filesystem failures report retained or
partial output. Existing destinations are never overwritten, and collection
does not cancel the pod. The option also works with artifact collection, while
independent signature, log and artifact verification remain separate operations.

Live Firecracker pod `2b3cfed7-4195-4b62-804a-e894445cdd52` completed the public
Apple-selected path using one collection command. Independent verification
accepted its 19-byte stdout (including binary bytes) and 20-byte stderr while
preserving exit 23. The pod was cancelled after verification. Evidence is under
`/tmp/nucleus-collect-logs-live/`. All 335 CLI unit tests passed, two ignored;
integration suites, scoped Clippy and convergence passed. Sandbox-only loopback
denials in the first full test run were resolved by running the fixtures with
loopback access.

Linux custom-lint run `37274884233` completed successfully on `d7053913a`.
The additional manifest checks pass for upstream action-input declarations,
merge-group scope parity, the single SVID validator, independent conformance,
attached boot spans, named netns programs, declared bridge filtering, distinct
workflow concurrency, and absence of piped installers/tracked build artifacts.
Coverage's mutation job remains active; final-head CI is still required.

Merge-authentication check at 07:15 UTC: the user gcloud login now fails refresh
with `Reauthentication failed. cannot prompt during non-interactive execution`.
The dedicated SPIFFE deployment wrapper still requires an interactive sudo
password (`sudo -n` refused); this is not evidence that its workload identity
failed. A request to refresh user authentication is pending. No GCP machines or
schedulers were changed. GitHub access and local implementation work continue.

Full `cargo deny` checks passed (advisories, bans, licenses and sources). The
exemplar scoreboard's 16 metrics passed; its lint-adoption baseline was raised
from 65/97 to the measured 66/98 after separating the HTTP adapter package.
The integer adoption floor remains 67%. A fresh main fetch has no missing
upstream commits.

The manually dispatched mutation job `111643425662` ended cancelled at 07:17 UTC
after reaching its existing 45-minute budget. It began 607 mutations and the log
records 23 `MISSED` results before cancellation; the machine-report gate also
failed. This is not a passing mutation result. Manual dispatch runs all six
configured modules. None of `capability.rs`, `guard.rs`, `lattice.rs`,
`certificate.rs`, `delegation.rs` or `trust.rs` differs from main on this branch;
the existing PR/merge-group path scopes that gate to changed lines. No timeout,
scope, threshold or test exclusion was changed. Coverage in the same run passed
as recorded above. The full log is retained at
`/tmp/nucleus-mutation-111643425662.log`.


### Persist the Apple host selection (2026-10-05)

`[node] apple_host_config = "host.json"` in the global CLI configuration now
selects the existing Apple readiness path for ordinary `run` and `node` commands.
It also reaches the goal/grant run path, preserving authorization before launch.
Explicit host, URL, identity or credential flags win over the saved default;
local and hook runs retain their selected mode. A failed saved host never falls
back to another host. `node` now reads its configured URL when no explicit URL
or Apple host is selected. Changing its argument to an option preserves the
difference between no selection and an explicitly chosen localhost address.

The saved JSON path resolves beside the global TOML file. Kernel/state paths
inside host JSON now resolve beside that JSON file, so changing the caller's
working directory cannot select another state directory. Direct `up` argument
paths retain their existing current-directory interpretation. This is an
intentional change for relative paths in existing host JSON files.

An isolated global config selected the existing development host without any
Apple-specific command flags: run dry-run, authenticated node health, create,
admission, receipt+raw-log collection and cancel all completed. Independent
verification accepted pod `f4f0f8c9-a8e5-47be-9d4c-307080ac92b4`'s exact 19/20
stdout/stderr bytes and preserved exit 23. Evidence is under
`/tmp/nucleus-apple-default-live/`. All 339 CLI unit tests passed, two ignored;
integration suites, scoped Clippy, convergence and four prepush gates passed.
The user's global configuration was not changed. Legacy setup/shell still need
Apple integration, and model-driven
coding journeys remain unverified.


### Apple setup with a verified ordinary workload (2026-10-05)

`setup --apple-host-config host.json` now uses the selected Apple host and saves
that selection for subsequent setup, run and node commands. Setup reads the
matched local image's input manifest, pins the guest kernel/rootfs, resolves the
requested inline policy and predicts isolation labels through the same shared
decider the node uses. It boots a short UID-1000 shell workload, obtains signer
information through authenticated admission, and checks the receipt with the
shared execution verifier. That verifier requires microVM execution and UID
isolation; setup additionally requires exit 0 and exact fresh stdout plus empty
stderr. The expected program and environment are computed before reading the
receipt. Signer enrollment trusts the provisioned local CA and operator-selected
image; it is not external platform attestation.

The temporary pod is cancelled before configuration is committed. Normal
verification errors and Ctrl-C after a pod ID is known also reach cancellation;
cleanup failures name the pod and retain the verification result in the error.
An initial-create interruption or process crash can still require manual cleanup.
Only `node.apple_host_config` is changed, using a comment-preserving TOML edit and
atomic private-file replacement. A concurrent config edit refuses replacement.
`--skip-verify` still requires host readiness, but reports the skipped workload
check explicitly. Incompatible Lima provisioning flags are refused.

Initial live checks correctly refused the requested/admitted digest mismatch and
cancelled their pods without writing config. Matching the host's existing
isolation labels and inline-policy normalization resolved that mismatch; the
binding comparison was retained. Pod `acd8306a-4b85-4f20-9755-18b2a1c1bddc`
then passed receipt and exact-log verification (57 stdout bytes, zero stderr,
exit 0) and confirmed cancellation. The new isolated config subsequently drove
saved-host setup, authenticated node health and run dry-run. Evidence is in
`/tmp/nucleus-apple-setup-live-report.json` and adjacent setup logs/config. All
343 CLI unit tests passed, two ignored; integration suites and scoped Clippy
passed. This used the existing development host and local image, not a published
fresh host image or either required model-driven coding journey.

The subsequent fresh-install check first confirmed that both the normal
`nucleus-microvm-host` container and `nucleus-microvm-host-srv` volume were absent.
Setup then created both from `nucleus-local-host:workspace-a125a6c43`, using new
state and identity under `/tmp/nucleus-fresh-apple-setup/`. Its ordinary pod
`7e952ef6-e342-4aa5-a9d2-7bdebf7b3e38` passed signed Firecracker/UID-isolation,
exit and exact-output checks, and was cancelled. The saved config then passed
authenticated health, reported the pod exited and supported run dry-run. The
idle host was trimmed and stopped with its state retained. This proves fresh
installation from that explicit local image; it is not a published-artifact
installation or a model-driven journey. Four prepush gates, convergence,
dependency visibility and all cargo-deny categories also passed.

### Repeat Apple installation verification (2026-10-05)

`verify --tier2` now honors the saved Apple host selection, and accepts an
explicit `--apple-host-config`. It uses the same supervised execution verifier
as setup, without rewriting CLI configuration. Explicit `--here` and `--vm-name`
retain the legacy Linux/Lima checks; the Apple JSON identifies its backend and
does not claim those legacy conformance checks ran.

The command restarted the stopped fresh installation and verified pod
`a614cc76-93a9-49d6-8424-1a1b2581dc86`: signed Firecracker execution, isolated
workload UID, exact 57-byte stdout, empty stderr and exit 0. Cancellation was
confirmed. The result is retained in
`/tmp/nucleus-fresh-apple-setup/standalone-verification.json`. All 344 CLI unit
tests passed (two ignored), along with integration suites and scoped Clippy.

### Wait for operator review (2026-10-05)

`node effect-approvals POD list --wait-secs N` now waits for unexpired pending
effects, allowing the operator to start observing before a workload reaches its
gated request. It polls the existing mTLS endpoint once per second and bounds
both requests and delays by the requested deadline. It returns only pending
entries; ordinary list remains an immediate snapshot. Timeout and observation
errors exit unsuccessfully without making a decision or cancelling the pod.
The wait does not extend a workload's approval timeout or replace exact-effect
review and grant. Pending/expiry selection shares the grant command's predicate.

Local mTLS integration proved that a newly published pending effect is returned
after an initial empty observation, completed/expired entries are omitted, and
an empty wait expires without posting a decision. All 347 CLI unit tests passed
(two ignored), integration suites, Clippy and all four prepush gates passed.
This is operator workflow validation, not an additional model-driven journey.

### Stop expired executions and return capacity (2026-10-05)

The node now constructs a monotonic execution deadline before admission/launch
and cancels a still-running pod when the reaper observes expiry. Previously
`timeout_seconds` bounded certificates and task tokens but did not itself stop
the execution. The existing teardown, capacity release and descendant cascade
are reused; cancellation failure retains the allocation and retries later.
Successful timeout cleanup records an unsigned `pod_timed_out` lifecycle event,
then the existing once-only exit handling retires authority. The reaper was
extracted from `main.rs` without duplicating its cleanup rules.

The reaper's ten-second polling interval and slow or failed driver operations
mean this is periodic cleanup, not an exact-time kill guarantee. A node restart
does not restore this in-memory monotonic deadline. `collect --wait-secs` remains
an observation limit and does not extend pod lifetime. Existing Apple images
must be rebuilt to include this node behavior.

A regression using real local child processes checked that unexpired pods remain
running, expiry stops the parent and cascades to its child, capacity becomes
available after teardown, and timeout/exit events are not repeated. A separate
local node accepted a five-second pod over mTLS; pod
`ddfce18f-7437-4365-81dc-53b27f910628` exited on the next reaper pass with a timeout
event. Evidence is under `/tmp/nucleus-execution-deadline-live/`; the temporary
node was stopped. The test needed explicit macOS capacity and Python's normal
CA validation without its optional strict AKI requirement, and used the actual
pod-list route. No node TLS policy changed.

Before this change, the combined all-feature suites passed 892 node and 580 proxy
unit tests plus their integrations. Afterward all 893 node unit tests (one
ignored) and three integrations passed, along with scoped Clippy, convergence
and four prepush gates. Clippy retained the existing four configuration warnings
about unreachable reqwest blocking-method paths in this feature selection.

### Retain the Firecracker slot until confirmed cleanup (2026-10-05)

Firecracker teardown previously returned its concurrency permit before killing
the VMM. Teardown now requires an observed process exit, including when its
caller supplies the `AlreadyExited` hint. Only the resulting private, consumed
`StoppedVm` witness reaches resource cleanup (ADR 0007 C-1, C-4, D). The slot
returns after packet-monitor and cgroup cleanup complete. A live process or
failed cgroup removal retains the slot; later cleanup can retry. The aggregate
capacity reservation still returns only after the enclosing teardown succeeds.
DNS child ownership likewise remains available when stopping that child fails.

Network cleanup still has its existing best-effort semantics, and jail-file
removal is not a proven disk-reclamation guarantee. The changed ordering ensures
that a stopped VM cannot keep using a returned network allocation; it does not
claim those older cleanup operations now report every failure. Tests use real
local child processes to validate lifecycle ownership, not a live Firecracker
image: a premature exit hint retains the slot, and a blocked cgroup removal
keeps it until a successful retry.

All 895 node unit tests (one ignored) and three integrations passed after this
change, along with scoped Clippy, convergence and four prepush gates. The existing
four Clippy configuration warnings remain. A newly unused macOS import exposed
by extraction was corrected; no warning suppression was added.

### Updated-node Apple microVM timeout validation (2026-10-05)

Built node commit `d2237238a` for `aarch64-unknown-linux-musl` and layered it
onto the existing local host image. The new image is
`nucleus-local-host:node-d2237238a` (image index
`sha256:b0f09de87c6c3a22dd8ef2375519cbd5fa547ee7fddde1d9e95dd60c561437c8`).
Only the node and its manifest entry changed; guest/rootfs and other host tools
remain the explicitly recorded `workspace-a125a6c43` inputs. The running node's
SHA-256 matched the built binary:
`50d03231f872bbe4ecb12c258364fc46298c2335bf18a193c1f9c18ef27df1a4`.

The idle normal Apple host was replaced with this image using retained CA/state.
Setup verified and cancelled ordinary pod `56ed1179-26e0-40b2-82a6-48cecf876724`.
A second workload requested a 15-second execution lifetime and ran a 60-second
sleep. The authenticated result reported `running`, then pod
`47b7a41f-8933-4b88-bc8a-656aa569582f` was observed exited with a node timeout
event. A subsequent ordinary workload, `5cb02591-5bcf-47c0-89b4-da582e4bb4ed`,
was admitted, independently checked by the shared execution/log verifier and
cancelled. Both verification workloads required Firecracker/UID-isolation,
exact output and exit 0.

Evidence, image provenance and the current test-host configuration are under
`/tmp/nucleus-node-refresh-d2237238a/`. An initial timeout-script invocation used
the wrong observation command and cancelled its pod; its records are retained
separately and are not counted as a timeout pass. The successful retry used
`node pods`. After validation the idle normal host was trimmed and stopped;
the existing development and primary acceptance hosts were not replaced.
Native tools were preserved before `cargo clean` reclaimed 6.2 GiB. This is live
microVM lifecycle evidence on a node refresh, not a newly published full image
or either model-driven coding journey.

### Confirm network cleanup before address reuse (2026-10-05)

Network reclamation now owns a non-cloneable lease instead of accepting a raw
pool index. Cleanup removes the pod's host rules, link and named namespace, then
requires successful namespace, link and firewall inventories showing the owned
resources absent. Deletion exit status alone is insufficient: an already-absent
resource and a failed command can both return nonzero. Only confirmed absence
consumes the lease and returns its index. A retired plan performs no further
deletions, including after another pod acquires that index (ADR 0007 C-4).

Registered Firecracker pods retain their plan and capacity when cleanup fails,
so a later reaper pass can retry. Failed launches log cleanup failures and leave
an unconfirmed index unavailable in that node process rather than recycling it.
This does not provide durable network-allocation recovery across node restart;
that remains open. Namespace guards on failed launch are still best-effort, but
their drop cannot return a network lease. Cleanup commands are asynchronous and
individually bounded by ten seconds.

Functional tests cover confirmed absence, retained ownership while resources
remain or inventory fails, successful retry and once-only recycling. All 897
node unit tests (one ignored), three integrations, scoped Clippy, the Linux
ARM64 build, convergence and four prepush gates passed. Existing Clippy
configuration warnings remain. A plain cross-target cargo check required an
uninstalled musl GCC; the configured Zig build completed successfully.

### Apple host forwarding and live network lease reuse (2026-10-05)

The trusted Apple Container host now explicitly leaves `/proc/sys` writable.
Apple Container 1.4.1's default read-only mount prevented the node from setting
forwarding inside a pod network namespace, even with its existing capabilities.
The remaining documented read-only paths and default masked paths are retained;
no additional capabilities are requested. This is a host default authority
change, not a change to the nested Firecracker guest's isolation. Lifecycle
inspection treats an absent or different read-only policy as configuration drift.

All 348 CLI unit tests (two ignored), integrations, scoped Clippy and four
prepush gates passed. The updated CLI replaced the idle normal host and setup
verified a signed ordinary workload. The local image refreshed only the node
from `b696c721e`; guest and other host inputs remain the previously recorded
base. Image index:
`sha256:e5515e43533b79a1b15d9cb422277bad789ffcd8cbbc24358b1ca506445f39fc`.
Node SHA-256:
`4ef5940f7fe298ee24943692a6d864db8a4f1a6794dcd26600337d1031e1d2ca`.

Two sequential ordinary network-enabled microVM workloads exited zero:
`58d8e115-0994-4221-ba02-355856757d3e` and
`3f24fd61-e2ee-494d-95fe-0bcc002c21e2`. After each cancellation, successful host
inventories showed its named namespace, link and firewall references absent.
Both used host address `10.200.0.1` on `10.200.0.0/30`, proving allocation reuse
after cleanup in the running node. Repeating cancellation of the first pod
while the second existed preserved the second pod's resources. This validates
network lifecycle, not outbound delivery or durable recovery across restart.

Evidence is under `/tmp/nucleus-network-refresh-b696c721e/`. Earlier attempts
exposed the read-only mount, a fixture allowlist too broad for SPIFFE issuance,
and host disk exhaustion during guest-disk copying. The successful fixture uses
a single-host allowlist and keeps broker enforcement enabled. A fixture parser
was corrected to accept cancellation's text output. Preserving native tools and
running `cargo clean` reclaimed 3.8 GiB before the successful retry.

### Bound queued launches by the admitted execution lifetime (2026-10-05)

Firecracker and container launches now acquire their driver slots against the
same monotonic deadline computed at admission. Before registration, the reaper
cannot see a queued launch; the previous semaphore wait could retain capacity
and delegated budget indefinitely. The shared acquisition helper refuses an
already-expired launch, bounds a pending wait, and rechecks after acquisition.
It preserves ownership of slots held by other workloads. This bounds queueing,
not every later driver operation or the full launch wall time.

A container admission test uses the real authority and capacity ledgers with a
held driver slot. Expiry occurs before any Docker request, leaves no registered
pod, and returns aggregate capacity and delegated budget. The helper tests also
cover successful subsequent acquisition and an unavailable pool. All 900 node
unit tests (one ignored), three integrations, scoped Clippy and the Linux ARM64
build passed. A first full run failed the existing state-lock test on immediate
reacquisition; that test passed in isolation and the complete rerun passed.
Existing Clippy configuration warnings remain.

### Adapter process lifetime validation and entry-point documentation (2026-10-05)

Coverage job `111695089444` on branch checkpoint `bf8aa11e5` failed before its
coverage verdict: the managed adapter unit test could still connect immediately
after its in-process helper returned. Listener teardown is now checked by an
integration test of the actual executable, avoiding shared unit-test process
descriptors during concurrent subprocess creation. The unit test still checks
the workload URL and exit code. The integration checks the announced loopback
address against the workload's environment, preserves exit code 7, and requires
the listener to be unreachable after the adapter process is reaped. Eight unit
tests and the process integration passed locally. This does not change adapter
runtime behavior or lower a coverage threshold; remote verification of the
updated branch is still required.

The README and macOS entry point now lead with the supported source-built Apple
Container workflow, including saved host selection and its local-artifact
requirements. Lima's release-artifact installation remains documented separately.

### Live Apple queue expiry and updated CI evidence (2026-10-05)

A local image of node `b3e1d1000` configured one Firecracker slot, with two
host vCPUs and 2048 MiB. Its index is
`sha256:d4de4d728643982941869bbe1c50d5de67089578779067464917fa04f41fc08d`;
node SHA-256 is
`cfedb93fcfa5d91715aaa153f91808b3cfa7587e8d477b209f4cb60fac095e8c`.
Guest artifacts remain the recorded base inputs. Setup independently verified
and cancelled pod `be4a5ba4-a571-4f0b-bd82-cf2143ebef89`.

Holder pod `6fc2955a-1aa4-417c-a874-a56db66724f9` kept running while a second
launch with a two-second lifetime waited for its slot. The queued launch
returned the deadline refusal after 2.26 seconds. After cancelling the holder,
`29ea47ac-1659-4879-8ac9-45747f2a7890` was admitted with 1024 MiB and two vCPUs
and exited zero. That larger request would not fit if the expired launch still
held its one-vCPU/512-MiB-plus-overhead reservation. Both admitted pods were
cancelled; the normal host was trimmed and stopped. Evidence and settings are
in `/tmp/nucleus-queue-deadline-live/`. Its one-slot entrypoint is a validation
configuration, not a new product default.

The first setup attempt exhausted host disk while copying the guest image and
left the container root marked `emergency_ro`. Native binaries were preserved,
`cargo clean` reclaimed 2.7 GiB, and the idle owned host was restarted after
space recovery. Setup and the lifecycle test then passed. No existing development
or primary acceptance host was replaced.

Coverage job `111701062376` in workflow `37290879260` passed on checkpoint
`47784445c`: workspace line coverage **83.53%**, portcullis line coverage
**90.42%**. The preceding `bf8aa11e5` coverage failure remains recorded; its
superseded manual run was cancelled with mutation testing unfinished. Custom
Dylint workflow `37289043619` passed on `bf8aa11e5`. These are checkpoint results,
not final-PR-head checks. The remaining full manual mutation run was cancelled
after coverage completed; all six mutation-targeted modules are unchanged from
main. That cancellation is not a passing mutation result, and PR/merge-queue
checks remain required.

### Keep all driver launches owned across cancelled handlers (2026-10-05)

HTTP and gRPC create handlers now use one node-owned launch task for every
driver. Previously only Docker did so: dropping a Firecracker or local create
future during boot could drop its resource reservations without finishing
driver cleanup. The task now retains the launch until completion. If the
waiting handler disappears, its unaccepted delivery cancels the registered pod
and retries cleanup until it can release authority. This moves the existing
Docker handoff into `pod_launch`; Docker-specific rollback remains separate.

A real local child-process test drops the caller while the proxy is starting.
The node finishes registration, kills/reaps the abandoned child and returns
aggregate capacity and delegated budget allocation. The existing delegation
model now observes the admitted certificate before teardown, checks the same
certificate/spec/lineage properties as a delivered launch, and expects the
cancelled pod to remain listed with retired authority. A booted workload may
have acted, so the existing conservative policy charges its allocation; this
is distinct from an unspawned failure's refund. No refund is inferred merely
from client disconnection.

All 901 node unit tests (one ignored), three integrations, scoped Clippy,
the Linux ARM64 build, convergence and four prepush gates passed after adapting
the model. Existing
Clippy configuration warnings remain. This proves handling of cancelled
handler futures; it is not a client receipt acknowledgment protocol or durable
recovery across node-process termination. A lost response after handler
completion can still require operator inspection and execution-timeout cleanup.

### Bound the VMM version probe before launch (2026-10-05)

The Firecracker version probe now has a ten-second maximum and shares the
admitted execution deadline when that is earlier. An already-expired request
does not start the probe. A timeout refuses launch and dropping the command's
output future requests termination of its direct child through Tokio's
`kill_on_drop`. It does not claim descendant containment or an exact-time
kill guarantee. Previously this subprocess wait had no bound, before the pod
was registered and therefore outside the reaper's reach.

Three focused preflight tests passed: missing executable, completed output
without a version, and a fixture exercising expiry-before-spawn, a stalled
probe, then a successful pinned-version probe. The Linux ARM64 build passed.
The preceding complete node suite remains 901 passing tests plus three
integrations; this focused change adds one unit test and does not claim a new
full-suite result.

### Matched host and guest installation (2026-10-05)

All nine rootfs binaries and the host binaries were built from `728972a74` for
Linux ARM64 musl. The guest-init build omitted CI instrumentation; tool-proxy
used its production `mcp,spire,remote-audit,otel` features. The standard probe
binaries were packaged for completeness, without executing adversarial probes.
The retained harness base archive supplied the ordinary system and harness
runtimes. Every guest binary was read back from the assembled ext4 image and
matched its staged SHA-256 digest.

The resulting local image is `nucleus-local-host:matched-728972a74`, index
`sha256:0ec5d9cf44afdb46bd1ed216c17f8079796a83586af3e18d86ffe296afc4e60f`.
Rootfs SHA-256 is
`4eefd49e21be0d3e4f5baec45f4a946aa953b6a7def91ffc73514ac0235ed8b7`;
node SHA-256 is
`b71e647befc6bc6f091055fcd2037490ce94be2a80ee194ab44725fb59ce936a`.
Build manifests, logs and readback digests are retained under
`/tmp/nucleus-matched-728972a74/`.

After privately cloning the stopped prior test volume, only that test host and
volume were replaced. Fresh setup created a new identity and verified pod
`f97f67b0-d6b7-41b8-91cb-607535dd3979`: Firecracker, UID isolation, exit zero,
exact expected output, and a valid host-signed execution receipt. Saved-host
`verify --tier2` independently repeated this with
`dc0febaf-88d7-40cb-8f1f-d34fc9fccdb4`. Both were cancelled by verification.

Pod `5bfd4652-e33d-4377-988f-05c16b8ce711` then ran the packaged managed HTTP
adapter at UID 1000. Its child received the bound loopback URL, cloned the
unchanged coding fixture, checked its commit and input hashes, observed the
expected nine-test failing baseline, and successfully invoked both installed
harness help commands. Independent verification used a separately read host
public key and intended environment, accepting all four artifacts and exact
stdout/stderr bytes. The pod was cancelled and the volume trimmed. No upstream
request or model call was part of this packaging preflight. Completed model
journeys remain zero; these results establish local packaging and installation,
not a published release or model compatibility.

The image build initially exhausted local disk, leaving the shared builder's
filesystem `emergency_ro` and an incomplete cached source snapshot. Reclaiming
unused Cargo targets and recreating the idle disposable builder resolved this;
the other active hosts and Apple Container service were not reset. The full
node suite on `728972a74` subsequently passed: **902 unit tests**, one ignored,
and **three integration tests**.

### Supported executor public-key enrollment (2026-10-05)

The verification exercise exposed a missing operator step: OpenSSL did not read
the persisted Ed25519 PKCS#8 v2 encoding, so separately enrolling the public key
required manual decoding. `nucleus-hostctl public-key <key-file>` now reads the
existing key with the same crypto library and prints only its public half as
64 hex characters. It never creates or rotates a key. Raw DER input is bounded
and zeroized on return. The receipt handoff documents invoking this on the
trusted Apple host and retaining the public pin separately from evidence.

The process integration checks exact public-only output, preservation of the
existing file, and refusal of missing or incomplete files without creating or
replacing them. All 45 library tests, two CLI tests and that integration passed,
as did scoped Clippy, the Linux ARM64 build and four prepush gates. A temporary
copy of the new binary on the fresh host returned the same independently
enrolled public key and was removed after verification. This addition follows
the matched image above and is not yet included in that image's recorded digest.

The follow-up image `nucleus-local-host:matched-b7a5b306f` packages the new
hostctl with the same verified node/guest inputs. Its index is
`sha256:f0118061d8df5c79df6f5cb68923c64c54538cb51d0347eb2f3cd0856b1e96e3`;
hostctl SHA-256 is
`c0808ab68b54ba154136a13139056964a1d583da33e55f110385942c024623a6`.
After upgrading the idle test host, setup verified
`4e2e50d1-652d-4c75-9504-4651d7894a85`, exited zero and cancelled it. The
packaged public-key command matched the prior independently enrolled key,
demonstrating identity preservation across this image replacement. The test
host was trimmed and stopped. Its configuration and evidence are under
`/tmp/nucleus-matched-b7a5b306f/`.

### Latest checkpoint checks and local verifier prerequisite (2026-10-05)

On `b7a5b306f`, coverage job `111722443690` passed in workflow `37297554229`:
**83.54% workspace lines** and **90.41% portcullis lines**. Custom Dylint
workflow `37297557548` and dependency hygiene workflow `37297560723` also
passed. The full manual mutation job was cancelled after coverage completed:
its six target modules are unchanged from main. That cancellation is not a
passing result or a substitute for the final PR's scoped checks.

The exact full-workspace local Clippy command stopped at the verifier service's
embedded WASM check. The local generated SDK artifact, dated September 14,
did not match the tracked canonical digest. An isolated source snapshot built
with Linux ARM64 Rust 1.96.1 and wasm-pack 0.13.1 also produced a different
digest. Neither the pin nor the existing local SDK artifacts was changed.
Main's canonical Linux CI Clippy check is green; the branch must still pass it.
Clippy with all workspace targets/features **except `nucleus-verifier-service`**
passed locally. This is a scoped result, not a full-workspace pass. The temporary
SDK container was removed after the build; evidence is retained under
`/tmp/nucleus-sdk-prerequisite/`.

CLI help now describes setup as Apple Container or Lima configuration and the
node surface as pod, approval and evidence operations. This is a help-text
correction only; runtime behavior is unchanged.

### Distinguish unavailable reports from missing pods (2026-10-05)

The legacy HTTP receipt route now returns `pod exit report is unavailable`
when an authorized, existing pod has no available exit report. It retains the
existing 404 status, but no longer reports `pod not found` for a cancelled pod
that remains registered. Lookup and ownership checks run first and keep their
existing missing-pod behavior. This does not create a report after cancellation
or change the independent signed workload-execution collection API.

The existing cancellation regression now checks the JSON response and status,
not only the internal error. All 22 handler tests passed, including caller
ownership checks and the running-pod case. This corrects the misleading behavior
recorded in the earlier environment notes; the pod-retention semantics remain.

Scoped Clippy, the Linux ARM64 node/CLI build and all four prepush gates passed.
The final local image `nucleus-local-host:final-ea6057adb` replaces those two
binaries on the matched `b7a5b306f` image, retaining its guest inputs. Its index is
`sha256:43324312bc39294df3559a59e900d809421daa25add205877bfa3e6d88dba788`.
Setup verified and cancelled `b92933fa-2c94-4074-bcd1-ad1f8b9c5e3d`. Over mTLS,
the pod remained listed as exited, its receipt returned 404 with the new report
diagnostic, and an unknown pod's receipt retained 404 `pod not found`.
The test host was trimmed and stopped. Build provenance and results are under
`/tmp/nucleus-final-ea6057adb/`.

The direct Python check used required verification under the installation CA,
with hostname checking disabled for the SPIFFE URI SAN, matching the CLI's
connection model. Python 3.14's optional `X509_STRICT` additionally demanded an
Authority Key Identifier extension and was not used by that check. Inspection
used the supported pod-list route; `GET /v1/pods/{id}` is not an authorized HTTP
operation here. No certificate, route or authorization policy was changed.


### Saved Apple installation lifecycle (2026-10-05)

`start`, `stop` and `doctor` now follow the saved Apple installation instead of
always invoking Lima. Start retains the existing checked readiness path; stop
uses the ownership witness and confirms the host stopped without deleting its
container, volume or identity. Doctor observes existing state and checks KVM and
mTLS without starting, replacing or provisioning anything. Explicit Apple and
Lima selections are mutually exclusive, with no backend fallback on failure.
Stop works when an old boot kernel has been removed, but refuses foreign or
mismatched containers. Persisted installation state survives; live workloads and
in-memory pod history do not survive a host stop.

The CLI suite passed **351 unit tests** (two ignored) and **16 integration tests**
(with the existing environment-dependent cases ignored). Scoped all-target
Clippy, the native build and four prepush gates passed. The task-owned normal
host on `nucleus-local-host:final-ea6057adb` demonstrated stopped-doctor refusal,
start readiness, read-only healthy diagnosis, mTLS node health, stop and repeated
stop. It is stopped again. Results are retained under
`/tmp/nucleus-final-ea6057adb/lifecycle/`. These are native operator CLI changes;
the image digest and its runtime inputs remain those recorded above.

The current node, tool proxy (MCP/SPIRE/remote-audit/OTel features), guest-init and
HTTP adapter also built successfully for `x86_64-unknown-linux-musl`. This is a
cross-build result, not live x86 KVM evidence. The log is
`/tmp/nucleus-final-ea6057adb/x86-runtime-build.log`. Model-driven journeys remain
zero, pending the previously requested operator model configuration.


### Confirmed Docker removal without an exit observation (2026-10-05)

A graceful-stop or inspect error can be followed by successful forced removal.
That path previously left no cached terminal state, so subsequent status could
report Docker's missing-container error even though cancellation had succeeded.
Confirmed removal (including Docker's already-absent response) now records
`Exited` with an unknown code when no exit was observed. An existing observed
exit code is preserved. Neither removal errors nor daemon unavailability count
as confirmation, and capacity remains held until teardown succeeds.

All three container lifecycle tests and scoped all-target/all-feature Clippy
passed. The new ordinary lifecycle regression fails on the original behavior
at the terminal-state assertion and passes with the correction; it covers both
forced removal after a failed graceful stop and an already-absent container.
Existing tests retain the capacity-on-removal-failure and observed-exit checks.
Evidence is under `/tmp/nucleus-container-terminal-*.log`. This change follows
the recorded Apple image checkpoint and affects Docker status reporting; that
image is not evidence for this later source revision.


### Publication image checkpoint (2026-10-05)

The Linux ARM64 node and CLI built from `08f74b39b` are packaged as
`nucleus-local-host:publication-08f74b39b`, retaining the previously verified
guest inputs. Its local index is
`sha256:7ac7e59d2cfdf8df626ebe5691013c71cc4cef599b3a7acbc7e6cfef46a6b5a2`.
The running image's node and CLI hashes matched the updated manifest:

- node: `94b7011f39c29b46ea5cc845f1429025c8d9050b2296c0c4f87c2467f7f6a545`
- CLI: `454f7630edb7c790041c4711957dc1e0dede741d1a0c2d153167e68f8b2d6d09`

Setup verified UID-isolated Firecracker execution, exit zero and exact logs for
`96394637-c48b-4a4c-9361-90f2d934f362`, then cancelled the pod. The host's exported
executor public key matched the independently enrolled pre-upgrade pin. Saved
`doctor` confirmed KVM and mTLS health; `stop` retained the installation, and a
subsequent `doctor` refused the stopped host. The task-owned host was trimmed and
is stopped. Results, image identity and build provenance are retained under
`/tmp/nucleus-publication-08f74b39b/`. The native operator CLI includes the saved
lifecycle integration. This is still a local image and ordinary installation
validation, not a completed model-driven journey or live Docker teardown test.

Custom Dylint workflow `37303376201` passed on the earlier Apple lifecycle source
`ebd6a0439`. The later Docker status correction has its scoped regression and
Clippy evidence above; final PR checks must run on the published head.


### Initial PR checks and feature/target corrections (2026-10-05)

On PR head `ac7ec4d83`, the workspace job `111752058096` ran **9,349 tests: all
passed, 47 skipped**. The default-feature Clippy ratchet separately found two
memory tests using the `local-driver`-only node fixture without declaring that
requirement. Path validation now constructs its host roots directly and remains
covered with default features; the container-environment fixture test declares
`local-driver`. The test-only reaper import has the same feature requirement.
Default node all-target compilation, three default-feature memory tests and all
five all-feature memory tests passed locally.

Linux CI also found a single-pattern match in the netlink receive loop, excluded
from the macOS lint build. It now uses the equivalent conditional binding.
Measuring the Linux-only transport additionally found 16 ratcheted conversion
warnings. Netlink attributes and messages now check length and type fields before
encoding; byte comparisons widen their inputs instead of truncating constants.
Valid wire encoding is unchanged. Oversized attributes and unrepresentable types
return errors before transport. Standard Linux all-target/all-feature Clippy
passed with the existing four stale-config dependency warnings; the changed
netlink module has zero remaining warning/error sites in the cast measurement.
The two Linux serializer/packet tests passed in a disposable Apple container.
The macOS workspace ratchet measured 342 against the unchanged ceiling of 345;
final Linux CI remains the authority for the workspace count.

The first live x86 quickstart run booted its pod but failed the obsolete
`NUCLEUS-MEDIATION-RECEIPT` assertion: it still requires the guest signing key
retired by this implementation. Its replacement must check host-issued evidence;
that migration is pending. Gatehouse's informational shadow jobs also could not
complete their control-plane authentication. Deployment access still requires
operator reauthentication. Neither failure is recorded as a passing check.

### Portable supervised-workload verification (2026-10-05)

The Apple setup verifier now delegates to a shared Rust workload verifier.
`nucleus verify --tier2 --here --execution` exposes the same check for an
installed local node. It hashes the operator's installed kernel/rootfs before
admission, accepts the supported x86_64 and aarch64 architectures, enrolls the
signer over mTLS independently of the receipt, and checks the requested program,
environment, Firecracker/UID isolation, exit status and exact nonce-bearing logs.
It cancels each pod after a returned creation ID, including on verification error.
The local node must enforce its host-supplied PodSpec; legacy baked workloads
cannot satisfy this check. Apple setup still requires an aarch64 input manifest.

The shared verifier passed the real Apple workload
`9dc078dc-5a72-4aa8-a66b-5b9a89f7ace4` against the publication-08f74b39b image:
exit zero, 57 stdout bytes, empty stderr, signed evidence verified and pod
cancelled. The two-architecture program-identity test and scoped all-target
Clippy passed. This is an execution check, not broker authorization evidence or a
model-driven journey. The obsolete quickstart receipt steps are still present;
their migration remains pending rather than silently narrowing that gate.

### Live host-evidence gate migration and response framing (2026-10-05)

The x86 quickstart's two guest-key receipt steps are replaced by the Rust
`host-evidence-live` gate. This explicitly changes the evidence producer to the
host, matching the design that retired guest-held host signing keys. Existing
guest-local allow/deny and delivery checks remain. The new check starts a separate
enforcing node with a fresh CA and operator registry, pins the host public key
before admission, boots a real Firecracker guest, and sends one ordinary echo
request through its proxy and host broker. The shipped offline auditor verifies
the host authorization/outcome journals; the check also compares the intended
effect digest, destination, tariff and exact response bytes. It claims host
authorization and observed transport completion, not remote action semantics or
truth of guest-local reports. A fresh success witness is written only after pod
cancellation and node shutdown, so Cargo selecting zero tests cannot pass.

The live check exposed a product defect: buffering a chunked guest response left
its Transfer-Encoding header on the rebuilt response. Axum added Content-Length
and Hyper refused the conflicting framing, closing the client connection after
the host had already completed the upstream call. The focused regression failed
with `IncompleteMessage` before the fix. Removing consumed transfer/trailer
headers passed all four signed-proxy tests and restored the real response path.

Live ARM64 Linux validation used the Apple KVM host, the publication-08f74b39b
guest image, and a separately staged node built with the framing fix. Pod
`870e9608-5e4e-4362-8e9a-ceb5064e9476` passed. A temporary missing-journal input
then made the real offline verification fail with NotFound after one authentic
fixture call; the restored gate passed again on pod
`03b190d5-61ab-47a4-852c-07e949aae961`. Both ordinary runs verified the exact
effect and completed cleanup. Scoped node, CLI and xtask Clippy passed. Final
x86 CI must still validate the workflow orchestration and its own source-built
guest; the ARM64 run is not substituted for that required result.

Separately, the portable Linux execution entry point from `c438db5b4` passed on
pod `1202c6c2-f72b-42d9-a44d-334aec3f516d`: signed execution, exit zero, exact
57-byte stdout, empty stderr and confirmed cancellation. No model-driven coding
journey is claimed by either fixture.

### CI checkpoint and installer source ownership (2026-10-05)

On `3e924d377`, the workspace job passed **9,352 tests, 48 skipped**. The
coverage job passed **83.38% workspace lines / 90.41% portcullis lines**. The
source-built x86 guest passed the existing boot checks, then the new receipt
gate correctly refused to start because its node binary was missing. Local
setup had deleted that input after copying it into `/usr/local/bin`.

Installer inputs now distinguish borrowed local artifacts from temporary Lima
transport copies. Only the latter carry cleanup authority. The regression
reproduced deletion before the fix, then passed two consecutive installs with
the original bytes intact. All 29 provisioning tests, including the real mTLS
handshake, and scoped all-target CLI Clippy passed. The same CI run also required
the unguarded-pipeline pin to decrease from 44 to 43 after the shell receipt
steps moved to Rust; the measured pin check passes at 43. Final x86 receipt
verification and merge checks remain required.

On `ae77c819c`, **9,353 workspace tests passed / 48 skipped**, documentation
tests passed, and coverage passed at **83.38% workspace lines / 90.42%
portcullis lines**. Dylint and the real x86 pod-list check also passed. The x86
host-evidence gate advanced past the installer precondition, then correctly
refused its networked pod because the runner had not loaded `br_netfilter`.
No fixture upstream call occurred. The workflow now explicitly loads that
kernel dependency before the transaction; host admission and verification remain
unchanged. CI configuration and all four prepush checks pass. A successful x86
transaction remains unverified until the next run completes.
