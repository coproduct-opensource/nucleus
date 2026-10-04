# Secure coding release implementation plan

Authorized order, 2026-10-04. The release outcome is a fresh installation that
runs a vendor-neutral agent harness inside a pod, fixes a repository, runs its
tests, obtains an action-bound approval, opens a PR through mediated egress, and
produces evidence an external verifier can inspect. Two distinct harnesses must
complete this journey. Gatehouse control-plane implementation stays outside this
repository.

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
7. Exercise the compromised-guest conformance harness, genuine allowed effects,
   reconnects, concurrency and real Tier-2 guest traffic. Promote each gap only
   when the corresponding live host property holds. Retire shadow-only behavior
   only after the enforcing path has this evidence.

## 2. Supported coding workflow (P0, alongside enforcement)

Issues: #2791, #2696, #2698. Reconcile existing workload-door, MCP and streaming
implementation before adding replacements. Bundle required runtime helpers;
align quickstarts, artifacts and versions. Verify the complete release journey
above on a supported host, including intelligible refusals and approval prompts.
Do not equate the algebra demo or an isolated proof pod with useful agent work.

## 3. Egress accounting and scoped credentials (P1)

Issues: #2905, #3160. Broker egress metering already exists. Complete accounting
for every permitted outbound path, preserving a shared pod budget. Test an
otherwise allowed service used as an exfiltration destination, including
concurrent calls. Give audit uploaders short-lived credentials restricted to the
resolved bucket/prefix, without ambient credentials in workload or uploader
environments. Keep provider implementations behind the vendor-neutral boundary.

## 4. Resource admission (P1)

Issue: #3153. Reserve aggregate host memory/vCPU capacity before admitting pods;
release on failed launch and exit. Bound swap where supported, clean development
cgroups, and test concurrent admission against an operator capacity plus host
reserve. Per-pod ceilings alone do not establish this property.

## 5. Evaluation through production enforcement (P1)

Issue: #2699. Restore the AgentDojo integration through the real kernel/runtime,
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

Paced egress admission currently treats the complete staged upload as one batch;
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

The updated binary still needs the real compromised-guest streaming run,
including nonce replay, spent-approval reuse and changed-payload refusal.

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
priority. Aggregate staging-disk capacity and reconciling external
containers surviving a node restart remain open.

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
removed. Clippy passed. The updated node has not yet been used for a live pod
launch with these defaults.

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
