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
host authorization evidence. These are local host tests, not Tier-2 evidence.

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

Each implementation change gets focused adversarial and positive controls, with
regression checks driven red where required by ADR 0007. Follow repository
prepush gates before every push. Protocol consumers include the node and the
tool proxy with all features. Real guest behavior needs a supported Tier-2 host;
macOS unit tests do not prove the Linux launch path.

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
