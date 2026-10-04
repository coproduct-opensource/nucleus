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
observed taint, absent/reused approval, and zero remaining budget. Its two signing
key properties remain gaps. These are local host tests, not Tier-2 evidence.

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
   obtain a clean policy or start a broker. Broker charging and revocation are
   not yet wired into this state, and durable runtime recovery remains open.
4. Connect host decisions to both PERFORM and streaming effects. The executable
   effect requires a consumed, matching host decision. Missing, stale, foreign,
   replayed and mismatched decisions refuse before credentials or upstream I/O.
   Recheck current pod taint, expiry, revocation and budget when committing the
   effect: another channel may change them after an earlier decision was issued.
   **In progress:** both broker paths check actual WebFetch authority plus the
   requested operation before credential access and again after async minting,
   immediately before execution. Private non-cloneable permits are required to
   construct either upstream call. Revocation and cost settlement remain.
5. Wire authenticated host approval, expiry and one-shot consumption. Preserve
   legitimate approved work; denying every approval-gated operation is not done.
   **In progress:** operator-only mTLS routes list and grant/refuse pending host
   effects. Approvals expire after five minutes and are consumed at final
   authorization, not preflight. Failed minting does not consume them. CLI UX and
   complete request review remain to be delivered.
6. Keep receipt and exit-report authority outside the guest. Distinguish host
   observations from guest assertions in signed evidence.
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
