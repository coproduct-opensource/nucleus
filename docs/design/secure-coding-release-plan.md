# Secure coding release implementation plan

Authorized order, 2026-10-04. The release outcome is a fresh installation that
runs a vendor-neutral agent harness inside a pod, fixes a repository, runs its
tests, obtains an action-bound approval, opens a PR through mediated egress, and
produces evidence an external verifier can inspect. Two distinct harnesses must
complete this journey. Gatehouse control-plane implementation stays outside this
repository.

## 1. Host-authoritative enforcement (P0)

Issues: #2702, #3114, #3115, #3116, #3117.

Current baseline: `host_decide` is shadow-only. Its kernel and taint are now
shared across pod channels; decision ledgers remain per connection. Broker
PERFORM and streaming calls do not consume host decision
rights. `pod_api/trust_boundary.rs` records six expected gaps. None of those gaps
may be relabelled as holding solely because a protocol or kernel unit test passes.

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
   **In progress:** non-streamed PERFORM has a derived canonical binding over
   operation, resolved upstream name/URL, HTTP method, credential header name,
   content type and exact body bytes. Method and content type are shared with
   the HTTP caller. The retry ledger rejects substitutions both while a call
   is in flight and after settlement; audit justification is deliberately not
   part of the effect. This binding is not yet connected to host decision
   consumption, and stream payload binding remains open.
3. Move enforceable state to the pod lifetime. Connection replacement cannot
   reset observed taint, spent budget or revocation. Concurrent channels must
   share the applicable limits. Host-delivered observations raise host taint
   independently of guest reports.
   **In progress:** the shadow service shares one kernel and taint across pod
   connections. Protocol sequence/decision epochs remain per channel. A policy
   panic refuses subsequent observations and decisions rather than resetting
   state. This is in-memory state for the running pod listener, not persistence
   across node restart. Broker charging, revocation and host-derived observations
   are not yet wired into this state.
4. Connect host decisions to both PERFORM and streaming effects. The executable
   effect requires a consumed, matching host decision. Missing, stale, foreign,
   replayed and mismatched decisions refuse before credentials or upstream I/O.
   Recheck current pod taint, expiry, revocation and budget when committing the
   effect: another channel may change them after an earlier decision was issued.
5. Wire authenticated host approval, expiry and one-shot consumption. Preserve
   legitimate approved work; denying every approval-gated operation is not done.
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
