# Nucleus North Star

## Vision

**Nucleus makes "agent jailbreak → silent damage" provably impossible by
construction, while remaining frictionless enough that small dev teams adopt it
like a linter.**

> Assume the agent is compromised. Constrain what it can do anyway.
> Prove the constraints hold.

## Flagship Safety Claim

**No external side effect occurs unless it is mediated by Nucleus and authorized
by a policy that can only stay the same or tighten during execution.**

Corollaries:

- **No exfiltration without an explicit sink capability.**
- **No "talk your way into more permissions" mid-run.**
- **No untrusted content reaching a sink without an approval/declassification gate.**

This is the apodictic core — logically compelled, machine-checkable, marketable.

"Can only stay the same or tighten" is stated from the **workload's** side, which
is what the second corollary makes precise: the agent cannot widen its own
authority mid-run. The single widening path, `POST /v1/escalate`, is not the
agent's to take — it requires a separate approver's authority and the result is
bounded by the delegation ceiling, so it never exceeds what was delegated (see
Pillar A #4). An adversary controlling the workload sees a pure ratchet.

### The Confidentiality Dual

The claim above is about **authority**: what a workload may *do*. Its dual is
about **confidentiality**: what a workload may *learn*. Both are needed, because
a tenant's first question is not "can this agent act" but "can another tenant's
agent read my secrets."

**Whatever an agent workload does — including when an adversary controls the
inputs feeding it — it can neither learn the secrets Nucleus holds on its behalf
nor those of any other pod, nor influence which of them get released; the sole
exception is a value a governor deliberately released with a single-use token,
and even then the adversary cannot steer which value that is. This covers
explicit flows through every mediated channel and excludes timing, cache, and
other microarchitectural channels, and excludes availability and
resource-contention channels such as a bounded pod pool; it is a theorem about
the code that ships, re-checked on every change, and a relying party can verify
from the outside that the pod they are talking to is the artifact the theorem is
about.**

The exclusions are **inside the sentence, not a footnote**, so the claim cannot
be quoted without its limits. Cross-pod confidentiality stated without them would
read as "immune to co-tenancy attacks" — the worst overclaim available to this
project, and one we have no basis for: Firecracker, the host kernel, and the
hardware are all in the TCB and none of them is modelled.

The **resource-contention** exclusion was added after the fact, and it is worth
saying why rather than letting it look like it was always there. The first
version excluded only timing, cache, and microarchitectural channels. Working
through the host state field by field (`cross-pod-view.md`) turned up
`firecracker_pool`: a bounded semaphore that pod spawn acquires with
`acquire_owned().await`. It **blocks**, so one tenant's pod delays another's, and
that channel is macroscopic and reliable — not microarchitectural at all. Under
the original wording a careful reader would have concluded the claim covered it,
and that the claim was false. It was. Possibilistic noninterference over values
conventionally says nothing about availability; the fix is to say so out loud,
which is what this sentence now does.

#### Status — what is proved, what is tested, what is not yet

Keeping these apart is a house rule, because a north star written in the present
tense is how a claim outruns its wiring. This table is a **machine-checked
ledger** (`scripts/check-north-star-ledger.sh`, run on every change): each row
names a clause of the sentence verbatim, carries exactly one status from
{PROVED, TESTED, NOT-YET}, an evidence handle CI can dereference, and the gate
that reds if the status regresses. The row count and the NOT-YET count are
pinned (`scripts/north-star-ledger-ratchet.txt`) — deleting a row or demoting a
status is a visible event, not an edit.

| # | Clause (verbatim from the sentence) | Status | Evidence | Falsified by |
| --- | --- | --- | --- | --- |
| C1 | "learn the secrets Nucleus holds on its behalf" | PROVED | `crates/portcullis-core/lean/IdentityMaterialNoninterferenceExtracted.lean#identity_material_never_reaches_the_workload`, `crates/portcullis-core/lean/ChannelAdmissionExtracted.lean#no_channel_delivers_secret_to_the_workload`, `crates/nucleus-tool-proxy/src/workload.rs#DEFAULT_WORKLOAD_UID`, `crates/nucleus-tool-proxy/src/workload.rs#PUBLIC_RESERVED` | `scripts/check-c1-inbound-fences.sh` |
| C2 | "nor those of any other pod" | NOT-YET | `docs/cross-pod-view.md` | — |
| C3 | "nor influence which of them get released" | PROVED | `crates/portcullis-core/lean/PodMachineSpike.lean#noninterference` | `.github/workflows/portcullis-core-proven-lean.yml` |
| C4 | "a governor deliberately released with a single-use token" | TESTED | `crates/portcullis-core/lean/DeclassifySinkScopeExtracted.lean#no_second_apply`, `crates/portcullis/src/kernel/declassify_authority.rs#apply_declassification_token_on`, `crates/portcullis/tests/declassify_rehome_egress.rs#c4_flip_back_on_one_graph`, `crates/portcullis/tests/kernel_token.rs` | `scripts/check-declassify-value-bound.sh` |
| C5 | "cannot steer which value that is" | PROVED | `crates/portcullis-core/lean/DeclassifySinkScopeExtracted.lean#four_run_value_robustness`, `crates/portcullis/src/flow_graph.rs#value_binding_ok`, `crates/portcullis/tests/declassify_scope.rs#four_run_released_value_is_not_attacker_steerable` | `scripts/check-declassify-value-bound.sh` |
| C6 | "every mediated channel" | TESTED | `crates/nucleus-ifc-kernel/src/egress_channel.rs#no_channel_is_an_open_hole`, `crates/portcullis-core/lean/MediationScopeExtracted.lean#no_sink_reachable_without_discharge`, `crates/nucleus-ifc-kernel/src/egress_channel.rs#documented_inventory_equals_the_enum`, `scripts/check-egress-probe.sh`, `docs/architecture/mediated-set.md` | `scripts/check-egress-probe.sh` |
| C7 | "a theorem about the code that ships" | TESTED | `.github/workflows/aeneas-ifc-scoped.yml`, `crates/nucleus-ifc-kernel/src/extracted/identity.rs` | `.github/workflows/aeneas-ifc-scoped.yml` |
| C8 | "re-checked on every change" | TESTED | `.github/workflows/aeneas-ifc-scoped.yml`, `scripts/check-extracted-callsites.sh`, `scripts/extracted-callsites-manifest.txt` | `scripts/check-extracted-callsites.sh` |
| C9 | "verify from the outside" | NOT-YET | `crates/nucleus-identity/src/attestation.rs`, `crates/nucleus-node/src/posture.rs#admit_posture` | — |
*The clause fragments quote the sentence above, whose exclusions travel with
them: the claim covers explicit flows only, excluding timing, cache, and other
microarchitectural channels, and excluding availability and resource-contention
channels.*

What each status means, and what it deliberately does not:

- **C1 (PROVED — re-promoted 2026-08-08; had been demoted earlier the same day).** FM-5 genuinely proves,
  over the seven modelled child-inheritance channels (Env, Argv, Cwd, Stdio,
  ExtraFd, Uid, Cmdline), the 11-kind × 3-principal delivery table,
  Aeneas-extracted, `sorry`-free, axiom-audited — but the *clause* is broader
  than that theorem,
  and the *clause* was **falsified by a channel FM-5 does not model**: the
  guest kernel command line (`/proc/cmdline`) is world-readable inside the VM,
  and it carried real secrets — `nucleus.approval_secret` (the symmetric HMAC
  key, so any workload could *forge approvals*, an authority bypass) on every
  pod, plus the AWS audit-sink credentials whenever an audit sink was
  configured. Both are closed as of 2026-08-08: the AWS credentials ride the
  workload API (`FETCH_AUDIT_CREDENTIALS`, served once before any workload
  exists), and approvals are Ed25519 signatures the guest verifies against
  the node's *public* key (`nucleus.approval_pubkeys`) — no shared secret
  exists in the guest. The **task-token cmdline copy** and the dead Tier-3
  **`nucleus.sandbox_token`** were then RETIRED (2026-08-08): the task token is
  fetched over the workload API (`FETCH_TASK_TOKEN`), and the sandbox token was
  verified with an `auth_secret` no shipped rootfs delivers
  (`/etc/nucleus/auth.secret` is written only under `build-rootfs.sh
  --legacy-secrets`), so it could never verify — a dead Secret on a
  world-readable channel. `MaterialKind::TaskToken` stays `Secret` in the FM-5
  model; rather than argue the cmdline copy harmless (an argument resting on
  `session_mint` keeping the nonce host-pinned forever), it is deleted. **No pod
  writes any per-pod material to `/proc/cmdline` now** — a categorical gate
  (`no_pod_cmdline_carries_any_per_pod_secret`) proves it over the real boot
  args for every identity outcome, and it is the Rust half of the Lean channel
  theorem. This also realized the FM-4 snapshot payoff: a realistic
  identity-bearing pod cmdline is `SafeToClone`. **The cmdline is now a MODELLED
  channel** (`ChannelKind::Cmdline`, Aeneas-extracted): the flagship
  `no_channel_delivers_secret_to_the_workload` covers it, and
  `the_cmdline_delivers_no_secret_to_the_workload` states it by name — a `Secret`
  re-appearing on the command line is now a RED theorem, not an unmodelled gap.
  So the specific falsifier that demoted C1 is closed AND proved. **C1 is
  re-promoted to PROVED** after a red-team walk of the four residual inbound
  surfaces resolved each — two as declared exclusions, two closed fail-closed:
  - **Bind-mounts (excluded).** Firecracker gives the guest virtio block
    devices, not a shared host filesystem; the only bind-mounts are host-side
    jailer-chroot plumbing the guest never sees as files. This is FM-5's existing
    mount fence (`extracted/channel.rs`), not a new one.
  - **`/etc/nucleus/*` (excluded).** The legacy secret files (`auth.secret`,
    `approval.secret`) are written only under a `--legacy-secrets` build flag no
    shipping path passes; `pod.yaml` is cred-split (no credential *values*); the
    one runtime-written private key is mode-0600 and folds into the uid fence
    below.
  - **`/proc/<pid>/environ` (gap B — now closed).** The runtime holds every
    per-pod secret in its own environment, and a same-uid workload reads it via
    `/proc`. The uid fence was wired only under credentialed egress, so a
    no-egress, no-uid pod ran the workload as the runtime's uid and was exposed.
    Every workload now runs as a distinct unprivileged uid, never the runtime's
    (`workload.rs`, `DEFAULT_WORKLOAD_UID`).
  - **The `_ => OrdinaryData` classifier fallthrough (gap D — now closed).** An
    unrecognised `NUCLEUS_*` name fell through to Public and was delivered, and
    the dual-classifier corpus test could not catch it (both classifiers share
    that default). Any unclassified reserved-namespace key is now refused at
    admission (`workload.rs`, `PUBLIC_RESERVED`).

  C1's **relation leg** is the Lean noninterference; its **conformance leg** —
  that the shipping runtime actually withholds — is TESTED and gated by
  `scripts/check-c1-inbound-fences.sh` (reverting fence B or D reds it). That
  conformance leg is bounded by C7 ("a theorem about the code that ships"),
  itself TESTED, so the row records the proven relation with the runtime
  conformance gated beside it — the same shape as C4.
- **C2 (NOT-YET)** — no artifact in the corpus mentions a second pod; the host
  is outside every model. `docs/cross-pod-view.md` is the design.
- **C3 (PROVED)** — the two-run noninterference theorem over the reference pod
  machine, whose step relation calls the extracted delivery oracle. Scope is
  honest: a coarse monitor LTS with an opaque workload, labelled Phase 0.
- **C4 (TESTED — promoted from NOT-YET 2026-08-10; held one notch below PROVED
  while the live-release e2e is boot-gated).**
  The clause names a specific live mechanism: a governor release via *a single-use
  token*. Both legs now hold on the graph the shipping egress verdict reads — but
  because the release's *shipping-path conformance* is a boot-gated end-to-end
  (proven mechanism + unit-level flip over the real `FlowGraph` type + endpoint
  wiring verified by inspection, not yet a running-pod HTTP e2e), the honest row
  status is TESTED, not PROVED. It returns to PROVED when a `boot-a-real-pod` e2e
  shows a `POST /v1/declassify` token flipping a live verdict for the committed
  value and denying a substituted one.
  * **Single-use, PROVED.** The absorbing `declass_step` machine (`no_second_apply`,
    `single_use`) over the Aeneas-extracted decision core, enforced by the shared
    one-shot burn ledger (`FlowGraph::release_burn_ledger`) and exercised at the
    kernel API by `crates/portcullis/tests/kernel_token.rs` (mint → apply →
    second-apply refused; a refusal never burns).
  * **Live on the graph egress reads, PROVED-mechanism / TESTED-conformance.** The
    demotion reason was that the proven token fired nowhere: `apply_declassification_token`
    recorded its scope on the kernel's own `flow_graph`, which no request path
    populated, so `POST /v1/declassify` returned `NodeNotFound` and the *actually*
    live release was the unproven k-of-n memory path. That inversion is closed. The
    apply is re-homed (`apply_declassification_token_on(&mut graph, token)`, #2235):
    the endpoint (`nucleus-tool-proxy/src/declassify.rs`) locks `state.flow_graph`
    — the graph egress reads — and lands the scope there, and egress honors per-node
    scopes fail-closed. So a single-use token now **flips the egress verdict
    Deny→Pass for exactly the committed value at exactly its signed sinks**, proven
    on one graph by `crates/portcullis/tests/declassify_rehome_egress.rs#c4_flip_back_on_one_graph`,
    with a boundary matrix that denies a substituted value (`ContentMismatch`), an
    unsigned sink, a replay, a second secret node, and poison. The k-of-n mint now
    feeds the *same* value-bound, sink-scoped, one-shot `DeclassScope` on that graph
    (#2234), so there is one enforcement and two mint policies, not a proven-but-dead
    path beside an unproven-but-live one.

  **Honest caveat — which leg is TESTED.** The proven single-use/sink-scope theorems
  and the value-bound apply→egress flip are exercised at the **unit level over the
  real `FlowGraph` type** (the same type and API the endpoint uses), and the endpoint
  wiring (`apply_declassification_token_on` on `state.flow_graph`) is asserted by
  inspection in `scripts/check-declassify-value-bound.sh`. The full
  **HTTP-`POST /v1/declassify`-against-a-running-pod e2e** — a real governor request
  flipping a real tool-proxy egress verdict — is **boot-gated** (`boot-a-real-pod`,
  requires `/dev/kvm`) and is the conformance leg, the same shape as C1's runtime
  conformance. The falsifier `scripts/check-declassify-value-bound.sh` reds if the
  value-binding is neutered OR the endpoint is re-pointed at the orphan kernel graph
  (the exact #2235 regression), so the dead-mechanism inversion cannot return silently.
- **C5 (PROVED — re-promoted 2026-08-10; had been demoted 2026-08-08).** The clause
  is about the VALUE axis: an adversary controlling the inputs cannot steer *which*
  value a governor release yields. This is now both **enforced** and **proven
  relationally**, closing the sink-axis-only overclaim that demoted it (the old
  citation `sink_outside_a_singleton_mask_denied` proves *where* data goes, not
  *which value* is released).
  * **Enforced (value-binding at apply).** The token carries a signed
    `content_commitment: [u8; 32]` (SHA-256 of the exact authorized bytes, bound
    into `canonical_bytes` at `canonical-v3`). Apply releases **only** for a node
    whose monitor-recomputed ingest `content_hash` **equals** that commitment
    (`FlowGraph::value_binding_ok`); a substituted value, an unbound (`[0u8;32]`)
    commitment, or a node with no recorded hash is refused `ContentMismatch` —
    fail-closed and **non-burning** (the token stays usable). The content hash is
    a monitor-recorded fact (`observe_with_content_hash`, SHA-256 recomputed at
    ingest, never an agent field), so the adversary cannot forge the equality.
  * **Proven relationally (four-run robustness).** `four_run_value_robustness`
    (`DeclassifySinkScopeExtracted.lean`) states that over the 2×2 grid of
    attacker-controlled recorded content against one governor commitment, every run
    releases **exactly the committed value or denies** — no attacker input releases
    any other value. Sorry-free; `#print axioms = {propext}`. This is the value axis
    of robust / non-malleable declassification (Sabelfeld–Sands; Cecchetti et al.,
    CCS'17), which nucleus can reach because the proxy mediates every egress.

  **Honest abstraction — the u64-tag / 32-byte nuance.** The extracted decision core
  the theorem is stated over (`value_authorized`, in `EXTRACT_ROOTS`) models value
  identity as a **u64 tag** and decides on **tag equality**. The runtime compares the
  full **32-byte `ContentHash`**. The two are bound by the parity test
  `crates/portcullis/tests/declassify_scope.rs#authorize_release_value_binding_matches_the_extracted_decision`
  (equal bytes ⇔ equal tag; unequal ⇔ deny), so the relational theorem transfers to
  the byte-level runtime decision **by tested parity**, not by a proof over 32-byte
  arrays. That is the one gap between the proof and the shipped comparison, and it is
  gated: the falsifier `scripts/check-declassify-value-bound.sh` runs both the
  four-run test and the parity test, and reds if value-binding stops refusing a
  substituted value.
- **C6 (TESTED — promoted from NOT-YET 2026-08-11; complete-mediation Phases 1–3).** Five
  legs now hold. (a) *Tier-A total mediation is a theorem:* over the closed
  `SinkClass`/`Operation` enum, `no_sink_reachable_without_discharge`
  (`MediationScopeExtracted.lean`, Aeneas-extracted, `sorry`-free, axioms ⊆
  `[propext, Classical.choice, Quot.sound]`) proves no consequential sink is
  reachable from idle without discharging an `Authority`; a new sink forces a
  match arm (#2241). (b) *The effect boundary is enforced, not advisory:* the
  `mediated` dylint pass runs enforcing-at-zero over the sealed effect home
  `portcullis-effects` — counted by report count, not exit status, with a
  reds-on-revert self-test (`scripts/check-mediation-dylint.sh`, #2244). (c)
  *The transport/egress surface now has a unified, gated inventory:*
  `docs/architecture/mediated-set.md` enumerates every outbound channel against
  the closed `EgressChannel` enum, and `documented_inventory_equals_the_enum`
  reds if the table and enum disagree on the key set or a channel's status
  (Phase 0). The three Tier-B surfaces that kept this NOT-YET are now closed:
  (d) *Phase 2* — the netns default-deny backstop for in-shell / raw-socket egress
  (channels 5, 10) is **proven applied on boot** by the in-guest egress probe
  (`scripts/check-egress-probe.sh`, x86_64 boot gate: an off-allowlist connect
  from inside the live guest returns `ENETUNREACH`; #2246); (e) *Phase 3* — the
  `effects()` escape hatch (channel 12, #1248) is closed (`unmediated_effects`
  requires an opt-in token + strictest-sink discharge + `FlowTracker` observe,
  fail-closed tested), and the `partial` transport channels (7, 8) rest on tested
  structural refusals (host-CID pin `only_the_host_cid_is_accepted`, broker refusal
  by absence). The inventory now carries **no open hole** —
  `no_channel_is_an_open_hole` asserts it, the machine meaning of "every".
  **TESTED, not PROVED:** "every" here is a *union* of tested properties plus one
  theorem, not a single proof. The Tier-A theorem covers only the effect-API
  surface (channels 1–4); the in-shell/raw-socket backstop (5, 10) rests on
  "iptables applies the rules", which is TESTED-on-boot with the kernel in the TCB,
  not proven; the partial transport channels (7, 8) rest on tested structural
  refusals; and channel 12's audit-DAG granularity is coarse (one node per grant).
  The falsifier is `scripts/check-egress-probe.sh` — it reds if the live-path
  backstop stops confining egress; `no_channel_is_an_open_hole` reds if any channel
  regresses to an open hole. Re-earning toward PROVED would need the network
  backstop proven (not tested) applied and the theorem extended past the API
  surface.
- **C7 (TESTED — unchanged 2026-08-10; the declassify gap narrowed but C7 is
  broader).** The theorems are about a scalar-only extracted restatement of the
  enforcement predicates, re-extracted from the current Rust on every proof-workflow
  run and bound to production by exhaustive parity tests and the boot-gate
  conformance replay. The declassification arc (#2227–#2236) *narrowed* this gap for
  its own slice — the declassify decision core (`value_authorized`) is now in
  `EXTRACT_ROOTS`, so the proofs describe the graph the live egress actually reads,
  and the u64-tag↔32-byte binding is parity-tested — but that does not promote C7,
  which is the broader whole-slice↔shipped-code correspondence. The surrounding
  kernel, classifier, and spawn path are still covered by tests and lints, not by
  the theorem; and even the declassify slice's byte-level runtime comparison
  transfers to the proof by *tested* parity, not by proof. C7 stays TESTED.
- **C8 (TESTED — promoted from NOT-YET 2026-08-11).** Two gaps closed. (a) The
  proof workflow's trigger was an *allowlist* of the extracted Lean files that
  missed the production types the parity tests bind against (`IFCLabel`,
  `SinkClass`, `ConfLevel` in `ifc_ops.rs`/`lib.rs`); it now triggers on the
  whole `crates/nucleus-ifc-kernel/**` domain (derived, not enumerated), so a
  change to the enforcement the theorems mirror re-extracts + re-parity-tests +
  re-proves. (b) Nothing checked that the extracted predicates are still *wired*
  into the live path — a theorem about a function nobody calls is a proof about
  dead code. `scripts/check-extracted-callsites.sh` (required, runs every PR via
  `ci.yml`) now asserts each manifest-covered predicate has a live production
  call site (production region, test blocks excluded); it reds if the call site
  is deleted. Every extracted family is accounted for (a call-site audit confirmed
  none is proven-but-silently-unwired): the **wired** ones carry a live anchor —
  identity delivery (`ident_may_deliver`, a direct call to the extracted
  predicate), mediation (`classify_sink` for `sinkcode`, and `authorizes` — the
  effect-gate `require_scope` — for `scope_admits`), declassify
  (`authorize_release`), egress (`egress_chain`), and the capability lattice
  (`CapabilityLevel`'s ordering, used live in the trifecta classifier for
  `capleq`); the genuinely **structural** ones carry their construction anchor —
  `channel_admits` (C1's no-secret-channel / distinct-uid fence) and
  `cred_may_deliver` (the broker builds its store from the node env, never the
  guest spec, so a Secret credential never reaches the Guest sink by
  construction). **Ceiling:** these two are proof-only *by design* — there is no
  runtime predicate call to check, so the gate anchors the construction instead;
  and the base flows-to relations (`iflows_to`/`cflows_to`) are exercised
  transitively by the decision predicates. TESTED, not PROVED: the correspondence
  is a build-system + grep-gate check, not a proof.
- **C9 (NOT-YET — demoted 2026-08-08, was TESTED).** The external-verification
  leg is not wired end to end, so a relying party CANNOT yet verify from the
  outside. Concretely: `FETCH_SVID` serves a plain certificate
  (`manager.fetch_certificate` → `sign_csr`) with **no** DICE attestation
  extension; the only producer that would embed measurements,
  `fetch_attested_certificate`, is `#[allow(dead_code)]` and, at its single call
  site, its success value is **discarded** (only the error arm is handled), and
  no CA implements `sign_attested_csr` — every backend falls through to plain
  `sign_csr`. So no served cert carries a measurement. On the consumer side,
  `AttestationRequirements::verify` / `LaunchAttestation::from_der` have no
  production caller, so no shipped relying party extracts and checks a launch
  attestation. What DOES exist and is real: `admit_posture` verifies a claimed
  `posture@digest` against a self-measured rootfs digest, fail-closed and
  perturbation-tested (`admit_posture_one_byte_of_drift_reds_the_gate`) — but it
  is the pod's own self-characterization at admission, not outside verification,
  and it is inert unless a pod carries a `dlc_posture` label (no shipped spec or
  the CI probe emits one, so the boot gate never exercises it — which is also
  why the former `quickstart-boot.yml` falsifier could not red on a regression).
  Re-earning C9 needs: embed the measurement on the served SVID (implement
  `sign_attested_csr`, stop discarding the attested cert), a shipped
  relying-party verifier that checks it, and signed provenance binding the
  artifact digest to the theorem set.

The cross-pod leg is the open one, and it is deliberately sequenced audit-first:
a lookup keyed on something a guest can forge is a far likelier defect than a
flaw in the label lattice, and a real finding there is worth more than a theorem.
Per-caller identity at the node API is the enabling step — until the node can
tell *which* pod is calling, no cross-pod property is even statable, because the
system cannot assign a secret to a pod any more than the model can.

### Theoretical Foundation

This claim rests on the **capability safety theorem**: in an object-capability
(ocap) system, authority propagates only through explicit capability references.
If the enforcement boundary is capability-safe, no code inside it can acquire
authority it was not granted. This connects Nucleus to a 40-year lineage
(E language, KeyKOS, seL4, Capsicum) and is the formal basis for "prove the
boundary, not the model."

## Three Pillars

### Pillar A — Math That Survives (Kernel Semantics)

The math core is small and sharp:

1. **Capability lattice** (authority) — 12-dimensional product lattice with
   3-level capability states (Never/LowRisk/Always). Compare, combine, restrict
   permissions algebraically.

2. **Exposure lattice** (trust) — 3-bool semilattice tracking `private_data`,
   `untrusted_content`, and `exfil_vector`. When all three co-occur (uninhabitable state),
   the operation requires explicit approval. Exposure is monotone: it never
   decreases.

3. **Trace semantics** (time) — ordered record of actions, authority, and exposure
   at each step. Free monoid with homomorphic exposure accumulation.

4. **Monotonicity** (ratchet) — authority can only stay the same or tighten
   **under the workload's own action**. Budget can only decrease. Exposure can
   only increase. The nucleus operator ν is idempotent and deflationary.
   The one widening is `POST /v1/escalate`, and it is not the workload's to
   take: it requires a separate approver's authority (mTLS identity + a valid
   trace chain), and the granted authority is intersected with the delegation
   ceiling (`cert_bridge.rs`, `effective.leq(verified.effective)`), so it can
   never exceed what was delegated. So the flagship's "can only tighten" holds
   for the agent (the corollary "no talking your way into more permissions
   mid-run" is exact), and an approver-authorized widening stays bounded by the
   ceiling — it is a move within the lattice, not above it.

Key design choice: **prove properties about the enforcement boundary**, not
about LLM behavior. The agent is a black box. The kernel is the TCB.

**Current state:** 113 Kani harnesses + ~277 Lean 4 theorems verify the security
core in CI, covering lattice laws, uninhabitable state operator, Heyting algebra,
modal operators (S4), exposure monoid, graded monad laws, Galois connections,
fail-closed auth boundary, capability coverage theorem, budget monotonicity, and
delegation ceiling theorem. (Verus was evaluated and removed; verification
consolidated on Lean 4 + Kani — see the README verification table.) Phase 0-2
partially complete.

### Pillar B — Formal Methods as a Product Feature

Proofs are first-class artifacts, not academic exercises:

- **Kani bounded model checking** — 113 machine-checked harnesses over the Rust
  kernel's decision logic; complete over the finite lattice state space. CI-gated
  via `kani-nightly.yml`.
- **Lean 4 model** — ~277 kernel-checked theorems for the security core (capability
  Heyting algebra, IFC semilattice, taint monotonicity, exposure monoid,
  delegation); the Aeneas pipeline mechanically translates the core capability
  types from Rust to Lean so proofs run over generated code. CI-gated via
  `lean-build.yml` / `aeneas-ifc-scoped.yml`.
- **Differential testing** (planned) — Cedar pattern: millions of random inputs
  compared between Rust engine and Lean model.
- **Public Verified Claims page** — each claim maps to a proof artifact and
  code commit.
- **Continuous verification gates** — CI fails if a change violates a proven
  invariant. No regression path.

### Pillar C — Dead-Simple Developer Usability

A developer can get value in under 10 minutes. No lattice theory required.

- Install with `pip` (Python SDK) or `cargo` (Rust SDK)
- Run `nucleus audit` for immediate CI integration
- Wrap a workflow in a "safe session" with 10 lines of code
- Choose from built-in profiles, never think about lattices

## Product Surface

One mental model across all entry points, with value at every tier:

### Tier 0: `nucleus audit`

Fast value, no runtime required:

- Scan repo settings, MCP configs, agent configurations
- Emit PR comments / SARIF
- Generate a minimal safe profile + allowlist snippet
- **PLG funnel entry**: teams adopt this before committing to a runtime

### Tier 0.5: `nucleus observe`

Bridge from "I don't know what my agent does" to "here's a tight profile":

- Run alongside an existing agent, record all tool calls and side effects
- Suggest a minimal capability lattice policy based on observed behavior
- Output is formal (a lattice policy), not statistical (a behavioral baseline)
- **Differentiator from ARMO**: prescriptive output, not behavioral baseline

### Tier 1: `nucleus run --local`

Immediate felt safety:

- All side effects go through a local proxy
- No direct agent access except via the mediated gateway
- Approval prompts for risky actions (uninhabitable state triggers)
- Same policy language as Tier 2

### Tier 2: `nucleus run --vm`

Hard containment:

- Firecracker microVM boundary (Firecracker-based isolation)
- Default-deny egress, allowlisted DNS/hosts
- gRPC tool proxy inside the VM, SPIFFE workload identity
- Same policy language, same traces, same proofs
- **Target: <500ms cold start** via pre-warmed VM pools

Dev usability does not wait for Tier 2. But Tier 2 is the "serious people"
finish line.

### MCP Mediation (cross-tier)

MCP is the de facto agent-tool protocol. Nucleus is an MCP-aware mediator:

- Interposes on MCP tool calls, applies capability checks, records traces
- `nucleus run` accepts MCP server configs and proxies them through the policy
  engine
- Any MCP client gets enforcement for free — no SDK adoption required
- **Current state:** `nucleus-mcp` crate provides Claude Code ↔ tool-proxy
  bridging. Extend to general MCP mediation.

## The Python SDK

The "Hello World" experience should feel like `requests` + `pathlib`, not
like configuring SELinux.

### SDK Principles

- A developer should never need to think about lattices
- Unsafe actions are impossible to express without explicit approval steps
- Audit traces are produced automatically
- Intent-based API maps to built-in profiles

### Example

```python
from nucleus import Session, approve
from nucleus.tools import fs, net, git

with Session(profile="safe_pr_fixer") as s:
    readme = fs.read("README.md")           # ok
    fs.write("README.md", readme + "\n")    # ok (scoped)

    # risky: outbound fetch — explicit gate
    page = approve("fetch", net.fetch, "https://example.com")

    # forbidden: publish
    git.push("origin", "main")              # raises PolicyDenied
```

### SDK Ships With

- **Profiles**: `safe_pr_fixer`, `doc_editor`, `test_runner`, `triage_bot`,
  `code_review`, `codegen`, `release`, `research_web`, `read_only`, `local_dev`
- **Typed handles**: `FileHandle`, `NetResponse`, `CommandOutput` that carry
  exposure metadata
- **Exceptions**: `PolicyDenied`, `ApprovalRequired`, `BudgetExceeded`,
  `StateBlocked`
- **Trace export**: `session.trace.export_jsonl()`

**Current state (March 2026):** Draft Python SDK at `sdk/python/` with
intent-first API, mTLS/SPIFFE auth, and tool wrappers for fs/git/net.
Functional for direct tool-proxy connections.

## The Kernel Boundary

**The agent process must not have ambient authority.**

No direct egress. No direct filesystem beyond what is mediated. No token leaks.

The kernel is the only place where:

- Decisions are made (capability check)
- Approvals are validated (uninhabitable state gate)
- Traces are recorded (audit log)
- Exposure is tracked (monotone accumulation)

This is what makes formal verification tractable: the TCB is small (~10-15K
LOC of verified Rust), and every path through it either enforces the lattice
or panics. No fail-open. No silent degradation.

```
┌─────────────────────────────────────────────────────┐
│  Verified Core (Lean 4 + Kani)      ~10-15K LOC     │
│  ├── portcullis lattice engine     113 Kani proofs  │
│  ├── exposure guard + uninhabitable state        proven monotone  │
│  ├── permission enforcement        fail-closed      │
│  └── sandbox boundary              proven panics    │
├─────────────────────────────────────────────────────┤
│  Formal Model (Lean 4, hand-written) partial         │
│  ├── CapabilityLevel HeytingAlgebra Lean 4 proofs   │
│  ├── Aeneas pipeline (core types)  in progress      │
│  └── graded monad laws             planned          │
├─────────────────────────────────────────────────────┤
│  Differential Testing              planned          │
│  ├── Rust engine vs Lean model     cargo fuzz       │
│  └── Lean/Kani proof ratchet       CI-gated         │
├─────────────────────────────────────────────────────┤
│  Runtime (standard Rust)           ~70K LOC         │
│  ├── gRPC, tokio, tonic            Kani checks      │
│  ├── Firecracker + SPIFFE          integration      │
│  └── Tool proxy, audit, MCP        proptest         │
└─────────────────────────────────────────────────────┘
```

## Competitive Positioning

```
                    Formal Guarantees
                         ▲
                         │
                         │  ★ Nucleus (target)
                         │
    Papers ●             │
    (no product)         │
                         │
         AgentSpec ●     │
                         │
    ─────────────────────┼──────────────────► Dev Usability
                         │
              ARMO ●     │         E2B ●
                         │     Daytona ●
              CodeGate ● │  microsandbox ●
                         │
```

### Why Not X?

| Alternative | What it does | What it lacks |
|---|---|---|
| **E2B / Daytona / microsandbox** | Run code in Firecracker/Docker | No policy, no capability model, no exposure, no proofs. Ambient authority inside the box. |
| **AgentSpec** (ICSE 2026) | DSL for runtime rule enforcement | Ad-hoc rules, not lattice-based. No monotonicity guarantee. Rules are LLM-generated (95% precision — 5% are wrong). |
| **ARMO** | eBPF observe → baseline → enforce | Behavioral, not prescriptive. Must allow bad behavior before blocking it. No formal guarantees. |
| **Google Agent Sandbox** (GKE) | Pre-warmed VM pools, fast launch | Infrastructure-level only. No policy language, no exposure, no proofs. |
| **CodeGate** | Firecracker + locked pip installs | Single-purpose (supply chain). No general policy engine. |

**Nucleus's five differentiators:**

1. **Capability lattice with monotonicity proof** — authority is a
   mathematical ratchet, not a config file.
2. **Exposure tracking with uninhabitable state gate** — information flow control that
   blocks exfiltration by construction.
3. **"Prove the boundary, not the model"** — verify the enforcement kernel
   (tractable, seL4-style), not LLM behavior (impossible).
4. **Tiered value delivery** — `nucleus audit` gives value before any runtime
   commitment. Audit-first PLG funnel.
5. **Vendor-agnostic by design** — self-hosted runtime any orchestrator can
   target. No cloud lock-in.

### What to Learn From the Field

- **E2B's SDK ergonomics** — `pip install` + 3 lines = sandbox. Match this
  simplicity.
- **ARMO's progressive enforcement** — the observe → baseline → enforce UX is
  excellent for teams that don't know what policy to write. `nucleus observe`
  adopts this pattern but outputs formal policies, not behavioral baselines.
- **microsandbox's MCP integration** — MCP-native runtime is table-stakes.
  Nucleus must be an MCP-aware mediator.
- **AgentSpec's DSL readability** — trigger/predicate/action patterns are
  ergonomic. Policy authoring should be at least as readable.
- **Google's pre-warmed pools** — sub-second cold start is an infrastructure
  requirement for Tier 2.

## Formal Methods Ladder

Each rung is shippable independently.

### Rung 1 — Kani + Lean Proofs (in progress)

- 113 Kani harnesses + ~277 Lean theorems verified in CI (minimum gate)
- Covers: lattice laws, uninhabitable state operator, Heyting algebra, S4 modal
  operators, exposure monoid, graded monad laws, Galois connections, fail-closed
  auth, capability coverage, budget monotonicity, delegation ceiling
- **Key finding from proofs**: nucleus operator ν is NOT monotone (proven
  counterexample — uninhabitable state fires for y but not x). This was discovered by
  the proofs, not by tests. The proofs are working.

### Rung 2 — Lean 4 Model (partial)

- **Done**: hand-written kernel-checked proof of `CapabilityLevel` as a
  `HeytingAlgebra` (Mathlib-linked, 27-case `decide`). Discriminant
  correspondence enforced by `lean_tonat_matches_rust_discriminants` CI test.
  Kani R1/R2/R3 harnesses bridge the Lean proofs to bounded model checking.
- **Planned**: Aeneas/Charon pipeline translation (Rust MIR → LLBC → Lean)
  for the full portcullis crate; Mathlib links for broader algebraic structures;
  graded monad laws in Lean 4.

### Rung 3 — Differential Testing (planned, Phase 3)

- Cedar pattern: Rust engine vs Lean model on millions of random inputs
- Catches: serialization boundaries, encoding issues, discrepancies between
  verified model and production code
- CI-gated: every PR checked against the formal model

### Rung 4 — Extended TCB Verification (planned, Phase 4)

- Sandbox boundary, credential handling, tool proxy
- Kani bounded model checking for arithmetic paths
- Goal: full TCB machine-checked end to end

### Rung 5 — TCB Minimization

The moonshot is not "prove all the code." The moonshot is: **make the proven
kernel tiny enough that proving it is realistic.** This is how seL4 thinking
wins: reduce the surface you must trust.

## Supply Chain Integrity (Exposure Tracking Use Case)

The exposure lattice has a concrete day-one demo: supply chain safety.

- Package installs from untrusted registries carry `untrusted_content` exposure
- Exposed dependencies cannot reach sinks (network, filesystem writes) without
  explicit approval
- Combined with `exfil_vector` exposure on git push / network egress, the
  uninhabitable state gate blocks dependency-confusion attacks by construction
- This is what CodeGate does with a bespoke tool. Nucleus does it as a natural
  consequence of the exposure lattice.

## Success Criteria

### Dev Adoption

- A team gets value in **< 10 minutes**
- `pip install nucleus` + `nucleus audit` produces:
  - a clear pass/fail in CI
  - a minimal safe profile suggestion
  - an MCP allowlist snippet
- `nucleus observe` generates a first-pass policy from 30 minutes of agent
  observation

### Security

- "No direct agent calls except via proxy" is enforceable and demonstrable
- Traces are replayable and tamper-evident enough for incident review
- A red-team attempt produces a **PolicyDenied** or an approval request — not
  a leak

### Formal Methods

- Public "Verified Claims" matrix:
  - Claim → Proof artifact → Code hash
- CI fails if a change violates the proven model
- Proof count (Kani harnesses + Lean theorems) is monotonically non-decreasing (ratchet)

### Performance

- Tier 2 cold start: <500ms with pre-warmed pools
- Policy evaluation overhead: <1ms per decision
- Exposure tracking overhead: negligible (3-bool join)

## Iteration Plan

PR-sized increments that ship value while converging on the moonshot:

| PR | Scope | Ships |
|---|---|---|
| PR0 | North Star + Verified Claims doc | This document, claims table, threat model |
| PR1 | Python SDK skeleton | `Session`, exceptions, trace export, local proxy wiring |
| PR2 | Policy schema + canonical profiles | Tiny stable policy surface, "break the uninhabitable state" defaults |
| PR3 | Minimal kernel decision engine | Complete mediation for file/net/exec/publish, monotone session state |
| PR4 | Exposure plumbing | Exposure on handles, exposed-to-sink gating + approval |
| PR5 | Executable spec + model checking | Lock semantics early, prevent drift |
| PR6 | Proofs of the core invariants | Monotonicity + source-sink safety |
| PR7 | `nucleus observe` | Progressive discovery mode, formal policy output |
| PR8 | MCP mediation layer | General MCP interposition, not just Claude Code bridging |
| PR9 | VM mode hardening | Shrink ambient authority further, pre-warmed pools, <500ms target |
| PR10 | Attenuation tokens | Delegation that can only reduce power, "no escalation" cryptographically natural |

## The North Star Sentence

> **Nucleus is a runtime that makes it impossible for an agent to do something
> dangerous unless you explicitly gave it the power — and that boundary is small
> enough to prove.**

Others sandbox the agent. Nucleus proves the sandbox holds.

## Why Rust

Rust is the only language that satisfies all four requirements simultaneously:

1. **Near-C performance** — zero-cost abstractions, no GC, deterministic
   latency inside Firecracker microVMs
2. **Modern type system** — algebraic data types, pattern matching, traits,
   async/await, package ecosystem
3. **Formal verification** — Verus (SMT-based, SOSP 2025 Best Paper),
   Aeneas (Rust → Lean 4), Kani (bounded model checking), hax (Rust → F*)
4. **Safety certification** — Ferrocene qualified at ISO 26262 ASIL-D,
   IEC 61508 SIL 4, IEC 62304 Class C

## Precedents

- **AWS Nitro Isolation Engine** — formally verified Rust hypervisor (Verus +
  Isabelle/HOL). Deployed at AWS scale on Graviton5.
- **Atmosphere microkernel** (SOSP 2025 Best Paper) — L4-class microkernel
  verified with Verus. 7.5:1 proof-to-code ratio.
- **AWS Cedar** — formally verified authorization engine. Rust + Lean +
  differential testing. 1B auth/sec. Our architectural template.
- **libcrux** — formally verified post-quantum crypto in Rust via hax → F*.
  Shipping in Firefox.
- **AutoVerus** (OOPSLA 2025) — LLM agents auto-generate Verus proofs.
  137/150 tasks proven, >90% automation rate.

## References

- [Verus: Verified Rust for Systems Code](https://verus-lang.github.io/verus/)
- [Atmosphere: SOSP 2025 Best Paper](https://dl.acm.org/doi/10.1145/3731569.3764821)
- [AutoVerus: OOPSLA 2025](https://arxiv.org/abs/2409.13082)
- [AWS Nitro Isolation Engine](https://www.antstack.com/talks/reinvent25/aws-reinvent-2025---introducing-nitro-isolation-engine-transparency-through-mathematics-cmp359/)
- [AWS Cedar Formal Verification](https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing)
- [Aeneas: Rust → Lean 4](https://aeneasverif.github.io/)
- [Ferrocene Qualified Rust Compiler](https://ferrocene.dev/)
- [libcrux: Verified Crypto via hax](https://github.com/cryspen/libcrux)
- [Systems Security Foundations for Agentic Computing](https://arxiv.org/abs/2512.01295)
- [AgentSpec: ICSE 2026](https://arxiv.org/abs/2503.18666)
- [Agent Behavioral Contracts](https://arxiv.org/html/2602.22302)
