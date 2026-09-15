# A unified command grammar for nucleus

Draft, 2026-09-15. One many-sorted signature covering the node's HTTP API, the
guest's vsock workload API, and the CLI's artifact operations — specified
tightly enough that a random walk can compute the enabled set from its own model
and use the *disabled* set as an oracle.

Companion to [`build-ops-algebra.md`](build-ops-algebra.md), which does the same
job for the gatehouse build lane. That document's sorts (`Spec`, `Tree`,
`Scratch`, `Prog`) are imported here unchanged; this one adds the pod, the
guest, and the artifact.

## Why algebraic and not pre/post

Pre/post conditions specify each operation against a hidden state you have to
describe to state them. Equations specify *compositions* — `cancel ; cancel =
cancel` needs no account of what a pod record looks like. The argument that
equations are the better fit for generic APIs is
[Meyer's](https://dl.acm.org/doi/10.1145/2692956.2663183); the reason it matters
here is narrower. Nucleus's headline claim is a statement about compositions:
*no host conclusion depends on anything a guest said*. That is not a
postcondition of any one operation. It is an equation over sequences (A6 below),
and it is only expressible in a grammar that has sequencing in it.

So: three judgments per operation — a precondition `pre`, an effect `eff` on an
abstract state, an observation `obs` — plus a separate layer of equations that
quantify over sequences. The first three drive the walk. The equations are what
the walk is *for*.

## Carriers

The signature is many-sorted, and the sorts matter because they decompose the
walk. Three carriers, one bridge:

```
Pod      -- the node's live state: pods, their lineage, their served capabilities
Artifact -- receipts, envelopes, lineage chains, bundles, manifests: bytes on disk
Build    -- Spec x Tree x Scratch, imported from build-ops-algebra.md
```

`Artifact` operations never read or write `Pod`. `Pod` operations never read
`Artifact` except through the bridge. The bridge is exactly three operations —
`run`, `receipt`, `ship` — and everything else factors. A walker may therefore
run two independent sub-walks and only needs the product walk across the bridge,
which is where the interesting failures are and where the budget should go.

### Principals

Every operation is indexed by who issues it. This is not decoration; `pre`
reads it.

```
Principal := Anon | Operator(scope) | Pod(id) | Guest(pod) | Node
```

`Guest(p)` is the principal inside pod `p` speaking over vsock. It is distinct
from `Pod(p)`, the principal that authenticated to the node's HTTP API as pod
`p`, because their authorities differ and the difference is the architecture:
`Guest` says things, `Pod` proves them.

## Abstract state

The walker maintains this and nothing else. It must be small enough to carry
exactly, and complete enough to decide every `pre`. It is both.

```
Sigma = { pods : PodId -> PodRec, node : NodeRec }

PodRec = {
  parent   : Option<PodId>,
  phase    : Booting | Running | Exited(Option<i32>) | Errored | Cancelled,
  prog     : ProgramId,          -- digest of the IN-projection of the spec
  served   : Set<VsockOp>,       -- the one-shot ledger
  barrier  : Bool,               -- SNAPSHOT_READY announced
  mount    : NeverMounted | Mounted | Unknown,
  bootargs : PerPod | Shared,
}
```

Two derived predicates do most of the work, and both already exist in the code:

```
may_manage(c, p)  =  c = None  or  parent(p) = Some c  or  p = c
personalized(p)   =  exists v in served(p) . personalizes_the_vm(v)
```

`may_manage` is `pod_api::caller_may_manage` — direct children and self, not the
transitive closure. `personalizes_the_vm` is the exhaustive match in
`workload_api_protocol.rs`, which the compiler already forces to classify every
new command. **The grammar does not introduce a new classification; it consumes
the one the build already refuses to let drift.** A new vsock command cannot be
added without answering the question the walker's model reads.

## Signature: the Pod carrier

Node HTTP surface. `p!` marks a subject that must exist.

```
create  : Principal x PodSpec              -> PodId + Refusal
list    : Principal                        -> [PodInfo]
cancel  : Principal x p!                   -> Ack + Refusal
logs    : Principal x p!                   -> Bytes + Refusal
result  : Principal x p!                   -> WorkloadResult + Refusal
receipt : Principal x p!                   -> Receipt + Refusal        (bridge)
stdout  : Principal x p!                   -> Bytes + Refusal
stderr  : Principal x p!                   -> Bytes + Refusal
snapshot: Principal x p!                   -> Base + Refusal
health  : Principal                        -> Ok
oidc    : Principal x Token                -> Assertion + Refusal
```

Guest vsock surface. Every one is issued by `Guest(p)` and by nobody else; the
socket is per-pod and the host knows which pod it belongs to without being told.

```
ping     : Guest(p)                        -> Pong
bundle   : Guest(p)                        -> TrustBundle
pod_list : Guest(p)                        -> [PodInfo]
svid     : Guest(p)                        -> Svid
task_tok : Guest(p)                        -> Token
dlc      : Guest(p)                        -> Admission
pod_cert : Guest(p)                        -> Cert
caller   : Guest(p)                        -> Token
pod_spec : Guest(p)                        -> PodSpec
broker   : Guest(p)                        -> Secret + Refusal(Repeat)
audit    : Guest(p)                        -> Creds  + Refusal(Repeat)
mediate  : Guest(p)                        -> Key    + Refusal(Repeat)
ready    : Guest(p)                        -> Ack
ship     : Guest(p) x ReceiptBytes         -> Ack + Refusal            (bridge)
```

### Preconditions

```
pre(create, c, spec)    =  spec well-formed under deny_unknown_fields
                        /\ resources within node budget
pre(cancel, c, p)       =  may_manage(c, p) /\ phase(p) in {Booting, Running}
pre(logs|result|receipt
    |stdout|stderr, c,p)=  may_manage(c, p)
pre(list, c)            =  true                 -- result FILTERED by may_manage
pre(snapshot, c, p)     =  may_manage(c, p)
                        /\ barrier(p)
                        /\ not personalized(p)
                        /\ mount(p) = NeverMounted
                        /\ bootargs(p) = Shared
pre(v, Guest(p))        =  phase(p) = Running
                        /\ (one_shot(v) -> v not in served(p))
pre(ship, Guest(p), b)  =  phase(p) = Running /\ |b| <= RECEIPT_MAX
```

where `one_shot = {broker, audit, mediate}`.

Three things to notice, because each is a place the grammar disagrees with an
obvious guess:

* `pre(list)` is `true`. `list` is always enabled and the *answer* is scoped.
  That is a different testable claim from "refuse if unscoped", and the walker
  checks it as an observation (O2) rather than a refusal.
* `pre(snapshot)` is a conjunction of one host fact (`personalized`), one guest
  fact (`barrier`), and one measurement (`mount`). None is derivable from the
  others; the code asks all three for that reason. A walker that models only
  `barrier` will call `snapshot` enabled when it is not, and will report a false
  failure — so the model state carries all three or the walk is noise.
* `pre` for guest commands does not mention the principal's authority at all,
  because a guest has none to vary. What varies is *history* — the served
  ledger. The guest surface is a one-shot-ledger machine, not an authorization
  machine, and the grammar says so by which conjuncts appear.

### Effects

Only these change `Sigma`. Everything else is `eff = id`, which is itself the
claim O1 checks.

```
eff(create)        Sigma[pods += p |-> {parent = subject(c), phase = Booting, ...}]
eff(cancel, p)     Sigma[phase(p) := Cancelled] ; cascade over lineage(p)
eff(v, Guest(p))   Sigma[served(p) += v]
eff(ready, p)      Sigma[barrier(p) := true]
-- environment steps, not commands:
step_boot(p)       Sigma[phase(p) := Running]
step_exit(p, code) Sigma[phase(p) := Exited(code)]
step_fault(p, why) Sigma[phase(p) := Errored]
step_mount(p)      Sigma[mount(p) := Mounted]
```

The environment steps are the honest part. `Errored` and
`WorkloadResult::Unavailable` are **unreachable by any command sequence** — no
composition of the signature above produces them. A walk over commands alone
therefore leaves two states of the result lattice dead, and every refusal path
that branches on them untested. Either the walker gets a fault alphabet (kill
the VMM, truncate the scratch, stall the supervisor) or the grammar should admit
that those states are outside it. Naming them as environment steps rather than
omitting them keeps the reachability claim honest.

## Signature: the Artifact carrier

Closed under itself, and much simpler — which is why it is worth separating.

```
sign    : Payload x Key                    -> Envelope
verify  : Envelope x TrustBundle           -> Ok + Refusal(reason)
extend  : Chain x Entry                    -> Chain
vchain  : Chain                            -> Ok + Refusal(reason)
manifest: [Path]                           -> Manifest
attest  : Attestation x Registry           -> Ok + Refusal(reason)
replay  : Receipt x Bundle                 -> Verdict                 (bridge)
tamper  : Bytes x Index                    -> Bytes                   -- walker-only
```

`tamper` is not a shipped operation. It is in the signature because the
interesting equations about `verify` are equations *about* `tamper`, and a
grammar that cannot say "flip a byte" cannot state them.

## Equations

These are what the walk asserts. Each quantifies over sequences, and each is
checkable by comparing two executions or by an invariant maintained along one.

**A1 — reads do not move.** For every `r` in `{list, logs, result, receipt,
stdout, stderr, health, ping, bundle, pod_list}`: `eff(r) = id`. Checkable
along a single walk: the model predicts every subsequent answer unchanged, so
inserting any number of reads anywhere must not change any later observation.
The one exception is spelled out, not waived: `logs`, `stdout`, `stderr` are
monotone-growing on a pod in `phase = Running`, and *stable* once
`phase in {Exited, Cancelled, Errored}`. A walk asserts growth-monotonicity
before termination and byte equality after it.

**A2 — one-shot absorption.** For `v` in `{broker, audit, mediate}`:

```
v ; v  =  v ; Refusal(Repeat)
```

and, crucially, the second call returns a refusal *and no bytes*. A walk that
only checks "the second call errors" misses the failure that matters, which is a
refusal that still leaks the secret in a diagnostic. The observation is on the
response body, not the status.

**A3 — cancel is absorbing.** `cancel ; cancel = cancel`, and for every
state-advancing `x`, `cancel ; x = cancel ; Refusal`. Reads survive: `cancel ;
r = cancel ; r` for `r` in A1's set — a cancelled pod's logs and receipt remain
readable, which is the whole point of cancelling rather than deleting.

**A4 — identity is invariant under OUT, sensitive to IN.** Let `δ` be a
perturbation of one `PodSpec` field. Then

```
field in OUT  ->  prog(create(spec)) = prog(create(δ·spec))
field in IN   ->  prog(create(spec)) != prog(create(δ·spec))
```

```
OUT = { vsock, cgroup, audit_sink, credentials,
        metadata.name, metadata.task_grant_id }
IN  = { work_dir, timeout_seconds, policy, budget_model, resources, network,
        image, credentialed_egress, workload, seccomp,
        metadata.namespace, metadata.labels }
```

The `identity.rs` match is exhaustive, so this table cannot silently fall out of
date — but it can be *wrong*, and A4 is how a walk catches a field classified
OUT that changes the answer. Two entries are worth the walker's weight because
they are the ones a reader guesses wrong:

* `metadata.labels` is **IN**, though it reads like annotation. Two pods
  differing only in a label are different programs.
* `credentials` is **OUT**, though it reads like authority. What the pod may
  reach is named by `launch_hash` in the result, not by `prog`.

A4 must also be stated at the *leaf*, not the field. `policy` is IN, but the
`time` tag inside an inline lattice is OUT — that distinction is the
validity-window bug closed last week, and a field-level A4 would not have caught
it.

**A5 — personalization and snapshot do not commute.**

```
ready ; snapshot        =  ready ; Base
ready ; svid ; snapshot =  ready ; svid ; Refusal(PersonalizedSince)
```

For every `v` with `personalizes_the_vm(v)`. This is the only non-commutation in
the grammar that the walker can hit by pure luck, and it is the one with the
worst blast radius when it fails (a base that hands one pod's identity to every
clone). It deserves a weight, not a uniform draw.

**A6 — guest operations are invisible to host observations.** The central law.
Let `G` be any finite sequence drawn from the guest vsock surface minus `ship`,
and let `o` be any host observation (`result`, `receipt`, `prog`, or an
attestation). Then

```
o ∘ G  =  o
```

A guest may ask for things; nothing it asks for changes what the host concludes.
The walk form is a two-execution comparison: run a pod to completion with an
empty `G`, run it again with a randomly generated `G`, and assert the host's
signed observations are byte-identical. `ship` is excluded because shipping a
receipt is *supposed* to move data guest→host — and that exclusion is where the
next law goes.

**A7 — a shipped receipt is data, never authority.** For any `b`:

```
verify(receipt(p)) after ship(Guest(p), b)  =  verify(receipt(p)) before
```

unless `b` verifies against a trusted signer. A guest can put bytes in front of
the host; it cannot make the host sign them. Walk form: ship adversarial bodies
(truncated, oversized, a valid receipt for a *different* pod, a replay of this
pod's earlier receipt) and assert the host's own receipt is unchanged and the
verdict on `b` is a refusal with the specific reason.

**A8 — verification is exact.** `verify(sign(m, k), bundle(k)) = Ok` and
`verify(tamper(sign(m, k), i), bundle(k)) = Refusal` for every byte index `i`.
The universally-quantified form is the point: a walk that flips one random byte
per iteration covers the envelope's whole surface over a run, and any index
where verification still passes is a finding.

**A9 — lineage is append-only.** `vchain(extend(c, e)) = Ok` if `vchain(c) =
Ok`; and for any `c' != c` reachable by `tamper`, `vchain(c') = Refusal`.
Combined with A8 this says the chain is as strong as its weakest envelope, which
is a claim worth failing loudly.

## The walk

```
walk(Sigma, budget):
  while budget:
    E <- { (op, args) : pre(op, args) holds in Sigma }
    D <- { (op, args) : pre(op, args) fails  in Sigma }   -- with the reason
    (op, args, expect) <- weighted_draw(E ∪ D)
    ans <- execute(op, args)
    if expect = Enabled:  assert obs(op, ans, Sigma)
    else:                 assert ans = Refusal(expected_reason)
    Sigma <- eff(op, args, Sigma)
    maybe: Sigma <- environment_step(Sigma)
```

### The disabled set is the oracle

This is the design decision that earns the specification. A grammar whose `pre`
only *filters* the draw tests the happy path and nothing else; every
authorization bug, every one-shot leak, every premature snapshot lives in `D`.
Drawing from `E ∪ D` and asserting the **specific named reason** — not merely
"an error" — turns `pre` from a generator constraint into a security oracle.
Nucleus already refuses with named reasons everywhere and never with a silent
fallback, so the reasons exist to be asserted against.

The sharpest instances: `cancel` a pod you are a *grandparent* of (must refuse —
`may_manage` is deliberately non-transitive, and a walk generating three-deep
lineage is what keeps that deliberate rather than accidental); `snapshot` a pod
that announced `ready` and then fetched an SVID (A5); a second `broker` (A2).

### Weighting

A uniform draw over `E ∪ D` spends its budget on `ping` and `health`. The
[weighted random walk for CFSM
conformance](https://link.springer.com/chapter/10.1007/978-0-387-35271-8_17)
result is the one to copy: weight inversely by visit count over *transitions*,
not states, so the walk is pulled toward untried (state, command) pairs. Two
nucleus-specific adjustments:

* **Depth costs.** Lineage depth 3 is needed for the non-transitivity test and
  is reached only by three nested `create`s that a novelty walker has no reason
  to prefer. Seed it, or weight `create` by a lineage-depth histogram.
* **One-shots are consumed.** After `broker` is served, every further draw of it
  is the same `D` transition. Cap repeats per pod and spend the budget on a
  fresh pod instead.

### Shrinking

[`proptest-state-machine`](https://docs.rs/proptest-state-machine) is the right
harness: it generates operation sequences against a reference model, checks
postconditions, and shrinks to a minimal failing sequence. The model above *is*
its `ReferenceStateMachine` — `Sigma` is the state, `pre` is
`preconditions`, `eff` is `apply`, `obs` is the postcondition check. The mapping
is close enough that the doc and the impl should share the names.

Shrinking matters more here than in a typical state-machine test because A6 and
A7 fail as *pairs of executions*, and an unshrunk counterexample to A6 is a
200-command guest transcript nobody can read. Shrinking must be over `G`, and it
must preserve the pod's completion, or it will shrink to "the pod never ran".

## What this grammar does not yet cover

* **The CLI's 24 subcommands are not all in it.** `Audit`, `Trust`, `Guard`,
  `Setup`, `Lockdown`, `Observe`, `Grant`, `Node`, `Start`, `Stop` are node- and
  operator-configuration operations whose state is the node's, not a pod's, and
  `NodeRec` above is a placeholder. That carrier needs the same treatment and
  has not had it. The ones that *are* covered — `Envelope`, `EnvelopeVerify`,
  `Lineage`, `LineageVerifyChain`, `Bundle`, `Verify`, `VerifyAttestation`,
  `Manifest`, `Replay` — are the Artifact carrier, complete.
* **`Errored` and `Unavailable` are unreachable** without a fault alphabet, as
  above. Until one exists, any claim that the walk "covers the result lattice"
  is false.
* **`obs` is under-specified for `receipt`.** The grammar says a receipt is
  returned; it does not say what must be in it. A6 compares two receipts for
  equality, which is strong, but it does not check that the receipt says
  anything *true*. That check is `replay`, and wiring `replay` into the walk as
  a postcondition on every terminal pod is the highest-value next step.
* **Time.** `timeout_seconds` is IN, so a pod that times out is a different
  program from one that does not, and the walk has no way to reach a timeout
  cheaply. Either timeouts get a scaled clock or that branch stays untested.

## Sources

* [Specification of generic APIs, or: why algebraic may be better than pre/post](https://dl.acm.org/doi/10.1145/2692956.2663183)
* [A weighted random walk approach for conformance testing of a system specified as communicating finite state machines](https://link.springer.com/chapter/10.1007/978-0-387-35271-8_17)
* [Random Test Generation of Application Programming Interfaces](https://arxiv.org/pdf/2207.13143)
* [A Random Walk Based Algorithm for Structural Test Case Generation](https://arxiv.org/pdf/1704.04772)
* [Build Systems à la Carte](https://www.microsoft.com/en-us/research/wp-content/uploads/2018/03/build-systems.pdf)
