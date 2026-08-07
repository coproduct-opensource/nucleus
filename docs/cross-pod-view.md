# The pod view relation (cross-pod NI, Phase X-1)

**Status: design, not yet mechanised.** This document produces the relation and
its justification *before* any theorem uses it, which is the whole point of the
phase. Nelson & Bornholt's survey of verified systems is explicit that the
view-partitioning relation is the hard, auditable part, and that verified systems
each invent their own notion of noninterference — which is how a guarantee
quietly becomes weaker than it sounds. So the relation is written down and argued
about here, where it can be disagreed with, rather than inside a proof where its
weakness would be invisible.

## What this is for

Every observer relation in the corpus today is a **trace projection**
(`lowObs : List Event → …`). There is no view over *state* anywhere. Cross-pod
noninterference needs one: what pod A can observe *of the shared substrate*.

```
podView : PodId → HostState → Observation
```

The claim it will serve: pod A's observable behaviour is independent of pod B's
secrets, for an arbitrary B.

## Why this is statable now and was not before

The corpus has no pod identifier because **the system had none**. Every
tool-proxy signed its management requests as the literal actor `"tool-proxy"`
with the same node-wide secret, so the node could not tell callers apart. A model
cannot assign a material to a pod when the system cannot either.

Per-caller identity at the node API (#2196) removes that. `HostState` can now
carry a pod-indexed structure because the running system does.

## Prior art, and the architecture it changed my mind about

The first draft of this document hand-justified each field. The literature says
that is the weaker of two available structures, and the stronger one is worth
adopting before any Lean is written.

**Nickel (OSDI 2018) makes the view relation *untrusted*.** Noninterference is
defined over `output` alone; the observational equivalence `≈` and the state
invariant `I` appear only in the unwinding theorem, and *any* instances
satisfying the unwinding conditions establish the theorem. The trusted surface is
the **policy** and `output` — not the relation. Their reported experience is
exactly the worry this phase was created around: *"it was non-trivial to determine
which part of the system state was observable by each domain."*

That reframes the deliverable. A too-coarse relation stops being a soundness risk
and becomes a **proof failure**, which is a far better place for a mistake to
show up. Concretely, the two unwinding conditions squeeze each field from both
sides:

| Bound | Condition | Meaning for a field |
| --- | --- | --- |
| lower | **output consistency** | anything a pod can read back through the API must be *determined* by `podView`, or OC fails — the relation is too coarse |
| upper | **local respect** | anything another pod's action writes must be *excluded* from `podView`, or LR fails — the relation is too fine |

A field admissible in neither direction — read by nobody, written by others — is
a design smell rather than a modelling choice. This is a decision procedure where
this document previously had an argument, and X-2 should use it directly.

**seL4 derives the partition instead of declaring it.** `subjectReads` is an
inductive closure over the authority graph, grown under the confidentiality
obligation until the proof closes — *the fixpoint is the answer, not the guess*.
Same instinct as this project's `derive-the-domain-dont-declare-it` rule, and the
right long-run replacement for the table below. seL4 also keeps a short explicit
list of scalars every domain observes (`cur_thread`, `cur_domain`, …) — declared
visible to all and therefore provably useless as a channel, which is the honest
analogue of nucleus's structural 27.

**van der Meyden (ESORICS 2007)** is the cautionary one: Haigh & Young's
intransitive noninterference definition was accepted for roughly twenty years
before being shown to admit flows it was meant to forbid. A definition being
standard is not evidence it says what you want.

**SeKVM** is the closest system — many VMs and untrusted host components on one
machine — and earns the right to omit TLBs from the abstract machine rather than
asserting it. Worth copying that standard.

## Method

`HostState` is `NodeState`, whose 38 fields were **derived from the source**
rather than listed by hand — a hand-maintained enumeration standing in for a
computable one is how a field goes missing:

```sh
awk '/^struct NodeState \{/,/^\}/' crates/nucleus-node/src/main.rs \
  | grep -E "^    [a-z_]+:" | sed 's/^    //; s/:.*//' | sort
```

Each field is classified as **structural** (no pod can influence it), **secret**
(never observable, by construction), or **shared-mutable** (pods write it, pods
read it — the only category where cross-pod flow can exist).

The classification question is deliberately *not* "can pod A read this field?".
It is **"can pod B's actions change what pod A observes?"** A field every pod can
read but no pod can write carries no information *between* pods.

## Field classification

### Structural — 27 of 38

`auth`, `authz_policy`, `broker_enforcing`, `broker_listen`, `broker_vsock_port`,
`container_image`, `container_network`, `driver`, `drand_config`,
`firecracker_jailer`, `firecracker_netns`, `firecracker_netns_drift_check`,
`firecracker_netns_drift_interval`, `firecracker_path`,
`firecracker_seccomp_verify`, `github_oidc`, `identity_vsock_port`,
`jailer_chroot_base`, `jailer_gid`, `jailer_path`, `jailer_uid`, `listen_addr`,
`proxy_actor`, `state_dir`, `tool_proxy_path`, `trust_gate`, `trusted_postures`

Operator configuration, fixed at startup and never mutated. Identical for every
pod, so no pod's behaviour can move them. These drop out of `podView` entirely —
not because they are hidden, but because a constant carries no information.

**This is the load-bearing simplification.** Roughly three quarters of the host
state is inert, which is why a cross-pod theorem is tractable at all.

### Secret — 3 of 38

| Field | Justification |
| --- | --- |
| `caller_secret` | Node-only, fresh per process, never persisted, never sent to a pod. A pod holding it could derive any pod's caller token, which would collapse the identity mechanism entirely. |
| `proxy_auth_secret` | **Shared with every proxy.** So it is observable to all pods equally — which is precisely why it cannot distinguish them, and precisely why ownership enforcement had to move node-side (#2199). Not a cross-pod channel; it is a *reason* the node cannot trust the proxy. |
| `proxy_approval_secret` | As above. |

### Shared-mutable — 8 of 38, and the entire subject

| Field | Written by | Cross-pod flow? |
| --- | --- | --- |
| `pods` | every create / cancel | **Mediated.** Was unrestricted; now filtered by lineage, and the listing is filtered rather than only the accessors (#2199). |
| `identity_manager` (`vm_registry`) | register / unregister | **Yes, defective.** Never drained (#2198); the serving path returns an arbitrary entry (#2197). |
| `lockdown_tx` | operator lockdown | **Yes — see below.** |
| `firecracker_pool` | pod spawn / exit | **Yes — see below.** |
| `container_pool` | pod spawn / exit | As `firecracker_pool`. |
| `network_allocator` | pod spawn / exit | **Yes, confirmed.** `guest_ip = base + index * POD_STRIDE + 3`, so a pod's own IP *is* its allocation index, and allocation is a dense counter from zero. Reveals a count of prior pods, nothing about their contents. Excluded as co-tenancy cardinality. |
| `docker` | shared client | Connection-pool contention; same shape as the semaphores. |
| `http_client` | shared client | As above. |

## The two findings this phase produced

### 1. Lockdown is broadcast to every pod's proxy

`lockdown_tx` is a `broadcast::Sender`. The node sends **one command to all
subscribed proxies** and each proxy decides locally whether it applies
(`lockdown_client.rs`, `apply_scope`). The command carries:

```protobuf
message LockdownCommand {
  bool   active; string reason; string operator_id;
  uint64 timestamp_unix; string scope;   // "all", "pod:<id>", "label:<selector>"
}
```

So when an operator locks down pod A, **pod B's proxy receives pod A's UUID**,
the operator's free-text reason, and who issued it.

Stated precisely, because the bound matters:

- **In pod B's VM memory: the whole command**, reason included. Always.
- **In pod B's proxy log: only the scope** — the non-applying branch logs
  `scope` and its own `pod_id` at `debug`, not the reason. So the operator's free
  text does not reach the log of a non-target pod.
- Whether the *workload* sees either depends on proxy→workload paths. The
  architecture treats the proxy as the enforcement point and the agent as
  untrusted, so this is not immediately a workload-visible leak — but "another
  tenant's identifier is resident in this VM's address space" is a markedly
  weaker position than "it never left the host."

**This is fixable, and the fix is now available.** Filtering belongs server-side:
the node knows which pod each proxy serves, so it can send only to the relevant
stream instead of broadcasting and filtering in the guest. It could not do that
before per-caller identity. Client-side filtering of a broadcast is the same
mistake as returning the full pod list and refusing individually — the
information has already crossed by the time the check runs.

### 2. The bounded pod pool makes the promoted claim FALSE as written

`firecracker_pool` is an `Option<Arc<Semaphore>>`, and spawn does:

```rust
pool.clone().acquire_owned().await
```

It **blocks**. Pod B's creation completes only once some other pod releases a
permit. Pod A therefore influences pod B's observable behaviour, and the
influence is macroscopic, reliable, and requires no measurement apparatus — B
simply observes that its request did not complete until A finished.

The claim promoted to `north-star.md` excludes "timing, cache, and other
microarchitectural channels." **A blocking semaphore is none of those three.**
It is an ordinary architectural resource-contention channel, and a careful reader
would correctly conclude the claim covers it — and that the claim is false.

This is the "too coarse / too fine" hazard landing on the actual system, and it
is what the phase is for. Three ways out:

1. **Exclude availability and resource-contention channels explicitly.** Standard
   — possibilistic NI over values conventionally says nothing about availability
   — and honest, provided the exclusion is *stated* rather than assumed.
2. Define `podView` to exclude request completion. Rejected: too fine. A relation
   that cannot see whether your pod started is too weak to interest anyone.
3. Remove the shared bound. Not a modelling decision, and it trades a real
   operational protection for a property nobody asked for.

**Taken: (1).** The claim's exclusion is widened accordingly, and the doc-honesty
gate is extended so the new exclusion cannot be dropped either. Note the channel
exists only in *bounded* configurations — an unset pool has no ceiling and no
channel — but the claim must hold for shipped configurations, not the permissive
one.

## The relation

```
Observation ::=
  { ownPods      : Set PodId        -- pods this pod may manage (lineage-filtered)
  , ownMaterials : PodId → Labels   -- its own credential labels
  , ownEvents    : List Event       -- the existing trace projection, per pod
  }

podView p σ =
  { ownPods      = { q ∈ σ.pods | q.parent = p ∨ q = p }
  , ownMaterials = σ.materials restricted to p
  , ownEvents    = lowObs (σ.trace filtered to p)
  }
```

Deliberately **excluded** from `Observation`, each with its reason:

| Excluded | Why |
| --- | --- |
| pool occupancy / permit availability | Finding 2. Excluded by the widened claim, not by pretending it is unobservable. |
| wall-clock and completion latency | Pre-existing exclusion; unchanged. |
| co-tenancy cardinality (own allocation index / IP) | The index is the pod's own IP and allocation is a dense counter, so it is plainly observable. It reveals a COUNT of prior pods and nothing about their contents. See the KILL assessment — this is the exclusion my own operational test misfired on. |
| the identity registry | Currently defective (#2197, #2198). Modelling it as sound would prove a property the system does not have. It re-enters once retired or fixed. |
| lockdown delivery | Finding 1. Re-enters as non-observable once filtering moves server-side; until then, including it would make the theorem false. |

The last two are the important entries. Excluding a field **because the code is
currently wrong** is legitimate only if the exclusion is recorded with the defect
it tracks, so the model cannot quietly keep assuming soundness after the bug is
fixed — or, worse, be read as having proven something about it.

## KILL assessment

The phase's KILL condition: *if a field cannot be justified either way, stop —
the claim is not yet statable.*

**It did not fire.** All 38 fields are classified, and each of the four
exclusions has a stated reason rather than a shrug. Two required changing
something outside the model — one claim correction and two filed defects — which
is the phase working as intended rather than a detour around it.

**The `network_allocator` pass — and a test of mine that misfired.**

The first draft of this section said: *if a pod can read its own index and
indices are densely sequential, this phase reopens.* That pass has now been done,
and **both conditions hold**:

- Allocation is `self.next.fetch_add(1, SeqCst)` from zero, with released indices
  recycled LIFO. Densely sequential.
- `offset = index * POD_STRIDE; guest_ip = base + offset + 3`. The index **is**
  the pod's own IP address. Every pod can read it with `ip addr`, divide by the
  stride, and recover its allocation index exactly.

So by the letter of the criterion I wrote, this phase reopens. It does not, and
the reason is worth recording, because the failure was in the test rather than in
the system.

"Densely sequential" was a *proxy* for the real criterion in the sentence
immediately before it — **"unbounded in what it reveals."** The proxy over-fires.
Dense sequencing establishes that the index carries information about other
pods; it says nothing about *how much*. On inspection the channel reveals a
**count**, and a smaller one than that phrasing suggests. Allocation pops a LIFO
free list first and only increments the counter when that list is empty, so
`next` climbs to the **high-water mark of concurrent pods** and then stops. With
`NET_POOL_PREFIX = 24` and `POD_PREFIX = 30` the pool is **64 indices**, and
`--firecracker-max-pods` defaults to **15**. So an index reveals "at some point
at least this many pods were concurrently live", bounded by the concurrency
limit — not a count of every tenant that has ever run here. Not their identity, not their labels, not their contents, and nothing
that varies with any secret nucleus holds. The flagship claim is about secrets
and about which of them get released; a cardinality leak falsifies neither.

That makes this a fourth exclusion — **co-tenancy cardinality** — rather than a
collapse of the relation. Recorded here rather than folded silently into the
claim, because a criterion that fires and is then argued past is exactly how a
guarantee becomes weaker than it sounds. The correct lesson is that the
operational test should have been written against what the channel *reveals*, not
against the shape of the counter, and a future pass on `docker` / `http_client`
connection reuse should use the revelation form directly.

**But an exclusion is the second-best answer here, and the literature has the
first.** CertiKOS hit this exact channel: `proc_create` allocated the lowest free
process ID, so `y − x − 1` told Alice precisely how many children other
principals had spawned while she was yielded. They did not exclude it — they
**partitioned the identifier space by construction**, making the child of `i` be
`i * m_c + c + 1` so different parents' child-ID sets are disjoint and an
identifier reveals nothing about anyone else's allocations. Nickel independently
names the same rule: *"partition names among domains."*

nucleus's allocator is the dense-counter shape CertiKOS moved away from
(`fetch_add` from zero, LIFO recycle), so per-lineage partitioning would make a
pod's own IP reveal only its own subtree.

**Measured, that fix does not fit.** Sixty-four indices cannot be meaningfully
partitioned per parent: any block size worth having leaves room for a handful of
parents, which trades node capacity for a metadata property. Recommending it
before checking it against this constraint was backwards, and nucleus #2202
carries the correction.

What remains is a genuine three-way choice — widen the CIDR and then partition,
randomise within the free set (cheap, but a probabilistic guarantee this
possibilistic model cannot state), or keep the exclusion. **Kept as an
exclusion**, because it is honest and cheap while both fixes cost either capacity
or expressibility. This document should not be read as having settled for it
without looking; it was measured, and the numbers are above.

**What would still kill this phase:** a shared-mutable field whose observable
projection varies with another pod's *contents* rather than its existence or
count. None of the eight does today.

## What X-2 inherits

- A relation over three fields, not thirty-eight.
- Two exclusions tied to open defects, which must be re-examined when those close.
- The baseline X-2 calls its control — pods sharing nothing — is now genuinely
  trivial, since 27 of 38 fields are constants and 3 are unreachable secrets.
- The one genuinely shared surface to introduce first is `pods`, because it is the
  only shared-mutable field that is *mediated by design* rather than by accident.

## Sources

- Nelson, Bornholt, Krishnamurthy, Torlak, Wang — *Noninterference specifications
  for secure systems*, SIGOPS OSR 54(1), 2020.
  https://jamesbornholt.com/papers/ni-osr20.pdf
- Sigurbjarnarson et al. — *Nickel: A Framework for Design and Verification of
  Information Flow Control Systems*, OSDI 2018.
  https://jamesbornholt.com/papers/nickel-osdi18.pdf
- Murray et al. — *seL4: from General Purpose to a Proof of Information Flow
  Enforcement*, IEEE S&P 2013.
  https://sel4.systems/Research/pdfs/sel4-from-general-purpose-to-proof-information-flow-enforcement.pdf
- l4v, `proof/infoflow/InfoFlow.thy` — `reads_equiv` / `states_equiv_for` /
  `subjectReads`. https://github.com/seL4/l4v/blob/master/proof/infoflow/InfoFlow.thy
- Costanzo, Shao, Gu — *End-to-End Verification of Information-Flow Security for C
  and Assembly Programs*, PLDI 2016. The observation-function formulation, and the
  `proc_create` identifier channel with its partitioned-ID fix.
  https://flint.cs.yale.edu/flint/publications/security.pdf
- van der Meyden — *What, Indeed, Is Intransitive Noninterference?*, ESORICS 2007.
  https://link.springer.com/chapter/10.1007/978-3-540-74835-9_16
- Li et al. — *A Secure and Formally Verified Linux KVM Hypervisor*, IEEE S&P 2021.
  https://www.cs.columbia.edu/~nieh/pubs/ieeesp2021_kvm.pdf
