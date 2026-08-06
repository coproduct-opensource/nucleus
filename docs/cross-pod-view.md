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
| `network_allocator` | pod spawn / exit | Sequential index allocation is a counting channel; a pod that observes its own index learns how many pods preceded it. Needs its own pass. |
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

**What would have killed it:** had `network_allocator`'s index-assignment channel
turned out to be both observable and unbounded in what it reveals, `podView`
would have needed to model allocation order, and the relation would have stopped
being auditable. It is listed above as needing its own pass; if that pass shows a
pod can read its own index *and* indices are densely sequential, this phase
reopens.

## What X-2 inherits

- A relation over three fields, not thirty-eight.
- Two exclusions tied to open defects, which must be re-examined when those close.
- The baseline X-2 calls its control — pods sharing nothing — is now genuinely
  trivial, since 27 of 38 fields are constants and 3 are unreachable secrets.
- The one genuinely shared surface to introduce first is `pods`, because it is the
  only shared-mutable field that is *mediated by design* rather than by accident.
