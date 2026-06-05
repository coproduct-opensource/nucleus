# RFC: Agent Control Plane on Fly Machines

> Status: **Draft / exploratory.** Describes a target architecture; not yet
> implemented. The substrate primitive it relies on (Firecracker VM
> snapshot/restore) is provided by Fly's `suspend`/`start` — we do not build it.

## Thesis

Fly Machines *are* Firecracker microVMs, exposed through a REST API with
`suspend` (memory snapshot) / `start` (restore) and scale-to-zero. So we **do
not build the node / runtime / snapshot / scale-to-zero layer** — we build the
agent-specific control plane (scheduler, budget, information-flow + provenance,
verified policy) and drive Fly's Machines API. Fly is the substrate; nucleus +
the orchestrator are the brains.

Crucially, Fly's `suspend` is the "freeze an idle agent to ~$0, thaw in ~ms on
the next message" primitive — the single feature that is both a large efficiency
win for bursty agent workloads and structurally impossible on Kubernetes (a
paused pod still reserves resources; CRIU is fragile). We get it out of the box.

## Responsibility split

| Concern | **Fly provides** | **We build** |
|---|---|---|
| microVM isolation | Machines = Firecracker | — |
| Freeze / resume | `suspend` (mem snapshot) / `start` | *when* to suspend (session semantics) |
| Scale-to-zero | `auto_stop/start`, `min_machines=0` | per-**session** (not per-app) policy |
| Boot / placement / regions | Machines API, global | which region per session (affinity) |
| Networking | 6PN, Flycast, egress | data-flow policy (IFC), default-deny intent |
| Identity token | Machine **OIDC** token | `nucleus-fly-oidc` → SPIFFE SVID |
| Compute billing | machine-seconds usage | **token / $ budget** (CostStore) |
| Scheduler | (places machines you ask for) | matchmaker / VCG, work queue, reconciler |
| Policy / admission | — | portcullis kernel (Lean/Kani), IFC, Cedar |
| Provenance | — | `nucleus-lineage` signed DAG |

## Session → Machine lifecycle

```text
submit work ─► admit (budget pre-flight) ─► create Machine (or clone warm snapshot) ─► ACTIVE
ACTIVE ─(idle N s / awaiting human)──────► suspend       ─► FROZEN   (~$0 compute)
FROZEN ─(inbound message)────────────────► start         ─► ACTIVE   (mem-restore, ~ms)
ACTIVE ─(budget exhausted / done)────────► stop/destroy  ─► TERMINAL (+ volume GC)
crash / host evict ──────────────────────► reconciler restores from last suspend / volume checkpoint
```

Our reconciler owns this state machine; the transitions are Machines API calls.

## Suspend-on-idle / resume-on-message (the efficiency core)

- **Idle detector** (per session) → `suspend` when a session is waiting on a
  human or quiescent. Compute meter → 0; pay only suspended-memory storage.
- **Resume router**: inbound message → if the session's Machine is `FROZEN`,
  `start` it then forward. Fly's request-based `auto_start` covers app-level; for
  **per-session** control we call the API explicitly (or via `fly-replay`).
- **Tiering**: after a long freeze (or near Fly's max-suspend limit), demote
  `suspend` → full `stop` + a volume/lineage checkpoint — lower storage cost and
  no dependence on suspend-duration limits.

## Budget enforcement via the Machines API

Fly meters **machine-seconds**; we meter **tokens/$** in-band and combine both in
the CostStore. Three enforcement points:

1. **Pre-flight admission** — don't `create`/`start` a Machine if the
   session/tenant budget is exhausted.
2. **In-session circuit breaker** — the tool-proxy / portcullis kernel denies
   tool calls at the budget ceiling → triggers `suspend` (pause spend) or
   `destroy`.
3. **Idle → suspend** — the cheapest lever: stop the compute meter the instant a
   session goes quiet.

## Identity: SPIFFE via fly-oidc (no long-lived secrets)

Machine boots → fetches its **Fly Machine OIDC token** → presents it to the
control plane → `nucleus-fly-oidc` validates it against Fly's JWKS and derives a
SPIFFE id from the *verified* machine/app claims → issues a scoped SVID + a
portcullis capability cert (delegation-ceiling'd). That SVID backs mTLS to the
tool-proxy / control plane and signs every lineage edge. (`nucleus-fly-oidc` is
the validation half today; this is its production consumer.)

## Fly call vs ours (cheat sheet)

- **Fly API:** `machines.create / start / suspend / stop / destroy / wait`,
  volumes, OIDC token fetch, 6PN / Flycast.
- **Ours (never Fly):** the scheduler / queue, the budget meter + circuit
  breakers, IFC FlowTracker + Cedar/portcullis decisions, lineage/provenance,
  SPIFFE issuance, and the session↔Machine state machine.

## Avoiding lock-in

Keep execution behind a `MachineDriver` trait: Fly is one implementation
(`FlyMachineDriver`), raw-Firecracker / `nucleus-node` another, an in-memory
`MockMachineDriver` for tests. The reconciler depends only on the trait.

## Open risks (verify before committing)

Suspend limits (max duration, machine size, GPU), resume latency for large RAM,
suspended-memory storage cost, per-session vs per-app `auto_start` semantics,
Machines API rate limits, multi-region session affinity, and Fly lock-in
(mitigated by the `MachineDriver` abstraction).

## Phasing

- **P0:** single region; reconciler drives create/suspend/start/destroy per
  session; budget pre-flight + idle-suspend; SPIFFE via fly-oidc.
- **P1:** resume-on-message router; in-session budget circuit breaker;
  per-session lineage.
- **P2:** warm-pool + clone-from-snapshot; multi-region affinity; spot-style
  eviction → restore.

P0 is mostly wiring an existing reconciler to the Fly Machines API + budget
pre-flight + fly-oidc SVID issuance. The hard primitive (snapshot freeze/resume)
is Fly's `suspend`.
