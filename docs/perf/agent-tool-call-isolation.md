# Rubric: one microVM per agent tool call

A coding agent's tool calls — read a file, write a file, run a command, search a
tree, fetch a URL — currently run wherever the agent runs. This rubric drives
nucleus to the point where **each tool call executes in its own Firecracker
microVM**, and does so fast enough that a person does not notice.

It is written to be run as a loop: forty numbered iterations, each with a
checkable definition of done. A loop iteration picks the lowest-numbered
iteration not yet `PASS` in `docs/perf/RUBRIC-LEDGER.md`, does it, records the
result, and stops. Nothing here requires remembering the previous session.

> **Naming.** nucleus is vendor-neutral (CLAUDE.md), so this document says
> "agent tool call" throughout. The tool classes below are the generic shapes —
> file read, file write, command execution, search, network fetch — not any one
> vendor's tool schema.

## The problem, in one number

Measured 2026-09-02 on aarch64 / KVM / 4 vCPU / 7.9 GiB, with
`nucleus-perf podburst`:

| what | measured |
| --- | --- |
| single pod, submit → running | **5,580 ms** |
| largest burst with zero failures | **5 pods** |
| resident memory per pod | **50 MiB** (512 MiB configured — 10x over-estimate) |
| N=10 with the stock 30s health timeout | 0/10 started |
| N=10 with the timeout raised | 10/10 started, 74 s |
| guest startup accounted for by instrumentation | **86.5%** as of 2026-09-03 (`unaccounted=62ms of 458ms`). Was 11% when this rubric was written; see ledger row 9. |

**Update 2026-09-03:** the last row is now 86.5% -- iteration 9 is met, and the
boot breaks down as state_build 109ms, runtime_build 92ms, args_parse 68ms,
sandbox_proof 35ms, router_build 32ms. Those first three are 269ms of a 458ms
boot and are where Stage C should aim.

A tool call that takes 5.6 seconds is unusable; a plausible target is **under
250 ms p50**. That target is not arbitrary: production agent
sandboxes in 2026 restore Firecracker snapshots in 5-30 ms (E2B advertises
sub-30 ms cold starts), and 90-200 ms is widely treated as the ceiling for a
tool call that should feel instant. 250 ms is therefore a conservative first
target, not an ambitious one -- Stage C exists to reach the range the field
already operates in. That is the gap this rubric closes — roughly 20x — and the last
row explains why nobody has closed it yet: **89% of guest startup is untimed**,
so optimisation today is guesswork.

Two facts are already established and should not be re-litigated:

* Memory is **not** the constraint. 100 pods is ~5 GiB resident on a 7.9 GiB
  host. Capacity planning that multiplies the *configured* 512 MiB is wrong by
  10x.
* The observed concurrency wall was a **fixed 30 s proxy health timeout** under
  CPU contention, not capacity — raising it turned 0/10 into 10/10.

## How to run one iteration

```
cargo run -p nucleus-perf -- podburst --spec <spec> --counts <N> --auth-secret "$SECRET"
```

Every iteration must state its number in the commit subject, e.g.
`perf(rubric): 12 -- batch the guest vsock handshake into one round trip`.

**Three rules, each earned the hard way:**

1. **Assert non-vacuity before asserting the property.** A burst that "passes"
   because nothing booted is the default failure mode. Every iteration checks
   `started == N` before it looks at latency.
2. **Measure the target, not your own actions.** Count running microVMs and
   read their RSS; do not count the requests you sent.
3. **Compare like with like.** Host binaries, guest rootfs and harness must come
   from one tree. Version skew presents as `401 invalid signature` (#2396), not
   as a version error.

---

## Stage A — correctness: every tool class runs in a pod at all (1–8)

Latency is irrelevant until each shape works. No optimisation in this stage.

| # | Iteration | Done when |
| --- | --- | --- |
| 1 | **Baseline, recorded.** Run the ramp 1,5,10,25 and commit the numbers to the ledger. | Ledger holds a table with `started`, `failed`, p50 and RSS for each N. |
| 2 | **File read in a pod.** One pod reads a path the sandbox permits and returns its bytes. | A 200 with non-empty contents, and a path outside the permitted set refused with `path_denied`. **Not** "matches a host-side checksum": the sandbox is a disk image, not a host mount, so the host can neither place a file in it nor read one out. Needs a readable fixture to exist at all -- see ledger row 2b. |
| 3 | **File write in a pod.** Write, then read the same bytes back through the guest. | Round trip returns exactly what was written; a write outside the writable root is refused. Requires the `/v1/approve` path: `write_files` is `LowRisk` in `codegen`, so an unapproved write is refused with `approval_required` (measured). |
| 4 | **Command execution.** Run `argv` with no shell, capture stdout/stderr/exit. | Exit code and both streams round-trip; a denied binary is refused by policy, not by absence. |
| 5 | **Search.** Run a tree-wide search, return matches. | Matches equal a host-side run over the same tree. |
| 6 | **Network fetch under the default-deny fence.** | An allowed host resolves; a denied host is refused *and the refusal is attributable to the fence*, not to DNS failure. |
| 7 | **Refusals are policy, not accident.** For each class above, one denied variant. | Every refusal carries a policy reason; none is a bare timeout or a missing file. |
| 8 | **One session, many calls.** 20 mixed calls in sequence, each its own pod, **each torn down before the next call starts**. | 20/20 succeed; no leaked microVM, netns, cgroup or state dir afterwards. |

## Stage B — make the cost visible (9–16)

Optimising while 89% of the boot is untimed is guessing. This stage buys sight.

| # | Iteration | Done when |
| --- | --- | --- |
| 9 | **Close the instrumentation gap.** Add spans until `unaccounted` is under 15% of guest startup. | `nucleus-startup-trace` shows `unaccounted` < 15%. |
| 10 | **Split the host-side timeline.** Attribute submit → running across admission, Firecracker spawn, kernel, guest init, health check. | Every phase has a number; they sum to within 10% of the total. |
| 11 | **Name the top three costs.** | Ledger names them with measured milliseconds, not adjectives. |
| 12 | ~~**Batch the guest vsock handshake.**~~ **DROPPED — refuted by measurement.** | The five sequential fetches were timed (#2409) and cost **26 ms of a 458 ms boot, about 5%**. Batching them has a 26 ms ceiling, so it is not worth the protocol change. Also measured: `handshake_total` is 85 ms, so 59 ms of it is the work BETWEEN the fetches, not the transport. Kept in the table rather than deleted -- the reasoning that made it look worthwhile is the useful part, and deleting it invites someone to propose it again. |
| 13 | **Take the health check off the hot path.** A fixed 30 s poll gates every start. | Readiness is edge-triggered or the guest announces itself; N=10 passes with the *stock* timeout. |
| 14 | **Per-call latency budget.** Publish a budget that sums to the target. | Budget committed; every line has an owner phase from #10. |
| 15 | **A latency regression gate.** | CI fails when single-pod p50 regresses >20% against the ledger. |
| 16 | **A non-vacuity gate on the gate.** | Deliberately break the boot; the gate must go red. If it stays green it is decorative. |

## Stage C — latency: 5,580 ms toward 250 ms (17–26)

| # | Iteration | Done when |
| --- | --- | --- |
| 17 | **Shared read-only rootfs.** One rootfs, per-pod overlay for writes. | Two pods share the backing file; writes stay private; measured saving recorded. |
| 18 | **Drop per-pod artifact re-open.** | Kernel/rootfs opened once per node, not once per pod. |
| 19 | **Firecracker snapshot: create.** Snapshot a booted, pre-handshake guest. | Snapshot written and restorable; contents documented. |
| 20 | **Snapshot: restore.** Serve a tool call from a restored snapshot. | Restore-to-serving under **50 ms**; result identical to a cold pod. |
| 21 | **Snapshot freshness.** A stale snapshot must not serve. | Rootfs or policy change invalidates it; a stale snapshot is refused, not silently used. |
| 22 | **Identity across restore.** Each restored pod needs its *own* SVID. | Two restored pods have distinct SVIDs; neither reuses the snapshot's. **This is the security crux of snapshotting — treat a shared identity as a failure.** |
| 23 | **Warm pool.** Keep K pre-booted pods; a call takes one. | p50 under **250 ms**; pool refills; exhaustion degrades to cold start, never to an error. |
| 24 | **Pool sizing from measurement.** | K derived from measured arrival rate and refill time, and written down. |
| 25 | **Cold-path budget.** Pool miss stays usable. | Cold p99 under **2 s**. |
| 26 | **Latency table.** Re-run the full ramp. | Ledger shows before/after per stage; total speedup stated. |

## Stage D — concurrency and real sessions (27–34)

| # | Iteration | Done when |
| --- | --- | --- |
| 27 | **Admission queue.** The node currently accepts every request and lets them fight for CPU. | Boots are staggered to a measured concurrency; N=50 reaches 50/50 rather than 5/50. |
| 28 | **Find the real ceiling.** Ramp until failure with queueing on. | Ceiling stated with its binding resource (CPU, vsock, fds, PIDs). |
| 29 | **100 pods.** | Either 100/100 with numbers, **or** a written statement of the exact resource that stops it and what hardware would not. |
| 30 | **Burst of mixed classes.** 50 concurrent calls across all six shapes. | No class starves; per-class p50 within 2x of the best. |
| 31 | **Sustained session.** 500 sequential calls. | No leak in RSS, fds, netns, cgroups or state dirs; last call as fast as the first. |
| 32 | **Parallel sessions.** 10 sessions × 50 calls. | No cross-session visibility; isolation asserted, not assumed. |
| 33 | **Failure injection.** Kill Firecracker, exhaust the pool, corrupt a snapshot mid-call. | Each fails closed with an attributable reason; no hang, no silent success. |
| 34 | **Cancellation.** | Cancelled call frees its VM within 1 s; no orphan. |

## Stage E — make it stay fixed (35–40)

| # | Iteration | Done when |
| --- | --- | --- |
| 35 | **Isolation gate.** Prove call N cannot observe call N−1. | A canary written by one call is unreadable by the next; the gate goes red when isolation is removed. |
| 36 | **Policy gate per class.** | Each of the six shapes has an allowed and a denied case in CI. |
| 37 | **Latency gate in CI.** | Ramp runs in CI; regressions fail the build. |
| 38 | **Capacity documented.** | Pods-per-core and MiB-per-pod published from measurement, with the 10x configured-vs-resident trap called out. |
| 39 | **Operator story.** | One page: enabling per-call isolation, sizing the pool, what to do when the pool is exhausted. |
| 40 | **End-to-end.** A real agent session runs every tool call in its own microVM. | Session completes; p50 under 250 ms; ledger holds the final table and the honest list of what is still slow. |

---

## Ledger format

`docs/perf/RUBRIC-LEDGER.md`, one row per iteration:

```
| # | status | date | evidence |
| 1 | PASS | 2026-09-02 | 1:5580ms 5:10902ms 10:0/10 25:0/25, 50MiB/pod |
```

`status` is `PASS`, `FAIL`, or `BLOCKED: <reason>`. A `FAIL` row stays; the
retry is a new row. Never overwrite a failure — the history of what did not work
is the most useful thing here.
