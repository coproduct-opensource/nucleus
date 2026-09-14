# nucleus-otel-bootstrap

Shared OpenTelemetry OTLP bootstrap for nucleus server binaries.

[![docs.rs](https://img.shields.io/docsrs/nucleus-otel-bootstrap)](https://docs.rs/nucleus-otel-bootstrap)

Wires `tracing` → `tracing-opentelemetry` → `opentelemetry-otlp` so every server
(verifier, control-plane, OIDC OP, …) emits trace spans to a collector when
configured, and falls through to stderr-only logging when not. One helper, called
once in `main`, so the observability setup is identical across binaries.

## Usage

```rust,ignore
use nucleus_otel_bootstrap::{init, OtelGuard};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Hold the guard for the whole process: dropping it flushes pending spans.
    let _otel: OtelGuard = init("nucleus-verifier-service")?;
    // ...your server here; spans propagate to the collector...
    Ok(())
}
```

The returned `OtelGuard` must live until the server finishes serving — dropping
it flushes spans emitted near shutdown, which would otherwise be lost.

## Activation

OTLP export turns on when `OTEL_EXPORTER_OTLP_ENDPOINT` is set (the canonical
[OTel env var][envs]); with no endpoint, the subscriber still installs
`fmt` + `EnvFilter` logging and the OTel pieces are no-ops.

| Env var | Effect |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | collector endpoint; **presence enables export** |
| `OTEL_SERVICE_NAME` | overrides the `service_name` argument |
| `OTEL_PROPAGATORS` | not read; W3C tracecontext is installed |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | not read; export uses gRPC |

[envs]: https://opentelemetry.io/docs/languages/sdk-configuration/general/

## Scope

This crate sets up **trace and runtime metric** export. It is the single place server
binaries call so trace context propagates uniformly via W3C Trace Context.

## License

MIT

## Memory monitoring

Every enabled process receives a random `service.instance.id` unless the
operator supplies one through `OTEL_RESOURCE_ATTRIBUTES`. Keep that resource
attribute when storing metrics so different nodes and process lifetimes do not
collapse into one time series.

With OTLP enabled, a periodic reader collects memory metrics every five seconds
(export backpressure can delay collection). Hold `OtelGuard` until shutdown to
flush both providers. The node requires its `otel` feature. No global meter
provider is replaced. Measurements follow the
[Linux cgroup v2 interface](https://docs.kernel.org/admin-guide/cgroup-v2.html).

| Instrument | Unit | Measurements (`memory.field`) |
|---|---|---|
| `nucleus.memory.bytes` | bytes | host MemTotal, MemAvailable, SwapTotal, SwapFree; process VmRSS, VmHWM, RssAnon, RssFile, RssShmem, VmSwap; cgroup memory.current, peak, max, high, swap.current, swap.max; finite max/high headroom; memory.stat anon, file, kernel, shmem, slab, inactive_file, active_file, file_mapped, file_dirty, file_writeback |
| `nucleus.memory.pressure` | percent | some/full avg10, avg60, avg300; resolution 0.01 percentage points |
| `nucleus.memory.events` | cumulative events | memory.events low, high, max, oom, oom_kill, oom_group_kill; memory.stat pgfault, pgmajfault, pgscan, pgsteal and workingset_refault/activate/restore for anon/file |
| `nucleus.memory.observation.success` | 0 or 1 | per-field parsing/read success and cgroup discovery success |

`memory.scope=process` means the exporting process itself (RSS includes shared
pages; it is not proportional set size or total pod memory).
`memory.scope=host` means the kernel hosting this process. `cgroup.0` is the
process's cgroup, `cgroup.1` its visible parent, and so on to the mounted root.
Discovery uses the process membership and mountinfo, including subtree mounts.
Only visible ancestors can be measured; cgroup namespaces can hide limits.
Depth is bounded at 64 and each pseudo-file read at 64 KiB. No repository,
command, pod ID, or filesystem path is exported as a metric attribute.

`max` means unlimited: the successful observation has **no byte limit or
headroom sample**, never a zero limit. Failed or missing reads omit the value
and emit an unsuccessful observation. Dashboards must treat missing/stale
samples as unknown. Older kernels may lack individual fields such as peak.
Ancestor event counts include descendants; do not sum them across scopes.

Use host MemAvailable/MemTotal alongside the smallest finite ancestor headroom.
Show anonymous memory and file cache separately: current includes reclaimable
cache, and memory.stat subcategories overlap (do not add all of them).
Headroom is max(0, limit-current), a snapshot rather than a guarantee that an
allocation will succeed. Show PSI some/full and changes in high/max/OOM event
counts together with headroom and swap use. OOM events indicate an occurrence,
not advance warning. Sampling can miss short spikes; peak and cumulative events
help retain evidence, but cannot prevent an OOM.

Retention, dashboards, thresholds, alerts, and scheduling responses belong to
the consuming control plane. A suitable dashboard includes freshness and read
failures, host availability, every visible finite cgroup limit/headroom,
anonymous/file/kernel memory, PSI, swap, and OOM counter increases. Do not infer
**guest** memory health from the host Firecracker process: a guest needs its own
kernel memory observations. This bootstrap observes its own process's
host and cgroup ancestors; it does not discover arbitrary pod cgroups. The tool
proxy also registers this sampler when built with `otel` and configured with an
endpoint. Inside a guest, its host scope describes the guest kernel. This requires
a reachable collector and runtime provisioning of telemetry configuration. Live collector delivery and guest coverage require separate
acceptance before claiming build-wide OOM monitoring is operational.

## CPU, I/O and optimization signals

`init` and `otel_layer` also register the resource sampler. Applications composing
an existing provider use `register_runtime_metrics` and install
`runtime_metrics_view` on the provider builder. That view permits 4096 series per
runtime instrument so all 64 visible ancestor scopes fit without the SDK's default
cardinality overflow. It leaves unrelated instrumentation unchanged.

| Instrument | Unit | `resource.field` |
|---|---|---|
| `nucleus.resource.time` | seconds, cumulative | cgroup CPU usage/user/system/throttled time; host and cgroup CPU/memory/I/O PSI some/full cumulative stall time |
| `nucleus.resource.io.bytes` | bytes, cumulative | cgroup io.rbytes, wbytes, dbytes summed across devices |
| `nucleus.resource.events` | events, cumulative | CPU periods/throttled periods; I/O read/write/discard operations |
| `nucleus.resource.observation.success` | 0 or 1 | each resource field and cgroup discovery |

Scopes have the same meanings as memory scopes. These are application-specific
instruments, not aliases for standard `system.*` or `process.*` metrics: ancestor
cgroups are overlapping aggregates, not individual processes. Take counter rates
within a stable service instance and scope; never sum usage with its user/system
components or sum ancestor scopes. I/O device removal can decrease an aggregate;
treat a decrease as a reset, not negative throughput. An empty readable io.stat
means no device I/O; missing, corrupt, incomplete or overflowing observations are
unknown. Device identifiers are intentionally omitted to bound series count.

CPU time rate gives cores consumed, not a percentage of available CPU capacity.
Throttled time and PSI distinguish scheduling pressure from useful CPU work.
The CPU full PSI value at system scope is undefined by Linux; do not use it to
infer host health. PSI totals retain short stalls that averaged samples can miss.
The sampler does not yet export CPU quota/affinity or per-device latency.

### Cache pressure and memory mapping

Use file refault rates with reclaim, major faults and I/O PSI to investigate cache
churn: refaults count previously evicted pages needed again. Activation and restore
counters provide working-set context. They are not application cache hits/misses
and do not yield a cache hit ratio. Dirty/writeback bytes help distinguish pending
write work from clean cache; mapped and active file bytes describe overlapping
subsets, not additional memory to sum. Missing kernel fields remain unknown.

Memory mapping is an optimization candidate for bounded reads of immutable files.
[Linux mmap semantics](https://www.man7.org/linux/man-pages/man2/mmap.2.html) do not
make MAP_PRIVATE an immutable snapshot of mutable backing storage, and truncation
can cause SIGBUS. Require enforced file lifetime and immutability before mapping
verified objects. Compare the actual buffered and mapped Rust paths on cold/warm
Linux workloads, measuring wall/CPU time, faults, RSS and cgroup pressure. Mapping
does not replace digest verification or durable publication. Filesystem
[reflink COW](https://www.man7.org/linux/man-pages/man2/FICLONERANGE.2const.html)
is a separate mechanism for isolating writes to cloned files. No mmap read path
or cache policy is enabled by these measurements.

### Measurement contract and research (2026-09-13)

Measure duration, volume, errors and saturation at meaningful operation boundaries.
Keep request, artifact and build identifiers in traces or evidence, with bounded
operation/outcome labels on metrics. Use seconds and bytes consistently. OTel
provides [general metric conventions](https://opentelemetry.io/docs/specs/semconv/general/metrics/)
and [application metric naming guidance](https://opentelemetry.io/docs/specs/semconv/general/naming/).

Pair memory headroom with [Linux PSI](https://docs.kernel.org/accounting/psi.html)
and [cgroup CPU/I/O accounting](https://docs.kernel.org/admin-guide/cgroup-v2.html).
A low instantaneous RSS sample cannot establish absence of resource contention.

Monitor the telemetry pipeline itself: exporter queue occupancy, refused data,
enqueue failures, send failures and collection freshness. The
[Collector scaling guidance](https://opentelemetry.io/docs/collector/scaling/)
explains why adding queue capacity alone can worsen memory pressure. Durable queue
storage and recovery, retention, sampling policy and alert routing belong to the
operator's control plane; see [Collector resiliency](https://opentelemetry.io/docs/collector/resiliency/).
Telemetry is operational evidence and never substitutes for signed execution receipts.

This change provides runtime resource observations and preserves existing trace
instrumentation. Full HTTP/network/disk-capacity coverage, arbitrary pod-cgroup
discovery, continuous profiling, operation-by-operation coverage, collector loss
acceptance and live guest delivery remain separate work. Registration and fixture
export tests do not establish that a deployed collector is receiving these signals.

The proxy also has a subprocess test that starts the real metric exporter inside
Tokio and checks a loopback HTTP receiver gets `/v1/metrics` and the resource-health
instrument. HTTP exporters let the SDK resolve generic and signal-specific endpoint
environment variables; setting a generic base URL programmatically would bypass
OTLP's signal suffix. This confirms local delivery, not deployed guest routing.
