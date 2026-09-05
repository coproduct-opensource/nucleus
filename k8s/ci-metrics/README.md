# CI throughput metrics (OpenTelemetry)

Why: on 2026-09-05 a rebase wave of eight PRs took over an hour and the only
way to know why was `kubectl get ephemeralrunners` by hand. This is the
instrumented answer: how long jobs wait for a runner, how long they run, how
busy each pool is, how deep the merge queue is — as time series, on one
dashboard.

## Two halves, one collector

| half | source | how it gets in |
| --- | --- | --- |
| runner side | actions-runner-controller listeners + controller (`gha_*`: assigned/running jobs, busy/idle/desired runners, job start-up and execution histograms) | the collector's `prometheus` receiver scrapes them via pod discovery in `arc-systems`; the controller chart must have `metrics:` set (`k8s/ci-runner/README.md`) |
| GitHub side | the Actions API: per-job `created_at` → `started_at` (queue wait) → `completed_at` (duration), conclusion, workflow, event; merge-queue depth | `cargo xtask ci-otel` pushes OTLP/HTTP JSON every 15 min from `.github/workflows/ci-metrics.yml` (self-hosted pool only: the collector is in-cluster) |

Collector → Prometheus (remote write, 60-day retention on a `local-path` PVC)
→ Grafana with the provisioned **CI throughput** dashboard.

## Deploy / update (on the `pci-k3s` Lima VM)

```sh
for f in k8s/ci-metrics/*.yaml; do limactl copy "$f" "pci-k3s:/tmp/ci-metrics/$(basename "$f")"; done
limactl copy k8s/ci-metrics/dashboards/ci-throughput.json pci-k3s:/tmp/ci-metrics/ci-throughput.json
limactl shell pci-k3s -- sudo kubectl apply -f /tmp/ci-metrics/00-namespace-rbac.yaml
# once: the Grafana admin password
limactl shell pci-k3s -- sudo kubectl -n ci-metrics create secret generic grafana-admin --from-literal=password="$(openssl rand -hex 12)"
limactl shell pci-k3s -- sudo kubectl -n ci-metrics create configmap grafana-dashboards \
  --from-file=ci-throughput.json=/tmp/ci-metrics/ci-throughput.json --dry-run=client -o yaml \
  | limactl shell pci-k3s -- sudo kubectl apply -f -
limactl shell pci-k3s -- sudo kubectl apply -f /tmp/ci-metrics/10-otel-collector.yaml \
  -f /tmp/ci-metrics/20-prometheus.yaml -f /tmp/ci-metrics/30-grafana.yaml
```

Lima forwards the NodePorts to the host:

| what | URL |
| --- | --- |
| Grafana (anonymous Viewer; admin = the secret above) | http://localhost:30300/d/ci-throughput |
| Prometheus | http://localhost:30909 |
| OTLP/HTTP (for a backfill from the host) | http://localhost:30318 |

## Backfill / local run

```sh
cargo xtask ci-otel --since 1440 --endpoint http://localhost:30318   # last 24 h
cargo xtask ci-otel --since 60 --dry-run                              # print the OTLP JSON
```

The xtask reports delta histograms for its window; the collector's
`deltatocumulative` processor makes them cumulative. Overlapping windows
double-count at the edges, so backfill once, then let the schedule run.

## Reading it

- **Jobs queued for a runner** (ARC `assigned − running`) rising while
  **busy / max** sits at 1.0 is the pool saturated; the fix is fewer or shorter
  jobs, not (on this VM) more runners — see the sizing note in
  `k8s/ci-runner/README.md`.
- **Job queue wait p95 by runner pool** is the same fact from GitHub's side,
  including hosted runners.
- **Workflow duration p95 by event** separates pull_request (scoped) from
  merge_group (full workspace) and push.
