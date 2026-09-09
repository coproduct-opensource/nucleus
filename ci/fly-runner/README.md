# Fly merge build lane

Prepared 2026-09-08. Deployment and measured image size are pending infrastructure approval.

GitHub still owns nucleus's merge queue and all required checks. Only the workspace-test and
Clippy jobs in `ci.yml`, on `merge_group`, opt into `CI_FLY_MERGE_BUILD_RUNNER`. An unset
variable keeps their current routing. PR and push workloads keep their existing runners.

## Image assessment

The existing `docker/Dockerfile.runner` is documented as 11.4 GB in the ARC configuration.
It already preinstalls toolchains, uses sccache with incremental compilation disabled, uses
lld and reduced debug information, and keeps mutable toolchains private to each runner.
Its size comes partly from carrying the Rust, Lean, Aeneas, MSRV and cross-compilation lanes
in one image. It is tuned for warm job throughput, not image size or pull latency.

The separate `.gatehouse/Dockerfile.gate` is an offline executor environment, not an Actions
runner. It vendors ~1.7 GB of sources, but `COPY crates` invalidates the vendor stage on source
changes. Its `/warm` source copies are in separate layers from the command that deletes them,
so those source bytes remain in the distributed image. Its claim that a vendor directory
cannot contain multiple versions is incorrect: Cargo supports this and `cargo vendor --sync`
can unify workspace and SDK stores. These are opportunities for a separate hermetic-image
change; changing that image requires updating gate environment digests and receipts.

This Fly lane has one pinned Rust toolchain, wasm target, Clippy, rustfmt, prebuilt nextest,
sccache and just, and native build dependencies. It does not carry unrelated proof toolchains
or nucleus source. Build context is restricted to this directory's explicit allowlist.
Do not report a size or speed improvement until the image is built and cold/warm timings
are collected on Fly.

Primary references checked:

- [Docker cache optimization](https://docs.docker.com/build/cache/optimize/): stable dependency
  layers, small contexts, cache mounts, external caches.
- [Cargo vendor](https://doc.rust-lang.org/stable/cargo/commands/cargo-vendor.html): `--sync`
  and versioned directories for multiple dependency graphs.
- [sccache Rust constraints](https://github.com/mozilla/sccache/blob/main/docs/Rust.md): disable
  incremental compilation; cache compatibility includes compiler and compilation inputs.
- [GitHub self-hosted runners](https://docs.github.com/en/actions/reference/runners/self-hosted-runners):
  ephemeral/JIT jobs; ARC or the Scale Set Client for larger fleets.
- [Fly CPU](https://fly.io/docs/machines/cpu-performance/) and
  [volume limits](https://fly.io/docs/volumes/overview/): sustained compilation needs adequate
  CPU and disk bandwidth, not just nominal vCPU count.

## Deployment shape

Two apps in Fly organization `personal`, region `iad`:

- `nucleus-fly-build`: at most two job Machines, each 4 performance CPUs / 16 GiB, with one
  exclusive 80 GB cache/work volume per slot. Each Machine is created for one JIT runner,
  exits after one job, has a 60-minute lifetime limit, and is destroyed by the manager.
- `nucleus-fly-runner-manager`: one 256 MiB shared-CPU Machine, no public service. Polls the
  two relevant workflow types every 30 seconds. Holds GitHub runner-administration and
  Fly worker-app credentials; neither credential is sent to workers. Workers receive only
  a one-job JIT configuration. Use a repository-scoped GitHub credential and an app-scoped
  Fly deploy token for the worker app.

The volume preserves a 12 GB sccache and Cargo archive cache. Workspaces are deleted at boot.
Toolchains, registry source extractions, Git checkouts and Cargo executables are not shared.
This pool is for trusted merge-group revisions, not arbitrary PR runs. The manager accepts
manual smoke runs as well. Job hooks report cache hits and resource usage to GitHub logs;
manager lifecycle events go to Fly logs. Worker diagnostic log retention beyond those job
logs remains an operational follow-up before expanding this lane.

Storage: 160 GB provisioned × $0.15/GB-month = $24/month, even with no jobs. Worker CPU/RAM
is billed only while running; manager, remote image builds, snapshots and transfer add cost.
See [Fly pricing](https://fly.io/docs/about/pricing/). The proposed maximum is two workers,
not an unlimited autoscaler.

## Provision and validate

Run from this directory after approval:

```sh
fly apps create nucleus-fly-build --org personal
fly apps create nucleus-fly-runner-manager --org personal
fly deploy --config fly.toml --build-only --push --remote-only --yes
fly volumes create runner_cache_a -a nucleus-fly-build --region iad --size 80 --vm-cpu-kind performance --vm-cpus 4 --vm-memory 16384
fly volumes create runner_cache_b -a nucleus-fly-build --region iad --size 80 --vm-cpu-kind performance --vm-cpus 4 --vm-memory 16384
```

Set manager secrets via stdin (`fly secrets import`), never command-line literals or a tracked
file: `GITHUB_TOKEN`, `FLY_API_TOKEN`, `RUNNER_IMAGE` (the built image's `@sha256:` reference),
and `RUNNER_VOLUMES` (JSON array of the two `{id, region}` objects). Use one manager Machine:

```sh
fly deploy --config manager.toml --remote-only --ha=false --yes
```

After this PR lands, dispatch `runner-smoke.yml` with input `runner=nucleus-fly-build`.
Inspect both its cold and warm build, cache hits, CPU/memory peaks, disk use, and runner
cleanup. Then enable only the reviewed merge-group lane:

```sh
gh variable set CI_FLY_MERGE_BUILD_RUNNER --repo coproduct-opensource/nucleus --body nucleus-fly-build
```

Before the smoke-workflow input is on main, its existing fixed `nucleus-k3s` label can be
used for the manual smoke by temporarily setting the manager's `RUNNER_LABEL` to that label.
Restore `nucleus-fly-build` before enabling merge routing. No CI_RUNNER or CI_BUILD_RUNNER
change is needed.

## Rollback

Delete `CI_FLY_MERGE_BUILD_RUNNER`. Newly created merge-group jobs use the existing hosted
fallback. Already queued jobs retain their labels; re-create their queue run if necessary.
Stop the manager to stop new worker creation; let active jobs finish. Remove idle worker
Machines and cache volumes if abandoning the pool (stopped volumes continue billing).
No branch protections, required contexts, or queue-owner settings change.

## Local validation

```sh
python3 -m unittest discover -s ci/fly-runner -p 'test_*.py'
bash -n ci/fly-runner/entrypoint.sh
cargo test -p ci-spec --locked
```
