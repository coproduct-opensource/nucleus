# The Fly runner pool

Measured on 2026-09-09, before this lane: every job on every workflow ran on GitHub-hosted
`ubuntu-latest` (the `CI_RUNNER` variables were unset), and the account's hosted concurrency
was the whole bottleneck. One green merge-group CI run (#7167) was 33 jobs with 44 minutes of
work and 401 minutes of queue wait; 27 of the 33 jobs run in 90 seconds or less and waited 10
to 18 minutes each for a slot. Open pull requests sat "queued" for an hour before their first
job started; 6-second gate jobs waited 44 to 60 minutes. The merge queue moved one entry every
30 to 180 minutes, entirely because its runs waited behind everyone else's.

The fix is capacity that does not count against hosted concurrency: self-hosted runners on
Fly Machines, warm, bounded, one job per boot, taking every job on a label for every event.

## How it works

The manager (`crates/ci-fly-runner`, one shared-CPU Machine, no public service) holds the
administrative credentials and runs a pass every `POLL_SECONDS`. A pass reads the world once,
plans over that snapshot, and applies the plan — the planner is pure and the API calls are the
only effects, because the two ways a loop like this loses a job are both orderings a planner
cannot express: retiring a machine the same pass just handed a job to, and reaping a runner
registration the same pass just created (a registration is `offline` until its guest boots).

1. **Demand**: queued jobs per label across the most recent `LOOKBACK_RUNS` runs of every
   workflow and event, with conditional requests (an unchanged answer is a 304 that costs no
   rate limit).
2. **Warm starts**: each pool is a fixed set of Machines that cycle created → stopped →
   started → stopped. A Machine is created in one pass and first booted in a later one — a
   start issued in the pass that created it races Fly's placement and is answered 412 — and
   that first boot is a warm-up unless a job is already waiting, in which case it takes the job
   and pulls its image on the way. A stopped Machine keeps its root filesystem on its host, so starting it takes
   about a second and pulls nothing. Before each start the manager writes that boot's one-job
   JIT runner configuration into the Machine (`/run/runner-jit`); the runner exits after the
   job and the Machine stops. A Machine that boots without a configuration is a warm-up: it
   exits at once, image now cached on the host.
3. **Bounds**: `size` Machines per pool at most, `standby` of them kept stopped-and-warm even
   with no demand; the rest are destroyed after `IDLE_MINUTES` stopped and re-created when
   demand returns. Nothing autoscales past `size`.
4. **Hygiene**: JIT runners are removed by GitHub after their job. A registration is read as
   orphaned only when it is offline, unclaimed by any Machine that is up, and older than the
   grace period in the manager's own issuance ledger — never merely "offline and not busy",
   which is what every registration looks like for the seconds after it is issued.

Workers receive exactly one JIT configuration and never a GitHub or Fly token. A build pool
Machine owns one volume at `/data` for its sccache store and cargo registry cache (never a
checkout, toolchain or executable); a gate pool Machine has no volume.

## Pools (manager.toml `POOLS`)

| pool | label | Machine | jobs |
|---|---|---|---|
| build | `nucleus-fly-build` | performance-8x, 32 GB, one 40 GB volume each; size 4, standby 2 | everything on `CI_BUILD_RUNNER`: workspace tests, clippy, live-path gates, hack, llvm-cov, dylint, the A2A example (27 `runs-on` sites) |
| gate | `nucleus-fly-gate` | shared-cpu-2x, 4 GB, no volume; size 12, standby 4 | everything on `CI_RUNNER` (52 sites), opt-in |

Routing is the two repository variables the workflows already read:

```sh
gh variable set CI_BUILD_RUNNER --repo coproduct-opensource/nucleus --body nucleus-fly-build
# second lever, after the build pool has run a day of jobs cleanly:
gh variable set CI_RUNNER --repo coproduct-opensource/nucleus --body nucleus-fly-gate
```

The build pool alone removes the jobs that hold a hosted slot for 6 to 12 minutes; the short
jobs left on hosted runners then flow. The gate pool takes the rest. Jobs that hard-code
`ubuntu-latest` (44 sites) or `ubuntu-24.04` (13) stay hosted; those are the ones that need
Docker, CodeQL or a hosted-only tool. The image here is a Rust build image (pinned
toolchain, wasm target, clippy, rustfmt, nextest, sccache, just, node via `setup-node`,
python3); a job on `CI_RUNNER` that needs elan, aeneas or kani installs it in-job today on
hosted runners and keeps doing so here.

## Provision

```sh
cd ci/fly-runner
fly apps create nucleus-fly-build --org personal
fly apps create nucleus-fly-runner-manager --org personal
fly deploy --config fly.toml --build-only --push --remote-only --yes      # prints the image digest
for i in 0 1 2 3; do
  fly volumes create runner_cache_$i -a nucleus-fly-build --region iad --size 40 \
    --vm-cpu-kind performance --vm-cpus 8 --vm-memory 32768
done
```

Manager secrets, via stdin (`fly secrets import -a nucleus-fly-runner-manager`), never on a
command line or in a tracked file:

- `GITHUB_TOKEN`: a fine-grained token on this repository with `administration: write`
  (runner registration) and `actions: read` (queue polling), nothing else.
- `FLY_API_TOKEN`: an app-scoped deploy token for `nucleus-fly-build` only.
- `RUNNER_IMAGE`: the built image by digest, `registry.fly.io/nucleus-fly-build@sha256:…`.
- `POOLS`: the tracked default from `manager.toml` with the four volume ids added to the
  build pool as `"volumes": ["vol_…", …]` (one per Machine, in index order).

```sh
# from the repository root: the manager is a workspace member, so its build context is the tree
fly deploy . --config ci/fly-runner/manager.toml --remote-only --ha=false --yes
```

Then: dispatch `runner-smoke.yml` with `runner=nucleus-fly-build`, read its cold and warm
timings and the sccache line the job hook prints, and set `CI_BUILD_RUNNER`. The manager's
log (`fly logs -a nucleus-fly-runner-manager`) shows every start, warm-up and retirement.

## Cost and capacity

Stopped Machines cost their root filesystem only. Running: performance-8x is billed per second
while a build runs (a 5-minute clippy or a 10-minute test job is cents); shared-cpu-2x gate
Machines are a fraction of a cent per job. Volumes: 4 × 40 GB × $0.15 = $24/month standing.
Compare: the same jobs on hosted runners cost nothing in dollars and everything in hours.

The merge queue's own throughput is bounded by `ci/merge-queue.toml` (`max_entries_to_build
= 1`, so one merge-group run at a time, ALLGREEN): once a run is 10 minutes instead of 60 to
180, that is 6 merges an hour. Raising `max_entries_to_build` is a separate, theorem-checked
change (the capacity hypotheses in `ci/lean/CiSpec/Capacity.lean` and `live-parity`).

## Rollback

Unset `CI_BUILD_RUNNER` (and `CI_RUNNER`): new jobs use hosted runners; jobs already queued
on a pool label keep it until their run is re-created. `fly machine stop` the manager to stop
new starts; running jobs finish on their own. Destroy the worker Machines and volumes only when
abandoning the pool (stopped Machines and volumes keep billing storage). No branch protection,
required context or queue setting is touched by any of this.

## Local validation

```sh
cargo test -p ci-fly-runner --locked      # 22 tests: planning, applying, the client, the two races
bash -n ci/fly-runner/entrypoint.sh
bash -n ci/fly-runner/install-tools.sh
cargo test -p ci-spec --locked            # the runs-on routing this lane depends on
```

The two ordering tests (`a_machine_launched_this_pass_is_never_also_retired`,
`a_registration_whose_machine_is_coming_up_is_not_an_orphan`) are red against the mutate-as-you-go
shape and green against the planner; the other eighteen do not move between the two. Both failures
they pin are silent — a job that is never taken and a machine destroyed mid-start look like a slow
queue, not like a bug.
