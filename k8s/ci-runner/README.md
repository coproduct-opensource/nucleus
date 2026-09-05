# Self-hosted CI runners: `nucleus-k3s`

An actions-runner-controller (ARC 0.14.2) runner scale set on a k3s node,
so CI jobs stop waiting on GitHub's shared runner pool. Jobs opt in with
`runs-on: nucleus-k3s`; this repo's workflows spell it
`runs-on: ${{ vars.CI_RUNNER || 'ubuntu-latest' }}`, so the repo variable
`CI_RUNNER` is the one switch: set to `nucleus-k3s` to route, unset to fall
back to hosted runners.

## What is where

| Piece | Location |
|---|---|
| Runner image | `docker/Dockerfile.runner` (OS deps, sccache, just, and every pinned Rust toolchain baked in per runner user) |
| Scale-set values | `values.yaml` (the `nucleus-k3s` gate pool, 8 small runners) and `values-build.yaml` (the `nucleus-k3s-build` pool, 3 big runners; DERIVED by `render-build-values.sh`, never hand-edited); no credential, both reference the `gh-token` secret |
| Persistent mounts | `/var/lib/nucleus-ci/cargo/registry/{cache,index}` and `/var/lib/nucleus-ci/cache` on the node, uid 1001 (immutable caches only; `registry/src` and the whole cargo git db are per pod) |
| Warm-up | `warm.sh` (installs rustup 1.96.1 + elan/Lean v4.30.0-rc2 into the mounts) |
| Job hooks | `hooks/job-started.sh`, `hooks/job-completed.sh` (ConfigMap `runner-hooks`; sccache hit rate and cgroup peaks per job) |
| Timing report | `cargo xtask ci-timings --sha <commit>` (per-label run/queue distributions, critical path, longest steps) |

Toolchains are in the image and nothing mutable under `~/.rustup` or
`~/.cargo/bin` is shared: the first cohort runs shared them and one job's
`rustup override`, plus a concurrent rustup reinstall, intermittently broke
every other job. Only the caches are on the mounts, so an image rebuild never
invalidates a cache.
`sccache` (`RUSTC_WRAPPER`) is the cross-job compile cache; the cargo registry
and the Mathlib `lake exe cache` store are persistent for the same reason.

## Setup on the node (Lima `pci-k3s`)

```sh
# 0. tools (once): podman to build, k3s's containerd to run
sudo apt-get install -y podman

# 1. build the image for the node's architecture and hand it to k3s
podman build -f docker/Dockerfile.runner -t localhost/nucleus-ci-runner:0.2.4 .
podman save localhost/nucleus-ci-runner:0.2.4 | sudo k3s ctr -n k8s.io images import -

# 2. persistent mounts + toolchains
sudo bash k8s/ci-runner/warm.sh

# 3. the job hooks (per-job sccache hit rate + pod resource peaks in every job log)
#    and the per-pod cargo config (lld for the host target; see cargo-config.toml)
sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl create configmap runner-cargo-config \
  -n arc-runners --from-file=config.toml=k8s/ci-runner/cargo-config.toml --dry-run=client -o yaml \
  | sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl apply -f -
sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl create configmap runner-hooks \
  -n arc-runners --from-file=k8s/ci-runner/hooks/ --dry-run=client -o yaml \
  | sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl apply -f -

# 4. the scale set (controller `arc` in arc-systems is already installed)
sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml helm upgrade --install nucleus-k3s \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --version 0.14.2 -n arc-runners -f k8s/ci-runner/values.yaml
```

Install the build pool the same way with `-f k8s/ci-runner/values-build.yaml`
and release name `nucleus-k3s-build`.

Then set the repo variables: `gh variable set CI_RUNNER --body nucleus-k3s` and
`gh variable set CI_BUILD_RUNNER --body nucleus-k3s-build`. Heavy jobs spell
`runs-on: ${{ vars.CI_BUILD_RUNNER || vars.CI_RUNNER || 'ubuntu-latest' }}`, so
unsetting `CI_BUILD_RUNNER` alone folds them back into the gate pool.

## What runs here and what stays hosted

Routed (cohort 1): the pure Rust and Lean jobs — `ci.yml`, the ratchets, the
feature matrix, dylint, scans, and the Lean builds that do not download the
x86-only Charon/Aeneas binaries.

Stays hosted: anything needing docker-in-docker, KVM, a network namespace,
or an x86-only prebuilt (quickstart-boot, release, tpm-and-net-isolation,
the Aeneas extraction jobs, Kani until validated under sccache, CodeQL,
scorecard).

## Security note

This is a public repository with a self-hosted runner. The repo's fork
approval policy must be "all outside collaborators", so a fork's workflow
never runs here without a maintainer clicking approve. The runner pods are
ephemeral and unprivileged; step 3 of the plan (a nucleus microVM per job)
is the real isolation boundary and is tracked separately.
