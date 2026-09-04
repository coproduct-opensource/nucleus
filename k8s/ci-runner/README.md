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
| Runner image | `docker/Dockerfile.runner` (OS deps + sccache + just; nothing else) |
| Scale-set values | `values.yaml` (no credential; references the `gh-token` secret) |
| Persistent mounts | `/var/lib/nucleus-ci/{rustup,cargo,cache,elan}` on the node, uid 1001 |
| Warm-up | `warm.sh` (installs rustup 1.96.1 + elan/Lean v4.30.0-rc2 into the mounts) |

The toolchains and caches are on the mounts, not in the image, so an image
rebuild never invalidates a cache and a toolchain bump never needs one.
`sccache` (`RUSTC_WRAPPER`) is the cross-job compile cache; the cargo registry
and the Mathlib `lake exe cache` store are persistent for the same reason.

## Setup on the node (Lima `pci-k3s`)

```sh
# 0. tools (once): podman to build, k3s's containerd to run
sudo apt-get install -y podman

# 1. build the image for the node's architecture and hand it to k3s
podman build -f docker/Dockerfile.runner -t localhost/nucleus-ci-runner:0.1.0 .
podman save localhost/nucleus-ci-runner:0.1.0 | sudo k3s ctr -n k8s.io images import -

# 2. persistent mounts + toolchains
sudo bash k8s/ci-runner/warm.sh

# 3. the scale set (controller `arc` in arc-systems is already installed)
sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml helm upgrade --install nucleus-k3s \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --version 0.14.2 -n arc-runners -f k8s/ci-runner/values.yaml
```

Then set the repo variable: `gh variable set CI_RUNNER --body nucleus-k3s`.

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
