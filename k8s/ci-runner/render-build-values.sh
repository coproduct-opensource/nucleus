#!/usr/bin/env bash
# Render values-build.yaml (the `nucleus-k3s-build` pool) from values.yaml.
# Helm replaces YAML lists wholesale, so the build pool cannot be a small
# overlay on top of the base file: it is the base file with the pool name,
# runner count, cargo parallelism and resources swapped. Re-run after editing
# values.yaml; ci checks the two do not drift (k8s/ci-runner/README.md).
set -euo pipefail
cd "$(dirname "$0")"
{
  cat <<'HDR'
# DERIVED from values.yaml by k8s/ci-runner/render-build-values.sh — do not
# hand-edit. The `nucleus-k3s-build` pool: 3 big runners for the compile-class
# jobs (see values.yaml for the two-pool rationale).
#
#   helm upgrade --install nucleus-k3s-build \
#     oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
#     --version 0.14.2 -n arc-runners -f k8s/ci-runner/values-build.yaml
HDR
  sed -e 's/^runnerScaleSetName: nucleus-k3s$/runnerScaleSetName: nucleus-k3s-build/' \
      -e 's/^maxRunners: 8$/maxRunners: 3/' \
      -e '/name: CARGO_BUILD_JOBS/{n;s/value: "2"/value: "3"/;}' \
      -e '/^          requests:$/,/^          limits:$/{s/cpu: "500m"/cpu: "2500m"/;s/memory: 1Gi/memory: 5Gi/;}' \
      -e '/^          limits:$/,/^        volumeMounts:$/{s/cpu: "2"/cpu: "4"/;s/memory: 3Gi/memory: 8Gi/;}' \
      values.yaml
} > values-build.yaml
echo "rendered values-build.yaml"
