#!/usr/bin/env bash
# Pre-populate the persistent runner mounts on the k3s node so the FIRST CI job
# on a fresh node does not spend its time installing toolchains. Idempotent.
# Run ON THE NODE (inside the Lima VM) as root, after the image is imported:
#
#   sudo bash k8s/ci-runner/warm.sh
#
# Everything installs as uid 1001 (the image's `runner` user) into the same
# host paths the scale set mounts (values.yaml), via a throwaway podman
# container of the runner image itself, so what the warm step produces is
# exactly what a runner pod sees.
set -euo pipefail

IMAGE="${IMAGE:-localhost/nucleus-ci-runner:0.1.2}"
ROOT="${ROOT:-/var/lib/nucleus-ci}"
RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-1.96.1}"   # rust-toolchain.toml
LEAN_TOOLCHAIN="${LEAN_TOOLCHAIN:-leanprover/lean4:v4.30.0-rc2}"  # every lean-toolchain in the tree

mkdir -p "$ROOT"/{rustup,cargo,cache,elan}
chown -R 1001:1001 "$ROOT"

podman run --rm --user 1001:1001 \
  -e HOME=/home/runner \
  -v "$ROOT/rustup:/home/runner/.rustup" \
  -v "$ROOT/cargo:/home/runner/.cargo" \
  -v "$ROOT/cache:/home/runner/.cache" \
  -v "$ROOT/elan:/home/runner/.elan" \
  "$IMAGE" bash -euxo pipefail -c '
    if ! command -v rustup >/dev/null; then
      curl -fsSL https://sh.rustup.rs | sh -s -- -y --no-modify-path \
        --default-toolchain "'"$RUST_TOOLCHAIN"'" -c clippy -c rustfmt
    fi
    rustup toolchain install "'"$RUST_TOOLCHAIN"'" -c clippy -c rustfmt
    rustup target add x86_64-unknown-linux-musl wasm32-unknown-unknown --toolchain "'"$RUST_TOOLCHAIN"'"
    if ! command -v elan >/dev/null; then
      curl -fsSL https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh \
        | sh -s -- -y --no-modify-path --default-toolchain "'"$LEAN_TOOLCHAIN"'"
    fi
    elan toolchain install "'"$LEAN_TOOLCHAIN"'"
    rustc --version; cargo --version; lean --version
  '
echo "warm: $ROOT populated for uid 1001"
