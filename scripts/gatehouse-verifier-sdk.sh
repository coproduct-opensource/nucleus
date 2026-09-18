#!/bin/sh
# Build sdks/verifier-js the way nucleus's canonical CI builder does, so that
# crates/nucleus-verifier-service/embedded-wasm.pins verify on a builder that is not that
# runner — gatehouse's arm64 Firecracker gate lane.
#
# Four things decide the bytes (measured 2026-09-17, gatehouse probe/wasm-repro): the source
# paths the compiler sees, the host triple cargo hashes into -C metadata
# (rust-lang/cargo#13922), the wasm-bindgen binary (the official release stamps its commit into
# the producers section) and wasm-opt (pinned by wasm-pack 0.13.1). The gate image provides the
# builder's paths, the release wasm-bindgen and a rustc that reports the builder's host to
# cargo; this script mounts the source where the builder had it and builds there.
#
# Anywhere without that image (a developer machine, the GitHub shadow lane) it is the plain
# build CI runs.
set -eu
tools=/opt/gate-tools
if [ ! -f "$tools/pins.json" ] || [ ! -x "$tools/bin/rustc-ci-host" ]; then
  exec wasm-pack build sdks/verifier-js --target web --release
fi
# The manifest is JSON, so read it with a JSON parser when the image has one. The sed fallback
# tolerates whitespace around the colon, which the first version did not: the gate tools image
# started pretty-printing pins.json on 2026-09-17 and `"ci_workspace": "..."` stopped matching
# `"ci_workspace":"..."`. The field came back empty, the bind mount target was the empty string,
# and every clippy and test-core run failed with `mount: : mount point does not exist` followed by
# cargo resolving the workspace root as a registry. A parser that only works for one pretty-printer
# is a contract nobody wrote down.
field() {
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg k "$1" '.[$k] // empty' "$tools/pins.json"
  else
    sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$tools/pins.json"
  fi
}
workspace=$(field ci_workspace)
registry=$(field ci_registry)
test -n "$workspace" && test -n "$registry"
mkdir -p /work/.cache /work/cargo-js
cp -a "$tools/cache/." /work/.cache/
sed "s#^directory = .*#directory = \"$registry\"#" /opt/nucleus-build/cargo-js/config.toml > /work/cargo-js/config.toml
exec unshare -Urm sh -c '
  mount --bind "$1" "$2"
  cd "$2"
  exec env -u CARGO_TARGET_DIR RUSTC=/opt/gate-tools/bin/rustc-ci-host RUSTUP_HOME=/usr/local/rustup \
    RUSTUP_TOOLCHAIN=1.96.1 CARGO_HOME=/work/cargo-js XDG_CACHE_HOME=/work/.cache \
    wasm-pack build sdks/verifier-js --target web --release' sh "$(pwd -P)" "$workspace"
