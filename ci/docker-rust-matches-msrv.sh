#!/usr/bin/env bash
# The Dockerfiles' Rust base must be at least the workspace MSRV.
#
# WHY: they pinned `rust:1.88-bookworm` while the workspace requires 1.95, so
# `cargo chef cook` died with:
#
#   portcullis@0.0.1 requires rustc 1.93
#   portcullis-effects@0.0.1 requires rustc 1.95
#
# Both image builds had been failing since the MSRV moved past 1.88. Nobody saw
# it because docker.yml runs on `v*` tags only, so the images are built when a
# release is cut and at no other time — the same reason the rootfs inputs and
# the macOS build could rot unnoticed.
#
# Two facts in two files that must agree: `rust-version` in Cargo.toml and the
# base image tag. That is the shape that drifts.
set -euo pipefail
cd "$(dirname "$0")/.."

msrv=$(grep -m1 '^rust-version = ' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
[ -n "$msrv" ] || { echo "::error::could not read rust-version from Cargo.toml"; exit 1; }
msrv_major=${msrv%%.*}; msrv_minor=$(echo "$msrv" | cut -d. -f2)

fail=0
checked=0
for f in docker/Dockerfile*; do
  while read -r ver; do
    checked=$((checked + 1))
    maj=${ver%%.*}; min=$(echo "$ver" | cut -d. -f2)
    if [ "$maj" -lt "$msrv_major" ] || { [ "$maj" -eq "$msrv_major" ] && [ "$min" -lt "$msrv_minor" ]; }; then
      echo "::error::$f pins rust:$ver but the workspace MSRV is $msrv — cargo will refuse to build"
      fail=1
    fi
  done < <(grep -oE '^FROM rust:[0-9]+\.[0-9]+' "$f" 2>/dev/null | sed 's/^FROM rust://')
done

# Non-vacuity: there ARE Rust stages. A parse that finds none would otherwise
# pass by checking nothing.
if [ "$checked" -eq 0 ]; then
  echo "::error::no 'FROM rust:<version>' stages found in docker/ — this check would be vacuous"
  exit 1
fi

[ "$fail" -eq 0 ] && echo "ok: all $checked Rust stages are >= MSRV $msrv"
exit $fail
