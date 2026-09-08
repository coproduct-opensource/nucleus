#!/usr/bin/env bash
# The delegation compiler is offline by construction.
#
# `nucleus-task-compiler` turns a goal into a minimum-authority grant from
# the repository on disk and the effect catalog. It must never open a socket:
# the whole point of the pluggable proposer being a child process is that an
# LLM-backed proposer lives OUTSIDE nucleus (vendor neutrality, CLAUDE.md)
# and outside this crate's dependency closure. A network crate appearing in
# any of its dependency tables, or a socket type in its sources, is the
# compiler acquiring a way to phone home — red, not a warning.
#
# Text-level on purpose: no cargo invocation, so the gate-of-gates
# (scripts/check-gates-can-fail.sh) can perturb Cargo.toml and restore it
# without touching Cargo.lock.
#
# Usage: scripts/check-task-compiler-offline.sh

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
crate="$root/crates/nucleus-task-compiler"
manifest="$crate/Cargo.toml"
src="$crate/src"

if [[ ! -f "$manifest" ]]; then
    echo "::error::$manifest not found"
    exit 1
fi

# Crates that open sockets or embed an async runtime that does.
NETWORK_CRATES=(reqwest ureq hyper hyper-util tokio tonic iroh curl isahc surf async-std axum h2 rustls)

fail=0

# Every dependency table: [dependencies], [dev-dependencies],
# [build-dependencies], and target-specific variants.
tables="$(awk '
    /^\[.*dependencies.*\]/ { in_deps = 1; next }
    /^\[/                    { in_deps = 0 }
    in_deps && /^[A-Za-z0-9_-]+[[:space:]]*=/ { print $1 }
' "$manifest")"

for c in "${NETWORK_CRATES[@]}"; do
    if printf '%s\n' "$tables" | grep -qx -- "$c"; then
        echo "::error::crates/nucleus-task-compiler/Cargo.toml depends on '$c' — the task compiler must stay offline"
        fail=1
    fi
done

if grep -rnE 'std::net|TcpStream|TcpListener|UdpSocket|UnixStream' "$src" >/dev/null; then
    echo "::error::crates/nucleus-task-compiler/src reaches for a socket type:"
    grep -rnE 'std::net|TcpStream|TcpListener|UdpSocket|UnixStream' "$src" || true
    fail=1
fi

if [[ "$fail" -ne 0 ]]; then
    exit 1
fi

echo "OK: nucleus-task-compiler names no network crate and no socket type"
