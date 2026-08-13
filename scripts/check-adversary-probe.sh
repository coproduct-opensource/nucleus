#!/usr/bin/env bash
# Host-side falsifier for nucleus-adversary-probe.
#
# WHY THIS EXISTS
#
# The adversary probe's real verdict is earned INSIDE a booted microVM, where it
# runs as the pod workload and the sandbox is live (brick 2 wires a boot-lane
# assertion in quickstart-boot.yml). But that job boots on x86_64 CI and is NOT a
# required check — so on its own the probe could silently rot: a refactor that made
# it always CONTAINED, or that dropped the anti-vacuity control, would red nothing
# that blocks a merge.
#
# This gate closes that gap WITHOUT a boot, by reconstructing each attack surface
# hermetically (env overrides the probe exposes for exactly this) and asserting the
# campaign's verdict logic across the three states a real probe must distinguish:
#
#   1. CONFINED           -> CONTAINED  (every attack attempted and blocked)
#   2a SECRET READABLE    -> BREACH:pid1-secret-theft   (reds-on-regression)
#   2b ROOTFS WRITABLE    -> BREACH:rootfs-tamper        (reds-on-regression)
#   2c EGRESS REACHABLE   -> BREACH:exfil                (reds-on-regression)
#   3. CONTROL DEAD       -> INCONCLUSIVE, never CONTAINED   (anti-vacuity)
#
# Plus a META-ANTI-LEAK assertion: in the secret-breach state the probe must report
# the breach WITHOUT ever echoing the secret VALUE — a probe that leaks the secret
# to its own (host-readable) console has itself become the exfil channel.
#
# Usage: scripts/check-adversary-probe.sh
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

failures=0
fail() { echo "  FAIL  $1"; failures=$((failures + 1)); }
ok() { echo "  ok    $1"; }

# ── Locate (or build) the probe binary ──────────────────────────────────────
BIN="${ADVERSARY_PROBE_BIN:-}"
if [[ -z "$BIN" ]]; then
    for cand in \
        target/release/nucleus-adversary-probe \
        target/debug/nucleus-adversary-probe \
        target/*/release/nucleus-adversary-probe \
        target/*/debug/nucleus-adversary-probe; do
        [[ -x "$cand" ]] && {
            BIN="$cand"
            break
        }
    done
fi
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
    echo "building nucleus-adversary-probe…"
    cargo build -q -p nucleus-adversary-probe || {
        echo "ERROR: build failed"
        exit 1
    }
    BIN=target/debug/nucleus-adversary-probe
fi
echo "probe: $BIN"

WORK="$(mktemp -d)"
LISTENER_PID=""
cleanup() {
    [[ -n "$LISTENER_PID" ]] && kill "$LISTENER_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# Shared safe defaults for a CONFINED run. WRITE_TARGET=/proc gives a path that is
# non-writable even for root (proc rejects the create), so the confined state holds
# regardless of the CI uid; the TEST-NET-3 address (RFC 5737) is guaranteed
# non-routable so the exfil connect fails without a netns.
CONFINED_ENV=(
    "NUCLEUS_TOOL_PROXY_URL=http://mediator.invalid"
    "NUCLEUS_ADVERSARY_PID1_ENVIRON=/dev/null"
    "NUCLEUS_ADVERSARY_WRITE_TARGET=/proc"
    "NUCLEUS_ADVERSARY_DENY_TARGETS=203.0.113.1:443"
    "NUCLEUS_ADVERSARY_TIMEOUT_MS=400"
)

# run_probe <extra KEY=VAL>... -> writes combined stdout+stderr to $OUT, sets $RC
run_probe() {
    OUT="$WORK/out"
    env -i "${CONFINED_ENV[@]}" "$@" "$BIN" >"$OUT" 2>&1
    RC=$?
}

# ── State 1: CONFINED -> CONTAINED (exit 0) ─────────────────────────────────
run_probe
if [[ "$RC" -eq 0 ]] && grep -q "NUCLEUS_ADVERSARY: CONTAINED" "$OUT"; then
    ok "confined campaign -> CONTAINED (exit 0)"
else
    fail "confined campaign should be CONTAINED/exit0, got rc=$RC:"
    sed 's/^/        /' "$OUT"
fi

# ── State 2a: SECRET READABLE -> BREACH:pid1-secret-theft + meta-anti-leak ───
SECRET="adversary-falsifier-secret-$RANDOM$RANDOM"
printf 'NUCLEUS_TASK_TOKEN=%s\0' "$SECRET" >"$WORK/decoy_environ"
run_probe "NUCLEUS_ADVERSARY_PID1_ENVIRON=$WORK/decoy_environ"
if [[ "$RC" -eq 1 ]] && grep -q "NUCLEUS_ADVERSARY: BREACH:pid1-secret-theft" "$OUT"; then
    ok "readable mediator secret -> BREACH:pid1-secret-theft (exit 1)"
else
    fail "a stealable secret should be BREACH:pid1-secret-theft/exit1, got rc=$RC:"
    sed 's/^/        /' "$OUT"
fi
if grep -qF "$SECRET" "$OUT"; then
    fail "META-ANTI-LEAK: the probe echoed the stolen secret VALUE to its console — it became the exfil channel"
else
    ok "meta-anti-leak: breach reported without echoing the secret value"
fi

# ── State 2b: ROOTFS WRITABLE -> BREACH:rootfs-tamper ────────────────────────
run_probe "NUCLEUS_ADVERSARY_WRITE_TARGET=$WORK"
if [[ "$RC" -eq 1 ]] && grep -q "NUCLEUS_ADVERSARY: BREACH:rootfs-tamper" "$OUT"; then
    ok "writable target -> BREACH:rootfs-tamper (exit 1)"
    [[ -e "$WORK/.nucleus-adversary-tamper" ]] && fail "the probe left its tamper artifact behind"
else
    fail "a writable rootfs should be BREACH:rootfs-tamper/exit1, got rc=$RC:"
    sed 's/^/        /' "$OUT"
fi

# ── State 2c: EGRESS REACHABLE -> BREACH:exfil ──────────────────────────────
# Stand up a throwaway TCP listener the probe can actually reach.
PORT=0
if command -v python3 >/dev/null; then
    python3 - "$WORK/port" <<'PY' &
import socket, sys
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(16)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
while True:
    try: c, _ = s.accept(); c.close()
    except OSError: break
PY
    LISTENER_PID=$!
    for _ in $(seq 1 50); do [[ -s "$WORK/port" ]] && break; sleep 0.1; done
    PORT="$(cat "$WORK/port" 2>/dev/null || echo 0)"
fi
if [[ "$PORT" != "0" ]]; then
    run_probe "NUCLEUS_ADVERSARY_DENY_TARGETS=127.0.0.1:$PORT"
    if [[ "$RC" -eq 1 ]] && grep -q "NUCLEUS_ADVERSARY: BREACH:exfil" "$OUT"; then
        ok "reachable egress -> BREACH:exfil (exit 1)"
    else
        fail "a reachable egress target should be BREACH:exfil/exit1, got rc=$RC:"
        sed 's/^/        /' "$OUT"
    fi
else
    echo "  skip  egress-breach state (no python3 to host a listener) — other states still gate"
fi

# ── State 3: CONTROL DEAD -> INCONCLUSIVE, never CONTAINED (anti-vacuity) ────
# Withhold the mediator URL so the positive control cannot go live.
OUT="$WORK/out"
env -i \
    "NUCLEUS_ADVERSARY_PID1_ENVIRON=/dev/null" \
    "NUCLEUS_ADVERSARY_WRITE_TARGET=/proc" \
    "NUCLEUS_ADVERSARY_DENY_TARGETS=203.0.113.1:443" \
    "NUCLEUS_ADVERSARY_TIMEOUT_MS=400" \
    "$BIN" >"$OUT" 2>&1
RC=$?
if [[ "$RC" -eq 2 ]] && grep -q "NUCLEUS_ADVERSARY: INCONCLUSIVE" "$OUT" \
    && ! grep -q "NUCLEUS_ADVERSARY: CONTAINED" "$OUT"; then
    ok "dead positive control -> INCONCLUSIVE, not CONTAINED (exit 2)"
else
    fail "a dead attacker must be INCONCLUSIVE (never CONTAINED), got rc=$RC:"
    sed 's/^/        /' "$OUT"
fi

echo
if [[ "$failures" -gt 0 ]]; then
    echo "FAILED: $failures problem(s) — the adversary probe's verdict logic is broken."
    exit 1
fi
echo "OK: the adversary campaign distinguishes CONTAINED / BREACH:<stage> / INCONCLUSIVE,"
echo "    and reports a breach without leaking the secret value."
