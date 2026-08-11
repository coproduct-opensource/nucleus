#!/usr/bin/env bash
# C6 phase 2 host-side falsifier for nucleus-egress-probe.
#
# WHY THIS EXISTS
#
# The egress probe's real verdict is earned inside a booted microVM, where the
# netns/iptables default-deny policy is live (the boot gate in quickstart-boot.yml
# greps its PASS sentinel). But that job boots on x86_64 CI and is not a required
# check — so on its own the probe could silently rot: a refactor that made it
# always FAIL, or always PASS, or that dropped the anti-vacuity control, would not
# red anything that blocks a merge.
#
# This gate closes that gap WITHOUT a boot. On Linux it reconstructs the exact
# fence the guest runs — a network namespace with the `net::apply_default_deny`
# rules — and asserts the probe behaves correctly against it in THREE states:
#
#   1. FENCE PRESENT  → PASS   (loopback works; the non-allowlisted peer is dropped)
#   2. FENCE REMOVED  → FAIL   (OUTPUT policy opened; the peer becomes reachable)
#   3. LOOPBACK ALSO BLOCKED → FAIL   (the vacuity guard: a dead network must NOT
#                                      read as "confined" — the positive control
#                                      fails, so the probe must refuse to certify)
#
# State 2 is the reds-on-regression control (a fence that is not applied is
# caught). State 3 is the anti-vacuity control (a probe that passes because the
# net is dead is caught). A probe that cannot distinguish all three is not a
# probe. On a host without netns/iptables (a dev Mac) it degrades to a loopback
# open/closed-port check of the same verdict logic.
#
# Usage: scripts/check-egress-probe.sh
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

NS=nucleus-egress-probe-test
VETH_H=vethep-h
VETH_N=vethep-n
HOST_IP=10.201.77.1
NS_IP=10.201.77.2
# An UNPRIVILEGED port: the peer listener runs without sudo, and CI runners keep
# net.ipv4.ip_unprivileged_port_start at 1024, so a privileged port (e.g. 443)
# would fail to bind there and make the peer unreachable — which would look like
# the fence blocking traffic when in fact nothing was listening.
PEER_PORT=34443
PEER=""          # host:port the probe treats as a denied target
LISTENER_PID=""

failures=0
fail() { echo "  FAIL  $1"; failures=$((failures + 1)); }
ok()   { echo "  ok    $1"; }

# ── Locate the probe binary ─────────────────────────────────────────────────
BIN="${EGRESS_PROBE_BIN:-}"
if [[ -z "$BIN" ]]; then
    for cand in \
        target/release/nucleus-egress-probe \
        target/debug/nucleus-egress-probe \
        target/*/release/nucleus-egress-probe \
        target/*/debug/nucleus-egress-probe; do
        [[ -x "$cand" ]] && { BIN="$cand"; break; }
    done
fi
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
    echo "building nucleus-egress-probe (no prebuilt binary found)…"
    cargo build -p nucleus-egress-probe >/dev/null 2>&1 || { echo "ERROR: build failed"; exit 1; }
    BIN=target/debug/nucleus-egress-probe
fi
# Absolutize so the probe runs the same from any cwd (netns exec keeps cwd).
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
echo "probe: $BIN"

# run_probe <sudo-prefix> : echoes the probe's combined output; returns its exit.
# Deny target + name are pointed at the hermetic peer so nothing reaches the
# real internet. A short DNS timeout keeps the resolve check from stalling.
run_probe() {
    "$@" env \
        NUCLEUS_EGRESS_PROBE_DENY_TARGETS="$PEER" \
        NUCLEUS_EGRESS_PROBE_DENY_NAME="egress-probe.invalid" \
        NUCLEUS_EGRESS_PROBE_TIMEOUT_MS=800 \
        "$BIN" 2>&1
}

# Same, but with an EMPTY deny-target list — for the anti-vacuity guard: the
# probe must refuse to pass when it probed zero targets.
run_probe_empty() {
    "$@" env \
        NUCLEUS_EGRESS_PROBE_DENY_TARGETS="" \
        NUCLEUS_EGRESS_PROBE_DENY_NAME="egress-probe.invalid" \
        NUCLEUS_EGRESS_PROBE_TIMEOUT_MS=800 \
        "$BIN" 2>&1
}

assert_pass() { # <label> <output> <exit>
    local label="$1" out="$2" rc="$3"
    if [[ "$rc" -eq 0 ]] && grep -q "NUCLEUS_EGRESS_PROBE: PASS" <<<"$out"; then
        ok "$label → PASS"
    else
        fail "$label → expected PASS, got exit=$rc"
        sed 's/^/        /' <<<"$out"
    fi
}
assert_fail() { # <label> <output> <exit> <needle>
    local label="$1" out="$2" rc="$3" needle="$4"
    if [[ "$rc" -ne 0 ]] && grep -q "NUCLEUS_EGRESS_PROBE: FAIL" <<<"$out" && grep -qi "$needle" <<<"$out"; then
        ok "$label → FAIL ($needle)"
    else
        fail "$label → expected FAIL matching '$needle', got exit=$rc"
        sed 's/^/        /' <<<"$out"
    fi
}

# ── Degraded path: no netns/iptables (dev Mac) ──────────────────────────────
if ! command -v ip >/dev/null 2>&1 || [[ "$(uname -s)" != "Linux" ]]; then
    echo "no Linux netns available — degraded loopback-only check of the verdict logic"
    # A closed loopback port stands in for 'denied': connect fails ⇒ PASS.
    PEER="127.0.0.1:1"    # nothing listens on port 1
    out="$(run_probe)"; rc=$?
    assert_pass "closed-port (stands in for fenced)" "$out" "$rc"
    # An open loopback port stands in for 'reachable': connect succeeds ⇒ FAIL.
    python3 - <<'PY' &
import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",34567)); s.listen(16); time.sleep(8)
PY
    lp=$!; sleep 1
    PEER="127.0.0.1:34567"
    out="$(run_probe)"; rc=$?
    assert_fail "open-port (stands in for unfenced)" "$out" "$rc" "SUCCEEDED"
    kill "$lp" 2>/dev/null
    # Anti-vacuity: no deny targets → FAIL.
    out="$(run_probe_empty)"; rc=$?
    assert_fail "no deny targets (vacuity guard)" "$out" "$rc" "vacuously"
    echo
    [[ "$failures" -eq 0 ]] && { echo "OK (degraded): the probe's verdict logic is correct; run on Linux for the real fence."; exit 0; }
    echo "FAILED: $failures problem(s)."; exit 1
fi

# ── Linux path: reconstruct the real fence in a netns ───────────────────────
if [[ "$(id -u)" -ne 0 ]]; then SUDO=(sudo); else SUDO=(); fi
command -v iptables >/dev/null 2>&1 || { echo "ERROR: iptables not found"; exit 1; }

cleanup() {
    [[ -n "$LISTENER_PID" ]] && kill "$LISTENER_PID" 2>/dev/null
    "${SUDO[@]}" ip netns del "$NS" 2>/dev/null
    "${SUDO[@]}" ip link del "$VETH_H" 2>/dev/null
}
trap cleanup EXIT INT TERM
cleanup   # clear any stale leftovers from a killed run

# Namespace + veth pair; the netns end gets an IP and a default route so a
# connect REACHES the OUTPUT chain (and is dropped there) rather than failing
# with "network unreachable" — we are testing iptables, not the absence of a route.
"${SUDO[@]}" ip netns add "$NS"
"${SUDO[@]}" ip link add "$VETH_H" type veth peer name "$VETH_N"
"${SUDO[@]}" ip link set "$VETH_N" netns "$NS"
"${SUDO[@]}" ip addr add "$HOST_IP/24" dev "$VETH_H"
"${SUDO[@]}" ip link set "$VETH_H" up
"${SUDO[@]}" ip -n "$NS" addr add "$NS_IP/24" dev "$VETH_N"
"${SUDO[@]}" ip -n "$NS" link set "$VETH_N" up
"${SUDO[@]}" ip -n "$NS" link set lo up
"${SUDO[@]}" ip -n "$NS" route add default via "$HOST_IP"

# A listener on the host end, so that with the fence OFF the probe's connect
# genuinely SUCCEEDS (proving the fence — not a dead peer — is what blocks it).
if command -v python3 >/dev/null 2>&1; then
    python3 - "$HOST_IP" "$PEER_PORT" <<'PY' &
import socket,sys,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((sys.argv[1],int(sys.argv[2]))); s.listen(16); time.sleep(120)
PY
    LISTENER_PID=$!
elif command -v nc >/dev/null 2>&1; then
    nc -l -k "$HOST_IP" "$PEER_PORT" >/dev/null 2>&1 & LISTENER_PID=$!
else
    echo "ERROR: need python3 or nc to run the peer listener"; exit 1
fi

# Readiness: the "fence removed → FAIL" state only means something if the peer is
# genuinely reachable when the fence is down. Confirm the listener accepts BEFORE
# running any state, so a listener problem is diagnosed here, not mistaken for a
# fence. Uses bash's /dev/tcp from the host (default) namespace.
ready=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if (exec 3<>"/dev/tcp/$HOST_IP/$PEER_PORT") 2>/dev/null; then ready=1; exec 3>&- 3<&-; break; fi
    sleep 0.3
done
if [[ "$ready" -ne 1 ]]; then
    echo "ERROR: peer listener never came up on $HOST_IP:$PEER_PORT — cannot run the fence-removed state"
    exit 1
fi
PEER="$HOST_IP:$PEER_PORT"

# apply_default_deny, mirrored from crates/nucleus-node/src/net.rs:385.
apply_default_deny() {
    "${SUDO[@]}" ip netns exec "$NS" iptables -w -F
    "${SUDO[@]}" ip netns exec "$NS" iptables -w -X
    "${SUDO[@]}" ip netns exec "$NS" iptables -w -P INPUT DROP
    "${SUDO[@]}" ip netns exec "$NS" iptables -w -P OUTPUT DROP
    "${SUDO[@]}" ip netns exec "$NS" iptables -w -P FORWARD DROP
    "${SUDO[@]}" ip netns exec "$NS" iptables -w -A OUTPUT -o lo -j ACCEPT
    "${SUDO[@]}" ip netns exec "$NS" iptables -w -A INPUT -i lo -j ACCEPT
    "${SUDO[@]}" ip netns exec "$NS" iptables -w -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    "${SUDO[@]}" ip netns exec "$NS" iptables -w -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
}

# ── State 1: fence present → PASS ───────────────────────────────────────────
apply_default_deny
out="$(run_probe "${SUDO[@]}" ip netns exec "$NS")"; rc=$?
assert_pass "fence present" "$out" "$rc"

# ── State 2: fence removed → FAIL (reds-on-regression) ──────────────────────
"${SUDO[@]}" ip netns exec "$NS" iptables -w -F
"${SUDO[@]}" ip netns exec "$NS" iptables -w -P OUTPUT ACCEPT
"${SUDO[@]}" ip netns exec "$NS" iptables -w -P INPUT ACCEPT
out="$(run_probe "${SUDO[@]}" ip netns exec "$NS")"; rc=$?
assert_fail "fence removed" "$out" "$rc" "SUCCEEDED"

# ── State 3: no deny targets → FAIL (anti-vacuity guard) ────────────────────
# The socketpair positive control cannot be broken with iptables, so the vacuity
# door this state closes is the other one: a probe that checked NOTHING. With an
# empty target list the fence is (re-)present, yet the probe must still FAIL
# rather than pass on having probed zero targets.
apply_default_deny
out="$(run_probe_empty "${SUDO[@]}" ip netns exec "$NS")"; rc=$?
assert_fail "no deny targets (vacuity guard)" "$out" "$rc" "vacuously"

echo
if [[ "$failures" -gt 0 ]]; then
    echo "FAILED: $failures problem(s) — the egress probe does not correctly track the fence."
    exit 1
fi
echo "OK: the egress probe PASSes with the default-deny fence present, FAILs when it is"
echo "removed, and FAILs when it probed no targets (no vacuous pass). The fence the guest"
echo "runs is the fence this probe observes."
