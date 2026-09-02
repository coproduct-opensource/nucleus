#!/usr/bin/env bash
# Every `run_netns` call must name the PROGRAM to run inside the namespace.
#
# WHY: `ip netns exec <ns> <argv>` runs argv as a command IN the namespace. It
# inserts no program name, deliberately, because callers run `iptables` and
# `sysctl` as well as `ip`. Ten call sites in `setup_network` passed bare ip
# SUBCOMMANDS:
#
#   run_netns(ns, &["link", "add", br, "type", "bridge"])
#
# which executed `ip netns exec ns link add ...` -- GNU coreutils `link(1)`, the
# hard-link utility. Every pod with a `network` block failed to launch in ~90 ms
# with `link: extra operand 'type'` (#2380).
#
# ip commands now go through `run_netns_ip(netns, &IpCmd::…)`, whose `render`
# supplies `ip` and cannot omit it. This gate covers the remaining raw callers.
#
# It is the cheap form of the dylint pass proposed on #2380: assert the first
# argv element at every raw `run_netns` call site is a known program literal.
set -euo pipefail
cd "$(dirname "$0")/.."

NET_RS="crates/nucleus-node/src/net.rs"
[ -f "$NET_RS" ] || { echo "::error::$NET_RS missing"; exit 1; }

# Programs it is legitimate to exec inside a pod namespace.
ALLOWED_RE='^(ip|iptables|ip6tables|sysctl)$'

# For each `run_netns(` call that is NOT a doc comment, not the definition, and
# not run_netns_ip/run_netns_iptables, take the first string literal that follows
# and require it to name a program.
findings=$(awk -v allowed="$ALLOWED_RE" '
  # skip comments entirely -- the doc comment for IpCmd quotes the OLD broken call
  /^[[:space:]]*(\/\/|\*)/ { next }
  /fn run_netns/           { next }
  /run_netns_ip|run_netns_iptables/ { next }
  /run_netns[[:space:]]*\(/ { hunting = 1; site = NR; buf = ""; }
  hunting {
    buf = buf $0
    # first double-quoted token in the accumulated call text
    if (match(buf, /"[^"]*"/)) {
      tok = substr(buf, RSTART + 1, RLENGTH - 2)
      if (tok !~ allowed) print site ": first argv element is \"" tok "\", not a program"
      hunting = 0
    } else if (NR - site > 6) { hunting = 0 }
  }
' "$NET_RS")

# Non-vacuity: there ARE raw run_netns callers (iptables/sysctl). If the scan
# finds no call sites at all, the parse broke rather than the callers vanishing.
sites=$(grep -cE 'run_netns[[:space:]]*\(' "$NET_RS" || true)
if [ "${sites:-0}" -lt 3 ]; then
  echo "::error::only $sites run_netns call sites parsed from $NET_RS; the scan looks broken"
  exit 1
fi

if [ -n "$findings" ]; then
  echo "::error::run_netns call sites that do not name a program:"
  # Prefix with awk, not sed: $NET_RS contains slashes, which break an
  # s/^/.../ substitution using / as the delimiter -- the finding printed as a
  # sed error instead of as the finding.
  printf '%s\n' "$findings" | awk -v f="$NET_RS" '{ print "  " f ":" $0 }'
  echo "  'ip netns exec' runs argv IN the namespace, so a bare subcommand execs"
  echo "  the wrong binary. Use run_netns_ip(netns, &IpCmd::...) for ip commands."
  exit 1
fi

echo "ok: all $sites run_netns call sites name a program"
