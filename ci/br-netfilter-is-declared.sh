#!/usr/bin/env bash
# br_netfilter must be a DECLARED dependency, in every VM template and in code.
#
# WHY: `net::setup_network` sets net.bridge.bridge-nf-call-iptables, and the
# /proc/sys/net/bridge tree only exists once br_netfilter is loaded. It used to
# be present by accident — hosts running Docker/containerd load it for their own
# bridge networking. The nucleus templates disable containerd deliberately, which
# removed the thing that had been loading it, and every pod spec with a `network`
# block began failing mid-launch on a bare `sysctl: cannot stat` (#2382).
#
# An undeclared dependency borrowed from whatever else happens to be running is
# exactly what this gate exists to prevent recurring.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# 1. Every Lima template provisions it, and persists it across a reboot.
shopt -s nullglob
templates=(scripts/lima/*.yaml)
if [ "${#templates[@]}" -lt 2 ]; then
  echo "::error::found ${#templates[@]} Lima template(s) under scripts/lima; the glob looks broken"
  exit 1
fi

for t in "${templates[@]}"; do
  if ! grep -vE '^\s*#' "$t" | grep -q 'modprobe br_netfilter'; then
    echo "::error::$t never loads br_netfilter — a pod with a \`network\` block will fail mid-launch"
    fail=1
  fi
  # Non-comment lines only. The first version of this check matched the word
  # "modules-load.d" in a COMMENT explaining why persistence matters, so deleting
  # the actual command still passed — a gate satisfied by prose about itself.
  if ! grep -vE '^\s*#' "$t" | grep -q '/etc/modules-load.d'; then
    echo "::error::$t loads br_netfilter but does not persist it; a bare modprobe does"
    echo "  not survive a VM restart, which is how #2382 was rediscovered"
    fail=1
  fi
done

# 2. The code refuses BEFORE building interfaces, rather than failing at the
#    sysctl with a path and no remedy.
NET_RS="crates/nucleus-node/src/net.rs"
[ -f "$NET_RS" ] || { echo "::error::$NET_RS missing"; exit 1; }

if ! grep -q 'ensure_bridge_netfilter()' "$NET_RS"; then
  echo "::error::$NET_RS has no br_netfilter preflight. Without it the failure"
  echo "  surfaces from inside a half-built namespace after the veth pair, bridge"
  echo "  and tap already exist."
  fail=1
fi

# The preflight must run BEFORE the first interface is created, or it is not a
# preflight. `run_ip(` is the first thing setup_network does that builds state.
order=$(awk '
  /^pub async fn setup_network/ { in_fn = 1 }
  in_fn && /ensure_bridge_netfilter\(\)/ { print "preflight " NR; exit }
  in_fn && /run_ip\(/            { print "interface " NR; exit }
' "$NET_RS")
case "$order" in
  preflight*) ;;
  *) echo "::error::the br_netfilter preflight does not run before the first interface is built ($order)"
     fail=1 ;;
esac

[ "$fail" -eq 0 ] && echo "ok: br_netfilter declared in ${#templates[@]} templates and preflighted in code"
exit $fail
