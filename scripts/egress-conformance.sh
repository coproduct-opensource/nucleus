#!/bin/sh
# Differential conformance: does the real Linux kernel agree with the egress
# model our Lean theorems are stated over?
#
# EgressConfinementExtracted.lean proves things about a fold over a rule list.
# It cannot prove that iptables implements those semantics — that is the one
# assumption in the egress leg no amount of Rust or Lean closes from inside.
# This script does not close it either, but it turns it from ASSUMED into
# TESTED: build the chain `net::egress_chain` produces, apply it to a real
# netns, and check the kernel's verdict against the model's on each probe.
#
# Requires Linux + root (netns, iptables). Verified by running it under a
# privileged container; on a dev Mac: docker run --privileged.
apt-get -qq update >/dev/null 2>&1
apt-get -qq install -y iproute2 iptables netcat-openbsd >/dev/null 2>&1

setup() {
  ip netns add cf
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns cf
  ip addr add 10.0.0.1/8 dev veth0; ip link set veth0 up
  ip -n cf addr add 10.0.0.2/8 dev veth1; ip -n cf link set veth1 up; ip -n cf link set lo up
  for t in 10.0.1.9 10.0.1.7 10.0.2.9; do ip addr add $t/32 dev veth0; done
}
verdict() { # ip port -> prints accept|drop
  s=$(date +%s%N)
  ip netns exec cf timeout 4 nc -z -w 3 "$1" "$2" >/dev/null 2>&1
  e=$(date +%s%N); ms=$(( (e - s) / 1000000 ))
  if [ "$ms" -lt 1000 ]; then echo accept; else echo drop; fi
}
FAIL=0
check() { got=$(verdict "$1" "$2")
  if [ "$got" = "$3" ]; then echo "  OK        $1:$2  kernel=$got  model=$3"
  else echo "  MISMATCH  $1:$2  kernel=$got  model=$3"; FAIL=1; fi }

setup
echo "=== baseline: no rules, everything must be reachable ==="
check 10.0.1.9 443 accept
check 10.0.2.9 443 accept

echo "=== chain under test (what net::egress_chain builds) ==="
ip netns exec cf iptables -w -P OUTPUT DROP
ip netns exec cf iptables -w -A OUTPUT -o lo -j ACCEPT
ip netns exec cf iptables -w -A OUTPUT -d 10.0.1.7/32 -j DROP
ip netns exec cf iptables -w -A OUTPUT -d 10.0.1.0/24 -p tcp --dport 443 -j ACCEPT
ip netns exec cf iptables -w -S OUTPUT | sed 's/^/    /'

echo "=== model vs kernel ==="
check 10.0.1.9 443 accept   # inside allow, right port
check 10.0.1.9 80  drop     # inside allow net, wrong port
check 10.0.1.7 443 drop     # specific deny beats the broader allow
check 10.0.2.9 443 drop     # routable, outside the allow -> policy DROP
echo "=== result ==="
[ "$FAIL" = "0" ] && echo "CONFORMANCE: kernel agrees with the model on every probe" || echo "CONFORMANCE: MISMATCH"
ip netns del cf
