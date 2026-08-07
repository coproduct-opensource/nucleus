#!/usr/bin/env bash
# Does the guest-address channel actually stay closed, with real packets?
#
# `net.rs`'s unit tests cover ADDRESSING -- that two plans agree on the guest's
# view and differ on the link. They cannot cover the part that decides whether
# the design works at all: two namespaces carrying the SAME guest subnet on one
# host, and whether the constant address is translated before it escapes.
#
# This needs a Linux kernel, root, and iptables, so it is a script rather than a
# `#[test]`. Exit 0 means the property holds; anything else means it does not.
#
# Exercise the #2205 topology for real: two pods whose GUESTS have IDENTICAL
# addressing, sharing one host. This is the assumption the whole change rests on,
# and it is the part unit tests cannot reach.
#
# Mirrors net.rs exactly:
#   link subnet  10.200.0.{0,4}/30   host .1/.5   peer .2/.6   (index-derived)
#   guest subnet 192.168.241.0/30    gw .1        guest .2     (CONSTANT)
set -u

LOG=/tmp/nettest.out
: > "$LOG"
say() { echo "$*" | tee -a "$LOG"; }

cleanup() {
  for i in 0 1; do
    sudo ip netns del "pod$i"   2>/dev/null
    sudo ip netns del "guest$i" 2>/dev/null
    sudo ip link del "veth$i"   2>/dev/null
  done
  sudo ip link del nucdummy 2>/dev/null
  sudo iptables -t nat -D POSTROUTING -s 10.200.0.0/24 -j MASQUERADE 2>/dev/null
}
cleanup
trap cleanup EXIT

sudo sysctl -qw net.ipv4.ip_forward=1

# A host address both pods can route to, standing in for "the rest of the world".
sudo ip link add nucdummy type dummy 2>/dev/null
sudo ip addr add 10.99.0.1/32 dev nucdummy 2>/dev/null
sudo ip link set nucdummy up

for i in 0 1; do
  base=$((i * 4))
  HOST_IP="10.200.0.$((base + 1))"
  PEER_IP="10.200.0.$((base + 2))"

  sudo ip netns add "pod$i"
  sudo ip netns add "guest$i"

  # veth: host namespace <-> pod namespace. Index-derived, guest never sees it.
  sudo ip link add "veth$i" type veth peer name "vpeer$i"
  sudo ip link set "vpeer$i" netns "pod$i"
  sudo ip addr add "$HOST_IP/30" dev "veth$i"
  sudo ip link set "veth$i" up
  sudo ip netns exec "pod$i" ip addr add "$PEER_IP/30" dev "vpeer$i"
  sudo ip netns exec "pod$i" ip link set "vpeer$i" up
  sudo ip netns exec "pod$i" ip link set lo up

  # bridge carrying the CONSTANT gateway; the tap would hang off this.
  sudo ip netns exec "pod$i" ip link add br0 type bridge
  sudo ip netns exec "pod$i" ip addr add 192.168.241.1/30 dev br0
  sudo ip netns exec "pod$i" ip link set br0 up

  # Stand-in for the guest VM: its own namespace on the bridge, IDENTICAL in
  # both pods. If the design is wrong, this is where it collides.
  sudo ip link add "gv$i" type veth peer name "gp$i"
  sudo ip link set "gv$i" netns "pod$i"
  sudo ip link set "gp$i" netns "guest$i"
  sudo ip netns exec "pod$i" ip link set "gv$i" master br0
  sudo ip netns exec "pod$i" ip link set "gv$i" up
  sudo ip netns exec "guest$i" ip addr add 192.168.241.2/30 dev "gp$i"
  sudo ip netns exec "guest$i" ip link set "gp$i" up
  sudo ip netns exec "guest$i" ip link set lo up
  sudo ip netns exec "guest$i" ip route add default via 192.168.241.1

  sudo ip netns exec "pod$i" sysctl -qw net.ipv4.ip_forward=1
  sudo ip netns exec "pod$i" ip route add default via "$HOST_IP"

  # THE RULE UNDER TEST: rewrite the constant guest address to this pod's
  # unique link address on the way out of the namespace.
  sudo ip netns exec "pod$i" iptables -t nat -A POSTROUTING \
      -s 192.168.241.0/30 -o "vpeer$i" -j MASQUERADE
done

sudo iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -j MASQUERADE

say "=== both guests have the SAME address (the assumption under test) ==="
for i in 0 1; do
  say "  guest$i: $(sudo ip netns exec guest$i ip -4 -o addr show dev gp$i | awk '{print $4}')"
done

say ""
say "=== what the host sees as the source of each guest's traffic ==="
sudo python3 - "$LOG" <<'PYEOF' &
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.99.0.1", 9999))
s.settimeout(20)
seen = []
for _ in range(2):
    try:
        data, addr = s.recvfrom(64)
        seen.append((data.decode(errors="replace"), addr[0]))
    except socket.timeout:
        break
with open("/tmp/nettest.seen", "w") as f:
    for tag, src in seen:
        f.write(f"{tag} {src}\n")
PYEOF
LISTENER=$!
sleep 2

for i in 0 1; do
  sudo ip netns exec "guest$i" python3 -c "
import socket
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'guest$i', ('10.99.0.1', 9999))
" 2>>"$LOG" || say "  guest$i SEND FAILED"
  sleep 1
done

wait $LISTENER 2>/dev/null
rc=0
say ""
if [ -f /tmp/nettest.seen ]; then
  cat /tmp/nettest.seen | tee -a "$LOG"
  n=$(sort -u -k2 /tmp/nettest.seen | wc -l)
  say ""
  say "distinct source addresses observed by the host: $n (want 2)"
  [ "$n" -eq 2 ] || { say "FAIL: the host cannot tell the two pods apart"; rc=1; }
  if grep -q "192.168.241.2" /tmp/nettest.seen; then
    say "FAIL: the constant guest address ESCAPED the namespace"
    rc=1
  else
    say "OK: the constant guest address never reached the host"
  fi
  # Both guests must have reached the host at all -- "nothing arrived" would
  # otherwise pass the two checks above by vacuity.
  [ "$(wc -l < /tmp/nettest.seen)" -eq 2 ] || {
    say "FAIL: expected 2 datagrams, got $(wc -l < /tmp/nettest.seen) -- the"
    say "      checks above would pass vacuously on an empty capture"
    rc=1
  }
else
  say "FAIL: listener recorded nothing"
  rc=1
fi
exit $rc
