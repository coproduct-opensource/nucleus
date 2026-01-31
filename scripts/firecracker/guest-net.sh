#!/bin/sh
set -eu

ALLOW_FILE=${ALLOW_FILE:-/etc/nucleus/net.allow}
DENY_FILE=${DENY_FILE:-/etc/nucleus/net.deny}

# Default deny policy for outbound.
if command -v iptables >/dev/null 2>&1; then
  iptables -P OUTPUT DROP
  iptables -P INPUT DROP
  iptables -P FORWARD DROP

  # Allow loopback
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A INPUT -i lo -j ACCEPT

  # Allow established connections
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  # Allow DNS to resolver only if allowlist present.
  if [ -f "$ALLOW_FILE" ]; then
    while IFS= read -r entry; do
      [ -z "$entry" ] && continue
      # Allow IP or host:port. If port not provided, allow all ports.
      host=$(echo "$entry" | cut -d: -f1)
      port=$(echo "$entry" | cut -s -d: -f2)
      if [ -n "$port" ]; then
        iptables -A OUTPUT -p tcp -d "$host" --dport "$port" -j ACCEPT
        iptables -A OUTPUT -p udp -d "$host" --dport "$port" -j ACCEPT
      else
        iptables -A OUTPUT -d "$host" -j ACCEPT
      fi
    done < "$ALLOW_FILE"
  fi

  if [ -f "$DENY_FILE" ]; then
    while IFS= read -r entry; do
      [ -z "$entry" ] && continue
      host=$(echo "$entry" | cut -d: -f1)
      iptables -A OUTPUT -d "$host" -j DROP
    done < "$DENY_FILE"
  fi
fi
