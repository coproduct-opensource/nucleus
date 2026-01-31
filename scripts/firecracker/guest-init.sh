#!/bin/sh
set -eu

mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run

mkdir -p /etc/nucleus /work

if [ -b /dev/vdb ]; then
  mount /dev/vdb /work || true
fi

if [ ! -f /etc/nucleus/pod.yaml ] && [ -f /pod.yaml ]; then
  cp /pod.yaml /etc/nucleus/pod.yaml
fi

if [ ! -f /etc/nucleus/pod.yaml ]; then
  echo "missing /etc/nucleus/pod.yaml" >&2
  exec /bin/sh
fi

export NUCLEUS_TOOL_PROXY_AUDIT_LOG=${NUCLEUS_TOOL_PROXY_AUDIT_LOG:-/tmp/nucleus-audit.log}

exec /usr/local/bin/nucleus-tool-proxy --spec /etc/nucleus/pod.yaml
