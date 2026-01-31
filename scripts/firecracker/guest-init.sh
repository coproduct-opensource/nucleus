#!/bin/sh
set -eu

mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run

umask 077
mkdir -p /etc/nucleus /work 2>/dev/null || true

if [ -b /dev/vdb ]; then
  mount -o rw,nosuid,nodev /dev/vdb /work || true
fi

POD_SPEC_PATH=/etc/nucleus/pod.yaml
if [ ! -f "$POD_SPEC_PATH" ] && [ -f /pod.yaml ]; then
  if ! cp /pod.yaml "$POD_SPEC_PATH" 2>/dev/null; then
    POD_SPEC_PATH=/pod.yaml
  fi
fi

if [ ! -f "$POD_SPEC_PATH" ]; then
  echo "missing pod spec (expected /etc/nucleus/pod.yaml or /pod.yaml)" >&2
  exec /bin/sh
fi

if [ -f /etc/nucleus/net.allow ] || [ -f /etc/nucleus/net.deny ]; then
  if [ -x /usr/local/bin/guest-net.sh ]; then
    /usr/local/bin/guest-net.sh || true
  fi
fi

if [ -f /etc/nucleus/auth.secret ]; then
  export NUCLEUS_TOOL_PROXY_AUTH_SECRET="$(cat /etc/nucleus/auth.secret)"
fi

if [ -f /etc/nucleus/audit.path ]; then
  export NUCLEUS_TOOL_PROXY_AUDIT_LOG="$(cat /etc/nucleus/audit.path)"
else
  if touch /work/.nucleus_write_test 2>/dev/null; then
    rm -f /work/.nucleus_write_test
    mkdir -p /work/audit 2>/dev/null || true
    export NUCLEUS_TOOL_PROXY_AUDIT_LOG=${NUCLEUS_TOOL_PROXY_AUDIT_LOG:-/work/audit/nucleus-audit.log}
  else
    export NUCLEUS_TOOL_PROXY_AUDIT_LOG=${NUCLEUS_TOOL_PROXY_AUDIT_LOG:-/tmp/nucleus-audit.log}
  fi
fi

mount -o remount,ro / 2>/dev/null || true

exec /usr/local/bin/nucleus-tool-proxy --spec "$POD_SPEC_PATH"
