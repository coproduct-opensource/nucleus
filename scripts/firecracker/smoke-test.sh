#!/bin/sh
# Boot a throwaway Firecracker microVM and prove the Tier 2 path actually works.
#
# WHY THIS EXISTS
#
# `nucleus setup` could report success while leaving a machine on which no
# microVM will ever boot: `test -c /dev/kvm` passing says the device node is
# there, not that Firecracker can use it. Every other check in setup is an
# inference. This one runs the thing.
#
# Runs INSIDE the Lima VM (needs Linux, KVM and root). Downloads a kernel and
# rootfs from the Firecracker CI bucket once and caches them under
# /var/cache/nucleus-smoke, so a re-run is fast and offline.
#
# Exit 0 = a microVM booted to a userspace prompt. Anything else is a failure
# worth showing the user verbatim.
set -eu

CACHE=/var/cache/nucleus-smoke
# The v1.13 artifacts. Note the older v1.12 paths and the `ubuntu-24.04.ext4`
# name both 404 now — this was found the hard way; list the bucket with
# ?list-type=2&prefix=firecracker-ci/ if these ever move again.
BASE=https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13
case "$(uname -m)" in
  aarch64) ARCH=aarch64; KERNEL=vmlinux-6.1.141 ;;
  x86_64)  ARCH=x86_64;  KERNEL=vmlinux-6.1.141 ;;
  *) echo "smoke-test: unsupported arch $(uname -m)" >&2; exit 2 ;;
esac

command -v firecracker >/dev/null 2>&1 || {
  echo "smoke-test: firecracker is not installed" >&2; exit 2; }
[ -r /dev/kvm ] || {
  echo "smoke-test: /dev/kvm is not readable (need root, or the kvm group)" >&2; exit 2; }

mkdir -p "$CACHE"
[ -s "$CACHE/vmlinux" ]  || curl -fsSL -o "$CACHE/vmlinux"  "$BASE/$ARCH/$KERNEL"
[ -s "$CACHE/rootfs.squashfs" ] || curl -fsSL -o "$CACHE/rootfs.squashfs" "$BASE/$ARCH/ubuntu-24.04.squashfs"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cat > "$WORK/vm.json" <<JSON
{
  "boot-source": {
    "kernel_image_path": "$CACHE/vmlinux",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off ro"
  },
  "drives": [{
    "drive_id": "rootfs", "path_on_host": "$CACHE/rootfs.squashfs",
    "is_root_device": true, "is_read_only": true
  }],
  "machine-config": { "vcpu_count": 1, "mem_size_mib": 256 }
}
JSON

# The guest has no shutdown path here, so the VM is killed by the timeout. That
# is expected: reaching a userspace prompt is the whole assertion.
timeout 45 firecracker --no-api --config-file "$WORK/vm.json" > "$WORK/boot.log" 2>&1 || true

if grep -qE 'login:|root@|# $' "$WORK/boot.log"; then
  echo "smoke-test: PASS - a microVM booted to userspace on this host"
  exit 0
fi

echo "smoke-test: FAIL - the microVM did not reach userspace" >&2
echo "--- boot log (last 20 lines) ---" >&2
tail -20 "$WORK/boot.log" >&2
exit 1
