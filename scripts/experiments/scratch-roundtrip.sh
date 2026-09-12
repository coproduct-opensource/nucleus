#!/usr/bin/env bash
# Does a file the GUEST wrote to /work come back out of the scratch image
# through the HOST's read-back path?
#
# `scratch_readback::read_file` had three tests and all of them wrote the file
# host-side with `debugfs -w`. That exercises the dump, not the round trip: a
# guest writes through a mounted ext4 with a journal and a page cache, and
# whether those bytes are visible to a host reading the raw image afterwards is
# a different question from whether debugfs can read what debugfs wrote.
#
# Answered YES on 2026-09-12 (Firecracker v1.16.1, aarch64/KVM):
#
#   guest:  GUEST-WROTE-AND-UNMOUNTED
#   host:   READ-BACK OK: {"workspace_hash":"written-inside-the-guest"}
#   fsck:   clean, 12/4096 files
#
# Busybox, not nucleus-guest-init: guest-init aborts before the workload without
# a full credential chain (approval authority, task token), and faking that is
# where using the real node becomes cheaper than the fake. The claim under test
# is about ext4 and virtio-blk, so the smaller guest is the better instrument.
#
# Needs /dev/kvm, firecracker, ~/fc/vmlinux, busybox, e2fsprogs.
set -e
cd "$(dirname "$0")"
# The guest side of it (rfs/init):
#   #!/bin/sh
#   /bin/busybox mount -t proc proc /proc 2>/dev/null
#   /bin/busybox mkdir -p /work
#   /bin/busybox mount -t ext4 /dev/vdb /work
#   echo "{\"workspace_hash\":\"written-inside-the-guest\"}" > /work/.nucleus-exit-report.json
#   /bin/busybox sync
#   /bin/busybox umount /work
#   echo GUEST-WROTE-AND-UNMOUNTED
#   /bin/busybox sleep 3
#   /bin/busybox poweroff -f
#
# The host side is one command, and it is the production query verbatim:
#   debugfs -R "dump /.nucleus-exit-report.json <out>" scratch.ext4
echo "see the header: this records a measurement, and the full harness lives in"
echo "the session that produced it. Re-run by building a busybox rootfs whose"
echo "/init is the block above, booting it with a fresh 16 MiB ext4 as vdb, and"
echo "running the debugfs dump against that image afterwards."
