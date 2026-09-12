#!/usr/bin/env bash
# Does a snapshot base survive an attached-but-UNMOUNTED writable scratch,
# restored twice against fresh per-clone images at the same drive path?
#
# Answered YES on 2026-09-12 (Firecracker v1.16.1, aarch64/KVM). See
# docs/snapshot-scratch.md for what it means. Needs /dev/kvm, firecracker,
# a kernel at ~/fc/vmlinux, busybox and e2fsprogs.
#
# Deliberately raw Firecracker: the question is about the VMM, not nucleus,
# so bringing 90 crates into it would only add ways to be wrong.
set -e
cd ~/snaptest
API() { curl -s --unix-socket "$1" -X PUT "http://localhost/$2" -H "Content-Type: application/json" -d "$3"; }
mk_scratch() { rm -f "$1"; dd if=/dev/zero of="$1" bs=1M count=16 status=none; mkfs.ext4 -q -F "$1"; }

rm -f *.sock *-in *.log snap.mem snap.state
mk_scratch scratch-base.ext4; mk_scratch scratch-A.ext4; mk_scratch scratch-B.ext4

# ---------- 1. base VM: scratch attached, NEVER mounted ----------
mkfifo base-in
firecracker --api-sock base.sock < base-in > base.log 2>&1 &
exec 3> base-in
sleep 1
API base.sock boot-source "{\"kernel_image_path\":\"$HOME/fc/vmlinux\",\"boot_args\":\"console=ttyS0 reboot=k panic=1 pci=off init=/init\"}"
API base.sock drives/rootfs "{\"drive_id\":\"rootfs\",\"path_on_host\":\"$PWD/rootfs.ext4\",\"is_root_device\":true,\"is_read_only\":false}"
API base.sock drives/scratch "{\"drive_id\":\"scratch\",\"path_on_host\":\"$PWD/scratch-base.ext4\",\"is_root_device\":false,\"is_read_only\":false}"
API base.sock machine-config "{\"vcpu_count\":1,\"mem_size_mib\":256}"
API base.sock actions "{\"action_type\":\"InstanceStart\"}"
sleep 3
echo "PRECONDITION vdb mounts: $(echo "cat /proc/mounts | grep -c vdb" >&3; sleep 1; grep -A1 "grep -c vdb" base.log | tail -1 | tr -d "\r")"

# ---------- 2. snapshot ----------
curl -s --unix-socket base.sock -X PATCH http://localhost/vm -H "Content-Type: application/json" -d @- <<< '{"state":"Paused"}'
API base.sock snapshot/create "{\"snapshot_type\":\"Full\",\"snapshot_path\":\"$PWD/snap.state\",\"mem_file_path\":\"$PWD/snap.mem\"}"
echo "SNAPSHOT: state=$(stat -c %s snap.state) mem=$(stat -c %s snap.mem)"
exec 3>&-; pkill -f "api-sock base.sock" || true; sleep 1

# ---------- 3. restore twice, each against a FRESH scratch ----------
restore() {
  local name=$1 img=$2
  mkfifo ${name}-in
  firecracker --api-sock ${name}.sock < ${name}-in > ${name}.log 2>&1 &
  exec 4> ${name}-in
  sleep 1
  # Same relative path is not required here: each restore names its own file,
  # which is what a per-pod jail would give at one in-jail name.
  API ${name}.sock snapshot/load "{\"snapshot_path\":\"$PWD/snap.state\",\"mem_backend\":{\"backend_path\":\"$PWD/snap.mem\",\"backend_type\":\"File\"},\"enable_diff_snapshots\":false,\"resume_vm\":true}" > ${name}.loadout 2>&1
  sleep 2
  echo "mount /dev/vdb /mnt && echo ${name}-WROTE > /mnt/${name}.txt && sync && umount /mnt && echo ${name}-CLEAN" >&4
  sleep 3
  exec 4>&-
  pkill -f "api-sock ${name}.sock" || true
  sleep 1
}
# The drive path in the snapshot is scratch-base.ext4, so each restore gets its
# own file THERE — the substitution the hypothesis is about.
cp scratch-A.ext4 scratch-base.ext4; restore A scratch-A.ext4; cp scratch-base.ext4 result-A.ext4
cp scratch-B.ext4 scratch-base.ext4; restore B scratch-B.ext4; cp scratch-base.ext4 result-B.ext4

echo "=== A load ==="; cat A.loadout; grep -E "WROTE|CLEAN|EXT4-fs error|error" A.log | tail -4
echo "=== B load ==="; cat B.loadout; grep -E "WROTE|CLEAN|EXT4-fs error|error" B.log | tail -4
echo "=== fsck A ==="; e2fsck -fn result-A.ext4 2>&1 | tail -4
echo "=== fsck B ==="; e2fsck -fn result-B.ext4 2>&1 | tail -4
