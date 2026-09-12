#!/usr/bin/env bash
# Does guest-init reach the snapshot barrier with /work still UNMOUNTED?
#
# Answered YES on 2026-09-12 (Firecracker v1.16.1, aarch64/KVM):
#
#   BEFORE-BOOT  mount_count=0
#   AT-BARRIER   mount_count=0   <- the claim
#   SAW_BARRIER=True
#   AFTER-RUN    mount_count=1   <- mounted, on the far side
#
# The two halves of M3 were written against each other and never run
# together: guest-init defers the mount (this repo) and snapshot::mount_state
# refuses a base whose scratch was mounted. This is the integration.
#
# The measurement is taken the instant SNAPSHOT_READY arrives and nowhere
# else. There is no race: announce_snapshot_ready READS the reply before
# returning ("the content is not interesting, the ordering is"), so the guest
# is blocked at the barrier for the whole dumpe2fs call and cannot have
# mounted. barrier-observer.py answers only after measuring.
#
# Needs: /dev/kvm, firecracker, ~/fc/vmlinux, busybox, e2fsprogs, and a
# rootfs whose /init is a musl build of nucleus-guest-init.
set -e
cd ~/e2e
PORT=5005
rm -f fc.sock fc.sock_vsock fc.sock_vsock_5005 vm.log observer.log scratch.ext4
dd if=/dev/zero of=scratch.ext4 bs=1M count=16 status=none && mkfs.ext4 -q -F scratch.ext4

python3 barrier-observer.py "$PWD/fc.sock_vsock" $PORT "$PWD/scratch.ext4" > observer.log 2>&1 &
OBS=$!
sleep 1

firecracker --api-sock fc.sock > vm.log 2>&1 &
sleep 1
API() { curl -s --unix-socket fc.sock -X PUT "http://localhost/$1" -H "Content-Type: application/json" -d "$2" >/dev/null; }
API boot-source "{\"kernel_image_path\":\"$HOME/fc/vmlinux\",\"boot_args\":\"console=ttyS0 reboot=k panic=1 pci=off init=/init nucleus.workload_api_port=$PORT\"}"
API drives/rootfs "{\"drive_id\":\"rootfs\",\"path_on_host\":\"$PWD/rootfs.ext4\",\"is_root_device\":true,\"is_read_only\":false}"
API drives/scratch "{\"drive_id\":\"scratch\",\"path_on_host\":\"$PWD/scratch.ext4\",\"is_root_device\":false,\"is_read_only\":false}"
API vsock "{\"guest_cid\":3,\"uds_path\":\"$PWD/fc.sock_vsock\"}"
API machine-config "{\"vcpu_count\":1,\"mem_size_mib\":256}"
curl -s --unix-socket fc.sock -X PUT http://localhost/actions -H "Content-Type: application/json" -d '{"action_type":"InstanceStart"}' >/dev/null
sleep 12
pkill -f "api-sock fc.sock" 2>/dev/null || true
wait $OBS 2>/dev/null || true
echo "===== OBSERVER ====="; cat observer.log
echo "===== GUEST (init phases + mount) ====="; grep -aE "nucleus-init-phase|snapshot barrier|mount /work|WORKLOAD-RAN|error" vm.log | head -14
