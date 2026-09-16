# Recovering a Lima VM that says "Running" but never boots

`limactl list` shows the VM as `Running`, but `limactl shell` refuses or resets
the connection, and `limactl start` eventually fails with
`did not receive an event with the running status`. `nucleus doctor` reports
**VM boot: … unreachable**.

"Running" means only that Apple's hypervisor started. The guest can still be
stopped at a prompt that nobody can see.

## 1. Let `nucleus doctor` measure it

```bash
nucleus doctor
```

It checks three things, cheapest first:

| Signal | What it means |
|---|---|
| SSH answers | The VM is fine. Every in-VM check runs as normal. |
| The console (`~/.lima/<vm>/serialv.log`) shows `requires a manual fsck`, `Kernel panic`, `(initramfs)` … | The boot stopped, and this line says why. |
| Nothing on the console, and the VM process is idle for 4 s | It is waiting at a prompt on a console Lima cannot capture. |
| Nothing on the console, CPU busy | It is still booting or provisioning, so wait. |

VMs created by current `nucleus setup` boot with `console=hvc0`, so the
console row is decisive for them. Older VMs use `console=ttyAMA0`, a UART
that Apple's VZ does not provide. On those VMs the console stays **empty**
whatever happens, so an idle-but-unreachable verdict is the most `doctor`
can say.

## 2. The common cause: a manual fsck after an unclean stop

A host crash, sleep or `limactl stop -f` can leave the root ext4 dirty in a
way the initramfs's automatic `fsck -a` refuses to repair:

```
cloudimg-rootfs: Inodes that were part of a corrupted orphan linked list found.
cloudimg-rootfs: UNEXPECTED INCONSISTENCY; RUN fsck MANUALLY.
The root filesystem on /dev/vda1 requires a manual fsck
(initramfs)
```

Current templates set `fsck.repair=yes`, so the initramfs runs `fsck -y` and
keeps booting. VMs created before that change need a one-time repair from
outside.

### Repair (keeps the VM)

```bash
VM=nucleus
limactl stop -f "$VM"
cp -c ~/.lima/$VM/disk ~/.lima/$VM/disk.bak   # APFS clone: instant, copy-on-write

# Any throwaway Linux VM that mounts the instance directory writable:
limactl start --name=diskfix --tty=false \
  --set ".mounts=[{\"location\":\"~/.lima/$VM\",\"mountPoint\":\"/vm\",\"writable\":true}] | .containerd.system=false | .containerd.user=false" \
  template:ubuntu-24.04
limactl shell diskfix -- sudo bash -c '
  L=$(losetup -P -f --show /vm/disk)
  e2fsck -fy ${L}p1; e2fsck -fn ${L}p1
  losetup -d $L'
limactl delete -f diskfix

limactl start "$VM"
```

`e2fsck -fy` exits 1 when it corrected errors. The second `e2fsck -fn` must
exit 0. Once the VM has booted and you trust it, delete `disk.bak`.

Two traps:

- `limactl edit --set` on a VM that is **already running** does not remount.
  If `/vm` is read-only, stop and start the helper VM.
- Never run the repair while the broken VM is running. Two kernels writing one
  ext4 image will corrupt it for real.

After this boot, make the fix permanent by running the template's boot drop-in
inside the VM:

```bash
limactl shell "$VM" -- sudo bash -c '
  echo "GRUB_CMDLINE_LINUX_DEFAULT=\"\$GRUB_CMDLINE_LINUX_DEFAULT console=hvc0 fsck.repair=yes\"" \
    > /etc/default/grub.d/60-nucleus-boot.cfg && update-grub'
```

### Or discard it

```bash
nucleus setup --force
```

## 3. Seeing the console of an old VM

If `doctor` says *idle and unreachable* and the VM predates `console=hvc0`, you
can boot its own kernel directly with a console VZ can capture. Lima boots a
`kernel`/`initrd`/`kernel.cmdline` found in the instance directory in place of
the firmware:

1. From a helper VM like the one above, copy `/boot/vmlinuz-<ver>` (`zcat` it
   into an uncompressed arm64 `Image`) and `/boot/initrd.img-<ver>` out of the
   disk's `BOOT` partition (`${L}p16`).
2. Put them in `~/.lima/$VM/` as `kernel` and `initrd`, and write
   `kernel.cmdline` as `root=UUID=<root fs uuid> ro console=hvc0`.
3. Run `limactl start "$VM"`, then read `~/.lima/$VM/serialv.log`.
4. **Delete the three files afterwards.** While they exist, the VM ignores its
   own GRUB.
