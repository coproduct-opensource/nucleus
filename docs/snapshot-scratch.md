# A snapshot base cannot carry a mounted writable scratch

**2026-09-12.** A correction to the "nucleus builds nucleus" plan, which
described making pods snapshot-eligible as *"two one-line policy changes"*:
turn on `--firecracker-api-boot`, and stop `scratch_for_pod` auto-provisioning
a writable disk. The first is a one-line change. **The second is not a policy
question at all**, and the reasoning already in `snapshot.rs` is better than
the plan's.

## What the plan got wrong

`clone_safety` returns `WritableScratchAttached` as its **first** refusal, so
every jailed pod is unsnapshottable today. The plan read that as a policy
default to flip. It is not — the doc comment states the actual constraint:

> Scratch is per-pod and writable. A restored clone inherits the base's
> in-memory ext4 state for it, so two clones pointed at one file corrupt each
> other, and giving each a fresh file at the same in-jail name leaves the
> guest's cached metadata describing a filesystem that is no longer there.
> Both are filesystem corruption arriving later and elsewhere.

The obvious workaround does not work, and is the *second* case above.
Firecracker requires that disk backing files be at **the same relative path**
to the restoring process (`docs/snapshotting/snapshot-support.md`), and because
each pod has its own jail, `/scratch.ext4` can be a different host file per
pod at the same relative path. That looks like it solves the sharing problem.
It does not: the guest's cached ext4 metadata came from the snapshot and now
describes a filesystem that is not underneath it.

## Upstream agrees, and has the scars

- Firecracker's own snapshot design says sharing is for memory pages and
  **read-only** disks. Writable disks are not in the sharing story.
- `firecracker-containerd` #759 is EXT4 inode-checksum errors after loading a
  snapshot, with the restored disk state inconsistent with the VM's.
- Firecracker #4014: drives cannot be reconfigured for a snapshot-booted VM, so
  there is no "attach a different disk at restore" escape either.
- Firecracker #5795 — block-level copy-on-write overlay with dirty-bitmap
  tracking, which *would* solve this — is an open **feature request**, not a
  capability. Tensorlake ships something equivalent out-of-tree. Neither is in
  the pinned v1.16.1.

## The candidate design — MEASURED 2026-09-12, and it holds

**Attach the scratch but do not MOUNT it before the barrier.**

The drive must exist in the config at snapshot time, or the paths will not
match at restore. But if the guest has never mounted it, the snapshot contains
no ext4 metadata for it — only virtio-blk queue state, which describes the
device and not its content. On resume the guest mounts a fresh per-pod image at
the same in-jail name and reads its superblock for the first time.

That makes mounting scratch part of *personalization*, which is where it
belongs: the barrier already separates "a base anyone can restore" from "a VM
committed to one job", and `FETCH_POD_SPEC` is on the same side of it.

### The measurement

`scripts/experiments/snapshot-deferred-mount.sh`, on Firecracker v1.16.1,
aarch64/KVM, 2026-09-12. Raw Firecracker and a busybox rootfs — the question is
about the VMM, not nucleus, so bringing ninety crates into it would only add
ways to be wrong.

Boot with a 16 MiB ext4 attached as `vdb` and never mounted; snapshot; restore
twice, each against a **fresh, distinct** image of identical geometry at the
drive's path; mount, write, sync, unmount in each guest; `fsck` both host-side.

| | |
|---|---|
| precondition — vdb mounts at snapshot time | **0** |
| restore A / B | mounted, wrote, unmounted cleanly |
| `result-A.ext4` / `result-B.ext4` contents | `A.txt` only / `B.txt` only |
| cross-contamination | **none** |
| `EXT4-fs error` in either guest | **0** |
| `e2fsck -fn` on both | clean, 12/4096 files, 1292/4096 blocks |

So the corruption `clone_safety` refuses is specifically about a **mounted**
scratch. An unmounted one leaves virtio-blk queue state in the snapshot and no
ext4 metadata, and a fresh filesystem underneath it is read for the first time
on the restored guest's own mount.

This is one configuration, not a proof. It says nothing about a scratch of
DIFFERENT geometry, about a guest that read the raw device without mounting it,
or about the same trick on a root filesystem. Each would need its own run.

## What still has to change

`clone_safety`'s predicate is **attachment**-based: `snapshot_inputs` sets
`writable_scratch` for any writable non-root drive. It has to become
mount-based, and the host cannot see whether the guest mounted anything — the
guest must say so, which is exactly what `SNAPSHOT_READY` already does for "I
have asked for nothing yet". Extending that report to "and I have mounted
nothing writable" is the change.

Mounting scratch then becomes part of *personalization*, which is where the
barrier already puts `FETCH_POD_SPEC`: take the base, then tell the VM what to
run and give it somewhere to write.

## What this means for the plan

M3 is unblocked, and is a guest-side change plus a predicate, not the two
one-line policy flips the plan claimed.

It never blocked M2: command-in (`FETCH_POD_SPEC`), result-out (the scratch
read-back) and host-signing are independent of whether the base is
snapshot-restorable, because **a pod that cold-boots produces the same receipt
as one that resumes.** The measurement also settles the branch that would have
hurt: had the deferred mount failed, the base would have had to be scratch-free
entirely, which would have taken the output channel off the scratch disk and
invalidated the read-back.
