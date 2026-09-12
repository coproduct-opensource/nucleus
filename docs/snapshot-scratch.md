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

## The candidate design, stated as untested

**Attach the scratch but do not MOUNT it before the barrier.**

The drive must exist in the config at snapshot time, or the paths will not
match at restore. But if the guest has never mounted it, the snapshot contains
no ext4 metadata for it — only virtio-blk queue state, which describes the
device and not its content. On resume the guest mounts a fresh per-pod image at
the same in-jail name and reads its superblock for the first time.

That makes mounting scratch part of *personalization*, which is where it
belongs: the barrier already separates "a base anyone can restore" from "a VM
committed to one job", and `FETCH_POD_SPEC` is on the same side of it.

Two things this needs that do not exist:

1. `clone_safety`'s predicate is currently **attachment**-based
   (`snapshot_inputs` sets `writable_scratch` for any writable non-root drive).
   It would have to become mount-based, and the host cannot see whether the
   guest mounted anything — the guest would have to say so, which is what
   `SNAPSHOT_READY` already does for "I have asked for nothing yet".
2. Validation. The claim that virtio-blk device state survives a substituted
   backing file of identical geometry is **reasoning, not a measurement.** It
   is exactly the kind of claim #759 is the failure of.

## What this means for the plan

M3's snapshot work is larger than one line and depends on a guest-side change
that cannot be checked without a real boot. It does not block M2 — the
command-in (`FETCH_POD_SPEC`), result-out (scratch read-back) and host-signing
pieces are independent of whether the base is snapshot-restorable, and a pod
that cold-boots produces the same receipt as one that resumes.

The honest sequencing is therefore: finish and land M2, then validate the
deferred-mount hypothesis on real hardware before writing any of it into a
design.
