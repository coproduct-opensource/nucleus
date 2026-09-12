# What a snapshot restore can actually save on a CI pod

**2026-09-12.** Measured on `nucleus-kvm` (Lima, aarch64, Firecracker v1.16.1,
`/dev/kvm`), booting the same pod three times with `--firecracker-api-boot` on.
This is the timing half of the snapshot question; [snapshot-scratch.md] is the
correctness half.

[snapshot-scratch.md]: ./snapshot-scratch.md

## The measurement

Three cold `POST /v1/pods`, same spec, digests pinned:

| wall | `proxy.health_wait` | `attestation.hash` | everything else |
|-----:|--------------------:|-------------------:|----------------:|
| 3347 | 3132 | 176 | 39 |
| 3521 | 3133 | 175 | 213 |
| 3524 | 3127 | 175 | 222 |

`vmm.preflight`, `prepare_jail`, `firecracker.spawn`, `seccomp.wait`,
`vsock.wait` and `cert.issue` each measured **0 ms** in all three.

## What it says

**94% of pod create is spent in `proxy.health_wait`.** But that stage is not
"the proxy is slow" — it is *the host waiting for the guest to finish booting*,
because the host starts polling at +214 ms and the guest has not finished its
kernel by then. Reading the guest console against the host clock decomposes it:

| phase | guest kernel clock | duration |
|---|---|---:|
| kernel boot (`0.000` → `Run /init as init process`) | 0.000 → 1.534 | **1.53 s** |
| `guest-init` (→ `[workload]`) | 1.534 → 2.598 | **1.06 s** |
| tool-proxy until it answers healthy | 2.598 → ~3.35 | **~0.75 s** |

Those sum to 3.34 s against a 3.35 s host wall, so the decomposition is
complete — there is no unexplained remainder.

### What a restore actually replaces

A VM snapshot restores memory and vCPU state, so the guest **resumes at the
frozen point and does not re-run its kernel**. A base frozen at the mount
barrier — `vsock_bind`, 669 ms into `guest-init`, so kernel clock ≈ 2.20 s —
skips everything before it:

> **~2.2 s of a ~3.35 s pod create, or about two thirds.** What remains is the
> ~0.75 s the tool-proxy spends becoming healthy, plus ~0.2 s of host-side
> work.

The `17 ms restore vs ~79 ms cold boot` figure in `snapshot_restore.rs` is a
VMM-level measurement — how long the *VMM* takes to start. It is correct and it
is not the interesting number. The interesting number is the guest boot the
restore skips entirely, which is 30× larger than the VMM difference.

### A correction

The first version of this document concluded the opposite — that a restore
"removes at most ~200 ms, under 6%". That was wrong, and wrong in the way that
would have redirected effort away from the thing worth doing. It treated
`proxy.health_wait` as irreducible in-guest proxy startup because the stage is
named after the proxy. It is named after what the host is polling, not after
what the guest is doing, and for the first 2.2 s of it the guest is booting.

The lesson is narrow and worth keeping: **a stage name describes the waiter,
not the work.** The host-side breakdown alone could not distinguish "the proxy
takes 3.1 s" from "the guest takes 3.1 s to reach a proxy that then answers
quickly"; only the guest console could, and those two readings imply opposite
optimisations.

## The two refusals a CI pod meets today, in order

Both are correct, and both were reached by trying it rather than reading it.

**1. No program identity.** `POST /v1/pods/{id}/snapshot` on a pod whose image
carries no digests:

```
this pod names an image but pins no digest for it, so its program has no
stable identity — set image.kernel_digest and image.rootfs_digest
```

`program_digest` refusing an unpinned image, exactly as designed. Pinning
`kernel_digest` and `rootfs_digest` clears it.

**2. A writable scratch — and the reason is not the obvious one.**

```
refusing to snapshot this microVM: this microVM has a writable scratch disk,
which clones cannot share and cannot be given fresh without stranding the
guest's cached filesystem state
```

The obvious reading — `scratch_for_pod` provisions a scratch, and any scratch
is refused — is wrong. `clone_safety` was changed at exactly that point:

> `ATTACHED is fine; MOUNTED is not` … This *was* "is a writable non-root drive
> attached", which refused every jailed pod.

The refusal above is `Mounted`, not "attached". The pod had booted fully, and a
booted pod has mounted `/work`. So the real question is **whether anything can
observe the VM while it is still at its barrier** — and today nothing can:

1. `guest-init` announces `SNAPSHOT_READY` and **does not stop**.
   `announce_snapshot_ready` is best-effort by design: "announcing a barrier is
   not a request for anything."
2. The host's handler declines to act on it, explicitly:
   > **Recorded, not acted on.** Taking the snapshot here would make every boot
   > wait on a decision only the operator has, so the guest is told to carry on
   > and the host keeps the fact for whoever asks to snapshot later.
3. So `at_snapshot_barrier` latches true, the guest proceeds to mount `/work`,
   and the operator's `POST /v1/pods/{id}/snapshot` — the only way to publish a
   base — necessarily arrives *after* the mount.

`clone_safety` is therefore **structurally unsatisfiable on the live path** for
any pod with a scratch, which is every jailed pod. Not because the check is
wrong, but because the only certifiable instant is one nothing is positioned to
catch. A synchronisation point does exist — the guest blocks reading the reply
to `SNAPSHOT_READY`, deliberately, "the content is not interesting, the
ordering is" — and the handler declines to use it, for a stated reason.

On `origin/main` it is not even a race: `/work` mounts at
`crates/nucleus-guest-init/src/main.rs:132`, *before* the pod spec is resolved,
so the barrier is announced with the scratch already mounted. #2867 moves that
mount past the barrier and is still in the merge queue.

## What this changes about what to do next

1. **A base frozen at the mount barrier is worth ~2.2 s per pod**, two thirds
   of pod create. The barrier is both where `clone_safety` can certify and
   where the saving is — contrary to this document's first version, the same
   place.
2. **Nothing can currently freeze there.** One of two things has to change, and
   it is a design choice rather than a flag:
   - a pod mode that **halts at the barrier** awaiting a snapshot decision — an
     explicit "build me a base" pod, paying the wait once rather than on every
     boot, which is the cost the handler's comment is refusing; or
   - deferring the `/work` mount to **first use** rather than to immediately
     past the barrier, so a pod that never touches `/work` stays certifiable
     for as long as it stays untouched.

   The second is the better shape: no new mode, and an ordinary pod becomes
   usable as a base rather than needing one built for the purpose.
3. **#2867 is a prerequisite either way** — without it the mount happens before
   the barrier is announced at all.
4. **The residual after a barrier snapshot is the tool-proxy's ~0.75 s**, which
   a barrier-frozen base does not capture. Second-order target, worth about a
   third of what the snapshot is.

## Reproducing

```sh
# in the KVM host, node running with --firecracker-api-boot
nucleus node --url https://127.0.0.1:9900 create pod-with-pinned-digests.yaml
# then, with a client cert minted from the node's CA:
curl -sSk --cert cli-cert.pem --key cli-key.pem \
  -X POST https://127.0.0.1:9900/v1/pods/<id>/snapshot
```

The boot breakdown is emitted by the node at `INFO` on the `boot_trace` target,
one line per pod create.
