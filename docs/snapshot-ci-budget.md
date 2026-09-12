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

**2. A writable scratch — even when the spec declares none.**

```
refusing to snapshot this microVM: this microVM has a writable scratch disk,
which clones cannot share and cannot be given fresh without stranding the
guest's cached filesystem state
```

This one is worth stating precisely, because it is easy to read as a spec
problem and it is not: **the pod spec declared no `scratch_path` at all.**
`scratch_for_pod` provisions one for every *jailed* pod, so a jailed pod always
has a writable scratch, `clone_safety` always sees one, and **no base can be
published on the live path today**. Every pod cold-boots, which is what the
table above measures.

## What this changes about what to do next

1. **A base frozen at the mount barrier is worth ~2.2 s per pod** — two thirds
   of pod create. The barrier is the place `clone_safety` can certify, and it
   is also, contrary to this document's first version, the place worth
   freezing. They are the same place after all.
2. **The residual target is the tool-proxy's ~0.75 s**, which a barrier
   snapshot does not capture because the barrier precedes it. That is the
   second-order optimisation, worth roughly a third of what the snapshot is.
3. **None of it is reachable until a base can be published at all.**
   `scratch_for_pod` provisions a writable scratch for every jailed pod, so
   `clone_safety` refuses every one of them — see refusal 2 below, and
   `snapshot-scratch.md` for why that constraint is real rather than a default
   to flip.

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
