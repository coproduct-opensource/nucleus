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

**94% of pod create is waiting for the in-guest tool-proxy to answer a health
check.** The microVM itself is up in about 200 ms; the remaining ~3.13 s is
`wait_for_proxy_health` polling at 100 ms intervals — about 31 polls, so this
is real in-guest startup, not a fixed sleep. The guest's own trace agrees and
locates it: `nucleus-startup-trace total=697ms … vsock_bind=1ms`, so
`guest-init` finishes in ~700 ms and the tool-proxy spends roughly 2.4 s more
before it reports healthy.

The consequence for the "nucleus builds nucleus" plan is direct, and it is not
what the plan assumed:

> **A 17 ms restore removes at most ~200 ms of a ~3.4 s pod create — under 6%
> — unless the base is taken PAST the point where the proxy is healthy.**

The 17 ms figure in `snapshot_restore.rs` is a real measurement of *VMM* restore
(10 ms load + 6 ms resume vs ~79 ms cold boot). It is not wrong. It is just
measuring the part of pod create that was already nearly free. Optimising the
VMM further is optimising 6% of the wall clock; the other 94% is in-guest
process startup, which a snapshot captures **only if the barrier sits after
it**.

That makes barrier placement the design question, not an implementation
detail. A base frozen at the mount barrier — before `/work` and before
personalisation, which is where `clone_safety` can certify it — is frozen
*before* the tool-proxy is healthy, and therefore saves the cheap 200 ms and
none of the expensive 3.13 s.

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

1. **Measure the 3.13 s before optimising the 200 ms.** Whatever the tool-proxy
   is doing between `vsock_bind` and its first healthy response is the budget.
   Nothing here has looked at it yet.
2. **A base is only worth taking where it captures that time.** Freezing at the
   mount barrier is the safe place and the cheap place; those are not the same
   place, and the plan treated them as one.
3. **Publishing a base at all needs the scratch question answered first** —
   `snapshot-scratch.md` argues it is a real constraint rather than a default to
   flip, and this measurement does not weaken that argument.

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
