# macOS Quickstart (Tier 2 — real microVM isolation)

One command takes an Apple Silicon Mac from nothing to a booted nucleus pod:

```bash
curl -fsSL https://raw.githubusercontent.com/coproduct-opensource/nucleus/main/scripts/install.sh | bash
```

or, if you already have the `nucleus` binary:

```bash
nucleus setup
```

> **Verified against the published release, 2026-07-30.** From `limactl delete
> nucleus`, the one-liner resolved `v2.1.0` from `/releases/latest`, installed
> that CLI, provisioned the VM and booted a real pod on Apple Silicon: tier 2
> `spiffe-identity`, an allowed operation served from inside the sandbox, a
> forbidden one refused with `kind=kernel_denied`, and no PID-1 panic.
>
> `v2.1.0` is the first release whose rootfs carries a CA bundle — everything up
> to 2.0.2 panics as PID 1, and `GUEST_RELEASE_FLOOR` refuses to install those.
> Earlier revisions of this page told you to build from a clone instead, because
> at the time no published release could boot a pod.
>
> **Measured 2026-07-29: 48.7 s** from `limactl delete nucleus` to a booted,
> identity-proving pod, with `gh attestation verify` passing on every downloaded
> artifact. `--artifacts local` uses this working tree's build instead.
>
> If your Mac has installed nucleus before, setup pauses once at "Setting up
> secrets" on a macOS Keychain dialog and waits until you answer it — a changed
> binary is not on the existing items' ACL. See
> [Troubleshooting](#troubleshooting).

---

## Requirements, stated plainly

| | |
|---|---|
| Chip | Apple **M3 or newer** |
| macOS | **15 (Sequoia)** or newer |
| Lima | 2.0+ (`brew install lima`, or `nucleus setup --install-deps`) |

**There is no emulation fallback, and earlier versions of this page were wrong to
imply one.** Firecracker is a KVM-based VMM. Nested virtualisation on Apple
Silicon requires M3+ on macOS 15+; without it the Lima guest has no `/dev/kvm`,
and Firecracker does not run slowly — it does not run. The same applies to Intel
Macs, where QEMU's HVF accelerator virtualises the guest but cannot expose KVM
inside it.

On hardware that cannot do Tier 2, `nucleus setup` still configures Tier 0/1 and
says so; `nucleus verify --tier2` then fails, which is the truth rather than a
warning you can mistake for a caveat about speed.

`nucleus doctor` reads `/dev/kvm` directly rather than inferring from the chip
name. If the probe says available, Tier 2 works, whatever else the output guesses.

## What `nucleus setup` does

1. Creates a Lima VM from `scripts/lima/nucleus-<arch>.yaml` (Ubuntu 24.04,
   `vz`, nested virtualisation on).
2. Installs, into that VM, from digests pinned in
   `nucleus_spec::tier2_artifacts` and `nucleus_spec::vmm_version`:
   Firecracker + jailer, the guest kernel (SHA-256 verified against a constant
   compiled into the binary), the nucleus rootfs, `nucleus-node`, and the Linux
   `nucleus` CLI.
3. Generates three HMAC secrets in the macOS Keychain and writes them to a
   root-owned `0600` `/etc/nucleus/node.env` in the VM, along with a systemd unit
   that reads it.
4. Boots a real pod and verifies it (below).

The VM template names **no** artifact versions or URLs. Those live in one place
in the code, so the template cannot drift from what the node enforces — which is
how the published template came to pin a kernel URL that returns HTTP 404.

> **Keychain prompt.** The first run of a new or rebuilt `nucleus` binary makes
> macOS ask permission to read the secrets it stored. Setup waits at that dialog.
> It prints a line before touching the Keychain so a pause there is explicable.

## The proof: `nucleus verify --tier2`

```
$ nucleus verify --tier2

Tier 2 verification: booting a real nucleus pod
================================================
  [OK] /dev/kvm
  [OK] /dev/vhost-vsock
  [OK] firecracker
  [OK] guest kernel
  [OK] nucleus rootfs
  [OK] nucleus-node + secrets
  [OK] nucleus-node is answering on http://127.0.0.1:8080
  [OK] pod created in 7620 ms, tool-proxy at http://127.0.0.1:42149
  [OK] guest proved itself to its proxy: tier 2 (spiffe-identity)
  [OK] allowed operation served from the guest sandbox
       glob "*" -> {"matches":["audit"]}
  [OK] forbidden operation denied by policy (kind=kernel_denied)
  [OK] SPIFFE identity fetched
  [OK] task token fetched over vsock
  [OK] no PID-1 panic
  [OK] Firecracker is running under a seccomp filter
```

Measured on Apple M5 Pro / macOS 26.6 / Lima 2.2.0 / Firecracker 1.16.1,
2026-07-29.

Each line is there because it has failed:

| Assertion | What its absence looked like |
|---|---|
| tier 2 (spiffe-identity) | a silent fall back to the kernel-cmdline token |
| forbidden operation denied | the pod ran commands with no policy enforced |
| SPIFFE identity fetched | `Connection reset by peer` from a socket the node owned |
| task token over vsock | the guest reading it off `/proc/cmdline` instead |
| no PID-1 panic | a rootfs with no CA store panicking the guest kernel |
| seccomp filter | a fail-closed check reading the mode of a dead process |

This runs **inside** the Lima VM: the per-pod tool-proxy binds an ephemeral port
on the VM's loopback, which the workstation has no route to. `nucleus setup`
installs the Linux CLI there for that reason.

### Why not `nucleus run`?

`nucleus run` in enforced mode spawns a specific vendor's assistant CLI. Making
the quickstart's proof depend on a vendor binary would break this project's
vendor-neutrality rule and fail on any machine without it. `verify --tier2` drives
the tool-proxy directly — the same enforcement path, no vendor in it.

## Where guest artifacts come from

`nucleus setup --artifacts <auto|local|release>`:

- **`auto`** (default) — use this working tree's build output if it is complete,
  otherwise the pinned release.
- **`local`** — require the working tree's build (`scripts/firecracker/build-rootfs.sh`
  plus musl builds of `nucleus-node`, `nucleus-cli`).
- **`release`** — require the pinned release.

Releases at or below **2.0.2 cannot boot**: their rootfs contains no CA bundle
anywhere, and on such a rootfs the tool-proxy's drand client fails and, as PID 1,
takes the guest kernel with it. `tier2_artifacts::GUEST_RELEASE_FLOOR` refuses
them rather than installing a pod that cannot start.

The pinned release is **`2.1.0`**, the first build carrying the CA bundle,
the `ip netns exec` separator fix and the workload-API socket chown. Each
downloaded asset is checked against the release API digest and, when `gh` is on
PATH, against its Sigstore build provenance — the output says which of the two
happened rather than implying both.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `no /dev/kvm` in the VM | chip older than M3, or macOS older than 15 | no fix on that hardware; use a Linux host with KVM |
| `no /dev/vhost-vsock` | the host vsock module is not loaded | `sudo modprobe vhost_vsock` — the guest fetches its SVID and task token over vsock, so without it a pod fails at device setup |
| setup pauses with no output after "Setting up secrets" | macOS Keychain dialog awaiting an answer | answer it; it recurs when the binary changes |
| `nucleus-node did not become healthy` | a missing secret — the node exits at startup without all three | `nucleus setup` rewrites `/etc/nucleus/node.env`; the error quotes the node's own log |
| `pinned guest release ... is not published yet` | `GUEST_RELEASE` points past the newest release | `nucleus setup --artifacts local` |
| `ip netns exec ... failed` | fixed — iproute2 execs a `--` separator as the command | update; regression-guarded in `net.rs` |
| pod created but `Connection reset by peer` in the guest log | fixed — the workload API socket was root-owned while Firecracker runs jailed | update; the node now chowns it to the jailer uid |

Diagnose with:

```bash
nucleus doctor                                   # are the components installed?
nucleus verify --tier2                           # does a pod actually boot?
limactl shell nucleus -- sudo journalctl -u nucleus-node -n 50
```

`nucleus doctor` checks components **inside the VM**, which is where they are
used, and exits non-zero when one is missing. It previously checked the
workstation's own directories and graded every miss a warning, so it printed
"All checks passed" in the same minute `nucleus start` exited 1.

## Architecture

```
macOS host
└── Lima VM (Apple Virtualization.framework, nestedVirtualization: true)
    ├── /dev/kvm
    ├── nucleus-node ──── workload API (SVIDs, task tokens) over vsock
    └── Firecracker microVM (jailed, seccomp filter active)
        └── /init (guest-init) → nucleus-tool-proxy
                                 enforces the permission lattice
```

Two isolation layers: macOS↔Lima (Apple vz) and Lima↔pod (KVM + jailer +
seccomp + a default-deny network namespace).

## Commands

| Command | Description |
|---|---|
| `nucleus setup` | Provision everything, then prove it works |
| `nucleus setup --force` | Recreate the VM |
| `nucleus setup --install-deps` | Also install Lima via Homebrew |
| `nucleus setup --skip-verify` | Skip the boot proof (says Tier 2 is unverified) |
| `nucleus verify --tier2` | Boot a real pod and assert what it did |
| `nucleus verify --pins` | Print every pinned artifact URL and digest as JSON |
| `nucleus doctor` | Are the components installed, in the VM |
| `nucleus start` / `stop` | Run `nucleus-node` as a service |
