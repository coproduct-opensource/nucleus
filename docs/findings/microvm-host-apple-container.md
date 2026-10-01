# Spike: Firecracker microVMs hosted in an Apple `container`

**Status:** PR0 of the host-tier plan (measurement only; nothing is wired into the CLI).
**Date:** 2026-09-29. **Machine:** Apple M5 Pro, macOS 26.6.2, `container` CLI 1.4.1.
**Recommendation: GO.** P1 passes, so the kill criterion does not fire. Before PR4 is
built on it, three findings change the plan (see [What changes in the plan](#what-changes-in-the-plan)).

## The question

Can `nucleus-node --driver firecracker` run inside an Apple `container` started with
`--virtualization`, with the container's VM acting as the L1 Linux host? The runtime's
default kernel (Kata 3.32.0, linux 6.18.35 arm64) has no KVM and no vhost-vsock, so the
spike builds its own L1 kernel and attaches it **per container** with
`container run --kernel`. No system-wide `container` property was changed.

## How to reproduce

```text
NUCLEUS_MICROVM_HOST_SPIKE=1 cargo test -p nucleus-cli --test microvm_host_spike \
    -- --ignored --nocapture --test-threads=1 <step>
```

The steps, in order: `build_l1_kernel`, `build_microvm_host_image`,
`p7_without_virtualization`, `p1_p2_kvm_and_devices`, `p2_minimal_capabilities`,
`p3_pod_boots`, `p5_exec_stdio`, `p4_workspace_roundtrip`, `p6_lifecycles`
(`NUCLEUS_SPIKE_P6_LOAD=exec|io` adds guest load), `p6b_forced_death`, `cleanup`.
Everything the harness creates is named `nucleus-spike-*`, and `remove()` refuses any
other name.

| File | Role |
|---|---|
| `docker/Containerfile.l1-kernel` | kernel.org 6.18.35 + the default kernel's own embedded config + the fragment, then `make Image` |
| `docker/l1-kernel.fragment` | the config delta |
| `docker/Containerfile.microvm-host` | debian bookworm-slim, Firecracker/jailer 1.17.0, guest kernel and rootfs, node and mcp, and the KVM probe. Every download is pinned by digest. |
| `docker/kvm-probe.c` | the in-container KVM ioctl probe. It is throwaway: PR2 moves it into `nucleus-hostctl`. |
| `crates/nucleus-cli/tests/microvm_host_spike.rs` | the harness, which drives `container` through `std::process::Command` |

## Results

| # | Criterion | Result | Numbers |
|---|---|---|---|
| P1 | `/dev/kvm`, API 12, `KVM_CREATE_VM` | **PASS** | `KVM_GET_API_VERSION`=12, `KVM_CREATE_VM` ok, `KVM_CREATE_VCPU` ok, max IPA 40 bits. The kernel boots at EL2 and prints `kvm [1]: Hyp nVHE mode initialized successfully` and `nv: 568 coarse grained trap handlers`. **No kernel argument is needed**: KVM picks nVHE by itself. |
| P2a | vhost-vsock, tun, cgroup2 | **PASS** | `/dev/kvm` (10,232), `/dev/vhost-vsock` (10,241) and `/dev/net/tun` (10,200) all exist and open read-write without `mknod`. cgroup2 is mounted with controllers `cpuset cpu io memory hugetlb pids`, and `mkdir` under `/sys/fs/cgroup` works. `subtree_control` starts empty; the jailer enables what it needs. `bridge-nf-call-iptables`=1. |
| P2b | minimal `--cap-add` | **PASS** | **`CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`**, added to the runtime default (CapEff `a80425fb`, the usual OCI default set). Found by leave-one-out; see the table below. |
| P3 | node boots a pod, proxy healthy | **PASS** | Pod create took 2.7–3.0 s, and the proxy answered `/v1/health` within 0.07–0.13 s: `sandbox_proof` tier 2 (`spiffe-identity`). The node was healthy 0.2 s after `container run` returned (0.7 s). |
| P4a | seed → guest edit → harvest (clean end) | **PASS** | `mkfs.ext4 -d` seed on the `/srv` volume. The guest copied a file, created a file and deleted `src/main.rs`. After cancel, `e2fsck -fp` returned 1 (journal replayed) and `debugfs cat` returned every synced edit. |
| P4b | the same after an unclean kill | **PASS** | `pkill -9 firecracker` mid-pod, then `e2fsck -fp` returned 1 and every synced edit survived. |
| P5a | `exec -i` 10 MiB byte-exact plus EOF | **FAIL**, with a workaround | Streaming full-duplex **wedges** (details below). Half-duplex works at every size: 1, 2, 4, 8 and 10 MiB were each byte-exact, with EOF propagated, in 85–370 ms. |
| P5b | MCP through `exec -i nucleus-mcp` | **PASS** | 5 of 5 runs passed. `initialize` took 55–83 ms including the exec spawn, `tools/list` took 0.29–0.52 ms and returned 6 tools, and the MCP server exited 0 on EOF. |
| P6 | 40 lifecycles, crash spacing | **PASS** (no deaths) | 40/40 idle, 40/40 under an exec storm and 40/40 under block I/O ([detail](#p6-crash-rate-against-3010)): 120 lifecycles and 0 host-VM deaths. Mean create to healthy was 2.5–2.7 s. |
| P6b | death detected in under 5 s, restart in under 60 s | **PASS** (forced) | `container kill` with a pod running: `container list` showed `stopped` after **0.50 s**, `container start` brought the node back healthy in **1.0 s**, the volume was intact (CA digest unchanged), and the next pod booted in 2.8 s. |
| P7 | no `--virtualization` gives a clear diagnostic | **PASS** | There is no `/dev/kvm`. Pod create returned `400: firecracker requires /dev/kvm (KVM not available)`. dmesg says why: `CPU: All CPU(s) started at EL1` and `kvm [1]: HYP mode not available`. With the default kernel plus `--virtualization`, `/dev/kvm` and `/dev/vhost-vsock` are both absent and `# CONFIG_VIRTUALIZATION is not set`, which confirms the premise. |

### P2: which capability does what (leave-one-out)

| Removed from {NET_ADMIN, SYS_ADMIN, SYS_PTRACE, SYS_RESOURCE} | Pod boots? | What fails |
|---|---|---|
| none (`ALL` also boots) | yes | |
| `CAP_NET_ADMIN` | no | `iptables ... Could not fetch rule set generation id: Permission denied` in the pod netns |
| `CAP_SYS_ADMIN` | no | `failed to create netns` |
| `CAP_SYS_PTRACE` | no | `nsenter: cannot open /proc/<fc pid>/ns/net: Permission denied`. The node enters the netns of a Firecracker that the jailer has already dropped to uid 123, which needs ptrace-read access. |
| `CAP_SYS_RESOURCE` | **yes** | not needed |
| no `--cap-add` at all | no | `failed to create netns` |

Each of these is needed even for a pod with no `network` block, because the node always
builds a netns with a default-deny iptables baseline (`net.default_deny`). `CAP_SYS_ADMIN`
is broad, but its blast radius is the container's own VM, not macOS.

### P5a: `container exec -i` wedges on full-duplex streams

When `cat` echoes stdin to stdout while stdin is still arriving, the transfer stalls
permanently. Of five runs it stalled at 1, 2, 4 and 10 MiB and completed at 8 MiB, so it
is a race, not a size threshold. Inside the container, `cat` sits in `anon_pipe_write`
with its stdout pipe full. It had read 9.56 MB and written 9.49 MB. Nothing drains its
stdout, even though the host side reads continuously. The same stall reproduces from a
plain shell pipeline, so the harness is not the cause. Stdin-only and stdout-only
transfers of 10 MiB are exact in under 0.1 s.

Two more facts matter for PR4:

- `SIGTERM` does not stop a wedged `container exec`. Only `SIGKILL` does.
- Killing the host-side client **leaves the in-container process running**. The harness
  had to `pkill` the orphaned `cat`s.

MCP over stdio is request/response and effectively half-duplex, so P5b passes. A large
tool response written while the client is still sending would hit this stall, though.

### P6: crash rate against #3010

#3010 measured the gatehouse builder, which is nested virtualization through Lima on the
same Virtualization.framework layer. It dies about every **13 microVM boots** (median;
35 crashes in 525 attempts). This spike booted about **140 nested microVMs** in all
(120 P6 lifecycles plus P2 trials, P3, P4, P5 and P6b) with **0 host-VM deaths**.

| Run | Guest load per pod | Lifecycles | Deaths |
|---|---|---|---|
| idle | none (boot, health, cancel) | 40 | 0 |
| exec | ~4.5k fork+exec/s for 10 s (`rounds` ~43k–54k) | 40 | 0 |
| io | 16 MiB `dd conv=fsync` rounds to a scratch disk for 10 s (361–383 rounds, ~0.6 GiB/s, ~230 GiB over the run) | 40 | 0 |

If a death came every 13 boots, the chance of none in 140 would be 0.923^140 ≈ 1×10⁻⁵.
So this setup does **not** reproduce #3010's rate. The comparison is not like for like,
and the report should not claim more than it measured:

- A gate build runs minutes of heavy compilation per microVM. These pods ran at most 10 s.
- #3010's layer is Lima's VZ configuration, and this is Apple `container`'s.

The crash is still possible here. P6b shows that recovery from one is fast (0.5 s to
detect, 1.0 s to healthy), but it was measured by forced kill, not by a real crash.
Because no real death occurred, what `container list` reports after a genuine
Virtualization.framework assert is **still unmeasured**.

### Observed on the shared `container` service

At the start of the session every `container run`, `builder start` and `delete` hung at
"Starting container" for about 40 minutes. Nothing that belongs to this spike was running
at the time. Another session's `container machine` was running with nested
virtualization at 821% CPU (`gatehouse-lane`). A `machine stop` of a second machine had
been pending for 20 minutes. All queued operations completed within a second of that
machine's runtime being booted out. This is correlation, not proof. But the shared
apiserver serialised every container operation behind one wedged VM, so PR4's supervisor
cannot assume `container start` returns promptly and needs its own timeout.

## Findings that change the plan

1. **The pinned guest cannot boot under a node built from `main`.** Taking the node from
   this tree (`NODE_SOURCE=source`) against the `GUEST_RELEASE` 2.2.0 rootfs fails two ways:
   - `read_only: true` fails with "failed to create identity directory: Read-only file
     system", and the VMM exits about 3 s in. The 2.2.0 guest predates the SVID moving to tmpfs.
   - With a writable rootfs, the node refuses the pod: "the guest produced no egress
     attestation. Expected a `NUCLEUS_EGRESS_PROBE:` line".

   P3 through P6 therefore ran the matched 2.2.0 **release** node (`NODE_SOURCE=release`,
   the image's default), with a per-run writable rootfs copy on `/srv`. This is the
   plan's PR1b: the host tier needs guest release 2.3.0 before a source-built node can be
   used. The same skew probably affects `nucleus verify --tier2` on `main`, which sends
   `read_only: true` against the 2.2.0 rootfs. That was not verified here.
2. **Workload ownership in the seed.** `mkfs.ext4 -d` copies host ownership verbatim. The
   workload runs as `nobody` (65534), and guest-init chowns only the `/work` root. A
   root-owned seed can be read but not edited: `rm: cannot remove '/work/src/main.rs':
   Permission denied`. PR2's `workspace::seed` must stage the tree as the guest uid, or
   use `mke2fs -E root_owner=` plus a chown.
3. **Even a clean cancel is an unclean unmount.** In both P4 cases `e2fsck -fp` had to
   replay the journal (exit 1), and a write made after the guest's last `sync` was lost
   both times. PR2's harvest must always replay the journal. PR6 must `sync` inside the
   guest, or have the proxy do it, before it deletes the pod. Otherwise the review diff
   silently drops the agent's last writes.
4. **`exec -i` is half-duplex only** (P5a). PR4's `McpLaunch::ContainerExec` is fine for
   MCP's request/response traffic. It needs a deadline plus `SIGKILL` and an in-container
   reap, because killing the client orphans the process. For bulk streams, use
   `--publish-socket` or copy files through the volume.
5. **A block volume attaches to one running container at a time.** A second attach fails
   with `VZErrorDomain Code=2 "The storage device attachment is invalid"`. The long-lived
   host owns `/srv`, so probes and preflight containers must not mount it.
6. **A dead pod leaves its jail behind.** After the forced death, one
   `/srv/jailer/firecracker/<id>` directory survived the restart on the volume. It did not
   block the next pod. The node's startup reaper should clear it.
7. **The baked spec shadows the submitted one** on the 2.2.0 rootfs. It ships
   `/etc/nucleus/pod.yaml` (policy `demo`), so a workload in the submitted spec is ignored:
   `[workload] no workload configured`. The spike baked its workloads into private rootfs
   copies with `debugfs -w`.

## L1 kernel

The fragment, as merged over the default kernel's embedded config (`extract-ikconfig` of
`vmlinux-6.18.35-197-debug`, sha256 `fb2cfb79…8c8d`, checked in the build):

```text
CONFIG_VIRTUALIZATION=y
CONFIG_KVM=y
CONFIG_VHOST_MENU=y
CONFIG_VHOST=y
CONFIG_VHOST_VSOCK=y
CONFIG_DEBUG_INFO_NONE=y
# CONFIG_DEBUG_INFO_BTF is not set
```

`olddefconfig` kept every requested symbol. The base config is a debug build with DWARF
and BTF, which are dropped here to spare the build pahole and several GiB. `CONFIG_MODULES`
stays off, so everything is built in. There is no `CONFIG_ARM64_VHE` in 6.18 to set.

**Kernel arguments:** none. The runtime's own command line (`console=hvc0 ... init=/sbin/vminitd`)
is unchanged, and KVM comes up in nVHE mode without `kvm-arm.mode=nvhe`.

| Artifact | Size | Build time |
|---|---|---|
| L1 kernel `Image` (sha256 `7f1beb7167f70b031a73f731fc2c28af403e4fda064e3d3cacc989a9927a020d`) | 25.9 MB | 174 s for `make Image` (218 s end to end, including apt and the 147 MB source download), builder at 8 CPU / 12 GiB |
| `nucleus-spike-microvm-host:dev`, release node | 102.2 MB | 10 s warm |
| the same image, node and mcp built from source | — | 169 s cold (`cargo build --release -p nucleus-node -p nucleus-mcp`: 2 m 16 s) |

`container build -o type=local` writes one directory per platform, so the output is
`<dest>/linux_arm64/{Image,config}`.

## Cleanup

Every `nucleus-spike-*` container and the `nucleus-spike-srv` volume were removed, and so
were the images this spike pulled or built. `relay-clean`, the `container machine`s and
the Lima VMs were not touched. The builder (`buildkit`) was recreated at 8 CPU / 12 GiB
for the spike and then stopped and deleted.
