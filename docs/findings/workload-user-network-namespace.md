# A private user+network namespace inside the workload's PID namespace — 2026-11-14

This is the runtime half of #3528, landed on top of the wire types (#3534). It makes
`WorkloadNamespace::PrivateUserNetwork { inner_uid, loopback }` admissible where the runtime can
make it true, and says what a receipt then claims. The question #3534 left open is the order of
two `unshare` calls: the PID namespace a guest workload already gets (#3344) and the user+network
namespace #3528 adds. The answer below is written down before the code. It decides what the
signed receipt says.

## The decision: PID namespace first, as root; user+network last, as the dropped workload

The guest's pre-exec hook already runs three processes (`hardening/pidns.rs`): the **waiter**, the
**init** (pid 1 of a new PID namespace) and the **workload** (pid 2). A private user+network
placement adds steps to the init and to the workload. The full sequence is:

| # | process | credentials | step | fails as |
|---|---|---|---|---|
| 1 | waiter | root, runtime's namespaces | `unshare(CLONE_NEWPID \| CLONE_NEWNS)`, `clone` the init | errno through std's status pipe |
| 2 | init | root, new PID+mount ns | `PR_SET_PDEATHSIG(SIGKILL)`, `/` made private, fresh `/proc` (`hidepid=invisible`) | errno |
| 3 | init | root | **`socketpair`**: one private channel to the workload it is about to fork | errno |
| 4 | init | root | `clone` the workload; keep only its own end of the channel | errno |
| 5 | workload | root | close the init's end; `setgroups(0)`, `setresgid(outer)`, `setresuid(outer)` | errno |
| 6 | workload | outer uid, no capabilities | **`PR_SET_DUMPABLE 0`, `unshare(CLONE_NEWUSER \| CLONE_NEWNET)`** | errno (`EPERM`, `ENOSPC`, `EINVAL`) |
| 7 | workload | full capabilities in the new user ns only | **raise `lo`, only if `loopback` was requested** | errno |
| 8 | workload | | **send one request byte** on the channel (`MSG_NOSIGNAL`) | `EPIPE` if the init is gone |
| 9 | init | root | **check the new user namespace's owner is `outer` (`NS_GET_OWNER_UID`), then write `uid_map`, `setgroups`=`deny`, `gid_map`**, each the one line `inner outer 1` | answers *refused* |
| 10 | init | root | **send one answer byte**: granted or refused; close the channel; reap until the workload exits | |
| 11 | workload | | **read the answer** | refused: `EACCES`; channel closed with no answer: `EPIPE` |
| 12 | workload | inner uid | **read back `/proc/self/uid_map`, `gid_map` and `setgroups`**; require exactly `inner outer 1`, twice, and `deny`; require real and effective uid and gid to be `inner` | `EACCES` |
| 13 | workload | | **lock `SECBIT_NOROOT`, clear the ambient set, clear effective, permitted and inheritable**; read them back empty | errno / `EACCES` |
| 14 | workload | inner uid, no capabilities | the ordinary hook: descriptor sweep, `no_new_privs`, rlimits, Landlock (with its own `/proc`), the write layer, the syscall filter | errno |
| 15 | workload | | exec | errno |

Steps 1, 2, 4, 5, 14 and 15 are main's, unchanged. Steps 3 and 6 to 13 are new, in bold.

### Why this order and not the other

The other order — the user namespace first, made by the waiter, and the PID namespace inside it
— is how an unprivileged container runtime (`unshare -Urpf --mount-proc`) works. It is rejected
here for three reasons, each of them about authority:

1. **Who owns the PID and mount namespaces.** A namespace is owned by the user namespace its
   creator was in. Made first, by root, the PID and mount namespaces are owned by the initial
   user namespace. The workload's later user namespace is a child of that one, and capabilities
   in a child user namespace confer nothing over namespaces its parent owns. So the workload,
   even as `inner_uid` 0 and before step 13 clears its capabilities, cannot remount `/proc`,
   mount anything, or signal the root init. In the other order the PID and mount namespaces
   would belong to the workload's user namespace, and step 13 would be the only thing standing
   between the workload and them.
2. **The mount of `/proc`.** Mounting procfs from inside a non-initial user namespace is
   allowed only when an existing procfs is fully visible (`mount_too_revealing`). The guest's
   `/proc` is mounted `hidepid=invisible`, so this depends on how the guest mounted it. Done by
   root first, the mount needs nothing of the kind.
3. **Who writes the map.** The map must be written by a process with `CAP_SETUID` and
   `CAP_SETGID` in the *parent* user namespace, unless the workload maps only its own uid. #3528
   found the workload cannot even do that: after std's root-to-workload drop it is non-dumpable,
   so its own `/proc/self/uid_map` is owned by root and the write is `EACCES`. In this order a
   writer is already there. The init is root in the parent user namespace, it shares the
   workload's PID namespace, and it is the workload's parent.

### What changed from #3528's mapper, and why

#3528 ran the map writer as a thread in the runtime, reached through a socket made when the
command was prepared. Under a PID namespace that design cannot work. The workload's `getpid()`
is 2 in its own namespace, and that number names some unrelated process in the runtime's `/proc`.
The runtime is not the workload's parent either, so #3528's `PPid` check would fail. That is a
fail-closed refusal, but by accident.

Making the init the writer removes five things #3528 needed:

- **The thread and its five-second window.** The channel is a `socketpair` the init makes during
  the spawn it serves (step 3), so it cannot outlive that spawn.
- **The per-fork random nonce.** It defended against a stale answer from an earlier spawn of a
  reused command, and with a channel made during the spawn there is no earlier spawn to answer
  for. `getrandom` in the hook, and its unseeded-kernel case, go too.
- **Pinning `/proc/<pid>` against pid reuse.** The workload is the init's own unreaped child,
  and the init does not reap until it has answered (step 10). A pid cannot be reused while its
  process is unreaped.
- **The `PPid`, `Uid`, `Gid` and `Groups` parsing of `/proc/<pid>/status`.** It is replaced by
  one kernel answer about the thing being mapped: the owner of the user namespace the init is
  about to write a map for (`NS_GET_OWNER_UID`). That owner is the euid of the process that made
  the namespace. It equals `outer` only if the workload dropped before it unshared (steps 5, 6),
  and it can never be 0 for a user namespace the workload made, because admission refuses an
  outer uid of 0.
- **The workload trusting the answer byte alone.** Step 12 reads the map back from the kernel.
  #3528's stale-nonce test showed why that matters: `inner_uid` 65534 is also the overflow uid
  an unmapped process reports, so `geteuid() == inner` alone does not show a map was written.
  `/proc/self/uid_map` is empty until a map is written.

What it keeps from #3528 and 507f0c042: the map line is formatted in the parent, never after the
fork; `setgroups` is `deny` before `gid_map`; `lo` is raised only when asked; `SECBIT_NOROOT` is
locked before capabilities are cleared; a closed channel is reported as an error through std's
status pipe instead of killing the workload with `SIGPIPE` (`MSG_NOSIGNAL`). That last one is
507f0c042's closed-mapper refusal, now `EPIPE` on either side of the exchange.

### Order as a type (ADR 0007 D-1)

The steps are values, not adjacent lines:

- `hardening::Isolation::PidnsThenUserNetwork` is the only isolation that carries a mapping.
  No variant combines a user+network namespace with the runtime's PID namespace, and the
  posture that leads to it is constructible only from a dropped, denylist-filtered posture whose
  spawn makes a PID namespace (`ChildConfinement::placed`).
- `pidns::enter` is generic over what goes inside the namespace. For the runtime's user+network
  namespaces it returns `()`. For a private one it returns `Unshared`, which only the workload
  branch of `enter` can mint: dropped (step 5), unshared (step 6), with its end of the init's
  channel. `Unshared::map` (steps 8 to 12) returns `Mapped`, and `Mapped::shed_capabilities`
  (step 13) returns `Placed`. Each takes the one before it by value. There is no way to ask for a
  map before the drop, or to shed capabilities before the map is verified.

## What each receipt then claims, and why it is true

**The launch receipt** (tool-proxy, schema 6) gains `ns=` in its hashed preimage, beside main's
`pids=`. Both are read off the `Hardened` that `ChildConfinement::restrict` mints when it installs
the hook, from the same `Isolation` the hook runs:

| isolation | `pids=` | `ns=` |
|---|---|---|
| `None` (shared PID namespace) | `shared` | `runtime` |
| `NetnsThenDrop` (the egress proxy) | `shared` | `private_network` |
| `PidnsThenDrop` (a guest workload, #3344) | `own` | `runtime` |
| `PidnsThenUserNetwork` | `own` | `private_user_network:<outer>:<inner>:<loopback>` |
| no hook (bare tier) | `shared` | `runtime` |

**The signed execution claim** (node, `nucleus.execution.v2`) carries `namespace`, the same
`NamespaceSetup`, now taken from that hook record (the supervisor's observation) rather than from
the admission decision. The node signs only if the observation equals what the spec asked for:
`WorkloadNamespace::admit(workload.uid, enforcement)`. A PID-namespaced workload with a private
user+network namespace therefore signs
`private_user_network { outer_uid, inner_uid, loopback }`.

**`NamespaceSetup` describes the user and network namespaces only.** It has no PID field, and
this change adds none. On main a guest workload already runs in its own PID namespace and signs
`runtime`, so `runtime` meant "the runtime's user and network namespaces" before this change too.
The doc comment now says so. The PID namespace is in the launch receipt's `pids=` and its hash
(the claim's `launch_hash`), not in a field of the claim. A relying party that needs "own PID
namespace" stated in the claim itself has nothing to read today. That is a gap, recorded rather
than closed here, because closing it changes the v2 wire format #3534 just published.

**Why the claim is true.** Under the PID namespace, std reports a failed hook through the copy of
its close-on-exec status pipe that the workload holds. The waiter and the init close theirs
(#3344), so `spawn()` returns `Ok` only if the workload's hook returned `Ok` and its exec
succeeded. The launch receipt is built only after `spawn()` returns `Ok`, and the observation the
node signs is read off that receipt. The workload's hook returns `Ok` only if each step in the
table above succeeded, and each step leaves something to see:

- the user namespace is new, and the workload's owner check (step 9) and read-back (step 12)
  show it maps exactly `inner outer 1` for both uid and gid, with `setgroups` denied;
- the network namespace is new, and a new network namespace has one interface, `lo`, which is
  down until step 7 raises it. Step 7 runs if and only if `loopback` is true;
- capabilities are empty, and `SECBIT_NOROOT` is locked (step 13, read back);
- after that, main's confinement runs unchanged (step 14). The workload denylist still refuses
  every namespace-creating call, so the workload cannot leave or add to this arrangement.

## Where it is admitted, and the refusals

`WorkloadNamespace::admit(outer_uid, enforcement)` is still the one decider. It now takes what
the deciding site knows:

- `enforcement` is `NamespaceEnforcement::{RuntimeOnly, PrivateUserNetwork}`. The node derives it
  from its backend (only `firecracker` runs the workload under a root guest runtime that makes a
  PID namespace). The tool-proxy derives it from the confinement it admitted
  (`ChildConfinement::namespace_enforcement`): a dropped, denylist-filtered posture whose spawn
  makes a PID namespace, on a Linux kernel that offers user namespaces.
- `outer_uid` must be stated (`workload.uid`). A default is not a mapping anyone can check from
  the spec alone. It must also not be 0 or `u32::MAX`, and `inner_uid` must not be `u32::MAX`:
  the first two would map to real root or to an id the kernel reserves, and the third to the
  kernel's reserved id.

Refusals, by when they happen:

| when | what | answer |
|---|---|---|
| node create, admission record, claim | backend is not `firecracker`; uid unstated or unmappable | `workload.namespace is refused: …` (`PostureRefused::WorkloadNamespace`) |
| tool-proxy launch admission | posture not dropped and filtered, PID namespace not its own, or the kernel's sysctls say no: `user.max_user_namespaces` missing or 0, `kernel.unprivileged_userns_clone` 0, or `kernel.apparmor_restrict_unprivileged_userns` 1 | refused by name before anything is spawned |
| spawn (the hook) | the kernel refuses the user namespace at step 6 (a limit, an LSM, no `CONFIG_USER_NS`), the init refuses or is gone (steps 8 to 11), the read-back disagrees (step 12) | the spawn fails with that errno. No child, no launch receipt, no observation, no signed claim |

The probe reads sysctls, so it can be wrong. Ubuntu's `apparmor_restrict_unprivileged_userns`
lets the `unshare` succeed and then denies the new namespace its capabilities, so the probe names
it. A policy the probe does not read fails at step 7 or 13 as a refused spawn. The probe exists
to name the common case before a spawn. It is not the control, and a test forces a placement
past it to show the hook alone refuses (below).

## Consequences

- **`RLIMIT_NPROC` now bounds this workload alone.** The kernel counts tasks per uid per user
  namespace (since 5.14), and the workload's user namespace is new and holds only the workload.
  That is the kernel's documented accounting; no test here measures it.
- **The workload door's peer uid is the outer uid.** `SO_PEERCRED` translates into the runtime's
  user namespace, so the door admits the same uid as before. A workload in a private network
  namespace cannot reach a TCP listener in the runtime's, loopback included. That is what
  "private" means, and it is why the request is per step.
- **No new `unsafe` site.** The exemplar ratchet's `unsafe_blocks` is at its baseline (11). The
  new raw syscalls are in `pidns::enter`'s existing block (the init's mapper, the workload's
  `unshare` and the `lo` ioctl), and steps 8, 11, 12 and 13 use `rustix`'s safe wrappers.

## Not established

- No live microVM boot with a gate step that asks for a private namespace. The Linux tests below
  run the hook as root on a VM, not inside a Firecracker guest.
- Nothing proves the absence of a path from inner uid 0 back to outer authority beyond the steps
  above; the read-backs show the state the hook leaves, not a confinement theorem.
- The signed claim does not state the PID namespace (above).
