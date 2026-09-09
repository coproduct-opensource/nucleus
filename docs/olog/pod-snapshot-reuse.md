# Olog: content-addressed pod execution and snapshot reuse

An [olog](https://arxiv.org/abs/1102.1889) — objects are types read as English nouns, arrows are
functions read as "is", and the laws are diagrams that must commute.

**This file is checked.** `crates/nucleus-node/tests/olog.rs` parses the tables below and fails if
a named symbol or file no longer exists. That is the whole point of writing it down: a prose
description of a system decays silently, and this repository has produced five things that were
"typed, tested, documented, and read by nothing." An olog whose arrows must resolve cannot quietly
become false — it can only break the build.

What it does *not* claim: that the arrow does what its reading says. The laws below carry that,
and each names the test that enforces it.

---

## Objects

Each box is a type, read as a noun phrase that makes the arrows into sentences.

| object | reading | where |
|---|---|---|
| `PodSpec` | a pod specification | `crates/nucleus-spec/src/lib.rs` |
| `Program` | what a pod computes, independent of where it runs | `crates/nucleus-spec/src/identity.rs` |
| `ImageSpec` | an image, named by path and pinned by digest | `crates/nucleus-spec/src/lib.rs` |
| `ArtifactDigest` | the bytes of an artifact, as an identity | `crates/nucleus-spec/src/lib.rs` |
| `VmmVersion` | a version of the virtual machine monitor | `crates/nucleus-spec/src/vmm_version.rs` |
| `VmmVerdict` | whether a VMM build may be launched on | `crates/nucleus-spec/src/vmm_version.rs` |
| `Derivation` | everything that must hold again for a restore to mean what the snapshot meant | `crates/nucleus-node/src/snapshot_store.rs` |
| `Manifest` | what a published base records about itself | `crates/nucleus-node/src/snapshot_store.rs` |
| `HostIdentity` | the machine, as far as a restored guest can tell | `crates/nucleus-node/src/snapshot_store.rs` |
| `SnapshotArtifacts` | the two files a snapshot is | `crates/nucleus-node/src/snapshot_vmm.rs` |
| `SnapshotSafety` | whether a microVM may be a base | `crates/nucleus-node/src/snapshot.rs` |
| `SnapshotInputs` | what the snapshot path needs from a pod, captured at launch | `crates/nucleus-node/src/snapshot_store.rs` |
| `Lookup` | the answer to "is there a base for this derivation" | `crates/nucleus-node/src/snapshot_store.rs` |
| `NoBase` | why this launch is cold-booting | `crates/nucleus-node/src/snapshot_restore.rs` |
| `PodMaterial` | the per-pod secrets the host has served this guest | `crates/nucleus-node/src/workload_api_vsock.rs` |
| `LaunchAttestation` | what was actually loaded into a microVM, measured | `crates/nucleus-identity/src/attestation.rs` |

## Aspects

Read each row as: *a `source` **is** a `target`*, via the named function.

| arrow | reading | site |
|---|---|---|
| `program_digest` | a pod specification **is** a program | `crates/nucleus-spec/src/identity.rs:program_digest` |
| `image_identity` | an image **is** the digests of its parts | `crates/nucleus-spec/src/identity.rs:image_identity` |
| `judge_version` | a VMM version **is** a verdict on that build | `crates/nucleus-spec/src/vmm_version.rs:judge_version` |
| `found` | a verdict **is** the version it was reached about | `crates/nucleus-spec/src/vmm_version.rs:found` |
| `snapshot_inputs` | a launched machine **is** what a snapshot of it would name | `crates/nucleus-node/src/firecracker_config.rs:snapshot_inputs` |
| `derivation` | captured launch inputs and a program **are** a derivation | `crates/nucleus-node/src/snapshot_store.rs:derivation` |
| `name` | a derivation **is** a content address | `crates/nucleus-node/src/snapshot_store.rs:name` |
| `detect` | this process **is** running on a host | `crates/nucleus-node/src/snapshot_store.rs:detect` |
| `clone_safety` | a running microVM **is** safe to clone, or is not | `crates/nucleus-node/src/snapshot.rs:clone_safety` |
| `personalizes_the_vm` | a workload-API command **is** one that makes a VM one particular pod | `crates/nucleus-node/src/workload_api_protocol.rs:personalizes_the_vm` |
| `create` | a safe microVM **is** a pair of snapshot files | `crates/nucleus-node/src/snapshot_vmm.rs:create` |
| `publish` | staged snapshot files **are** a base at a derivation | `crates/nucleus-node/src/snapshot_store.rs:publish` |
| `lookup` | a derivation **is** a base, an absence, or a refusal | `crates/nucleus-node/src/snapshot_store.rs:lookup` |
| `place_base` | a published base **is** a file inside this pod's jail | `crates/nucleus-node/src/snapshot_restore.rs:place_base` |
| `bring_up` | a spawned VMM **is** a running machine, restored or cold | `crates/nucleus-node/src/snapshot_restore.rs:bring_up` |
| `base_for` | a launch **is** entitled to a base, or is not | `crates/nucleus-node/src/snapshot_restore.rs:base_for` |
| `network_overrides` | a configuration **is** the tap retargeting a restore needs | `crates/nucleus-node/src/snapshot_restore.rs:network_overrides` |
| `verify` | a placed image **is** the image that was pinned | `crates/nucleus-node/src/image_identity.rs:verify` |

---

## Laws

Each is a diagram that must commute, and each names the test that makes it fail when it stops.

### L1 — A program is what a pod computes, not how it is written

    reformat                       set_credentials
PodSpec ────────► PodSpec      PodSpec ──────────────► PodSpec
   │                 │             │                      │
   │ program_digest  │ program_digest                     │
   ▼                 ▼             ▼                      ▼
Program ═══════ Program        Program ══════════════ Program

Reformatting, key reordering, credential changes, cgroup placement and audit routing all leave the
program fixed. Everything that decides the answer moves it.

- `formatting_and_key_order_do_not_change_the_program`
- `two_pods_differing_only_in_credentials_are_the_same_program`
- `host_placement_and_audit_routing_are_not_part_of_the_program`
- `the_same_bytes_at_different_paths_are_the_same_program`
- `everything_that_decides_the_answer_changes_the_program`

The exclusion set is a **type**, not a filter: `program_digest` destructures `PodSpecInner`
exhaustively, so a new field is `error[E0027]` until someone classifies it.

### L2 — A path is not an identity

`program_digest` is defined only where the image is pinned; an unpinned image has no program.
That is what makes `ImageSpec::kernel_digest` worth setting rather than a field left off forever.

- `an_unpinned_image_has_no_program_identity`

### L3 — A derivation names the program, never the pod

No arrow into `Derivation` factors through anything per-pod: not the tap name, guest MAC, vsock
path, guest CID, or pod id. Those are what `place_base` and `network_overrides` patch, and a base
naming them would be a base of exactly one pod.

- `a_derivation_names_the_program_not_the_pod` — asserts absence in the canonical preimage itself
- `every_derivation_field_changes_the_name` — the converse; an inert field would let two different machines share a base

### L4 — Judgement does not discard its evidence

    judge_version                found
VmmVersion ──────────► VmmVerdict ────► VmmVersion
     ║                                       ║
     ╚═══════════════════════════════════════╝

`found ∘ judge_version = id` on every parseable input. A floor exists precisely so more than one
version is acceptable, so "acceptable" alone does not identify the VMM.

- `an_acceptable_verdict_still_says_which_version`

### L5 — Safety is decided from what the host served, never from what the guest says

`clone_safety` is a function of the host's own record: the barrier flag and the personalization
flag, both set as a side effect of *answering* a vsock command. The guest is the thing being
contained, so it is not consulted about whether it is safe to clone. "Cannot be shown" reads as
"no" — a pod whose bridge is gone is not at its barrier.

- `personalizes_the_vm` classifies every command exhaustively; a new one is a compile error
- `an_unsafe_verdict_refuses_without_talking_to_the_vmm`
- `a_pod_may_manage_pods_but_may_not_publish_a_base`

### L6 — Publication is write-once, and the kernel is what enforces it

`publish` is a partial function: at most one base ever exists at a name. It is `rename()` onto a
non-empty directory returning `ENOTEMPTY`, so there is no interval between checking and acting.

- `a_second_publish_is_refused_and_does_not_overwrite` — falsified by removing the target first

### L7 — Restoring preserves the base

    restore                run for 4s
base ────────► microVM ──────────────► microVM
  ║                                        │
  ╚════════════════ mem unchanged ═════════╝

Measured, not assumed: Firecracker's File backend maps the memory image `MAP_PRIVATE`. Without
this one base could not back many clones, and reuse would be corruption.

- `a_base_this_code_published_is_one_this_code_restores`

### L8 — A base is restorable only where its own vsock path is free

The vsock UDS path is inside the snapshot and re-bound at load; it cannot be overridden. Under the
jailer every pod sees the same in-jail path in a different chroot — identical inside, distinct
outside — which is the only arrangement making a shared base coherent.

- `an_unjailed_launch_is_refused_a_base`
- `a_base_this_code_published_is_one_this_code_restores` — falsified by removing the stale-socket
  clearing, which reproduces `EADDRINUSE` from inside device restore

### L9 — Placement links, never copies

`place_base` factors through the same inode. A copy would be correct and useless: 256 MiB costs
more than the ~79 ms cold boot it replaces, making the cache slower than no cache.

- `placing_a_base_hard_links_it_rather_than_copying_it` — asserts `(st_dev, st_ino)` equality

### L10 — Every refusal is distinguishable to someone entitled to it

`Lookup` and `NoBase` are enums over the reasons rather than `Option`, because a silent miss on a
shared store is a cache that never warms with nobody able to say why. The dual constraint holds
too: per ADR 0001 §3 a non-owner is answered exactly as a non-existent resource, so an
*unentitled* caller learns nothing distinguishable.

- `a_base_from_another_host_is_refused_not_silently_missed`
- `a_foreign_host_refusal_names_both_machines`
- `a_partial_base_is_damaged_rather_than_absent`

---

## What is not yet an arrow

Stated so the gaps are legible rather than discovered:

- **`Base → Receipt`.** Nothing attests that a pod restored from a base rather than booting cold,
  so a receipt cannot yet distinguish them. `LaunchAttestation` measures kernel, rootfs and config
  — not a snapshot.
- **`Base → Tenant`.** The store is node-global. Co-residency needs a tenant dimension in the
  derivation or the placement, and per the plan's security section cross-tenant page sharing is
  refused for everything but a declared public-workload tier.
- **`MicroVM → Barrier` is a marker, not a block.** `announce_snapshot_ready` returns immediately
  and the guest proceeds, so the window in which a base can be taken from a *running* pod is
  microseconds wide. Safety is unaffected — the personalization flag refuses the clone — but
  base-building wants the guest to wait, which is a guest change not yet made.
