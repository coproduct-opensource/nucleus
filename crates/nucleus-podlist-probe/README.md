# nucleus-podlist-probe

The C2 cross-pod backstop, checked on the **real** guest.

`pod_api::caller_may_manage` is proved against the Lean `PodCrossView` relation
and host-unit-tested, and `scripts/cross-pod-scoped-check.sh` exercises the same
auth+filter composition KVM-free. What none of that checks is that a **booted**
pod, calling the scoped `POD_LIST` over its **own real vsock socket**, is served
a listing confined to its lineage. This binary runs as the workload inside pod A
and reports the pod set A can actually see.

## The probe reports; the host decides

A process inside A can only ever see A's own scoped view over A's own socket — it
cannot observe the operator view that proves sibling B exists, nor know B's id.
So the probe emits the raw id set it was served and the boot harness asserts the
property (it holds the ids of A, its child C, and sibling B):

```
A ∈ scoped  ∧  C ∈ scoped  ∧  B ∉ scoped  ∧  {A,B,C} ⊆ operator  ∧  scoped ⊊ operator
```

Self-present (`A ∈ scoped`) is checked by the host, against the id the operator
was given at create time. The probe does not know its own id and does not ask:
on Firecracker the only source is `FETCH_POD_CALLER_TOKEN`, which is served
once, to `nucleus-guest-init`, before any workload exists (#2724, #3113), and a
workload asking for it is refused. `POD_LIST` needs no token; the vsock socket
is the authority. The probe can send nothing else.

Self-present is **necessary but not the scoping signal** — a fail-open guest also
sees itself. `C ∈ scoped` is the discriminating tooth that proves the live filter
is *lineage-scoped*, not *self-only*; `B ∉ scoped` is the isolation; the operator
control proves B/C genuinely booted. The probe's local PASS means only "the
listing is real, now go check it."

## Verdict

A sentinel on **both** stdout and stderr, plus the exit code (the tool-proxy
drains stderr into the guest console, where the harness greps it back):

- `NUCLEUS_PODLIST_PROBE: PASS ids=<comma,list>` — a real, non-empty listing;
  `ids=` is the host's to check.
- `NUCLEUS_PODLIST_PROBE: FAIL: <reason>` (exit 1) — missing/empty/malformed
  reply or a refusal object.

## CI lane

`.github/workflows/podlist-probe.yml` boots this probe on a real x86_64
Firecracker guest on every pull request that touches its inputs (the probe, the
node, the tool proxy, guest-init, the pod spec, the harness, the rootfs build)
and in the merge queue, where it decides scope from the group's diff. Its
requireable twin, `podlist-probe-noop.yml`, passes only when those inputs are
untouched on a pull request; a runner without `/dev/kvm` is red in the real
lane, never green (#2604).

Coverage boundary: hosted arm64 runners have no KVM, so aarch64 Firecracker is
the weekly metal job in `quickstart-boot.yml` only; Apple Silicon's `vz` driver
(`nucleus setup` on a Mac) is a different driver, not Firecracker coverage.
