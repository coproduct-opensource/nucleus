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

Self-present is **necessary but not the scoping signal** — a fail-open guest also
sees itself. `C ∈ scoped` is the discriminating tooth that proves the live filter
is *lineage-scoped*, not *self-only*; `B ∉ scoped` is the isolation; the operator
control proves B/C genuinely booted. The probe's local PASS means only "the
listing is real and self-scoped, now go check exclusion."

## Verdict

A sentinel on **both** stdout and stderr, plus the exit code (the tool-proxy
drains stderr into the guest console, where the harness greps it back):

- `NUCLEUS_PODLIST_PROBE: PASS self=<id> ids=<comma,list>` — real, self-scoped
  listing; `ids=` is the host's to check.
- `NUCLEUS_PODLIST_PROBE: FAIL: <reason>` (exit 1) — missing/empty/malformed
  reply, a refusal object, or self absent (an unscoped/failed query).
