# ADR 0013 — The eval cell: a pod that holds against a hostile agent with guest root

- Status: **accepted** (2026-10-08). Proposed 2026-10-07 with milestone M0 (#3332); the
  owner approved it on 2026-10-08. The incident table below records what answers each
  class as of acceptance; rows marked NOT YET carry the milestone that owns them.
- Tracks: milestone M0 of the eval-cell programme. M1–M6 are the milestones the table
  below names for each answer that is not yet in place.
- Rests on: [ADR 0007](0007-make-the-defect-unwritable.md) (rule ids cited below),
  [ADR 0011](0011-node-evidence-what-booted.md) (the node's measured boot and quote),
  [ADR 0012](0012-the-federation-key-lives-in-the-tpm.md) (the TPM as the root of the
  node's own authority).
- Applies to: `nucleus-spec` (`isolation_profile`, `tier2_artifacts`), `nucleus-node`
  (`eval_cell`, `net`, `net::confinement`, `main.rs`'s create path), `nucleus-cli`
  (`run --isolation-profile`).

## Context

The agent escapes reported through 2026 were, almost all of them, failures of the
infrastructure around the agent rather than of the agent's own policy. Described by
class, without naming the products involved:

- evaluation sandboxes left with live internet access;
- a zero-day in a supporting service (a package-registry proxy) that the sandboxed
  agent could reach over the network;
- an unauthenticated control API on localhost, which an agent used to grant itself
  full access;
- configuration carried in the repository (git settings, hooks) that executed code
  before any approval prompt was shown;
- credentials readable from inside the sandbox;
- escapes from sealed evaluation environments run by several model developers, the
  class of which a VMM escape is the strongest form.

Nucleus has most of the parts an answer needs. Its weakness is where it decides: the
fine-grained decision point (the IFC kernel, the flow graph, the budget, the egress
allowlist) runs **inside the guest**, in the tool-proxy, and the host's copy of it is a
shadow that enforces nothing (`nucleus-node/src/host_decide.rs`). Against an agent that
holds root in its guest, everything the guest enforces is something the agent can turn
off. The pod is only as strong as what the host enforces around it.

## Decision

### The threat model

The adversary is **the agent, with root in its guest**. It controls the guest kernel's
userspace, can kill or replace the tool-proxy and guest-init, can read anything the
guest was given, and can open any socket the guest kernel lets it open. It does not
control the host, the VMM's process outside the guest, the host's network namespace
rules, or the TPM.

An eval cell is a pod in which such an adversary causes **zero contract-forbidden
effects**: no egress to a destination it was not given, no credential value it was not
given, no authority beyond its certificate, no write outside its scratch, no code run on
the host.

What this record does **not** claim: availability (the agent can always crash its own
guest), timing and microarchitectural channels, and anything about the agent's
behaviour. Those exclusions are the North Star's own.

### The trusted computing base

| In the TCB | Why it must hold |
|---|---|
| The host `nucleus-node` | It admits the pod, builds every host-side channel, withholds credentials, and is the only party that may decide (after M3). |
| Firecracker and the jailer | The VM boundary, the chroot, the cgroup placement, the non-root uid, and the VMM's own seccomp filter. |
| The host egress path | The per-pod network namespace and its default-deny chain, and the host-side performer of credentialed egress. Under guest root this is the only egress control. |
| The TPM (ADR 0012) | The node's own authority: the federation key and the node evidence a stranger checks. |

**Not** in the TCB, and therefore defence in depth only: the guest kernel, guest-init,
the in-guest tool-proxy and its kernel, the workload's Landlock ruleset, the syscall
filter derived from the lattice, and every verdict the guest prints on its console. A
compromised guest's console is never independent evidence (`cred_split.rs` already says
so). The eval cell still requires the in-guest layers, because a guest root reached by an
exploit chain is harder to reach through them; it never relies on them.

### The `eval-cell` isolation profile

A pod asks for it with the label `isolation.coproduct.one/profile: eval-cell`
(`nucleus_spec::isolation_profile`), or `nucleus run --isolation-profile eval-cell`. It is
a label and not a spec field because the pinned guest parses the spec with
`deny_unknown_fields`; the label map is IN the program identity whole, so a profile
change is a program change.

The node refuses the pod at create, by name, unless all of the following hold
(`nucleus-node/src/eval_cell.rs`, one decider called unconditionally from
`create_pod_internal` before the isolation clamp):

1. **Firecracker only.** The container, local and Apple VZ tiers are refused naming the
   tier (`isolation_backend(driver).name`, the name the clamp writes). Apple VZ is
   refused until its isolation is reviewed against this threat model. `nucleus run
   --local` and `--hook` are refused by the CLI, which is the only party that sees
   those tiers.
2. **The host controls are on.** `--firecracker-seccomp-verify` (a VMM whose filter is
   not confirmed active is not launched), `--firecracker-jailer`, no
   `--allow-workload-without-landlock`, and enforcing host-spec credential delivery
   (`cred_split`: the guest receives the admitted spec with every credential value
   withheld). The spec may not ask for a disabled or custom VMM seccomp filter, in any
   build.
3. **Egress is what the cell lists, host by host.** `network.allow` is empty unless the
   spec lists destinations, and every listed entry names exactly one host (a bare
   address, `/32` or `/128`). Ranges are refused whether public or private: a reachable
   private range is how an agent finds a supporting service it was never meant to reach.
   A policy that grants `web_fetch` or `web_search` while the spec lists nothing is
   refused rather than left to fail at the fence.
4. **The guest confines its children.** `GuestCapability::WorkloadLandlock` and
   `WorkloadSyscallPolicy` are `Demand::When(GuestUse::EvalCell)`: required for an eval
   cell, optional for every other pod, so the global guest floor does not move. The CLI
   refuses a `--guest-release` without them. The node cannot read a release off a
   Firecracker rootfs, so at boot it requires the guest's own `enforced` Landlock
   verdict and fails the boot otherwise (`eval_cell::require_confined_children`). The
   derived syscall filter has no console verdict yet; for it, the release table is the
   only check.
5. **A child stays an eval cell.** A pod an eval cell creates must carry the profile
   too; omitting the label is refused, never read as standard.

ADR 0007 B applies throughout: an unknown profile name is refused (B-3); the absent
label is the standard profile, which is the admission every pod already receives and
grants nothing more (rule 5 closes the one place absence could shed a requirement);
`IsolationProfile` has no `Default` (B-1); every decision over a profile or a driver is
an exhaustive match with no `_` arm (E-2), and the node posture is destructured whole
(E-1), so a new driver, profile or posture field does not compile until someone says
what an eval cell needs of it.

### The 2026 incident classes, and what answers each today

| Incident class | The nucleus control that answers it | Status |
|---|---|---|
| Evaluation sandbox with live internet | Every pod sits in a host network namespace with a default-deny chain the guest cannot reach, and the node refuses a pod whose guest cannot prove the fence drops traffic (`net::confinement`, egress attestation). An eval cell's allowlist names hosts one by one, never a range, and a network capability with nothing listed is refused (`eval_cell::admit_egress`). | **Answered** at admission (M0). The live probe that pins it under guest root is M2. |
| Zero-day in a reachable supporting proxy | An eval cell cannot list a range, so a supporting service is reachable only if listed by address. The host-side listeners the guest reaches over vsock (workload API, broker, decision channel) are reachable from guest root. They are one inventoried type, `HostListener` in `nucleus-ifc-kernel`, bound only through `guest_socket::bind_guest_listener` and held equal to the table in `docs/architecture/mediated-set.md` (#3331). | **Inventoried** (M1, #3331); **NOT YET → M1** for in-guest probes that reach each listener, **M4** (one mediated egress proxy; DNS answered by it). |
| Unauthenticated localhost or control API used for self-escalation | The node API is mTLS-only; approvals are Ed25519 signatures by a key the guest never holds; the tool-proxy's shared-secret tier carries no authority (#2446 step 2). But the deciding kernel is in the guest, so guest root can bypass the in-guest decision entirely. | **NOT YET → M3** (the host decides; the guest proxy becomes a thin client). |
| Repository-borne exec config before approval | `nucleus/src/consume_guard.rs` reverts a shell command's change to an execute-on-consume path, including `.git/config` exec keys. Nothing yet scans the incoming workspace before it is mounted. | **NOT YET → M1** (a pre-mount scan reusing `consume_guard`'s key list; the eval cell copies in no host-side agent config). |
| Credential theft | Enforcing host-spec delivery withholds every credential value from the guest's spec (`cred_split`), and credentialed egress is performed by the host, so the guest never holds the token; an eval cell is refused on a node without it. The broker capability is still served to the guest once per pod, so under guest root the first fetch can be the agent's. | **Answered** for spec credentials (M0); **NOT YET → M1** for the broker capability (bind it to identity or keep it host-side). |
| VMM escape | Firecracker under the jailer (chroot, cgroups, a uid that cannot be root), the VMM's seccomp filter verified active and fail-closed, both required of an eval cell; the node's boot measured and quoted by the TPM (ADRs 0011, 0012). | **Answered** at admission (M0); the VMM runs as pid 1 of its own PID namespace, is held through a pidfd, and runs under the jailer's file-size and open-file limits (M1, #3329, closes #2571). The guest-side PID namespace for workload children is not yet covered. |

## Consequences

- An eval cell admitted today is held by the host controls in the table's "answered"
  rows and by nothing it does not list. It is **not** yet held against an agent that
  uses guest root to bypass the in-guest decision; that is M3, and the escape lane of M2
  is where the gap is measured rather than asserted. The North Star frontier ledger
  carries the eval cell as a NOT-YET row whose falsifier is that lane.
- No pod that does not ask for the profile changes behaviour. The standard profile is
  admitted exactly as before, on every tier, and the guest floor is unchanged: 2.5.0 and
  2.6.0 guests still serve standard pods.
- An eval cell cannot boot on a guest that predates Landlock confinement, and the CLI
  refuses one on a release without the derived syscall filter.
- Leftovers, owned by later milestones: the node does not know a Firecracker rootfs's
  release (#3223), so the derived-filter requirement is a release-table check only; the
  profile is per pod, and a node that serves only eval cells is a later, separate flag.
