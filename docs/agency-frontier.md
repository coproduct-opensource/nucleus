# The agency frontier

The objective ([ADR 0005](adr/0005-delegatable-agency.md)) is a ratio:

```
             useful autonomous work completed
    ℐ  =  ───────────────────────────────────────────────────────
          authority risk + human friction + integration cost
```

subject to `exercised authority ≼ delegated authority`. This page is where its
readings live. **Every claim in this repository about how much work can be
delegated cites a row here, or it does not ship.**

## The tier

`docs/PROOFS.md` keeps PROVEN, TESTED and ATTESTED-MODELED apart so that a claim
cannot be quoted at a strength it did not earn. Numbers about *work* need a
fourth word, because none of those three fit — a completion rate is neither
proved nor modelled, it is observed, once, on a particular machine.

> **MEASURED** — a committed harness run at a named commit, on stated hardware,
> whose containment checks all held. Reproducible by re-running the command in
> the row.

A number that is not MEASURED is not quotable. In particular: a number from a
harness whose containment checks failed is not a measurement of *safely*
delegatable agency, and `AgencyReport::is_valid` refuses to call it one.

## Readings

### 2026-09-09 — `codegen` profile, Tier 2 microVM

**MEASURED.** aarch64 / KVM (Lima `nucleus-kvm`, 4 vCPU, 7.9 GiB), Firecracker,
`codegen` profile, pod boot ~3.0 s. Artifact: [`agency.json`](../agency.json).

```
agency: 5/5 tasks completed (100%) under microvm enforcement
cost:   ρ_effect = undefined · ρ_dimension = 1.75 · C(T) = 4 ·
        7 denial(s) inside the grant of 8 total, 5 of them deferrals to a person ·
        risk Medium
valid:  3 containment check(s) held
```

Reproduce:

```sh
nucleus-perf agency --spec <pod.yaml> --approval-key <approval_signing_key.der> \
    --commit "$(git rev-parse --short HEAD)" --out agency.json
```

**Work completed (the numerator).** Discover the workspace; read real bytes out
of the sandbox; write a file and read the same bytes back; change a file that
already exists; run a command. Each has a deterministic oracle — the read-back
tasks compare against bytes the *host* chose, so an empty success fails.

**Containment held (what makes the rate quotable).** A private key is not
readable; there is no egress; a write nobody approved does not land. These are
excluded from the numerator on purpose: a refusal is not work, and a suite that
counted its own refusals as completions would make ℐ rise as the runtime got
more restrictive.

**Reading the cost.**

| term | value | what it says |
|---|---|---|
| ρ_dimension | 1.75 | The profile holds 1.75× the core dimensions the run used. Coarse by construction — 13 buckets. |
| ρ_effect | *undefined* | **Not measured.** This pod ran under a *profile*; ρ over effects needs a compiled grant to divide by. `nucleus run --goal` produces one; a profile does not. Reported as null rather than 1.0, which would claim perfect precision for a quantity nobody computed. |
| C(T) | 4 | Four authorization decisions for five tasks. `codegen` rates writes, edits and shell `low_risk`, so each defers once. |
| denials inside the grant | 7 of 8 | Of these, **5 are deferrals** — the system asking a person, exactly as designed. Two are genuine refusals inside a granted dimension. |
| residual risk | Medium | Two of three uninhabitable-state components present at autonomous levels. |

## What this reading does not establish

- **It is not a model benchmark.** Nucleus does not own cognition (ADR 0005,
  decision 3). A task fails here when the *authority* would not admit the work.
  How well a model uses the authority is a different measurement, on a different
  axis, and the AgentDojo lane is where it belongs.
- **Five tasks is a floor, not a frontier.** The suite covers filesystem and
  shell work under one profile. It says nothing about the AWS, Kubernetes,
  database or messaging work a person might want to delegate — there are no
  effects for those yet, which is the point of widening the basis.
- **One profile, one architecture, one run.** No x86_64 reading, no Tier 1
  reading, and no unconstrained control arm to measure the enforcement cost
  against. `Enforcement::None` exists in the schema for that arm; nobody has run
  it.
- **ρ_effect is the number that matters and it is missing.** The dimension
  figure cannot fall below about 1.75 for this profile no matter how precise the
  grant gets, because 13 buckets is all the resolution it has.

## History

The first reading of this suite, an hour before the one above, was **3/5**. The
instrument found three defects in the runtime on its first run, and the rate
moved as each was fixed:

| reading | rate | what was in the way |
|---|---|---|
| 1 | 3/5 (60%) | `edit-an-existing-file`: the kernel mediated an overwrite as `WriteFiles` while the sandbox enforced `EditFiles`, so the approval the caller was told to get did not satisfy the retry. `run-a-command`: the command executor keyed approvals on the raw command (`echo hello`), a third vocabulary beside the kernel's and the sandbox's. |
| 2 | 3/5 (60%) | Both named correctly now, but the run guard *spent* the grant that the executor's own approver then needed — two spends per attempt. |
| 3 | 4/5 (80%) | `run-a-command` completes. The edit's discharge bundle authorised `EditFiles` while `Sandbox::write` still spent authority as `WriteFiles`. |
| 4 | 5/5 (100%) | The spend follows the operation. |

All four were the same rule, at four depths: **one act, one operation, one name,
at every gate.** None of them was visible to any unit test, because each gate
was internally consistent and only disagreed with its neighbour. That is the
argument for measuring the numerator: the denominator was green throughout.
