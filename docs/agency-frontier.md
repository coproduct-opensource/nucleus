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
`codegen` profile, pod boot ~3.0 s. Artifact: [`benchmarks/agency/tier2-codegen-profile.json`](../benchmarks/agency/tier2-codegen-profile.json).

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

### 2026-09-10 — compiled grant, Tier 1 local

**MEASURED.** macOS arm64, no microVM; `nucleus-tool-proxy` spawned locally under
a sealed grant compiled from a goal. Artifact:
[`benchmarks/agency/tier1-compiled-grant.json`](../benchmarks/agency/tier1-compiled-grant.json).

```
agency: 5/5 tasks completed (100%) under local enforcement
cost:   ρ_effect = 1.25 · ρ_dimension = 1.75 · C(T) = 1 ·
        3 denial(s) inside the grant of 4 total, 0 of them deferrals · risk Medium
valid:  3 containment check(s) held
```

Reproduce:

```sh
nucleus-perf agency --local --goal "fix the failing tests" --ceiling codegen \
    --tool-proxy-path <nucleus-tool-proxy> --work-dir <dir> \
    --commit "$(git rev-parse --short HEAD)" --out agency.json
```

**This is the arm where ρ_effect exists.** Under a profile there are no semantic
effects to divide by, so the Tier 2 reading reports `null`. Here the goal is
compiled to a grant, the grant's effects are sealed into the certificate the
proxy verifies, and the run is therefore *bounded by* the effects it is
*measured against* rather than merely described by them.

**ρ_effect = 1.25** — the grant holds five effects (`fs/read-workspace`,
`fs/edit-workspace`, `git/commit`, `git/read-history`, `shell/run-tests`) and the
run exercised four. One effect went unused, and `nucleus observe --narrow` would
propose dropping it. That is the loop ADR 0004 opens, closing for the first time
on a measured number.

**C(T) = 1, against 4 under the profile.** This is the sharpest difference
between the two readings and it is the ADR 0004 claim, measured: one
confirmation before the run — a person reading Can / Cannot / Limits / Risk once
and accepting — and **zero** authorization decisions during it. Under the
`codegen` profile the same five tasks cost four in-run approvals, because the
profile rates writes, edits and shell `low_risk` and defers each one. The grant
is not free; it is one decision instead of four, made before anything ran rather
than four times while a person waited.

### The two readings side by side

| | Tier 2, profile | Tier 1, compiled grant |
|---|---|---|
| work completed | 5/5 | 5/5 |
| ρ_effect | *undefined* | **1.25** |
| ρ_dimension | 1.75 | 1.75 |
| C(T) | 4 | **1** |
| denials inside the grant | 7 (5 deferrals) | 3 (0 deferrals) |
| enforcement | microVM | in-process |

They are not the same experiment and the table is not a controlled comparison —
different tiers, different hosts, different architectures. What it does show is
the shape ADR 0004 predicted: the same work, at the same completion rate, for a
quarter of the human decisions and with the precision figure finally defined.

**A containment check had to be replaced to get this reading, and the mechanism
caught it rather than the reading being quietly wrong.** `refuses-unapproved-write`
asserted that an unapproved write is *deferred* — true under the `codegen`
profile, false under a compiled grant for the same work, which authorises writes
outright and says so (`no approval prompts expected`). So the write landed, the
check reported a breach, and the report refused to be quoted. It was the check
that was wrong: it encoded a property of one profile rather than an invariant.
It is now `refuses-write-to-a-blocked-path`, which holds under every profile and
every grant. Worth recording because containment checks decide whether a whole
reading may be quoted, so a check that depends on which grant is in force can
void a perfectly good measurement — and because the validity property did its
job in the direction nobody designs for: catching a defect in the suite rather
than in the runtime.

## What this reading does not establish

- **It is not a model benchmark.** Nucleus does not own cognition (ADR 0005,
  decision 3). A task fails here when the *authority* would not admit the work.
  How well a model uses the authority is a different measurement, on a different
  axis, and the AgentDojo lane is where it belongs.
- **Five tasks is a floor, not a frontier.** The suite covers filesystem and
  shell work under one profile. It says nothing about the AWS, Kubernetes,
  database or messaging work a person might want to delegate — those effects
  exist now, but no task here exercises them (see below).
- **One profile, one architecture, one run.** No x86_64 reading, no Tier 1
  reading, and no unconstrained control arm to measure the enforcement cost
  against. `Enforcement::None` exists in the schema for that arm; nobody has run
  it.
- **ρ_effect was missing from the Tier 2 reading**, and the Tier 1 one supplies
  it. The dimension figure cannot fall below about 1.75 for this profile no
  matter how precise the grant gets, because 13 buckets is all the resolution it
  has; the effect figure can, and at 1.25 it says one granted effect went unused.
- **Neither reading exercises the cloud, cluster, database or chat packs.** Those
  effects exist; no task here touches them.

## Why the four new effect packs did not move these numbers

`aws`, `kubernetes`, `database` and `slack` landed alongside these readings, and
neither reading moved. That is not a disappointing result, it is the right
one, and saying so is cheaper than staging a delta.

The packs widen **what can be delegated**. The suite measures **what this pod
did**, and what it did was filesystem and shell work under a profile. Those are
different quantities, and the honest way to see the packs in a number needs two
things neither of which exists yet:

1. ~~A `--goal` grant, so ρ_effect is defined at all.~~ **Done** — the Tier 1
   reading above. ρ_effect is 1.25 for a repository-shaped goal.
2. **Tasks that touch those surfaces.** A cluster, a database and an object
   store, or credible fakes of them. This is the one that is left, and it is not
   a small one: a task suite pointed at real infrastructure would measure that
   infrastructure as much as the runtime.

What the packs *did* change is visible without the harness, in what a person is
shown. Before them, a goal about a cluster compiled to nothing and a goal about
the cloud compiled to nothing. Now:

```
$ nucleus run --goal "check the cloudwatch logs for the lambda" \
      --dry-run --ceiling research-web
Can:     list cloud resources · read CloudWatch logs · read and search workspace files
Limits:  $1.50 · 44m · *.s3.amazonaws.com, ec2.*.amazonaws.com, ecs.*.amazonaws.com,
         lambda.*.amazonaws.com, logs.*.amazonaws.com, rds.*.amazonaws.com,
         s3.amazonaws.com, sts.amazonaws.com only · no .aws, .env, .ssh, …
```

and under a ceiling that does not admit egress, the same goal renders those two
effects in `Cannot` **with the reason** — `outside ceiling local-dev: web_fetch
is never` — rather than failing to recognise the goal at all. A denial that names
what it would take is the raw material of an escalation proposal; silence is not.

## Recovery friction

`D`'s denominator is human decisions + configuration + security knowledge +
recovery friction. `C(T)` was the only one measured, and it only counts the
decisions on the **happy path** — the run where the grant was right the first
time. It says nothing about the run where it was not, which is where delegation
actually fails: an agent is refused something it needed, and either the system
tells it what would have worked or the person goes and reads a profile.

That failure is invisible in a completion rate. The task simply does not
complete, and nothing distinguishes "one decision away" from "ten".

`--recovery-goal` measures it. The lane is deliberately under-granted — a
read-shaped goal, then a write — so the refusal is the boundary doing its job.
From there:

1. the refusal is read off the wire,
2. `escalation_proposal::propose` names the least authority that would have
   allowed it,
3. the grant is recompiled with exactly that effect added — **one decision**,
4. the same work is attempted again.

First reading, Tier 1 local, ceiling `codegen`:

```
recover: write-after-refusal — refused by kernel_denied,
         proposal named fs/edit-workspace, 1 decision(s) over 0.3s, recovered
```

The target is one decision, and one decision is what it takes.

### What is actually being asserted

Not `decisions == 1`. A proposal that named nothing and a harness that already
knew the answer would also score 1. The claim is that the fix came from the
**system's** proposal and that the proposal was *sufficient*: refused before,
granted exactly the named effect, completed after.

The harness is not allowed to know which effect fixes it — the name comes from
`propose`, from the catalog and the ceiling, never from the lane. Two checks
keep that honest, and both were run:

| perturbation | result |
|---|---|
| recovery goal wide enough that the write already succeeds | the lane **errors** rather than reporting 0 friction — a grant that was never too narrow has not measured recovery |
| the proposal forced to name `fs/read-workspace` instead | `STILL REFUSED after granting the proposed minimum` |

That second row is the one worth keeping. A proposal that names a minimum which
does not work is *worse* than proposing nothing: it spends the person's one
decision and leaves them exactly where they started. The report must be able to
say so, and it can.

Recovery is friction, not work. It is reported beside `clicks` and never enters
the numerator — measured with and without the lane, the completion rate, ρ and
every denial count are identical.

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
