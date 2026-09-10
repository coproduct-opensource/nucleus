# ADR 0005 — Delegatable agency is the objective; containment is the constraint surface

- Status: accepted (2026-09-09)
- Extends: ADR 0004 (the delegation compiler), which stated this objective one level
  down and named two of its terms
- Applies to: `NORTH_STAR.md`, `README.md`, `docs/index.md`, `docs/north-star.md`,
  every future ADR, and the acceptance question on every pull request

## Context

Nucleus has, until now, described itself only by its constraint. Four live and
mutually unreferenced statements say the same kind of thing four ways:

| Where | What it says |
|---|---|
| `README.md` | "Don't trust the agent. Verify it." / "Assume the agent is compromised." |
| `NORTH_STAR.md`, `docs/north-star.md` | "makes *agent jailbreak → silent damage* provably impossible by construction" |
| `docs/index.md` | "a capability-based runtime for running untrusted agents" |
| `docs/adr/0004-delegation-compiler.md` | "intent in, minimum authority out" |

Each is true. None says what the constraint is *for*. A reader can finish all four
and still not know which of two proposed features nucleus should build, because the
statements are all of the form "nothing bad happens", and the feature that best
satisfies "nothing bad happens" is the feature nobody can use.

That is not a rhetorical gap; it has cost real direction. The runtime accumulated a
13-dimension lattice, sink scopes, SPIFFE identity, budgets, egress policy,
delegation chains, IFC labels and discharges, and the usability cost of being
correct fell on the user until ADR 0004 — a year of enforcement work before one
line asked how much work could actually get done inside the boundary. The project's
own ledger still records that question as open: `docs/perf/RUBRIC-LEDGER.md` rows 2
and 2b are unresolved FAIL rows in which a `codegen` pod could read *no* file in its
sandbox and `/work` — the pod spec's own `work_dir` — answered `sandbox_escape`.
Every number nucleus publishes is a proof count, a denial count, or a latency.

ADR 0004 got half of the fix without naming it. Its DX north star —

> Make least-privilege delegation feel easier than unrestricted execution.

— and its two invariants (ρ = A_granted / A_observably-required → 1; C(T) = 1 for a
new task, 0 for a previously approved one) are not DX metrics. They are two terms of
the project's objective function, scoped to one command.

### What the field looks like (September 2026)

The intersection this ADR claims is empty today, and each neighbour is empty in a
different direction:

- **Attenuating-capability engines** — Tenuo (Apache-2.0, Rust, warrants signed and
  verified offline in under 50 µs, standardizing as
  `draft-niyikiza-oauth-attenuating-agent-tokens`) hold the delegation calculus and
  say so plainly: *"Not a sandbox."* Isolation is left to containers or VMs.
- **Agent sandboxes** — E2B, Vercel Sandbox (GA January 2026), Modal, Daytona,
  Cloudflare — hold Firecracker/gVisor isolation and grant **ambient authority
  inside the box**: no attenuation, no delegation chain, no receipt.
- **Papers** hold the vocabulary without a product: *Sovereign Execution Broker*
  (certificate-bound runtime authority, no machine-checked proofs), *AgentBound*
  (governance receipts co-signed and replayable, no isolation), *Insuring Every
  Action* (an "Authority Frontier" and a Capital@k metric — authority released per
  unit of reserve capital), *Verifiability-First Agents* (an action attestation
  layer).
- **Standards** are unsettled. RFC 8693's `act` / `may_act` is the only shipped
  delegation primitive; the agent-specific OAuth drafts are individual submissions;
  A2A v1.0 specifies subdelegation and is *silent on how to downscope a credential*,
  a gap the literature has named "authorization creep".
- **Demand is measured, and blocked on exactly this.** Reported agent-pilot failure
  rates before production run 86–89%, attributed to governance and traceability
  rather than model capability; roughly three-quarters of deployments run with
  human-in-the-loop checkpoints. The recurring diagnosis is teams relying on
  observability instead of enforcement.

Nobody holds isolation *and* attenuating delegation *and* machine-checked proofs
*and* portable receipts at once. Nucleus does. Naming the objective is what makes
that a strategy rather than a coincidence of four workstreams.

## Decision

1. **The objective is delegatable agency, and it is a ratio.**

   > Nucleus continuously expands the frontier of safely delegatable machine
   > agency: any agent should be able to do as much useful real-world work as its
   > principal is willing to authorize, while being structurally incapable of
   > exceeding that authorization.

   Written as the quantity every workstream is trying to move:

   ```
                useful autonomous work completed
       ℐ  =  ───────────────────────────────────────────────────────
             authority risk + human friction + integration cost
   ```

   The denominator is not decoration. A perfectly secure system nobody can use has
   ℐ ≈ 0, and so does a system that completes every task by granting `*`.

2. **The invariant is the constraint surface, not the objective.**

   ```
       exercised authority  ≼  delegated authority
   ```

   Everything `NORTH_STAR.md` calls the Flagship Safety Claim, everything
   `docs/verified-claims.md` maps to a proof artifact, and every Kani harness and
   Lean theorem in the tree exists to make that `≼` hold and to make it checkable
   by someone who does not trust us. The constraint does not compete with the
   objective; it is what makes the objective's numerator *safe* to raise. **ℐ may
   never be raised by weakening `≼`.** A change that improves ℐ by widening what an
   agent may do without its principal saying so is not an improvement; it is a
   different product.

3. **Four layers, and nucleus owns three.**

   | Layer | Question | Owner |
   |---|---|---|
   | Containment | What is physically possible? | nucleus (isolation, mediation, IFC) |
   | Delegation | What has the principal authorized? | nucleus (lattice, certificates, effects, receipts) |
   | Allocation | How is scarce authorized authority spent? | nucleus (budgets, ledger; markets are RFC-stage) |
   | Cognition | What should the agent actually do? | **not nucleus** |

   The fourth row is a non-goal and stays one. It is also why vendor neutrality is a
   consequence of the architecture rather than a policy bolted onto it: nucleus does
   not need to know which mind is being delegated to.

4. **Every axis is a mechanism on one boundary, not a separate strategy.**

   | Work | How it moves ℐ |
   |---|---|
   | Isolation (Firecracker, seccomp, netns) | raises how *consequential* a delegation can safely be |
   | Formal proofs | raises the confidence a principal needs to delegate at all |
   | Receipts, provenance | lets delegated authority cross organizational boundaries |
   | Identity (SPIFFE, OIDC) | makes principal and delegate unambiguous |
   | Effects and plugins | raises the *dimensionality* of what can be delegated |
   | Integrations | raises reachable real-world agency |
   | DX | lowers the cost of expressing correct authority |
   | Policy compilation | lets a person delegate more precisely |
   | Distribution | raises the number of principals able to delegate at all |
   | Budgets, ledger | allows longer and larger autonomy safely |
   | Markets, auctions | improves utilization *inside* the frontier, never widening it |
   | Benchmarks | establish where the frontier actually is |

5. **Effects are basis vectors of authority space.** A pack of semantic effects
   (`crates/portcullis/effects/*.toml`, and a repository's `.nucleus/effects/`) is
   not an accessory or an integration convenience. Each pack adds a dimension a
   principal can grant along, and a good pack is *semantic compression of
   authority*: it lets a person say "read CI logs" where they would otherwise have
   said "GET api.github.com" and meant something narrower than they wrote. ADR 0004
   decision 2 made this a DX claim; here it is a strategic one. A pack can only
   narrow or starve a goal — the ceiling meet clamps it — so widening the basis
   never widens the root.

6. **DX is part of the security theorem.** Bad DX does not merely annoy; it
   produces `permissions: "*"`. The over-grant ratio

   ```
       ρ  =  authority granted ÷ authority observably required
   ```

   is therefore a security metric that a usability change moves. This is why ADR
   0004's ρ and C(T) are terms of ℐ's denominator rather than a separate scoreboard,
   and why `crates/portcullis/src/authority_metrics.rs` is feature-free: every
   surface that asks a person for authority has to be able to report what it cost.

7. **The product test.** Every proposed change answers one question:

   > **Does this let someone safely delegate more agency, more precisely, more
   > easily, or with greater confidence?**

   Four verbs, four mechanisms — *more* is the numerator, *precisely* is ρ, *easily*
   is C(T), *confidence* is the proof and receipt surface. A change with no
   projection onto any of them is peripheral, and saying so early is cheaper than
   discovering it in review.

8. **No ℐ claim ships ahead of its measurement.** `docs/PROOFS.md` already forbids
   describing a TESTED or MODELED claim as PROVEN. The same discipline extends to
   this objective: a number about how much work can be delegated is **MEASURED**
   only when a committed harness run at a named commit produces it. Until then the
   honest statement is that the numerator is unmeasured — which, as of this ADR, it
   is.

## Consequences

- `NORTH_STAR.md` becomes the single canonical statement and carries the objective
  above the Flagship Safety Claim, which is retained verbatim as the constraint
  surface. `docs/north-star.md` remains the long form and the CI-parsed
  mediation/confidentiality ledger; its Vision section states the same objective and
  defers to `NORTH_STAR.md`. `README.md` and `docs/index.md` lead with the objective
  and state `≼` immediately below it. The orphaned root `north-star.md` — a fourth
  positioning, referenced by nothing — moves to `notes/` as the pitch draft it is.
- The public framing layers rather than replaces. "Assume the agent is compromised"
  stays, in its place: the reason the objective is credible.
- Two numbers become project surfaces alongside the proof counts: ℐ's numerator
  (useful work completed under an enforced grant) and ρ over *effects* rather than
  over the 13 coarse dimensions. Neither exists today. Producing the first of them
  is the work this ADR makes first priority, and `docs/perf/RUBRIC-LEDGER.md` row 2c
  is where it starts.
- Claims that bear on "greater confidence" are load-bearing for the objective, so
  claim defects are objective defects. Two are outstanding at the time of writing:
  `KANI-STATUS.md` records that 12 of `ck-kernel`'s 17 harnesses have never
  completed — including the refinement bridge that would let the 5 that do verify
  stand in for the production `BTreeSet` path — while three documents cite "17"
  without the caveat; and the research-tier `sorry` counts disagree across
  documents that all designate `scripts/formal-numbers.sh` as the arbiter.
- Allocation work (`docs/rfcs/` clearing, markets, Pigouvian structure) is
  explicitly downstream of measurement: a frontier that has not been measured
  cannot be allocated.
- This ADR does not change a single enforcement path, type, or proof. It changes
  which of two correct changes gets built first.

## References

- `docs/adr/0004-delegation-compiler.md` — the compiler, ρ, C(T), and the effect
  catalog this ADR generalizes
- `docs/PROOFS.md` — the PROVEN / TESTED / ATTESTED-MODELED honesty tiers extended
  here by MEASURED
- `docs/verified-claims.md` — claim → proof artifact → CI gate
- `docs/perf/RUBRIC-LEDGER.md` — rows 2 / 2b / 2c, the open numerator
- `KANI-STATUS.md` — what the model checker has and has not proved
- Tenuo — <https://github.com/tenuo-ai/tenuo>; `draft-niyikiza-oauth-attenuating-agent-tokens`
- *Insuring Every Action: An Authority Frontier Framework for Runtime Actuarial
  Control of Autonomous AI Agents* — <https://arxiv.org/abs/2605.25632>
- *Sovereign Execution Broker: Enforcing Certificate-Bound Authority in Agentic
  Control Planes* — <https://arxiv.org/abs/2606.20520>
- *Governance Gaps in Agent Interoperability Protocols: What MCP, A2A, and ACP
  Cannot Express* — <https://arxiv.org/abs/2606.31498>
- RFC 8693 §4.1 (`act`, `may_act`) — the delegation primitive the certificate chain
  re-roots against in `crates/nucleus-node/src/pod_authority.rs`
