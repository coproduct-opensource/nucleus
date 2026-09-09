# ADR 0004 — Nucleus is a delegation compiler: intent in, minimum authority out

- Status: accepted (2026-09-08)
- Applies to: `nucleus run --goal`, `crates/nucleus-task-compiler`, `portcullis::effect_catalog`,
  `portcullis::task_grant`; every later surface that asks a person to grant an agent authority

## Context

Nucleus's authority model is sophisticated: a 13-dimension capability lattice, sink
scopes, SPIFFE identity, budgets, egress policy, delegation chains, IFC labels,
discharges. Until now that model was also the user's interface. To run an agent
safely a person picked a profile by name, or authored a lattice by hand, and read
denials as `IFC sink scope violation` and `web_fetch: never`. The security
architecture was correct and the usability cost of being correct fell on the user.

The rest of the field resolves that cost by widening authority. The common shape in
September 2026 is a per-action classifier or a two-knob sandbox (`read-only` /
`workspace-write` × `ask` / `never`), in which a person's stated boundary is a line in
a transcript that is lost when context is compacted, and in which users approve the
overwhelming majority of permission prompts because the prompts are ceremony rather
than a boundary. Research prototypes go the other way — task-scoped authorization
that treats a submitted task as implicitly authorizing exactly the operations its
faithful execution requires, and intent certificates that narrow a static tool
manifest — but nothing shipped compiles a stated goal into a durable, enforced,
minimum grant *before* execution. That is the open lane, and nucleus already owns
the substrate for it: signed certificates whose `extensions` narrow by meet,
`mint_child`, a weakening-gap calculator, receipts that attest which authority was
exercised, and an observer that synthesizes a narrower profile from a trace.

The DX north star this ADR serves:

> Make least-privilege delegation feel easier than unrestricted execution.

with two invariants DX work may not violate:

- **Authority overhead** ρ = A_granted / A_observably-required → 1. Usability never
  improves by granting more.
- **Delegation clicks** C(T) = 1 for a new safe task, 0 for a previously approved one.
  The consequential decision stays intentional; everything else is derived.

## Decision

1. **Intent is compiled, not classified.** A goal (`nucleus run --goal "fix the failing
   CI build"`) is input to a deterministic compiler that derives the *effects* the task
   needs from the goal and the repository it is stated in (ecosystem, CI system, git
   remotes, MCP configs), lowers them to a `PermissionLattice`, and **meets the result
   with a ceiling profile**. The grant is `≤ ceiling` by construction and is checked
   with the same `delegate_to` a certificate mint uses. The ceiling is the only knob a
   person can widen.
2. **The unit of authority a person reads is a semantic effect, not a lattice
   dimension.** `github/read-ci-logs`, `shell/run-tests`, `git/commit` are declared as
   data (`crates/portcullis/effects/*.toml`, plus a repository's `.nucleus/effects/`),
   each with a title, a risk grade, what it lowers to (operations, sinks, hosts) and
   how it is recognised (MCP tool names, command prefixes, HTTP method+host+path).
   The host→meaning table lives in the catalog, not in comments beside an allowlist.
   Plugins improve DX and security together by contributing effects: plugin quality is
   semantic compression of authority.
3. **The grant is an object, and it is rendered by meaning.** A `TaskGrant` records the
   goal (prompt playback), `can`, `cannot` (proposed but clipped by the ceiling,
   with the reason), limits, the lattice, a risk summary from the uninhabitable-state
   analysis, and provenance (which rules fired, which proposers were consulted, the
   repository-context digest). It renders as five lines — Goal / Can / Cannot /
   Limits / Risk — with progressive disclosure below them: the 13-dimension grid, then
   the per-dimension weakening requests and their cost. Same object, three depths.
4. **Effect proposal is deterministic and explainable, with a validated seam for
   more.** The built-in proposer is a rule table over goal phrases × repository
   context; every rule that fires is named in the grant. An orchestrator may add an
   `EffectProposer` as a *child process* (JSON in, JSON out). Its output is validated
   against the catalog and meet-clamped like everything else, so a proposer can only
   narrow or starve a goal, never widen it. Nucleus links no LLM SDK; the compiler
   crate is offline by construction and CI enforces that.
5. **Fail closed at every edge.** A goal nothing recognises is an error that names the
   remedy (`--effects`, `--profile`); it never falls back to a permissive profile. An
   effect the ceiling clips is reported in `cannot`, never silently granted or
   silently dropped. Without a TTY, `--goal` refuses to run unless `--yes` names the
   decision; an unattended run does not acquire authority by default.
6. **Improvement is narrowing-only.** The loop this ADR opens is
   `goal → effects → minimum authority → risk delta → execute → receipts → narrower
   reusable grant`. Later milestones seal the grant into a certificate (a durable
   intent, not a transcript line), turn every denial into a structured escalation
   proposal bounded by the same ceiling, attribute receipts to effects to compute ρ,
   and offer a profile with unused authority removed. None of those steps may
   introduce a path that widens authority outside `POST /v1/escalate` and the
   existing approval counters.

## Consequences

- `nucleus run --goal` is the primary interface; `--profile` and PodSpec YAML remain
  the expert path. `--dry-run` shows the grant and stops; `--explain technical |
  policy-trace` deepens it; `--save-grant` writes it.
- The 13-dimension verified core does not change. Effects are catalog data now and
  `extensions` keys on the certificate later, following the `tool_surface` pattern.
- Enforcement of a semantic effect is, in this milestone, the lattice it lowers to
  plus the host list plus the command prefixes it vouches for. An agent that reaches
  GitHub with `curl` rather than an MCP tool is bounded by host, not by method+path;
  per-effect enforcement at the credential boundary is a later milestone and the
  docs say so.
- Two metrics become product surfaces: ρ (authority granted ÷ authority used, from
  receipts) and C(T) (authorization decisions per task).
- A new CI gate, "The task compiler is offline by construction", is probed by the
  gate-of-gates like every other script gate.

## Milestones

| # | Delivers | Status |
|---|---|---|
| 1 | Effect catalog, `TaskGrant` + renderer, `nucleus-task-compiler`, `nucleus run --goal` preview and single confirmation, offline gate | #2675 |
| 2 | `effect/` certificate keys (`effect_surface`), `SealedTaskGrant` (grant + signed certificate, binding keys), `nucleus run --save-grant` / `--grant`, `nucleus grant seal|show` (C(T)=0) | this PR |
| 3 | Trace → effect attribution (`grant_usage`), ρ over dimensions and effects, post-run usage lines and "save a narrower profile", `nucleus observe --grant --narrow --save`, user profiles in `~/.config/nucleus/profiles` (never wider than a canonical name) | this PR |
| 4 | `EscalationProposal` (`escalation_proposal`): attempt, reason, minimum effect and raised dimensions, risk delta, scopes (always / this run), outside-ceiling and repair outcomes; `denials_in_trace`; post-run proposals; `nucleus grant propose\|widen`. Carriage inside MCP / tool-proxy / hook / SDK denial payloads is the next step | this PR |
| 5 | `AuthoritySummary` (`authority_metrics`, feature-free): ρ over dimensions, C(T) = confirmations + approvals, decision counts; in `ExitReport.authority`, the MCP `session_summary`, and the run's closing line; `PodSpec.metadata.task_grant_id` | this PR |
| 6 | Per-effect enforcement at the credential boundary (method+path) | |
