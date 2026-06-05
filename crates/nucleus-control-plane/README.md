# nucleus-control-plane

Job orchestrator: typed `JobSpec` → agent execution → provenance `Bundle`.

[![docs.rs](https://img.shields.io/docsrs/nucleus-control-plane)](https://docs.rs/nucleus-control-plane)

Given a typed `JobSpec` (input reference, task, destination, agent driver) and a
`JobRunner` implementation, `execute_job` runs the agent inside a fresh
SPIFFE-rooted session, captures every lineage edge it emits, and produces a
verified provenance [`Bundle`](../nucleus-envelope) via `nucleus-envelope`.

## Flow

```text
JobSpec ──► execute_job ──► (fresh SPIFFE session)
                              │  run JobRunner
                              │  capture lineage edges
                              ▼
                           provenance Bundle  ──► Destination
```

## Public surface

| Item | Role |
|---|---|
| `JobSpec`, `InputRef`, `Destination`, `AgentDriverRef` | the typed job description |
| `JobRunner` (+ `MockJobRunner`) | the agent-execution trait (mock for tests) |
| `execute_job` | orchestrates a single job end-to-end |
| `SessionWriter` | captures the lineage subgraph during a session |
| `JobId`, `JobState`, `JobOutcome` | job lifecycle/result types |

## Vendor neutrality

`JobRunner` is a **trait**. The orchestrator core knows only "run agent X, collect
lineage Y, package result Z" — it does not know which model does the work, what it
costs, or how its credentials are formatted. Concrete agent integrations and any
vendor-specific cost models / credential handling live in **downstream** crates
(e.g. the proprietary `workstream-kg` platform), never here. A `MockJobRunner` is
provided so the orchestration logic is fully testable with no external agent.

## License

MIT
