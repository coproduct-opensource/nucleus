# nucleus-task-compiler

The delegation compiler behind `nucleus run --goal`.

A goal ("fix the failing CI build") plus the repository it is stated in
(ecosystem, CI system, git remotes, MCP configs) compiles to a `TaskGrant`:
the semantic effects the task needs, lowered to a permission lattice and met
with a ceiling profile so it can never be wider than the ceiling. The grant
renders as five lines a person can approve (Goal / Can / Cannot / Limits /
Risk).

Effect proposal is deterministic and explainable (`rules.rs`). An
orchestrator may add a proposer as a child process (`ExternalCommandProposer`);
its output is validated against the catalog and clamped like everything
else, so a proposer can only narrow or starve a goal, never widen it.

This crate is offline by construction and CI enforces it.
