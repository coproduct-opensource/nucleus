#!/usr/bin/env bash
# The gate definitions and the plan are one fact written twice.
#
# `.gatehouse/pipeline.writ` is what the writ kernel proves admissible. `.gatehouse/gates/*.json`
# is what is actually PUT to controld and handed to the executor (`put_plan` takes a whole
# `GateDef` per gate; controld does not derive one from the writ). The plan's own header says the
# JSONs "carry the same commands, scopes and capabilities" — and until this script, nothing
# checked it. Saying it is not checking it, which is the argument `xtask gatehouse-pin` already
# makes about the prelude digest.
#
# What that cost, on 2026-09-19: every gate JSON was missing `tools` while the plan declared it
# for all six. `GateDef::tools` is `#[serde(default, skip_serializing_if)]` — deliberately, so a
# plan written before the field existed serializes byte-identically — so the absence deserialized
# to an empty list in silence. An agent that enforces the declaration then refused every gate with
# "a gate must declare the tools it needs; the image is held to them", and the lane decided
# nothing. The plan proved a property (`toolsCovered_b`) about a value the executor never received.
#
# THE PLAN SIDE IS READ BY THE ELABORATOR, NOT BY A PATTERN. `gate plan gates` emits the gate
# terms the kernel actually checked, as JSON. The first version of this script scraped the writ
# with a regex, and that regex silently matched the `tools` list where it meant `cmd` and reported
# all six gates as disagreeing — a false alarm of exactly the shape gatehouse's F-152 records
# ("a hand-rolled pattern's failure mode is silently matching less than you meant, and checking it
# with another hand-rolled pattern tests the same assumption twice"). The elaborator is the only
# reader that agrees with the kernel by construction.
#
# The elaboration is COMMITTED, at `.gatehouse/plan-gates.json`, and that is what makes this
# gate probeable. Needing a gatehouse checkout at the pinned ref would name the gate's SUBJECT
# while saying nothing about its DETECTION — the distinction `check-gates-can-fail.sh` keeps
# re-learning, where an exemption names a real obstacle to producing the input and stops short of
# asking whether the comparison itself can be exercised. It can, from this tree alone.
#
# The snapshot cannot go stale silently: `gatehouse-plan.yml` re-elaborates with `gate plan gates`
# at the pinned ref and refuses any difference, which is the half that genuinely needs the
# checkout.
#
# Usage: check-gate-defs-match-plan.sh [gates.json]
#   with no argument, compares against the committed `.gatehouse/plan-gates.json`.
# Logic lives in Rust; retain this path for existing workflow and mutation callers.
set -euo pipefail
cd "$(dirname "$0")/.."
exec cargo run --quiet -p xtask -- gate-defs "$@"
