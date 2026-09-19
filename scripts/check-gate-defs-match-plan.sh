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
# Usage: check-gate-defs-match-plan.sh <gates.json>
#   where <gates.json> is the output of `gate plan gates .gatehouse/pipeline.writ`.
# Without it this script REFUSES rather than guesses: it cannot look, and says so.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ $# -lt 1 ]; then
  echo "usage: $0 <gates.json>   (from: gate plan gates .gatehouse/pipeline.writ)" >&2
  echo "cannot look: without the elaborator's output there is nothing authoritative to compare" >&2
  exit 2
fi

ELABORATED="$1"
[ -s "$ELABORATED" ] || { echo "cannot look: $ELABORATED is empty or missing" >&2; exit 2; }

ELABORATED="$ELABORATED" python3 - <<'PY'
import json, os, pathlib, sys

elaborated = json.loads(pathlib.Path(os.environ["ELABORATED"]).read_text())
plan = {g["name"]: g for g in elaborated}
if not plan:
    sys.exit("cannot look: the elaborator emitted no gates")

gates_dir = pathlib.Path(".gatehouse/gates")
bad, seen = [], set()

for path in sorted(gates_dir.glob("*.json")):
    name = path.stem
    seen.add(name)
    if name not in plan:
        bad.append(f"{name}: has a gate definition and the plan declares no such gate")
        continue
    want, got = plan[name], json.loads(path.read_text())

    # Lists and scalars that mean the same thing on both sides.
    for field in ("cmd", "tools", "seeds", "outputs"):
        a, b = want.get(field, []), got.get(field, [])
        if a != b:
            bad.append(f"{name}: {field} is {b!r} in the gate definition and {a!r} in the plan")

    # The writ `Gate` carries scope as a flat list of globs; the JSON carries an object whose
    # other fields (exclude, external, git_history) the writ term has no room for. The INCLUDE
    # list is the part both spell, so it is the part compared.
    a = want.get("scope", [])
    b = (got.get("scope") or {}).get("include", [])
    if a != b:
        bad.append(f"{name}: scope.include is {b!r} and the plan declares {a!r}")

for name in sorted(set(plan) - seen):
    bad.append(f"{name}: the plan declares this gate and .gatehouse/gates/{name}.json is missing")

if bad:
    print("gate definitions disagree with the plan:", file=sys.stderr)
    for b in bad:
        print(f"  {b}", file=sys.stderr)
    sys.exit(1)

print(f"OK: {len(plan)} gate(s) carry the cmd, tools, seeds, outputs and scope the plan declares")
PY
