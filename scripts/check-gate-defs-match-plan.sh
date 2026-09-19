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
# Compares the fields that are a plain list or scalar on both sides. Scope and capabilities are
# deliberately NOT compared here: their writ encoding is a tuple of globs whose faithful
# comparison belongs with the elaborator, not with a regex. A narrower check that runs beats a
# wider one that does not.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import json, re, sys, pathlib

plan = pathlib.Path(".gatehouse/pipeline.writ").read_text()

# One `let <var> : ci.Gate = (#b"<name>", ...)` per gate, each on a single line.
# Field order is fixed by the prelude's `Gate` and documented in the plan's header:
#   (name, hash, scope, env, cap, cmd, timeoutMs, outputs, image, tools, diskMb, memMb,
#    platform, reads, seeds, measuredMs, replaces)
declared = {}
for line in plan.splitlines():
    m = re.match(r'let \w+ : ci\.Gate = \(#b"([^"]+)"', line)
    if not m:
        continue
    name = m.group(1)
    tools = re.search(r'image,\s*(\[[^\]]*\])', line)
    # `seeds` is the list after `platform,` and the one whose members carry a digest.
    seeds = re.search(r'platform,\s*\[[^\]]*\]\s*:\s*Bytes,\s*(\[[^\]]*\])', line)
    if not tools:
        sys.exit(f"cannot read the tools list for gate {name} out of the plan")
    declared[name] = {
        "tools": re.findall(r'#b"([^"]+)"', tools.group(1)),
        "seeds": re.findall(r'#b"([^"]+)"', seeds.group(1)) if seeds else [],
    }

if not declared:
    sys.exit("no gates found in .gatehouse/pipeline.writ: the parser and the plan disagree")

bad = []
seen = set()
for path in sorted(pathlib.Path(".gatehouse/gates").glob("*.json")):
    name = path.stem
    seen.add(name)
    if name not in declared:
        bad.append(f"{name}: has a gate definition and the plan declares no such gate")
        continue
    got = json.loads(path.read_text())
    for field in ("tools", "seeds"):
        want = declared[name][field]
        have = got.get(field, [])
        if have != want:
            bad.append(
                f"{name}: {field} in .gatehouse/gates/{name}.json is {have!r}, "
                f"and .gatehouse/pipeline.writ declares {want!r}"
            )

for name in sorted(set(declared) - seen):
    bad.append(f"{name}: the plan declares this gate and .gatehouse/gates/{name}.json is missing")

if bad:
    print("gate definitions disagree with the plan:", file=sys.stderr)
    for b in bad:
        print(f"  {b}", file=sys.stderr)
    sys.exit(1)

print(f"OK: {len(declared)} gate(s) carry the tools and seeds the plan declares")
PY
