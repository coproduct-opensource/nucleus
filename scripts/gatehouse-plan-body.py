#!/usr/bin/env python3
"""The plan gatehouse serves for this repository, as the body a push to main sends it.

    scripts/gatehouse-plan-body.py <checkout> <gate-binary>  > body.json

`{"plan": <hash>, "gates": [{name, class, gate}]}`: the plan hash `gate plan check` proves, each
`.gatehouse/gates/<name>.json` as the gate, and its class from the policy's required list. Refuses
a plan the kernel does not admit, and gate JSON that disagrees with the plan
(scripts/check-gate-defs-match-plan.sh). Copied from gatehouse's
ops/x86-lane/acceptance/plan-body.py, which is what an operator ran by hand before
.github/workflows/gatehouse-plan.yml sent it on every push.
"""
import json
import pathlib
import re
import subprocess
import sys

root, gate = pathlib.Path(sys.argv[1]), sys.argv[2]
writ = root / ".gatehouse/pipeline.writ"
check = subprocess.run([gate, "plan", "check", str(writ)], capture_output=True, text=True)
if check.returncode != 0 or "admissibility proved" not in check.stdout:
    sys.exit(f"gate plan check refused the plan:\n{check.stdout}{check.stderr}")
plan = re.search(r"^plan pipeline: ([0-9a-f]{64})$", check.stdout, re.M).group(1)
subprocess.run(["./scripts/check-gate-defs-match-plan.sh"], cwd=root, check=True,
               stdout=subprocess.DEVNULL)
policy = next(l for l in writ.read_text().splitlines() if l.startswith("let policy"))
required = re.findall(r'#b"([^"]+)"', policy.split("] : Bytes", 1)[0].split("(ceiling,", 1)[1])
gates = []
for g in sorted((root / ".gatehouse/gates").glob("*.json")):
    gates.append({"name": g.stem, "class": "required" if g.stem in required else "optional",
                  "gate": json.loads(g.read_text())})
assert {g["name"] for g in gates if g["class"] == "required"} == set(required), required
json.dump({"plan": plan, "gates": gates}, sys.stdout)
