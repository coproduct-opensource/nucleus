"""DisCoPy string diagrams of the Proof-Carrying-Authorization fabric.

Each diagram is a genuine morphism in a monoidal category — the boxes are the
fabric's processes, the wires are its typed data. Rendered to PNG.
"""
import os
os.environ.setdefault("MPLBACKEND", "Agg")

from discopy.monoidal import Ty, Box, Id

OUT = os.path.dirname(os.path.abspath(__file__))


def colored(box, c):
    try:
        box.color = c
    except Exception:
        pass
    return box


# ── Types (the wires) ──────────────────────────────────────────────────────
Policy   = Ty("Policy")
Request  = Ty("Request")
Decision = Ty("Decision")
Cert     = Ty("Cert")
Verdict  = Ty("Verdict")
Cap      = Ty("Cap")

# ════════════════════════════════════════════════════════════════════════════
# Diagram 1 — the PCA authorization pipeline (the strict "decide" leg).
#   (Policy ⊗ Request) --decide--> Decision --issue·sign--> Cert
#       --relocate: issuer ⇒ verifier--> Cert --verify·recompute--> Verdict
# The relocate box is the change of execution SITE; verify·recompute is the leg
# that makes the naturality square commute (same verdict, other site).
# ════════════════════════════════════════════════════════════════════════════
decide   = colored(Box("decide",            Policy @ Request, Decision), "white")
issue    = colored(Box("issue · sign",      Decision,         Cert),     "white")
relocate = colored(Box("relocate\nissuer ⇒ verifier", Cert,  Cert),     "red")
verify   = colored(Box("verify · recompute", Cert,            Verdict),  "white")

pipeline = decide >> issue >> relocate >> verify
pipeline.draw(path=f"{OUT}/01_fabric_pipeline.png", figsize=(7, 8), fontsize=13)

# ════════════════════════════════════════════════════════════════════════════
# Diagram 2 — delegation as a coKleisli composite of the INTERIOR comonad.
#   A capability wire threaded through repeated attenuation (meet with a
#   ceiling): root ∧ c_A ∧ c_B ∧ c_C — the weakest-link fold. Each box is the
#   coreflector (−)∧c; the composite is the interior comonad's coKleisli arrow.
# ════════════════════════════════════════════════════════════════════════════
att_a = colored(Box("∧ c_A   (delegate→A)", Cap, Cap), "green")
att_b = colored(Box("∧ c_B   (delegate→B)", Cap, Cap), "green")
att_c = colored(Box("∧ c_C   (delegate→C)", Cap, Cap), "green")
chain = att_a >> att_b >> att_c
chain.draw(path=f"{OUT}/02_delegation_chain.png", figsize=(4.5, 7), fontsize=13)

# ════════════════════════════════════════════════════════════════════════════
# Diagram 3 — the dual idempotent reflections + the sandwich i(x) ≤ x ≤ c(x).
#   delegate = interior comonad (pulls authority DOWN, deflationary),
#   enforce  = closure  monad   (pushes posture UP, inflationary),
#   shown as the two endomorphisms a verdict passes between.
# ════════════════════════════════════════════════════════════════════════════
Auth = Ty("authority")
interior = colored(Box("delegate = (−)∧c\n[interior comonad, ≤]", Auth, Auth), "green")
closure  = colored(Box("enforce = clamp↑\n[closure monad, ≥]",    Auth, Auth), "yellow")
sandwich = interior >> closure
sandwich.draw(path=f"{OUT}/03_dual_reflections.png", figsize=(4.5, 6), fontsize=12)

print("WROTE:")
for f in ("01_fabric_pipeline.png", "02_delegation_chain.png", "03_dual_reflections.png"):
    p = f"{OUT}/{f}"
    print(f"  {p}  ({os.path.getsize(p)} bytes)" if os.path.exists(p) else f"  MISSING {p}")
