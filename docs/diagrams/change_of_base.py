"""change_of_base : V_firecracker -> V_apple, as a DisCoPy monoidal functor.

A requested isolation posture is a tensor of three state-prep boxes (one per
lattice dimension). The functor F = change_of_base (relocate the workload to an
Apple Virtualization.framework host) REWRITES the diagram, clamping each level
UP to the nearest Apple-enforceable one:

    Namespaced -> MicroVM    (no namespaces tier)
    Sandboxed  -> ReadOnly   (no in-VM cap-std guarantee)
    Filtered   -> Airgapped  (no host-side egress allowlist)

Levels Apple can already enforce are fixed points. This is the lax naturality
square `enforce_B ∘ move ≥ move ∘ enforce_A` made into a categorical operation:
the enforced posture is at-least-as-strong, never weaker.
"""
import os
os.environ.setdefault("MPLBACKEND", "Agg")

from discopy.monoidal import Ty, Box, Functor

OUT = os.path.dirname(os.path.abspath(__file__))

Proc = Ty("process")
File = Ty("file")
Net = Ty("network")


def lvl(name, ty, color="white"):
    b = Box(name, Ty(), ty)  # a state-prep: emits the chosen level on a wire
    try:
        b.color = color
    except Exception:
        pass
    return b


# Requested posture on Firecracker (the full lattice enforces it faithfully).
req_proc = lvl("Namespaced", Proc)
req_file = lvl("Sandboxed", File)
req_net = lvl("Filtered", Net)
requested = req_proc @ req_file @ req_net
requested.draw(path=f"{OUT}/req_firecracker.png", figsize=(9, 4), fontsize=14)

# The Apple-enforceable images (strengthened levels highlighted green).
enf_proc = lvl("MicroVM", Proc, "green")
enf_file = lvl("ReadOnly", File, "green")
enf_net = lvl("Airgapped", Net, "green")

# F = change_of_base : objects fixed, each requested level box -> its Apple image.
F = Functor(
    ob={Proc: Proc, File: File, Net: Net},
    ar={req_proc: enf_proc, req_file: enf_file, req_net: enf_net},
)

enforced = F(requested)
enforced.draw(path=f"{OUT}/enf_apple.png", figsize=(9, 4), fontsize=14)

# Compose a single hero figure: requested  ⇒F⇒  enforced.
import matplotlib.pyplot as plt
import matplotlib.image as mpimg

fig = plt.figure(figsize=(15, 5.2))
gl = fig.add_axes([0.02, 0.06, 0.43, 0.82])
gr = fig.add_axes([0.55, 0.06, 0.43, 0.82])
for ax, img, title in (
    (gl, "req_firecracker.png", "requested  —  Firecracker (full lattice, faithful)"),
    (gr, "enf_apple.png", "enforced  —  Apple VZ (clamped ↑, never weaker)"),
):
    ax.imshow(mpimg.imread(f"{OUT}/{img}"))
    ax.axis("off")
    ax.set_title(title, fontsize=13)

fig.text(0.495, 0.47, "F\n⇒", ha="center", va="center", fontsize=26, fontweight="bold")
fig.suptitle(
    "F = change_of_base : V_firecracker → V_apple      (enforce is lax:  enforced ≥ requested)",
    fontsize=15, y=0.985,
)
fig.savefig(f"{OUT}/04_change_of_base.png", dpi=150, bbox_inches="tight")

print("WROTE 04_change_of_base.png", os.path.getsize(f"{OUT}/04_change_of_base.png"), "bytes")
