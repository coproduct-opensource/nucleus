# Categorical diagrams of the PCA fabric (DisCoPy)

String diagrams of the Proof-Carrying-Authorization fabric, rendered with
[DisCoPy](https://discopy.org). Each is a genuine morphism (or functor image) in
a monoidal category — the boxes are the fabric's processes, the wires are its
typed data — so the pictures are *computed from the structure*, not hand-drawn.

See the doctrine: *authorization is natural in the execution site* (decide
commutes `=`, enforce is lax `≥`).

## The diagrams

| File | Shows | Maps to |
|---|---|---|
| `01_fabric_pipeline.png` | the authorization pipeline `(Policy ⊗ Request) → decide → issue·sign → ⟦relocate: issuer⇒verifier⟧ → verify·recompute → Verdict`. The red box is the change of execution **site**; `verify·recompute` is the leg that makes the naturality square commute. | `nucleus-policy-cert` (`decide`/`issue_decision_cert`/`verify`) |
| `02_delegation_chain.png` | delegation as the **interior-comonad coKleisli composite** — a `Cap` wire threaded through `∧ c_A ∧ c_B ∧ c_C` (weakest-link meet-fold). | `portcullis::closure::Attenuator` (`(−)∧c`) |
| `03_dual_reflections.png` | the two idempotent reflections: `delegate` (interior comonad, `≤`) vs `enforce` (closure monad, `≥`) — the `i(x) ≤ x ≤ c(x)` sandwich. | `portcullis::closure` (`Attenuator` / `Reflector`) |
| `04_change_of_base.png` | **the hero.** `F = change_of_base : V_firecracker → V_apple` as a DisCoPy `Functor` that **rewrites** the requested posture (`Namespaced/Sandboxed/Filtered`) into the Apple-enforceable one (`MicroVM/ReadOnly/Airgapped`, green = strengthened). The right-hand diagram is *computed by `F(requested)`* — the lax law `enforced ≥ requested` performed, not asserted. | `portcullis::enforcement` (`require_isolation`, `BackendCapability::APPLE_VZ`) |

## Regenerate

```sh
python3 -m venv venv
. venv/bin/activate
pip install discopy matplotlib
python pca_diagrams.py        # 01, 02, 03
python change_of_base.py      # 04 (+ regen intermediates req_firecracker.png / enf_apple.png)
```

Rendered with discopy 1.1.7 + matplotlib 3.9.4. The scripts write PNGs alongside
themselves; `MPLBACKEND=Agg` (set in-script) makes them headless-safe.

## Honest scope

These depict the **order / process skeleton** of the fabric: the capability
quantale's product is `⊗ = meet`, and the enrichment sees the lattice structure.
Cryptographic facts — Ed25519 signatures, the SHA-256 commitment chain, expiry,
chain depth — live **outside** the value object `V`, the same boundary the
Lean `-core` proof (`CapabilityResiduatedQuantaleProofs`) has. The diagrams are
a faithful picture of the *categorical* content, not the crypto.
