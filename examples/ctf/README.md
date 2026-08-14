# Red-team CTF (v1) — the proven enforcement boundary as a live target

Turn nucleus's machine-checked enforcement boundary into a **live, adversarially
validated CTF**: a pod holds a canary flag behind the boundary, red-teamers try
to capture it, and every attempt becomes a **signed, tamper-evident
`MediationReceipt`** — the scoreboard. This directory is **Brick A**: the pod
definitions and runbook. Bricks B–E (below) add the external dial and scoreboard.

> **Not live yet.** This is the *mechanism*, built closed. Going live with real
> invitees — issuing credentials, exposing the pod, choosing the host and window
> — is a deliberate, outward decision, made separately.

## The flags map to the boundary claims

| Capture | Breaks | Proven by |
|---|---|---|
| Exfil the canary | IFC `flows_to` | the 5-axis noninterference proofs |
| Escalate a capability | the lattice attenuation | `CapabilityLattice::leq` (165 theorems) |
| Forge / replay a delegation | DLC admission | `admit_joint` / `decide_pure` (no-splicing) |
| Forge a receipt | the forensics | `verify_strict` over the mediator key |
| Escape the microVM | isolation | **not proven** — Firecracker/KVM is the unproven base |

The last row is honest: the proofs cover the *policy core*, not the hypervisor. A
host escape is a legitimate flag **and** a real, valuable finding — which is why
v1 runs on a **sacrificial, network-isolated host**.

## v1 shape (deliberately narrow)

- **One flag** — exfil the canary (the clearest claim: `flows_to` should block it).
- **Deterministic, closed surface** — the only attacker is the baked reference
  attack (`nucleus-adversary-probe`); no external dial yet.
- The boundary is the **strict `demo` profile**, egress **locked** (`ctf-pod.yaml`).

## The anti-vacuity control (non-negotiable)

"Flag not captured" means nothing unless it *can* be false. So v1 runs **two**
pods:

- `ctf-pod.yaml` — the real boundary. Expect `NUCLEUS_ADVERSARY: CONTAINED`,
  `BREACH` absent.
- A **weakened control** — the same pod with the boundary relaxed
  (`policy.name` set to a permissive profile and/or `network.allow: ["0.0.0.0/0"]`),
  where the canary **should** escape. The flag detector **must fire here**
  (`BREACH`), or "contained" on the real pod proves nothing.

Ship both; assert the detector fires on the control and stays silent on the real
pod — the same fail-closed + positive-control discipline as every gate in the
enforcement core.

## The scoreboard

With a mediator key configured on the node
(`NUCLEUS_MEDIATION_SIGNING_KEY` = 32 hex bytes, `NUCLEUS_MEDIATION_SPIFFE_ID`),
every mediation verdict emits a signed `MediationReceipt` (tracing target
`nucleus_mediation_receipt`) binding `art12_record_hash` to the record's chained
hash. Brick D verifies these (`verify_strict`) and renders attempts + verdicts +
`flag: captured?`. The receipt is forensic, not secret; the signing key stays
**host-side, out of the pod's reach** (grabbing it *is* the receipt-forgery flag).

## Brick roadmap

- **A (this dir):** CTF pod definitions + runbook. The boot-lane proof that the
  canary stays contained *and* a signed receipt is emitted lands once the live
  receipt-emit is on `main`.
- **B:** iroh `nucleus-spiffe-hail` → tool-proxy bridge; open exactly the iroh
  relay in `network.allow`; `min_assurance` gate + an invitee allowlist.
- **C:** flag detector — a unique canary token, tripwire on any egress attempt.
- **D:** receipt scoreboard — `verify_strict` + render.
- **E:** invitee allowlist, sacrificial host provisioning, kill switch.

## Running v1 (closed)

The existing boot lane (`.github/workflows/quickstart-boot.yml`) already plants a
canary and boots `probe-pod.yaml`, asserting `CONTAINED`. The CTF foundation is
that, pointed at `ctf-pod.yaml`, with a mediator key configured so a receipt is
emitted — validated on a real x86_64 KVM pod. Do not run against an
internet-exposed host until Brick E's host isolation + kill switch are in place.
