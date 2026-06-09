# RFC: Attested, proof-carrying enforcement — verify-only-the-math authorization

**Status:** moonshot / research target. Honest framing: this composes primitives
that **already exist in-tree** (DICE launch attestation, the formally-verified
`portcullis-core` decision lattice, the RISC-Zero zkVM guest, hash-chained Ed25519
receipts, the `nucleus-envelope` lineage DAG) into a single guarantee no current
system offers — but the strongest rungs (full-kernel zk proof, IVC-folded session
proof) are targets, not shipped. The near-term rung (A) is mostly extending an
existing struct. Related: `signed-ifc-attested-agents.md`, `guaranteed-safe-recursion.md`,
`witness-olog-functor.md`, `externality-oracle.md` (the rung ladder pattern),
`regenerative-default-substrate.md` (proof = standing).

## 1. The gap (what is trusted-but-unproven today)

`FORMAL_METHODS.md` is honest that the **decision lattice is proven** (Lean
HeytingAlgebra + Kani + Aeneas extraction over `portcullis-core`) but the
**sandbox boundary is tested, not proven**: Firecracker, seccomp-BPF, iptables,
and the enforcement *binaries themselves* are asserted-by-CI, not measured. And a
relying party today must **trust the operator**: that the pod ran the real kernel,
that the receipt came from it, that no ambient-authority path bypassed it.

The 2026 frontier (VERA, Maris, OPAQUE, VARC, Right-to-History, Trusted Compute
Units) pairs a **reference monitor** with **attestation** — but in every case the
reference monitor is *unverified trusted code*. Nucleus is the only stack with a
**machine-checked decision kernel**. That is the missing leg, and it is the basis
for something genuinely novel.

## 2. The thesis: bind three independent guarantees into one receipt

A *proof-carrying verdict* binds the three questions a relying party actually has:

| Leg | Question | Primitive (exists today) |
|-----|----------|--------------------------|
| **Attestation** | Did the *right code* run? | `LaunchAttestation` (DICE/X.509), `SandboxProof` 3-tier (`nucleus-tool-proxy`) |
| **Formal proof** | Is the code *correct*? | Aeneas-extracted Lean `decide`/lattice; `integrity_sink_never_admitted` |
| **Execution proof** | Was *this op* decided by *that* code? | RISC-Zero zkVM guest; hash-chained Ed25519 `VerdictReceipt` |

The novelty is the **vertical binding**: make the *same kernel artifact* be (a) the
thing Aeneas/Lean proves correct, (b) the thing DICE/TEE measures, and (c) the zkVM
`image_id` (or TEE-measured code identity) that authorizes each verdict. A remote
verifier then trusts **only the math** — not the operator, not the cloud, not the
kernel source. In Trusted-Compute-Unit terms, the "canonical relation" every proof
binds to becomes a *formally-verified function* rather than an agreed-upon spec.
That closes the one gap every competitor leaves open: *is the reference monitor
itself correct?*

**Prior art is the ingredients, not the dish.** Proof-carrying code (Necula '96),
proof-carrying authorization (Appel/Felten, Bauer), PCFS, zkVMs, TEE attestation,
and TCU's mechanism-agnostic proof clauses all exist. The profound part is the
composition *with a verified evaluator as the canonical relation* — proving the
*policy evaluator* correct **and** attesting that the correct evaluator is the one
physically running.

## 3. Construction (four rungs, cheap → moonshot)

### Rung A — Attest the enforcement *logic*, not just the VM image

Extend the DICE measurement from `kernel/rootfs/config` to the enforcement bytecode:

```rust
// nucleus-identity/src/attestation.rs — extend LaunchAttestation
pub struct SandboxMeasurement {
    pub kernel_hash:          Hash256,
    pub rootfs_hash:          Hash256,
    pub config_hash:          Hash256,
    pub seccomp_filter_hash:  Hash256, // BPF bytecode actually loaded
    pub iptables_baseline_hash: Hash256, // default-deny ruleset
    pub portcullis_binary_hash: Hash256, // the permission kernel
    pub hook_adapter_hash:    Hash256, // the decision logic
}
```

The Firecracker loader computes the measurement and embeds it in the SVID cert (new
DICE extension); `AttestationRequirements` already whitelist-checks. This turns *"we
tested the sandbox works"* into *"we attest the sandbox is the measured one, and the
measured one is the formally-verified one."* Highest ROI; closes the tested-not-proven
sandbox gap with a measurement rather than a proof.

### Rung B — The proof-carrying verdict

Add a mechanism-agnostic proof to the receipt, generated over the
**Aeneas-extractable, Lean-proven decision core** (`decide_pure` / lattice `meet` /
exposure gating) — the subset that is *both* provable and zk-friendly:

```rust
// portcullis/src/receipt_chain.rs — extend VerdictReceipt
pub struct VerdictReceipt { /* …existing… */ pub enforcement_proof: Option<EnforcementProof> }

pub enum EnforcementProof {
    /// zkVM receipt: image_id == the published, formally-verified kernel.
    Zkvm { image_id: [u8; 32], journal: Vec<u8> }, // journal commits (pre, op, verdict, post)
    /// TEE attestation (TDX/SEV-SNP/Nitro), EAT-formatted, over the same relation.
    Tee  { code_measurement: Hash256, quote: Vec<u8> },
    /// SVID-signed transition for the cheap path.
    IdentitySigned { spiffe_id: String, cert_hash: Hash256 },
}
```

Verifier check: `image_id ∈ {verified kernels} ∧ proof valid ∧ DICE attestation
valid ⇒ the decision provably came from the correct kernel inside the measured
sandbox.` This is the strongest known form of proof-carrying authorization.

### Rung C — Mechanism-agnostic clauses (TCU-style, over a verified relation)

The `EnforcementProof` enum is deliberately a *proof clause*: `Zkvm | Tee |
IdentitySigned`, all binding to the **same** verified `decide` relation and checked
inside a bounded local verifier. TEE for cheap real-time; zkVM for
disputed/high-assurance ops; SVID for the trusted-fast path. This realizes the
`externality-oracle.md` rung ladder for *enforcement*, and mirrors Trusted Compute
Units — except the canonical relation is machine-checked.

### Rung D — Recursive attestation = proof-carrying *data* for the agent economy

Put an `EnforcementProof` on every `nucleus-envelope` lineage edge. A verifier who
has **never seen the system** reconstructs trust from the **root measurement alone**
— eliminating the envelope's current "NOT self-anchoring / trust-anchor-out-of-band"
limitation. Fold per-op receipts with IVC/Nova-style recursion into **one succinct
proof**: *"every operation in this entire multi-agent session was authorized by the
verified kernel running in the attested sandbox."* Portable, recompute-free, and it
feeds the regenerative substrate directly: **proof-of-verified-enforcement = standing.**
This is the cryptographic completion of the witness→olog "proof-of-work that
accumulates" (`witness-olog-functor.md`).

## 4. Why this matters for Guaranteed-Safe Recursion

`guaranteed-safe-recursion.md` proves the constitutional verifier is *correct*
(T1–T5, Löb-sidestepped). But "frozen" is currently a software assumption. **DICE/TEE
measurement is how you make "frozen" physically tamper-evident and remotely
checkable.** T1–T5 prove the verifier is correct; attestation proves the *correct
verifier is the one actually running*; proof-carrying verdicts prove *it ran on this
operation*. Together: the first end-to-end Guaranteed-Safe-AI verifier that can be
verified *from the outside* — what ARIA Safeguarded AI / ProvablySafe.AI reach for,
and what the EU AI Act runtime-proof provisions (live 2026-08-02) will demand.

## 5. Threat model

- **Malicious operator** swaps the kernel binary → defeated by Rung A (measurement
  mismatch) + Rung B (`image_id` ∉ verified set).
- **Forged receipt** → defeated by Rung B/C proof; receipt without a valid clause
  is rejected.
- **Ambient-authority bypass** (the 146 direct `std::fs`/`Command` call sites) →
  *not* defeated by attestation alone; these must be routed through `PolicyEnforced`
  first (tracked: #1216). Attestation measures the kernel; it cannot prove the kernel
  was *consulted*. **This is the load-bearing residual** — see §6.
- **Replay across sessions** → existing `chain_id` anti-replay.
- **Compromised guest inside the VM** → contained by seccomp/iptables (measured in
  Rung A) but their *correctness* is still trusted (see §6).

## 6. Honesty boundary (what this does NOT prove)

1. **The fully-proven *and* zk-proven kernel is a subset.** Aeneas cannot extract
   HashMap/crypto/unsafe/nested loops (`PROOFS.md §5`); zk-proving strings/path-
   matching is costly. Realistic near-term: zk-prove the **pure lattice/exposure
   decision core**, *attest* the impure remainder. The receipt MUST disclose which
   part is proven vs attested (the `PROOFS.md` honesty discipline).
2. **Attestation proves code *identity*, not code *bug-freeness*** outside the
   verified core. Measurement and proof are complementary, not redundant.
3. **Mediation completeness is separate.** Attestation cannot prove every side
   effect went through the kernel; that is the `PolicyEnforced` completeness work
   (#1216, #1248, #1249). Without it, a proof-carrying verdict certifies *the
   decisions that were made*, not *that all operations were decided*.
4. **TEE has its own TCB + side-channels;** an irreducible residue remains (same
   shape as the `externality-oracle.md` Rung-5 physical boundary). Disclose it.
5. **Per-op zkVM latency is seconds today;** Rung D's IVC folding is research-grade.

## 7. What's proven vs proposed

- **Proven / built today:** the decision lattice (Lean + Kani + Aeneas); DICE
  `LaunchAttestation` + `AttestationRequirements`; `SandboxProof` 3-tier fail-closed;
  hash-chained Ed25519 `VerdictReceipt`; the zkVM guest (`parser_hash, input_hash,
  output_hash` journal); `nucleus-recompute` parity; `gov_is_functor`.
- **Proposed (this RFC):** `SandboxMeasurement` (A); `EnforcementProof` on receipts
  (B) and lineage edges (D); the verified-kernel `image_id` registry; the
  bounded local verifier for proof clauses (C); IVC folding (D). None of these
  has a discharged correctness theorem yet — **do not describe them as proven**
  before the zk-core extraction and the mediation-completeness work land.

## 8. Phasing

- **P1 (A):** `SandboxMeasurement` + DICE extension + deterministic-measurement test.
- **P2 (B):** zkVM guest over the decision core; `EnforcementProof::Zkvm`; verify in
  `nucleus-recompute` before trusting a receipt.
- **P3 (C):** `EnforcementProof::Tee` (TDX/SEV-SNP), EAT-formatted; bounded local
  verifier accepting any clause binding the verified relation.
- **P4 (D):** edge-level proofs in `nucleus-envelope`; recursive verifier; IVC fold
  to a single session proof; wire proof-of-enforcement → standing.
