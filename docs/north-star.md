# North Star: The First Formally Verified AI Agent Security Runtime

## Vision

Nucleus will be the first formally verified permission lattice and security
runtime for AI agents. Every security-critical code path will be
machine-checked: either proven correct by an SMT solver (Verus), verified
against a mathematical model (Lean 4 via Aeneas), or both.

The goal is not verification for its own sake. Our own audit found 5 critical
fail-open bugs that existed *despite* 6 Kani proofs, 233 proptest laws, and 70
OWASP attack scenarios. The proofs verified the lock works. They didn't check
if anyone locked it. Formal verification of the integration boundary — proving
that every code path either enforces the lattice or panics — is the missing
piece.

## Why Rust

Rust is the only language that satisfies all four requirements simultaneously:

1. **Near-C performance** — zero-cost abstractions, no GC, deterministic
   latency inside Firecracker microVMs
2. **Modern type system** — algebraic data types, pattern matching, traits,
   async/await, package ecosystem (crates.io)
3. **Formal verification** — Verus (SMT-based, SOSP 2025 Best Paper),
   Aeneas (Rust → Lean 4), Kani (bounded model checking), hax (Rust → F*)
4. **Safety certification** — Ferrocene qualified at ISO 26262 ASIL-D,
   IEC 61508 SIL 4, IEC 62304 Class C (highest levels)

### Alternatives Considered

| Language | Fatal Problem |
|----------|--------------|
| F* | Tiny ecosystem; extracts to C, losing Rust's memory safety |
| Lean 4 | ~5x slower than C; stdlib not 1.0 until mid-2026 |
| Dafny | Compiles to C#/Go/Java — 10-50x performance penalty |
| Ada/SPARK | Wrong domain (embedded/aerospace, not cloud-native) |
| Haskell | GC overhead; 3-10x slower; can't run in Firecracker efficiently |
| OCaml | GC overhead; 2-5x slower |

Switching 67.7K LOC of existing Rust would cost 3-8 person-years with no
verification advantage over verifying in place.

## Precedents

These production systems validate the approach:

- **AWS Nitro Isolation Engine** (Dec 2025) — formally verified Rust hypervisor
  component in production. Uses Verus for concurrency proofs + Isabelle/HOL for
  functional correctness. Deployed at AWS scale on Graviton5.

- **Atmosphere microkernel** (SOSP 2025 Best Paper) — full L4-class microkernel
  verified with Verus. 7.5:1 proof-to-code ratio (vs seL4's 20:1). Built in ~2
  person-years.

- **AWS Cedar** — formally verified authorization policy engine. Rust production
  engine + Lean formal model + differential fuzz testing. 1 billion auth
  requests/sec. The Cedar pattern (Rust runtime + Lean model + differential
  testing) is our architectural template for portcullis.

- **libcrux** (Cryspen) — formally verified post-quantum crypto in Rust via
  hax → F*. ML-KEM verified for correctness, panic freedom, and secret
  independence. Shipping into Firefox (Mozilla NSS).

- **AutoVerus** (OOPSLA 2025) — LLM agents auto-generate Verus proofs.
  137/150 tasks proven, >90% automation rate. More than half completed in
  <30 seconds.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Verified Core (Verus)              ~10-15K LOC     │
│  ├── portcullis                  Verus proofs    │
│  ├── permission enforcement         Verus proofs    │
│  └── sandbox boundary               Verus proofs    │
├─────────────────────────────────────────────────────┤
│  Formal Model (Lean 4 via Aeneas)                   │
│  ├── lattice algebra                Lean 4 proofs   │
│  ├── Heyting adjunction             Lean 4 proofs   │
│  └── graded monad laws              Lean 4 proofs   │
├─────────────────────────────────────────────────────┤
│  Differential Testing               Continuous      │
│  ├── Rust engine vs Lean model      cargo fuzz      │
│  └── AutoVerus proof generation     CI-gated        │
├─────────────────────────────────────────────────────┤
│  Runtime (standard Rust)            ~55K LOC        │
│  ├── gRPC, tokio, tonic             Kani checks     │
│  ├── Firecracker integration        Integration     │
│  └── Tool proxy, audit logs         Proptest        │
└─────────────────────────────────────────────────────┘
```

The verified core (~10-15K LOC) is the Trusted Computing Base (TCB). Following
the AWS Nitro approach, this code uses a restricted Rust subset amenable to
formal reasoning: no interior mutability, no `unsafe`, no dynamic dispatch.
Verus proofs are erased at compile time — the shipped binary is standard Rust
with zero overhead.

The Lean 4 model provides deeper mathematical reasoning about lattice
properties that benefit from Lean's Mathlib library: Galois connections, Heyting
algebra adjunctions, frame distributivity, graded monad laws. Aeneas translates
the Rust implementation to Lean 4 by exploiting ownership semantics to eliminate
memory reasoning, giving clean functional models.

Differential testing (the Cedar pattern) bridges the gap: millions of random
inputs are sent to both the Rust engine and the Lean model, checking identical
outputs. This catches discrepancies between the verified model and the
production code.

## Phased Roadmap

### Phase 0: Verified Lattice Core (3-4 months)

**Target:** portcullis crate (4.8K LOC, 96 existing tests)

**Tool:** Verus + AutoVerus

**What we prove:**
- Lattice laws: idempotent, commutative, associative, absorptive
- Nucleus operator: idempotent (ν(ν(x)) = ν(x)), deflationary (ν(x) ≤ x),
  monotone (x ≤ y ⟹ ν(x) ≤ ν(y))
- Distributivity: a ∧ (b ∨ c) = (a ∧ b) ∨ (a ∧ c)
- Heyting adjunction: a ∧ b ≤ c ⟺ a ≤ b → c
- Graded monad laws: associativity, unit

**Milestone:** "The first formally verified permission lattice for AI agent
security." This is the product claim.

### Phase 1: Lean 4 Mathematical Model (2-3 months)

**Target:** Translate portcullis to Lean 4 via Aeneas

**Tool:** Aeneas + Lean 4 + Mathlib

**What we prove:**
- All lattice properties in a richer proof environment
- Connections to established mathematical structures in Mathlib
- Properties that SMT solvers struggle with (induction over recursive
  structures, higher-order reasoning)

**Milestone:** Machine-checked mathematical foundation linked to Mathlib.

### Phase 2: Verified Enforcement Boundary (3-4 months)

**Target:** Integration layer — the code that decides whether to enforce

**Tool:** Verus

**What we prove:**
- Every code path through the daemon either enforces the lattice or panics
- No silent degradation: TLS failure = panic, missing config = 503
- Auth middleware is applied to every protected route (no `maybe_auth!` escape)

This directly addresses the 5 bugs our audit found. Formal methods on the
engine don't help if the ignition is optional.

**Milestone:** Proof that fail-closed is structurally guaranteed, not just
tested.

### Phase 3: Differential Testing Infrastructure (1-2 months)

**Target:** Cedar-pattern oracle testing

**Tool:** cargo fuzz + custom harness

**What we test:**
- Rust portcullis engine vs Lean 4 model on millions of random inputs
- Permission composition: same input → same decision in both implementations
- Edge cases that neither Verus nor Lean proofs would cover (serialization
  boundaries, encoding issues)

**Milestone:** Continuous verification in CI — every PR checked against the
formal model.

### Phase 4: Extended TCB Verification (3-4 months)

**Target:** Sandbox boundary, credential handling, tool proxy

**Tool:** Verus + Kani

**What we prove:**
- Sandbox escape is impossible given the proved invariants
- Credentials are never exposed outside the pod boundary
- Tool proxy enforces permissions on every operation

**Milestone:** Full TCB verification. The security runtime's critical path is
machine-checked end to end.

## Cost Estimates

Based on Atmosphere microkernel data (2 person-years for ~10K LOC verified at
7.5:1 proof-to-code ratio) and AutoVerus automation rates (90%+):

| Phase | LOC | Effort | Cost (1 eng) |
|-------|-----|--------|-------------|
| P0: Lattice core | 4.8K | 3-4 months | $50-70K |
| P1: Lean model | 4.8K (translated) | 2-3 months | $35-50K |
| P2: Enforcement boundary | ~5K | 3-4 months | $50-70K |
| P3: Differential testing | Infrastructure | 1-2 months | $15-25K |
| P4: Extended TCB | ~5K | 3-4 months | $50-70K |
| **Total** | **~15K verified** | **12-17 months** | **$200-285K** |

These estimates assume AutoVerus-class tooling is available for P0 and improves
over the project lifetime. Without LLM assistance, multiply by ~2x.

## Success Criteria

The north star is achieved when we can truthfully say:

> Nucleus is the first AI agent security runtime where the permission engine is
> formally verified (Verus SMT proofs), mathematically modeled (Lean 4 via
> Aeneas), and continuously tested against the formal model (differential
> fuzzing). Every code path in the trusted computing base either enforces the
> lattice or panics. No advisory security. No fail-open defaults. Machine-checked.

## References

- [Verus: Verified Rust for Systems Code](https://verus-lang.github.io/verus/)
- [Atmosphere: SOSP 2025 Best Paper](https://dl.acm.org/doi/10.1145/3731569.3764821)
- [AutoVerus: OOPSLA 2025](https://arxiv.org/abs/2409.13082)
- [AWS Nitro Isolation Engine](https://www.antstack.com/talks/reinvent25/aws-reinvent-2025---introducing-nitro-isolation-engine-transparency-through-mathematics-cmp359/)
- [AWS Cedar Formal Verification](https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing)
- [Aeneas: Rust → Lean 4](https://aeneasverif.github.io/)
- [Ferrocene Qualified Rust Compiler](https://ferrocene.dev/)
- [libcrux: Verified Crypto via hax](https://github.com/cryspen/libcrux)
