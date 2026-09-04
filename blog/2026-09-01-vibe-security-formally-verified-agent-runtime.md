# Vibe Security Is Killing Us. We're Building the First Formally Verified AI Agent Kernel.

*September 2026*

> **Updated 2026-09-04.** The verification stack described below has moved on
> since this was first published. Verus has been removed from the repository;
> the algebraic proofs it carried are now machine-checked in Lean 4 (unbounded,
> kernel-checked) and Kani (bounded model checking), and the Lean 4 via Aeneas
> extraction that the original post listed as a "Phase 1 (Q4 2026)" roadmap
> item is live and CI-gated today. The sections "Why Rust, Why Verus" and
> "What's Next" have been rewritten to match the tree; the proof narrative and
> the two counterexamples are kept as written because they still hold. The
> current, audited numbers live in
> [`FORMAL_METHODS.md`](https://github.com/coproduct-opensource/nucleus/blob/main/FORMAL_METHODS.md),
> which CI keeps in sync with the tree, so this post no longer quotes counts.

Andrej Karpathy coined "vibe coding" in February 2025: give in to the vibes, embrace exponentials, forget that the code even exists. Collins Dictionary made it 2025's Word of the Year. By 2026, 92% of US developers use AI coding tools daily. Google says 25% of their new code is AI-generated. Across the industry, the number is [24% and climbing](https://www.aikido.dev/).

Here's the problem nobody is talking about honestly: **we are now vibe-coding our security**.

45% of AI-generated code contains security flaws ([Veracode 2025](https://www.veracode.com/blog/ai-generated-code-security-risks/)). Each iteration makes it worse — [a 37.6% increase in critical vulnerabilities after just 5 rounds](https://arxiv.org/abs/2506.11022) of "fix this" / "improve that." One in five breaches is now attributed to AI-generated code. And the tools themselves have holes: [30+ vulnerabilities](https://thehackernews.com/2025/12/researchers-uncover-30-flaws-in-ai.html) across Cursor, Windsurf, Copilot, and Cline.

When your agent writes code it doesn't understand, reviews PRs it can't audit, and deploys infrastructure it can't verify — you don't have AI-assisted security. You have vibe security.

We're six months into building something different.

## The Problem With "Just Sandbox It"

The standard answer to AI agent security is containerization. Run the agent in Docker, restrict the network, call it a day.

This is necessary but nowhere near sufficient. Containers protect the *host*. They don't protect the *data inside the container*. An agent with read access to your codebase, web access to fetch untrusted content, and git push access to exfiltrate — that agent is dangerous *inside* the sandbox. This is Simon Willison's [uninhabitable state](https://simonwillison.net/2025/Jun/16/the-uninhabitable-state/):

```
Private Data Access  +  Untrusted Content  +  Exfiltration Vector  =  Data Exfiltration via Prompt Injection
```

You need a *permission kernel* — something that understands the *relationships* between capabilities and enforces invariants that hold even when the model is compromised.

## What We Built

[Nucleus](https://github.com/coproduct-opensource/nucleus) is an open-source security runtime for AI agents. The core is `portcullis`, a ~5,000 LOC Rust library that models permissions as a mathematical lattice: capabilities form a bounded distributive lattice, obligations use reversed subset ordering, and a normalization operator detects the uninhabitable state and adds mandatory approval gates.

Six months ago, we [audited our own platform](https://github.com/coproduct-opensource/nucleus/blob/main/blog/2026-03-04-we-audited-our-own-agent-platform.md) and found 5 critical fail-open vulnerabilities. Every bug followed the same pattern: security was present in code but absent in enforcement. We had Kani model-checking proofs. We had 233 proptest property tests. We had 70 OWASP LLM attack scenarios. None of them caught a single one of the 5 bugs.

That failure was the catalyst. We decided that if AI agents are going to write and deploy code on our behalf, the system enforcing their permissions needs a level of assurance that no amount of fuzzing or property testing can provide. We decided to formally verify the kernel.

## 49 Machine-Checked Proofs (and 2 Machine-Checked Counterexamples)

*Historical note (2026-09-04): this section describes the first proof pass, done in Verus. Verus and the `portcullis-verified` crate have since been removed; the same properties are now proved in Lean 4 and Kani, and the meet-preservation counterexample below is pinned as a Kani regression harness, `proof_nucleus_counterexample_witness`, so a future change cannot "fix" it by accident. The mathematics has not changed.*

At the time, we used [Verus](https://github.com/verus-lang/verus), an SMT-based verification tool for Rust. Verus translates Rust specifications into Z3 queries — if Z3 finds a satisfying assignment, the proof fails; if it exhausts the search space, the property is verified. No gaps between specification and implementation language. No translation trust boundary.

The `portcullis-verified` crate contained **49 verified proofs, 0 errors**:

**Capability lattice (37 proofs):**
- 7 lattice laws (commutativity, associativity, idempotence, absorption, distributivity, bounded) for a 3-element total order
- Full product lattice: 12-dimensional CapabilityLattice inherits all laws, including distributivity (which required per-component lemma invocations to avoid Z3 resource limits)
-  Uninhabitable state detection monotonicity: if the meet of two lattice elements doesn't have the uninhabitable state, neither does the meet (capabilities can only decrease under meet)

**Nucleus operator (12 proofs):**
- Idempotent: normalizing twice equals normalizing once
- Deflationary: normalization only adds obligations, never removes them
- Fixed point characterization: a permission is already normalized iff its obligations include the uninhabitable state gates
- Quotient meet produces fixed points
- Quotient meet is commutative
-  Uninhabitable state completeness is upward-monotone in capabilities
- Top element gets full obligations, bottom is identity

**And then the interesting part:** two properties we expected to prove turned out to be *false*.

### The Proofs That Failed — and What They Taught Us

We tried to prove:
1. **Meet preservation**: ν(x ∧ y) = ν(x) ∧ ν(y) — the nucleus distributes over meets
2. **Monotonicity**: x ≤ y implies ν(x) ≤ ν(y)

Both are required for the operator to be a *nucleus* in the frame-theoretic sense. Both turned out to be false, and we proved it with machine-checked counterexamples.

**Why meet preservation fails:** Take `a` with full capabilities (uninhabitable state complete) and `b` with no private data access (uninhabitable state incomplete). Their meet inherits `b`'s lack of private access, destroying the uninhabitable state. So `ν(a ∧ b)` adds no obligations. But `ν(a)` has full uninhabitable state obligations, which survive into `ν(a) ∧ ν(b)`. The two sides are provably unequal.

```rust
// Machine-checked counterexample (Z3-verified)
proof fn proof_nucleus_not_meet_preserving()
    ensures ({
        let a = Perm { caps: lattice_top(), obs: obs_empty(), uninhabitable_constraint: true };
        let b = Perm {
            caps: CapLattice { f0: 0, f1: 2, f2: 2, f3: 2, f4: 0, f5: 0,
                               f6: 2, f7: 2, f8: 2, f9: 2, f10: 2, f11: 2 },
            obs: obs_empty(), uninhabitable_constraint: true,
        };
        nucleus(perm_meet(a, b)) != perm_meet(nucleus(a), nucleus(b))
    })
{ }
```

**Why monotonicity fails:** Take `a ≤ b` where `a` lacks private access (uninhabitable state incomplete) and `b` has everything (uninhabitable state complete). The nucleus adds obligations to `b` but not to `a`. Since fewer obligations = *larger* in our reversed order, `ν(a)` ends up strictly larger than `ν(b)` — the opposite of what monotonicity requires.

**Why this matters:** The uninhabitable state detection is a *threshold function* — a conjunction of three disjunctions. Threshold functions are not lattice homomorphisms. This is not a bug in our code. It's a fundamental mathematical property of how we detect dangerous capability combinations. The operator is idempotent and deflationary, but it's not a nucleus. It's a *kernel operator* on a non-distributive quotient.

We could have papered over this. Instead, we published the counterexamples as verified proofs. If you're going to claim formal verification, the whole point is that you can't hide from what the math tells you.

The practical consequence: we proved that the *quotient meet* (which normalizes after meeting) always produces fixed points. The algebra is sound — just not via the classical nucleus construction. The fixed points form a well-behaved set under the quotient operations.

## Why Rust, Why Lean 4 + Kani, and What We Got Wrong About the Trust Boundary

*(Rewritten 2026-09-04. The original version of this section argued for Verus on the grounds that it avoids a translation trust boundary. We no longer use Verus, and we changed our mind about the boundary. Here is where we landed and why.)*

**The Cedar pattern.** AWS's [Cedar authorization engine](https://www.cedarpolicy.com/) uses a Lean 4 formal model with differential random testing against the Rust production implementation. This is the gold standard. Cedar's Lean model is a *separate implementation*, so there is a translation trust boundary between the verified model and the code that runs. The original post held that against it.

**We now accept that boundary on purpose, and gate it.** The [Aeneas](https://github.com/AeneasVerif/aeneas) toolchain (Charon lowers safe Rust to a typed intermediate representation; Aeneas lowers that to pure functional Lean 4) extracts our production Rust into Lean, where the deep proofs are done against Mathlib with the Lean kernel as the only thing trusted. That extraction *is* a trust boundary, and the honest answer is that every verification approach has one somewhere: Verus trusts its encoding into Z3 and Z3 itself, Kani trusts its MIR-to-GOTO lowering and CBMC. What matters is whether the boundary is checked in CI every time the code changes. Ours is, three ways:

- **Drift.** CI re-runs the extraction on every change and fails if the generated Lean differs from what is committed. A proof about last month's code cannot silently outlive the code.
- **Vacuity.** Every extracted theorem is followed by `#print axioms`, and the gate first asserts that the axiom output actually appeared before it believes the output's silence about `sorryAx`. A proof that did not run is not a proof.
- **Holes.** The proven tier bans `sorry` outright. Open research conjectures live in a separate, quarantined tier with a manifest, and CI counts them.

**What is extracted and proved today.** The capability lattice's `meet`, `join`, and `implies` are extracted and shown to agree with Mathlib's lattice operators, so the Heyting-algebra proofs are about the code, not a model of it. The integrity-flow kernel's noninterference theorem is proved on the extracted Rust. The OIDC-to-SPIFFE identity derivation and the constitutional policy kernel's soundness have their own scoped extractions and gates. Each family is a separate workflow in the repository's CI, and the scoped extraction gates are required checks on `main`.

**Kani carries the bounded half.** Bounded model checking on the production Rust types, no extraction at all: lattice laws, the kernel-operator counterexamples above, capability and budget escalation refusals, certificate-chain attenuation. A fast tier runs on every pull request; the full tier runs nightly and in the merge queue. Kani is where a property lands first, because a harness is cheap and a Lean proof is not; Lean is where it ends up when we want it unbounded.

**The language stack is converging.** Rust is the only language that simultaneously offers: (1) near-C performance for Firecracker microVM efficiency, (2) algebraic data types and async for modern systems code, (3) several independent formal verification backends (Kani/CBMC, Aeneas/Lean 4, Verus/Z3) that can be run against the same source, and (4) safety certification (Ferrocene, ISO 26262 ASIL-D). No other language hits all four.

## What's Next: The Roadmap, Revised

*(Rewritten 2026-09-04.)*

**Lean 4 via Aeneas: done, and central.** This was "Phase 1 (Q4 2026)" in the original post. It landed ahead of schedule and is the repository's deep-proof mechanism, as described above.

**Enforcement boundary: partly done, by gates rather than proofs.** The audit taught us that the real bugs are not in the algebra but in whether the algebra gets applied. Today that is held by structural CI gates on the live path: raw effect primitives are forbidden outside the mediated API, every input on the agent path must be content-addressed, verifiers must fail closed, and a meta-gate checks that each gate still fails on its own subject. These are checks over the source tree, not machine-checked proofs, and we say so. The certificate work of the last month moved more of this into signed data: the node issues every pod's certificate, and the proxy derives its permission kernel from that certificate rather than from a request.

**Differential testing: started.** Parity tests already assert that the extracted Lean and the Rust agree on generated inputs, and a property-based conformance suite covers the lattice composition. Cedar-scale randomized differential testing between a hand-written Lean model and the engine is still ahead of us.

**Full TCB verification: still the goal.** The trusted computing base for an AI agent sandbox includes the permission lattice (Lean 4 and Kani), the enforcement daemon (gates today, proofs later), the Firecracker VM boundary, and the SPIFFE identity chain. Each layer gets its own verification strategy appropriate to its abstraction level.

## The Honest Version

We are not done. The algebraic core is machine-checked, unbounded in Lean 4 and bounded in Kani (the audited inventory is in [`FORMAL_METHODS.md`](https://github.com/coproduct-opensource/nucleus/blob/main/FORMAL_METHODS.md)). The enforcement boundary — the thing that actually stops exfiltration — is gated and tested but not proved. The Firecracker isolation relies on AWS's existing verification work. The SPIFFE identity chain relies on SPIRE's audit trail.

What we have today is a formally verified permission *algebra* inside a conventionally tested enforcement *runtime*. That's better than nothing, and it's better than what anyone else in the AI agent space is shipping. But it's not the end state.

The end state is: **when an AI agent runs inside Nucleus, every permission decision from lattice computation through enforcement to audit log is covered by machine-checked proofs, and the system fails closed if any invariant is violated.**

seL4 proved you can formally verify an OS kernel. Cedar proved you can formally verify an authorization engine in production. We're trying to prove you can formally verify the security boundary around an AI agent.

Because "it's probably fine" is not a security posture. And vibe security is not security.

---

*Nucleus is open source under MIT/Apache-2.0: [github.com/coproduct-opensource/nucleus](https://github.com/coproduct-opensource/nucleus)*

*The proofs: the Lean 4 developments under [`crates/portcullis-core/lean`](https://github.com/coproduct-opensource/nucleus/tree/main/crates/portcullis-core/lean) and the Kani harnesses in [`crates/portcullis/src/kani.rs`](https://github.com/coproduct-opensource/nucleus/blob/main/crates/portcullis/src/kani.rs), including the two machine-checked counterexamples. The honest inventory, with what is and is not proved, is [`FORMAL_METHODS.md`](https://github.com/coproduct-opensource/nucleus/blob/main/FORMAL_METHODS.md).*
