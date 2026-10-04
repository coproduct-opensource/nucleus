# Architect Adversarial North Star — No Shims, No Bridges, No Adapters

A world-class codebase has no translation layers between its verified core and its production runtime. Every adapter, bridge, shim, or wrapper is a gap where the proof stops and trust begins. The architect's job is to eliminate these gaps.

## Claim 1: The verified type IS the production type

portcullis-core::CapabilityLevel is the same type used in production portcullis. There is no "model" and "implementation" — there is one type, verified by Lean 4 and used by the tool-proxy. If you change the Rust enum, the Lean proof breaks. If you change the Lean proof, the Rust tests break. The correspondence is enforced by the compiler, not by convention.

## Claim 2: The Aeneas-generated functions are the production functions

The Rust meet() in portcullis-core is translated by Aeneas to Lean, and the Lean proof shows it equals the lattice inf. The production portcullis crate calls the same function. There is no "verified version" and "fast version" — the verified code IS the fast code.

## Claim 3: No adapter pattern between verified and unverified code

The tool-proxy does not have a VerifiedPermissionAdapter that wraps the lattice. The lattice IS the permission system. The VerdictSink does not translate between "internal representation" and "external representation." Every tool call verdict flows through the same types, the same functions, the same code path that the proof covers.

## Claim 4: The proof pipeline has no manual steps

Charon extracts MIR automatically. Aeneas translates to Lean automatically. CI diffs the output automatically. The bridge proof type-checks automatically. There is no human in the loop who might forget to regenerate, might skip a step, might update one side without the other.

## What a skeptical architect would challenge

- "Show me the dependency graph. Does production portcullis actually import portcullis-core, or are they independent codebases with a gentleman's agreement?"
- "The FunsExternal.lean has hand-written implementations for PartialOrd. How do you know those match the Rust derived impl?"
- "The production CapabilityLattice has extensions: BTreeMap that the verified core doesn't model. What happens when someone adds a security-critical extension?"
- "CoreFuns.lean is a 'curated subset' of the full Funs.lean. Who curates it? What if the curation drops a function that matters?"
- "The lakefile pins Aeneas to commit b2b5e3d. When Aeneas updates, does everything still work?"
- "Where is the single source of truth for the CapabilityLevel discriminant values? Rust repr(u8)? Lean toNat? The compile-time assertion? Which one wins?"
