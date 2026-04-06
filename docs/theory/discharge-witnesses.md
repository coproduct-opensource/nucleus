# Discharge Witnesses: Linear Proof Tokens

`Discharged<O>` is a **zero-sized proof token** that an obligation O was
checked and passed. The token is sealed — only `preflight_action` can mint
one. This encodes the "proofs must be constructed, not assumed" axiom in the
Rust type system.

## The Proof-Carrying Paradigm

Traditional security kernels check permissions at runtime and return a boolean.
The caller receives "yes" or "no" but the evidence of checking is immediately
discarded. A subsequent code change that removes the check compiles and runs
without error.

Discharge witnesses make the evidence **structural**:

```rust
pub fn execute_write(path: &Path, content: &[u8], proof: &DischargedBundle) { ... }
```

The `proof` parameter is a `DischargedBundle` — a struct containing five
`Discharged<O>` tokens, one per obligation. The struct has a private `Seal`
field that cannot be named outside its module. The only way to obtain one
is through a successful `preflight_action` call.

**Removing the check is now a type error**, not a convention violation.

## The Linear Logic Connection

In linear logic, propositions are **resources** — they must be used exactly
once. A proof of A is not just evidence that A holds; it is a *token* that
must be consumed to exercise A.

`Discharged<O>` is a linear resource:
- It is `#[must_use]` — the compiler warns if it's discarded
- It is produced exactly once per obligation check (by `preflight_action`)
- It is consumed by the effect function that requires it

The five tokens in `DischargedBundle`:
```
Discharged<IntegrityGate>         — artifact integrity ≥ sink minimum
Discharged<PathAllowed>           — operation/sink pair is consistent
Discharged<DerivationClear>       — derivation class compatible with sink
Discharged<NoAdversarialAncestry> — no adversarial source labels
Discharged<BudgetNotExceeded>     — cost within budget
```

Each is an independent linear resource. Together they form the
**multiplicative conjunction** (tensor product ⊗) of all five proofs:

```
DischargedBundle ≅ Discharged<IntegrityGate>
                  ⊗ Discharged<PathAllowed>
                  ⊗ Discharged<DerivationClear>
                  ⊗ Discharged<NoAdversarialAncestry>
                  ⊗ Discharged<BudgetNotExceeded>
```

## Sealing as an Axiom Encoding

The `Seal` pattern encodes the axiom "only the kernel can produce proofs":

```rust
struct Seal;    // private to the module — external code cannot name it

pub struct Discharged<O: ProofObligation> {
    _marker: PhantomData<O>,
    _seal: Seal,                // cannot be constructed externally
}

impl<O: ProofObligation> Discharged<O> {
    fn mint() -> Self { ... }   // fn, not pub fn — module-private
}
```

External code can hold a `Discharged<O>`, inspect it, pass it to functions —
but never create one. The `Seal` field is a **private type** that acts as a
constructive proof obligation: the only code path that calls `mint()` is
inside `preflight_action`, which first checks the obligation.

This is an encoding of the **provability predicate** from provability logic:
`□A` (it is provable that A) can only be derived by actually proving A. You
cannot assume `□A` — you must construct it.

## The Monoidal Structure

The obligations form a **commutative monoid** under conjunction:

```
O₁ ⊗ O₂ = "both O₁ and O₂ are discharged"
I = ε = "no obligations" (the empty bundle)
```

`DischargedBundle` is the product of all obligations. Checking is sequential
(short-circuit on first failure), but the result is the full tensor product
— all five proofs bundled together.

The monoid is:
- **Commutative**: the order of obligation checking doesn't affect the result
  (each check examines disjoint fields)
- **Idempotent**: checking the same obligation twice produces the same token
- **Associative**: grouping obligations differently doesn't change the bundle

## Relationship to Repair

The repair system (#1268) is the **left adjoint** to discharge:

```
discharge : ActionTerm → Either<DischargedBundle, (RepairHint, ActionTerm)>
repair    : RepairHint × ActionTerm → Option<ActionTerm>
```

When discharge fails, the repair system produces a new term that will
succeed on the next attempt. The repaired term is in the **fiber** of
`discharge` over `Right(bundle)` — it maps to a successful discharge.

```
discharge(repair(hint, term)) = Right(bundle)
```

This is the counit of the repair adjunction applied to the discharge functor:
the repair guarantees that the repaired term produces a bundle.

## Verification Status

| Property | Tool | Reference |
|---|---|---|
| Bundle cannot be forged | Compile-fail doctest | `DischargedBundle` doc-test |
| Seal is private | Module privacy | `struct Seal` is `pub(self)` |
| mint() is module-private | Module privacy | `fn mint()` (not `pub fn`) |
| ProofObligation is sealed | Sealed trait | `obligation_sealed::ObligationSealed` |
| All 5 checks produce hints | Unit tests | 33 discharge tests |
