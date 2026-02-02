# Theoretical Foundations

Nucleus is built on ideas from type theory, category theory, and programming language semantics. This document explains the "why" behind the design.

## The Core Question

How do you give an AI agent enough capability to be useful while preventing it from exfiltrating your secrets?

This is not a data transformation problem (pipelines). It's a **capability tracking** problem. The permission state isn't data flowing through—it's a constraint on what effects can even occur.

---

## Graded Monads for Permission Tracking

The permission lattice is best understood as a **graded monad** (also called indexed or parameterized monad).

```haskell
-- The grade 'p' is the permission lattice
newtype Sandbox p a = Sandbox (Policy p -> IO a)

-- Operations require specific capabilities
readFile  :: HasCap p ReadFiles  => Path -> Sandbox p String
webFetch  :: HasCap p WebFetch   => URL  -> Sandbox p Response
gitPush   :: HasCap p GitPush    => Ref  -> Sandbox p ()

-- Sequencing composes permissions via lattice MEET
(>>=) :: Sandbox p a -> (a -> Sandbox q b) -> Sandbox (p ∧ q) b
```

When you sequence operations, their permission requirements compose via the lattice meet operation. The resulting type carries the combined constraints.

### Why Meet, Not Join?

Meet (∧) gives the greatest lower bound—the most restrictive combination. This ensures:

1. **Monotonicity**: Delegated permissions can only tighten, never relax
2. **Least privilege**: Combined operations get the intersection of capabilities
3. **Compositionality**: Order of composition doesn't matter (meet is commutative)

---

## The Trifecta as a Type-Level Constraint

The "lethal trifecta" (private data + untrusted content + exfiltration) is not a runtime check bolted on. It's a **type-level invariant**.

```haskell
-- When all three legs are present, the type changes
type family TrifectaGuard p where
  TrifectaGuard p = If (HasTrifecta p)
                       (RequiresApproval p)
                       p

-- Operations that can exfiltrate check this at the type level
gitPush :: TrifectaGuard p ~ p => Ref -> Sandbox p ()
```

In Rust, we approximate this with runtime normalization (the `ν` function), but the intent is the same: certain capability combinations **change the type of operations** from "autonomous" to "requires approval."

---

## Free Monads for the Three-Player Game

The Strategist/Reconciler/Validator pattern maps to the **free monad** pattern: separate the description of a computation from its interpretation.

```haskell
-- The functor describing sandbox operations
data SandboxF next
  = ReadFile Path (String -> next)
  | WriteFile Path String next
  | RunBash Command (Output -> next)
  | WebFetch URL (Response -> next)
  | GitPush Ref next

-- Free monad: a program is a sequence of operations
type SandboxProgram = Free SandboxF

-- Strategist: builds the program (pure)
strategist :: Issue -> SandboxProgram Plan

-- Reconciler: interprets with effects (IO)
reconciler :: SandboxProgram a -> Policy -> IO a

-- Validator: inspects the trace (pure)
validator :: Trace -> Verdict
```

This separation buys us:

1. **Testability**: Strategist output can be inspected without running effects
2. **Replay**: Programs can be re-interpreted against different policies
3. **Auditing**: The program structure is data, not opaque closures

---

## Algebraic Effects for Temporal Workflows

Temporal workflows go beyond classic monads. They're closer to **algebraic effects**:

```
effect CreatePod : PodSpec -> PodId
effect RunTool   : PodId * ToolCall -> ToolResult
effect AwaitSignal : SignalName -> SignalValue
effect Sleep     : Duration -> ()

handler workflow {
  return x -> Done(x)
  CreatePod(spec, k) -> persist(); pod <- firecracker(spec); k(pod)
  RunTool(pod, call, k) -> persist(); result <- proxy(pod, call); k(result)
  AwaitSignal(name, k) -> suspend(); await signal(name); k(value)
}
```

Effects can be:
- **Handled** at different levels (activity retries vs workflow timeouts)
- **Intercepted** (for logging, metering, approval injection)
- **Persisted** (workflow state survives process crashes)
- **Compensated** (rollback on failure)

This is more expressive than monad transformers because effects are first-class and can be handled non-locally.

---

## The Monotone Envelope

Security posture should be **monotone**: it can only tighten or terminate, never silently relax.

```
                    time →
    ┌─────────────────────────────────────────┐
    │  Permissions                            │
    │  ████████████████████                   │  ← start
    │  ██████████████████                     │  ← delegation
    │  ████████████████                       │  ← budget consumed
    │  ██████████████                         │  ← time elapsed
    │  ████████████                           │  ← approval consumed
    │                     ×                   │  ← terminated
    └─────────────────────────────────────────┘
```

This is modeled as a **monotone function** on the permission lattice:

```
ν : L → L
where ∀p. ν(p) ≤ p  (deflationary)
  and ν(ν(p)) = ν(p)  (idempotent)
```

The normalization function `ν` can only move down the lattice (add obligations, reduce capabilities), never up.

---

## Why Not Pipelines?

Unix pipelines are beautiful for data transformation:

```bash
cat file | grep pattern | sort | uniq
```

But they don't model:

1. **Capability requirements**: `grep` doesn't need different permissions than `sort`
2. **Effect sequencing**: Order matters for effects, not just data flow
3. **Failure modes**: Pipes abort; we need richer error handling
4. **Context threading**: Permissions, budget, time must flow through

Pipelines transform **data**. Monads sequence **effects with context**. Nucleus is about constraining which effects are expressible—that's fundamentally effect-theoretic.

---

## Practical Implications

### For the Rust Implementation

```rust
// Capability requirements as trait bounds (graded monad style)
pub trait ToolOp {
    type Capability: CapabilityRequirement;
    fn execute<P: Policy>(self, policy: &P) -> Result<Output, PolicyError>
    where
        P: HasCapability<Self::Capability>;
}

// Workflow steps as an enum (free monad style)
pub enum WorkflowStep<T> {
    CreatePod(PodSpec, Box<dyn FnOnce(PodId) -> WorkflowStep<T>>),
    RunTool(PodId, ToolCall, Box<dyn FnOnce(ToolResult) -> WorkflowStep<T>>),
    AwaitSignal(String, Box<dyn FnOnce(Signal) -> WorkflowStep<T>>),
    Done(T),
}

// Permission composition via meet
impl<P: PermissionLattice, Q: PermissionLattice> Meet for (P, Q) {
    type Output = <P as Meet<Q>>::Output;
    fn meet(self) -> Self::Output { ... }
}
```

### For Users

Think of Nucleus permissions as **types**, not configuration:

- The permission lattice is like a type parameter
- Operations have capability requirements like trait bounds
- Sequencing operations composes their requirements
- The trifecta constraint is a type-level invariant, not a runtime check

---

## References

- [Graded Monads](https://www.cs.kent.ac.uk/people/staff/dao7/publ/graded-monads-effects.pdf) - Katsumata, 2014
- [Algebraic Effects for Functional Programming](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/08/algeff-tr-2016-v2.pdf) - Leijen, 2016
- [Free Monads and Free Applicatives](https://www.paolocapriotti.com/assets/applicative.pdf) - Capriotti & Kaposi, 2014
- [Session Types](http://www.di.fc.ul.pt/~vv/papers/honda.vasconcelos.kubo_language-primitives.pdf) - Honda et al., 1998
- [The Lethal Trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) - Simon Willison, 2025

---

## Acknowledgments

The permission lattice design was influenced by capability-based security (Dennis & Van Horn, 1966), object-capability systems (Mark Miller's E language), and Rust's ownership model. The three-player game draws from formal verification's approach to separating specification from implementation.
