# Belnap Bilattice: Four-Valued Policy Logic

The `Verdict` type implements a **Belnap four-valued logic** — a bilattice
with two independent orderings (truth and knowledge) that interact via
De Morgan duality. This structure gives the policy engine the ability to
represent not just "yes/no" but "unknown" and "conflict."

## The Four Values

```
           knowledge ↑
                     │
          Conflict   │   (both Allow and Deny asserted)
           ╱    ╲    │
         ╱        ╲  │
  Deny ─────────── Allow      ← truth →
         ╲        ╱
           ╲    ╱
          Unknown        (neither Allow nor Deny asserted)
```

| Value | Meaning | When it arises |
|---|---|---|
| `Allow` | Operation permitted | All checks pass |
| `Deny` | Operation forbidden | At least one check fails |
| `Unknown` | No information | Check abstains (not applicable) |
| `Conflict` | Contradictory evidence | One source allows, another denies |

## Two Orderings

The bilattice has two independent lattice structures:

**Truth ordering** (≤_t): ranks values by "how permitted" the operation is.
```
Deny ≤_t Unknown ≤_t Allow
Deny ≤_t Conflict ≤_t Allow
```

- `truth_meet` = greatest lower bound in ≤_t (most restrictive)
- `truth_join` = least upper bound in ≤_t (most permissive)

**Knowledge ordering** (≤_k): ranks values by "how much information" we have.
```
Unknown ≤_k Allow ≤_k Conflict
Unknown ≤_k Deny  ≤_k Conflict
```

- `knowledge_meet` = greatest lower bound in ≤_k (least information)
- `knowledge_join` = least upper bound in ≤_k (most information)

## Why Two Orderings?

Single-valued logic (Allow/Deny) cannot represent "I don't know" — a common
situation when a check doesn't apply to the current operation. A check for
web egress policy has no opinion on file reads; it should return `Unknown`,
not `Allow` or `Deny`.

The truth ordering governs **what to do**: `truth_meet(Allow, Deny) = Deny`
(one denial blocks the operation). The knowledge ordering governs **how much
we know**: `knowledge_join(Allow, Deny) = Conflict` (contradictory evidence
from two sources).

In nucleus:
- `truth_meet` is used for **AllOf** combinators (all checks must agree)
- `truth_join` is used for **AnyOf** combinators (any check may permit)
- `knowledge_join` is used for **merging evidence** from independent sources

## De Morgan Duality

The truth and knowledge orderings are connected by **negation** (¬):

```
¬Allow = Deny
¬Deny = Allow
¬Unknown = Unknown
¬Conflict = Conflict
```

De Morgan laws hold:
```
¬(a ∧_t b) = (¬a) ∨_t (¬b)     truth meet/join
¬(a ∧_k b) = (¬a) ∨_k (¬b)     knowledge meet/join
```

This means the truth and knowledge operations are not independent — they
are dual under negation. Changing the truth ordering flips Allow↔Deny but
preserves Unknown and Conflict.

## The Bilattice as a Product

Belnap's four-valued logic is isomorphic to the product lattice **2 × 2**:

```
Allow   = (true, false)     — asserted true, not asserted false
Deny    = (false, true)     — not asserted true, asserted false
Unknown = (false, false)    — neither asserted
Conflict = (true, true)     — both asserted
```

The first component is the "positive evidence" lattice, the second is the
"negative evidence" lattice. Truth operations act on the first component;
knowledge operations act diagonally.

This product structure is why the bilattice works: it decomposes the
four-valued logic into two independent boolean channels that are recombined
by the De Morgan duality.

## Policy Composition via Bilattice

The combinator algebra maps to bilattice operations:

| Combinator | Bilattice operation | Semantics |
|---|---|---|
| `AllOf(checks)` | `truth_meet` over results | All must agree: one Deny blocks |
| `AnyOf(checks)` | `truth_join` over results | Any may permit: one Allow suffices |
| `Not(check)` | `¬` (negation) | Flip Allow↔Deny |
| `FirstMatch(checks)` | First non-Unknown result | Short-circuit evaluation |

The bilattice guarantees that these compositions are well-defined:
- `truth_meet` is commutative, associative, idempotent → AllOf order doesn't matter
- `truth_join` is commutative, associative, idempotent → AnyOf order doesn't matter
- De Morgan: `Not(AllOf(a, b)) = AnyOf(Not(a), Not(b))` → negation distributes

## The Conflict Value

`Conflict` arises when independent policy sources disagree:

```
knowledge_join(Allow, Deny) = Conflict
```

In nucleus, Conflict is treated as **RequiresApproval** — contradictory
evidence means a human must resolve the disagreement. This is a design
choice, not a mathematical necessity. Other systems treat Conflict as Deny
(conservative) or Allow (permissive).

The bilattice module's `truth_rank()` method assigns:
```
Deny < Unknown < Conflict < Allow
```

This means `truth_meet(Conflict, Allow) = Conflict` — an Allow doesn't
override a Conflict. The human must still resolve it.

## Verification Status

| Property | Tool | Reference |
|---|---|---|
| truth_meet commutativity | Unit tests | `truth_meet_commutative` |
| truth_meet associativity | Unit tests | `truth_meet_associative` |
| truth_join commutativity | Unit tests | `truth_join_commutative` |
| truth_join associativity | Unit tests | `truth_join_associative` |
| De Morgan duality | Unit tests | `de_morgan_truth_meet/join` |
| Deny absorbs in truth_meet | Unit tests | `truth_meet_deny_absorbs` |
| Knowledge ordering consistency | Unit tests | `info_join_never_loses_information` |
