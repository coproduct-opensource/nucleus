# Heyting Algebra: Permission Lattice with Implication

The `CapabilityLattice` is a **distributive Heyting algebra** — a product of
13 bounded chains with pointwise meet, join, and implication. The Heyting
structure provides a formal notion of "if you have permission A, then you
may do B" that is absent from simple Boolean lattices.

## The Product Structure

```
CapabilityLattice = CapabilityLevel^13
```

Where `CapabilityLevel` is the 3-element chain:

```
Never(0) < LowRisk(1) < Always(2)
```

Each of the 13 dimensions (read_files, write_files, edit_files, run_bash,
glob_search, grep_search, web_search, web_fetch, git_commit, git_push,
create_pr, manage_pods, spawn_agent) independently carries a capability level.

Operations are pointwise:
```
meet(a, b)_i   = min(a_i, b_i)     (most restrictive of two policies)
join(a, b)_i   = max(a_i, b_i)     (most permissive of two policies)
bottom_i       = Never              (no permissions)
top_i          = Always             (all permissions)
```

## Why Heyting, Not Boolean?

A Boolean algebra has complementation: for every element a, there exists ¬a
such that a ∧ ¬a = ⊥ and a ∨ ¬a = ⊤. The 3-element chain {Never, LowRisk,
Always} does NOT satisfy this — there is no element x such that
`LowRisk ∧ x = Never` and `LowRisk ∨ x = Always`.

A Heyting algebra relaxes complementation to **implication**:

```
a → b = max { c | c ∧ a ≤ b }
```

For the 3-element chain:
```
a → b = if a ≤ b then Always else b
```

Truth table:
```
         → | Never  LowRisk  Always
    -------|------------------------
    Never  | Always  Always   Always
    LowRisk| Never  Always   Always
    Always | Never  LowRisk  Always
```

The implication answers: "what's the maximum additional permission I could
grant, given that I already have `a`, without exceeding `b`?"

## The Adjunction Property

The Heyting implication is characterized by a **Galois connection**:

```
c ∧ a ≤ b   ⟺   c ≤ (a → b)
```

This is the **currying adjunction** — meet with a fixed element is left
adjoint to implication by that element:

```
(– ∧ a) ⊣ (a → –)
```

**Practical meaning**: "can I combine permission `c` with existing permission
`a` and stay within budget `b`?" is equivalent to "is `c` at most `a → b`?"
This is how the kernel checks whether a requested capability escalation is
safe: compute the implication and compare.

**Proved in Kani**: `proof_r1_heyting_adjunction`, `proof_r4_lattice_heyting_adjunction`.

## Pseudo-Complement

The pseudo-complement is ¬a = a → ⊥:

```
¬Never   = Always    (if you have no permission, any addition is safe)
¬LowRisk = Never     (LowRisk already exceeds bottom; no safe addition)
¬Always  = Never     (Always already exceeds bottom)
```

This is NOT Boolean complementation (¬LowRisk ∨ LowRisk = LowRisk ≠ Always).
The failure of Boolean complementation is precisely why we need Heyting: the
permission space has a "gray zone" (LowRisk) that is neither fully permitted
nor fully denied.

**Proved in Kani**: `proof_r2_pseudo_complement`.

## Named Profiles as Lattice Elements

The named profiles are specific elements of the lattice:

```
bottom ≤ ReadOnly ≤ Research
bottom ≤ ReadOnly ≤ Codegen
bottom ≤ Review ≤ top
```

Profile composition via `join_profile` is the lattice join:
```
Research ∨ Codegen = (the element with both web and bash capabilities)
```

The `CapabilityLattice::builder()` constructs elements starting from `bottom`
and raising individual dimensions — this is building an element as a join of
atoms.

## The Lockdown Operation

`CapabilityLattice::read_only()` is the **meet with a ceiling**:

```
lockdown(a) = a ∧ read_only_ceiling
```

Where `read_only_ceiling` has `Always` for read dimensions and `Never` for
write/exec dimensions. By the deflationary property of meet:

```
lockdown(a) ≤ a
```

Lockdown can only remove permissions, never add them. This is proved by
`read_only_is_deflationary` and follows from `meet(a, b) ≤ a` for all b.

## Distributivity

The lattice is distributive:

```
a ∧ (b ∨ c) = (a ∧ b) ∨ (a ∧ c)
a ∨ (b ∧ c) = (a ∨ b) ∧ (a ∨ c)
```

This holds because each dimension is a chain (all chains are distributive),
and the product of distributive lattices is distributive.

**Practical meaning**: restricting a combined policy is the same as combining
restricted policies. There are no "interference effects" between meet and
join — they compose predictably.

## Verification Status

| Property | Tool | Reference |
|---|---|---|
| Heyting adjunction | Kani BMC | `proof_r1_heyting_adjunction` |
| Lattice-level adjunction | Kani BMC | `proof_r4_lattice_heyting_adjunction` |
| Pseudo-complement | Kani BMC | `proof_r2_pseudo_complement` |
| Entailment | Kani BMC | `proof_r3_entailment` |
| Meet idempotency | Unit tests | `lattice_idempotent_meet` |
| Join idempotency | Unit tests | `lattice_idempotent_join` |
| Meet pointwise | Unit tests | `lattice_meet_pointwise` |
| Read-only deflationary | Unit tests | `read_only_is_deflationary` |
| Type generation | Lean 4 / Aeneas | `Types.lean` (generated) |
