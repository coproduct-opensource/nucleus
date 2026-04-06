# Labeled Type System: Compile-Time IFC via Phantom Tags

`Labeled<T, I, C>` encodes integrity and confidentiality as **phantom type
parameters**, making certain IFC violations compile errors rather than runtime
denials. This is the static approximation of the dynamic `IFCLabel` system.

## The Functor

`Labeled` is an **endofunctor** on the category of Rust types:

```
Labeled : Type × IntegTag × ConfTag → Type
Labeled(T, I, C) = { value: T, _integ: PhantomData<I>, _conf: PhantomData<C> }
```

With `map` as the morphism action:
```
map : (T → U) → Labeled<T, I, C> → Labeled<U, I, C>
```

This is a functor because:
- `map(id) = id` (mapping identity preserves the labeled value)
- `map(f ∘ g) = map(f) ∘ map(g)` (composition is preserved)

The IFC tags `I` and `C` are preserved by `map` — transforming the inner
value does not change the security classification. This is the key insight:
**computation preserves labels**.

## Subtyping via Trait Bounds

Rust doesn't have subtyping, but trait bounds on generics achieve the same
effect. The flow constraints are:

**Integrity floor** (`IntegAtLeast<Floor>`):
```
IntegAtLeast<Adversarial>:  Adversarial ✓  Untrusted ✓  Trusted ✓
IntegAtLeast<Untrusted>:    Adversarial ✗  Untrusted ✓  Trusted ✓
IntegAtLeast<Trusted>:      Adversarial ✗  Untrusted ✗  Trusted ✓
```

**Confidentiality ceiling** (`ConfAtMost<Ceiling>`):
```
ConfAtMost<Public>:    Public ✓  Internal ✗  Secret ✗
ConfAtMost<Internal>:  Public ✓  Internal ✓  Secret ✗
ConfAtMost<Secret>:    Public ✓  Internal ✓  Secret ✓
```

These form **preorders** on the tag types:
- `IntegAtLeast` is a covariant preorder (higher integrity satisfies more floors)
- `ConfAtMost` is a contravariant preorder (lower confidentiality satisfies more ceilings)

A function with bound `I: IntegAtLeast<Trusted>` accepts only `Trusted` data.
Passing `Labeled<String, Adversarial, Public>` is a **compile error** — the
trait bound is not satisfied.

## The Galois Connection with Runtime Labels

The phantom type system and the runtime `IFCLabel` system form a **Galois
connection**:

```
γ : PhantomTag → RuntimeLabel     (concretization)
α : RuntimeLabel → PhantomTag     (abstraction)
```

Where:
- `γ(Trusted) = IntegLevel::Trusted`
- `γ(Adversarial) = IntegLevel::Adversarial`
- `α(IntegLevel::Trusted) = Trusted`
- `α(IntegLevel::Adversarial) = Adversarial`

The abstraction-concretization pair satisfies:
```
α(γ(tag)) = tag           (round-trip is identity)
γ(α(label)) ≤ label       (abstraction may lose information)
```

The second property is where the approximation lives: the runtime system has
6 dimensions (conf, integ, authority, provenance, freshness, derivation);
the type system only tracks 2 (integrity, confidentiality). Authority,
provenance, freshness, and derivation are lost in the abstraction.

## Declassification as a Controlled Natural Transformation

Promoting `Labeled<T, Adversarial, C>` to `Labeled<T, Untrusted, C>` is a
**natural transformation** — a morphism between functors:

```
promote_integrity : Labeled<–, Adversarial, C> ⟹ Labeled<–, Untrusted, C>
```

Naturality means:
```
promote(map(f, x)) = map(f, promote(x))
```

Promoting then transforming = transforming then promoting. The declassification
commutes with computation.

The key constraint: `promote_integrity` requires an explicit `DeclassifyReason`.
This makes the natural transformation **non-free** — it exists but is gated
by a side condition (human review, deterministic verification, or sanitization).

The reason requirement breaks the category's free structure intentionally:
if promotion were free, the type system would provide no protection. The
gate is the security property — the natural transformation exists in the
category of "authorized transformations," not in the category of all
transformations.

## Weakening as Free Morphisms

Unlike declassification, **weakening** (losing privilege) is free:

```
weaken_to_untrusted : Labeled<T, Trusted, Public> → Labeled<T, Untrusted, Public>
raise_to_internal   : Labeled<T, I, Public> → Labeled<T, I, Internal>
raise_to_secret     : Labeled<T, I, Internal> → Labeled<T, I, Secret>
```

These are monotone in the security lattice: they move toward "more restricted"
(lower integrity, higher confidentiality). No authorization needed — you can
always discard privilege.

This asymmetry — free weakening, gated strengthening — is the categorical
encoding of the security principle: **it's always safe to be more cautious**.

## Composition with NucleusRuntime

The `NucleusRuntime` mediated methods return `Labeled` values:

```
read_file()  → ReadOutput  { data: Labeled<Vec<u8>, Trusted, Internal> }
fetch_url()  → FetchOutput { data: Labeled<Vec<u8>, Adversarial, Public> }
run_shell()  → ShellResult { data: Labeled<ShellOutput, Untrusted, Public> }
git_commit() → CommitOutput { hash: Labeled<String, Trusted, Internal> }
```

This composes the functor (Labeled) with the runtime IFC (FlowTracker):
- The **type** tells you the label at compile time
- The **FlowTracker** tracks the label at runtime (with full 6-dimension precision)
- Both agree on the integrity and confidentiality dimensions

The composition is sound because the runtime labels are always at least as
restrictive as the type-level tags (the Galois connection's `γ(α(label)) ≤ label`
property).

## Verification Status

| Property | Tool | Reference |
|---|---|---|
| Adversarial → Trusted is compile error | Compile-fail doctest | `Labeled` doc-test |
| Promotion requires reason | Unit tests | `promote_untrusted_to_trusted_rejects_sanitization` |
| Weakening is free | Unit tests | `weaken_trusted_to_untrusted` |
| Map preserves tags | Unit tests | `labeled_map_preserves_tags` |
| Runtime level correspondence | Unit tests | `runtime_levels_match` |
| Full pipeline (web → promote → gate) | Unit tests | `web_data_promoted_through_pipeline` |
