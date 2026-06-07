# nucleus-rubric-olog

A **decidable type-gate** that checks a *proposed* translation between two
rubric vocabularies is a valid **functor** — and, crucially, one that does not
move *load-bearing-ness* across the translation.

## The problem

Two teams score the same artifacts against different rubrics:

```
A = { correctness (RV), coverage (RV), cost (Attested) }
B = { accuracy    (RV), tests    (RV), spend (Attested) }
```

To compare or migrate scores you need a translation `A → B`. It is only
trustworthy if it is a **functor**: it must respect the rubric-as-schema
structure, AND it must map a `RecomputeVerified` (load-bearing) criterion onto a
`RecomputeVerified` one — never onto an `Attested`/`AttestationOnly` (inert)
one. Otherwise an unverifiable signal would inherit a verified column's rank
authority.

## What it does

* `rubric_to_schema(&Rubric) -> Schema` — objects = criterion ids + a single
  terminal `Artifact` object; morphisms = one `grade_of:{id}: {id} → Artifact`
  grade arrow per criterion.
* `RubricMapping` — a caller-supplied criterion-id → criterion-id object map
  (the `Artifact ↦ Artifact` part is canonical). The
  `SchemaMorphism`-equivalent.
* `check_translation(a, b, &mapping) -> Result<(), Misalignment>` — decidably
  validates the map is a well-defined, honesty-preserving functor; returns the
  first failure.
* `migrate_b_grades_into_a(...)` — round-trip: migrate a `B`-scored
  `Scorecard` into `A`'s vocabulary along an approved map, so the caller can
  re-run `nucleus_rubric::Rubric::validate_all`.

## Reject cases (`Misalignment`)

| Variant | Meaning |
|---|---|
| `UnmappedCriterion` | an `A`-criterion has no image (map not total) |
| `TargetCriterionMissing` | image is not a `B`-criterion (dangling target) |
| `NonInjectiveCollision` | two `A`-criteria collapse onto one `B`-criterion |
| `ArrowEndpointMismatch` | grade-arrow endpoints don't commute with the object map |
| `ProvenanceKindMismatch` | **honesty axis**: RV must map to RV (and vice versa) |
| `MaxGradeNarrowed` | `b.max_grade < a.max_grade` (a legal grade could go out of range) |

## Compatibility rule for `max_grade`

`b.max_grade >= a.max_grade`. Widening the image axis is fine; narrowing is not,
because a legal `A`-grade could then exceed `B`'s ceiling.

## Honest scope

* Verifies a **given** translation is a valid functor. Does **not** discover,
  search, or synthesize an alignment — the caller supplies the map; this is a
  checker, not a solver.
* Does **not** implement dinaturality, naturality, or any 2-categorical content.
* Decidable only on the **finitely-presented, equation-free fragment**. Each
  rubric-as-schema here is finite and free, so functoriality is a finite scan
  and is decidable. General functoriality between arbitrary finitely-*presented*
  categories (with equational relations) is undecidable; not attempted.
* Do **not** route a single rubric/scorecard validation through this gate —
  `nucleus_rubric::Rubric::validate_all` already covers within-one-vocabulary
  validity. This crate is strictly *between two vocabularies*.

## Why a local `Schema` (no olog dependency)

`nucleus` is public; the olog work is in a private repo. We must not add a git
or sibling-path dependency on private code, so the minimal `Schema` /
`SchemaMorphism` / functor-validity pattern from `olog-spivak-ops` is
**reimplemented locally** — it is small (a finite, decidable scan). The validity
shape mirrors `olog-spivak-ops`'s `compose_morphisms`, which returns `None`
exactly when a source object/morphism is unmapped or endpoints mismatch; here
that becomes the specific `Err(Misalignment::…)` reject path.

Dependencies: `nucleus-rubric` (path) + `serde` only.
