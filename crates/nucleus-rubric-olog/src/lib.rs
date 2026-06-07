//! `nucleus-rubric-olog` — a **decidable type-gate** that checks a *proposed*
//! translation between two rubric vocabularies is a valid **functor**.
//!
//! # What this crate is (and is not)
//!
//! Two teams can score the same artifacts against *different* rubrics —
//! `{correctness, coverage, …}` vs `{accuracy, tests, …}`. To compare or
//! migrate scores you need a translation from one vocabulary to the other.
//! A translation is only *trustworthy* if it is a **functor**: it must respect
//! the categorical structure of the rubric-as-schema AND — critically for
//! eval honesty — it must NOT move *load-bearing-ness*. A translation that
//! quietly maps a `RecomputeVerified` criterion onto an `AttestationOnly` one
//! would let an unverifiable signal inherit a recompute-verified column's rank
//! authority. That is the failure this gate rejects.
//!
//! [`check_translation`] takes two [`Rubric`]s and a caller-supplied
//! [`RubricMapping`] (a criterion-id → criterion-id object map) and decidably
//! answers: *is this a well-defined functor that preserves the honesty axis?*
//! It returns `Ok(())` or the **first** [`Misalignment`] it finds (the reject
//! path is specific and load-bearing — see [`Misalignment`]).
//!
//! # Honest scope (read this before claiming anything)
//!
//! * It **verifies a GIVEN translation** is a valid functor. It does **not**
//!   discover, search for, or synthesize an alignment — the caller supplies the
//!   map; the gate is a checker, not a solver.
//! * It does **not** implement dinaturality, naturality of transformations,
//!   or any 2-categorical content. It checks functoriality of a single map.
//! * Only the **finitely-presented equational fragment** is decidable. Each
//!   rubric-as-schema here is finite and free (criterion-id objects + one grade
//!   arrow per criterion into a single `Artifact` object, no imposed
//!   equations), so functoriality reduces to a finite scan and IS decidable.
//!   General functoriality between arbitrary finitely-*presented* categories
//!   (with equational relations) is undecidable; we do not attempt it.
//! * Do **not** route a single rubric / scorecard validation through this gate.
//!   `nucleus_rubric::Rubric::validate_all` already covers within-one-vocabulary
//!   validity. This crate is strictly about *between two vocabularies*.
//!
//! # Why a local Schema (no dependency on the private olog repo)
//!
//! `nucleus` is the PUBLIC repo; the olog work lives in a PRIVATE repo. We must
//! not add a git or sibling-path dependency on private code. So the minimal
//! `Schema` / `SchemaMorphism` / functor-validity pattern from
//! `olog-spivak-ops` is **reimplemented locally** below — it is small: a finite,
//! decidable scan. The validity pattern mirrors `olog-spivak-ops`'s
//! `compose_morphisms`, which returns `None` exactly when a source object /
//! morphism is unmapped or endpoints mismatch. Here that same shape is the
//! `Err(Misalignment::…)` reject path, specialised to the rubric domain.

#![forbid(unsafe_code)]

use nucleus_rubric::{Provenance, Rubric, Scorecard};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ─── Local Schema (reimplemented from olog-spivak-ops; no olog dep) ──────────

/// The distinguished terminal object every grade arrow points at: the artifact
/// being scored. Its name is reserved — a criterion may not be named this.
pub const ARTIFACT_OBJECT: &str = "Artifact";

/// A small-category schema. Objects are named string IDs; morphisms carry their
/// src + tgt object names. Identities and composition are implicit (the free
/// category on this signature — no imposed equations, which is exactly what
/// keeps functoriality a *decidable* finite scan). This is the minimal local
/// reimplementation of `olog_spivak_ops::Schema`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schema {
    /// Object names (criterion ids + the [`ARTIFACT_OBJECT`]).
    pub objects: Vec<String>,
    /// `(morphism_name, src_object, tgt_object)`.
    pub morphisms: Vec<(String, String, String)>,
}

impl Schema {
    /// `true` iff `name` is one of this schema's objects.
    pub fn has_object(&self, name: &str) -> bool {
        self.objects.iter().any(|o| o == name)
    }

    /// The `(src, tgt)` endpoints of morphism `name`, if present.
    pub fn morphism_endpoints(&self, name: &str) -> Option<(&str, &str)> {
        self.morphisms
            .iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, s, t)| (s.as_str(), t.as_str()))
    }
}

// ─── rubric_to_schema ────────────────────────────────────────────────────────

/// The morphism-name convention: the grade arrow out of criterion `c` is named
/// `grade_of:{c}`. Stable and collision-free because criterion ids are unique
/// within a rubric ([`Rubric::new`] enforces this).
pub fn grade_arrow_name(criterion_id: &str) -> String {
    format!("grade_of:{criterion_id}")
}

/// Present a [`Rubric`] as a [`Schema`]:
///
/// * **Objects** = every criterion id, plus the single [`ARTIFACT_OBJECT`]
///   terminal object.
/// * **Morphisms** = one *grade arrow* `grade_of:{id}: {id} → Artifact` per
///   criterion — "this criterion grades the artifact". The arrows make the
///   schema connected and give functoriality something to respect beyond a bare
///   object relabel: a valid translation must carry each grade arrow to the
///   image criterion's grade arrow.
///
/// The schema is free (no imposed equations) so a translation's functoriality
/// is a finite, decidable scan — see the module docs' honest-scope note.
pub fn rubric_to_schema(rubric: &Rubric) -> Schema {
    let mut objects = Vec::with_capacity(rubric.criteria.len() + 1);
    let mut morphisms = Vec::with_capacity(rubric.criteria.len());
    for c in &rubric.criteria {
        objects.push(c.id.clone());
        morphisms.push((
            grade_arrow_name(&c.id),
            c.id.clone(),
            ARTIFACT_OBJECT.to_string(),
        ));
    }
    objects.push(ARTIFACT_OBJECT.to_string());
    Schema { objects, morphisms }
}

// ─── RubricMapping (the caller-supplied SchemaMorphism, criterion-id keyed) ──

/// A proposed translation `A → B`: maps each criterion id of rubric `A` to a
/// criterion id of rubric `B`. The [`ARTIFACT_OBJECT`] is always mapped to
/// itself (the terminal object is canonical), so the caller only supplies the
/// criterion-to-criterion part. This is the criterion-id–keyed analogue of
/// `olog_spivak_ops::SchemaMorphism` (whose `object_map` we narrow to criterion
/// ids and whose `morphism_map` is *derived* — the grade arrow of `c` must go to
/// the grade arrow of `map(c)`, so it carries no independent freedom).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RubricMapping {
    /// `A.criterion_id → B.criterion_id`.
    pub object_map: BTreeMap<String, String>,
}

impl RubricMapping {
    /// Build a mapping from `(a_id, b_id)` pairs.
    pub fn new<I, S, T>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (S, T)>,
        S: Into<String>,
        T: Into<String>,
    {
        Self {
            object_map: pairs
                .into_iter()
                .map(|(a, b)| (a.into(), b.into()))
                .collect(),
        }
    }

    /// Induce the underlying [`SchemaMorphism`] on the *schemas* of `a` and `b`.
    /// The object map is the criterion map extended by `Artifact ↦ Artifact`;
    /// the morphism map sends `grade_of:{c} ↦ grade_of:{map(c)}` for every `c`
    /// the object map covers. Returned for inspection / debugging; the gate
    /// re-derives validity directly in [`check_translation`].
    pub fn induced_schema_morphism(&self, a: &Rubric, b: &Rubric) -> SchemaMorphism {
        let source = rubric_to_schema(a);
        let target = rubric_to_schema(b);
        let mut object_map = self.object_map.clone();
        object_map.insert(ARTIFACT_OBJECT.to_string(), ARTIFACT_OBJECT.to_string());
        let mut morphism_map = BTreeMap::new();
        for (a_id, b_id) in &self.object_map {
            morphism_map.insert(grade_arrow_name(a_id), grade_arrow_name(b_id));
        }
        SchemaMorphism {
            source,
            target,
            object_map,
            morphism_map,
        }
    }
}

/// The minimal local reimplementation of `olog_spivak_ops::SchemaMorphism`:
/// a schema morphism `F: source → target` with an object map and a morphism
/// map. Exposed so callers can see the induced functor; [`check_translation`]
/// does not require constructing one (it scans the rubrics directly).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaMorphism {
    /// `F`'s domain schema.
    pub source: Schema,
    /// `F`'s codomain schema.
    pub target: Schema,
    /// `source.object → target.object`.
    pub object_map: BTreeMap<String, String>,
    /// `source.morphism → target.morphism`.
    pub morphism_map: BTreeMap<String, String>,
}

// ─── Misalignment: the specific reject cases ─────────────────────────────────

/// Why a proposed translation is **not** a valid honesty-preserving functor.
/// Each variant is a distinct, decidable failure; [`check_translation`] returns
/// the **first** one it encounters in a canonical scan order, so the result is
/// deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Misalignment {
    /// A criterion of `A` has no entry in the object map — the map is not total
    /// on objects, so it is not even a function on the source schema. (Mirrors
    /// `compose_morphisms` returning `None` on an unmapped source object.)
    UnmappedCriterion {
        /// The `A`-criterion id with no image.
        a_id: String,
    },
    /// The object map sends an `A`-criterion to a name that is not a criterion
    /// of `B` (a dangling target — endpoint does not land in the codomain).
    TargetCriterionMissing {
        /// The `A`-criterion id.
        a_id: String,
        /// The claimed `B`-criterion id, which does not exist in `B`.
        b_id: String,
    },
    /// The induced grade arrow `grade_of:{a_id} ↦ grade_of:{b_id}` does not
    /// respect endpoints: the source/target objects of the `A` arrow do not map
    /// onto the source/target of the `B` arrow. (This is the
    /// endpoint-mismatch reject of `compose_morphisms`, specialised. With the
    /// `Artifact ↦ Artifact` convention this fires only if the object map and
    /// the criterion endpoint disagree — a defensive, structural check.)
    ArrowEndpointMismatch {
        /// The `A`-criterion id whose grade arrow is ill-mapped.
        a_id: String,
        /// The mapped `B`-criterion id.
        b_id: String,
    },
    /// The honesty axis is violated: an `A`-criterion's [`Provenance`] kind does
    /// not match its image's. Mapping a `RecomputeVerified` criterion onto a
    /// non-RV one (or vice versa) would move *load-bearing-ness* across the
    /// translation, so a verified column could inherit an unverifiable signal's
    /// rank authority (or the reverse). This is the eval-relevant agreement the
    /// gate exists to enforce.
    ProvenanceKindMismatch {
        /// The `A`-criterion id.
        a_id: String,
        /// `A`'s provenance on that criterion.
        a_provenance: Provenance,
        /// The mapped `B`-criterion id.
        b_id: String,
        /// `B`'s provenance on the image criterion.
        b_provenance: Provenance,
    },
    /// The image criterion's `max_grade` is **smaller** than the source's, so a
    /// legal `A`-grade could exceed `B`'s ceiling — a grade migrated under this
    /// map could be out of range, breaking `validate_all` on the `B` side. The
    /// documented compatibility rule is: `b.max_grade >= a.max_grade` (the image
    /// axis must be at least as wide; widening is fine, narrowing is not).
    MaxGradeNarrowed {
        /// The `A`-criterion id.
        a_id: String,
        /// `A`'s `max_grade`.
        a_max_grade: u32,
        /// The mapped `B`-criterion id.
        b_id: String,
        /// `B`'s `max_grade` (the offending narrower ceiling).
        b_max_grade: u32,
    },
    /// Two distinct `A`-criteria map to the **same** `B`-criterion. A functor
    /// *may* be non-injective in general, but for a rubric *grade* translation
    /// collapsing two load-bearing axes onto one silently changes the weighted
    /// total's structure (two RV columns would migrate into one). We reject
    /// collisions to keep the translation grade-faithful (see the round-trip in
    /// [`migrate_b_grades_into_a`], which needs the map to be a usable lookup).
    NonInjectiveCollision {
        /// The first `A`-criterion id mapping to `b_id`.
        first_a_id: String,
        /// The second `A`-criterion id mapping to the same `b_id`.
        second_a_id: String,
        /// The shared `B`-criterion id.
        b_id: String,
    },
}

impl std::fmt::Display for Misalignment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Misalignment::UnmappedCriterion { a_id } => {
                write!(f, "criterion {a_id} of A has no image in the translation map")
            }
            Misalignment::TargetCriterionMissing { a_id, b_id } => write!(
                f,
                "criterion {a_id} of A maps to {b_id}, which is not a criterion of B"
            ),
            Misalignment::ArrowEndpointMismatch { a_id, b_id } => write!(
                f,
                "grade arrow of {a_id} does not respect endpoints when mapped to {b_id}"
            ),
            Misalignment::ProvenanceKindMismatch {
                a_id,
                a_provenance,
                b_id,
                b_provenance,
            } => write!(
                f,
                "honesty axis violated: {a_id} ({a_provenance:?}) maps to {b_id} ({b_provenance:?}) — provenance kind must match"
            ),
            Misalignment::MaxGradeNarrowed {
                a_id,
                a_max_grade,
                b_id,
                b_max_grade,
            } => write!(
                f,
                "max_grade narrowed: {a_id} (max {a_max_grade}) maps to {b_id} (max {b_max_grade}); B's ceiling must be >= A's"
            ),
            Misalignment::NonInjectiveCollision {
                first_a_id,
                second_a_id,
                b_id,
            } => write!(
                f,
                "non-injective: both {first_a_id} and {second_a_id} of A map to {b_id} of B"
            ),
        }
    }
}

impl std::error::Error for Misalignment {}

// ─── check_translation: the decidable functor gate ───────────────────────────

/// Decidably validate that `mapping` is a well-defined, honesty-preserving
/// functor `schema(a) → schema(b)`. Returns `Ok(())` if so, else the **first**
/// [`Misalignment`] in this canonical scan order:
///
/// 1. **Totality on objects** — every criterion of `A` has an image
///    ([`Misalignment::UnmappedCriterion`]).
/// 2. **Targets land in B** — each image is an actual `B`-criterion
///    ([`Misalignment::TargetCriterionMissing`]).
/// 3. **Injectivity** — no two `A`-criteria collide on one `B`-criterion
///    ([`Misalignment::NonInjectiveCollision`]).
/// 4. **Arrow endpoints respected** — the grade arrow of `a_id` maps onto the
///    grade arrow of its image, endpoints commuting with the object map
///    ([`Misalignment::ArrowEndpointMismatch`]); always holds under the
///    `Artifact ↦ Artifact` convention but checked structurally.
/// 5. **Honesty axis** — provenance kind matches
///    ([`Misalignment::ProvenanceKindMismatch`]).
/// 6. **Grade-axis compatibility** — `b.max_grade >= a.max_grade`
///    ([`Misalignment::MaxGradeNarrowed`]).
///
/// Each check is a finite lookup over the two (finite) rubrics, so the whole
/// gate is decidable — the finitely-presented, equation-free fragment the
/// module docs call out as the decidable boundary.
///
/// This validates a *given* translation. It does not synthesize one, and it is
/// not a substitute for `Rubric::validate_all` on a single vocabulary.
pub fn check_translation(
    a: &Rubric,
    b: &Rubric,
    mapping: &RubricMapping,
) -> Result<(), Misalignment> {
    let schema_a = rubric_to_schema(a);
    let schema_b = rubric_to_schema(b);

    // B-side lookup: criterion id → its Criterion (for provenance + max_grade).
    let b_index: BTreeMap<&str, &nucleus_rubric::Criterion> =
        b.criteria.iter().map(|c| (c.id.as_str(), c)).collect();

    // (3) injectivity bookkeeping: B-criterion id → first A-criterion that hit it.
    let mut seen_targets: BTreeMap<&str, &str> = BTreeMap::new();

    for a_crit in &a.criteria {
        let a_id = a_crit.id.as_str();

        // (1) totality on objects.
        let b_id = match mapping.object_map.get(a_id) {
            Some(b_id) => b_id.as_str(),
            None => {
                return Err(Misalignment::UnmappedCriterion {
                    a_id: a_id.to_string(),
                });
            }
        };

        // (2) target lands in B.
        let b_crit = match b_index.get(b_id) {
            Some(entry) => *entry,
            None => {
                return Err(Misalignment::TargetCriterionMissing {
                    a_id: a_id.to_string(),
                    b_id: b_id.to_string(),
                });
            }
        };

        // (3) injectivity.
        if let Some(prev_a) = seen_targets.insert(b_id, a_id) {
            return Err(Misalignment::NonInjectiveCollision {
                first_a_id: prev_a.to_string(),
                second_a_id: a_id.to_string(),
                b_id: b_id.to_string(),
            });
        }

        // (4) arrow endpoints respected. The grade arrow of a_id is
        //     grade_of:{a_id}: a_id → Artifact; its image must be
        //     grade_of:{b_id}: b_id → Artifact, AND the object map must carry
        //     a_id → b_id (src) and Artifact → Artifact (tgt). We re-derive the
        //     A arrow's endpoints from schema_a and the B arrow's from schema_b
        //     and confirm they commute with the (object_map ∪ Artifact↦Artifact)
        //     map. This is the compose_morphisms endpoint check, specialised.
        let a_arrow = grade_arrow_name(a_id);
        let b_arrow = grade_arrow_name(b_id);
        let (a_src, a_tgt) = schema_a
            .morphism_endpoints(&a_arrow)
            .expect("rubric_to_schema emits a grade arrow per criterion");
        let (b_src, b_tgt) = match schema_b.morphism_endpoints(&b_arrow) {
            Some(ep) => ep,
            None => {
                // The B grade arrow is absent — only possible if b_id is not a
                // real B-criterion, already caught by (2). Defensive.
                return Err(Misalignment::ArrowEndpointMismatch {
                    a_id: a_id.to_string(),
                    b_id: b_id.to_string(),
                });
            }
        };
        // Object map applied to A's endpoints (Artifact ↦ Artifact convention).
        let mapped_src = if a_src == ARTIFACT_OBJECT {
            ARTIFACT_OBJECT
        } else {
            mapping
                .object_map
                .get(a_src)
                .map(|s| s.as_str())
                .unwrap_or("")
        };
        let mapped_tgt = if a_tgt == ARTIFACT_OBJECT {
            ARTIFACT_OBJECT
        } else {
            mapping
                .object_map
                .get(a_tgt)
                .map(|s| s.as_str())
                .unwrap_or("")
        };
        if mapped_src != b_src || mapped_tgt != b_tgt {
            return Err(Misalignment::ArrowEndpointMismatch {
                a_id: a_id.to_string(),
                b_id: b_id.to_string(),
            });
        }

        // (5) honesty axis: provenance kind must match exactly.
        if a_crit.provenance != b_crit.provenance {
            return Err(Misalignment::ProvenanceKindMismatch {
                a_id: a_id.to_string(),
                a_provenance: a_crit.provenance,
                b_id: b_id.to_string(),
                b_provenance: b_crit.provenance,
            });
        }

        // (6) grade-axis compatibility: B's ceiling must be >= A's.
        if b_crit.max_grade < a_crit.max_grade {
            return Err(Misalignment::MaxGradeNarrowed {
                a_id: a_id.to_string(),
                a_max_grade: a_crit.max_grade,
                b_id: b_id.to_string(),
                b_max_grade: b_crit.max_grade,
            });
        }
    }

    Ok(())
}

// ─── Round-trip: migrate B-scored grades into A's vocabulary ─────────────────

/// Errors from migrating a `B`-scorecard into `A`'s vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationError {
    /// The translation is not a valid functor — migration is only defined for a
    /// `check_translation`-approved map.
    Invalid(Misalignment),
    /// The supplied `B`-scorecard's grade count does not match `B`'s criteria.
    BScorecardShapeMismatch {
        /// Expected (== `B.criteria.len()`).
        expected: usize,
        /// Actual grade count.
        got: usize,
    },
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationError::Invalid(m) => write!(f, "invalid translation: {m}"),
            MigrationError::BScorecardShapeMismatch { expected, got } => {
                write!(f, "B-scorecard has {got} grades, expected {expected} for B")
            }
        }
    }
}

impl std::error::Error for MigrationError {}

/// Migrate a `B`-vocabulary [`Scorecard`] into `A`'s vocabulary along an
/// approved `mapping` (`A → B`). For each `A`-criterion `c`, look up its image
/// `map(c)` in `B`, find that `B`-criterion's positional grade in `b_sc`, and
/// place it at `c`'s position in the produced `A`-scorecard.
///
/// This is the **round-trip** the prompt asks for: it lets a score recorded in
/// one vocabulary be read in the other, and — because the gate guarantees
/// `b.max_grade >= a.max_grade` is the only allowed direction — a grade migrated
/// from `B` into `A` may *exceed* `A`'s ceiling (a wide `B`-axis value placed in
/// a narrow `A`-axis). The function therefore returns the migrated scorecard
/// **and** the caller is expected to run `a.validate_all(&[migrated])` to
/// confirm the migration is in range; the accompanying test does exactly that
/// for an equal-ceiling map (where it always holds).
///
/// Returns [`MigrationError::Invalid`] if the map is not a valid functor.
pub fn migrate_b_grades_into_a(
    a: &Rubric,
    b: &Rubric,
    mapping: &RubricMapping,
    b_sc: &Scorecard,
) -> Result<Scorecard, MigrationError> {
    check_translation(a, b, mapping).map_err(MigrationError::Invalid)?;
    if b_sc.grades.len() != b.criteria.len() {
        return Err(MigrationError::BScorecardShapeMismatch {
            expected: b.criteria.len(),
            got: b_sc.grades.len(),
        });
    }
    // B-criterion id → its positional index in b_sc.grades.
    let b_pos: BTreeMap<&str, usize> = b
        .criteria
        .iter()
        .enumerate()
        .map(|(i, c)| (c.id.as_str(), i))
        .collect();

    let mut grades = Vec::with_capacity(a.criteria.len());
    for a_crit in &a.criteria {
        // check_translation already proved these lookups succeed.
        let b_id = mapping
            .object_map
            .get(a_crit.id.as_str())
            .expect("check_translation proved totality");
        let pos = *b_pos
            .get(b_id.as_str())
            .expect("check_translation proved target exists");
        grades.push(b_sc.grades[pos]);
    }
    Ok(Scorecard {
        artifact_id: b_sc.artifact_id.clone(),
        grades,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_rubric::Criterion;

    fn crit(id: &str, p: Provenance, w: u32, max: u32) -> Criterion {
        Criterion {
            id: id.into(),
            provenance: p,
            weight: w,
            max_grade: max,
        }
    }

    /// A: {correctness(RV,10), coverage(RV,10), cost(Attested,10)}.
    fn rubric_a() -> Rubric {
        Rubric::new(vec![
            crit("correctness", Provenance::RecomputeVerified, 5, 10),
            crit("coverage", Provenance::RecomputeVerified, 3, 10),
            crit("cost", Provenance::Attested, 7, 10),
        ])
        .unwrap()
    }

    /// B: a renamed-but-aligned vocabulary, ceilings >= A's.
    fn rubric_b() -> Rubric {
        Rubric::new(vec![
            crit("accuracy", Provenance::RecomputeVerified, 4, 10),
            crit("tests", Provenance::RecomputeVerified, 6, 10),
            crit("spend", Provenance::Attested, 2, 10),
        ])
        .unwrap()
    }

    fn good_map() -> RubricMapping {
        RubricMapping::new([
            ("correctness", "accuracy"),
            ("coverage", "tests"),
            ("cost", "spend"),
        ])
    }

    // ── rubric_to_schema shape ────────────────────────────────────────────────

    #[test]
    fn schema_has_artifact_object_and_grade_arrows() {
        let s = rubric_to_schema(&rubric_a());
        assert!(s.has_object("correctness"));
        assert!(s.has_object(ARTIFACT_OBJECT));
        assert_eq!(s.objects.len(), 4); // 3 criteria + Artifact
                                        // grade_of:correctness : correctness → Artifact
        assert_eq!(
            s.morphism_endpoints("grade_of:correctness"),
            Some(("correctness", ARTIFACT_OBJECT))
        );
        assert_eq!(s.morphisms.len(), 3);
    }

    // ── accept path ───────────────────────────────────────────────────────────

    #[test]
    fn valid_translation_accepts() {
        assert_eq!(
            check_translation(&rubric_a(), &rubric_b(), &good_map()),
            Ok(())
        );
    }

    #[test]
    fn widening_max_grade_is_allowed() {
        // B ceilings strictly wider than A — allowed (widening, not narrowing).
        let b = Rubric::new(vec![
            crit("accuracy", Provenance::RecomputeVerified, 4, 100),
            crit("tests", Provenance::RecomputeVerified, 6, 100),
            crit("spend", Provenance::Attested, 2, 100),
        ])
        .unwrap();
        assert_eq!(check_translation(&rubric_a(), &b, &good_map()), Ok(()));
    }

    // ── reject path: one test per Misalignment variant ────────────────────────

    #[test]
    fn rejects_unmapped_criterion() {
        let m = RubricMapping::new([("correctness", "accuracy"), ("coverage", "tests")]);
        assert_eq!(
            check_translation(&rubric_a(), &rubric_b(), &m),
            Err(Misalignment::UnmappedCriterion {
                a_id: "cost".into()
            })
        );
    }

    #[test]
    fn rejects_target_criterion_missing() {
        let m = RubricMapping::new([
            ("correctness", "accuracy"),
            ("coverage", "tests"),
            ("cost", "nonexistent"),
        ]);
        assert_eq!(
            check_translation(&rubric_a(), &rubric_b(), &m),
            Err(Misalignment::TargetCriterionMissing {
                a_id: "cost".into(),
                b_id: "nonexistent".into(),
            })
        );
    }

    #[test]
    fn rejects_non_injective_collision() {
        let m = RubricMapping::new([
            ("correctness", "accuracy"),
            ("coverage", "accuracy"), // collision
            ("cost", "spend"),
        ]);
        match check_translation(&rubric_a(), &rubric_b(), &m) {
            Err(Misalignment::NonInjectiveCollision { b_id, .. }) => {
                assert_eq!(b_id, "accuracy");
            }
            other => panic!("expected collision, got {other:?}"),
        }
    }

    #[test]
    fn rejects_provenance_kind_mismatch() {
        // Map the RV `correctness` onto B's Attested `spend` — moves
        // load-bearing-ness. Build a B where the target is non-RV.
        let m = RubricMapping::new([
            ("correctness", "spend"), // RV → Attested: REJECT
            ("coverage", "tests"),
            ("cost", "accuracy"), // Attested → RV (also wrong, but correctness fires first)
        ]);
        match check_translation(&rubric_a(), &rubric_b(), &m) {
            Err(Misalignment::ProvenanceKindMismatch {
                a_id,
                a_provenance,
                b_provenance,
                ..
            }) => {
                assert_eq!(a_id, "correctness");
                assert_eq!(a_provenance, Provenance::RecomputeVerified);
                assert_eq!(b_provenance, Provenance::Attested);
            }
            other => panic!("expected provenance mismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_max_grade_narrowed() {
        // B's `accuracy` ceiling 5 < A's `correctness` ceiling 10.
        let b = Rubric::new(vec![
            crit("accuracy", Provenance::RecomputeVerified, 4, 5),
            crit("tests", Provenance::RecomputeVerified, 6, 10),
            crit("spend", Provenance::Attested, 2, 10),
        ])
        .unwrap();
        assert_eq!(
            check_translation(&rubric_a(), &b, &good_map()),
            Err(Misalignment::MaxGradeNarrowed {
                a_id: "correctness".into(),
                a_max_grade: 10,
                b_id: "accuracy".into(),
                b_max_grade: 5,
            })
        );
    }

    // ── round-trip migration ──────────────────────────────────────────────────

    #[test]
    fn migrate_then_validate_all_holds() {
        let a = rubric_a();
        let b = rubric_b();
        let m = good_map();
        // B-scored: accuracy=8, tests=7, spend=3.
        let b_sc = Scorecard {
            artifact_id: "artifact-1".into(),
            grades: vec![8, 7, 3],
        };
        let migrated = migrate_b_grades_into_a(&a, &b, &m, &b_sc).unwrap();
        // A order is correctness, coverage, cost ← accuracy, tests, spend.
        assert_eq!(migrated.grades, vec![8, 7, 3]);
        assert_eq!(migrated.artifact_id, "artifact-1");
        // The migrated A-scorecard passes A's own validation (ceilings equal).
        assert!(a.validate_all(&[migrated]).is_ok());
    }

    #[test]
    fn migrate_rejects_invalid_map() {
        let a = rubric_a();
        let b = rubric_b();
        let bad = RubricMapping::new([("correctness", "accuracy"), ("coverage", "tests")]);
        let b_sc = Scorecard {
            artifact_id: "x".into(),
            grades: vec![1, 2, 3],
        };
        assert!(matches!(
            migrate_b_grades_into_a(&a, &b, &bad, &b_sc),
            Err(MigrationError::Invalid(
                Misalignment::UnmappedCriterion { .. }
            ))
        ));
    }

    #[test]
    fn migrate_rejects_b_scorecard_shape() {
        let a = rubric_a();
        let b = rubric_b();
        let m = good_map();
        let b_sc = Scorecard {
            artifact_id: "x".into(),
            grades: vec![1, 2], // wrong length for B
        };
        assert_eq!(
            migrate_b_grades_into_a(&a, &b, &m, &b_sc),
            Err(MigrationError::BScorecardShapeMismatch {
                expected: 3,
                got: 2,
            })
        );
    }

    // ── induced schema morphism ───────────────────────────────────────────────

    #[test]
    fn induced_schema_morphism_carries_artifact_and_grade_arrows() {
        let sm = good_map().induced_schema_morphism(&rubric_a(), &rubric_b());
        assert_eq!(
            sm.object_map.get(ARTIFACT_OBJECT).map(|s| s.as_str()),
            Some(ARTIFACT_OBJECT)
        );
        assert_eq!(
            sm.object_map.get("correctness").map(|s| s.as_str()),
            Some("accuracy")
        );
        assert_eq!(
            sm.morphism_map
                .get("grade_of:correctness")
                .map(|s| s.as_str()),
            Some("grade_of:accuracy")
        );
    }

    // ── identity translation A → A is always valid ────────────────────────────

    #[test]
    fn serde_round_trips_mapping_and_misalignment() {
        let m = good_map();
        let m2: RubricMapping = serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(m, m2);

        let err = Misalignment::UnmappedCriterion {
            a_id: "cost".into(),
        };
        let err2: Misalignment =
            serde_json::from_str(&serde_json::to_string(&err).unwrap()).unwrap();
        assert_eq!(err, err2);

        let s = rubric_to_schema(&rubric_a());
        let s2: Schema = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn identity_translation_is_valid() {
        let a = rubric_a();
        let id = RubricMapping::new(a.criteria.iter().map(|c| (c.id.clone(), c.id.clone())));
        assert_eq!(check_translation(&a, &a, &id), Ok(()));
    }
}
