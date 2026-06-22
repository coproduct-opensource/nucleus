//! Generic recompute-verification, decoupled from any specific kernel.
//!
//! This is the differentiator over MemLineage / Portable Agent Memory: we do not
//! merely check that a record's *hash* matches, we re-derive its **label** (via
//! the taint-propagation rule [`derive_label`]) and, for deterministic
//! derivations, its very **value** (via a [`RecomputeMemory`] transform), and
//! admit only on a [`RecomputeVerdict::Match`]. A planted "summary" that does not
//! actually follow from its cited sources is rejected — the MINJA/MemoryGraft
//! seam. Non-deterministic LLM steps are not recomputable and are instead
//! quarantined by the label rule (`Adversarial` / `AIDerived`).

use std::collections::BTreeMap;

use nucleus_lineage::SourceClass;
use portcullis_core::memory::MemoryLabel;
use portcullis_core::{ConfLevel, DerivationClass, IntegLevel};
use serde::{Deserialize, Serialize};

use crate::record::{MemoryDerivation, MemoryRecord, TransformId};

/// Outcome of re-deriving a record from its sources — same discipline as
/// `nucleus_recompute::RecomputeOutcome`, kept local so this crate stays
/// decoupled from the economic kernels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "verdict")]
pub enum RecomputeVerdict {
    /// The record's label (and, for deterministic derivations, its value)
    /// re-derive exactly from its cited sources.
    Match,
    /// A re-derived field diverges from what the record claims.
    Mismatch {
        /// Which field diverged (`"label"` or `"value"`).
        field: String,
        /// What the record claimed.
        claimed: String,
        /// What re-derivation actually produced.
        recomputed: String,
    },
    /// The derivation is not well-formed (missing parent, unknown transform,
    /// transform error) — the claim cannot stand.
    Invalid {
        /// Human-readable reason the derivation could not be verified.
        reason: String,
    },
}

impl RecomputeVerdict {
    /// Whether this verdict admits the record (only [`RecomputeVerdict::Match`]).
    pub fn is_match(&self) -> bool {
        matches!(self, RecomputeVerdict::Match)
    }
}

/// A deterministic transform: a pure function from cited source records to the
/// value it should produce. Boxed so transforms can be registered dynamically.
pub type TransformFn = Box<dyn Fn(&[&MemoryRecord]) -> Result<String, String> + Send + Sync>;

/// A registry of deterministic transforms. The only recomputable derivation
/// class names a transform here; re-running it over the cited source records
/// must reproduce the stored value.
#[derive(Default)]
pub struct TransformRegistry {
    transforms: BTreeMap<TransformId, TransformFn>,
}

impl TransformRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a deterministic transform under `id`. It must be a pure function
    /// of its inputs (same inputs ⇒ same output) for recompute to be meaningful.
    pub fn register(
        &mut self,
        id: TransformId,
        f: impl Fn(&[&MemoryRecord]) -> Result<String, String> + Send + Sync + 'static,
    ) {
        self.transforms.insert(id, Box::new(f));
    }

    /// Whether a transform is registered.
    pub fn contains(&self, id: &TransformId) -> bool {
        self.transforms.contains_key(id)
    }
}

/// The transform interface the admission gate calls. Implemented by
/// [`TransformRegistry`]; callers may provide their own.
pub trait RecomputeMemory {
    /// Re-derive the value `transform` should produce from `inputs`. Errors if
    /// the transform is unknown or fails.
    fn recompute(
        &self,
        transform: &TransformId,
        inputs: &[&MemoryRecord],
    ) -> Result<String, String>;
}

impl RecomputeMemory for TransformRegistry {
    fn recompute(
        &self,
        transform: &TransformId,
        inputs: &[&MemoryRecord],
    ) -> Result<String, String> {
        match self.transforms.get(transform) {
            Some(f) => f(inputs),
            None => Err(format!("unknown transform {:?}", transform.0)),
        }
    }
}

/// Confidentiality flows UP: a derived value is at least as confidential as its
/// most-confidential source (join / max).
pub(crate) fn conf_join(a: ConfLevel, b: ConfLevel) -> ConfLevel {
    if (a as u8) >= (b as u8) {
        a
    } else {
        b
    }
}

/// Integrity flows DOWN: a derived value is at most as trusted as its
/// least-trusted source (meet / min).
pub(crate) fn integ_meet(a: IntegLevel, b: IntegLevel) -> IntegLevel {
    if (a as u8) <= (b as u8) {
        a
    } else {
        b
    }
}

/// Trust class of a raw-ingested source ⇒ integrity level. Untrusted-content
/// sources (web, RAG index, prior memory) are **adversarial** by default — the
/// lethal-trifecta "untrusted content" leg.
fn ingest_integrity(sc: SourceClass) -> IntegLevel {
    match sc {
        SourceClass::LocalFile => IntegLevel::Untrusted,
        SourceClass::Web | SourceClass::RagIndex | SourceClass::Memory => IntegLevel::Adversarial,
    }
}

/// **The taint-propagation rule.** Deterministically re-derive the label a record
/// MUST carry, given its derivation and its (already-admitted) parent records.
/// This is recomputed on admission and the record's claimed label must equal it
/// — so a record cannot smuggle in a more-trusting label than its lineage earns.
pub fn derive_label(derivation: &MemoryDerivation, parents: &[&MemoryRecord]) -> MemoryLabel {
    match derivation {
        // Raw ingest: integrity fixed by the source class; not yet derived, so
        // its derivation class is OpaqueExternal (came from outside the kernel).
        MemoryDerivation::RawIngest { source_class, .. } => {
            MemoryLabel::from_levels_with_derivation(
                ConfLevel::Public,
                ingest_integrity(*source_class),
                DerivationClass::OpaqueExternal,
            )
        }
        // Deterministic derivation: conf = max(parents), integ = min(parents),
        // derivation class = Deterministic joined with every parent's class
        // (so an AIDerived/OpaqueExternal ancestor is never laundered away —
        // "promotion does not cleanse").
        MemoryDerivation::Deterministic { .. } => {
            let mut conf = ConfLevel::Public;
            let mut integ = IntegLevel::Trusted;
            let mut deriv = DerivationClass::Deterministic;
            for p in parents {
                conf = conf_join(conf, p.label.conf_level());
                integ = integ_meet(integ, p.label.integ_level());
                deriv = deriv.join(p.label.derivation);
            }
            MemoryLabel::from_levels_with_derivation(conf, integ, deriv)
        }
        // Opaque LLM output: NOT recomputable. Adversarial by default (could be
        // injected) ⇒ MayNotAuthorize, AIDerived joined with the context lineage.
        MemoryDerivation::OpaqueLlm { .. } => {
            let mut conf = ConfLevel::Public;
            let mut deriv = DerivationClass::AIDerived;
            for p in parents {
                conf = conf_join(conf, p.label.conf_level());
                deriv = deriv.join(p.label.derivation);
            }
            MemoryLabel::from_levels_with_derivation(conf, IntegLevel::Adversarial, deriv)
        }
    }
}

/// Re-derive `record` from its `parents` and return the admission verdict.
///
/// - **Label** is always re-derived ([`derive_label`]); a claimed label that
///   exceeds what the lineage earns ⇒ `Mismatch{field:"label"}`.
/// - **Deterministic** records additionally have their **value** recomputed via
///   `registry`; a value that does not follow from the sources ⇒
///   `Mismatch{field:"value"}` (the MINJA/MemoryGraft seam). Missing parents or
///   unknown/failing transform ⇒ `Invalid`.
/// - **RawIngest / OpaqueLlm** have no recomputable value; the label check is the
///   gate (OpaqueLlm is thereby pinned `Adversarial`/`AIDerived`).
pub fn verify_admission(
    record: &MemoryRecord,
    parents: &[&MemoryRecord],
    registry: &dyn RecomputeMemory,
) -> RecomputeVerdict {
    let expected = derive_label(&record.derivation, parents);
    if record.label != expected {
        return RecomputeVerdict::Mismatch {
            field: "label".to_string(),
            claimed: format!("{:?}", record.label),
            recomputed: format!("{expected:?}"),
        };
    }

    if let MemoryDerivation::Deterministic {
        transform,
        input_hashes,
    } = &record.derivation
    {
        // Every cited input must be present among the supplied parents.
        if parents.len() != input_hashes.len() {
            return RecomputeVerdict::Invalid {
                reason: format!(
                    "deterministic derivation cites {} inputs but {} parents supplied",
                    input_hashes.len(),
                    parents.len()
                ),
            };
        }
        match registry.recompute(transform, parents) {
            Ok(recomputed_value) => {
                if recomputed_value != record.value {
                    return RecomputeVerdict::Mismatch {
                        field: "value".to_string(),
                        claimed: record.value.clone(),
                        recomputed: recomputed_value,
                    };
                }
            }
            Err(e) => return RecomputeVerdict::Invalid { reason: e },
        }
    }

    RecomputeVerdict::Match
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::ContentHash;
    use portcullis_core::memory::SchemaType;

    fn raw(value: &str, sc: SourceClass) -> MemoryRecord {
        let deriv = MemoryDerivation::RawIngest {
            source_class: sc,
            source_hash: ContentHash::of_canonical_bytes(value.as_bytes()),
        };
        let label = derive_label(&deriv, &[]);
        MemoryRecord::new(value, SchemaType::String, label, deriv)
    }

    fn concat_registry() -> TransformRegistry {
        let mut r = TransformRegistry::new();
        r.register(TransformId::new("concat"), |inputs| {
            Ok(inputs
                .iter()
                .map(|i| i.value.as_str())
                .collect::<Vec<_>>()
                .join(""))
        });
        r
    }

    #[test]
    fn raw_web_is_adversarial_opaque() {
        let r = raw("evil", SourceClass::Web);
        assert_eq!(r.label.integ_level(), IntegLevel::Adversarial);
        assert_eq!(r.label.derivation, DerivationClass::OpaqueExternal);
        assert!(verify_admission(&r, &[], &concat_registry()).is_match());
    }

    #[test]
    fn raw_localfile_is_untrusted() {
        let r = raw("cfg", SourceClass::LocalFile);
        assert_eq!(r.label.integ_level(), IntegLevel::Untrusted);
    }

    #[test]
    fn deterministic_value_recomputes() {
        let a = raw("foo", SourceClass::LocalFile);
        let b = raw("bar", SourceClass::LocalFile);
        let deriv = MemoryDerivation::Deterministic {
            input_hashes: vec![a.content_hash(), b.content_hash()],
            transform: TransformId::new("concat"),
        };
        let label = derive_label(&deriv, &[&a, &b]);
        let rec = MemoryRecord::new("foobar", SchemaType::String, label, deriv);
        assert!(verify_admission(&rec, &[&a, &b], &concat_registry()).is_match());
    }

    #[test]
    fn deterministic_forged_value_is_rejected() {
        // MINJA/MemoryGraft seam: a "summary" that does not follow from sources.
        let a = raw("foo", SourceClass::LocalFile);
        let b = raw("bar", SourceClass::LocalFile);
        let deriv = MemoryDerivation::Deterministic {
            input_hashes: vec![a.content_hash(), b.content_hash()],
            transform: TransformId::new("concat"),
        };
        let label = derive_label(&deriv, &[&a, &b]);
        let forged = MemoryRecord::new("attacker-payload", SchemaType::String, label, deriv);
        match verify_admission(&forged, &[&a, &b], &concat_registry()) {
            RecomputeVerdict::Mismatch { field, .. } => assert_eq!(field, "value"),
            other => panic!("expected value mismatch, got {other:?}"),
        }
    }

    #[test]
    fn integrity_floors_to_worst_parent() {
        // Deterministic over a trusted file + an adversarial web source ⇒ adversarial.
        let trusted = raw("ok", SourceClass::LocalFile);
        let evil = raw("evil", SourceClass::Web);
        let deriv = MemoryDerivation::Deterministic {
            input_hashes: vec![trusted.content_hash(), evil.content_hash()],
            transform: TransformId::new("concat"),
        };
        let label = derive_label(&deriv, &[&trusted, &evil]);
        assert_eq!(label.integ_level(), IntegLevel::Adversarial);
    }

    #[test]
    fn claimed_label_exceeding_lineage_is_rejected() {
        // Claim Trusted integrity over an adversarial web ingest.
        let deriv = MemoryDerivation::RawIngest {
            source_class: SourceClass::Web,
            source_hash: ContentHash::of_canonical_bytes(b"x"),
        };
        let liar = MemoryRecord::new(
            "x",
            SchemaType::String,
            MemoryLabel::from_levels_with_derivation(
                ConfLevel::Public,
                IntegLevel::Trusted,
                DerivationClass::Deterministic,
            ),
            deriv,
        );
        match verify_admission(&liar, &[], &concat_registry()) {
            RecomputeVerdict::Mismatch { field, .. } => assert_eq!(field, "label"),
            other => panic!("expected label mismatch, got {other:?}"),
        }
    }

    #[test]
    fn opaque_llm_is_quarantined() {
        let ctx = raw("context", SourceClass::LocalFile);
        let deriv = MemoryDerivation::OpaqueLlm {
            input_hashes: vec![ctx.content_hash()],
            model_tag: "some-model".to_string(),
        };
        let label = derive_label(&deriv, &[&ctx]);
        let rec = MemoryRecord::new("llm output", SchemaType::String, label, deriv);
        assert_eq!(rec.label.integ_level(), IntegLevel::Adversarial);
        // join with the OpaqueExternal parent keeps it tainted (never Deterministic).
        assert_ne!(rec.label.derivation, DerivationClass::Deterministic);
        assert_eq!(
            rec.authority(),
            portcullis_core::memory::MemoryAuthority::MayNotAuthorize
        );
        assert!(verify_admission(&rec, &[&ctx], &concat_registry()).is_match());
    }
}
