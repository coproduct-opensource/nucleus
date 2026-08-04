//! Live memory surface for the tool-proxy (most-paranoid next-bet #1).
//!
//! Two endpoints make `nucleus-provenance-memory`'s poisoning defense actually
//! run in the shipped proxy (it previously existed only as a tested library):
//!
//! - **write** → [`ProvenanceMemorySet::verified_admit`]: a record is admitted
//!   only if it recompute-verifies from its cited sources; a forged label is
//!   rejected, and an honest-but-poisoned web record is admitted-but-quarantined
//!   (`Adversarial` / `MayNotAuthorize`).
//! - **recall** → projects the record's (possibly [`declassify`]-promoted) label
//!   into the live [`FlowTracker`] via `observe_with_label`. An un-declassified
//!   adversarial record taints the session, so the *next* privileged tool call is
//!   denied by the existing IFC egress gate. A `declassify`-promoted record
//!   (k-of-n signed witness) is not tainting and may inform an action.
//!
//! The handlers are thin: memory ops touch only the in-process
//! [`ProvenanceMemorySet`] + the flow tracker — no filesystem sandbox, approval,
//! or verdict-sink machinery (those are for file/exec tools). The security logic
//! lives in the two `*_core` functions so it is unit-testable without a full
//! `AppState`.

use nucleus::portcullis::{FlowTracker, NodeKind};
use nucleus_provenance_memory::{
    declassify, memory_ifc_label, ContentHash, MemoryDerivation, MemoryLabel, MemoryRecord,
    ProvenanceMemorySet, RecomputeMemory, RecomputeVerdict, SchemaType, SignedDeclassify,
};
use serde::{Deserialize, Serialize};

use crate::ApiError;

/// Parse `NUCLEUS_DECLASSIFY_TRUSTED_KEYS` — a comma-separated list of 64-char
/// hex Ed25519 verifying keys — into 32-byte arrays. Malformed entries are
/// skipped (fail-closed: a bad key simply can't cosign). `None`/empty ⇒ no
/// trusted keys ⇒ every declassification fails closed.
pub fn parse_trusted_keys_env(raw: Option<&str>) -> Vec<[u8; 32]> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            let bytes = hex::decode(s).ok()?;
            <[u8; 32]>::try_from(bytes.as_slice()).ok()
        })
        .collect()
}

/// Persist a memory record (provenance-verified admission).
#[derive(Debug, Deserialize)]
pub struct MemoryWriteReq {
    /// The value to store.
    pub value: String,
    /// Value schema.
    pub schema: SchemaType,
    /// How the value was produced (the recompute claim).
    pub derivation: MemoryDerivation,
    /// The claimed IFC label (validated against the recomputed label on admit).
    pub label: MemoryLabel,
}

/// Result of a memory write.
#[derive(Debug, Serialize)]
pub struct MemoryWriteResp {
    /// Content address of the record.
    pub content_hash: String,
    /// Whether it was admitted to the set (`true` iff the verdict is `Match`).
    pub admitted: bool,
    /// The full recompute verdict (so a caller sees *why* it was rejected).
    pub verdict: RecomputeVerdict,
}

/// Recall a stored record, optionally presenting a declassification witness.
#[derive(Debug, Deserialize)]
pub struct MemoryRecallReq {
    /// Content address of the record to recall.
    pub content_hash: String,
    /// Optional signed declassification (k-of-n witness). Absent ⇒ the record is
    /// recalled with its stored (possibly adversarial) label.
    pub declassify: Option<SignedDeclassify>,
}

/// Result of a memory recall.
#[derive(Debug, Serialize)]
pub struct MemoryRecallResp {
    /// The recalled value.
    pub value: String,
    /// The effective label observed into the flow tracker (declassified if a
    /// valid witness was supplied, else the stored label).
    pub label: MemoryLabel,
    /// Whether a declassification witness was accepted.
    pub declassified: bool,
}

/// Core write logic: admit `req` into `set` via the recompute gate. Pure over
/// borrowed state so it is unit-testable without an `AppState`.
pub fn memory_write_core(
    set: &mut ProvenanceMemorySet,
    registry: &dyn RecomputeMemory,
    req: MemoryWriteReq,
) -> MemoryWriteResp {
    let record = MemoryRecord::new(req.value, req.schema, req.label, req.derivation);
    let content_hash = record.content_hash().to_hex();
    let verdict = set.verified_admit(&record, registry);
    MemoryWriteResp {
        content_hash,
        admitted: verdict.is_match(),
        verdict,
    }
}

/// Core recall logic: resolve the record, apply any declassification, and
/// observe the effective label into `flow` so the live IFC gate governs the next
/// action. Fail-closed: a declassify failure denies (and observes nothing).
pub fn memory_recall_core(
    set: &ProvenanceMemorySet,
    flow: &mut FlowTracker,
    trusted_keys: &[[u8; 32]],
    threshold: usize,
    now: u64,
    req: MemoryRecallReq,
) -> Result<MemoryRecallResp, ApiError> {
    let hash = ContentHash::from_hex(&req.content_hash)
        .map_err(|e| ApiError::Body(format!("bad content_hash: {e}")))?;
    let record = set
        .get(&hash)
        .cloned()
        .ok_or_else(|| ApiError::Body("memory record not found".to_string()))?;

    let (effective_label, declassified) = match &req.declassify {
        Some(signed) => {
            // Fail-closed: an un-quorumed / invalid witness informs NOTHING.
            let promoted = declassify(&record, signed, trusted_keys, threshold)
                .map_err(|e| ApiError::IfcDenied(format!("declassify refused: {e}")))?;
            (promoted, true)
        }
        None => (record.label.clone(), false),
    };

    // Observe with the record's OWN (possibly promoted) label — never the fixed
    // intrinsic memory label, which would launder an adversarial record.
    //
    // Brick 3: content-address the *actual recalled bytes* (`record.value`),
    // recomputed here from the real record — NEVER the agent-supplied
    // `req.content_hash` lookup key, which is only used to locate the record and
    // must not be trusted as the ingested content's digest.
    let ifc = memory_ifc_label(&effective_label, now);
    let content_hash = crate::ingest_content_hash(record.value.as_bytes());
    flow.observe_with_label_and_content_hash(NodeKind::MemoryRead, ifc, &[], content_hash)
        .map_err(|e| ApiError::IfcDenied(format!("flow observe failed: {e}")))?;

    Ok(MemoryRecallResp {
        value: record.value,
        label: effective_label,
        declassified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_provenance_memory::{recompute::derive_label, SourceClass, TransformRegistry};
    use sha2::{Digest, Sha256};

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }

    /// Build an admitted (honest-but-poisoned web) record carrying `value`.
    fn admit_record(set: &mut ProvenanceMemorySet, value: &str) -> MemoryRecord {
        let d = MemoryDerivation::RawIngest {
            source_class: SourceClass::Web,
            source_hash: ContentHash::of_canonical_bytes(value.as_bytes()),
        };
        let label = derive_label(&d, &[]);
        let rec = MemoryRecord::new(value, SchemaType::String, label, d);
        assert!(
            set.verified_admit(&rec, &TransformRegistry::new())
                .is_match(),
            "honest web record must be admitted"
        );
        rec
    }

    /// (a) A recalled record produces a MemoryRead node whose content hash equals
    /// the SHA-256 of the exact recalled bytes (`record.value`) — recomputed from
    /// the real record, NOT the agent-supplied `req.content_hash` lookup key.
    #[test]
    fn recall_content_addresses_the_recalled_bytes() {
        let mut set = ProvenanceMemorySet::new();
        let rec = admit_record(&mut set, "the recalled value bytes");
        let req = MemoryRecallReq {
            content_hash: rec.content_hash().to_hex(),
            declassify: None,
        };

        let mut flow = FlowTracker::new();
        let resp = memory_recall_core(&set, &mut flow, &[], 0, 0, req).unwrap();

        // Node 1 is the MemoryRead we just observed.
        let node_hash = flow
            .content_hash(1)
            .expect("MemoryRead node carries a hash");
        assert_eq!(
            node_hash.as_bytes(),
            &sha256(resp.value.as_bytes()),
            "node hash must equal SHA-256 of the exact recalled bytes"
        );
        // And it is NOT the agent-supplied lookup key's digest.
        assert_ne!(
            node_hash.as_bytes(),
            rec.content_hash().as_bytes(),
            "the ingest hash is over the value bytes, not the record address"
        );
    }

    /// (b) Non-forgeable: two records with different values recall to different
    /// node hashes — poisoned content cannot collide with benign content.
    #[test]
    fn recall_hash_is_non_forgeable() {
        let mut set = ProvenanceMemorySet::new();
        let a = admit_record(&mut set, "benign value");
        let b = admit_record(&mut set, "benign value.");

        let mut flow = FlowTracker::new();
        memory_recall_core(
            &set,
            &mut flow,
            &[],
            0,
            0,
            MemoryRecallReq {
                content_hash: a.content_hash().to_hex(),
                declassify: None,
            },
        )
        .unwrap();
        memory_recall_core(
            &set,
            &mut flow,
            &[],
            0,
            0,
            MemoryRecallReq {
                content_hash: b.content_hash().to_hex(),
                declassify: None,
            },
        )
        .unwrap();

        assert_ne!(
            flow.content_hash(1),
            flow.content_hash(2),
            "distinct recalled bytes must produce distinct node hashes"
        );
    }

    /// (c) Label/taint behaviour is unchanged: the hashed recall yields the exact
    /// same node label as the pre-brick `observe_with_label` path — the record's
    /// OWN (adversarial) label is preserved, never laundered.
    #[test]
    fn recall_hash_does_not_change_label_or_taint() {
        let mut set = ProvenanceMemorySet::new();
        let rec = admit_record(&mut set, "poisoned note");
        let req = MemoryRecallReq {
            content_hash: rec.content_hash().to_hex(),
            declassify: None,
        };

        // New hashed path.
        let mut flow_new = FlowTracker::new();
        memory_recall_core(&set, &mut flow_new, &[], 0, 0, req).unwrap();

        // Old label-only path (what the site did before brick 3).
        let mut flow_old = FlowTracker::new();
        flow_old
            .observe_with_label(NodeKind::MemoryRead, memory_ifc_label(&rec.label, 0), &[])
            .unwrap();

        assert_eq!(
            flow_new.label(1),
            flow_old.label(1),
            "label must be identical to the pre-hash path"
        );
        assert_eq!(flow_new.is_tainted(), flow_old.is_tainted());
        assert!(flow_new.is_tainted(), "adversarial record still taints");
        // The only difference is the added hash.
        assert!(flow_new.content_hash(1).is_some());
        assert_eq!(flow_old.content_hash(1), None);
    }
}
