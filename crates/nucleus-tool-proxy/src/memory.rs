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
    let ifc = memory_ifc_label(&effective_label, now);
    flow.observe_with_label(NodeKind::MemoryRead, ifc, &[])
        .map_err(|e| ApiError::IfcDenied(format!("flow observe failed: {e}")))?;

    Ok(MemoryRecallResp {
        value: record.value,
        label: effective_label,
        declassified,
    })
}
