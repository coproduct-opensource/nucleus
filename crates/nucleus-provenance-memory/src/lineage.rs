//! Memory → lineage edge emitter.
//!
//! Wires the documented-but-previously-unwired binding: every memory write/recall
//! emits a `nucleus_lineage::EdgeKind::DocumentRetrieved` edge with
//! `source_class: SourceClass::Memory`, pinning exactly which record was used so a
//! later poisoning can be traced to this access (the blind spot AgentPoison/eTAMP
//! exploit). The edge's `content_hash_hex` is the record's [`ContentHash`].

use chrono::Utc;
use nucleus_lineage::{CallSpiffeId, EdgeKind, IdError, LineageEdge, SourceClass};

use crate::record::MemoryRecord;

/// Emit a lineage edge attributing a memory recall/write of `record` to the
/// session pod `pod`. The derived child identity is content-addressed by the
/// record's canonical bytes, and the edge carries the record's content hash so
/// the lineage DAG can later be queried for "which records fed this action".
pub fn memory_lineage_edge(
    record: &MemoryRecord,
    pod: &CallSpiffeId,
) -> Result<LineageEdge, IdError> {
    let bytes = record.canonical_bytes();
    let child = pod.derive_artifact(&bytes)?;
    let hash_hex = record.content_hash().to_hex();
    let kind = EdgeKind::DocumentRetrieved {
        source_url: format!("memory://{hash_hex}"),
        content_hash: hash_hex.clone(),
        retrieval_ts: Utc::now(),
        source_class: SourceClass::Memory,
    };
    let mut edge = LineageEdge::from_parent(child, pod.clone(), kind);
    edge.content_hash_hex = Some(hash_hex);
    Ok(edge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::ContentHash;
    use crate::recompute::derive_label;
    use crate::record::MemoryDerivation;
    use portcullis_core::memory::SchemaType;

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap()
    }

    fn rec() -> MemoryRecord {
        let d = MemoryDerivation::RawIngest {
            source_class: SourceClass::Web,
            source_hash: ContentHash::of_canonical_bytes(b"doc"),
        };
        MemoryRecord::new("recalled", SchemaType::String, derive_label(&d, &[]), d)
    }

    #[test]
    fn emits_memory_source_class_edge_with_content_hash() {
        let r = rec();
        let edge = memory_lineage_edge(&r, &pod()).unwrap();
        assert_eq!(
            edge.content_hash_hex.as_deref(),
            Some(r.content_hash().to_hex().as_str())
        );
        match edge.kind {
            EdgeKind::DocumentRetrieved {
                source_class,
                content_hash,
                source_url,
                ..
            } => {
                assert_eq!(source_class, SourceClass::Memory);
                assert_eq!(content_hash, r.content_hash().to_hex());
                assert!(source_url.starts_with("memory://"));
            }
            other => panic!("expected DocumentRetrieved, got {other:?}"),
        }
        assert_eq!(edge.parents.len(), 1);
    }

    #[test]
    fn distinct_records_get_distinct_children() {
        let p = pod();
        let e1 = memory_lineage_edge(&rec(), &p).unwrap();
        let d = MemoryDerivation::RawIngest {
            source_class: SourceClass::Web,
            source_hash: ContentHash::of_canonical_bytes(b"other"),
        };
        let r2 = MemoryRecord::new("different", SchemaType::String, derive_label(&d, &[]), d);
        let e2 = memory_lineage_edge(&r2, &p).unwrap();
        assert_ne!(e1.child, e2.child);
    }
}
