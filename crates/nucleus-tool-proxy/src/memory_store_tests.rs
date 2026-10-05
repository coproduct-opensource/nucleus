use super::*;
use nucleus_ifc_kernel::{Operation, SinkClass, discharge::test_helpers::bundle_for_subject};
use nucleus_provenance_memory::{
    MemoryDerivation, SchemaType, SourceClass, TransformRegistry, recompute::derive_label,
};
use portcullis_effects::receipt::ReceiptLog;
use std::sync::Arc;

fn configured(dir: &std::path::Path) -> MemoryStoreArgs {
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    MemoryStoreArgs {
        memory_store: Some(dir.join("memory.jsonl")),
        memory_namespace: Some("project-a".into()),
    }
}
fn request(value: &str) -> MemoryWriteReq {
    let derivation = MemoryDerivation::RawIngest {
        source_class: SourceClass::Web,
        source_hash: ContentHash::of_canonical_bytes(value.as_bytes()),
    };
    MemoryWriteReq {
        value: value.into(),
        schema: SchemaType::String,
        label: derive_label(&derivation, &[]),
        derivation,
    }
}
fn prepare<'a>(store: &'a mut Store, value: &str) -> PreparedWrite<'a> {
    prepare_request(store, request(value))
}
fn prepare_request(store: &mut Store, req: MemoryWriteReq) -> PreparedWrite<'_> {
    let authority = Authority::new(bundle_for_subject(
        Operation::WriteFiles,
        SinkClass::MemoryPersist,
        &crate::memory::write_subject(&req),
    ))
    .witnessed_by(Arc::new(ReceiptLog::new()));
    store
        .prepare(&TransformRegistry::new(), req, authority)
        .unwrap()
}

#[tokio::test]
async fn restart_retains_records_labels_and_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let args = configured(dir.path());
    let mut store = args
        .open(workspace.path(), &TransformRegistry::new())
        .unwrap();
    let prepared = prepare(&mut store, "ordinary project note");
    let reply = prepared.commit().await.unwrap();
    let hash = ContentHash::from_hex(&reply.content_hash).unwrap();
    let expected = store.records().unwrap().get(&hash).unwrap().clone();
    let size = std::fs::metadata(args.memory_store.as_ref().unwrap())
        .unwrap()
        .len();
    let duplicate = prepare(&mut store, "ordinary project note");
    duplicate.commit().await.unwrap();
    assert_eq!(
        std::fs::metadata(args.memory_store.as_ref().unwrap())
            .unwrap()
            .len(),
        size
    );
    assert!(
        args.open(workspace.path(), &TransformRegistry::new())
            .is_err()
    );
    drop(store);
    let reopened = args
        .open(workspace.path(), &TransformRegistry::new())
        .unwrap();
    assert_eq!(reopened.records().unwrap().get(&hash), Some(&expected));
    drop(reopened);
    let foreign = MemoryStoreArgs {
        memory_store: args.memory_store.clone(),
        memory_namespace: Some("project-b".into()),
    };
    assert!(
        foreign
            .open(workspace.path(), &TransformRegistry::new())
            .is_err()
    );
}

#[tokio::test]
async fn restart_replays_parent_before_derived_record() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let args = configured(dir.path());
    let registry = TransformRegistry::new();
    let mut store = args.open(workspace.path(), &registry).unwrap();
    let prepared = prepare(&mut store, "project source note");
    let first = prepared.commit().await.unwrap();
    let parent_hash = ContentHash::from_hex(&first.content_hash).unwrap();
    let parent = store.records().unwrap().get(&parent_hash).unwrap();
    let derivation = MemoryDerivation::OpaqueLlm {
        input_hashes: vec![parent_hash],
        model_tag: "fixture-model".into(),
    };
    let req = MemoryWriteReq {
        value: "project summary".into(),
        schema: SchemaType::String,
        label: derive_label(&derivation, &[parent]),
        derivation,
    };
    let prepared = prepare_request(&mut store, req);
    let second = prepared.commit().await.unwrap();
    let hash = ContentHash::from_hex(&second.content_hash).unwrap();
    let expected = store.records().unwrap().get(&hash).unwrap().clone();
    drop(store);
    let reopened = args.open(workspace.path(), &registry).unwrap();
    assert_eq!(reopened.records().unwrap().get(&hash), Some(&expected));
    assert!(reopened.records().unwrap().contains(&parent_hash));
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "ordinary I/O failure fixture replaces only its temporary journal handle"
)]
async fn uncertain_write_latches_reads_and_writes_without_publishing_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let args = configured(dir.path());
    let mut store = args
        .open(workspace.path(), &TransformRegistry::new())
        .unwrap();
    if let Journal::Persistent { file, .. } = &mut store.journal {
        *file = tokio::fs::File::from_std(
            std::fs::File::open(args.memory_store.as_ref().unwrap()).unwrap(),
        );
    } else {
        panic!("persistent journal required");
    }
    let prepared = prepare(&mut store, "a note");
    assert!(prepared.commit().await.is_err());
    assert!(store.records().is_err());
    assert!(store.set.is_empty());
    let req = request("another note");
    let authority = Authority::new(bundle_for_subject(
        Operation::WriteFiles,
        SinkClass::MemoryPersist,
        &crate::memory::write_subject(&req),
    ))
    .witnessed_by(Arc::new(ReceiptLog::new()));
    assert!(
        store
            .prepare(&TransformRegistry::new(), req, authority)
            .is_err()
    );
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "recovery fixture truncates only its temporary journal"
)]
async fn incomplete_journal_refuses_restart_and_workspace_storage_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let args = configured(dir.path());
    drop(
        args.open(workspace.path(), &TransformRegistry::new())
            .unwrap(),
    );
    let path = args.memory_store.as_ref().unwrap();
    let file = OpenOptions::new().write(true).open(path).unwrap();
    file.set_len(file.metadata().unwrap().len() - 1).unwrap();
    assert!(
        args.open(workspace.path(), &TransformRegistry::new())
            .is_err()
    );
    assert!(
        configured(workspace.path())
            .open(workspace.path(), &TransformRegistry::new())
            .is_err()
    );
}
