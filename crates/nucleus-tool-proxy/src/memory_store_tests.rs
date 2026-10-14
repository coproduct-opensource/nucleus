use super::*;
use nucleus_ifc_kernel::{Operation, SinkClass, discharge::test_helpers::bundle_for_subject};
use nucleus_provenance_memory::{
    MemoryDerivation, SchemaType, SourceClass, TransformRegistry, recompute::derive_label,
};
use portcullis_effects::receipt::ReceiptLog;
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

fn configured(dir: &std::path::Path) -> MemoryStoreArgs {
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    MemoryStoreArgs {
        memory_store: Some(dir.join("memory.jsonl")),
        memory_namespace: Some("project-a".into()),
    }
}
/// Children at a uid that owns nothing here: the reach every store test that
/// is not about the reach opens under.
fn separated() -> ChildReach {
    ChildReach::for_test(vec![nucleus::ChildUid::Distinct(
        nucleus::runtime_uid().wrapping_add(1),
    )])
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
        .open(workspace.path(), &TransformRegistry::new(), &separated())
        .unwrap();
    let prepared = prepare(&mut store, "ordinary project note");
    let reply = prepared.commit(&TransformRegistry::new()).unwrap();
    let hash = ContentHash::from_hex(&reply.content_hash).unwrap();
    let expected = store.records().unwrap().get(&hash).unwrap().clone();
    let size = std::fs::metadata(args.memory_store.as_ref().unwrap())
        .unwrap()
        .len();
    let duplicate = prepare(&mut store, "ordinary project note");
    duplicate.commit(&TransformRegistry::new()).unwrap();
    assert_eq!(
        std::fs::metadata(args.memory_store.as_ref().unwrap())
            .unwrap()
            .len(),
        size
    );
    assert!(
        args.open(workspace.path(), &TransformRegistry::new(), &separated())
            .is_err()
    );
    drop(store);
    let reopened = args
        .open(workspace.path(), &TransformRegistry::new(), &separated())
        .unwrap();
    assert_eq!(reopened.records().unwrap().get(&hash), Some(&expected));
    drop(reopened);
    let foreign = MemoryStoreArgs {
        memory_store: args.memory_store.clone(),
        memory_namespace: Some("project-b".into()),
    };
    assert!(
        foreign
            .open(workspace.path(), &TransformRegistry::new(), &separated())
            .is_err()
    );
}

#[tokio::test]
async fn restart_replays_parent_before_derived_record() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let args = configured(dir.path());
    let registry = TransformRegistry::new();
    let mut store = args
        .open(workspace.path(), &registry, &separated())
        .unwrap();
    let prepared = prepare(&mut store, "project source note");
    let first = prepared.commit(&TransformRegistry::new()).unwrap();
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
    let second = prepared.commit(&TransformRegistry::new()).unwrap();
    let hash = ContentHash::from_hex(&second.content_hash).unwrap();
    let expected = store.records().unwrap().get(&hash).unwrap().clone();
    drop(store);
    let reopened = args
        .open(workspace.path(), &registry, &separated())
        .unwrap();
    assert_eq!(reopened.records().unwrap().get(&hash), Some(&expected));
    assert!(reopened.records().unwrap().contains(&parent_hash));
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
        args.open(workspace.path(), &TransformRegistry::new(), &separated())
            .unwrap(),
    );
    let path = args.memory_store.as_ref().unwrap();
    let file = OpenOptions::new().write(true).open(path).unwrap();
    file.set_len(file.metadata().unwrap().len() - 1).unwrap();
    assert!(
        args.open(workspace.path(), &TransformRegistry::new(), &separated())
            .is_err()
    );
    assert!(
        configured(workspace.path())
            .open(workspace.path(), &TransformRegistry::new(), &separated())
            .is_err()
    );
}

/// #3454: the one decider of "can a child reach the journal", over every
/// `ChildUid` and owner relation. A bare-tier child is refused whatever owns
/// the journal; a separated child is refused exactly when it owns the part.
#[test]
fn a_journal_a_child_could_reach_is_refused_by_name() {
    let owner = 4242;
    let reach = |children| ChildReach::for_test(children);
    assert!(reach(vec![]).excludes("file", owner).is_ok());
    assert!(
        reach(vec![nucleus::ChildUid::Distinct(owner + 1)])
            .excludes("directory", owner)
            .is_ok()
    );
    for children in [
        vec![nucleus::ChildUid::SharedWithRuntime],
        vec![
            nucleus::ChildUid::Distinct(owner + 1),
            nucleus::ChildUid::SharedWithRuntime,
        ],
    ] {
        let refused = reach(children).excludes("file", owner).unwrap_err();
        assert!(refused.contains("bare host tier"), "{refused}");
    }
    for what in ["directory", "file"] {
        let refused = reach(vec![
            nucleus::ChildUid::Distinct(owner + 1),
            nucleus::ChildUid::Distinct(owner),
        ])
        .excludes(what, owner)
        .unwrap_err();
        assert!(
            refused.contains(&format!("journal's {what} is owned by uid {owner}")),
            "{refused}"
        );
    }
}

/// #3454: `open` asks the reach about the directory before it creates
/// anything, and about the opened file. Driven through the real open, so the
/// two calls are proved to be there, not only the decider.
#[test]
fn open_refuses_a_journal_whose_directory_or_file_a_child_owns() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let args = configured(dir.path());
    let me = nucleus::ChildUid::Distinct(nucleus::runtime_uid());
    let refused = args
        .open(
            workspace.path(),
            &TransformRegistry::new(),
            &ChildReach::for_test(vec![me]),
        )
        .err()
        .expect("a child owning the directory is refused");
    assert!(
        refused.to_string().contains("journal's directory"),
        "{refused}"
    );
    assert!(
        !args.memory_store.as_ref().unwrap().exists(),
        "refused before the journal was created"
    );
    let bare = ChildReach::for_test(vec![nucleus::ChildUid::SharedWithRuntime]);
    let refused = args
        .open(workspace.path(), &TransformRegistry::new(), &bare)
        .err()
        .expect("a bare-tier child is refused");
    assert!(refused.to_string().contains("bare host tier"), "{refused}");
}

/// Admit and spawn `spec` as the proxy does a workload, under the harness's
/// declared bare tier, and return its stdout.
#[cfg(target_os = "linux")]
async fn run_probe(spec: nucleus_spec::WorkloadSpec, work_dir: &std::path::Path) -> String {
    let plan =
        crate::workload::WorkloadLaunch::build(&spec, "http://127.0.0.1:8080", work_dir, &[])
            .admit(HARNESS, OPTED_IN, NO_WAIVER)
            .expect("the harness admits its probe");
    let (child, _) = crate::workload::spawn_admitted(
        plan,
        nucleus::RlimitPolicy::node_ceiling().at_ceiling(),
        portcullis::SeccompPolicy::derive(
            &portcullis::PermissionLattice::permissive(),
            portcullis::NetworkEgress::Declared,
        ),
    )
    .unwrap();
    let out = child.wait_with_output().await.unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The harness's posture, as the workload tests declare it: the bare host
/// tier, opted in, no Landlock waiver.
#[cfg(target_os = "linux")]
const HARNESS: nucleus::ContainmentMode = nucleus::ContainmentMode::Unsandboxed;
#[cfg(target_os = "linux")]
const OPTED_IN: nucleus::UnsandboxedOptIn = nucleus::UnsandboxedOptIn::Explicit;
#[cfg(target_os = "linux")]
const NO_WAIVER: nucleus::LandlockWaiver = nucleus::LandlockWaiver::Absent;

/// **#3454, on a real spawn.** A workload admitted the way the proxy admits
/// one (`WorkloadLaunch::admit` then `spawn_admitted`, under the harness's
/// declared bare tier) tries to read the open journal and append to it.
/// Either the proxy refused to open the journal for the reach the same
/// deciders report, or the child can do neither.
///
/// Red with the reach check removed from `open`, as a non-root runtime: the
/// journal opened, and the bare-tier child printed its header and appended a
/// line. A root runtime's child drops to 65534 and the `0700` directory keeps
/// it out. Linux only: the harness spawn is.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_workload_child_cannot_read_or_append_the_journal() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let args = configured(dir.path());
    let journal = args.memory_store.clone().unwrap();
    let probe = |target: &std::path::Path| nucleus_spec::WorkloadSpec {
        command: "/bin/sh".into(),
        artifacts: Default::default(),
        args: vec![
            "-c".into(),
            format!(
                "cat '{0}' && echo READ; printf 'forged\\n' >> '{0}' && echo APPENDED; true",
                target.display()
            ),
        ],
        uid: None,
        env: Default::default(),
    };
    let spec = probe(&journal);
    let reach = ChildReach::of(Some(&spec), HARNESS, OPTED_IN, NO_WAIVER);
    match args.open(workspace.path(), &TransformRegistry::new(), &reach) {
        Ok(store) => {
            let before = std::fs::read(&journal).unwrap();
            let seen = run_probe(spec, workspace.path()).await;
            assert!(
                !seen.contains("READ") && !seen.contains("nucleus.memory-journal"),
                "child read: {seen}"
            );
            assert!(!seen.contains("APPENDED"), "child appended: {seen}");
            assert_eq!(std::fs::read(&journal).unwrap(), before);
            drop(store);
        }
        Err(refused) => {
            assert!(refused.to_string().contains("bare host tier"), "{refused}");
            assert!(!journal.exists(), "refused before the journal was created");
            // Positive control: the refusal is not vacuous. This child could
            // have read and appended a journal the proxy holds open.
            std::fs::write(&journal, b"{\"schema\":\"stand-in\"}\n").unwrap();
            std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
            let seen = run_probe(probe(&journal), workspace.path()).await;
            assert!(seen.contains("READ") && seen.contains("APPENDED"), "{seen}");
        }
    }
}

#[test]
fn each_live_write_is_one_commit_on_the_head_and_a_v1_journal_is_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let args = configured(dir.path());
    let path = args.memory_store.clone().unwrap();
    // A journal a v1 proxy wrote: header, then one record per line.
    let v1 = request("written by a v1 proxy");
    let record =
        nucleus_provenance_memory::MemoryRecord::new(v1.value, v1.schema, v1.label, v1.derivation);
    let mut bytes =
        b"{\"schema\":\"nucleus.memory-journal.v1\",\"namespace\":\"project-a\"}\n".to_vec();
    bytes.extend(serde_json::to_vec(&record).unwrap());
    bytes.push(b'\n');
    std::fs::write(&path, &bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut store = args
        .open(workspace.path(), &TransformRegistry::new(), &separated())
        .unwrap();
    assert!(store.records().unwrap().contains(&record.content_hash()));
    for value in ["first live note", "second live note", "second live note"] {
        prepare(&mut store, value)
            .commit(&TransformRegistry::new())
            .unwrap();
    }
    drop(store);
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].contains("\"nucleus.memory-journal.v2\""));
    let versions: Vec<u64> = lines[1..]
        .iter()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["version"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(
        versions,
        vec![1, 2, 3],
        "migration, then one commit per distinct write"
    );
    let reopened = args
        .open(workspace.path(), &TransformRegistry::new(), &separated())
        .unwrap();
    assert_eq!(reopened.records().unwrap().len(), 3);
}
