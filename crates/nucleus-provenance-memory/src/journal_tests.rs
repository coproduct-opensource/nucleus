use super::*;
use crate::overlay::Overlay;
use crate::recompute::{TransformRegistry, derive_label};
use crate::record::MemoryDerivation;
use crate::version::StoreInvariants;
use nucleus_lineage::SourceClass;
use portcullis_core::memory::{MemoryLabel, SchemaType};
use portcullis_core::{ConfLevel, DerivationClass, IntegLevel};
use std::sync::atomic::{AtomicU64, Ordering};

/// A private (0700) scratch directory, removed on drop. Not `tempfile`, so this
/// crate's dependency set is unchanged.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "npm-journal-{}-{nanos}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }

    fn location(&self) -> JournalLocation {
        JournalLocation::new(&self.0.join("memory.jsonl"), "space-a").unwrap()
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Excludes no one.
struct Anyone;

impl ReachCheck for Anyone {
    fn admit(&self, _: JournalPart, _: u32) -> Result<(), String> {
        Ok(())
    }
}

/// Excludes whoever owns `part`.
struct ExcludeOwnerOf(JournalPart);

impl ReachCheck for ExcludeOwnerOf {
    fn admit(&self, part: JournalPart, owner_uid: u32) -> Result<(), String> {
        if part == self.0 {
            return Err(format!(
                "the journal's {part:?} owner {owner_uid} is excluded"
            ));
        }
        Ok(())
    }
}

fn registry() -> TransformRegistry {
    TransformRegistry::new()
}

fn raw(value: &str) -> MemoryRecord {
    let d = MemoryDerivation::RawIngest {
        source_class: SourceClass::Web,
        source_hash: ContentHash::of_canonical_bytes(value.as_bytes()),
    };
    let label = derive_label(&d, &[]);
    MemoryRecord::new(value, SchemaType::String, label, d)
}

fn derived(value: &str, parent: &MemoryRecord) -> MemoryRecord {
    let d = MemoryDerivation::OpaqueLlm {
        input_hashes: vec![parent.content_hash()],
        model_tag: "fixture-model".into(),
    };
    let label = derive_label(&d, &[parent]);
    MemoryRecord::new(value, SchemaType::String, label, d)
}

fn relabelled(record: &MemoryRecord, label: MemoryLabel) -> MemoryRecord {
    let mut out = record.clone();
    out.label = label;
    out
}

fn lowered(record: &MemoryRecord) -> MemoryRecord {
    relabelled(
        record,
        MemoryLabel::from_levels_with_derivation(
            ConfLevel::Public,
            IntegLevel::Trusted,
            DerivationClass::Deterministic,
        ),
    )
}

fn raised(record: &MemoryRecord) -> MemoryRecord {
    relabelled(
        record,
        MemoryLabel::from_levels_with_derivation(
            ConfLevel::Secret,
            record.label.integ_level(),
            record.label.derivation,
        ),
    )
}

fn unbounded() -> StoreInvariants {
    StoreInvariants::new(usize::MAX, MAX_JOURNAL_BYTES)
}

fn publish(
    journal: &mut PublishedJournal,
    patch: &Patch,
    expected: Pin,
) -> Result<Pin, PublishRefusal> {
    journal.publish(
        patch,
        expected,
        PublisherBinding::from_bytes([1; 32]),
        Epoch::new(1),
        &unbounded(),
        &registry(),
    )
}

fn publish_now(journal: &mut PublishedJournal, records: Vec<MemoryRecord>) -> Pin {
    let head = journal.head().unwrap();
    publish(journal, &Patch::new(head, records), head).unwrap()
}

fn v1_bytes(namespace: &str, records: &[MemoryRecord]) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&Header {
        schema: SCHEMA_V1.into(),
        namespace: namespace.into(),
    })
    .unwrap();
    bytes.push(b'\n');
    for r in records {
        bytes.extend(serde_json::to_vec(r).unwrap());
        bytes.push(b'\n');
    }
    bytes
}

fn write_private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn hashes(set: &ProvenanceMemorySet) -> Vec<ContentHash> {
    set.iter().map(MemoryRecord::content_hash).collect()
}

#[test]
fn a_pinned_reader_observes_the_same_records_after_later_commits() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    let mut journal = PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap();
    let v1 = publish_now(&mut journal, vec![raw("a")]);
    let first = PinnedSnapshot::open(&loc, v1, &Anyone, &registry()).unwrap();
    let v2 = publish_now(&mut journal, vec![raw("b")]);
    let again = PinnedSnapshot::open(&loc, v1, &Anyone, &registry()).unwrap();
    assert_eq!(first.records(), again.records());
    assert_eq!(hashes(again.records()), vec![raw("a").content_hash()]);
    assert!(!again.records().contains(&raw("b").content_hash()));
    let later = PinnedSnapshot::open(&loc, v2, &Anyone, &registry()).unwrap();
    assert_eq!(later.records().len(), 2);
    // Version 0 is the empty space.
    let empty = PinnedSnapshot::open(&loc, Pin::genesis("space-a"), &Anyone, &registry()).unwrap();
    assert!(empty.records().is_empty());
}

#[test]
fn a_pinned_reader_refuses_a_pin_the_journal_does_not_hold() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    let mut journal = PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap();
    let v1 = publish_now(&mut journal, vec![raw("a")]);
    let wrong_head = Pin::new(1, Pin::genesis("space-a").head());
    assert!(matches!(
        PinnedSnapshot::open(&loc, wrong_head, &Anyone, &registry()),
        Err(JournalError::PinMismatch { version: 1 })
    ));
    let future = Pin::new(2, v1.head());
    assert!(matches!(
        PinnedSnapshot::open(&loc, future, &Anyone, &registry()),
        Err(JournalError::VersionAbsent {
            requested: 2,
            head: 1
        })
    ));
}

#[test]
fn publish_refuses_a_stale_base_returns_the_head_and_rebases() {
    let scratch = Scratch::new();
    let mut journal = PublishedJournal::open(scratch.location(), &Anyone, &registry()).unwrap();
    let base = journal.head().unwrap();
    let first = Patch::new(base, vec![raw("a")]);
    let second = Patch::new(base, vec![raw("b")]);
    let v1 = publish(&mut journal, &first, base).unwrap();
    let size = std::fs::metadata(scratch.location().path()).unwrap().len();
    let current = match publish(&mut journal, &second, base) {
        Err(PublishRefusal::StaleBase { current }) => current,
        other => panic!("expected a stale base, got {other:?}"),
    };
    assert_eq!(current, v1);
    assert_eq!(
        std::fs::metadata(scratch.location().path()).unwrap().len(),
        size,
        "a refused publish writes nothing"
    );
    // Rebase: the same patch, now expecting the head it was told about.
    let v2 = publish(&mut journal, &second, current).unwrap();
    assert_eq!(v2.version(), 2);
    assert_eq!(journal.records().unwrap().len(), 2);
}

#[test]
fn two_patches_each_under_the_cap_are_refused_together_after_rebase() {
    let scratch = Scratch::new();
    let mut journal = PublishedJournal::open(scratch.location(), &Anyone, &registry()).unwrap();
    let cap = StoreInvariants::new(10, MAX_JOURNAL_BYTES);
    let six = |p: &str| -> Vec<MemoryRecord> { (0..6).map(|i| raw(&format!("{p}{i}"))).collect() };
    let base = journal.head().unwrap();
    let a = Patch::new(base, six("a"));
    let b = Patch::new(base, six("b"));
    let binding = PublisherBinding::from_bytes([1; 32]);
    let v1 = journal
        .publish(&a, base, binding, Epoch::new(1), &cap, &registry())
        .unwrap();
    let current = match journal.publish(&b, base, binding, Epoch::new(1), &cap, &registry()) {
        Err(PublishRefusal::StaleBase { current }) => current,
        other => panic!("expected a stale base, got {other:?}"),
    };
    assert!(matches!(
        journal.publish(&b, current, binding, Epoch::new(1), &cap, &registry()),
        Err(PublishRefusal::Invalid(CandidateRefusal::RecordCap {
            records: 12,
            cap: 10
        }))
    ));
    assert_eq!(journal.head().unwrap(), v1);
    assert_eq!(journal.records().unwrap().len(), 6);
}

#[test]
fn the_byte_cap_counts_the_commit_being_appended() {
    let scratch = Scratch::new();
    let mut journal = PublishedJournal::open(scratch.location(), &Anyone, &registry()).unwrap();
    let size = std::fs::metadata(scratch.location().path()).unwrap().len();
    let cap = StoreInvariants::new(usize::MAX, size + 10);
    let head = journal.head().unwrap();
    let refused = journal.publish(
        &Patch::new(head, vec![raw("a")]),
        head,
        PublisherBinding::from_bytes([1; 32]),
        Epoch::new(1),
        &cap,
        &registry(),
    );
    assert!(matches!(
        refused,
        Err(PublishRefusal::Invalid(CandidateRefusal::ByteCap { .. }))
    ));
    assert_eq!(journal.head().unwrap(), head);
}

#[test]
fn a_label_never_lowers_across_commits() {
    let scratch = Scratch::new();
    let mut journal = PublishedJournal::open(scratch.location(), &Anyone, &registry()).unwrap();
    let v1 = publish_now(&mut journal, vec![raw("a")]);
    let refused = publish(&mut journal, &Patch::new(v1, vec![lowered(&raw("a"))]), v1);
    assert!(matches!(
        refused,
        Err(PublishRefusal::Invalid(CandidateRefusal::LabelLowered { hash })) if hash == raw("a").content_hash()
    ));
    assert_eq!(journal.head().unwrap(), v1);
    assert_eq!(
        journal.records().unwrap().get(&raw("a").content_hash()),
        Some(&raw("a"))
    );
}

#[test]
fn a_concurrent_key_conflicts_and_a_resolution_is_still_replayed() {
    let scratch = Scratch::new();
    let mut journal = PublishedJournal::open(scratch.location(), &Anyone, &registry()).unwrap();
    let base = journal.head().unwrap();
    let v1 = publish(&mut journal, &Patch::new(base, vec![raw("a")]), base).unwrap();
    let rival = Patch::new(base, vec![raised(&raw("a"))]);
    let hash = raw("a").content_hash();
    assert!(matches!(
        publish(&mut journal, &rival, v1),
        Err(PublishRefusal::Invalid(CandidateRefusal::KeyedConflict { hash: h })) if h == hash
    ));
    // Resolving the key passes the validator; the label still has to re-derive
    // from provenance, and a hand-raised one does not.
    assert!(matches!(
        publish(&mut journal, &rival.resolve(hash), v1),
        Err(PublishRefusal::Provenance { hash: h, .. }) if h == hash
    ));
    assert_eq!(journal.head().unwrap(), v1);
}

#[test]
fn publish_refuses_a_base_from_another_history_and_an_empty_patch() {
    let scratch = Scratch::new();
    let mut journal = PublishedJournal::open(scratch.location(), &Anyone, &registry()).unwrap();
    let v1 = publish_now(&mut journal, vec![raw("a")]);
    let foreign = Pin::genesis("space-b");
    assert!(matches!(
        publish(&mut journal, &Patch::new(foreign, vec![raw("b")]), v1),
        Err(PublishRefusal::ForeignBase { .. })
    ));
    assert!(matches!(
        publish(&mut journal, &Patch::new(v1, vec![raw("a")]), v1),
        Err(PublishRefusal::NothingToPublish)
    ));
}

#[test]
fn commits_survive_reopen_and_only_one_writer_holds_the_journal() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    let mut journal = PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap();
    let a = raw("a");
    publish_now(&mut journal, vec![a.clone()]);
    let v2 = publish_now(&mut journal, vec![derived("summary", &a)]);
    assert!(matches!(
        PublishedJournal::open(loc.clone(), &Anyone, &registry()),
        Err(JournalError::Locked)
    ));
    let expected = journal.records().unwrap().clone();
    drop(journal);
    let reopened = PublishedJournal::open(loc, &Anyone, &registry()).unwrap();
    assert_eq!(reopened.head().unwrap(), v2);
    assert_eq!(reopened.records().unwrap(), &expected);
}

#[test]
fn a_tampered_chain_is_refused_on_reopen() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    let mut journal = PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap();
    publish_now(&mut journal, vec![raw("a")]);
    let v2 = publish_now(&mut journal, vec![raw("b")]);
    drop(journal);
    let good = std::fs::read(loc.path()).unwrap();
    let text = String::from_utf8(good.clone()).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3);
    let swapped = format!("{}\n{}\n{}\n", lines[0], lines[2], lines[1]);
    let dropped_first = format!("{}\n{}\n", lines[0], lines[2]);
    let edited_value = text.replace("\"value\":\"b\"", "\"value\":\"c\"");
    assert_ne!(edited_value, text);
    for tampered in [swapped, dropped_first, edited_value] {
        write_private(loc.path(), tampered.as_bytes());
        assert!(
            matches!(
                PublishedJournal::open(loc.clone(), &Anyone, &registry()),
                Err(JournalError::Chain { .. })
            ),
            "tampered journal must be refused"
        );
    }
    // Removing the last commit leaves a valid prefix; only a holder of the pin
    // can tell, and the pinned reader does.
    let truncated = format!("{}\n{}\n", lines[0], lines[1]);
    write_private(loc.path(), truncated.as_bytes());
    assert!(matches!(
        PinnedSnapshot::open(&loc, v2, &Anyone, &registry()),
        Err(JournalError::VersionAbsent { .. })
    ));
    write_private(loc.path(), &good);
    assert_eq!(
        PublishedJournal::open(loc, &Anyone, &registry())
            .unwrap()
            .head()
            .unwrap(),
        v2
    );
}

#[test]
fn an_unknown_schema_is_refused_by_name() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    write_private(
        loc.path(),
        b"{\"schema\":\"nucleus.memory-journal.v9\",\"namespace\":\"space-a\"}\n",
    );
    match PublishedJournal::open(loc.clone(), &Anyone, &registry()) {
        Err(JournalError::UnknownSchema(name)) => assert_eq!(name, "nucleus.memory-journal.v9"),
        other => panic!("expected an unknown schema, got {:?}", other.err()),
    }
    write_private(
        loc.path(),
        b"{\"schema\":\"nucleus.memory-journal.v2\",\"namespace\":\"space-a\",\"extra\":1}\n",
    );
    assert!(matches!(
        PublishedJournal::open(loc.clone(), &Anyone, &registry()),
        Err(JournalError::InvalidHeader)
    ));
    write_private(
        loc.path(),
        b"{\"schema\":\"nucleus.memory-journal.v2\",\"namespace\":\"space-b\"}\n",
    );
    assert!(matches!(
        PublishedJournal::open(loc, &Anyone, &registry()),
        Err(JournalError::NamespaceDiffers)
    ));
}

#[test]
fn a_v1_journal_migrates_to_one_commit_and_reopening_is_a_no_op() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    let a = raw("a");
    let records = vec![a.clone(), derived("summary", &a), raw("b")];
    write_private(loc.path(), &v1_bytes("space-a", &records));
    let journal = PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap();
    let head = journal.head().unwrap();
    assert_eq!(head.version(), 1);
    let expected = journal.records().unwrap().clone();
    assert_eq!(expected.len(), 3);
    drop(journal);
    let migrated = std::fs::read(loc.path()).unwrap();
    let text = String::from_utf8(migrated.clone()).unwrap();
    assert!(text.starts_with("{\"schema\":\"nucleus.memory-journal.v2\""));
    assert_eq!(text.lines().count(), 2, "header and one commit");
    let commit: Commit = serde_json::from_str(text.lines().nth(1).unwrap()).unwrap();
    assert_eq!(commit.records(), records.as_slice(), "admission order kept");
    assert_eq!(commit.publisher(), PublisherBinding::v1_migration());
    assert!(!loc.staging_path().exists());
    let mode = std::fs::metadata(loc.path()).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    // Idempotent: reopening a v2 journal rewrites nothing.
    let reopened = PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap();
    assert_eq!(reopened.head().unwrap(), head);
    assert_eq!(reopened.records().unwrap(), &expected);
    drop(reopened);
    assert_eq!(std::fs::read(loc.path()).unwrap(), migrated);
}

#[test]
fn an_empty_v1_journal_migrates_to_version_zero() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    write_private(loc.path(), &v1_bytes("space-a", &[]));
    let journal = PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap();
    assert_eq!(journal.head().unwrap(), Pin::genesis("space-a"));
    drop(journal);
    assert_eq!(
        std::fs::read_to_string(loc.path()).unwrap().lines().count(),
        1
    );
}

#[test]
fn a_migration_interrupted_at_any_step_leaves_v1_or_complete_v2() {
    let a = raw("a");
    let records = vec![a.clone(), derived("summary", &a)];
    for step in MigrationStep::ALL {
        let scratch = Scratch::new();
        let loc = scratch.location();
        let original = v1_bytes("space-a", &records);
        write_private(loc.path(), &original);
        let mut fault = |at: MigrationStep| {
            if at == step {
                Err(std::io::Error::other("injected crash"))
            } else {
                Ok(())
            }
        };
        assert!(
            PublishedJournal::open_with(loc.clone(), &Anyone, &registry(), &mut fault).is_err(),
            "the injected fault at {step:?} must surface"
        );
        let after = std::fs::read(loc.path()).unwrap();
        let renamed = matches!(step, MigrationStep::Renamed | MigrationStep::ParentSynced);
        if renamed {
            assert!(
                after.starts_with(b"{\"schema\":\"nucleus.memory-journal.v2\""),
                "{step:?}: the journal is the complete v2 file"
            );
        } else {
            assert_eq!(
                after, original,
                "{step:?}: the journal is still v1, untouched"
            );
        }
        // Recovery is an ordinary open, and its result is the same either way.
        let journal = PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap();
        assert_eq!(journal.head().unwrap().version(), 1, "{step:?}");
        let mut expected = ProvenanceMemorySet::new();
        for r in &records {
            assert!(expected.verified_admit(r, &registry()).is_match());
        }
        assert_eq!(journal.records().unwrap(), &expected, "{step:?}");
        assert!(
            !loc.staging_path().exists(),
            "{step:?}: no staging file left"
        );
        let settled = std::fs::read(loc.path()).unwrap();
        drop(journal);
        drop(PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap());
        assert_eq!(
            std::fs::read(loc.path()).unwrap(),
            settled,
            "{step:?}: idempotent"
        );
    }
}

#[test]
fn v1_replay_verification_is_still_enforced_and_refusal_leaves_v1() {
    let a = raw("a");
    let forged = lowered(&raw("forged"));
    let orphan = derived("summary", &a);
    for bad in [vec![a.clone(), forged], vec![orphan, a.clone()]] {
        let scratch = Scratch::new();
        let loc = scratch.location();
        let original = v1_bytes("space-a", &bad);
        write_private(loc.path(), &original);
        assert!(matches!(
            PublishedJournal::open(loc.clone(), &Anyone, &registry()),
            Err(JournalError::Replay { line: 3, .. } | JournalError::Replay { line: 2, .. })
        ));
        assert_eq!(std::fs::read(loc.path()).unwrap(), original);
        assert!(!loc.staging_path().exists());
    }
    let scratch = Scratch::new();
    let loc = scratch.location();
    write_private(loc.path(), &v1_bytes("space-b", &[raw("a")]));
    assert!(matches!(
        PublishedJournal::open(loc.clone(), &Anyone, &registry()),
        Err(JournalError::NamespaceDiffers)
    ));
    // A pinned reader never migrates; it refuses a v1 journal by name.
    write_private(loc.path(), &v1_bytes("space-a", &[raw("a")]));
    assert!(matches!(
        PinnedSnapshot::open(&loc, Pin::genesis("space-a"), &Anyone, &registry()),
        Err(JournalError::NotMigrated)
    ));
}

#[test]
fn a_failed_append_latches_reads_and_publishes() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    let mut journal = PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap();
    let v1 = publish_now(&mut journal, vec![raw("a")]);
    // Swap in a read-only handle: the next write fails part-way.
    journal.fail_next_write_for_test().unwrap();
    assert!(matches!(
        publish(&mut journal, &Patch::new(v1, vec![raw("b")]), v1),
        Err(PublishRefusal::Uncertain(_))
    ));
    assert!(matches!(journal.records(), Err(JournalError::Unavailable)));
    assert!(matches!(journal.head(), Err(JournalError::Unavailable)));
    assert!(matches!(
        publish(&mut journal, &Patch::new(v1, vec![raw("c")]), v1),
        Err(PublishRefusal::Unavailable)
    ));
    assert!(!journal.history.set.contains(&raw("b").content_hash()));
}

#[test]
fn an_incomplete_journal_is_refused() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    let mut journal = PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap();
    publish_now(&mut journal, vec![raw("a")]);
    drop(journal);
    let bytes = std::fs::read(loc.path()).unwrap();
    write_private(loc.path(), &bytes[..bytes.len() - 1]);
    assert!(matches!(
        PublishedJournal::open(loc, &Anyone, &registry()),
        Err(JournalError::Incomplete)
    ));
}

#[test]
fn a_journal_whose_path_was_replaced_is_refused() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    drop(PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap());
    let file = File::open(loc.path()).unwrap();
    std::fs::rename(loc.path(), scratch.file("moved.jsonl")).unwrap();
    write_private(
        loc.path(),
        &std::fs::read(scratch.file("moved.jsonl")).unwrap(),
    );
    assert!(matches!(
        check_names_file(loc.path(), &file),
        Err(JournalError::Replaced)
    ));
}

fn overlay_over(scratch: &Scratch, name: &str, base: Pin) -> Overlay {
    let loc = scratch.location();
    let snapshot = PinnedSnapshot::open(&loc, base, &Anyone, &registry()).unwrap();
    Overlay::open(&scratch.file(name), &loc, snapshot, &Anyone, &registry()).unwrap()
}

#[test]
fn two_overlays_over_one_base_never_see_each_other() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    let mut journal = PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap();
    let v1 = publish_now(&mut journal, vec![raw("base")]);
    let mut left = overlay_over(&scratch, "left.jsonl", v1);
    let mut right = overlay_over(&scratch, "right.jsonl", v1);
    let x = left.stage(raw("x"), &registry()).unwrap();
    let y = right.stage(raw("y"), &registry()).unwrap();
    for (mine, theirs, overlay) in [(x, y, &left), (y, x, &right)] {
        let seen = overlay.records().unwrap();
        assert!(seen.contains(&mine));
        assert!(seen.contains(&raw("base").content_hash()));
        assert!(!seen.contains(&theirs), "a sibling's write is invisible");
    }
    assert_eq!(left.patch().unwrap().records(), &[raw("x")]);
    assert_eq!(left.patch().unwrap().base(), v1);
    // Staging a base record writes nothing new to the patch.
    left.stage(raw("base"), &registry()).unwrap();
    assert_eq!(left.patch().unwrap().records().len(), 1);
    // The published journal is untouched until a publish.
    assert_eq!(journal.head().unwrap(), v1);
    assert!(!journal.records().unwrap().contains(&x));
    // One writer per overlay; a reopen keeps the branch.
    let snapshot = PinnedSnapshot::open(&loc, v1, &Anyone, &registry()).unwrap();
    assert!(matches!(
        Overlay::open(
            &scratch.file("left.jsonl"),
            &loc,
            snapshot.clone(),
            &Anyone,
            &registry()
        ),
        Err(JournalError::Locked)
    ));
    drop(left);
    let left = Overlay::open(
        &scratch.file("left.jsonl"),
        &loc,
        snapshot,
        &Anyone,
        &registry(),
    )
    .unwrap();
    assert_eq!(left.patch().unwrap().records(), &[raw("x")]);
    drop(left);
    // Over a different base, the same overlay file is refused.
    let genesis =
        PinnedSnapshot::open(&loc, Pin::genesis("space-a"), &Anyone, &registry()).unwrap();
    assert!(matches!(
        Overlay::open(
            &scratch.file("left.jsonl"),
            &loc,
            genesis.clone(),
            &Anyone,
            &registry()
        ),
        Err(JournalError::BaseDiffers)
    ));
    assert!(matches!(
        Overlay::open(loc.path(), &loc, genesis, &Anyone, &registry()),
        Err(JournalError::Location(_))
    ));
}

#[test]
fn overlays_publish_through_cas_and_the_second_rebases() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    let mut journal = PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap();
    let v1 = publish_now(&mut journal, vec![raw("base")]);
    let mut left = overlay_over(&scratch, "left.jsonl", v1);
    let mut right = overlay_over(&scratch, "right.jsonl", v1);
    left.stage(raw("x"), &registry()).unwrap();
    let base = raw("base");
    right
        .stage(derived("from-base", &base), &registry())
        .unwrap();
    let v2 = publish(&mut journal, &left.patch().unwrap(), v1).unwrap();
    let patch = right.patch().unwrap();
    let current = match publish(&mut journal, &patch, patch.base()) {
        Err(PublishRefusal::StaleBase { current }) => current,
        other => panic!("expected a stale base, got {other:?}"),
    };
    assert_eq!(current, v2);
    let v3 = publish(&mut journal, &patch, current).unwrap();
    assert_eq!(v3.version(), 3);
    assert_eq!(journal.records().unwrap().len(), 3);
    // The overlay is a branch: it still sees its own base, not the sibling's publish.
    assert!(!right.records().unwrap().contains(&raw("x").content_hash()));
}

#[test]
fn an_overlay_refuses_a_record_that_does_not_re_derive() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    let mut journal = PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap();
    let v1 = publish_now(&mut journal, vec![raw("base")]);
    let mut overlay = overlay_over(&scratch, "branch.jsonl", v1);
    let size = std::fs::metadata(scratch.file("branch.jsonl"))
        .unwrap()
        .len();
    assert!(matches!(
        overlay.stage(lowered(&raw("forged")), &registry()),
        Err(JournalError::Admission { .. })
    ));
    assert!(matches!(
        overlay.stage(derived("orphan", &raw("missing")), &registry()),
        Err(JournalError::Admission { .. })
    ));
    assert_eq!(
        std::fs::metadata(scratch.file("branch.jsonl"))
            .unwrap()
            .len(),
        size
    );
    assert!(overlay.patch().unwrap().records().is_empty());
}

#[test]
fn reach_is_asked_before_anything_is_created_or_read() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    // The directory: refused before the journal file exists.
    assert!(matches!(
        PublishedJournal::open(
            loc.clone(),
            &ExcludeOwnerOf(JournalPart::Directory),
            &registry()
        ),
        Err(JournalError::Reachable(_))
    ));
    assert!(!loc.path().exists());
    // The file: an existing v1 journal is refused before it is read or migrated.
    let original = v1_bytes("space-a", &[raw("a")]);
    write_private(loc.path(), &original);
    assert!(matches!(
        PublishedJournal::open(loc.clone(), &ExcludeOwnerOf(JournalPart::File), &registry()),
        Err(JournalError::Reachable(_))
    ));
    assert_eq!(std::fs::read(loc.path()).unwrap(), original);
    let v1 = PublishedJournal::open(loc.clone(), &Anyone, &registry())
        .unwrap()
        .head()
        .unwrap();
    for part in [JournalPart::Directory, JournalPart::File] {
        assert!(matches!(
            PinnedSnapshot::open(&loc, v1, &ExcludeOwnerOf(part), &registry()),
            Err(JournalError::Reachable(_))
        ));
    }
    let snapshot = PinnedSnapshot::open(&loc, v1, &Anyone, &registry()).unwrap();
    assert!(matches!(
        Overlay::open(
            &scratch.file("branch.jsonl"),
            &loc,
            snapshot,
            &ExcludeOwnerOf(JournalPart::Directory),
            &registry()
        ),
        Err(JournalError::Reachable(_))
    ));
    assert!(!scratch.file("branch.jsonl").exists());
}

/// What the node delivers to a run is a v1 journal: a v2 writer migrates it on open into
/// one commit holding exactly those records, and the returned digest is the file's bytes.
#[test]
fn a_delivery_is_a_journal_every_writer_opens_and_its_digest_is_its_bytes() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    let parent = raw("a");
    let child = derived("b", &parent);
    let digest = write_delivery(&loc, &[parent.clone(), child.clone()], &registry()).unwrap();
    let bytes = std::fs::read(loc.path()).unwrap();
    assert_eq!(bytes, v1_bytes("space-a", &[parent.clone(), child.clone()]));
    assert_eq!(
        digest.as_slice(),
        <sha2::Sha256 as sha2::Digest>::digest(&bytes).as_slice()
    );
    assert!(
        matches!(
            write_delivery(&loc, std::slice::from_ref(&parent), &registry()),
            Err(JournalError::Io(_))
        ),
        "a delivery never overwrites"
    );
    let journal = PublishedJournal::open(loc, &Anyone, &registry()).unwrap();
    assert_eq!(journal.head().unwrap().version(), 1);
    assert_eq!(journal.records().unwrap().len(), 2);
}

/// A delivery a proxy would refuse on open is refused before it is written: a derived record
/// whose cited parent was left out does not re-derive.
#[test]
fn a_delivery_missing_a_cited_parent_is_refused_and_not_written() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    let child = derived("b", &raw("a"));
    assert!(matches!(
        write_delivery(&loc, &[child], &registry()),
        Err(JournalError::Replay { .. })
    ));
    assert!(!loc.path().exists());
}

/// The unlocked reader returns every record in admission order, from a v1 journal and from a
/// v2 journal whose writer still holds the lock, and ignores a torn tail.
#[test]
fn the_unlocked_reader_reads_v1_and_v2_in_admission_order_beside_the_writer() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    let (a, b) = (raw("a"), raw("b"));
    let child = derived("c", &a);
    write_private(
        loc.path(),
        &v1_bytes("space-a", &[a.clone(), child.clone()]),
    );
    assert_eq!(
        read_unlocked(&loc, &Anyone, &registry()).unwrap(),
        vec![a.clone(), child.clone()]
    );
    let mut journal = PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap();
    publish_now(&mut journal, vec![b.clone()]);
    let mut torn = std::fs::OpenOptions::new()
        .append(true)
        .open(loc.path())
        .unwrap();
    torn.write_all(b"{\"version\":").unwrap();
    assert_eq!(
        read_unlocked(&loc, &Anyone, &registry()).unwrap(),
        vec![a, child, b],
        "the writer still holds the lock; the torn tail is not a line yet"
    );
}

/// The receipt hook runs on the sealed commit before the append: refusing it leaves the
/// journal byte for byte as it was, and a kept receipt names the head the commit creates.
#[test]
fn a_publish_whose_receipt_is_not_kept_appends_nothing() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    let mut journal = PublishedJournal::open(loc.clone(), &Anyone, &registry()).unwrap();
    let head = journal.head().unwrap();
    let before = std::fs::read(loc.path()).unwrap();
    let size = journal.bytes().unwrap();
    assert_eq!(size, u64::try_from(before.len()).unwrap());
    let patch = Patch::new(head, vec![raw("a")]);
    let by = (PublisherBinding::from_bytes([1; 32]), Epoch::new(1));
    let refused = journal.publish_with(&patch, head, by, &unbounded(), &registry(), &mut |_| {
        Err("the receipt log is full".into())
    });
    assert!(matches!(refused, Err(PublishRefusal::NotRecorded(_))));
    assert_eq!(std::fs::read(loc.path()).unwrap(), before);
    assert_eq!(journal.head().unwrap(), head);
    let mut named = None;
    let next = journal
        .publish_with(&patch, head, by, &unbounded(), &registry(), &mut |commit| {
            named = Some(commit.head());
            Ok(())
        })
        .unwrap();
    assert_eq!(named, Some(next));
    assert!(journal.bytes().unwrap() > size);
}
