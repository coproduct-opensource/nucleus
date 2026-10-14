//! Program C, C1: a record carries its writer's dependency stamp, admission re-derives its label
//! against the floor the stamp RECORDS, and nothing about a record becomes less constrained by
//! being stored, replayed, merged or migrated.
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use nucleus_lineage::SourceClass;
use portcullis_core::memory::{MemoryLabel, SchemaType};
use portcullis_core::{ConfLevel, IntegLevel};

use crate::hash::ContentHash;
use crate::journal::{JournalError, JournalLocation, JournalPart, PublishedJournal, ReachCheck};
use crate::recompute::{RecomputeVerdict, TransformRegistry, derive_label, verify_admission};
use crate::record::{LabelStamp, MemoryDerivation, MemoryRecord};
use crate::version::{Commit, Epoch, Patch, Pin, PublisherBinding, StoreInvariants};
use crate::{MAX_JOURNAL_BYTES, ProvenanceMemorySet};

const SECRET: LabelStamp = LabelStamp::Stamped {
    writer_floor: ConfLevel::Secret,
};
const PUBLIC: LabelStamp = LabelStamp::Stamped {
    writer_floor: ConfLevel::Public,
};

/// The literal a session writes. Its derivation is a raw ingest whatever selected it.
fn literal(value: &str, stamp: LabelStamp) -> MemoryRecord {
    let d = MemoryDerivation::RawIngest {
        source_class: SourceClass::LocalFile,
        source_hash: ContentHash::of_canonical_bytes(value.as_bytes()),
    };
    let label = derive_label(&d, &[], stamp);
    MemoryRecord::new(value, SchemaType::String, label, d).with_stamp(stamp)
}

fn summary(value: &str, parent: &MemoryRecord, stamp: LabelStamp) -> MemoryRecord {
    let d = MemoryDerivation::OpaqueLlm {
        input_hashes: vec![parent.content_hash()],
        model_tag: "fixture-model".into(),
    };
    let label = derive_label(&d, &[parent], stamp);
    MemoryRecord::new(value, SchemaType::String, label, d).with_stamp(stamp)
}

fn with_conf(record: &MemoryRecord, conf: ConfLevel) -> MemoryRecord {
    let mut out = record.clone();
    out.label = MemoryLabel::from_levels_with_derivation(
        conf,
        record.label.integ_level(),
        record.label.derivation,
    );
    out
}

/// A session that read Secret data writes a literal that read SELECTED (control dependence:
/// the value itself carries nothing Secret, only which value it is). Its record is Secret, a
/// Public label under that floor is refused, and the floor touches confidentiality alone.
///
/// A-19: with the floor dropped from `derive_label` (the session join), the stamped Secret
/// record is a mismatch and the Public claim is admitted.
#[test]
fn a_literal_a_secret_read_selected_is_secret_and_a_public_claim_is_refused() {
    let registry = TransformRegistry::new();
    let stored = literal("deploy-window: tuesday", SECRET);
    assert_eq!(stored.label.conf_level(), ConfLevel::Secret);
    assert_eq!(stored.effective_confidentiality(), ConfLevel::Secret);
    assert!(verify_admission(&stored, &[], &registry).is_match());

    let unfloored = literal("deploy-window: tuesday", LabelStamp::Unstamped);
    assert_eq!(
        stored.label.integ_level(),
        unfloored.label.integ_level(),
        "integrity is the derivation's, not the floor's"
    );
    assert_eq!(stored.label.derivation, unfloored.label.derivation);
    assert_eq!(
        stored.content_hash(),
        unfloored.content_hash(),
        "the stamp is not identity"
    );

    let claimed_public = with_conf(&stored, ConfLevel::Public);
    match verify_admission(&claimed_public, &[], &registry) {
        RecomputeVerdict::Mismatch { field, .. } => assert_eq!(field, "label"),
        other => panic!("a Public label under a Secret floor must be refused: {other:?}"),
    }
    // A record that existed only because of a Secret read (record existence conditioned on
    // Secret) is covered the same way: every write of the session carries the floor.
    let derived = summary("summary of the window", &stored, PUBLIC);
    assert_eq!(
        derived.label.conf_level(),
        ConfLevel::Secret,
        "a child of a Secret record is Secret whatever its own floor"
    );
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "npm-stamp-{}-{}",
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
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Anyone;

impl ReachCheck for Anyone {
    fn admit(&self, _: JournalPart, _: u32) -> Result<(), String> {
        Ok(())
    }
}

fn publish_now(journal: &mut PublishedJournal, records: Vec<MemoryRecord>) -> Pin {
    let head = journal.head().unwrap();
    journal
        .publish(
            &Patch::new(head, records),
            head,
            PublisherBinding::from_bytes([1; 32]),
            Epoch::new(1),
            &StoreInvariants::new(usize::MAX, MAX_JOURNAL_BYTES),
            &TransformRegistry::new(),
        )
        .unwrap()
}

fn write_private(path: &std::path::Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Replay in a fresh session keeps Secret: the journal is reopened by a writer that has read
/// nothing, and the record is still Secret, because admission re-derives against the floor the
/// record RECORDS. Rewriting the floor on disk is refused (the stamp is in the head hash), and a
/// commit sealed honestly over a Secret label with a Public floor is refused by replay.
///
/// A-19: with replay re-deriving from a fresh (Public) session instead of the recorded floor,
/// the honest reopen is refused, and the first assertion reds.
#[test]
fn replay_in_a_fresh_session_keeps_the_recorded_floor() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    let registry = TransformRegistry::new();
    let secret = literal("chosen by a secret read", SECRET);
    let head = {
        let mut journal = PublishedJournal::open(loc.clone(), &Anyone, &registry).unwrap();
        publish_now(&mut journal, vec![secret.clone()])
    };
    let reopened = PublishedJournal::open(loc.clone(), &Anyone, &registry)
        .expect("an honest stamped journal replays in a fresh session");
    assert_eq!(reopened.head().unwrap(), head);
    let held = reopened
        .records()
        .unwrap()
        .get(&secret.content_hash())
        .unwrap();
    assert_eq!(held.label.conf_level(), ConfLevel::Secret);
    assert_eq!(held.stamp, SECRET);
    drop(reopened);

    let good = std::fs::read_to_string(loc.path()).unwrap();
    let rewritten = good
        .replace("\"writer_floor\":\"secret\"", "\"writer_floor\":\"public\"")
        .replace(
            "\"confidentiality\":\"secret\"",
            "\"confidentiality\":\"public\"",
        );
    assert_ne!(rewritten, good);
    write_private(loc.path(), rewritten.as_bytes());
    assert!(
        matches!(
            PublishedJournal::open(loc.clone(), &Anyone, &registry),
            Err(JournalError::Chain { .. })
        ),
        "a floor rewritten on disk breaks the chain"
    );

    // Sealed honestly (the head hash matches) but the label is not what the recorded floor earns.
    let lying = with_conf(&secret, ConfLevel::Public);
    let commit = Commit::seal(
        Pin::genesis("space-a"),
        vec![lying],
        PublisherBinding::from_bytes([1; 32]),
        Epoch::new(1),
    )
    .unwrap();
    let header = good.lines().next().unwrap();
    let body = format!("{header}\n{}\n", serde_json::to_string(&commit).unwrap());
    write_private(loc.path(), body.as_bytes());
    assert!(
        matches!(
            PublishedJournal::open(loc, &Anyone, &registry),
            Err(JournalError::Replay { .. })
        ),
        "a label below the recorded floor is refused by replay"
    );
}

/// The stamp is part of what a commit binds: two commits that differ only in a record's stamp
/// have different heads. An unstamped record encodes with no `stamp` field, so a journal written
/// before stamps existed replays to the same heads.
#[test]
fn the_head_binds_the_stamp_and_an_unstamped_record_encodes_as_before() {
    let a = literal("same content", PUBLIC);
    let b = literal("same content", SECRET);
    let unstamped = literal("same content", LabelStamp::Unstamped);
    let seal = |r: &MemoryRecord| {
        Commit::seal(
            Pin::genesis("space-a"),
            vec![r.clone()],
            PublisherBinding::from_bytes([1; 32]),
            Epoch::new(1),
        )
        .unwrap()
        .head()
    };
    assert_ne!(seal(&a), seal(&b));
    assert_ne!(
        seal(&a),
        seal(&unstamped),
        "a Public stamp is not the absence of one"
    );
    // The head origin/main 3145a9071 (before stamps existed) seals for this exact commit,
    // measured there: an unstamped record's entry is unchanged, so every published head is.
    assert_eq!(
        seal(&unstamped).head().to_hex(),
        "38d9382e8826bb4613a7ecf1ffd9336e04a0e9e2624630f056fa2170530ff0f9"
    );
    let encoded = serde_json::to_value(&unstamped).unwrap();
    assert!(encoded.get("stamp").is_none(), "{encoded}");
    let back: MemoryRecord = serde_json::from_value(encoded).unwrap();
    assert_eq!(back.stamp, LabelStamp::Unstamped);
    let stamped = serde_json::to_value(&b).unwrap();
    assert_eq!(stamped["stamp"]["kind"], "stamped");
    assert_eq!(stamped["stamp"]["writer_floor"], "secret");
}

/// An unstamped record says nothing of what its writer had read, so it is Secret wherever it is
/// delivered; its held form (stamped Secret) keeps its content hash and re-derives, and so does
/// a held chain. Merging an unstamped copy with a stamped one is stamped Secret,
/// never the stamped copy's lower floor, and the merge re-derives.
#[test]
fn an_unstamped_record_is_secret_and_merges_and_quarantines_fail_closed() {
    let registry = TransformRegistry::new();
    let legacy = literal("written before stamps", LabelStamp::Unstamped);
    assert_eq!(legacy.label.conf_level(), ConfLevel::Public);
    assert_eq!(legacy.effective_confidentiality(), ConfLevel::Secret);
    let child = summary("its summary", &legacy, LabelStamp::Unstamped);

    let held = legacy.held_secret();
    let held_child = child.held_secret();
    assert_eq!(held.content_hash(), legacy.content_hash());
    assert_eq!(
        (held.stamp, held.label.conf_level()),
        (SECRET, ConfLevel::Secret)
    );
    assert_eq!(held.label.integ_level(), legacy.label.integ_level());
    assert!(verify_admission(&held, &[], &registry).is_match());
    assert!(verify_admission(&held_child, &[&held], &registry).is_match());
    assert_eq!(
        held.held_secret(),
        held,
        "holding a held record changes nothing"
    );

    let stamped_public = literal("written before stamps", PUBLIC);
    let mut a = ProvenanceMemorySet::new();
    assert!(a.verified_admit(&legacy, &registry).is_match());
    let mut b = ProvenanceMemorySet::new();
    assert!(b.verified_admit(&stamped_public, &registry).is_match());
    let merged = a.join(&b);
    assert_eq!(merged, b.join(&a), "commutative");
    assert_eq!(merged.join(&merged), merged, "idempotent");
    let record = merged.get(&legacy.content_hash()).unwrap();
    assert_eq!(record.stamp, SECRET);
    assert_eq!(record.label.conf_level(), ConfLevel::Secret);
    assert_eq!(record.label.integ_level(), IntegLevel::Untrusted);
    assert!(verify_admission(record, &[], &registry).is_match());
    // Admitting the stamped copy into a set holding the unstamped one is the same merge.
    assert!(a.verified_admit(&stamped_public, &registry).is_match());
    assert_eq!(a, merged);
}

/// A v1 journal (and a v1 record line) has no stamps: it migrates to v2 with every record
/// unstamped, so it is Secret wherever it is delivered until a separate declassification says
/// otherwise. Import never stamps it.
#[test]
fn a_v1_journal_migrates_unstamped() {
    let scratch = Scratch::new();
    let loc = scratch.location();
    let legacy = literal("v1 record", LabelStamp::Unstamped);
    let mut bytes = br#"{"schema":"nucleus.memory-journal.v1","namespace":"space-a"}"#.to_vec();
    bytes.push(b'\n');
    bytes.extend(serde_json::to_vec(&legacy).unwrap());
    bytes.push(b'\n');
    write_private(loc.path(), &bytes);
    let journal = PublishedJournal::open(loc, &Anyone, &TransformRegistry::new()).unwrap();
    let migrated = journal
        .records()
        .unwrap()
        .get(&legacy.content_hash())
        .unwrap();
    assert_eq!(migrated.stamp, LabelStamp::Unstamped);
    assert_eq!(migrated.effective_confidentiality(), ConfLevel::Secret);
}
