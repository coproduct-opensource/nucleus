use super::*;
use crate::recompute::derive_label;
use crate::record::MemoryDerivation;
use nucleus_lineage::SourceClass;
use portcullis_core::memory::{MemoryLabel, SchemaType};
use portcullis_core::{ConfLevel, DerivationClass, IntegLevel};

fn raw(value: &str) -> MemoryRecord {
    let d = MemoryDerivation::RawIngest {
        source_class: SourceClass::Web,
        source_hash: ContentHash::of_canonical_bytes(value.as_bytes()),
    };
    let label = derive_label(&d, &[], crate::record::LabelStamp::Unstamped);
    MemoryRecord::new(value, SchemaType::String, label, d)
}

fn relabelled(record: &MemoryRecord, label: MemoryLabel) -> MemoryRecord {
    let mut out = record.clone();
    out.label = label;
    out
}

fn seal(parent: Pin, records: Vec<MemoryRecord>) -> Commit {
    Commit::seal(
        parent,
        records,
        PublisherBinding::operator_direct(),
        Epoch::PRE_BINDING,
    )
    .unwrap()
}

fn set_of(records: &[MemoryRecord]) -> ProvenanceMemorySet {
    let mut set = ProvenanceMemorySet::new();
    for r in records {
        assert!(
            set.verified_admit(r, &crate::TransformRegistry::new())
                .is_match()
        );
    }
    set
}

#[test]
fn a_sealed_commit_verifies_against_its_parent_and_chains() {
    let genesis = Pin::genesis("space-a");
    let first = seal(genesis, vec![raw("a"), raw("b")]);
    let v1 = first.verify(&genesis).unwrap();
    assert_eq!(v1.version(), 1);
    let second = seal(v1, vec![raw("c")]);
    let v2 = second.verify(&v1).unwrap();
    assert_eq!(v2.version(), 2);
    assert_ne!(v1.head(), v2.head());
    // The successor does not verify against the wrong parent.
    assert_eq!(
        second.verify(&genesis),
        Err(CommitError::NotNext {
            parent: 0,
            found: 2
        })
    );
    let foreign = Pin::new(1, HeadHash::genesis("space-a"));
    assert_eq!(second.verify(&foreign), Err(CommitError::ParentMismatch));
}

#[test]
fn the_head_hash_ignores_record_order_but_binds_everything_else() {
    let genesis = Pin::genesis("space-a");
    let ab = seal(genesis, vec![raw("a"), raw("b")]);
    let ba = seal(genesis, vec![raw("b"), raw("a")]);
    assert_eq!(ab.head(), ba.head());
    assert_ne!(ab.head(), seal(genesis, vec![raw("a")]).head());
    assert_ne!(
        ab.head(),
        seal(Pin::genesis("space-b"), vec![raw("a"), raw("b")]).head()
    );
    let other_publisher = Commit::seal(
        genesis,
        vec![raw("a"), raw("b")],
        PublisherBinding::from_bytes([7; 32]),
        Epoch::PRE_BINDING,
    )
    .unwrap();
    assert_ne!(ab.head(), other_publisher.head());
    let other_epoch = Commit::seal(
        genesis,
        vec![raw("a"), raw("b")],
        PublisherBinding::operator_direct(),
        Epoch::new(1),
    )
    .unwrap();
    assert_ne!(ab.head(), other_epoch.head());
}

#[test]
fn a_tampered_commit_line_fails_verification() {
    let genesis = Pin::genesis("space-a");
    let commit = seal(genesis, vec![raw("a")]);
    let line = serde_json::to_string(&commit).unwrap();
    let edits = [
        line.replace("\"value\":\"a\"", "\"value\":\"z\""),
        line.replace("\"integrity\":\"adversarial\"", "\"integrity\":\"trusted\""),
        // Same length, so only the label bytes themselves can catch it.
        line.replace(
            "\"confidentiality\":\"public\"",
            "\"confidentiality\":\"secret\"",
        ),
        line.replace("\"epoch\":0", "\"epoch\":9"),
    ];
    for edited in edits {
        assert_ne!(edited, line, "the fixture edit must change the line");
        let parsed: Commit = serde_json::from_str(&edited).unwrap();
        assert_eq!(parsed.verify(&genesis), Err(CommitError::HashMismatch));
    }
    let extra = line.replacen('{', "{\"extra\":1,", 1);
    assert!(serde_json::from_str::<Commit>(&extra).is_err());
}

#[test]
fn a_commit_adds_distinct_records_and_at_least_one() {
    let genesis = Pin::genesis("space-a");
    let err = Commit::seal(
        genesis,
        vec![raw("a"), raw("a")],
        PublisherBinding::operator_direct(),
        Epoch::PRE_BINDING,
    );
    assert_eq!(
        err,
        Err(CommitError::DuplicateRecord(raw("a").content_hash()))
    );
    let err = Commit::seal(
        genesis,
        Vec::new(),
        PublisherBinding::operator_direct(),
        Epoch::PRE_BINDING,
    );
    assert_eq!(err, Err(CommitError::Empty));
}

fn candidate<'a>(
    head: &'a ProvenanceMemorySet,
    concurrent: &'a BTreeSet<ContentHash>,
    patch: &'a Patch,
) -> Candidate<'a> {
    Candidate {
        head,
        concurrent,
        patch,
        additions: patch.records(),
        journal_bytes: 100,
    }
}

#[test]
fn whole_candidate_cap_refuses_two_patches_each_under_it() {
    let invariants = StoreInvariants::new(10, 1_000);
    let six = |p: &str| -> Vec<MemoryRecord> { (0..6).map(|i| raw(&format!("{p}{i}"))).collect() };
    let empty = ProvenanceMemorySet::new();
    let none = BTreeSet::new();
    let a = Patch::new(Pin::genesis("s"), six("a"));
    let b = Patch::new(Pin::genesis("s"), six("b"));
    assert_eq!(invariants.validate(&candidate(&empty, &none, &a)), Ok(()));
    assert_eq!(invariants.validate(&candidate(&empty, &none, &b)), Ok(()));
    let after_a = set_of(a.records());
    assert_eq!(
        invariants.validate(&candidate(&after_a, &none, &b)),
        Err(CandidateRefusal::RecordCap {
            records: 12,
            cap: 10
        })
    );
}

#[test]
fn byte_cap_is_checked_on_the_journal_after_the_commit() {
    let invariants = StoreInvariants::new(10, 99);
    let empty = ProvenanceMemorySet::new();
    let none = BTreeSet::new();
    let patch = Patch::new(Pin::genesis("s"), vec![raw("a")]);
    assert_eq!(
        invariants.validate(&candidate(&empty, &none, &patch)),
        Err(CandidateRefusal::ByteCap {
            bytes: 100,
            cap: 99
        })
    );
}

#[test]
fn a_label_never_lowers_and_raising_it_is_not_a_violation() {
    let invariants = StoreInvariants::new(10, 1_000);
    let base = raw("a");
    let head = set_of(std::slice::from_ref(&base));
    let none = BTreeSet::new();
    let lowered = relabelled(
        &base,
        MemoryLabel::from_levels_with_derivation(
            ConfLevel::Public,
            IntegLevel::Trusted,
            DerivationClass::Deterministic,
        ),
    );
    let hash = base.content_hash();
    let patch = Patch::new(Pin::genesis("s"), vec![lowered]);
    assert_eq!(
        invariants.validate(&candidate(&head, &none, &patch)),
        Err(CandidateRefusal::LabelLowered { hash })
    );
    let raised = relabelled(
        &base,
        MemoryLabel::from_levels_with_derivation(
            ConfLevel::Secret,
            base.label.integ_level(),
            base.label.derivation,
        ),
    );
    let patch = Patch::new(Pin::genesis("s"), vec![raised]);
    assert_eq!(
        invariants.validate(&candidate(&head, &none, &patch)),
        Ok(())
    );
}

#[test]
fn a_concurrently_published_key_conflicts_unless_resolved() {
    let invariants = StoreInvariants::new(10, 1_000);
    let base = raw("a");
    let head = set_of(std::slice::from_ref(&base));
    let hash = base.content_hash();
    let concurrent: BTreeSet<ContentHash> = [hash].into();
    let raised = relabelled(
        &base,
        MemoryLabel::from_levels_with_derivation(
            ConfLevel::Secret,
            base.label.integ_level(),
            base.label.derivation,
        ),
    );
    let patch = Patch::new(Pin::genesis("s"), vec![raised]);
    assert_eq!(
        invariants.validate(&candidate(&head, &concurrent, &patch)),
        Err(CandidateRefusal::KeyedConflict { hash })
    );
    let resolved = patch.resolve(hash);
    assert_eq!(
        invariants.validate(&candidate(&head, &concurrent, &resolved)),
        Ok(())
    );
}

#[test]
fn wire_forms_are_hex_and_refuse_bad_lengths() {
    let head = HeadHash::genesis("s");
    let json = serde_json::to_string(&head).unwrap();
    assert_eq!(json, format!("\"{}\"", head.to_hex()));
    assert_eq!(serde_json::from_str::<HeadHash>(&json).unwrap(), head);
    assert!(serde_json::from_str::<HeadHash>("\"abcd\"").is_err());
    assert!(serde_json::from_str::<PublisherBinding>("\"abcd\"").is_err());
    assert_ne!(
        PublisherBinding::v1_migration(),
        PublisherBinding::operator_direct()
    );
}
