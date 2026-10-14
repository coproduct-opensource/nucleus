//! The laws the Lean model proves, checked over the Rust: exhaustively where the
//! domain allows, by seeded proptest where it does not. Named counterexamples
//! (the budget case, the old epoch, the wider view) are tests of their own, so a
//! mutant that reintroduces one reds a test that names it.

use proptest::prelude::*;

use crate::parity_tests::{all_entries, all_slots};
use crate::{
    AdmitRefusal, Binding, CandidateRefusal, CommitRefusal, Entry, Epoch, History, Invariants, Key,
    LabelRank, Mode, Overlap, ReadRefusal, Scope, ScopeAtom, Section, Units, ValueId, Version,
    View, admit, assemble_candidate, compare_on_overlap, observe, restrict, validate_candidate,
};

fn entry(value: u8, label: LabelRank, units: u8) -> Entry {
    Entry {
        value: ValueId::new(value).expect("in the model"),
        label,
        units: Units::new(units).expect("in the model"),
    }
}

#[test]
fn mask_is_every_atom() {
    let folded = ScopeAtom::ALL.iter().fold(0u8, |m, a| m | a.bit());
    assert_eq!(Scope::FULL.bits(), folded);
    assert_eq!(Scope::all().count(), 1 << ScopeAtom::ALL.len());
    assert_eq!(
        Scope::from_bits(folded | 8),
        None,
        "a bit naming no atom is refused"
    );
    for atom in ScopeAtom::ALL {
        assert!(Scope::of(atom).contains(atom));
        assert!(Scope::EMPTY.with(atom).is_subset_of(Scope::FULL));
    }
}

// ── Restriction ────────────────────────────────────────────────────────────

#[test]
fn restriction_identity_over_every_view() {
    for v in View::all() {
        assert_eq!(restrict(v, v), Some(v));
    }
}

#[test]
fn restriction_composition_over_every_view_triple() {
    let mut composed = 0;
    for v in View::all() {
        for m in View::all() {
            for n in View::all() {
                if let Some(r) = restrict(v, m).and_then(|m2| restrict(m2, n)) {
                    assert_eq!(restrict(v, n), Some(r), "{v:?} → {m:?} → {n:?}");
                    composed += 1;
                }
                if m.is_within(v) && n.is_within(m) {
                    assert_eq!(
                        restrict(v, m).and_then(|m2| restrict(m2, n)),
                        restrict(v, n)
                    );
                }
            }
        }
    }
    assert!(composed > 0, "the composition law was exercised");
}

#[test]
fn restrict_refuses_every_wider_view() {
    let mut refused = 0;
    for v in View::all() {
        for n in View::all() {
            match restrict(v, n) {
                Some(r) => {
                    assert!(r.scope.is_subset_of(v.scope), "{v:?} widened to {r:?}");
                    assert!(r.ceiling.at_most(v.ceiling), "{v:?} raised to {r:?}");
                }
                None => {
                    assert!(!n.is_within(v));
                    refused += 1;
                }
            }
        }
    }
    // 576 pairs; 6 × 27 = 162 are within (Σ over scopes of 2^|s|, times Σ ceilings).
    assert_eq!(refused, 576 - 162);
}

// ── Observation ────────────────────────────────────────────────────────────

fn section_strategy() -> impl Strategy<Value = Section> {
    let slots = all_slots();
    proptest::collection::vec(proptest::sample::select(slots), Key::ALL.len()).prop_map(|v| {
        let mut s = Section::EMPTY;
        for (key, slot) in Key::ALL.into_iter().zip(v) {
            s.set(key, slot);
        }
        s
    })
}

fn view_strategy() -> impl Strategy<Value = View> {
    proptest::sample::select(View::all().collect::<Vec<_>>())
}

proptest! {
    #[test]
    fn observation_keeps_entries_and_labels(s in section_strategy(), v in view_strategy()) {
        let seen = observe(&s, v);
        for key in Key::ALL {
            if let Some(e) = seen.get(key) {
                prop_assert_eq!(s.get(key), Some(e), "observation altered an entry");
                prop_assert!(v.scope.contains(key.atom()));
                prop_assert!(e.label.at_most(v.ceiling));
            }
        }
    }

    #[test]
    fn observing_through_a_restriction_is_restricting_the_observation(
        s in section_strategy(), v in view_strategy(), n in view_strategy(),
    ) {
        if let Some(r) = restrict(v, n) {
            prop_assert_eq!(observe(&observe(&s, v), r), observe(&s, r));
        }
    }
}

// ── Assembly and validation ────────────────────────────────────────────────

proptest! {
    #[test]
    fn assembly_recovers_every_accepted_local_section(
        base in section_strategy(),
        patches in proptest::collection::vec(section_strategy(), 0..4),
    ) {
        let mut h = History::genesis();
        let snapshot = if base == Section::EMPTY {
            h.snapshot(Version::GENESIS).expect("genesis")
        } else {
            let c = assemble_candidate(&h.snapshot(Version::GENESIS).expect("genesis"), &[base]);
            let valid = validate_candidate(c, Invariants { quota: u16::MAX }).expect("over empty");
            let v = h.commit(valid).expect("onto head");
            h.snapshot(v).expect("just committed")
        };
        let c = assemble_candidate(&snapshot, &patches);
        for key in Key::ALL {
            let writes: Vec<Entry> = patches.iter().filter_map(|p| p.get(key)).collect();
            if writes.is_empty() {
                prop_assert_eq!(c.merged().get(key), base.get(key), "base kept where no patch wrote");
                prop_assert!(!c.is_conflicted(key));
            } else if c.is_conflicted(key) {
                prop_assert!(writes.iter().any(|w| *w != writes[0]), "a conflict needs a disagreement");
            } else {
                for w in writes {
                    prop_assert_eq!(c.merged().get(key), Some(w), "an accepted write was lost");
                }
            }
        }
    }

    #[test]
    fn two_patches_conflict_exactly_where_they_disagree(a in section_strategy(), b in section_strategy()) {
        let h = History::genesis();
        let c = assemble_candidate(&h.snapshot(Version::GENESIS).expect("genesis"), &[a, b]);
        let any_conflict = Key::ALL.into_iter().any(|k| c.is_conflicted(k));
        prop_assert_eq!(any_conflict, compare_on_overlap(&a, &b) != Overlap::Agree);
    }

    #[test]
    fn a_valid_candidate_is_valid_as_a_whole(
        base in section_strategy(),
        patches in proptest::collection::vec(section_strategy(), 0..3),
        quota in 0u16..=64,
    ) {
        let snapshot = crate::Snapshot::for_test(Version::GENESIS, base);
        let c = assemble_candidate(&snapshot, &patches);
        let merged = *c.merged();
        let conflicted: Vec<bool> = Key::ALL.into_iter().map(|k| c.is_conflicted(k)).collect();
        if let Ok(valid) = validate_candidate(c, Invariants { quota }) {
            let mut total = 0u16;
            for (key, conflict) in Key::ALL.into_iter().zip(conflicted) {
                prop_assert!(!conflict);
                if let Some(stored) = base.get(key) {
                    let next = merged.get(key).expect("never dropped");
                    prop_assert!(stored.label.at_most(next.label), "label lowered");
                }
                total += merged.get(key).map_or(0, |e| u16::from(e.units.get()));
            }
            prop_assert!(total <= quota);
            prop_assert_eq!(valid.section(), &merged);
        }
    }
}

/// The required counterexample: two patches on DISJOINT keys agree on every overlap
/// (vacuously), each is valid alone under a quota of 10, and glued they spend 12.
#[test]
fn overlap_agreement_is_not_validity_budget_6_plus_6_over_10() {
    let h = History::genesis();
    let base = h.snapshot(Version::GENESIS).expect("genesis");
    let a = Section::EMPTY.with(Key::K0, entry(1, LabelRank::Public, 6));
    let b = Section::EMPTY.with(Key::K2, entry(2, LabelRank::Public, 6));
    let quota = Invariants { quota: 10 };

    assert_eq!(compare_on_overlap(&a, &b), Overlap::Agree);
    assert!(validate_candidate(assemble_candidate(&base, &[a]), quota).is_ok());
    assert!(validate_candidate(assemble_candidate(&base, &[b]), quota).is_ok());
    assert_eq!(
        validate_candidate(assemble_candidate(&base, &[a, b]), quota),
        Err(CandidateRefusal::QuotaExceeded {
            total: 12,
            quota: 10
        })
    );
}

#[test]
fn a_keyed_conflict_is_refused_by_name() {
    let base = History::genesis()
        .snapshot(Version::GENESIS)
        .expect("genesis");
    let a = Section::EMPTY.with(Key::K1, entry(1, LabelRank::Public, 1));
    let b = Section::EMPTY.with(Key::K1, entry(3, LabelRank::Public, 1));
    assert_eq!(
        compare_on_overlap(&a, &b),
        Overlap::Conflict { key: Key::K1 }
    );
    assert_eq!(
        validate_candidate(
            assemble_candidate(&base, &[a, b]),
            Invariants { quota: 100 }
        ),
        Err(CandidateRefusal::KeyConflict { key: Key::K1 })
    );
}

#[test]
fn a_stored_label_never_lowers() {
    let mut h = History::genesis();
    let secret = Section::EMPTY.with(Key::K0, entry(1, LabelRank::Secret, 1));
    let genesis = h.snapshot(Version::GENESIS).expect("genesis");
    let v1 = h
        .commit(
            validate_candidate(
                assemble_candidate(&genesis, &[secret]),
                Invariants { quota: 9 },
            )
            .expect("valid"),
        )
        .expect("onto head");
    let base = h.snapshot(v1).expect("committed");
    let lowering = Section::EMPTY.with(Key::K0, entry(1, LabelRank::Public, 1));
    assert_eq!(
        validate_candidate(
            assemble_candidate(&base, &[lowering]),
            Invariants { quota: 9 }
        ),
        Err(CandidateRefusal::LabelLowered {
            key: Key::K0,
            from: LabelRank::Secret,
            to: LabelRank::Public
        })
    );
    // Raising is fine.
    let raising = Section::EMPTY.with(Key::K0, entry(2, LabelRank::Secret, 1));
    assert!(
        validate_candidate(
            assemble_candidate(&base, &[raising]),
            Invariants { quota: 9 }
        )
        .is_ok()
    );
}

#[test]
fn every_entry_can_be_stored_alone_under_an_ample_quota() {
    let base = History::genesis()
        .snapshot(Version::GENESIS)
        .expect("genesis");
    for key in Key::ALL {
        for e in all_entries() {
            let c = assemble_candidate(&base, &[Section::EMPTY.with(key, e)]);
            assert!(
                validate_candidate(c, Invariants { quota: 15 }).is_ok(),
                "{key:?} {e:?}"
            );
        }
    }
}

// ── Versions ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn a_pinned_version_is_unchanged_by_later_commits(
        commits in proptest::collection::vec(section_strategy(), 1..History::CAPACITY),
        v in view_strategy(),
    ) {
        let mut h = History::genesis();
        let mut seen: Vec<Section> = vec![observe(&Section::EMPTY, v)];
        for patch in commits {
            let head = h.snapshot(h.head()).expect("head exists");
            let c = assemble_candidate(&head, &[patch]);
            if let Ok(valid) = validate_candidate(c, Invariants { quota: u16::MAX }) {
                h.commit(valid).expect("onto head, below capacity");
                seen.push(observe(h.snapshot(h.head()).expect("head").section(), v));
            }
            for (n, before) in seen.iter().enumerate() {
                let version = Version::new(u8::try_from(n).expect("small"));
                let now = observe(h.snapshot(version).expect("committed").section(), v);
                prop_assert_eq!(&now, before, "version {} moved", n);
            }
            let past = Version::new(h.head().number() + 1);
            prop_assert!(h.snapshot(past).is_none(), "a version past the head is not readable");
        }
    }
}

#[test]
fn a_stale_base_is_refused_then_rebases() {
    let mut h = History::genesis();
    let base = h.snapshot(Version::GENESIS).expect("genesis");
    let mine = Section::EMPTY.with(Key::K0, entry(1, LabelRank::Public, 1));
    let theirs = Section::EMPTY.with(Key::K2, entry(2, LabelRank::Public, 1));
    let quota = Invariants { quota: 10 };

    let my_valid = validate_candidate(assemble_candidate(&base, &[mine]), quota).expect("valid");
    let their_valid =
        validate_candidate(assemble_candidate(&base, &[theirs]), quota).expect("valid");
    let v1 = h.commit(their_valid).expect("first wins");
    assert_eq!(
        h.commit(my_valid),
        Err(CommitRefusal::StaleBase {
            generation: Version::GENESIS,
            head: v1
        })
    );
    // Rebase: assemble over the new head and validate the whole candidate again.
    let head = h.snapshot(v1).expect("head");
    let rebased = validate_candidate(assemble_candidate(&head, &[mine]), quota).expect("valid");
    let v2 = h.commit(rebased).expect("onto the new head");
    let both = h.snapshot(v2).expect("committed");
    assert_eq!(both.section().get(Key::K0), mine.get(Key::K0));
    assert_eq!(both.section().get(Key::K2), theirs.get(Key::K2));
}

#[test]
fn a_full_history_refuses_by_name() {
    let mut h = History::genesis();
    for _ in 1..History::CAPACITY {
        let head = h.snapshot(h.head()).expect("head");
        let c = assemble_candidate(&head, &[]);
        h.commit(validate_candidate(c, Invariants { quota: 0 }).expect("empty"))
            .expect("below capacity");
    }
    let head = h.snapshot(h.head()).expect("head");
    let c =
        validate_candidate(assemble_candidate(&head, &[]), Invariants { quota: 0 }).expect("empty");
    assert_eq!(
        h.commit(c),
        Err(CommitRefusal::Full {
            capacity: History::CAPACITY
        })
    );
}

// ── Admission ──────────────────────────────────────────────────────────────

fn binding(epoch: u32, not_after: u64, base: Version) -> Binding {
    Binding {
        binding_id: 1,
        view: View {
            scope: Scope::of(ScopeAtom::Ns0),
            ceiling: LabelRank::Internal,
        },
        base,
        mode: Mode::ReadPropose,
        epoch: Epoch(epoch),
        not_after,
    }
}

#[test]
fn admit_refuses_every_old_epoch() {
    for current in 1..=8u32 {
        for old in 0..current {
            for (not_after, now) in [(0, 0), (10, 5), (u64::MAX, 0)] {
                assert_eq!(
                    admit(
                        &binding(old, not_after, Version::GENESIS),
                        Epoch(current),
                        now
                    ),
                    Err(AdmitRefusal::ForeignEpoch {
                        binding: Epoch(old),
                        current: Epoch(current)
                    }),
                    "epoch {old} admitted in {current}"
                );
            }
        }
    }
}

#[test]
fn admit_refuses_expired_and_checks_the_epoch_first() {
    assert_eq!(
        admit(&binding(3, 10, Version::GENESIS), Epoch(3), 11),
        Err(AdmitRefusal::Expired {
            not_after: 10,
            now: 11
        })
    );
    // not_after is inclusive.
    assert!(admit(&binding(3, 10, Version::GENESIS), Epoch(3), 10).is_ok());
    // Revoked AND expired reports the revocation.
    assert!(matches!(
        admit(&binding(2, 10, Version::GENESIS), Epoch(3), 11),
        Err(AdmitRefusal::ForeignEpoch { .. })
    ));
}

proptest! {
    #[test]
    fn admitted_iff_current_epoch_and_not_expired(
        be in 0u32..4, ce in 0u32..4, na in any::<u64>(), now in any::<u64>(),
    ) {
        let r = admit(&binding(be, na, Version::GENESIS), Epoch(ce), now);
        prop_assert_eq!(r.is_ok(), be == ce && now <= na);
        if let Ok(a) = r {
            prop_assert_eq!(a.epoch(), Epoch(ce));
            prop_assert_eq!(a.not_after(), na);
        }
    }
}

#[test]
fn an_admitted_read_sees_its_pinned_view_not_the_head() {
    let mut h = History::genesis();
    let quota = Invariants { quota: 100 };
    let genesis = h.snapshot(Version::GENESIS).expect("genesis");
    let first = Section::EMPTY
        .with(Key::K0, entry(1, LabelRank::Public, 1))
        .with(Key::K2, entry(2, LabelRank::Public, 1))
        .with(Key::K1, entry(3, LabelRank::Secret, 1));
    let v1 = h
        .commit(validate_candidate(assemble_candidate(&genesis, &[first]), quota).expect("valid"))
        .expect("head");

    let b = binding(0, 100, v1);
    let before = admit(&b, Epoch(0), 1)
        .expect("current")
        .read(&h)
        .expect("pinned");
    // Only K0: K2 is out of scope, K1 is above the ceiling.
    assert_eq!(
        before,
        Section::EMPTY.with(Key::K0, entry(1, LabelRank::Public, 1))
    );

    // A sibling publishes over the head; the pinned read does not move.
    let head = h.snapshot(v1).expect("head");
    let sibling = Section::EMPTY.with(Key::K0, entry(1, LabelRank::Internal, 1));
    h.commit(validate_candidate(assemble_candidate(&head, &[sibling]), quota).expect("valid"))
        .expect("head");
    let after = admit(&b, Epoch(0), 2)
        .expect("current")
        .read(&h)
        .expect("pinned");
    assert_eq!(after, before);

    // A binding pinned past the head is refused, not read as empty.
    let ahead = binding(0, 100, Version::new(7));
    assert_eq!(
        admit(&ahead, Epoch(0), 1).expect("current").read(&h),
        Err(ReadRefusal::BaseNotCommitted {
            base: Version::new(7),
            head: h.head()
        })
    );
}
