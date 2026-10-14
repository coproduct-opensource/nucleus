//! Each `extracted/` slice bound to its production function by EXHAUSTIVE case
//! analysis over the finite domain. For a finite domain an exhaustive check is a
//! complete equivalence proof, not a sample. Every loop asserts how many cases it
//! visited, so a domain that silently shrank to nothing is a red, not a pass.

use crate::candidate::{SlotAcc, step_slot};
use crate::extracted::{self, FlatSlot, flat};
use crate::{
    AdmitRefusal, Binding, Candidate, CandidateRefusal, Entry, Epoch, History, Invariants, Key,
    LabelRank, Mode, Overlap, Scope, Section, Snapshot, Units, ValidCandidate, ValueId, Version,
    View, admit, compare_on_overlap, observe, restrict, validate_candidate,
};

/// Every entry of the finite model.
pub(crate) fn all_entries() -> Vec<Entry> {
    let mut out = Vec::new();
    for value in 0..ValueId::COUNT {
        for label in LabelRank::ALL {
            for units in 0..=Units::MAX {
                out.push(Entry {
                    value: ValueId::new(value).expect("in the model"),
                    label,
                    units: Units::new(units).expect("in the model"),
                });
            }
        }
    }
    out
}

/// Every slot of the finite model: absent, or any entry.
pub(crate) fn all_slots() -> Vec<Option<Entry>> {
    std::iter::once(None)
        .chain(all_entries().into_iter().map(Some))
        .collect()
}

/// The size of the slot domain, derived from the domain's own constants.
fn slot_count() -> usize {
    1 + usize::from(ValueId::COUNT) * LabelRank::ALL.len() * (usize::from(Units::MAX) + 1)
}

fn key_bit(key: Key) -> u8 {
    key.atom().bit()
}

fn only(key: Key, slot: Option<Entry>) -> Section {
    let mut s = Section::EMPTY;
    s.set(key, slot);
    s
}

#[test]
fn the_slot_domain_is_the_one_the_constants_describe() {
    assert_eq!(all_slots().len(), slot_count());
    assert_eq!(slot_count(), 193);
    assert_eq!(View::all().count(), 8 * LabelRank::ALL.len());
}

#[test]
fn scope_subset_matches_production_over_every_scope_pair() {
    let mut n = 0;
    for a in Scope::all() {
        for b in Scope::all() {
            assert_eq!(
                a.is_subset_of(b),
                extracted::view::scope_subset(a.bits(), b.bits()),
                "{a:?} ⊆ {b:?}"
            );
            n += 1;
        }
    }
    assert_eq!(n, 64);
}

#[test]
fn restrict_matches_extracted_over_every_view_pair() {
    let mut n = 0;
    for v in View::all() {
        for narrower in View::all() {
            let production = restrict(v, narrower);
            let admits = extracted::view::restrict_admits(
                v.scope.bits(),
                v.ceiling.rank(),
                narrower.scope.bits(),
                narrower.ceiling.rank(),
            );
            assert_eq!(
                production.is_some(),
                admits,
                "restrict({v:?}, {narrower:?})"
            );
            if let Some(r) = production {
                assert_eq!(r, narrower, "restrict returns the narrower view itself");
            }
            n += 1;
        }
    }
    assert_eq!(n, 24 * 24);
}

#[test]
fn observe_matches_extracted_over_every_view_key_and_slot() {
    let mut n = 0;
    for view in View::all() {
        for key in Key::ALL {
            for slot in all_slots() {
                let seen = observe(&only(key, slot), view);
                let expected = extracted::observe::observe_slot(
                    view.scope.bits(),
                    view.ceiling.rank(),
                    key_bit(key),
                    flat(slot),
                );
                assert_eq!(flat(seen.get(key)), expected, "{view:?} {key:?} {slot:?}");
                for other in Key::ALL.into_iter().filter(|k| *k != key) {
                    assert_eq!(seen.get(other), None, "observe invents nothing");
                }
                n += 1;
            }
        }
    }
    assert_eq!(n, 24 * 4 * slot_count());
}

#[test]
fn compare_on_overlap_matches_extracted_over_every_slot_pair() {
    let mut n = 0;
    for key in Key::ALL {
        for a in all_slots() {
            for b in all_slots() {
                let production = compare_on_overlap(&only(key, a), &only(key, b));
                let agree = extracted::overlap::slots_agree(flat(a), flat(b));
                match production {
                    Overlap::Agree => assert!(agree, "{key:?} {a:?} {b:?}"),
                    Overlap::Conflict { key: k } => {
                        assert!(!agree, "{key:?} {a:?} {b:?}");
                        assert_eq!(k, key);
                    }
                }
                n += 1;
            }
        }
    }
    assert_eq!(n, 4 * slot_count() * slot_count());
}

fn flat_acc(acc: SlotAcc) -> extracted::assemble::FlatAcc {
    extracted::assemble::FlatAcc {
        slot: flat(acc.slot),
        touched: acc.touched,
        conflict: acc.conflict,
    }
}

#[test]
fn step_slot_matches_extracted_over_every_accumulator_and_patch() {
    let mut n = 0;
    for slot in all_slots() {
        for touched in [false, true] {
            for conflict in [false, true] {
                let acc = SlotAcc {
                    slot,
                    touched,
                    conflict,
                };
                for patch in all_slots() {
                    let production = flat_acc(step_slot(acc, patch));
                    let extracted = extracted::assemble::step_slot(flat_acc(acc), flat(patch));
                    assert_eq!(production, extracted, "{acc:?} + {patch:?}");
                    n += 1;
                }
            }
        }
    }
    assert_eq!(n, slot_count() * 4 * slot_count());
}

fn refusal_code(r: &Result<ValidCandidate, CandidateRefusal>) -> u8 {
    match r {
        Ok(_) => extracted::validate::SLOT_OK,
        Err(CandidateRefusal::KeyConflict { .. }) => extracted::validate::SLOT_CONFLICT,
        Err(CandidateRefusal::EntryDropped { .. }) => extracted::validate::SLOT_DROPPED,
        Err(CandidateRefusal::LabelLowered { .. }) => extracted::validate::SLOT_LOWERED,
        Err(CandidateRefusal::QuotaExceeded { .. }) => u8::MAX,
    }
}

#[test]
fn slot_check_matches_validate_candidate_over_every_base_merged_and_conflict() {
    let mut n = 0;
    let unlimited = Invariants { quota: u16::MAX };
    for key in Key::ALL {
        for conflict in [false, true] {
            for base in all_slots() {
                for merged in all_slots() {
                    let mut flags = [false; Key::ALL.len()];
                    for (k, f) in Key::ALL.into_iter().zip(flags.iter_mut()) {
                        *f = conflict && k == key;
                    }
                    let candidate = Candidate::for_test(
                        Snapshot::for_test(Version::GENESIS, only(key, base)),
                        only(key, merged),
                        flags,
                    );
                    let production = refusal_code(&validate_candidate(candidate, unlimited));
                    let extracted =
                        extracted::validate::slot_check(conflict, flat(base), flat(merged));
                    assert_eq!(
                        production, extracted,
                        "{key:?} {conflict} {base:?} {merged:?}"
                    );
                    n += 1;
                }
            }
        }
    }
    assert_eq!(n, 4 * 2 * slot_count() * slot_count());
}

#[test]
fn the_quota_total_matches_extracted_over_every_presence_and_units_vector() {
    // The total depends only on presence and units, so this is every section up to
    // that equivalence: (absent | 0..=15)^4.
    let units_or_absent: Vec<Option<u8>> = std::iter::once(None)
        .chain((0..=Units::MAX).map(Some))
        .collect();
    let mut n = 0;
    for u0 in &units_or_absent {
        for u1 in &units_or_absent {
            for u2 in &units_or_absent {
                for u3 in &units_or_absent {
                    let mut section = Section::EMPTY;
                    let mut total: u16 = 0;
                    for (key, u) in Key::ALL.into_iter().zip([u0, u1, u2, u3]) {
                        let slot = u.map(|units| Entry {
                            value: ValueId::new(0).expect("in the model"),
                            label: LabelRank::Public,
                            units: Units::new(units).expect("in the model"),
                        });
                        section.set(key, slot);
                        total = extracted::validate::add_units(total, flat(slot));
                    }
                    for quota in [0, total.saturating_sub(1), total, total.saturating_add(1)] {
                        let candidate = Candidate::for_test(
                            Snapshot::for_test(Version::GENESIS, Section::EMPTY),
                            section,
                            [false; Key::ALL.len()],
                        );
                        let production = validate_candidate(candidate, Invariants { quota });
                        let admits = extracted::validate::quota_admits(total, quota);
                        match production {
                            Ok(_) => assert!(admits, "total {total} quota {quota}"),
                            Err(CandidateRefusal::QuotaExceeded { total: t, quota: q }) => {
                                assert!(!admits, "total {total} quota {quota}");
                                assert_eq!((t, q), (total, quota));
                            }
                            Err(other) => panic!("only the quota is in play here: {other:?}"),
                        }
                    }
                    n += 1;
                }
            }
        }
    }
    assert_eq!(n, 17 * 17 * 17 * 17);
}

#[test]
fn quota_admits_is_le_over_every_reachable_total_and_quota() {
    let max_total = u16::from(Units::MAX) * Key::ALL.len() as u16;
    let mut n = 0u64;
    for total in 0..=max_total {
        for quota in 0..=u16::MAX {
            assert_eq!(
                extracted::validate::quota_admits(total, quota),
                total <= quota
            );
            n += 1;
        }
    }
    assert_eq!(n, (u64::from(max_total) + 1) * 65536);
}

/// Epochs and instants at and around every boundary the comparison has.
const EPOCHS: [u32; 5] = [0, 1, 2, u32::MAX - 1, u32::MAX];
const INSTANTS: [u64; 5] = [0, 1, 2, u64::MAX - 1, u64::MAX];

fn binding(epoch: u32, not_after: u64) -> Binding {
    Binding {
        binding_id: 7,
        view: View {
            scope: Scope::FULL,
            ceiling: LabelRank::Secret,
        },
        base: Version::GENESIS,
        mode: Mode::Read,
        epoch: Epoch(epoch),
        not_after,
    }
}

fn admit_class(r: &Result<crate::AdmittedOp, AdmitRefusal>) -> u8 {
    match r {
        Ok(_) => extracted::admit::ADMITTED,
        Err(AdmitRefusal::ForeignEpoch { .. }) => extracted::admit::FOREIGN_EPOCH,
        Err(AdmitRefusal::Expired { .. }) => extracted::admit::EXPIRED,
    }
}

#[test]
fn admit_matches_extracted_over_every_boundary() {
    let mut n = 0;
    for be in EPOCHS {
        for ce in EPOCHS {
            for na in INSTANTS {
                for now in INSTANTS {
                    let production = admit_class(&admit(&binding(be, na), Epoch(ce), now));
                    assert_eq!(
                        production,
                        extracted::admit::admit_code(be, na, ce, now),
                        "epoch {be}/{ce} not_after {na} now {now}"
                    );
                    n += 1;
                }
            }
        }
    }
    assert_eq!(n, 625);
}

proptest::proptest! {
    #[test]
    fn admit_matches_extracted_over_the_full_range(
        be in proptest::prelude::any::<u32>(),
        ce in proptest::prelude::any::<u32>(),
        na in proptest::prelude::any::<u64>(),
        now in proptest::prelude::any::<u64>(),
    ) {
        let production = admit_class(&admit(&binding(be, na), Epoch(ce), now));
        proptest::prop_assert_eq!(production, extracted::admit::admit_code(be, na, ce, now));
        // And the same epoch, which a random pair almost never draws.
        let same = admit_class(&admit(&binding(be, na), Epoch(be), now));
        proptest::prop_assert_eq!(same, extracted::admit::admit_code(be, na, be, now));
    }
}

fn history_at(head: u8) -> History {
    let mut h = History::genesis();
    for _ in 0..head {
        let g = h.head();
        h.commit(ValidCandidate::for_test(Section::EMPTY, g))
            .expect("below capacity");
    }
    assert_eq!(h.head(), Version::new(head));
    h
}

#[test]
fn commit_matches_extracted_over_every_generation_and_head() {
    let capacity = u8::try_from(History::CAPACITY).expect("capacity fits a u8");
    let mut n = 0;
    for head in 0..capacity {
        for generation in 0..=u8::MAX {
            let mut h = history_at(head);
            let production = match h.commit(ValidCandidate::for_test(
                Section::EMPTY,
                Version::new(generation),
            )) {
                Ok(v) => {
                    assert_eq!(v.number(), head + 1);
                    extracted::commit::COMMITTED
                }
                Err(crate::CommitRefusal::StaleBase { .. }) => extracted::commit::STALE_BASE,
                Err(crate::CommitRefusal::Full { .. }) => extracted::commit::FULL,
            };
            assert_eq!(
                production,
                extracted::commit::commit_code(generation, head, capacity),
                "generation {generation} head {head}"
            );
            n += 1;
        }
    }
    assert_eq!(n, History::CAPACITY * 256);
}

/// The bridge is injective on the slot domain, so a flat equality IS a production
/// equality — without this, the parity above could hide two production slots that
/// flatten alike.
#[test]
fn flat_is_injective_on_the_slot_domain() {
    let flats: Vec<FlatSlot> = all_slots().into_iter().map(flat).collect();
    for (i, a) in flats.iter().enumerate() {
        for (j, b) in flats.iter().enumerate() {
            assert_eq!(i == j, extracted::flat_slot_eq(*a, *b), "{a:?} {b:?}");
        }
    }
}
