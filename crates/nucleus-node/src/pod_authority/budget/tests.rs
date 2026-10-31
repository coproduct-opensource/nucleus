use super::*;
fn ledger() -> BudgetLedger {
    BudgetLedger::for_parent(&portcullis::BudgetLattice::with_cost_limit(5.0))
}

#[test]
fn failed_evidence_never_debits_or_runs_when_unaffordable() {
    let budget = SharedBudget::memory(ledger());
    assert!(
        budget
            .commit::<()>(Decimal::ONE, || Err::<(), _>("failed evidence".into()))
            .is_err()
    );
    assert_eq!(budget.available().unwrap(), Decimal::from(5));
    assert!(
        budget
            .commit::<()>(Decimal::from(6), || panic!(
                "unaffordable evidence must not run"
            ))
            .is_err()
    );
    budget.commit::<()>(Decimal::from(5), || Ok(())).unwrap();
    assert_eq!(budget.available().unwrap(), Decimal::ZERO);
}

#[test]
fn checkpoint_failure_latches_both_effect_and_delegation_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let pod = Uuid::new_v4();
    let budget = SharedBudget::new(ledger(), pod, dir.path());
    std::fs::create_dir(dir.path().join("budget-consumption.json")).unwrap();
    assert!(
        budget
            .commit::<()>(Decimal::ONE, || Ok(()))
            .unwrap_err()
            .contains("checkpoint failed")
    );
    std::fs::remove_dir(dir.path().join("budget-consumption.json")).unwrap();
    assert!(
        budget
            .commit::<()>(Decimal::ONE, || panic!("latched failure"))
            .is_err()
    );
    assert!(budget.try_allocate(1, Decimal::ONE).is_err());
    assert!(budget.snapshot().is_err());
}

#[test]
fn bad_or_absent_checkpoint_never_resets_runtime_history() {
    let dir = tempfile::tempdir().unwrap();
    let pod = Uuid::new_v4();
    assert!(SharedBudget::restore(ledger(), pod, dir.path()).is_ok());
    std::fs::write(
        dir.path().join(nucleus_spec::host_effect::LOG_FILE),
        "old runtime history",
    )
    .unwrap();
    assert!(SharedBudget::restore(ledger(), pod, dir.path()).is_err());
    let path = dir.path().join("budget-consumption.json");
    for record in [
        Checkpoint {
            version: 2,
            pod,
            consumed_micro: 1,
            overrun_micro: 0,
        },
        Checkpoint {
            version: 1,
            pod: Uuid::new_v4(),
            consumed_micro: 1,
            overrun_micro: 0,
        },
        Checkpoint {
            version: 1,
            pod,
            consumed_micro: 6_000_000,
            overrun_micro: 0,
        },
    ] {
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(SharedBudget::restore(ledger(), pod, dir.path()).is_err());
    }
    std::fs::write(&path, "{").unwrap();
    assert!(SharedBudget::restore(ledger(), pod, dir.path()).is_err());
}

#[test]
fn poisoned_shared_ledger_cannot_admit_or_spend() {
    let budget = SharedBudget::memory(ledger());
    let other = budget.clone();
    assert!(
        std::thread::spawn(move || {
            let _lock = other.state.lock().unwrap();
            panic!("poison");
        })
        .join()
        .is_err()
    );
    assert!(budget.try_allocate(1, Decimal::ONE).is_err());
    assert!(
        budget
            .commit::<()>(Decimal::ONE, || panic!("poisoned evidence"))
            .is_err()
    );
}

/// 2026-10-31: holds are taken under the one lock, so concurrent calls cannot
/// reserve more than the balance between them. $5 fits three $1.5 holds.
#[test]
fn concurrent_holds_cannot_reserve_past_the_balance() {
    let budget = SharedBudget::memory(ledger());
    let admitted: usize = (0..8)
        .map(|_| {
            let budget = budget.clone();
            std::thread::spawn(move || {
                budget
                    .commit_holding::<()>(Decimal::ZERO, 1_500_000, || Ok(()))
                    .is_ok()
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|t| usize::from(t.join().unwrap()))
        .sum();
    assert_eq!(admitted, 3);
    assert_eq!(budget.held_micro().unwrap(), 4_500_000);
    assert_eq!(budget.available().unwrap(), Decimal::new(5, 1));
    // A child cannot take what the calls hold.
    assert!(budget.try_allocate(1, Decimal::ONE).is_err());
    for _ in 0..3 {
        budget.settle(1_500_000, 100).unwrap();
    }
    assert_eq!(budget.held_micro().unwrap(), 0);
    assert_eq!(
        budget.snapshot().unwrap().core().parent_consumed_units(),
        300
    );
    assert!(
        budget.settle(1, 0).is_err(),
        "a hold never reserved is refused"
    );
}

/// The checkpoint carries consumed plus held, so a node that dies mid-call
/// restores with that call charged its ceiling; an overrun survives a restore.
#[test]
fn a_restore_charges_held_calls_and_keeps_an_overrun() {
    let dir = tempfile::tempdir().unwrap();
    let pod = Uuid::new_v4();
    let budget = SharedBudget::new(ledger(), pod, dir.path());
    budget
        .commit_holding::<()>(Decimal::ZERO, 2_000_000, || Ok(()))
        .unwrap();
    let restored = SharedBudget::restore(ledger(), pod, dir.path()).unwrap();
    assert_eq!(restored.available().unwrap(), Decimal::from(3));
    // Hold 1, charge 4.5: 3.5 beyond the hold. With 2 still held, the checkpoint
    // is capped at the maximum so a restore still reads it.
    budget
        .commit_holding::<()>(Decimal::ZERO, 1_000_000, || Ok(()))
        .unwrap();
    budget.settle(1_000_000, 4_500_000).unwrap();
    assert_eq!(budget.overrun_micro().unwrap(), 3_500_000);
    assert_eq!(
        budget.available().unwrap(),
        Decimal::ZERO,
        "the pod is exhausted"
    );
    budget.settle(2_000_000, 0).unwrap();
    let restored = SharedBudget::restore(ledger(), pod, dir.path()).unwrap();
    assert_eq!(restored.overrun_micro().unwrap(), 3_500_000);
}
