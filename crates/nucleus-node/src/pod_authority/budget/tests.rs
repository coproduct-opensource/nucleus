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
        },
        Checkpoint {
            version: 1,
            pod: Uuid::new_v4(),
            consumed_micro: 1,
        },
        Checkpoint {
            version: 1,
            pod,
            consumed_micro: 6_000_000,
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
