use super::*;
use nucleus_decision_protocol::ArgsDigest;
use portcullis::Operation;

fn charge(policy: &crate::host_decide::SharedPodPolicy, dollars: u64) -> Result<(), String> {
    let charge = crate::upstreams::RegistryEntry::env(registered("model-api"))
        .with_call_charge(dollars * 1_000_000)
        .call_charge()
        .unwrap();
    let _permit = policy.lock().unwrap().authorize_effect(
        ArgsDigest::new([17; 32]),
        Operation::WebFetch,
        "https://upstream.invalid",
        1000,
        charge,
    )?;
    Ok(())
}

#[tokio::test]
async fn allocations_and_effects_use_one_balance_in_both_orders() {
    for allocation_first in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let auth = authority(dir.path(), args());
        let parent = Uuid::new_v4();
        auth.admit_kept(&by(MINTER), &spec_with(lattice(5)), parent)
            .await
            .unwrap();
        // Also cover policy creation after the child already exists.
        if allocation_first {
            auth.admit_kept(&from_pod(parent), &spec_with(lattice(3)), Uuid::new_v4())
                .await
                .unwrap();
        }
        let policy = auth.host_policy(parent).await.unwrap();
        if allocation_first {
            assert!(charge(&policy, 3).is_err());
            charge(&policy, 2).unwrap();
        } else {
            charge(&policy, 3).unwrap();
            assert!(
                auth.admit_kept(&from_pod(parent), &spec_with(lattice(3)), Uuid::new_v4())
                    .await
                    .is_err()
            );
            auth.admit_kept(&from_pod(parent), &spec_with(lattice(2)), Uuid::new_v4())
                .await
                .unwrap();
        }
        assert!(charge(&policy, 1).is_err());
        let held = auth.held().await;
        let ledger = held.pods[&parent].ledger;
        assert_eq!(ledger.consumed + ledger.allocated, ledger.max);
    }
}

#[tokio::test]
async fn broker_spending_survives_restart_without_double_counting_retired_children() {
    for retirement_order in [0, 1, 2] {
        let dir = tempfile::tempdir().unwrap();
        let auth = authority(dir.path(), args());
        let parent = Uuid::new_v4();
        auth.admit_kept(&by(MINTER), &spec_with(lattice(5)), parent)
            .await
            .unwrap();
        let child = Uuid::new_v4();
        auth.admit_kept(&from_pod(parent), &spec_with(lattice(1)), child)
            .await
            .unwrap();
        let policy = auth.host_policy(parent).await.unwrap();
        if retirement_order == 1 {
            auth.release_child(child).await;
        }
        charge(&policy, 2).unwrap();
        if retirement_order == 2 {
            auth.release_child(child).await;
        }
        let restarted = authority(dir.path(), args());
        restarted.restore_from_disk().await;
        assert!(
            restarted.host_policy(parent).await.is_err(),
            "budget recovery alone cannot recover taint"
        );
        assert!(
            restarted
                .admit_kept(&from_pod(parent), &spec_with(lattice(3)), Uuid::new_v4())
                .await
                .is_err()
        );
        restarted
            .admit_kept(&from_pod(parent), &spec_with(lattice(2)), Uuid::new_v4())
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_child_admission_and_broker_commit_cannot_both_take_the_same_balance() {
    let dir = tempfile::tempdir().unwrap();
    let auth = std::sync::Arc::new(authority(dir.path(), args()));
    let parent = Uuid::new_v4();
    auth.admit_kept(&by(MINTER), &spec_with(lattice(5)), parent)
        .await
        .unwrap();
    let policy = auth.host_policy(parent).await.unwrap();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let other = barrier.clone();
    let worker = tokio::spawn(async move {
        other.wait().await;
        charge(&policy, 3).is_ok()
    });
    barrier.wait().await;
    let admitted = auth
        .admit_kept(&from_pod(parent), &spec_with(lattice(3)), Uuid::new_v4())
        .await
        .is_ok();
    assert_ne!(admitted, worker.await.unwrap());
}

#[tokio::test]
async fn unspawned_child_returns_balance_to_broker_but_exited_child_does_not() {
    for unspawned in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let auth = authority(dir.path(), args());
        let parent = Uuid::new_v4();
        auth.admit_kept(&by(MINTER), &spec_with(lattice(5)), parent)
            .await
            .unwrap();
        let policy = auth.host_policy(parent).await.unwrap();
        let child = Uuid::new_v4();
        let issued = auth
            .admit(&from_pod(parent), &spec_with(lattice(3)), child)
            .await
            .unwrap();
        assert!(charge(&policy, 4).is_err());
        if unspawned {
            issued.reservation.release().await;
        } else {
            issued.reservation.commit();
            auth.release_child(child).await;
        }
        assert_eq!(charge(&policy, 4).is_ok(), unspawned);
    }
}

#[tokio::test]
async fn child_allocation_after_preflight_is_rechecked_before_authorization() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let parent = Uuid::new_v4();
    auth.admit_kept(&by(MINTER), &spec_with(lattice(5)), parent)
        .await
        .unwrap();
    let policy = auth.host_policy(parent).await.unwrap();
    let tariff = crate::upstreams::RegistryEntry::env(registered("model-api"))
        .with_call_charge(2_000_000)
        .call_charge()
        .unwrap();
    policy
        .lock()
        .unwrap()
        .preflight_effect(
            ArgsDigest::new([17; 32]),
            Operation::WebFetch,
            "https://upstream.invalid",
            1000,
            tariff,
        )
        .unwrap();
    auth.admit_kept(&from_pod(parent), &spec_with(lattice(4)), Uuid::new_v4())
        .await
        .unwrap();
    assert!(charge(&policy, 2).is_err());
    let log = dir
        .path()
        .join("pods")
        .join(parent.to_string())
        .join(nucleus_spec::host_effect::LOG_FILE);
    assert!(
        std::fs::read(log).unwrap().is_empty(),
        "no authorization was issued"
    );
    charge(&policy, 1).unwrap();
}
