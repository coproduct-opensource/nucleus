//! #2905: a child's egress ceiling is the meet of what it declared and what its parent's chain
//! has left, and every byte a child sends is spent by each of its ancestors too.

use super::*;
use crate::egress_meter::EgressMeter;
use nucleus_spec::{EgressBudgetSpec, NetworkSpec};
use std::sync::Arc;

/// A spec with a network section whose `egress` is `max_bytes` (or undeclared).
fn spec_egress(max_bytes: Option<u64>) -> PodSpec {
    let mut spec = spec_with(lattice(1));
    let mut network = NetworkSpec::nothing_listed();
    network.egress = max_bytes.map(|max_bytes| EgressBudgetSpec {
        max_bytes,
        rate: None,
    });
    spec.spec.network = Some(network);
    spec
}

/// The meter a driver builds for `pod`: over the chain its admission issued.
async fn meter_of(auth: &PodAuthority, pod: Uuid, dir: &Path) -> Arc<EgressMeter> {
    EgressMeter::for_pod(
        auth.egress_chain(pod)
            .await
            .expect("an admitted pod has an egress chain"),
        dir.join("pods").join(pod.to_string()),
        pod,
        crate::egress_meter::test_authority().egress_record_signer(),
    )
}

/// Send `bytes` through `meter`, now.
async fn send(meter: &Arc<EgressMeter>, bytes: u64) -> Result<(), portcullis::EgressRefusal> {
    meter
        .admit(bytes, 0)
        .await
        .map(crate::egress_meter::EgressCharge::sent)
}

/// A root pod with `max_bytes` of egress and cost enough for every child these tests make:
/// the cost ledger is not what they are about.
async fn root_pod(auth: &PodAuthority, max_bytes: u64) -> Uuid {
    let pod = Uuid::new_v4();
    let mut spec = spec_egress(Some(max_bytes));
    spec.spec.policy = PolicySpec::Inline {
        lattice: Box::new(lattice(100)),
    };
    auth.admit_kept(&by(MINTER), &spec, pod)
        .await
        .expect("the root minter admits");
    pod
}

fn refused_for_egress(result: &Result<IssuedAuthority, ApiError>) -> bool {
    matches!(result, Err(ApiError::Authority(m)) if m.contains("egress conservation"))
}

/// The defect: admission never read a child's `network.egress`, so a child declared more
/// than its parent held and its meter enforced the larger number.
#[tokio::test]
async fn a_child_declaring_more_egress_than_its_parent_has_left_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let parent = root_pod(&auth, 1_000).await;

    let greedy = auth
        .admit_kept(&from_pod(parent), &spec_egress(Some(5_000)), Uuid::new_v4())
        .await;
    assert!(refused_for_egress(&greedy), "got {greedy:?}");
    assert!(
        matches!(&greedy, Err(ApiError::Authority(m)) if m.contains("5000") && m.contains("1000")),
        "the refusal names both numbers: {greedy:?}"
    );

    // Exactly what is left fits.
    let issued = auth
        .admit_kept(&from_pod(parent), &spec_egress(Some(1_000)), Uuid::new_v4())
        .await
        .expect("the parent's whole remaining");
    assert_eq!(issued.egress.max_bytes(), 1_000);
}

/// A child that declared nothing asked for no amount: it is met with what is left, and the
/// spec the node delivers records the clamp.
#[tokio::test]
async fn an_undeclared_child_is_met_with_its_parents_remaining_and_the_clamp_is_delivered() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let parent = root_pod(&auth, 1_000).await;
    let child = Uuid::new_v4();
    let mut spec = spec_egress(None);
    let issued = auth
        .admit_kept(&from_pod(parent), &spec, child)
        .await
        .expect("an undeclared child is admitted");
    assert_eq!(
        issued.egress.max_bytes(),
        1_000,
        "met, not the 1 GiB default"
    );
    issued.apply_to(&mut spec).commit();
    assert_eq!(
        spec.spec.network.as_ref().and_then(|n| n.egress),
        Some(EgressBudgetSpec {
            max_bytes: 1_000,
            rate: None
        }),
        "the delivered spec records the clamp"
    );

    let meter = meter_of(&auth, child, dir.path()).await;
    send(&meter, 1_000).await.expect("what it was admitted");
    assert!(send(&meter, 1).await.is_err(), "and no more");

    // A root pod that declared nothing keeps the finite default, unclamped.
    let mut root_spec = spec_egress(None);
    let issued = auth
        .admit_kept(&by(MINTER), &root_spec, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(issued.egress, portcullis::EgressCeiling::undeclared());
    issued.apply_to(&mut root_spec).commit();
    assert_eq!(root_spec.spec.network.and_then(|n| n.egress), None);
}

/// Every byte a child sends is charged to its parent too, so the parent's own sends and its
/// later children see what is left.
#[tokio::test]
async fn a_childs_bytes_deplete_its_parent() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let parent = root_pod(&auth, 1_000).await;
    let child = Uuid::new_v4();
    auth.admit_kept(&from_pod(parent), &spec_egress(Some(600)), child)
        .await
        .unwrap();
    assert_eq!(auth.egress_remaining(parent).await, Some(1_000));

    let child_meter = meter_of(&auth, child, dir.path()).await;
    send(&child_meter, 600).await.expect("the child's own 600");
    assert_eq!(auth.egress_remaining(child).await, Some(0));
    assert_eq!(
        auth.egress_remaining(parent).await,
        Some(400),
        "the child's bytes are the parent's"
    );

    let late = auth
        .admit_kept(&from_pod(parent), &spec_egress(Some(500)), Uuid::new_v4())
        .await;
    assert!(refused_for_egress(&late), "got {late:?}");

    let parent_meter = meter_of(&auth, parent, dir.path()).await;
    send(&parent_meter, 400)
        .await
        .expect("the parent's own sends have what is left");
    assert!(send(&parent_meter, 1).await.is_err(), "and nothing more");
}

/// A restart hands no bytes back: the parent's remaining after it is what it was, less at most
/// one checkpoint step it never spent.
#[tokio::test]
async fn a_restart_preserves_a_parents_remaining_egress() {
    const CEILING: u64 = 256 * 100;
    const STEP: u64 = CEILING / egress::CHECKPOINT_STEPS;
    let dir = tempfile::tempdir().unwrap();
    let parent;
    let before = {
        let auth = authority(dir.path(), args());
        parent = root_pod(&auth, CEILING).await;
        let child = Uuid::new_v4();
        auth.admit_kept(&from_pod(parent), &spec_egress(Some(10_000)), child)
            .await
            .unwrap();
        send(&meter_of(&auth, parent, dir.path()).await, 6_000)
            .await
            .unwrap();
        send(&meter_of(&auth, child, dir.path()).await, 4_000)
            .await
            .unwrap();
        let before = auth.egress_remaining(parent).await.unwrap();
        assert_eq!(before, CEILING - 10_000, "non-vacuity: both sends charged");
        before
    };

    let auth = authority(dir.path(), args());
    assert_eq!(auth.restore_from_disk().await, 2);
    let after = auth
        .egress_remaining(parent)
        .await
        .expect("restored with its account");
    assert!(
        after <= before,
        "a restart handed back {} bytes",
        after - before
    );
    assert!(
        before - after <= STEP,
        "a restart cost {} bytes, more than one step ({STEP})",
        before - after
    );
    let greedy = auth
        .admit_kept(
            &from_pod(parent),
            &spec_egress(Some(after + 1)),
            Uuid::new_v4(),
        )
        .await;
    assert!(refused_for_egress(&greedy), "got {greedy:?}");
    auth.admit_kept(&from_pod(parent), &spec_egress(Some(after)), Uuid::new_v4())
        .await
        .expect("what is left after the restart");
}

/// A grandchild is met with the least its chain has left — its parent's AND its
/// grandparent's — and its bytes are spent by both.
#[tokio::test]
async fn a_grandchild_meets_its_parent_and_grandparent() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let grandparent = root_pod(&auth, 1_000).await;
    let parent = Uuid::new_v4();
    auth.admit_kept(&from_pod(grandparent), &spec_egress(Some(800)), parent)
        .await
        .unwrap();
    send(&meter_of(&auth, grandparent, dir.path()).await, 500)
        .await
        .unwrap();
    assert_eq!(auth.egress_remaining(grandparent).await, Some(500));
    assert_eq!(auth.egress_remaining(parent).await, Some(800));

    let greedy = auth
        .admit_kept(&from_pod(parent), &spec_egress(Some(600)), Uuid::new_v4())
        .await;
    assert!(
        refused_for_egress(&greedy),
        "800 left in the parent, 500 in the grandparent: got {greedy:?}"
    );
    let grandchild = Uuid::new_v4();
    auth.admit_kept(&from_pod(parent), &spec_egress(Some(500)), grandchild)
        .await
        .expect("the least of the chain");

    send(&meter_of(&auth, grandchild, dir.path()).await, 500)
        .await
        .unwrap();
    assert_eq!(auth.egress_remaining(grandparent).await, Some(0));
    assert_eq!(auth.egress_remaining(parent).await, Some(300));
    assert_eq!(auth.egress_remaining(grandchild).await, Some(0));
}

/// A pod whose parent's account did not survive a restart cannot rebuild its chain: what its
/// children send could no longer be charged upward, so it may not create any.
#[tokio::test]
async fn a_pod_whose_parent_was_not_restored_may_not_create_children() {
    let dir = tempfile::tempdir().unwrap();
    let parent = Uuid::new_v4();
    {
        let auth = authority(dir.path(), args());
        let grandparent = root_pod(&auth, 1_000).await;
        auth.admit_kept(&from_pod(grandparent), &spec_egress(Some(500)), parent)
            .await
            .unwrap();
        auth.release_child(grandparent).await;
    }
    let auth = authority(dir.path(), args());
    assert_eq!(auth.restore_from_disk().await, 1);
    let child = auth
        .admit_kept(&from_pod(parent), &spec_egress(Some(1)), Uuid::new_v4())
        .await;
    assert!(
        matches!(&child, Err(ApiError::Authority(m)) if m.contains("egress conservation") && m.contains("not restored")),
        "got {child:?}"
    );
}
