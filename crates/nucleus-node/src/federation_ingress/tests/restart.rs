//! A node killed with a federated pod registered settles that pod at its next start as the
//! pod's reaper would have: by the settle mode the pod was admitted under, against the spend the
//! host metered into its ledger before the kill (`pod_authority/previous_life.rs`).

use super::reload::{Live, ceiling, open_window, refused_with};
use super::*;
use crate::pod_authority::registry::ReloadOutcome;

/// The node's next life over the same state directory and registry file.
fn next_life(live: &Live) -> PodAuthority {
    let args = AuthorityArgs {
        root_minter_spiffe_id: None,
        cert_trust_anchors: Vec::new(),
        max_children_per_pod: 8,
        upstreams: Some(live.path.clone()),
        upstreams_poll_secs: 0,
        federation_issuer: None,
        ingress: FederationArgs::default(),
        approvals: crate::host_decide::effects::ApprovalTimingArgs::HUMAN,
    };
    PodAuthority::new(
        &args,
        NODE_TD,
        live.dir.path(),
        &crate::pod_authority::NO_TPM,
    )
    .unwrap()
}

/// What the node's startup does with the authority before it serves.
async fn start(auth: &PodAuthority) {
    auth.restore_from_disk().await;
    auth.release_previous_life().await;
}

#[tokio::test]
async fn a_metered_pod_left_by_a_killed_node_is_charged_what_it_metered() {
    use std::str::FromStr;
    let (from, until) = open_window();
    let live = Live::new(&ceiling(100, from, until), Some("5"));
    assert_eq!(live.settle("metered"), ReloadOutcome::Applied);
    let who = live.exchange().await.unwrap();
    let pod = live.admit(&who, 3).await.unwrap();
    live.st
        .authority
        .meter(pod, rust_decimal::Decimal::from_str("0.5").unwrap())
        .await
        .unwrap();
    // Killed here: the pod is never released by this life.

    let next = next_life(&live);
    start(&next).await;
    assert_eq!(
        live.ledger_file()["ledger"]["consumed_micro"],
        500_000,
        "the binding's ledger keeps what the pod metered, not its $3 allocation"
    );
    let fits = next
        .admit_kept(&who, &pod_spec(Vec::new(), 4), uuid::Uuid::new_v4())
        .await
        .map(|_| uuid::Uuid::nil());
    assert!(
        fits.is_ok(),
        "the day kept $0.5 of $5, so $4 fits: {fits:?}"
    );
    let over = next
        .admit_kept(&who, &pod_spec(Vec::new(), 1), uuid::Uuid::new_v4())
        .await
        .map(|_| uuid::Uuid::nil());
    assert!(refused_with(&over, "daily allowance"), "{over:?}");
}
