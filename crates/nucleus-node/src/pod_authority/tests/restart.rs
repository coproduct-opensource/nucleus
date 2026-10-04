//! A restart restores every ledger the authority held, exactly: what retired
//! children consumed and an external chain's ceiling included, which no live
//! child records. And a record that cannot be read is refused, not defaulted.

use super::*;

/// An authority over `dir` whose anchors include `ext_root`.
fn trusting(dir: &Path, ext_root: &Ed25519KeyPair) -> PodAuthority {
    let mut a = args();
    a.cert_trust_anchors = vec![hex::encode(ext_root.public_key().as_ref())];
    authority(dir, a)
}

/// The admission of a caller presenting a $`budget` chain rooted at
/// `ext_root`. One chain is one fingerprint: build it once per test.
fn chain_caller(ext_root: &Ed25519KeyPair, budget: u32) -> Admission {
    let caller = "spiffe://other.example/ns/agents/sa/orchestrator";
    let expiry = Utc::now() + Duration::hours(1);
    let (leaf, _k) = LatticeCertificate::mint(
        lattice(budget),
        caller.into(),
        expiry,
        ext_root,
        &ring::rand::SystemRandom::new(),
    );
    let token = AttenuationToken::seal(leaf, ext_root.public_key().as_ref().to_vec());
    Admission {
        caller_spiffe_id: caller.into(),
        caller_pod: None,
        header_cert: Some(token.to_base64().unwrap()),
    }
}

async fn held_ledgers(auth: &PodAuthority) -> (Vec<(Uuid, LedgerView)>, Vec<LedgerView>) {
    let held = auth.held().await;
    (
        held.pods.iter().map(|(id, p)| (*id, p.ledger)).collect(),
        held.external.values().copied().collect(),
    )
}

/// What retired children consumed is restored with the parent, so the
/// parent's remaining budget after a restart is what it was before.
#[tokio::test]
async fn a_restart_restores_what_retired_children_consumed() {
    let dir = tempfile::tempdir().unwrap();
    let parent = Uuid::new_v4();
    let before = {
        let auth = authority(dir.path(), args());
        auth.admit_kept(&by(MINTER), &spec_with(lattice(5)), parent)
            .await
            .unwrap();
        let done = Uuid::new_v4();
        auth.admit_kept(&from_pod(parent), &spec_with(lattice(3)), done)
            .await
            .unwrap();
        auth.admit_kept(&from_pod(parent), &spec_with(lattice(1)), Uuid::new_v4())
            .await
            .unwrap();
        auth.release_child(done).await;
        held_ledgers(&auth).await
    };
    let auth = authority(dir.path(), args());
    assert_eq!(auth.restore_from_disk().await, 2);
    assert_eq!(held_ledgers(&auth).await, before, "every ledger, exactly");
    // $5 - $3 consumed - $1 live: $1 left, not $4.
    assert!(
        auth.admit_kept(&from_pod(parent), &spec_with(lattice(2)), Uuid::new_v4())
            .await
            .is_err()
    );
    auth.admit_kept(&from_pod(parent), &spec_with(lattice(1)), Uuid::new_v4())
        .await
        .expect("the $1 that is left");
}

/// The same for an external caller's chain, whose ledger has no pod to be
/// persisted with: its ceiling and consumption are restored, not re-derived
/// from whatever children happen to be live.
#[tokio::test]
async fn a_restart_restores_an_external_chains_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let ext_root = ephemeral_key().unwrap();
    let chain = chain_caller(&ext_root, 4);
    let before = {
        let auth = trusting(dir.path(), &ext_root);
        let done = Uuid::new_v4();
        auth.admit_kept(&chain, &spec_with(lattice(3)), done)
            .await
            .unwrap();
        auth.release_child(done).await;
        held_ledgers(&auth).await
    };
    let auth = trusting(dir.path(), &ext_root);
    auth.restore_from_disk().await;
    assert_eq!(held_ledgers(&auth).await, before);
    assert!(
        auth.admit_kept(&chain, &spec_with(lattice(2)), Uuid::new_v4())
            .await
            .is_err(),
        "$4 - $3 consumed leaves $1"
    );
}

/// A release writes the parent's record before removing the child's file.
/// Interrupted between the two, the child is restored neither live nor
/// twice: its parent names it as retired.
#[tokio::test]
async fn a_child_its_parent_retired_is_not_restored() {
    let dir = tempfile::tempdir().unwrap();
    let parent = Uuid::new_v4();
    let child = Uuid::new_v4();
    let before = {
        let auth = authority(dir.path(), args());
        auth.admit_kept(&by(MINTER), &spec_with(lattice(5)), parent)
            .await
            .unwrap();
        auth.admit_kept(&from_pod(parent), &spec_with(lattice(3)), child)
            .await
            .unwrap();
        let kept = std::fs::read(auth.authority_path(child)).unwrap();
        auth.release_child(child).await;
        std::fs::write(auth.authority_path(child), kept).unwrap();
        held_ledgers(&auth).await
    };
    let auth = authority(dir.path(), args());
    assert_eq!(auth.restore_from_disk().await, 1, "the parent alone");
    assert_eq!(held_ledgers(&auth).await, before);
    assert!(
        !auth.authority_path(child).exists(),
        "and the leftover is removed"
    );
}

/// A chain ledger that cannot be read refuses that chain rather than
/// starting it from zero.
#[tokio::test]
async fn an_unreadable_chain_ledger_refuses_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let ext_root = ephemeral_key().unwrap();
    let chain = chain_caller(&ext_root, 4);
    {
        let auth = trusting(dir.path(), &ext_root);
        auth.admit_kept(&chain, &spec_with(lattice(1)), Uuid::new_v4())
            .await
            .unwrap();
    }
    let records: Vec<_> = std::fs::read_dir(dir.path().join("authority/external"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(records.len(), 1, "{records:?}");
    std::fs::remove_file(&records[0]).unwrap();
    std::fs::write(&records[0], b"{\"version\":1,").unwrap();

    let auth = trusting(dir.path(), &ext_root);
    auth.restore_from_disk().await;
    assert!(matches!(
        auth.admit_kept(&chain, &spec_with(lattice(0)), Uuid::new_v4()).await,
        Err(ApiError::Authority(m)) if m.contains("could not restore")
    ));
    auth.admit_kept(&by(MINTER), &spec_with(lattice(1)), Uuid::new_v4())
        .await
        .expect("the root minter holds no ledger and is unaffected");
}

/// A pod record that cannot be read cannot say whose child it was, so no
/// delegated admission is charged until it is resolved.
#[tokio::test]
async fn an_unreadable_pod_record_refuses_delegated_admission() {
    let dir = tempfile::tempdir().unwrap();
    let ext_root = ephemeral_key().unwrap();
    let parent = Uuid::new_v4();
    let child = Uuid::new_v4();
    {
        let auth = trusting(dir.path(), &ext_root);
        auth.admit_kept(&by(MINTER), &spec_with(lattice(5)), parent)
            .await
            .unwrap();
        auth.admit_kept(&from_pod(parent), &spec_with(lattice(1)), child)
            .await
            .unwrap();
        let path = auth.authority_path(child);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"not json").unwrap();
    }
    let auth = trusting(dir.path(), &ext_root);
    assert_eq!(auth.restore_from_disk().await, 1);
    for who in [from_pod(parent), chain_caller(&ext_root, 4)] {
        assert!(matches!(
            auth.admit_kept(&who, &spec_with(lattice(0)), Uuid::new_v4()).await,
            Err(ApiError::Authority(m)) if m.contains("could not restore")
        ));
    }
    auth.admit_kept(&by(MINTER), &spec_with(lattice(1)), Uuid::new_v4())
        .await
        .expect("the root minter is unaffected");
}

/// Records are written whole: no temporary file is left beside them.
#[tokio::test]
async fn a_record_is_written_whole_and_owner_read_only() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let pod = Uuid::new_v4();
    auth.admit_kept(&by(MINTER), &spec_with(lattice(1)), pod)
        .await
        .unwrap();
    let path = auth.authority_path(pod);
    let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, vec![std::ffi::OsString::from(AUTHORITY_FILE)]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o400);
    }
}
