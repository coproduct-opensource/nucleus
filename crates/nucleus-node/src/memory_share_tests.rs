//! `memory_share`'s tests: the grant's decision, attenuation, revocation and the registry file.
use super::*;

const NOW: u64 = 1_000;

/// A recorder that keeps every receipt (the signed sink is `memory_provisioning`'s tests').
fn keep(_: &FlowClaim<'_>) -> Result<(), ApiError> {
    Ok(())
}

fn tenant() -> TenantKey {
    TenantKey::of("spiffe://test.local/ns/system/sa/tenant-a")
}
fn holders(readers: &[Holder], writers: &[Holder], expiry: Expiry) -> Narrowing {
    Narrowing {
        readers: readers.iter().copied().collect(),
        writers: writers.iter().copied().collect(),
        expiry,
    }
}
fn registry() -> (tempfile::TempDir, Registry) {
    let dir = tempfile::tempdir().unwrap();
    let registry = Registry::load(dir.path()).unwrap();
    (dir, registry)
}

#[test]
fn a_grant_decides_access_by_named_lineage_and_tenant() {
    let (_dir, mut shares) = registry();
    let (reader, writer, stranger) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let grant = shares
        .mint(
            &tenant(),
            "team",
            "notes",
            holders(
                &[Holder::Lineage(reader)],
                &[Holder::Lineage(writer)],
                Expiry::UntilRevoked,
            ),
            NOW,
            &mut keep,
        )
        .unwrap();
    let access = |lineage| {
        shares
            .exercise(grant, &tenant(), lineage, "notes", NOW)
            .map(|e| e.access)
    };
    assert_eq!(access(writer), Ok(Access::ReadWrite));
    assert_eq!(access(reader), Ok(Access::Read));
    assert_eq!(
        access(stranger),
        Err(Refusal::NotNamed {
            grant,
            lineage: stranger
        })
    );
    // Another tenant presenting the id is told what an absent id is told.
    let other = TenantKey::of("spiffe://test.local/ns/system/sa/tenant-b");
    assert_eq!(
        shares
            .exercise(grant, &other, writer, "notes", NOW)
            .map(|e| e.access),
        Err(Refusal::Unknown(grant))
    );
    let absent = Uuid::new_v4();
    assert_eq!(
        shares
            .exercise(absent, &tenant(), writer, "notes", NOW)
            .map(|e| e.access),
        Err(Refusal::Unknown(absent))
    );
}

#[test]
fn the_tenant_root_holder_names_every_lineage_of_its_tenant_only() {
    let (_dir, mut shares) = registry();
    let grant = shares
        .mint(
            &tenant(),
            "team",
            "notes",
            holders(&[Holder::TenantRoot], &[], Expiry::UntilRevoked),
            NOW,
            &mut keep,
        )
        .unwrap();
    for _ in 0..3 {
        assert_eq!(
            shares
                .exercise(grant, &tenant(), Uuid::new_v4(), "notes", NOW)
                .map(|e| e.access),
            Ok(Access::Read)
        );
    }
}

#[test]
fn an_attenuated_grant_cannot_widen_its_parent() {
    let (_dir, mut shares) = registry();
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let parent = shares
        .mint(
            &tenant(),
            "team",
            "notes",
            holders(
                &[Holder::Lineage(b)],
                &[Holder::Lineage(a)],
                Expiry::At(NOW + 100),
            ),
            NOW,
            &mut keep,
        )
        .unwrap();
    let widen = |shares: &mut Registry, narrowing| {
        shares
            .attenuate(&tenant(), parent, narrowing, NOW, &mut keep)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default()
    };
    // A reader promoted to writer, a stranger added, the tenant root added, a longer life.
    assert!(
        widen(
            &mut shares,
            holders(&[], &[Holder::Lineage(b)], Expiry::At(NOW + 10))
        )
        .contains("as a writer")
    );
    assert!(
        widen(
            &mut shares,
            holders(
                &[Holder::Lineage(Uuid::new_v4())],
                &[],
                Expiry::At(NOW + 10)
            )
        )
        .contains("as a reader")
    );
    assert!(
        widen(
            &mut shares,
            holders(&[Holder::TenantRoot], &[], Expiry::At(NOW + 10))
        )
        .contains("as a reader")
    );
    assert!(
        widen(
            &mut shares,
            holders(&[Holder::Lineage(b)], &[], Expiry::UntilRevoked)
        )
        .contains("outlives the parent")
    );
    assert!(
        widen(
            &mut shares,
            holders(&[Holder::Lineage(b)], &[], Expiry::At(NOW + 101))
        )
        .contains("outlives the parent")
    );

    // Narrowing is honoured: the writer demoted to a reader, the other reader dropped.
    let child = shares
        .attenuate(
            &tenant(),
            parent,
            holders(&[Holder::Lineage(a)], &[], Expiry::At(NOW + 50)),
            NOW,
            &mut keep,
        )
        .unwrap();
    let access = |lineage| {
        shares
            .exercise(child, &tenant(), lineage, "notes", NOW)
            .map(|e| e.access)
    };
    assert_eq!(access(a), Ok(Access::Read));
    assert!(matches!(access(b), Err(Refusal::NotNamed { .. })));
    // And a child of the tenant-root grant may name one lineage: that narrows.
    let wide = shares
        .mint(
            &tenant(),
            "team",
            "notes",
            holders(&[], &[Holder::TenantRoot], Expiry::UntilRevoked),
            NOW,
            &mut keep,
        )
        .unwrap();
    assert!(
        shares
            .attenuate(
                &tenant(),
                wide,
                holders(&[], &[Holder::Lineage(b)], Expiry::UntilRevoked),
                NOW,
                &mut keep
            )
            .is_ok()
    );
}

#[test]
fn a_revoked_or_expired_grant_is_refused_by_name() {
    let (_dir, mut shares) = registry();
    let lineage = Uuid::new_v4();
    let expiring = shares
        .mint(
            &tenant(),
            "team",
            "notes",
            holders(&[], &[Holder::Lineage(lineage)], Expiry::At(NOW + 10)),
            NOW,
            &mut keep,
        )
        .unwrap();
    assert!(
        shares
            .exercise(expiring, &tenant(), lineage, "notes", NOW + 9)
            .is_ok()
    );
    assert_eq!(
        shares
            .exercise(expiring, &tenant(), lineage, "notes", NOW + 10)
            .map(|e| e.access),
        Err(Refusal::Expired {
            grant: expiring,
            at: NOW + 10
        })
    );
    let child = shares
        .attenuate(
            &tenant(),
            expiring,
            holders(&[Holder::Lineage(lineage)], &[], Expiry::At(NOW + 5)),
            NOW,
            &mut keep,
        )
        .unwrap();
    assert_eq!(shares.revoke(&tenant(), "team", NOW, &mut keep).unwrap(), 1);
    for grant in [expiring, child] {
        assert_eq!(
            shares
                .exercise(grant, &tenant(), lineage, "notes", NOW)
                .map(|e| e.access),
            Err(Refusal::Revoked {
                grant,
                share: "team".into(),
                issued: 0,
                current: 1
            })
        );
    }
    // A revoked grant is not a parent either.
    assert!(
        shares
            .attenuate(
                &tenant(),
                child,
                holders(&[Holder::Lineage(lineage)], &[], Expiry::At(NOW + 1)),
                NOW,
                &mut keep
            )
            .is_err()
    );
    // A grant minted after the revocation is live at the share's new epoch.
    let fresh = shares
        .mint(
            &tenant(),
            "team",
            "notes",
            holders(&[], &[Holder::Lineage(lineage)], Expiry::UntilRevoked),
            NOW,
            &mut keep,
        )
        .unwrap();
    assert_eq!(
        shares
            .exercise(fresh, &tenant(), lineage, "notes", NOW)
            .map(|e| e.epoch),
        Ok(1)
    );
}

#[test]
fn minting_refuses_what_a_grant_cannot_mean() {
    let (_dir, mut shares) = registry();
    let lineage = Holder::Lineage(Uuid::new_v4());
    let refused = |shares: &mut Registry, share: &str, namespace: &str, narrowing| {
        shares
            .mint(&tenant(), share, namespace, narrowing, NOW, &mut keep)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default()
    };
    assert!(
        refused(
            &mut shares,
            "team",
            "notes",
            holders(&[], &[], Expiry::UntilRevoked)
        )
        .contains("at least one")
    );
    assert!(
        refused(
            &mut shares,
            "team",
            "notes",
            holders(&[lineage], &[], Expiry::At(NOW))
        )
        .contains("in the future")
    );
    assert!(
        refused(
            &mut shares,
            "../team",
            "notes",
            holders(&[lineage], &[], Expiry::UntilRevoked)
        )
        .contains("ASCII")
    );
    shares
        .mint(
            &tenant(),
            "team",
            "notes",
            holders(&[lineage], &[], Expiry::UntilRevoked),
            NOW,
            &mut keep,
        )
        .unwrap();
    assert!(
        refused(
            &mut shares,
            "team",
            "other",
            holders(&[lineage], &[], Expiry::UntilRevoked)
        )
        .contains("serves namespace notes")
    );
    assert!(shares.revoke(&tenant(), "nobody", NOW, &mut keep).is_err());
}

#[test]
fn the_registry_survives_a_restart_and_refuses_a_malformed_file() {
    let (dir, mut shares) = registry();
    let lineage = Uuid::new_v4();
    let grant = shares
        .mint(
            &tenant(),
            "team",
            "notes",
            holders(&[], &[Holder::Lineage(lineage)], Expiry::UntilRevoked),
            NOW,
            &mut keep,
        )
        .unwrap();
    shares.revoke(&tenant(), "team", NOW, &mut keep).unwrap();
    let reloaded = Registry::load(dir.path()).unwrap();
    assert!(matches!(
        reloaded.exercise(grant, &tenant(), lineage, "notes", NOW),
        Err(Refusal::Revoked { .. })
    ));
    assert_eq!(reloaded.grants_of(&tenant()).len(), 1);
    std::fs::write(dir.path().join(REGISTRY_FILE), b"{\"schema\":\"other\"}").unwrap();
    assert!(Registry::load(dir.path()).is_err());
}

#[test]
fn migration_ids_are_derived_from_the_store() {
    let a = migration_grant_id(&tenant(), "notes");
    assert_eq!(a, migration_grant_id(&tenant(), "notes"));
    assert_ne!(a, migration_grant_id(&tenant(), "other"));
}

fn lose(_: &FlowClaim<'_>) -> Result<(), ApiError> {
    Err(ApiError::Driver("receipt sink unavailable".into()))
}

/// Durable evidence precedes the right: a mint, attenuation or revocation whose receipt was not
/// kept is undone, in memory and on disk.
#[test]
fn a_decision_whose_receipt_is_not_kept_does_not_take_effect() {
    let (dir, mut shares) = registry();
    let everyone = || holders(&[], &[Holder::TenantRoot], Expiry::UntilRevoked);
    assert!(
        shares
            .mint(&tenant(), "team", "notes", everyone(), NOW, &mut lose)
            .is_err()
    );
    assert!(shares.grants_of(&tenant()).is_empty());
    assert!(
        Registry::load(dir.path())
            .unwrap()
            .grants_of(&tenant())
            .is_empty()
    );
    let grant = shares
        .mint(&tenant(), "team", "notes", everyone(), NOW, &mut keep)
        .unwrap();
    let narrower = holders(&[Holder::TenantRoot], &[], Expiry::UntilRevoked);
    assert!(
        shares
            .attenuate(&tenant(), grant, narrower, NOW, &mut lose)
            .is_err()
    );
    assert_eq!(shares.grants_of(&tenant()).len(), 1);
    assert!(shares.revoke(&tenant(), "team", NOW, &mut lose).is_err());
    assert!(
        shares
            .exercise(grant, &tenant(), Uuid::new_v4(), "notes", NOW)
            .is_ok(),
        "a revocation whose receipt failed did not happen"
    );
}
