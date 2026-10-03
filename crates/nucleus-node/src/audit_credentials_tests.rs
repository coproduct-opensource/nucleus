//! #3160: what a pod's audit uploader is given to sign with.

use super::fake::{self, Behaviour, FakeMinter};
use super::*;

fn minter(behaviour: Behaviour) -> (Arc<FakeMinter>, Arc<dyn ScopedCredentialMinter>) {
    let fake = FakeMinter::new(behaviour);
    let dynamic: Arc<dyn ScopedCredentialMinter> = fake.clone();
    (fake, dynamic)
}

/// The minter is asked for exactly the resolved destination: the operator's bucket, under the
/// operator's prefix narrowed by the spec, and nothing wider. The grant carries that scope and the
/// credential minted for it, and the uploader's environment carries that credential.
#[tokio::test]
async fn the_minted_credential_names_only_the_resolved_prefix() {
    let (fake, minter) = minter(Behaviour::Mint);
    let ttl = credential_ttl(3600);
    let grant = admit(Some(fake::target()), Some(&minter))
        .expect("a minter is configured")
        .expect("a sink was asked for")
        .mint(ttl)
        .await
        .expect("minted");

    let asked = fake.asked();
    assert_eq!(asked.len(), 1, "one pod, one mint");
    let (scope, asked_ttl) = &asked[0];
    assert_eq!(*asked_ttl, ttl);
    assert_eq!(scope.bucket(), "operator-audit");
    assert_eq!(scope.prefix(), Some("nucleus/team-a"));
    assert_eq!(scope.endpoint(), None);
    assert_eq!(scope.region(), None);
    assert_eq!(scope.object_pattern(), "operator-audit/nucleus/team-a/*");
    assert_eq!(
        grant.scope(),
        scope,
        "the grant records what was minted for"
    );

    let env = grant.proxy_env();
    assert!(env.contains(&("AWS_ACCESS_KEY_ID", fake::MINTED_KEY_ID)));
    assert!(env.contains(&("AWS_SECRET_ACCESS_KEY", fake::MINTED_SECRET)));
    assert!(env.contains(&("AWS_SESSION_TOKEN", fake::MINTED_TOKEN)));
    assert!(env.contains(&("NUCLEUS_TOOL_PROXY_AUDIT_S3_BUCKET", "operator-audit")));
    assert!(env.contains(&("NUCLEUS_TOOL_PROXY_AUDIT_S3_PREFIX", "nucleus/team-a")));
}

/// No minter, no sink: a named refusal, and nothing to fall back on (ADR 0007 A, B).
#[test]
fn no_minter_is_a_named_refusal() {
    let refused = match admit(Some(fake::target()), None) {
        Ok(_) => panic!("no minter must refuse the sink"),
        Err(refused) => refused,
    };
    assert_eq!(
        refused,
        AuditGrantRefused::NoMinter {
            sink: "audit".to_string(),
            scope: "operator-audit/nucleus/team-a/*".to_string(),
        }
    );
    assert!(
        refused.to_string().contains("audit_sink.sink `audit`"),
        "{refused}"
    );
}

/// A pod with no audit sink needs no minter, and a configured minter is not asked.
#[test]
fn no_sink_asks_nothing() {
    assert!(matches!(admit(None, None), Ok(None)));
    let (fake, minter) = minter(Behaviour::Mint);
    assert!(matches!(admit(None, Some(&minter)), Ok(None)));
    assert!(fake.asked().is_empty());
}

/// A minter that fails, or returns a credential outliving the lifetime asked for, refuses the pod.
#[tokio::test]
async fn a_failed_or_standing_credential_is_refused() {
    for (behaviour, want) in [
        (Behaviour::Fail, "failed"),
        (Behaviour::Overlong, "outlives"),
    ] {
        let (_, minter) = minter(behaviour);
        let refused = admit(Some(fake::target()), Some(&minter))
            .expect("a minter is configured")
            .expect("a sink was asked for")
            .mint(credential_ttl(3600))
            .await
            .expect_err("refused");
        let msg = refused.to_string();
        assert!(msg.contains(want), "{msg}");
        assert!(msg.contains("audit_sink.sink `audit`"), "{msg}");
    }
}

/// The lifetime asked for is the pod's own, between the floor and the ceiling.
#[test]
fn the_credential_lifetime_is_the_pods_bounded() {
    assert_eq!(credential_ttl(3600), Duration::from_secs(3600));
    assert_eq!(credential_ttl(0), MIN_CREDENTIAL_TTL);
    assert_eq!(credential_ttl(u64::MAX), MAX_CREDENTIAL_TTL);
}
