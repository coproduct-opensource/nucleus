//! Program C, C0: the bare tier is a declared insecure mode.

use super::*;

#[cfg(feature = "local-driver")]
fn no_env(_: &str) -> Option<String> {
    None
}

/// Every trusted authority, in order.
#[cfg(feature = "local-driver")]
const ALL: &[TrustedAuthority] = &[
    TrustedAuthority::FederationIssuer,
    TrustedAuthority::FederationExchange,
    TrustedAuthority::CredentialedUpstreams,
    TrustedAuthority::CertTrustAnchors,
    TrustedAuthority::NodeEvidenceTpm,
    TrustedAuthority::NodeEvidenceSoftwareTpm,
    TrustedAuthority::NodeEvidenceReference,
    TrustedAuthority::NodeEvidenceAkPin,
    TrustedAuthority::PublicEvidence,
    TrustedAuthority::DecisionTrustRoots,
    TrustedAuthority::AuditSinks,
    TrustedAuthority::AuditMinter,
    TrustedAuthority::TrustApiUrl,
    TrustedAuthority::TrustReceiptSecret,
    TrustedAuthority::TrustExecutorId,
];

/// A case: an authority's place in [`ALL`], and the flags and environment
/// that configure it.
#[cfg(feature = "local-driver")]
type Case = (usize, Vec<&'static str>, Vec<(&'static str, &'static str)>);

/// The case for `authority`. Exhaustive with no `_` arm: a new authority does
/// not compile until it has a case here, and the index ties that case to
/// [`ALL`].
#[cfg(feature = "local-driver")]
fn case(authority: TrustedAuthority) -> Case {
    use TrustedAuthority as T;
    match authority {
        T::FederationIssuer => (
            0,
            vec!["--federation-issuer", "https://issuer.example"],
            vec![],
        ),
        T::FederationExchange => (1, vec!["--federation-listen", "127.0.0.1:0"], vec![]),
        T::CredentialedUpstreams => (
            2,
            vec!["--upstreams", "/nonexistent/upstreams.toml"],
            vec![],
        ),
        T::CertTrustAnchors => (3, vec!["--cert-trust-anchors", "00"], vec![]),
        T::NodeEvidenceTpm => (4, vec!["--node-evidence-tpm", "/dev/tpmrm0"], vec![]),
        T::NodeEvidenceSoftwareTpm => (
            5,
            vec!["--node-evidence-software-tpm", "127.0.0.1:2321"],
            vec![],
        ),
        T::NodeEvidenceReference => (
            6,
            vec!["--node-evidence-reference", "/nonexistent/reference.json"],
            vec![],
        ),
        // The pin requires a reference, which is refused beside it.
        T::NodeEvidenceAkPin => (
            7,
            vec![
                "--node-evidence-reference",
                "/nonexistent/reference.json",
                "--node-evidence-ak-pin",
                "00",
            ],
            vec![],
        ),
        T::PublicEvidence => (8, vec!["--public-evidence-addr", "127.0.0.1:0"], vec![]),
        T::DecisionTrustRoots => (
            9,
            vec![
                "--decision-trust-roots",
                "/nonexistent/roots.json",
                "--decision-tenant",
                "github~owner~name",
                "--decision-bundles",
                "/nonexistent/bundles",
            ],
            vec![],
        ),
        T::AuditSinks => (10, vec!["--audit-sinks", "/nonexistent/sinks.toml"], vec![]),
        T::AuditMinter => (
            11,
            vec!["--audit-minter-socket", "/nonexistent/minter.sock"],
            vec![],
        ),
        T::TrustApiUrl => (12, vec![], vec![("TRUST_API_URL", "https://trust.example")]),
        T::TrustReceiptSecret => (13, vec![], vec![("TRUST_RECEIPT_SECRET", "c2VjcmV0")]),
        T::TrustExecutorId => (
            14,
            vec![],
            vec![("TRUST_EXECUTOR_ID", "nucleus-executor/0011")],
        ),
    }
}

#[cfg(feature = "local-driver")]
fn parse(driver: &str, allow: bool, extra: &[&str]) -> crate::Args {
    let mut argv = vec!["nucleus-node", "--driver", driver];
    if allow {
        argv.push("--allow-local-driver");
    }
    argv.extend_from_slice(extra);
    <crate::Args as clap::Parser>::try_parse_from(argv).expect("the flags parse")
}

#[cfg(feature = "local-driver")]
fn tier_of(args: &crate::Args) -> EvidenceTier {
    EvidenceTier::of(crate::local_driver_opt_in(
        &args.driver,
        args.allow_local_driver,
    ))
}

/// A node with the local driver allowed refuses to start with each trusted
/// authority, and the refusal names its flag. The same configuration on a
/// separating driver is not refused here.
#[cfg(feature = "local-driver")]
#[test]
fn a_local_driver_node_refuses_to_start_with_each_trusted_authority_by_name() {
    for (index, &authority) in ALL.iter().enumerate() {
        let (at, flags, env) = case(authority);
        assert_eq!(at, index, "{authority:?} is not at its place in ALL");
        let lookup = |name: &str| {
            env.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_string())
        };
        let insecure = parse("local", true, &flags);
        assert_eq!(tier_of(&insecure), EvidenceTier::InsecureSharedUid);
        let found = configured(&insecure, lookup);
        assert!(
            found.contains(&authority),
            "{authority:?} not found: {found:?}"
        );
        assert!(
            found.iter().all(|f| *f == authority
                || (authority == TrustedAuthority::NodeEvidenceAkPin
                    && *f == TrustedAuthority::NodeEvidenceReference)),
            "{authority:?}'s flags configured more: {found:?}"
        );
        let refusal = refuse_trusted_authorities(tier_of(&insecure), &found)
            .expect_err("an insecure node started with a trusted authority");
        assert!(
            refusal.contains(authority.setting()),
            "the refusal does not name {}: {refusal}",
            authority.setting()
        );

        let separated = parse("firecracker", false, &flags);
        assert_eq!(tier_of(&separated), EvidenceTier::Separated);
        assert!(
            refuse_trusted_authorities(tier_of(&separated), &configured(&separated, lookup))
                .is_ok()
        );
    }
}

/// The C1/C2 live-path gates' configuration: the local driver with an
/// operator identity and nothing else. It configures no trusted authority,
/// so the gates keep running.
#[cfg(feature = "local-driver")]
#[test]
fn the_live_path_gates_configuration_starts_in_insecure_mode() {
    let args = parse(
        "local",
        true,
        &[
            "--root-minter-spiffe-id",
            "spiffe://nucleus.local/ns/default/sa/test-cli",
            "--tool-proxy-path",
            "/nonexistent/nucleus-tool-proxy",
        ],
    );
    assert_eq!(tier_of(&args), EvidenceTier::InsecureSharedUid);
    assert_eq!(configured(&args, no_env), vec![]);
    assert!(refuse_trusted_authorities(tier_of(&args), &[]).is_ok());
}

/// An empty trust-API URL configures nothing, as it never enabled the
/// trust gate.
#[cfg(feature = "local-driver")]
#[test]
fn an_empty_trust_api_url_is_not_a_trusted_authority() {
    let args = parse("local", true, &[]);
    let env = |name: &str| (name == "TRUST_API_URL").then(String::new);
    assert_eq!(configured(&args, env), vec![]);
}

#[test]
fn an_insecure_node_refuses_a_state_dir_holding_an_executor_key() {
    let dir = tempfile::tempdir().unwrap();
    // What a node that separated its workloads left behind.
    crate::keys::load_or_create_signing_key(dir.path(), &crate::pod_authority::NO_TPM.node_keys)
        .unwrap();
    let refusal = prepare_state_dir(EvidenceTier::InsecureSharedUid, dir.path()).unwrap_err();
    assert!(refusal.contains("executor key"), "{refusal}");
    assert!(
        !dir.path().join(INSECURE_MODE_MARKER).exists(),
        "a refused directory was marked"
    );
}

#[test]
fn a_separating_node_refuses_a_state_dir_an_insecure_node_used() {
    let dir = tempfile::tempdir().unwrap();
    prepare_state_dir(EvidenceTier::Separated, dir.path()).expect("a fresh dir");
    prepare_state_dir(EvidenceTier::InsecureSharedUid, dir.path()).expect("a fresh dir");
    // Insecure again on its own directory is fine; it never made an executor key.
    let _ = crate::trust_gate::TrustGateConfig::from_env(
        dir.path(),
        &crate::pod_authority::NO_TPM.node_keys,
        EvidenceTier::InsecureSharedUid,
    )
    .unwrap();
    prepare_state_dir(EvidenceTier::InsecureSharedUid, dir.path()).expect("its own dir");
    let refusal = prepare_state_dir(EvidenceTier::Separated, dir.path()).unwrap_err();
    assert!(refusal.contains("insecure mode"), "{refusal}");
}

/// The insecure-mode trust gate signs under an insecure kid with a key that is
/// not the executor key, and never creates the executor key.
#[test]
fn insecure_mode_never_creates_the_executor_key() {
    let dir = tempfile::tempdir().unwrap();
    let gate = crate::trust_gate::TrustGateConfig::from_env(
        dir.path(),
        &crate::pod_authority::NO_TPM.node_keys,
        EvidenceTier::InsecureSharedUid,
    )
    .unwrap();
    assert_eq!(gate.tier, EvidenceTier::InsecureSharedUid);
    assert!(gate.executor_id.starts_with(INSECURE_SHARED_UID_KID_PREFIX));
    assert!(!gate.is_enabled());
    assert!(gate.receipt_secret.is_none());
    assert_eq!(
        crate::keys::executor_key_files(dir.path()),
        Vec::<PathBuf>::new()
    );
    // Persisted: the kid is stable across restarts.
    let again = crate::trust_gate::TrustGateConfig::from_env(
        dir.path(),
        &crate::pod_authority::NO_TPM.node_keys,
        EvidenceTier::InsecureSharedUid,
    )
    .unwrap();
    assert_eq!(again.executor_id, gate.executor_id);
    // A separating node on another directory signs as the executor.
    let other = tempfile::tempdir().unwrap();
    let separated = crate::trust_gate::TrustGateConfig::from_env(
        other.path(),
        &crate::pod_authority::NO_TPM.node_keys,
        EvidenceTier::Separated,
    )
    .unwrap();
    assert!(
        !separated
            .executor_id
            .starts_with(INSECURE_SHARED_UID_KID_PREFIX)
    );
    assert_eq!(crate::keys::executor_key_files(other.path()).len(), 1);
}

/// Every PKCS#8 Ed25519 key a process at the node's uid can read under
/// `dir`: what a bare-tier child holds.
#[cfg(feature = "local-driver")]
fn readable_ed25519_keys(dir: &Path) -> Vec<(PathBuf, ed25519_dalek::SigningKey)> {
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
    let mut out = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(d) = pending.pop() {
        for entry in std::fs::read_dir(&d).expect("the child can list the state dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if let Ok(bytes) = std::fs::read(&path)
                && let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_der(&bytes)
            {
                out.push((path, key));
            }
        }
    }
    out
}

/// **The forgery C0 exists to make worthless.** A bare-tier child reads every
/// key in the node's state directory (it runs at the node's uid) and signs an
/// execution claim saying `backend = firecracker, uid_isolated = true` with
/// each, under the kid the node's own workload admission tells a controller
/// to pin. No such receipt verifies against that pin.
///
/// Before C0 the node signed with its executor key, which lived in that
/// directory, so the forgery under the pinned kid verified: this test is red
/// with `TrustGateConfig::from_env` ignoring the tier.
#[cfg(feature = "local-driver")]
#[tokio::test]
async fn a_bare_tier_child_forging_with_every_key_it_can_read_gains_nothing() {
    use nucleus_ci_verdict::execution::{
        Backend, ExecutionClaim, ExecutionSchema, ExpectedExecution, NodePlatform, verify_execution,
    };
    use nucleus_receipt::{Receipt, Session};
    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static NO_ARTIFACTS: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();

    let dir = tempfile::tempdir().unwrap();
    prepare_state_dir(EvidenceTier::InsecureSharedUid, dir.path()).unwrap();
    // The node, as the fixture mirrors `main()`: `--driver local --allow-local-driver`.
    let state = crate::pod_api::handler_tests::state(&dir);
    assert_eq!(state.trust_gate.tier, EvidenceTier::InsecureSharedUid);
    // What the node's `GET /v1/pods/{id}/workload-admission` hands a controller to pin.
    let pinned_kid = state.trust_gate.executor_id.clone();
    let pinned_key = state
        .trust_gate
        .executor_signing_key
        .verifying_key()
        .to_bytes();

    let forged = |key: &ed25519_dalek::SigningKey, kid: &str| {
        let claim = ExecutionClaim {
            schema: ExecutionSchema::V1,
            pod_id: "pod-1".into(),
            source_commit: "commit-1".into(),
            source_tree: "tree-1".into(),
            gate: "gate-1".into(),
            program_digest: DIGEST.into(),
            architecture: "x86_64".into(),
            backend: Backend::Firecracker,
            uid_isolated: true,
            exit_code: Some(0),
            stdout_sha256: DIGEST.into(),
            stderr_sha256: DIGEST.into(),
            launch_hash: DIGEST.into(),
            environment_inputs_sha256: DIGEST.into(),
            environment_complete_sha256: DIGEST.into(),
            artifacts: Default::default(),
            node_platform: NodePlatform::Unattested {
                reason: "forged".into(),
            },
            // The forger omits the declaration.
            sandbox_tier: SandboxTier::Driver,
        };
        Receipt::sign(
            Session {
                session_id: "pod-1".into(),
                issuer_kid: kid.into(),
                issued_at_micros: 150,
                parent_chain: vec![],
            },
            vec![claim.to_projection().unwrap()],
            key,
        )
    };
    let expect = |key: &'static [u8; 32], kid: &'static str| ExpectedExecution {
        pod_id: "pod-1",
        source_commit: "commit-1",
        source_tree: "tree-1",
        gate: "gate-1",
        program_digest: DIGEST,
        architecture: "x86_64",
        environment_inputs_sha256: DIGEST,
        artifacts: &NO_ARTIFACTS,
        session_id: "pod-1",
        issuer_kid: kid,
        verifying_key: key,
        issued_not_before_micros: 100,
        issued_not_after_micros: 200,
    };
    let pinned_key: &'static [u8; 32] = Box::leak(Box::new(pinned_key));
    let pinned_kid: &'static str = Box::leak(pinned_kid.into_boxed_str());

    // Control: the probe is not vacuous. The same forged claim, under a key
    // and an ordinary kid a controller pinned, verifies.
    let honest = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
    let honest_key: &'static [u8; 32] = Box::leak(Box::new(honest.verifying_key().to_bytes()));
    assert!(
        verify_execution(
            &forged(&honest, "nucleus-executor/0011"),
            &expect(honest_key, "nucleus-executor/0011")
        )
        .is_ok()
    );

    let keys = readable_ed25519_keys(dir.path());
    assert!(
        keys.iter()
            .any(|(_, k)| k.verifying_key().to_bytes() == *pinned_key),
        "the child cannot read the key the node signs with, so this probe tests nothing"
    );
    for (path, key) in &keys {
        for kid in [pinned_kid, "nucleus-executor/0011"] {
            let verdict = verify_execution(&forged(key, kid), &expect(pinned_key, pinned_kid));
            assert!(
                verdict.is_err(),
                "a claim forged with {} under kid {kid} was accepted",
                path.display()
            );
        }
    }
}
