//! `pod_authority`'s tests, kept beside it rather than in it so the module
//! stays under the line ratchet's default ceiling.

use super::*;
use nucleus_spec::{PodSpecInner, PolicySpec};
use portcullis::CapabilityLevel;
use rust_decimal::Decimal;

const TD: &str = "test.local";
const MINTER: &str = "spiffe://test.local/ns/system/sa/cli";

fn args() -> AuthorityArgs {
    AuthorityArgs {
        root_minter_spiffe_id: None,
        cert_trust_anchors: Vec::new(),
        max_children_per_pod: 8,
        upstreams: None,
        federation_issuer: None,
        ingress: Default::default(),
    }
}

fn authority(dir: &Path, args: AuthorityArgs) -> PodAuthority {
    PodAuthority::new(&args, TD, dir).expect("authority builds")
}

fn spec_with(lattice: PermissionLattice) -> PodSpec {
    PodSpec::new(PodSpecInner {
        work_dir: PathBuf::from("/work"),
        timeout_seconds: 600,
        policy: PolicySpec::Inline {
            lattice: Box::new(lattice),
        },
        budget_model: None,
        resources: None,
        network: None,
        credentialed_egress: Vec::new(),
        workload: None,
        image: None,
        vsock: None,
        seccomp: None,
        cgroup: None,
        audit_sink: None,
        credentials: None,
    })
}

fn lattice(budget_usd: u32) -> PermissionLattice {
    let mut l = PermissionLattice::permissive();
    l.budget.max_cost_usd = Decimal::from(budget_usd);
    l
}

fn by(spiffe: &str) -> Admission {
    Admission {
        caller_spiffe_id: spiffe.into(),
        caller_pod: None,
        header_cert: None,
    }
}

fn from_pod(parent: Uuid) -> Admission {
    Admission {
        caller_spiffe_id: format!("spiffe://{TD}/ns/pods/sa/{parent}"),
        caller_pod: Some(parent),
        header_cert: None,
    }
}

#[tokio::test]
async fn the_root_minter_creates_from_a_bare_policy_and_nobody_else_does() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let pod = Uuid::new_v4();

    let issued = auth
        .admit_kept(&by(MINTER), &spec_with(lattice(5)), pod)
        .await
        .expect("bootstrap identity mints a root");
    assert_eq!(issued.chain_depth, 1);
    assert_eq!(issued.effective.budget.max_cost_usd, Decimal::from(5));
    let boot = auth.boot_certificate(pod).await.expect("registered");
    let token = AttenuationToken::from_base64(&boot.token_b64).unwrap();
    assert_eq!(token.leaf_identity(), auth.pod_spiffe_id(pod));
    assert_eq!(token.root_identity(), MINTER);
    assert!(verify_certificate(token.certificate(), &auth.root_pubkey, Utc::now(), 10).is_ok());

    let stranger = by("spiffe://test.local/ns/default/sa/someone");
    let denied = auth
        .admit_kept(&stranger, &spec_with(lattice(5)), Uuid::new_v4())
        .await;
    assert!(
        matches!(denied, Err(ApiError::Authority(_))),
        "an unidentified non-minter must be refused, got {denied:?}"
    );
    assert!(auth.boot_certificate(Uuid::new_v4()).await.is_none());
}

#[tokio::test]
async fn a_child_is_narrowed_to_its_parent_and_budget_is_conserved() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let parent = Uuid::new_v4();
    let mut parent_policy = lattice(5);
    parent_policy.capabilities.git_push = CapabilityLevel::Never;
    auth.admit_kept(&by(MINTER), &spec_with(parent_policy.clone()), parent)
        .await
        .unwrap();

    // Child asks for MORE than the parent (git_push Always, $3): capability
    // is meet-clamped, budget is reserved.
    let mut greedy = lattice(3);
    greedy.capabilities.git_push = CapabilityLevel::Always;
    let c1 = Uuid::new_v4();
    let issued = auth
        .admit_kept(&from_pod(parent), &spec_with(greedy.clone()), c1)
        .await
        .unwrap();
    assert_eq!(issued.chain_depth, 2);
    assert_eq!(
        issued.effective.capabilities.git_push,
        CapabilityLevel::Never
    );
    assert!(issued.effective.leq(&parent_policy));

    // Second $3 child: 3 + 3 > 5 — refused. This is the defect: before the
    // ledger, every child got the parent's full budget.
    let c2 = Uuid::new_v4();
    let denied = auth
        .admit_kept(&from_pod(parent), &spec_with(lattice(3)), c2)
        .await;
    assert!(
        matches!(&denied, Err(ApiError::Authority(m)) if m.contains("budget conservation")),
        "got {denied:?}"
    );
    // A $2 child fits exactly.
    auth.admit_kept(&from_pod(parent), &spec_with(lattice(2)), c2)
        .await
        .unwrap();
    // Nothing left.
    assert!(
        auth.admit_kept(&from_pod(parent), &spec_with(lattice(1)), Uuid::new_v4())
            .await
            .is_err()
    );

    // Releasing c1 folds its allocation into the parent's consumption
    // (conservative: no refund), so the parent still cannot over-spawn.
    auth.release_child(c1).await;
    assert!(
        auth.admit_kept(&from_pod(parent), &spec_with(lattice(1)), Uuid::new_v4())
            .await
            .is_err()
    );
    assert!(auth.boot_certificate(c1).await.is_none());
}

/// A legacy guest can sign a complete, zero-spend seal with its own key.
/// Such a claim must never restore the parent's spending authority.
#[tokio::test]
async fn legacy_guest_zero_spend_seal_cannot_refund_a_running_child() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let parent = Uuid::new_v4();
    auth.admit_kept(&by(MINTER), &spec_with(lattice(5)), parent)
        .await
        .unwrap();
    let child = Uuid::new_v4();
    auth.admit_kept(&from_pod(parent), &spec_with(lattice(3)), child)
        .await
        .unwrap();
    let pod_dir = dir.path().join("pods").join(child.to_string());
    let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
    std::fs::write(
        pod_dir.join("mediator-pubkey.hex"),
        hex::encode(key.verifying_key().to_bytes()),
    )
    .unwrap();
    let seal = portcullis::spend_receipt::SpendReceipt::seal(
        "spiffe://t/mediator",
        &child.to_string(),
        1,
        0,
        &key,
    );
    let line = serde_json::to_string(&seal).unwrap();
    let kept = crate::spend_receipt_collector::append_spend(&pod_dir, &line)
        .await
        .unwrap();
    assert!(kept.proves(
        &crate::spend_receipt_collector::spend_log_path(&pod_dir),
        &line
    ));
    assert_eq!(
        crate::clearing_receipt_collector::guest_reported_spend(&pod_dir, &child.to_string()),
        Some(Decimal::ZERO)
    );
    auth.release_child(child).await;
    assert!(
        auth.admit_kept(&from_pod(parent), &spec_with(lattice(4)), Uuid::new_v4())
            .await
            .is_err()
    );
    auth.admit_kept(&from_pod(parent), &spec_with(lattice(2)), Uuid::new_v4())
        .await
        .expect("the unallocated $2 remains usable");
}

/// A pod whose driver never started it spent nothing, so its parent gets
/// the whole reservation back through `Reservation::release` — unlike
/// `release_child(_)`, which folds it. The control: the same $5
/// sibling is refused after a fold.
#[tokio::test]
async fn a_pod_that_never_spawned_hands_its_whole_reservation_back() {
    async fn five_dollar_sibling_fits(unspawned: bool) -> bool {
        let dir = tempfile::tempdir().unwrap();
        let auth = authority(dir.path(), args());
        let parent = Uuid::new_v4();
        auth.admit_kept(&by(MINTER), &spec_with(lattice(5)), parent)
            .await
            .unwrap();
        let child = Uuid::new_v4();
        if unspawned {
            let issued = auth
                .admit(&from_pod(parent), &spec_with(lattice(3)), child)
                .await
                .unwrap();
            issued.reservation.release().await;
        } else {
            auth.admit_kept(&from_pod(parent), &spec_with(lattice(3)), child)
                .await
                .unwrap();
            auth.release_child(child).await;
        }
        auth.admit_kept(&from_pod(parent), &spec_with(lattice(5)), Uuid::new_v4())
            .await
            .is_ok()
    }

    assert!(
        five_dollar_sibling_fits(true).await,
        "nothing ran, nothing spent"
    );
    assert!(
        !five_dollar_sibling_fits(false).await,
        "the control: a fold keeps the $3 consumed"
    );
}

#[tokio::test]
async fn a_request_over_the_parent_budget_is_refused_not_clamped() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let parent = Uuid::new_v4();
    auth.admit_kept(&by(MINTER), &spec_with(lattice(5)), parent)
        .await
        .unwrap();
    let denied = auth
        .admit_kept(&from_pod(parent), &spec_with(lattice(500)), Uuid::new_v4())
        .await;
    assert!(
        matches!(denied, Err(ApiError::Authority(_))),
        "got {denied:?}"
    );
    // And the failed attempt reserved nothing.
    auth.admit_kept(&from_pod(parent), &spec_with(lattice(5)), Uuid::new_v4())
        .await
        .expect("the full budget is still available");
}

#[tokio::test]
async fn fan_out_is_capped_per_parent() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = args();
    a.max_children_per_pod = 2;
    let auth = authority(dir.path(), a);
    let parent = Uuid::new_v4();
    auth.admit_kept(&by(MINTER), &spec_with(lattice(100)), parent)
        .await
        .unwrap();
    auth.admit_kept(&from_pod(parent), &spec_with(lattice(1)), Uuid::new_v4())
        .await
        .unwrap();
    auth.admit_kept(&from_pod(parent), &spec_with(lattice(1)), Uuid::new_v4())
        .await
        .unwrap();
    let third = auth
        .admit_kept(&from_pod(parent), &spec_with(lattice(1)), Uuid::new_v4())
        .await;
    assert!(
        matches!(&third, Err(ApiError::Authority(m)) if m.contains("live children")),
        "got {third:?}"
    );
}

#[tokio::test]
async fn an_unregistered_pod_cannot_spawn() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let denied = auth
        .admit_kept(
            &from_pod(Uuid::new_v4()),
            &spec_with(lattice(1)),
            Uuid::new_v4(),
        )
        .await;
    assert!(matches!(denied, Err(ApiError::Authority(_))));
}

#[tokio::test]
async fn chain_depth_bounds_recursion() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let mut current = Uuid::new_v4();
    auth.admit_kept(&by(MINTER), &spec_with(lattice(1_000_000)), current)
        .await
        .unwrap();
    let mut depth = 1;
    loop {
        let next = Uuid::new_v4();
        match auth
            .admit_kept(&from_pod(current), &spec_with(lattice(1)), next)
            .await
        {
            Ok(issued) => {
                depth = issued.chain_depth;
                current = next;
            }
            Err(ApiError::Authority(m)) => {
                assert!(m.contains("depth") && m.contains("exceed"), "{m}");
                break;
            }
            Err(e) => panic!("unexpected {e:?}"),
        }
        assert!(depth <= DEFAULT_MAX_CHAIN_DEPTH);
    }
    assert_eq!(depth, DEFAULT_MAX_CHAIN_DEPTH);
}

/// An external caller: a chain rooted at an operator-registered anchor,
/// whose leaf is the authenticated identity. Re-rooted with provenance.
#[tokio::test]
async fn an_external_chain_is_verified_against_our_anchors_and_bound_to_the_caller() {
    let dir = tempfile::tempdir().unwrap();
    let rng = ring::rand::SystemRandom::new();
    let ext_root = ephemeral_key().unwrap();
    let ext_root_hex = hex::encode(ext_root.public_key().as_ref());

    let mut a = args();
    a.cert_trust_anchors = vec![ext_root_hex];
    let auth = authority(dir.path(), a);

    let caller = "spiffe://other.example/ns/agents/sa/orchestrator";
    // One expiry for both hops: a second `Utc::now()` is already later,
    // and a child may not outlive its parent block.
    let expiry = Utc::now() + Duration::hours(1);
    let (root, holder) = LatticeCertificate::mint(
        lattice(10),
        "spiffe://other.example/human/alice".into(),
        expiry,
        &ext_root,
        &rng,
    );
    let (leaf, _k) = root
        .delegate(&lattice(4), caller.into(), expiry, &holder, &rng)
        .unwrap();
    let token = AttenuationToken::seal(leaf.clone(), ext_root.public_key().as_ref().to_vec());
    let header = token.to_base64().unwrap();

    let pod = Uuid::new_v4();
    let admission = Admission {
        caller_spiffe_id: caller.into(),
        caller_pod: None,
        header_cert: Some(header.clone()),
    };
    let issued = auth
        .admit_kept(&admission, &spec_with(lattice(3)), pod)
        .await
        .unwrap();
    assert_eq!(issued.effective.budget.max_cost_usd, Decimal::from(3));
    let boot = auth.boot_certificate(pod).await.unwrap();
    let minted = AttenuationToken::from_base64(&boot.token_b64).unwrap();
    assert_eq!(
        minted.certificate().authority().provenance,
        Some(token.fingerprint())
    );
    assert_eq!(minted.root_identity(), caller);
    assert!(verify_certificate(minted.certificate(), &auth.root_pubkey, Utc::now(), 10).is_ok());

    // The caller's chain carried $4: a second $3 pod is refused.
    let denied = auth
        .admit_kept(&admission, &spec_with(lattice(3)), Uuid::new_v4())
        .await;
    assert!(matches!(&denied, Err(ApiError::Authority(m)) if m.contains("budget conservation")));

    // Leaf/caller mismatch: same valid chain, different authenticated identity.
    let impostor = Admission {
        caller_spiffe_id: "spiffe://other.example/ns/agents/sa/impostor".into(),
        caller_pod: None,
        header_cert: Some(header),
    };
    assert!(matches!(
        auth.admit_kept(&impostor, &spec_with(lattice(1)), Uuid::new_v4())
            .await,
        Err(ApiError::Authority(_))
    ));

    // A chain rooted at a key we do NOT trust — even a self-consistent
    // token carrying its own root key — is refused.
    let stranger_root = ephemeral_key().unwrap();
    let (sroot, _) = LatticeCertificate::mint(
        lattice(10),
        caller.into(),
        Utc::now() + Duration::hours(1),
        &stranger_root,
        &rng,
    );
    let stoken = AttenuationToken::seal(sroot, stranger_root.public_key().as_ref().to_vec());
    let untrusted = Admission {
        caller_spiffe_id: caller.into(),
        caller_pod: None,
        header_cert: Some(stoken.to_base64().unwrap()),
    };
    assert!(matches!(
        auth.admit_kept(&untrusted, &spec_with(lattice(1)), Uuid::new_v4())
            .await,
        Err(ApiError::Authority(_))
    ));
}

#[tokio::test]
async fn authority_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let parent = Uuid::new_v4();
    let child = Uuid::new_v4();
    {
        let auth = authority(dir.path(), args());
        auth.admit_kept(&by(MINTER), &spec_with(lattice(5)), parent)
            .await
            .unwrap();
        auth.admit_kept(&from_pod(parent), &spec_with(lattice(3)), child)
            .await
            .unwrap();
    }
    // "Restart": a new authority over the same state dir.
    let auth = authority(dir.path(), args());
    assert_eq!(auth.restore_from_disk().await, 2);
    // The restored parent can still delegate (its holder key came back)...
    auth.admit_kept(&from_pod(parent), &spec_with(lattice(2)), Uuid::new_v4())
        .await
        .expect("restored holder key delegates");
    // ...and its ledger came back too: 3 + 2 = 5, nothing left.
    assert!(
        auth.admit_kept(&from_pod(parent), &spec_with(lattice(1)), Uuid::new_v4())
            .await
            .is_err()
    );
    // The restored child's certificate still verifies under the same root.
    let boot = auth.boot_certificate(child).await.unwrap();
    let t = AttenuationToken::from_base64(&boot.token_b64).unwrap();
    assert!(verify_certificate(t.certificate(), &auth.root_pubkey, Utc::now(), 10).is_ok());
}

// ── Credentialed upstreams, bounded at the NODE ──────────────────────
//
// Before these, the node passed `credentialed_egress` through verbatim and
// the only clamp was the in-guest tool-proxy's. Every test below calls
// `admit` — the node's own gate — with the Admission a direct caller of
// `POST /v1/pods` produces, so none of them passes through the proxy.

const REGISTRY: &str = r#"
[[upstream]]
name = "model-api"
base_url = "https://model-api.invalid/v1"
header = "authorization"
value_prefix = "Bearer "
credential.env.var = "LLM_API_TOKEN"

[[upstream]]
name = "search-api"
base_url = "https://search-api.invalid"
header = "x-api-key"
credential.env.var = "SEARCH_API_TOKEN"
"#;

fn with_registry(dir: &Path) -> PodAuthority {
    let path = dir.join("upstreams.toml");
    std::fs::write(&path, REGISTRY).unwrap();
    let mut a = args();
    a.upstreams = Some(path);
    authority(dir, a)
}

fn registered(name: &str) -> CredentialedEgressSpec {
    crate::upstreams::UpstreamRegistry::from_toml_str(REGISTRY)
        .unwrap()
        .entries()
        .iter()
        .find(|e| e.name == name)
        .cloned()
        .expect("fixture names a registry entry")
}

/// The exfiltration shape: a real registry name pointed at a URL the caller
/// chose, and an invented entry naming a node variable nobody registered.
fn loot() -> Vec<CredentialedEgressSpec> {
    let mut retargeted = registered("model-api");
    retargeted.upstream = "https://attacker.invalid".into();
    let invented = CredentialedEgressSpec {
        name: "loot".into(),
        upstream: "https://attacker.invalid".into(),
        credential_env: "NUCLEUS_NODE_PROXY_AUTH_SECRET".into(),
        header: "authorization".into(),
        value_prefix: String::new(),
    };
    vec![retargeted, invented]
}

fn requesting(ups: Vec<CredentialedEgressSpec>, budget: u32) -> PodSpec {
    let mut spec = spec_with(lattice(budget));
    spec.spec.credentialed_egress = ups;
    spec
}

/// The refusal a caller gets for `name`: the entry, never the reason.
fn refused(name: &str) -> String {
    ApiError::Authority(format!("credentialed upstream `{name}` is not granted")).to_string()
}

/// (a) **A pod calling the node directly cannot name an upstream its
/// parent lacks** — not an unregistered one, and not even a REGISTERED one
/// the parent was never admitted. Delegation narrows; it never invents. The
/// pod is REFUSED (ADR 0010 §1), not created without the entry, and the
/// refusal gives back the budget it had reserved against the parent.
#[tokio::test]
async fn a_pod_caller_is_refused_an_upstream_its_parent_lacks() {
    let dir = tempfile::tempdir().unwrap();
    let auth = with_registry(dir.path());
    let parent = Uuid::new_v4();
    let issued = auth
        .admit_kept(
            &by(MINTER),
            &requesting(vec![registered("model-api")], 5),
            parent,
        )
        .await
        .unwrap();
    assert_eq!(
        issued.upstreams,
        vec![registered("model-api")],
        "the control: the root minter is admitted a registry entry"
    );

    // Registered, but the parent lacks it.
    let err = auth
        .admit(
            &from_pod(parent),
            &requesting(vec![registered("search-api")], 1),
            Uuid::new_v4(),
        )
        .await
        .expect_err("an upstream the parent lacks refuses the pod");
    assert_eq!(err.to_string(), refused("search-api"));
    // A registry name retargeted at the caller's URL, then an invented entry.
    let err = auth
        .admit(&from_pod(parent), &requesting(loot(), 1), Uuid::new_v4())
        .await
        .expect_err("a retargeted entry refuses the pod");
    assert_eq!(err.to_string(), refused("model-api"));
    assert_eq!(
        auth.inner.lock().await.pods[&parent].ledger.live_children(),
        0,
        "a refused child holds no reservation against its parent"
    );

    // Delegation still works for what the parent holds.
    let child = auth
        .admit_kept(
            &from_pod(parent),
            &requesting(vec![registered("model-api")], 1),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert_eq!(child.upstreams, vec![registered("model-api")]);
}

/// (b) **With a registry, the root minter and an external caller are
/// admitted only registry entries**, field for field. A differing field is
/// a different entry, and an entry naming a variable the operator never
/// registered refuses the pod, whoever asks.
#[tokio::test]
async fn root_and_external_callers_are_refused_what_the_registry_lacks() {
    let dir = tempfile::tempdir().unwrap();
    let rng = ring::rand::SystemRandom::new();
    let ext_root = ephemeral_key().unwrap();
    let path = dir.path().join("upstreams.toml");
    std::fs::write(&path, REGISTRY).unwrap();
    let mut a = args();
    a.upstreams = Some(path);
    a.cert_trust_anchors = vec![hex::encode(ext_root.public_key().as_ref())];
    let auth = authority(dir.path(), a);

    let caller = "spiffe://other.example/ns/agents/sa/orchestrator";
    let expiry = Utc::now() + Duration::hours(1);
    let (leaf, _k) = LatticeCertificate::mint(lattice(10), caller.into(), expiry, &ext_root, &rng);
    let token = AttenuationToken::seal(leaf, ext_root.public_key().as_ref().to_vec());
    let external = Admission {
        caller_spiffe_id: caller.into(),
        caller_pod: None,
        header_cert: Some(token.to_base64().unwrap()),
    };

    for who in [by(MINTER), external] {
        let mut asked = vec![registered("search-api")];
        asked.extend(loot());
        let err = auth
            .admit(&who, &requesting(asked, 1), Uuid::new_v4())
            .await
            .expect_err("an entry outside the registry refuses the pod");
        assert_eq!(
            err.to_string(),
            refused("model-api"),
            "{}",
            who.caller_spiffe_id
        );
        let ok = auth
            .admit_kept(
                &who,
                &requesting(vec![registered("search-api")], 1),
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        assert_eq!(ok.upstreams, vec![registered("search-api")]);
    }
}

/// The refusal is not an oracle (ADR 0004): "not in the registry" and "not
/// held by the parent" read the same, differing only in the name the caller
/// itself sent.
#[tokio::test]
async fn a_refusal_names_the_entry_not_the_reason() {
    let dir = tempfile::tempdir().unwrap();
    let auth = with_registry(dir.path());
    let parent = Uuid::new_v4();
    auth.admit_kept(&by(MINTER), &requesting(vec![], 5), parent)
        .await
        .unwrap();
    let mut invented = loot().pop().expect("the invented entry");
    invented.name = "search-api-2".into();
    let not_registered = auth
        .admit(
            &from_pod(parent),
            &requesting(vec![invented], 1),
            Uuid::new_v4(),
        )
        .await
        .expect_err("unregistered");
    let not_held = auth
        .admit(
            &from_pod(parent),
            &requesting(vec![registered("search-api")], 1),
            Uuid::new_v4(),
        )
        .await
        .expect_err("registered, not held");
    assert_eq!(
        not_registered
            .to_string()
            .replace("search-api-2", "search-api"),
        not_held.to_string()
    );
}

/// No registry is an empty ceiling for EVERY case, the root minter
/// included. See `upstreams.rs` for why this is not "trust the operator CLI".
#[tokio::test]
async fn without_a_registry_a_pod_requesting_an_upstream_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let err = auth
        .admit(
            &by(MINTER),
            &requesting(vec![registered("model-api")], 5),
            Uuid::new_v4(),
        )
        .await
        .expect_err("no registry grants nothing");
    assert_eq!(err.to_string(), refused("model-api"));
    let issued = auth
        .admit_kept(&by(MINTER), &requesting(vec![], 5), Uuid::new_v4())
        .await
        .unwrap();
    assert!(issued.upstreams.is_empty(), "asking for none still works");
}

/// The per-pod admitted set is persisted with the certificate, so a
/// restarted node still bounds a restored parent's children by it.
#[tokio::test]
async fn a_parents_admitted_upstreams_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let parent = Uuid::new_v4();
    with_registry(dir.path())
        .admit_kept(
            &by(MINTER),
            &requesting(vec![registered("model-api")], 5),
            parent,
        )
        .await
        .unwrap();
    let auth = with_registry(dir.path());
    assert_eq!(auth.restore_from_disk().await, 1);
    let err = auth
        .admit(
            &from_pod(parent),
            &requesting(vec![registered("model-api"), registered("search-api")], 1),
            Uuid::new_v4(),
        )
        .await
        .expect_err("the restored parent never held search-api");
    assert_eq!(err.to_string(), refused("search-api"));
    let child = auth
        .admit_kept(
            &from_pod(parent),
            &requesting(vec![registered("model-api")], 1),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert_eq!(child.upstreams, vec![registered("model-api")]);
}

/// #3032: a reservation dropped without `commit` hands the budget back and
/// retires the child's certificate on disk, so a restart cannot restore it.
#[tokio::test]
async fn a_dropped_reservation_hands_the_budget_back() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let parent = Uuid::new_v4();
    auth.admit_kept(&by(MINTER), &spec_with(lattice(5)), parent)
        .await
        .unwrap();
    let child = Uuid::new_v4();
    let issued = auth
        .admit(&from_pod(parent), &spec_with(lattice(1)), child)
        .await
        .unwrap();
    assert_eq!(auth.live_children(parent).await, Some(1));
    assert!(
        auth.authority_path(child).exists(),
        "the child was persisted"
    );

    drop(issued);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while auth.live_children(parent).await != Some(0) {
        assert!(
            std::time::Instant::now() < deadline,
            "a dropped reservation never handed the budget back"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        auth.live_children(child).await,
        None,
        "the child's cert is retired"
    );
    assert!(
        !auth.authority_path(child).exists(),
        "and its authority.json removed"
    );
}

/// The control: a committed reservation is kept.
#[tokio::test]
async fn a_committed_reservation_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let parent = Uuid::new_v4();
    auth.admit_kept(&by(MINTER), &spec_with(lattice(5)), parent)
        .await
        .unwrap();
    let mut spec = spec_with(lattice(1));
    auth.admit(&from_pod(parent), &spec, Uuid::new_v4())
        .await
        .unwrap()
        .apply_to(&mut spec)
        .commit();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(auth.live_children(parent).await, Some(1));
}

/// Admission deciding is half of it; the spec the driver launches from
/// must CARRY the decision. `apply_to` replaces both fields...
#[test]
fn apply_to_replaces_the_requested_upstreams_with_the_admitted_ones() {
    let mut spec = requesting(loot(), 5);
    let issued = IssuedAuthority {
        effective: lattice(1),
        chain_depth: 1,
        upstreams: vec![registered("model-api")],
        reservation: Reservation { release: None },
        root_identity: MINTER.to_string(),
    };
    let owner = issued.root_identity.clone();
    let reservation = issued.apply_to(&mut spec);
    reservation.commit();
    assert_eq!(spec.spec.credentialed_egress, vec![registered("model-api")]);
    assert_eq!(owner, MINTER, "the owner recorded is the root issued");
}

/// ...and `create_pod_internal` calls it, unconditionally, right after
/// admission. A source check, the same shape as
/// `the_clamp_is_wired_before_admission_unconditionally`: the node's launch
/// path spawns VMs, so no unit test can drive it end to end.
#[test]
fn create_pod_internal_applies_the_issued_authority() {
    let main = include_str!("../../main.rs");
    let admit = main
        .find("state.authority.admit(&admission, &spec, id)")
        .expect("admission is called from main.rs");
    let apply = main
        .find("let reservation = issued.apply_to(&mut spec);")
        .expect("the issued authority is applied to the spec in main.rs, and its reservation kept");
    assert!(admit < apply, "applied after it is issued");
    let spawn = main[admit..]
        .find("let spawned = match state.driver")
        .expect("the spawn follows admission");
    assert!(
        apply < admit + spawn,
        "applied before the pod is spawned from the spec"
    );
    let indent = main[..apply].rsplit('\n').next().unwrap_or("");
    assert_eq!(
        indent, "    ",
        "at function-body level, not under a condition"
    );
}

// ── Federated upstreams: the issuer, and who an assertion names ──────

const FEDERATED_REGISTRY: &str = r#"
[[upstream]]
name = "model-api"
base_url = "https://model-api.invalid/v1"
header = "authorization"
value_prefix = "Bearer "

[upstream.credential.federated]
token_endpoint = "https://auth.model-api.invalid/oauth/token"
grant = "jwt-bearer"
encoding = "json"
audience = "https://auth.model-api.invalid"
"#;

fn federated_args(dir: &Path, issuer: Option<&str>) -> AuthorityArgs {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let path = dir.join("upstreams.toml");
    std::fs::write(&path, FEDERATED_REGISTRY).unwrap();
    let mut a = args();
    a.upstreams = Some(path);
    a.federation_issuer = issuer.map(str::to_string);
    a
}

/// **Fail closed at start.** A registry that needs an issuer and has none
/// is a node that would admit pods to an upstream and then refuse every
/// call — so it does not start. Nor does one with a cleartext issuer.
#[test]
fn a_federated_registry_without_an_issuer_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let err = PodAuthority::new(&federated_args(dir.path(), None), TD, dir.path())
        .err()
        .expect("no issuer: refused");
    assert!(err.contains("--federation-issuer"), "{err}");
    assert!(
        PodAuthority::new(
            &federated_args(dir.path(), Some("http://federation.example.invalid")),
            TD,
            dir.path()
        )
        .is_err(),
        "a cleartext issuer was accepted"
    );
    // The control: with an issuer it starts, and no key file is written by
    // a node that has no issuer.
    let ok = PodAuthority::new(
        &federated_args(dir.path(), Some("https://federation.example.invalid")),
        TD,
        dir.path(),
    )
    .expect("starts with an issuer");
    assert!(ok.federation_source().is_some());
    let plain = tempfile::tempdir().unwrap();
    authority(plain.path(), args());
    assert!(!plain.path().join("jwt_svid_p256_signing_key.der").exists());
}

/// **Who an assertion names, read from the certificate the node issued.**
/// `sub` is the pod's own identity, the root and tenant are the chain's,
/// and the chain claim is the certificate's fingerprint — and a broker
/// identity that disagrees with the certificate gets nothing.
#[tokio::test]
async fn the_federation_subject_comes_from_the_issued_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let auth = PodAuthority::new(
        &federated_args(dir.path(), Some("https://federation.example.invalid")),
        TD,
        dir.path(),
    )
    .unwrap();
    let pod = Uuid::new_v4();
    let federated = auth.upstream_registry().unwrap().entries().to_vec();
    let issued = auth
        .admit_kept(&by(MINTER), &requesting(federated.clone(), 5), pod)
        .await
        .unwrap();
    assert_eq!(
        issued.upstreams, federated,
        "the federated projection is admitted"
    );

    let observed = nucleus_cred_broker::PodIdentity::observed_by_host(auth.pod_spiffe_id(pod));
    let subject = auth
        .federation_subject(pod, &observed)
        .await
        .expect("an issued pod has a subject");
    assert_eq!(subject.pod_spiffe_id(), auth.pod_spiffe_id(pod));
    let debug = format!("{subject:?}");
    let fp = hex::encode(auth.certificate_fingerprint(pod).await.unwrap());
    assert_eq!(fp.len(), 64);
    for fact in [MINTER, TD, fp.as_str()] {
        assert!(debug.contains(fact), "the subject lacks {fact}: {debug}");
    }

    let stranger =
        nucleus_cred_broker::PodIdentity::observed_by_host(auth.pod_spiffe_id(Uuid::new_v4()));
    assert!(
        auth.federation_subject(pod, &stranger).await.is_none(),
        "a broker identity that is not the certificate's leaf got a subject"
    );
    assert!(
        auth.federation_subject(Uuid::new_v4(), &observed)
            .await
            .is_none(),
        "a pod with no certificate got a subject"
    );

    // And the broker's credentials for this pod can mint; a node with no
    // issuer's cannot.
    let entries = auth.upstream_registry().unwrap().resolve(&issued.upstreams);
    let creds = crate::broker_launch::pod_credentials(&auth, pod, &observed, &entries).await;
    assert!(
        format!("{creds:?}").contains("federated: true"),
        "{creds:?}"
    );
    let plain = with_registry(tempfile::tempdir().unwrap().path());
    let creds = crate::broker_launch::pod_credentials(&plain, pod, &observed, &entries).await;
    assert!(
        format!("{creds:?}").contains("federated: false"),
        "{creds:?}"
    );
}

// Ledgers across a restart.
mod restart;

#[tokio::test]
async fn release_revokes_policy_references_already_held_by_brokers() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let pod = Uuid::new_v4();
    auth.admit_kept(&by(MINTER), &spec_with(lattice(5)), pod)
        .await
        .unwrap();
    let policy = auth.host_policy(pod).await.unwrap();
    assert!(crate::host_decide::PodPolicy::available(&policy).is_ok());
    auth.release_child(pod).await;
    assert!(crate::host_decide::PodPolicy::available(&policy).is_err());
    assert!(auth.host_policy(pod).await.is_err());
    let mut policy = policy.lock().unwrap();
    assert!(
        policy
            .authorize_effect(
                nucleus_decision_protocol::ArgsDigest::new([1; 32]),
                portcullis::Operation::WebFetch,
                "https://upstream.invalid",
                100,
                crate::upstreams::CallCharge::free()
            )
            .is_err()
    );
}
