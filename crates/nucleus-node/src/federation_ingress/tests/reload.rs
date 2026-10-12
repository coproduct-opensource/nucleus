//! A running node's registry is reloaded, not restarted (`pod_authority/registry.rs`), and a
//! binding's allocations are bounded per UTC day (`pod_authority/daily.rs`). Every test here
//! keeps ONE `PodAuthority` for its whole length: "no restart" is the property under test.

use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};

use chrono::{DateTime, Utc};
use portcullis::TimeLattice;

use super::*;
use crate::pod_authority::registry::ReloadOutcome;

/// One node, one binding (A) whose ceiling and allowance each test rewrites.
struct Live {
    st: IngressState,
    a: Issuer,
    /// The second tenant, so a reload has a tenant set to keep; it signs nothing.
    b: Issuer,
    path: PathBuf,
    /// Days added to the real UTC date, as the allowance reads it.
    day: Arc<AtomicI64>,
    dir: tempfile::TempDir,
    /// A distinct subject per exchange, so no token is a replay of another.
    n: std::sync::atomic::AtomicU32,
}

/// The binding's ceiling: `codegen` with an explicit budget and window.
fn ceiling(budget: u32, from: DateTime<Utc>, until: DateTime<Utc>) -> PermissionLattice {
    let mut l = PermissionLattice::codegen();
    l.budget.max_cost_usd = rust_decimal::Decimal::from(budget);
    l.time = TimeLattice::between(from, until);
    l
}

fn open_window() -> (DateTime<Utc>, DateTime<Utc>) {
    let now = Utc::now();
    (
        now - chrono::Duration::seconds(60),
        now + chrono::Duration::hours(1),
    )
}

/// The registry file: one upstream and two tenants, A with `ceiling` (and
/// `per_day`, if any), B fixed. `third` adds a tenant, which a reload refuses.
fn registry(
    live_a: &Issuer,
    b: &Issuer,
    a: &PermissionLattice,
    per_day: Option<&str>,
    third: bool,
) -> String {
    let base = format!(
        r#"
[[upstream]]
name = "model-api"
base_url = "https://model.example.invalid/v1"
header = "authorization"
value_prefix = "Bearer "
[upstream.credential.env]
var = "MODEL_TOKEN"

[[caller]]
label = "runtime-a"
issuer = "{ISS_A}"
audience = "{AUD}"
algs = ["ES256"]
jwks = {{ inline = '{jwks_a}' }}
max_lifetime_secs = 900
trust_domain = "{TD_A}"
upstreams = ["model-api"]
ceiling = {{ profile = "read_only" }}

[[caller]]
label = "runtime-b"
issuer = "{ISS_B}"
audience = "{AUD}"
algs = ["ES256"]
jwks = {{ inline = '{jwks_b}' }}
max_lifetime_secs = 900
trust_domain = "{TD_B}"
ceiling = {{ profile = "read_only" }}
"#,
        jwks_a = live_a.jwks(),
        jwks_b = b.jwks(),
    );
    let mut doc: toml::Table = toml::from_str(&base).unwrap();
    let callers = doc["caller"].as_array_mut().unwrap();
    let a_table = callers[0].as_table_mut().unwrap();
    let mut inline = toml::Table::new();
    inline.insert("inline".into(), toml::Value::try_from(a).unwrap());
    a_table.insert("ceiling".into(), toml::Value::Table(inline));
    if let Some(usd) = per_day {
        a_table.insert(
            "max_cost_usd_per_day".into(),
            toml::Value::String(usd.into()),
        );
    }
    if third {
        let mut c = callers[1].as_table().unwrap().clone();
        c.insert("label".into(), "runtime-c".into());
        c.insert("issuer".into(), "https://issuer-c.example.invalid".into());
        c.insert("trust_domain".into(), "tenant-c.example.invalid".into());
        callers.push(toml::Value::Table(c));
    }
    toml::to_string(&doc).unwrap()
}

impl Live {
    fn new(a_ceiling: &PermissionLattice, per_day: Option<&str>) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (a, b) = (Issuer::new(ISS_A, "key-a"), Issuer::new(ISS_B, "key-b"));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upstreams.toml");
        std::fs::write(&path, registry(&a, &b, a_ceiling, per_day, false)).unwrap();
        let args = AuthorityArgs {
            root_minter_spiffe_id: None,
            cert_trust_anchors: Vec::new(),
            max_children_per_pod: 8,
            upstreams: Some(path.clone()),
            upstreams_poll_secs: 0,
            federation_issuer: None,
            ingress: FederationArgs::default(),
            approvals: crate::host_decide::effects::ApprovalTimingArgs::HUMAN,
        };
        let day = Arc::new(AtomicI64::new(0));
        let clock_day = Arc::clone(&day);
        let authority =
            PodAuthority::new(&args, NODE_TD, dir.path(), &crate::pod_authority::NO_TPM)
                .unwrap()
                .with_day_clock(Arc::new(move || {
                    Utc::now().date_naive()
                        + chrono::Duration::days(clock_day.load(Ordering::SeqCst))
                }));
        let identity =
            crate::identity::IdentityManager::new(NODE_TD, Duration::from_secs(3600)).unwrap();
        Self {
            st: IngressState {
                authority: Arc::new(authority),
                identity,
                gate: Arc::new(Semaphore::new(4)),
                request_proofs: None,
            },
            a,
            b,
            path,
            day,
            dir,
            n: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Rewrite the file as an operator (or a keeper) would.
    fn rewrite(&self, a_ceiling: &PermissionLattice, per_day: Option<&str>, third: bool) {
        std::fs::write(
            &self.path,
            registry(&self.a, &self.b, a_ceiling, per_day, third),
        )
        .unwrap();
    }

    /// A fresh token through the exchange, as `POST /v1/pods` would then use it.
    async fn exchange(&self) -> Result<Admission, Refusal> {
        let sub = format!("agent-{}", self.n.fetch_add(1, Ordering::SeqCst));
        let resp = exchange(
            &self.st,
            Some(&format!("Bearer {}", self.a.token(&sub, now()))),
            None,
            &body(&csr_for(&principal_a(&sub)), None),
            now(),
        )
        .await?;
        Ok(admission(&resp))
    }

    /// Admit a pod of `budget` USD and keep it: it holds its allocation.
    async fn admit(&self, who: &Admission, budget: u32) -> Result<uuid::Uuid, crate::ApiError> {
        let pod = uuid::Uuid::new_v4();
        self.st
            .authority
            .admit_kept(who, &pod_spec(Vec::new(), budget), pod)
            .await
            .map(|_| pod)
    }

    /// Where the binding's ledger is persisted: the key format is pinned here too.
    fn ledger_path(&self) -> PathBuf {
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        h.update(b"nucleus/federated-ledger/v1\0");
        h.update(TD_A.as_bytes());
        let key: [u8; 32] = h.finalize().into();
        self.dir
            .path()
            .join("authority/external")
            .join(format!("{}.json", hex::encode(key)))
    }

    /// The binding's persisted ledger record.
    fn ledger_file(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.ledger_path()).unwrap()).unwrap()
    }
}

fn refused_with(r: &Result<uuid::Uuid, crate::ApiError>, what: &str) -> bool {
    matches!(r, Err(crate::ApiError::Authority(m)) if m.contains(what))
}

/// (a) The window a caller's delegation carries is the binding's. A lapsed
/// window refuses the pod; the operator renews it in the file; the SAME node
/// admits the next exchange.
#[tokio::test]
async fn renewing_a_window_by_reload_admits_what_the_lapsed_one_refused() {
    let now = Utc::now();
    let lapsed = ceiling(
        10,
        now - chrono::Duration::hours(2),
        now - chrono::Duration::hours(1),
    );
    let live = Live::new(&lapsed, None);
    let who = live
        .exchange()
        .await
        .expect("the exchange itself still answers");
    let refused = live.admit(&who, 1).await;
    assert!(refused_with(&refused, "expired"), "{refused:?}");

    let (from, until) = open_window();
    live.rewrite(&ceiling(10, from, until), None, false);
    assert_eq!(
        live.st.authority.reload_registry(false),
        ReloadOutcome::Applied
    );

    let who = live.exchange().await.unwrap();
    live.admit(&who, 1)
        .await
        .expect("the renewed window admits, with no restart");
}

/// (b) A file that does not validate changes nothing: the bindings in force
/// stay in force, the node keeps serving, and health names what was refused.
#[tokio::test]
async fn an_invalid_registry_on_reload_keeps_the_old_one_serving() {
    use sha2::Digest as _;
    let (from, until) = open_window();
    let good = ceiling(10, from, until);
    let live = Live::new(&good, None);
    let health = live.st.authority.registry_health();
    let active = health["active_sha256"].clone();
    assert_eq!(health["reload"], "ok");

    // A typo'd field: start-up refuses it, so a reload must too.
    let mut text = std::fs::read_to_string(&live.path).unwrap();
    text.push_str("\n[[upstream]]\nname = \"x\"\nbase_url = \"https://x.example.invalid\"\nheader = \"h\"\ntypo = 1\n[upstream.credential.env]\nvar = \"X\"\n");
    std::fs::write(&live.path, &text).unwrap();
    let outcome = live.st.authority.reload_registry(false);
    assert!(matches!(outcome, ReloadOutcome::Refused(_)), "{outcome:?}");
    let health = live.st.authority.registry_health();
    assert_eq!(health["reload"], "refused");
    assert_eq!(
        health["active_sha256"], active,
        "the old file is still in force"
    );
    assert_eq!(
        health["refused_sha256"],
        json!(hex::encode(sha2::Sha256::digest(text.as_bytes())))
    );
    // Polled again, the same bad file is not re-read or re-logged.
    assert_eq!(
        live.st.authority.reload_registry(false),
        ReloadOutcome::Unchanged
    );

    // Still serving, under the old bindings.
    let who = live.exchange().await.unwrap();
    live.admit(&who, 1)
        .await
        .expect("the node is still admitting");

    // A valid file that adds a tenant is refused too: that is a restart.
    live.rewrite(&good, None, true);
    let outcome = live.st.authority.reload_registry(false);
    assert!(
        matches!(&outcome, ReloadOutcome::Refused(m) if m.contains("trust domains")),
        "{outcome:?}"
    );
    assert!(
        live.st
            .authority
            .caller_bindings()
            .by_trust_domain("tenant-c.example.invalid")
            .is_none()
    );

    // Put back, the file is the one in force again: nothing to reload, and
    // nothing refused any more.
    live.rewrite(&good, None, false);
    assert_eq!(
        live.st.authority.reload_registry(false),
        ReloadOutcome::Unchanged
    );
    assert_eq!(live.st.authority.registry_health()["reload"], "ok");
    // And a different good file is applied.
    live.rewrite(&ceiling(11, from, until), None, false);
    assert_eq!(
        live.st.authority.reload_registry(false),
        ReloadOutcome::Applied
    );
    assert_eq!(live.st.authority.registry_health()["reload"], "ok");
}

/// (c) The registry decides the ceiling. Raising `max_cost_usd` admits what
/// was refused; consumption and the retired list are carried over exactly;
/// lowering it below what is spent admits nothing more and refunds nothing.
#[tokio::test]
async fn raising_the_ceiling_by_reload_admits_and_keeps_history_exact() {
    let (from, until) = open_window();
    let live = Live::new(&ceiling(5, from, until), None);
    let who = live.exchange().await.unwrap();
    let first = live.admit(&who, 5).await.expect("the whole ceiling");
    live.st.authority.release_child(first).await;
    let refused = live.admit(&who, 1).await;
    assert!(refused_with(&refused, "budget conservation"), "{refused:?}");
    let before = live.ledger_file();
    assert_eq!(before["ledger"]["consumed_micro"], 5_000_000);
    assert_eq!(before["max_micro"], 5_000_000);

    live.rewrite(&ceiling(20, from, until), None, false);
    assert_eq!(
        live.st.authority.reload_registry(false),
        ReloadOutcome::Applied
    );
    let who = live.exchange().await.unwrap();
    live.admit(&who, 1)
        .await
        .expect("the raised ceiling admits, with no restart");
    let after = live.ledger_file();
    assert_eq!(after["ledger"], before["ledger"], "history byte-identical");
    assert_eq!(after["max_micro"], 20_000_000);

    // Lowered below what is used (5 consumed + 1 allocated): nothing more is
    // admitted, and nothing already spent is clamped away.
    live.rewrite(&ceiling(2, from, until), None, false);
    assert_eq!(
        live.st.authority.reload_registry(false),
        ReloadOutcome::Applied
    );
    let who = live.exchange().await.unwrap();
    let refused = live.admit(&who, 1).await;
    assert!(refused_with(&refused, "budget conservation"), "{refused:?}");
    assert_eq!(live.ledger_file()["ledger"], before["ledger"]);
    let held = live.st.authority.held().await;
    let ledger = held.external.values().next().unwrap();
    assert_eq!(
        (ledger.max, ledger.consumed, ledger.allocated),
        (6_000_000, 5_000_000, 1_000_000),
        "max(ceiling, consumed + allocated): nothing spent is clamped away"
    );
}

/// (d) A binding's day: exhausted, refused; the next UTC day admits, with no
/// restart. An unspawned pod's allocation is credited to the day it was
/// charged to.
#[tokio::test]
async fn a_spent_day_refuses_and_the_next_utc_day_admits() {
    let (from, until) = open_window();
    let live = Live::new(&ceiling(100, from, until), Some("3"));
    let who = live.exchange().await.unwrap();
    live.admit(&who, 2).await.unwrap();
    live.admit(&who, 1).await.unwrap();
    let refused = live.admit(&who, 1).await;
    assert!(refused_with(&refused, "daily allowance"), "{refused:?}");
    // The day is the only thing refusing: the ledger had room.
    assert!(!refused_with(&refused, "budget conservation"));

    live.day.fetch_add(1, Ordering::SeqCst);
    let pod = uuid::Uuid::new_v4();
    let (_plan, reservation) = live
        .st
        .authority
        .admit_pod(
            &who,
            pod_spec(Vec::new(), 3),
            pod,
            crate::host_decide::StartingLabel::Clean,
        )
        .await
        .expect("a new UTC day admits");
    assert!(refused_with(&live.admit(&who, 1).await, "daily allowance"));
    // The pod never ran: its 3 come back to the day they were charged to.
    reservation.release().await;
    live.admit(&who, 3)
        .await
        .expect("the unspawned allocation was credited back");
    let days = &live.ledger_file()["days"];
    assert_eq!(days.as_object().unwrap().len(), 2, "{days}");
    assert!(
        days.as_object().unwrap().values().all(|v| v == 3_000_000),
        "{days}"
    );
}

/// (e) A ledger written before days existed (version 1) still loads, and its
/// consumption still binds. A version this code does not know is refused.
#[tokio::test]
async fn a_version_one_ledger_still_loads() {
    let (from, until) = open_window();
    let live = Live::new(&ceiling(5, from, until), Some("100"));
    let who = live.exchange().await.unwrap();
    // Byte for byte what `persist_external` wrote before this change.
    let restore_into = |text: &str| {
        let path = live.ledger_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let _ = std::fs::remove_file(&path); // written 0o400
        std::fs::write(path, text).unwrap();
    };
    restore_into(
        r#"{"version":1,"max_micro":5000000,"ledger":{"consumed_micro":2000000,"retired":[]}}"#,
    );

    // A second node process over the same state: the restart path.
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
    let node = |live: &Live| {
        PodAuthority::new(
            &args,
            NODE_TD,
            live.dir.path(),
            &crate::pod_authority::NO_TPM,
        )
        .unwrap()
    };
    let restarted = node(&live);
    restarted.restore_from_disk().await;
    restarted
        .admit_kept(&who, &pod_spec(Vec::new(), 3), uuid::Uuid::new_v4())
        .await
        .expect("5 ceiling - 2 consumed in the v1 record = 3");
    let refused = restarted
        .admit_kept(&who, &pod_spec(Vec::new(), 1), uuid::Uuid::new_v4())
        .await;
    assert!(
        matches!(&refused, Err(crate::ApiError::Authority(m)) if m.contains("budget conservation")),
        "{refused:?}"
    );
    let rewritten = live.ledger_file();
    assert_eq!(rewritten["version"], 2);
    assert_eq!(rewritten["ledger"]["consumed_micro"], 2_000_000);

    restore_into(r#"{"version":9,"max_micro":5000000,"ledger":{"consumed_micro":0,"retired":[]}}"#);
    let restarted = node(&live);
    restarted.restore_from_disk().await;
    let refused = restarted
        .admit_kept(&who, &pod_spec(Vec::new(), 1), uuid::Uuid::new_v4())
        .await;
    assert!(
        matches!(&refused, Err(crate::ApiError::Authority(m)) if m.contains("could not restore")),
        "{refused:?}"
    );
}

/// The poll picks up a changed file by itself; nothing signals the node.
#[tokio::test]
async fn a_changed_file_is_reloaded_by_the_poll() {
    let (from, until) = open_window();
    let live = Live::new(&ceiling(5, from, until), None);
    crate::pod_authority::registry::spawn(
        Arc::clone(&live.st.authority),
        Duration::from_millis(20),
    );
    let before = live.st.authority.registry_health()["active_sha256"].clone();
    live.rewrite(&ceiling(7, from, until), None, false);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while live.st.authority.registry_health()["active_sha256"] == before {
        assert!(
            std::time::Instant::now() < deadline,
            "the poll never reloaded"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let bindings = live.st.authority.caller_bindings();
    let budget = &bindings.by_trust_domain(TD_A).unwrap().ceiling().budget;
    assert_eq!(budget.max_cost_usd, rust_decimal::Decimal::from(7));
}

/// The finding behind (c), on the restart path: before the registry was made
/// authoritative, the ledger's ceiling persisted at first charge won forever,
/// so even a RESTART with a raised `max_cost_usd` admitted nothing more.
#[tokio::test]
async fn a_raised_ceiling_applies_across_a_restart_too() {
    let (from, until) = open_window();
    let live = Live::new(&ceiling(5, from, until), None);
    let who = live.exchange().await.unwrap();
    let first = live.admit(&who, 5).await.unwrap();
    live.st.authority.release_child(first).await;
    live.rewrite(&ceiling(20, from, until), None, false);

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
    let restarted = PodAuthority::new(
        &args,
        NODE_TD,
        live.dir.path(),
        &crate::pod_authority::NO_TPM,
    )
    .unwrap();
    restarted.restore_from_disk().await;
    // The delegation from before the restart carries the old ceiling (5, of
    // which none is left in the lattice's own count); a new exchange is what a
    // caller does after a restart, and its certificate carries 20.
    let fresh = {
        let f = IngressState {
            authority: Arc::new(restarted),
            identity: live.st.identity.clone(),
            gate: Arc::new(Semaphore::new(1)),
            request_proofs: None,
        };
        let sub = "after-restart";
        let resp = exchange(
            &f,
            Some(&format!("Bearer {}", live.a.token(sub, now()))),
            None,
            &body(&csr_for(&principal_a(sub)), None),
            now(),
        )
        .await
        .unwrap();
        (f, admission(&resp))
    };
    fresh
        .0
        .authority
        .admit_kept(&fresh.1, &pod_spec(Vec::new(), 1), uuid::Uuid::new_v4())
        .await
        .expect("the registry's raised ceiling binds after a restart");
    assert_eq!(live.ledger_file()["ledger"]["consumed_micro"], 5_000_000);
}
