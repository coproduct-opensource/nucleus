//! Links between pods, the control plane (ADR 0017 L4a): the routes that make,
//! unmake and list links, the 409 a cancel of a linked pod gets, and the drop
//! receipts an exit the node did not request signs.
//!
//! # Who decides what
//!
//! Authorization stays the node's. Every handler resolves the pods it names
//! through [`get_pod_for_caller`], so a pod outside the caller's scope is a 404
//! whichever end it is — the answer never says which end failed (ADR 0001, §2).
//! Only then does the handler ask [`LinkTable`] (with [`Scope::NodeWide`], since
//! the caller's scope has already been applied), whose extracted predicates
//! decide the rest: both ends running, one trust domain, no self link, no
//! duplicate row (`LinkTableExtracted.lean`, `may_link_is_admitLink`).
//!
//! # Trust domains
//!
//! A pod's trust domain is the one its certificate root was issued in
//! ([`Lineage::lineage_tenant`]). A pod with no federated owner — every pod an
//! operator, orchestrator or pod of this node created — is in the node-local
//! domain, written `""`. So a federated tenant's pod and a node-local pod never
//! share a domain, and are never linked.
//!
//! # The data plane (L4b)
//!
//! A pod with a link proxy (`link_proxy`) has a [`Relay`]: the control socket
//! its proxy reads `LINK`/`SEVER` lines from, and its own Firecracker vsock
//! socket, which is where a link TO it is dialled. Making a link writes `LINK`
//! to the source's relay; unmaking it, or either end exiting, writes `SEVER`
//! **before** the receipt is signed, so a receipt that says "unlinked" is never
//! signed while the proxy can still carry bytes on it. Both are written under
//! the table lock. Each request the link proxy asks about is recorded in the
//! table as `connect` then `request` (`link_proxy::LinkDecider`).

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::routing::{delete, post};
use axum::{Extension, Json, Router};
use nucleus_ifc_kernel::extracted::link::{Link, names};
use nucleus_ifc_kernel::links::{Conn, Effect, LinkTable, Outcome, Scope};
use nucleus_receipt::{Projection, Receipt};
use serde::Deserialize;
use uuid::Uuid;

use crate::api_error::ApiError;
use crate::auth::CallerScope;
use crate::pod_api::{Lineage, get_pod_for_caller};
use crate::{NodeState, PodHandle, PodState};

/// The table, and the drop receipts signed for each surviving end.
pub(crate) struct Links {
    table: LinkTable,
    drops: HashMap<Uuid, Vec<Receipt>>,
    /// Each running pod's link proxy control socket and vsock path (L4b).
    relays: HashMap<Uuid, crate::link_proxy::Relay>,
    /// The node-side byte pipe of each announced link, keyed by row.
    forwarders: HashMap<(u128, u128, u32), crate::link_proxy::Forwarder>,
    /// Names forwarder sockets (`lf-<n>.sock`): a pod directory and a uuid
    /// would overrun a Unix socket path's 108 bytes.
    next_forwarder: u64,
}

/// `NodeState.links`. An async lock: [`cancel_unlinked`] holds it across a
/// teardown, so no link is made between "no link names it" and the cancel.
pub(crate) type SharedLinks = Arc<tokio::sync::Mutex<Links>>;

#[must_use]
pub(crate) fn shared() -> SharedLinks {
    Arc::new(tokio::sync::Mutex::new(Links {
        table: LinkTable::empty(),
        drops: HashMap::new(),
        relays: HashMap::new(),
        forwarders: HashMap::new(),
        next_forwarder: 0,
    }))
}

impl Links {
    /// Whether the table holds exactly this row (the link proxy's route).
    pub(crate) fn has_row(&self, row: Link) -> bool {
        self.table.links().contains(&row)
    }

    /// Record one request the link proxy asked about: a connection on the row
    /// (`LinkTable::connect`), then the request with the host's answer
    /// (`LinkTable::request`), then its close (`LinkTable::close`). The table's own
    /// predicates decide all three.
    pub(crate) fn record_request(&mut self, id: u64, row: Link, admitted: bool) {
        let connected = self.table.connect(id, row);
        if connected.outcome == Outcome::Done {
            let conn = Conn { id, link: row };
            let _ = self.table.request(conn, admitted);
            // One request per connection (ADR 0015): once it is decided the
            // connection is over (`LinkTable.close`), so the table stays bounded
            // however many requests a link carries
            // (`connect_request_close_bounded`).
            let _ = self.table.close(conn);
        }
    }

    /// How many connections the table holds open.
    #[cfg(test)]
    pub(crate) fn open_conns(&self) -> usize {
        self.table.conns().len()
    }

    /// Start the node-side forwarder for `row` and write `LINK` to its source's
    /// relay, naming the forwarder (`link_proxy::Forwarder`: the proxy cannot
    /// reach the destination's jail). Nothing to write when either end has no
    /// link proxy.
    async fn announce(&mut self, row: Link) {
        let (Some(src), Some(dst)) = (
            self.relays.get(&uuid_of(row.src)),
            self.relays.get(&uuid_of(row.dst)),
        ) else {
            return;
        };
        self.next_forwarder += 1;
        let path = src.pod_dir.join(format!("lf-{}.sock", self.next_forwarder));
        let forwarder = match crate::link_proxy::Forwarder::start(
            path,
            &src.vsock,
            dst.vsock.clone(),
            src.run_as,
        ) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, src = %uuid_of(row.src), "link forwarder not started; the link carries nothing");
                return;
            }
        };
        let line = format!(
            "LINK {} {} {} {}",
            uuid_of(row.dst),
            row.port,
            nucleus_spec::LINK_RELAY_GUEST_PORT,
            forwarder.path().display()
        );
        let control = Arc::clone(&src.control);
        self.forwarders
            .insert((row.src, row.dst, row.port), forwarder);
        if let Err(e) = control.send(&line).await {
            tracing::warn!(error = %e, src = %uuid_of(row.src), "link proxy control: LINK not written");
        }
    }

    /// Write `SEVER` for `row` to its source's relay. Called before the
    /// receipt is signed; a relay that is gone carries nothing to sever.
    async fn sever(&mut self, row: Link) {
        // The node's pipe first: its connections close whatever the proxy does.
        self.forwarders.remove(&(row.src, row.dst, row.port));
        let Some(src) = self.relays.get(&uuid_of(row.src)) else {
            return;
        };
        let line = format!("SEVER {} {}", uuid_of(row.dst), row.port);
        if let Err(e) = src.control.send(&line).await {
            tracing::warn!(error = %e, src = %uuid_of(row.src), "link proxy control: SEVER not written");
        }
    }
}

/// A pod's link proxy came up: record its relay, so links to and from it reach
/// the data plane.
pub(crate) async fn relay_started(state: &NodeState, pod: Uuid, relay: crate::link_proxy::Relay) {
    state.links.lock().await.relays.insert(pod, relay);
}

pub(crate) fn routes() -> Router<NodeState> {
    Router::new()
        .route("/v1/pods/{id}/links", post(link_pods).get(list_links))
        .route("/v1/pods/{id}/links/{dst}/{port}", delete(unlink_pods))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinkBody {
    pub dst: Uuid,
    pub port: u32,
}

fn trust_domain(pod: &Arc<PodHandle>) -> String {
    pod.lineage_tenant().unwrap_or("").to_owned()
}

async fn running(pod: &PodHandle) -> bool {
    matches!(pod.status().await, PodState::Running)
}

fn uuid_of(raw: u128) -> Uuid {
    Uuid::from_u128(raw)
}

/// The Link projection's body for one table effect (`nucleus-receipt`,
/// `Projection::Link`): `src`, `dst`, `port`, and per op what else happened.
fn body(effect: &Effect, exited: Option<Uuid>) -> Option<(Uuid, serde_json::Value)> {
    let row = |l: &Link| {
        serde_json::json!({
            "src": uuid_of(l.src).to_string(),
            "dst": uuid_of(l.dst).to_string(),
            "port": l.port,
        })
    };
    let with = |l: &Link, op: &str, extra: serde_json::Value| {
        let mut v = row(l);
        v["op"] = serde_json::Value::from(op);
        if let (Some(m), Some(e)) = (v.as_object_mut(), extra.as_object()) {
            m.extend(e.clone());
        }
        (uuid_of(l.src), v)
    };
    match effect {
        Effect::Link(l) => Some(with(l, "link", serde_json::json!({}))),
        Effect::Unlink { link, severed } => Some(with(
            link,
            "unlink",
            serde_json::json!({ "severed": severed }),
        )),
        Effect::Drop(l) => Some(with(
            l,
            "drop-on-exit",
            serde_json::json!({ "exited": exited.map(|e| e.to_string()) }),
        )),
        Effect::Connect(_) | Effect::Request(_) | Effect::Close(_) | Effect::Cancel(_) => None,
    }
}

fn sign(state: &NodeState, effect: &Effect, exited: Option<Uuid>) -> Result<Receipt, ApiError> {
    let (session, value) =
        body(effect, exited).ok_or_else(|| ApiError::Driver("not a link receipt".into()))?;
    crate::workload_result::sign_projection(state, session, Projection::Link(value))
}

/// Both ends, each through the caller's scope. Either out of scope is the same
/// 404, so the answer does not say which.
async fn both(
    state: &NodeState,
    caller: &CallerScope,
    src: Uuid,
    dst: Uuid,
) -> Result<(Arc<PodHandle>, Arc<PodHandle>), ApiError> {
    let s = get_pod_for_caller(state, src, caller).await;
    let d = get_pod_for_caller(state, dst, caller).await;
    match (s, d) {
        (Ok(s), Ok(d)) => Ok((s, d)),
        _ => Err(ApiError::NotFound),
    }
}

/// `POST /v1/pods/{src}/links` `{dst, port}`.
async fn link_pods(
    State(state): State<NodeState>,
    Extension(caller): Extension<CallerScope>,
    AxumPath(src): AxumPath<Uuid>,
    Json(req): Json<LinkBody>,
) -> Result<Json<Receipt>, ApiError> {
    // A link port is a TCP port: the proxy's control line and its target
    // carry it as one, and a line it cannot parse severs every link.
    if req.port == 0 || req.port > u32::from(u16::MAX) {
        return Err(ApiError::InvalidSpec(format!(
            "link port {} is not a TCP port (1..=65535)",
            req.port
        )));
    }
    let (s, d) = both(&state, &caller, src, req.dst).await?;
    let mut links = state.links.lock().await;
    if !(running(&s).await && running(&d).await) {
        return Err(ApiError::Conflict(
            "both pods must be running to be linked".into(),
        ));
    }
    links.table.pod_started(src.as_u128(), trust_domain(&s));
    links.table.pod_started(req.dst.as_u128(), trust_domain(&d));
    let link = Link {
        src: src.as_u128(),
        dst: req.dst.as_u128(),
        port: req.port,
    };
    let r = links.table.link(&Scope::NodeWide, link);
    match r.outcome {
        Outcome::Done => {
            links.announce(link).await;
            Ok(Json(sign(&state, &r.effect, None)?))
        }
        Outcome::Refused => Err(ApiError::Conflict(
            "link refused: the pods are in different trust domains, are the same pod, or are \
             already linked on this port"
                .into(),
        )),
    }
}

/// `DELETE /v1/pods/{src}/links/{dst}/{port}`. Only the source is resolved:
/// unmaking a link needs the source in scope (`may_unlink`), and resolving the
/// destination would answer whether it exists.
async fn unlink_pods(
    State(state): State<NodeState>,
    Extension(caller): Extension<CallerScope>,
    AxumPath((src, dst, port)): AxumPath<(Uuid, Uuid, u32)>,
) -> Result<Json<Receipt>, ApiError> {
    get_pod_for_caller(&state, src, &caller).await?;
    let mut links = state.links.lock().await;
    let link = Link {
        src: src.as_u128(),
        dst: dst.as_u128(),
        port,
    };
    let r = links.table.unlink(&Scope::NodeWide, link);
    match r.outcome {
        Outcome::Done => {
            // Severed before the receipt that says so is signed.
            links.sever(link).await;
            Ok(Json(sign(&state, &r.effect, None)?))
        }
        Outcome::Refused => Err(ApiError::NotFound),
    }
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct Listing {
    pub links: Vec<serde_json::Value>,
    /// Signed receipts for links this pod lost because the other end exited.
    pub dropped: Vec<Receipt>,
}

/// `GET /v1/pods/{src}/links`: the links naming the pod, and its drop receipts.
async fn list_links(
    State(state): State<NodeState>,
    Extension(caller): Extension<CallerScope>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<Json<Listing>, ApiError> {
    get_pod_for_caller(&state, id, &caller).await?;
    let links = state.links.lock().await;
    let rows = links
        .table
        .links()
        .iter()
        .filter(|l| names(**l, id.as_u128()))
        .map(|l| {
            serde_json::json!({
                "src": uuid_of(l.src).to_string(),
                "dst": uuid_of(l.dst).to_string(),
                "port": l.port,
            })
        })
        .collect();
    let dropped = links.drops.get(&id).cloned().unwrap_or_default();
    Ok(Json(Listing {
        links: rows,
        dropped,
    }))
}

/// A cancel through the API: refused (409) while a link names the pod
/// (`may_cancel`, `cancel_refuses_linked`). The table lock is held across the
/// teardown, so no link is made in between.
///
/// The check, the teardown and the forget run in one detached task, as
/// `PodHandle::cancel_detached` does for an unlinked node: a caller that drops
/// the request mid-teardown neither strands the pod's capacity nor releases the
/// table lock while the pod is half torn down.
pub(crate) async fn cancel_unlinked(
    state: &NodeState,
    pod: &Arc<PodHandle>,
) -> Result<(), ApiError> {
    let links = Arc::clone(&state.links);
    let pod = Arc::clone(pod);
    tokio::spawn(async move {
        let mut links = links.lock().await;
        if links
            .table
            .links()
            .iter()
            .any(|l| names(*l, pod.id.as_u128()))
        {
            return Err(ApiError::Conflict(
                "the pod is linked; unlink it before cancelling".into(),
            ));
        }
        pod.cancel().await?;
        // No link names it, so this drops nothing; it only forgets the pod.
        let dropped = links.table.exit(pod.id.as_u128());
        links.relays.remove(&pod.id);
        debug_assert!(dropped.is_empty());
        Ok(())
    })
    .await
    .map_err(|e| ApiError::SupervisorUnavailable(format!("teardown task failed: {e}")))?
}

/// The gRPC form of [`cancel_unlinked`]: a linked pod is `FAILED_PRECONDITION`.
pub(crate) async fn grpc_cancel(state: &NodeState, pod: &Arc<PodHandle>) -> Result<(), tonic::Status> {
    cancel_unlinked(state, pod).await.map_err(|e| match e {
        ApiError::Conflict(m) => tonic::Status::failed_precondition(m),
        other => tonic::Status::internal(other.to_string()),
    })
}

/// An exit the node did not request (timeout, reaper, cascade, drain, an
/// abandoned launch): the pod's links go, and each surviving end is given a
/// signed drop receipt (`exit_drops_links`).
pub(crate) async fn pod_gone(state: &NodeState, id: Uuid) {
    let mut links = state.links.lock().await;
    for r in links.table.exit(id.as_u128()) {
        let Effect::Drop(link) = &r.effect else {
            continue;
        };
        // Severed before the drop receipt is signed. If the exited pod was
        // the source, its proxy is going with it.
        links.sever(*link).await;
        let survivor = if uuid_of(link.src) == id {
            uuid_of(link.dst)
        } else {
            uuid_of(link.src)
        };
        match sign(state, &r.effect, Some(id)) {
            Ok(receipt) => links.drops.entry(survivor).or_default().push(receipt),
            Err(error) => tracing::error!(pod = %id, %error, "drop receipt not signed"),
        }
    }
    links.relays.remove(&id);
}

#[cfg(all(test, feature = "local-driver"))]
mod tests {
    use super::*;
    use crate::pod_api::handler_tests::{register, register_as, state};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const TENANT_A: &str = "spiffe://tenant-a.example.invalid/ns/rt-a/sa/alice";
    const TENANT_A2: &str = "spiffe://tenant-a.example.invalid/ns/rt-a/sa/bob";
    const TENANT_B: &str = "spiffe://tenant-b.example.invalid/ns/rt-b/sa/bob";

    fn tenant(td: &str) -> CallerScope {
        CallerScope::Tenant(td.to_owned())
    }

    async fn call(
        st: &NodeState,
        caller: CallerScope,
        method: &str,
        uri: String,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let app = routes().layer(Extension(caller)).with_state(st.clone());
        let mut req = Request::builder().method(method).uri(uri);
        let body = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let resp = app.oneshot(req.body(body).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    fn vk(st: &NodeState) -> [u8; 32] {
        st.trust_gate
            .executor_signing_key
            .verifying_key()
            .to_bytes()
    }

    async fn link(st: &NodeState, caller: CallerScope, a: Uuid, b: Uuid) -> StatusCode {
        call(
            st,
            caller,
            "POST",
            format!("/v1/pods/{a}/links"),
            Some(serde_json::json!({"dst": b, "port": 8080})),
        )
        .await
        .0
    }

    /// A link's receipt verifies; unlink signs a second; GET lists, then not.
    #[tokio::test]
    async fn link_list_unlink_with_verifying_receipts() {
        let dir = tempfile::tempdir().unwrap();
        let st = state(&dir);
        let (a, b) = (register(&st, None).await, register(&st, None).await);
        let (s, v) = call(
            &st,
            CallerScope::NodeWide,
            "POST",
            format!("/v1/pods/{a}/links"),
            Some(serde_json::json!({"dst": b, "port": 8080})),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let r: Receipt = serde_json::from_value(v).unwrap();
        r.verify(&vk(&st)).expect("link receipt verifies");
        assert_eq!(r.projections[0].kind(), "link");

        let (s, v) = call(
            &st,
            CallerScope::NodeWide,
            "GET",
            format!("/v1/pods/{b}/links"),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            v["links"].as_array().unwrap().len(),
            1,
            "the dst end lists it too"
        );

        let (s, v) = call(
            &st,
            CallerScope::NodeWide,
            "DELETE",
            format!("/v1/pods/{a}/links/{b}/8080"),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let r: Receipt = serde_json::from_value(v).unwrap();
        r.verify(&vk(&st)).expect("unlink receipt verifies");
        let (_, v) = call(
            &st,
            CallerScope::NodeWide,
            "GET",
            format!("/v1/pods/{a}/links"),
            None,
        )
        .await;
        assert!(v["links"].as_array().unwrap().is_empty());
        // An unlink of a link that is not there is a 404.
        let (s, _) = call(
            &st,
            CallerScope::NodeWide,
            "DELETE",
            format!("/v1/pods/{a}/links/{b}/8080"),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    /// `no_cross_tenant_link`: a node-wide caller cannot link two trust
    /// domains (409); a tenant naming another tenant's pod gets 404, the same
    /// whichever end it is; within one domain the link is made.
    #[tokio::test]
    async fn no_cross_tenant_link() {
        let dir = tempfile::tempdir().unwrap();
        let st = state(&dir);
        let a = register_as(&st, None, Some(TENANT_A)).await;
        let a2 = register_as(&st, None, Some(TENANT_A2)).await;
        let b = register_as(&st, None, Some(TENANT_B)).await;
        let local = register(&st, None).await;
        let ta = tenant("tenant-a.example.invalid");

        assert_eq!(
            link(&st, CallerScope::NodeWide, a, b).await,
            StatusCode::CONFLICT
        );
        assert_eq!(
            link(&st, CallerScope::NodeWide, a, local).await,
            StatusCode::CONFLICT
        );
        assert_eq!(link(&st, ta.clone(), a, b).await, StatusCode::NOT_FOUND);
        assert_eq!(link(&st, ta.clone(), b, a).await, StatusCode::NOT_FOUND);
        assert_eq!(
            link(&st, ta.clone(), a, a).await,
            StatusCode::CONFLICT,
            "no self link"
        );
        assert_eq!(link(&st, ta.clone(), a, a2).await, StatusCode::OK);
        assert_eq!(
            link(&st, ta, a, a2).await,
            StatusCode::CONFLICT,
            "no duplicate row"
        );
        let listed = st.links.lock().await.table.links().len();
        assert_eq!(listed, 1);
    }

    /// `cancel_refuses_linked`: 409 while linked; after unlink, the cancel runs.
    #[tokio::test]
    async fn cancel_of_a_linked_pod_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let st = state(&dir);
        let (a, b) = (register(&st, None).await, register(&st, None).await);
        assert_eq!(link(&st, CallerScope::NodeWide, a, b).await, StatusCode::OK);
        let cancel = crate::pod_api::cancel_pod(
            State(st.clone()),
            Extension(CallerScope::NodeWide),
            AxumPath(b),
        )
        .await;
        assert!(matches!(cancel, Err(ApiError::Conflict(_))), "{cancel:?}");
        let pod = crate::pod_api::get_pod(&st, b).await.unwrap();
        assert!(running(&pod).await, "a refused cancel changes nothing");
        call(
            &st,
            CallerScope::NodeWide,
            "DELETE",
            format!("/v1/pods/{a}/links/{b}/8080"),
            None,
        )
        .await;
        let cancel = crate::pod_api::cancel_pod(
            State(st.clone()),
            Extension(CallerScope::NodeWide),
            AxumPath(b),
        )
        .await;
        assert!(cancel.is_ok(), "{cancel:?}");
        let other = crate::pod_api::get_pod(&st, a).await.unwrap();
        other.cancel().await.unwrap();
    }

    /// `exit_drops_links`: an exit the node did not request drops the link and
    /// gives the survivor a verifying drop receipt.
    #[tokio::test]
    async fn exit_drops_links_with_a_receipt_for_the_survivor() {
        let dir = tempfile::tempdir().unwrap();
        let st = state(&dir);
        let (a, b) = (register(&st, None).await, register(&st, None).await);
        assert_eq!(link(&st, CallerScope::NodeWide, a, b).await, StatusCode::OK);
        let pod = crate::pod_api::get_pod(&st, b).await.unwrap();
        pod.cancel().await.unwrap();
        pod_gone(&st, b).await;
        let (_, v) = call(
            &st,
            CallerScope::NodeWide,
            "GET",
            format!("/v1/pods/{a}/links"),
            None,
        )
        .await;
        assert!(v["links"].as_array().unwrap().is_empty());
        let dropped: Vec<Receipt> = serde_json::from_value(v["dropped"].clone()).unwrap();
        assert_eq!(dropped.len(), 1);
        dropped[0].verify(&vk(&st)).expect("drop receipt verifies");
        let crate_body = serde_json::to_value(&dropped[0].projections[0]).unwrap();
        assert_eq!(crate_body["body"]["op"], "drop-on-exit");
        assert_eq!(crate_body["body"]["exited"], b.to_string());
        crate::pod_api::get_pod(&st, a)
            .await
            .unwrap()
            .cancel()
            .await
            .unwrap();
    }
}
