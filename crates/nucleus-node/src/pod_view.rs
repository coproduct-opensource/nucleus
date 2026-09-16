//! The pod types the management API serves.
//!
//! Extracted from `main.rs` so the node's entrypoint is the wiring and not also
//! the data model. Nothing here decides anything: these are the shapes
//! `pod_api` returns and `pod_receipt` matches on, and the reason they are
//! together is that they are the pod as an OPERATOR sees it — id, lineage,
//! liveness, posture — which is a different thing from the pod as the node runs
//! it (`PodHandle`, still in `main.rs` with the machinery it owns).

use std::collections::BTreeMap;

use nucleus_spec::PodSpec;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PodState {
    Running,
    Exited { code: Option<i32> },
    Error { message: String },
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PodInfo {
    pub(crate) id: Uuid,
    pub(crate) name: Option<String>,
    pub(crate) created_at_unix: u64,
    pub(crate) state: PodState,
    pub(crate) proxy_addr: Option<String>,
    pub(crate) labels: BTreeMap<String, String>,
    /// The pod that created this one (its lineage parent), or `null` for a
    /// node/orchestrator-created top-level pod. Surfaced because it is the fact
    /// the management API's cross-pod scoping (`pod_api::caller_may_manage`) reads:
    /// an operator can see the lineage the filter enforces, and a running-node
    /// test can assert the create path recorded it. Not agent-controlled — the
    /// node establishes it from the authenticated caller at creation.
    /// Explicit null distinguishes a root from a node that does not report lineage.
    pub(crate) parent_pod_id: Option<Uuid>,
    /// The verified proof-carrying posture (`<posture>:verified`), present only
    /// when the pod carried a `dlc_posture` claim that passed admission against
    /// the host-measured rootfs and the trusted-posture registry. Absent means
    /// the pod made no such claim — a pod whose claim FAILED never reaches this
    /// list, because admission refused it. See `posture.rs`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) posture: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreatePodResponse {
    pub(crate) id: Uuid,
    pub(crate) proxy_addr: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreatePodRequest {
    #[serde(default)]
    pub(crate) spec: Option<PodSpec>,
    #[serde(default)]
    pub(crate) yaml: Option<String>,
}
