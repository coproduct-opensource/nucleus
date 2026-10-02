//! What a pod spec may say about the posture its pod runs under (#3120).
//!
//! # The rule
//!
//! A `PodSpec` is written by whoever creates the pod: an operator, a federated tenant, a CI
//! identity, or a pod creating a child. None of them is trusted to weaken the containment the
//! node puts around the pod. So every spec field that reaches a node-owned channel (the guest
//! kernel command line, the VMM config, a runtime environment) is either built by the node, or
//! parsed here against a grammar the node chose and **refused by name at create** when it does
//! not parse. Nothing is stripped: an author whose value silently disappears does not learn that
//! their spec means something other than what they wrote (#3124, #3125).
//!
//! [`admit`] is the one decider, and `create_pod_internal` calls it before anything is spawned.
//! Where a fact is needed again when the node builds the channel, admission hands the builder the
//! value it resolved (the audit sink's [`crate::audit_sink::AuditTarget`]) rather than the builder
//! deciding again (ADR 0007 G-1).
//!
//! # What each check closes
//!
//! - **`audit_sink`** — its four strings were appended verbatim to the guest kernel command line,
//!   after the node's own tokens. A bucket of `b init=/bin/sh` was two tokens; the kernel takes
//!   the LAST `init=`, so PID 1 was the spec's (#3120). And the spec chose the bucket and endpoint
//!   that the node's credentials then signed writes to (#3131). The spec now only names a sink the
//!   operator configured and may narrow its prefix (`audit_sink.rs`); an unknown name is refused.
//! - **`vsock.guest_cid`** — the node's PID-1 transport authenticates the host by peer CID 2
//!   (`KB-VSOCK-PEER-CID`). A guest whose own CID is 2 makes a loopback peer indistinguishable
//!   from the host. The guest only ever binds CID 3 (#2395), so 3 is the node's value.
//! - **`credentials.env`** — on the container driver these are appended after the runtime's own
//!   variables, so a spec could set `NUCLEUS_TOOL_PROXY_APPROVAL_SECRET` or `LD_PRELOAD` for the
//!   mediating process itself.
//! - **`timeout_seconds`** — becomes a certificate and task-token lifetime. A value past
//!   `TimeDelta`'s range panicked the create handler; one inside it minted tokens for centuries.
//! - **`budget_model`** — the spec priced its own command executions, below the runtime's
//!   default, so a budget stopped bounding how much a pod could run.

use nucleus_spec::{BudgetModelSpec, PodSpec};

use crate::ApiError;
use crate::audit_sink::{AuditSinks, AuditTarget};

/// The only guest vsock CID the node configures. The guest binds this CID (#2395), and the host
/// is CID 2, so the two can never coincide.
pub(crate) const GUEST_CID: u32 = 3;

/// The longest pod lifetime a spec may ask for: 30 days. It bounds the certificate and the
/// session task token minted from `timeout_seconds`, and keeps every value inside `TimeDelta`.
pub(crate) const MAX_TIMEOUT_SECONDS: u64 = 30 * 24 * 60 * 60;

/// The one `NUCLEUS_*` name a spec may put in `credentials.env`: the container driver's direct-mode
/// task runner, which the orchestrator supplies there (`spawn_container_pod`). Every other name in
/// the namespace is the runtime's.
const SPEC_SETTABLE_RESERVED: &[&str] = &["NUCLEUS_TASK_CMD"];

/// Why a spec was refused. Every variant names the field, and the value where showing it is safe.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub(crate) enum PostureRefused {
    /// An `audit_sink` value outside its grammar. These values ride the guest kernel command line.
    #[error(
        "audit_sink.{field} `{value}` is refused: {why}. Audit sink values are written to the \
         guest kernel command line, which the node owns, so each must be exactly one token."
    )]
    AuditSink {
        field: &'static str,
        value: String,
        why: &'static str,
    },
    /// An `audit_sink` naming a sink this node's operator did not configure (#3131).
    #[error(
        "audit_sink.sink `{name}` is refused: {configured}. Audit logs are written with the \
         operator's credentials, so the operator chooses where (`nucleus-node --audit-sinks`); \
         a spec may only name one of those sinks and narrow its prefix."
    )]
    AuditSinkUnknown { name: String, configured: String },
    /// A guest CID other than the node's.
    #[error(
        "vsock.guest_cid {cid} is refused: the node owns the guest CID and configures {GUEST_CID}. \
         CID 2 is the host, and the in-guest proxy authenticates the host by it."
    )]
    GuestCid { cid: u32 },
    /// A `credentials.env` name the runtime owns, or that is not an environment variable name.
    #[error(
        "credentials.env key `{key}` is refused: {why}. Credentials are passed to the pod's \
         workload, never to the runtime that mediates it."
    )]
    CredentialName { key: String, why: &'static str },
    /// A lifetime past the node's ceiling.
    #[error(
        "timeout_seconds {seconds} is refused: the most a pod may ask for is \
         {MAX_TIMEOUT_SECONDS} (30 days). It bounds the pod's certificate and task token."
    )]
    Timeout { seconds: u64 },
    /// A cost below the runtime's own price, or not a finite number.
    #[error(
        "budget_model.{field} {value} is refused: a pod spec may raise the price of an execution \
         but not lower it below the runtime's {floor}"
    )]
    BudgetModel {
        field: &'static str,
        value: f64,
        floor: f64,
    },
    /// A container network mode other than the node's own or `none`.
    #[error(
        "label nucleus.io/network `{value}` is refused: a pod may ask for `none` or the node's \
         own network (`{node}`), never a different one such as `host`"
    )]
    ContainerNetwork { value: String, node: String },
}

impl From<PostureRefused> for ApiError {
    fn from(e: PostureRefused) -> Self {
        ApiError::InvalidSpec(e.to_string())
    }
}

/// Refuse at create a spec that asks for a weaker posture than the node gives. The one decider.
///
/// On success, returns where the pod's audit log goes, resolved against the operator's `sinks`:
/// the only value the drivers render an audit sink from.
pub(crate) fn admit(
    spec: &PodSpec,
    sinks: &AuditSinks,
) -> Result<Option<AuditTarget>, PostureRefused> {
    let inner = &spec.spec;
    let audit = sinks.resolve_for(spec)?;
    if let Some(vsock) = &inner.vsock
        && vsock.guest_cid != GUEST_CID
    {
        return Err(PostureRefused::GuestCid {
            cid: vsock.guest_cid,
        });
    }
    if let Some(creds) = &inner.credentials {
        for key in creds.env.keys() {
            credential_name(key)?;
        }
    }
    if inner.timeout_seconds > MAX_TIMEOUT_SECONDS {
        return Err(PostureRefused::Timeout {
            seconds: inner.timeout_seconds,
        });
    }
    if let Some(model) = &inner.budget_model {
        budget_model(model)?;
    }
    Ok(audit)
}

/// A `credentials.env` name: an environment variable name outside the runtime's namespaces.
fn credential_name(key: &str) -> Result<(), PostureRefused> {
    let why = if key.is_empty()
        || key.starts_with(|c: char| c.is_ascii_digit())
        || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        Some("an environment variable name is [A-Za-z_][A-Za-z0-9_]*")
    } else if key.starts_with("NUCLEUS_") && !SPEC_SETTABLE_RESERVED.contains(&key) {
        Some("the NUCLEUS_ namespace is the runtime's")
    } else if key.starts_with("LD_") {
        Some("LD_ variables configure the dynamic loader of the process that receives them")
    } else {
        None
    };
    match why {
        Some(why) => Err(PostureRefused::CredentialName {
            key: key.to_string(),
            why,
        }),
        None => Ok(()),
    }
}

/// A spec may price an execution above the runtime's default, never below it.
fn budget_model(model: &BudgetModelSpec) -> Result<(), PostureRefused> {
    let floor = nucleus::BudgetModel::default();
    let BudgetModelSpec {
        base_cost_usd,
        cost_per_second_usd,
    } = *model;
    for (field, value, floor) in [
        ("base_cost_usd", base_cost_usd, floor.base_cost_usd),
        (
            "cost_per_second_usd",
            cost_per_second_usd,
            floor.cost_per_second_usd,
        ),
    ] {
        // Finiteness first: NaN compares false both ways, so `value < floor` alone would admit it.
        if !value.is_finite() || value < floor {
            return Err(PostureRefused::BudgetModel {
                field,
                value,
                floor,
            });
        }
    }
    Ok(())
}

/// The docker network mode a container pod runs in: the node's own, unless the pod asks for
/// `none`, which is narrower. Any other value — `host`, `container:<id>`, another named network —
/// is refused.
pub(crate) fn container_network(
    label: Option<&str>,
    node_default: &str,
) -> Result<String, PostureRefused> {
    match label {
        None => Ok(node_default.to_string()),
        Some(v) if v == "none" || v == node_default => Ok(v.to_string()),
        Some(v) => Err(PostureRefused::ContainerNetwork {
            value: v.to_string(),
            node: node_default.to_string(),
        }),
    }
}

#[cfg(test)]
#[path = "spec_posture_tests.rs"]
mod tests;
