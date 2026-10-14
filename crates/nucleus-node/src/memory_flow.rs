//! Memory-flow receipts: every decision about who may see or change a memory space, signed by
//! the node and appended to its own `lifecycle.log` before the decision takes effect.
//!
//! One claim per decision. Its derived serialization, canonicalized (RFC 8785), is the preimage
//! (ADR 0007 F-1): nothing is formatted into it, and each event carries exactly its own fields
//! (an enum, not a struct of options). The signature space is the node root key's
//! `SignedRecord::MemoryFlow`, so a flow receipt never verifies as a pod receipt.
//!
//! What a receipt claims, and what it does not:
//!
//! * a **snapshot delivery** says these bytes (by SHA-256) were placed where this run's binding
//!   could read them, for this space, version, head and view. It is written before the pod is
//!   handed the directory, so it over-approximates disclosure when a pod then fails to start,
//!   never the other way round. It does not claim anything the run then read: reads of a
//!   delivered snapshot are local to the pod and unmediated, and nothing here observes them;
//! * a **publish authorized** says the node decided this commit onto this head under this
//!   binding, and is kept before the commit is appended;
//! * revocation receipts say what was refused from then on. Revocation does not erase what a
//!   run was already given: a delivered snapshot stays disclosed.
use std::path::{Path, PathBuf};

use nucleus_provenance_memory::Pin;
use serde::Serialize;
use uuid::Uuid;

use crate::ApiError;
use crate::memory_space::{
    Audience, Expiry, LabelStamping, MemoryWriter, Mode, PolicyAuthority, SchemaAtom, SpaceId,
    SpaceOrigin, TenantKey, ViewSpec,
};

const FLOW_SCHEMA: &str = "nucleus.memory-flow.v2";

/// Records a decision's signed receipt before the decision takes effect (`record`, bound to the
/// node's state dir and authority by its caller).
pub(crate) type Recorder<'r> = &'r mut dyn FnMut(&FlowClaim<'_>) -> Result<(), ApiError>;

/// One memory-flow decision, as the node signs it.
#[derive(Debug, Serialize)]
pub(crate) struct FlowClaim<'a> {
    schema: &'static str,
    tenant: &'a str,
    space: &'a SpaceId,
    at_unix: u64,
    event: FlowEvent<'a>,
}

/// What was decided. Each arm carries its own fields and no other's.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum FlowEvent<'a> {
    /// A space came to exist.
    SpaceCreated {
        origin: SpaceOrigin,
        schema: &'a std::collections::BTreeSet<SchemaAtom>,
        quota_bytes: u64,
        epoch: u32,
        /// Whether every record it holds is dependency-stamped (Program C, C1).
        stamping: LabelStamping,
    },
    /// A binding policy was recorded.
    PolicyCreated {
        policy: Uuid,
        audience: &'a Audience,
        mode: Mode,
        view: &'a ViewSpec,
        may_publish: bool,
        allocation_bytes: u64,
        expiry: Expiry,
        authority: &'a PolicyAuthority,
        epoch: u32,
    },
    /// A policy was revoked: no new binding from it, and no new mediated op under one.
    PolicyRevoked { policy: Uuid },
    /// A space moved to `epoch`: every policy and binding of an earlier epoch is refused.
    SpaceRevoked { epoch: u32 },
    /// A store from an earlier layout became this space, reachable under `policy`.
    Migrated {
        layout: &'static str,
        policy: Uuid,
        audience: &'a Audience,
    },
    /// A store from an earlier layout collides with a space the tenant already has; it is not
    /// migrated and stays unreachable.
    MigrationSkipped { layout: &'static str },
    /// A run's binding was minted and its snapshot placed where the run can read it.
    SnapshotDelivery {
        binding: Uuid,
        pod: Uuid,
        lineage: Uuid,
        policy: Uuid,
        audience: &'a Audience,
        mode: Mode,
        view: &'a ViewSpec,
        view_digest: String,
        base: Pin,
        records: usize,
        bytes_sha256: String,
        epoch: u32,
        not_after: u64,
        allocation_bytes: u64,
        /// Whether the run's proxy stamps its writes, which decided what it was given: a legacy
        /// run is given only stamped Public records (Program C, C1).
        writer: MemoryWriter,
    },
    /// The node decided a publish under a binding: `head` is the head its commit creates.
    PublishAuthorized {
        binding: Uuid,
        pod: Uuid,
        base: Pin,
        expected: Pin,
        head: Pin,
        records: usize,
        spend_bytes: u64,
        epoch: u32,
    },
}

impl FlowEvent<'_> {
    fn name(&self) -> &'static str {
        match self {
            FlowEvent::SpaceCreated { .. } => "memory_space_created",
            FlowEvent::PolicyCreated { .. } => "memory_policy_created",
            FlowEvent::PolicyRevoked { .. } => "memory_policy_revoked",
            FlowEvent::SpaceRevoked { .. } => "memory_space_revoked",
            FlowEvent::Migrated { .. } => "memory_space_migrated",
            FlowEvent::MigrationSkipped { .. } => "memory_space_migration_skipped",
            FlowEvent::SnapshotDelivery { .. } => "memory_snapshot_delivery",
            FlowEvent::PublishAuthorized { .. } => "memory_publish_authorized",
        }
    }

    /// The pod a decision is about, if it is about one.
    fn pod(&self) -> Option<Uuid> {
        match self {
            FlowEvent::SnapshotDelivery { pod, .. } | FlowEvent::PublishAuthorized { pod, .. } => {
                Some(*pod)
            }
            FlowEvent::SpaceCreated { .. }
            | FlowEvent::PolicyCreated { .. }
            | FlowEvent::PolicyRevoked { .. }
            | FlowEvent::SpaceRevoked { .. }
            | FlowEvent::Migrated { .. }
            | FlowEvent::MigrationSkipped { .. } => None,
        }
    }
}

impl<'a> FlowClaim<'a> {
    pub(crate) fn new(
        tenant: &'a TenantKey,
        space: &'a SpaceId,
        at_unix: u64,
        event: FlowEvent<'a>,
    ) -> Self {
        Self {
            schema: FLOW_SCHEMA,
            tenant: tenant.as_str(),
            space,
            at_unix,
            event,
        }
    }
}

/// The node's own audit log: `<state_dir>/lifecycle.log`, the sink every node-level lifecycle
/// event goes to, and outside every pod's reach (a container pod is bound only its pod
/// directory and its binding's directory).
pub(crate) fn flow_log_path(state_dir: &Path) -> PathBuf {
    state_dir.join("lifecycle.log")
}

/// Sign and durably append one flow decision. A failure is returned, not logged and dropped: a
/// decision whose receipt was not kept does not take effect.
pub(crate) fn record(
    state_dir: &Path,
    authority: &crate::pod_authority::PodAuthority,
    claim: &FlowClaim<'_>,
) -> Result<(), ApiError> {
    let preimage = serde_json_canonicalizer::to_vec(claim)
        .map_err(|e| ApiError::Driver(format!("cannot encode a memory flow receipt: {e}")))?;
    let signature = authority.sign_memory_flow(&preimage);
    let subject = match claim.event.pod() {
        Some(pod) => format!("pod:{pod}"),
        None => format!("tenant:{}", claim.tenant),
    };
    let entry = serde_json::json!({
        "timestamp_unix": claim.at_unix,
        "actor": "nucleus-node",
        "event": claim.event.name(),
        "subject": subject,
        "result": "recorded",
        "claim": claim,
        "signature": signature,
    });
    let line = serde_json::to_string(&entry)
        .map_err(|e| ApiError::Driver(format!("cannot encode a memory flow receipt: {e}")))?;
    let path = flow_log_path(state_dir);
    let kept = nucleus_jsonl::append_line_synced(&path, &line)?;
    if !kept.proves(&path, &line) {
        return Err(ApiError::Driver("memory flow receipt was not kept".into()));
    }
    Ok(())
}
