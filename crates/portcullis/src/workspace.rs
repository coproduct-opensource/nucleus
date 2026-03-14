//! Multi-agent workspace exposure composition.
//!
//! When multiple agents share a workspace, their exposure sets compose into
//! a shared global exposure. This module defines the trait contract for
//! workspace-level exposure tracking.
//!
//! ## Mathematical Structure
//!
//! The shared exposure is modeled as the **global section** of a exposure presheaf:
//! each agent has a local exposure set, and the workspace exposure is their join
//! (union). When any agent's exposure contributes to a dangerous combination,
//! ALL agents in the workspace are subject to the resulting obligations.
//!
//! This is the correct categorical construction: exposure flows "up" from agents
//! to the workspace (a colimit), and obligations flow "down" from the workspace
//! to agents (a limit). The adjunction between colimits and limits gives us
//! the soundness guarantee.
//!
//! ## v1.0 Status
//!
//! This is a **trait definition only** — no implementation in v1.0. It
//! establishes the contract that multi-agent composition will satisfy and
//! ensures the [`GradedExposureGuard`](crate::guard::GradedExposureGuard) API is
//! compatible with future shared-exposure scenarios.

use crate::capability::Operation;
use crate::guard::{CheckProof, ExposureSet, GuardError};

/// Workspace permission context for concurrent agents.
///
/// The shared exposure is the global section of the exposure presheaf:
/// `Γ(T) = ⋃_{a ∈ Agents} T(a)`
///
/// When the join reaches a dangerous combination, obligations propagate
/// to all agents via the limit construction.
pub trait WorkspaceGuard: Send + Sync {
    /// Record that an agent performed an operation.
    ///
    /// Updates the agent's local exposure and recomputes the shared workspace
    /// exposure. May block other agents if the shared exposure now triggers a
    /// dangerous combination.
    fn record(&self, agent: &str, op: Operation) -> Result<(), GuardError>;

    /// Check if an agent can perform an operation given shared exposure.
    ///
    /// The check considers both the agent's local exposure and the workspace's
    /// shared exposure when evaluating dangerous combinations.
    fn check(&self, agent: &str, op: Operation) -> Result<CheckProof, GuardError>;

    /// Get the current shared workspace exposure (the global section).
    fn shared_exposure(&self) -> ExposureSet;

    /// Get the local exposure for a specific agent.
    fn agent_exposure(&self, agent: &str) -> Option<ExposureSet>;
}
