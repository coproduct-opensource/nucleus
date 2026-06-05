//! An agent loop's static configuration: who it is, what it buys, the IFC flow
//! its calls declare, the price, and how often it acts.

use crate::event::{AgentId, MicroUsd};
use nucleus_verify_commerce::FlowDeclaration;

/// One simulated buyer agent in the marketplace.
pub struct AgentLoop {
    /// Stable agent handle.
    pub agent: AgentId,
    /// The resource it purchases.
    pub resource: String,
    /// The IFC data-flow each of its calls declares (drives allow/deny).
    pub flow: FlowDeclaration,
    /// Price per call.
    pub price: MicroUsd,
    /// Pacing between attempts (milliseconds) for the live `run` loop. Ignored by
    /// the deterministic `step_once` test path.
    pub interval_ms: u64,
}

impl AgentLoop {
    /// Construct an agent loop.
    pub fn new(
        agent: impl Into<String>,
        resource: impl Into<String>,
        flow: FlowDeclaration,
        price: MicroUsd,
        interval_ms: u64,
    ) -> Self {
        Self {
            agent: AgentId(agent.into()),
            resource: resource.into(),
            flow,
            price,
            interval_ms,
        }
    }

    /// The sorted+deduped declared-input tokens this agent exposes (the same set
    /// the IFC verdict reports), for the `AgentRegistered` coverage surface.
    pub fn declared_inputs(&self) -> Vec<String> {
        self.flow.decide().declared_inputs
    }
}
