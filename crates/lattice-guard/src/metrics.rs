//! Metrics primitives for reputation tracking.
//!
//! This module provides interfaces and default implementations for tracking
//! agent behavior metrics that can be consumed by reputation systems.
//!
//! # Design
//!
//! The metrics system is designed around traits that external reputation
//! systems can implement. Nucleus provides:
//!
//! 1. **Core traits** - `ReputationMetrics`, `MetricsCollector`
//! 2. **Default implementations** - In-memory collectors for testing
//! 3. **Standard metrics** - Deviation rate, approval rate, trifecta frequency
//!
//! # Standard Metrics
//!
//! | Metric | Description | Interpretation |
//! |--------|-------------|----------------|
//! | `deviation_rate` | Weakenings requested / operations | Higher = more deviation from declared |
//! | `approval_rate` | Approvals granted / approvals requested | Higher = better track record |
//! | `trifecta_frequency` | Trifecta completions / sessions | Higher = more risky behavior |
//! | `avg_weakening_cost` | Total cost / weakenings | Higher = bigger deviations |
//! | `block_rate` | Executions blocked / operations | Higher = hitting policy limits |
//!
//! # Example
//!
//! ```rust
//! use lattice_guard::metrics::{MetricsCollector, InMemoryMetrics, MetricEvent, ReputationMetrics};
//! use lattice_guard::Operation;
//!
//! // Create a metrics collector
//! let metrics = InMemoryMetrics::new();
//!
//! // Record events
//! metrics.record(
//!     "spiffe://nucleus.local/ns/default/sa/coder-001",
//!     MetricEvent::OperationAttempted { operation: Operation::GitPush },
//! );
//!
//! // Query metrics (requires ReputationMetrics trait in scope)
//! let deviation_rate = metrics.deviation_rate("spiffe://nucleus.local/ns/default/sa/coder-001");
//! ```

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::capability::{Operation, TrifectaRisk};
use crate::weakening::WeakeningCost;

/// Standard metrics that reputation systems can query.
///
/// This trait defines the interface for computing reputation-relevant metrics.
/// Implementors can choose different algorithms for computing these metrics.
pub trait ReputationMetrics: Send + Sync {
    /// Deviation rate: weakenings / operations (0.0 - 1.0+).
    ///
    /// A rate of 0.0 means no deviations from declared permissions.
    /// A rate > 1.0 means more weakenings than operations (multiple per op).
    fn deviation_rate(&self, identity: &str) -> f64;

    /// Approval rate: granted / requested (0.0 - 1.0).
    ///
    /// A rate of 1.0 means all approval requests were granted.
    /// A rate of 0.0 means all approval requests were denied.
    fn approval_rate(&self, identity: &str) -> f64;

    /// Trifecta frequency: completions / sessions (0.0 - 1.0+).
    ///
    /// A rate of 0.0 means the trifecta was never completed.
    /// Higher rates indicate more frequent dangerous permission combinations.
    fn trifecta_frequency(&self, identity: &str) -> f64;

    /// Average weakening cost per weakening.
    fn avg_weakening_cost(&self, identity: &str) -> rust_decimal::Decimal;

    /// Block rate: blocked / attempted (0.0 - 1.0).
    ///
    /// A rate of 0.0 means no executions were blocked by policy.
    /// Higher rates indicate hitting policy limits more often.
    fn block_rate(&self, identity: &str) -> f64;

    /// Compute an aggregate reputation score (0.0 - 1.0).
    ///
    /// This is a weighted combination of all metrics.
    /// Higher scores indicate better reputation (fewer deviations, more approvals).
    ///
    /// The default implementation uses equal weights:
    /// ```text
    /// score = (1 - deviation_rate) * 0.25
    ///       + approval_rate * 0.25
    ///       + (1 - trifecta_frequency) * 0.25
    ///       + (1 - block_rate) * 0.25
    /// ```
    fn reputation_score(&self, identity: &str) -> f64 {
        let deviation = (1.0 - self.deviation_rate(identity).min(1.0)).max(0.0);
        let approval = self.approval_rate(identity);
        let trifecta = (1.0 - self.trifecta_frequency(identity).min(1.0)).max(0.0);
        let block = (1.0 - self.block_rate(identity).min(1.0)).max(0.0);

        (deviation * 0.25 + approval * 0.25 + trifecta * 0.25 + block * 0.25).clamp(0.0, 1.0)
    }

    /// Get all metrics as a structured report.
    fn report(&self, identity: &str) -> MetricsReport {
        MetricsReport {
            identity: identity.to_string(),
            deviation_rate: self.deviation_rate(identity),
            approval_rate: self.approval_rate(identity),
            trifecta_frequency: self.trifecta_frequency(identity),
            avg_weakening_cost: self.avg_weakening_cost(identity),
            block_rate: self.block_rate(identity),
            reputation_score: self.reputation_score(identity),
        }
    }
}

/// A structured metrics report for an identity.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MetricsReport {
    /// The SPIFFE ID.
    pub identity: String,
    /// Deviation rate.
    pub deviation_rate: f64,
    /// Approval rate.
    pub approval_rate: f64,
    /// Trifecta frequency.
    pub trifecta_frequency: f64,
    /// Average weakening cost.
    pub avg_weakening_cost: rust_decimal::Decimal,
    /// Block rate.
    pub block_rate: f64,
    /// Aggregate reputation score.
    pub reputation_score: f64,
}

impl std::fmt::Display for MetricsReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Metrics Report for {}", self.identity)?;
        writeln!(
            f,
            "  Deviation rate:    {:.2}%",
            self.deviation_rate * 100.0
        )?;
        writeln!(f, "  Approval rate:     {:.2}%", self.approval_rate * 100.0)?;
        writeln!(
            f,
            "  Trifecta freq:     {:.2}%",
            self.trifecta_frequency * 100.0
        )?;
        writeln!(f, "  Avg cost:          {}", self.avg_weakening_cost)?;
        writeln!(f, "  Block rate:        {:.2}%", self.block_rate * 100.0)?;
        writeln!(
            f,
            "  Reputation score:  {:.2}%",
            self.reputation_score * 100.0
        )?;
        Ok(())
    }
}

/// Events that affect metrics.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MetricEvent {
    /// An operation was attempted.
    OperationAttempted {
        /// The operation.
        operation: Operation,
    },

    /// A weakening was requested.
    WeakeningRequested {
        /// The cost of the weakening.
        cost: WeakeningCost,
    },

    /// An approval was requested.
    ApprovalRequested,

    /// An approval was granted.
    ApprovalGranted,

    /// An approval was denied.
    ApprovalDenied,

    /// The trifecta was completed.
    TrifectaCompleted,

    /// A session started.
    SessionStarted,

    /// A session ended.
    SessionEnded,

    /// An execution was blocked by policy.
    ExecutionBlocked,
}

/// Interface for collecting metrics from events.
pub trait MetricsCollector: ReputationMetrics {
    /// Record a metric event for an identity.
    fn record(&self, identity: &str, event: MetricEvent);

    /// Reset metrics for an identity.
    fn reset(&self, identity: &str);

    /// Reset all metrics.
    fn reset_all(&self);
}

/// Counters for computing metrics.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
struct IdentityCounters {
    operations_attempted: u64,
    weakenings_requested: u64,
    total_weakening_cost: rust_decimal::Decimal,
    approvals_requested: u64,
    approvals_granted: u64,
    approvals_denied: u64,
    trifecta_completions: u64,
    sessions_started: u64,
    sessions_ended: u64,
    executions_blocked: u64,
}

/// In-memory metrics collector.
///
/// Suitable for testing and single-node deployments.
/// For production, implement `MetricsCollector` with a persistent backend.
#[derive(Debug)]
pub struct InMemoryMetrics {
    counters: Arc<RwLock<HashMap<String, IdentityCounters>>>,
}

impl Clone for InMemoryMetrics {
    fn clone(&self) -> Self {
        Self {
            counters: Arc::clone(&self.counters),
        }
    }
}

impl Default for InMemoryMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryMetrics {
    /// Create a new in-memory metrics collector.
    pub fn new() -> Self {
        Self {
            counters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get counters for an identity.
    fn get_counters(&self, identity: &str) -> IdentityCounters {
        let counters = self.counters.read().expect("lock poisoned");
        counters.get(identity).cloned().unwrap_or_default()
    }
}

impl ReputationMetrics for InMemoryMetrics {
    fn deviation_rate(&self, identity: &str) -> f64 {
        let counters = self.get_counters(identity);
        if counters.operations_attempted == 0 {
            return 0.0;
        }
        counters.weakenings_requested as f64 / counters.operations_attempted as f64
    }

    fn approval_rate(&self, identity: &str) -> f64 {
        let counters = self.get_counters(identity);
        if counters.approvals_requested == 0 {
            return 1.0; // No approvals needed = good
        }
        counters.approvals_granted as f64 / counters.approvals_requested as f64
    }

    fn trifecta_frequency(&self, identity: &str) -> f64 {
        let counters = self.get_counters(identity);
        let sessions = counters.sessions_started.max(1);
        counters.trifecta_completions as f64 / sessions as f64
    }

    fn avg_weakening_cost(&self, identity: &str) -> rust_decimal::Decimal {
        let counters = self.get_counters(identity);
        if counters.weakenings_requested == 0 {
            return rust_decimal::Decimal::ZERO;
        }
        counters.total_weakening_cost / rust_decimal::Decimal::from(counters.weakenings_requested)
    }

    fn block_rate(&self, identity: &str) -> f64 {
        let counters = self.get_counters(identity);
        if counters.operations_attempted == 0 {
            return 0.0;
        }
        counters.executions_blocked as f64 / counters.operations_attempted as f64
    }
}

impl MetricsCollector for InMemoryMetrics {
    fn record(&self, identity: &str, event: MetricEvent) {
        let mut counters = self.counters.write().expect("lock poisoned");
        let entry = counters.entry(identity.to_string()).or_default();

        match event {
            MetricEvent::OperationAttempted { .. } => {
                entry.operations_attempted += 1;
            }
            MetricEvent::WeakeningRequested { cost } => {
                entry.weakenings_requested += 1;
                entry.total_weakening_cost += cost.total();
            }
            MetricEvent::ApprovalRequested => {
                entry.approvals_requested += 1;
            }
            MetricEvent::ApprovalGranted => {
                entry.approvals_granted += 1;
            }
            MetricEvent::ApprovalDenied => {
                entry.approvals_denied += 1;
            }
            MetricEvent::TrifectaCompleted => {
                entry.trifecta_completions += 1;
            }
            MetricEvent::SessionStarted => {
                entry.sessions_started += 1;
            }
            MetricEvent::SessionEnded => {
                entry.sessions_ended += 1;
            }
            MetricEvent::ExecutionBlocked => {
                entry.executions_blocked += 1;
            }
        }
    }

    fn reset(&self, identity: &str) {
        let mut counters = self.counters.write().expect("lock poisoned");
        counters.remove(identity);
    }

    fn reset_all(&self) {
        let mut counters = self.counters.write().expect("lock poisoned");
        counters.clear();
    }
}

/// Configuration for weighted reputation scoring.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ReputationWeights {
    /// Weight for deviation rate (default 0.25).
    pub deviation_weight: f64,
    /// Weight for approval rate (default 0.25).
    pub approval_weight: f64,
    /// Weight for trifecta frequency (default 0.25).
    pub trifecta_weight: f64,
    /// Weight for block rate (default 0.25).
    pub block_weight: f64,
}

impl Default for ReputationWeights {
    fn default() -> Self {
        Self {
            deviation_weight: 0.25,
            approval_weight: 0.25,
            trifecta_weight: 0.25,
            block_weight: 0.25,
        }
    }
}

impl ReputationWeights {
    /// Validate that weights sum to 1.0.
    pub fn validate(&self) -> Result<(), &'static str> {
        let total =
            self.deviation_weight + self.approval_weight + self.trifecta_weight + self.block_weight;
        if (total - 1.0).abs() > 0.001 {
            return Err("weights must sum to 1.0");
        }
        if self.deviation_weight < 0.0
            || self.approval_weight < 0.0
            || self.trifecta_weight < 0.0
            || self.block_weight < 0.0
        {
            return Err("weights must be non-negative");
        }
        Ok(())
    }

    /// Compute reputation score with custom weights.
    pub fn score(&self, metrics: &dyn ReputationMetrics, identity: &str) -> f64 {
        let deviation = (1.0 - metrics.deviation_rate(identity).min(1.0)).max(0.0);
        let approval = metrics.approval_rate(identity);
        let trifecta = (1.0 - metrics.trifecta_frequency(identity).min(1.0)).max(0.0);
        let block = (1.0 - metrics.block_rate(identity).min(1.0)).max(0.0);

        (deviation * self.deviation_weight
            + approval * self.approval_weight
            + trifecta * self.trifecta_weight
            + block * self.block_weight)
            .clamp(0.0, 1.0)
    }
}

/// A deviation report summarizing declared vs actual permissions.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeviationReport {
    /// The SPIFFE ID.
    pub identity: String,
    /// Description of declared permissions.
    pub declared_description: String,
    /// Description of actual (ceiling) permissions.
    pub actual_description: String,
    /// Trifecta risk of declared permissions.
    pub declared_trifecta: TrifectaRisk,
    /// Trifecta risk of actual permissions.
    pub actual_trifecta: TrifectaRisk,
    /// Total weakening cost.
    pub total_cost: rust_decimal::Decimal,
    /// Number of capability weakenings.
    pub capability_weakenings: usize,
    /// Number of obligation removals.
    pub obligation_removals: usize,
    /// Whether the trifecta was completed.
    pub trifecta_completed: bool,
    /// Individual deviation details.
    pub deviations: Vec<DeviationDetail>,
}

/// Detail of a single deviation.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeviationDetail {
    /// The operation affected.
    pub operation: Operation,
    /// What was declared.
    pub declared: String,
    /// What was requested/used.
    pub actual: String,
    /// The cost of this deviation.
    pub cost: rust_decimal::Decimal,
    /// The trifecta impact.
    pub trifecta_impact: TrifectaRisk,
}

impl std::fmt::Display for DeviationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Deviation Report for {}", self.identity)?;
        writeln!(
            f,
            "  Declared: {} ({:?})",
            self.declared_description, self.declared_trifecta
        )?;
        writeln!(
            f,
            "  Actual:   {} ({:?})",
            self.actual_description, self.actual_trifecta
        )?;
        writeln!(f, "  Total cost: {}", self.total_cost)?;
        writeln!(
            f,
            "  Weakenings: {} capability, {} obligation",
            self.capability_weakenings, self.obligation_removals
        )?;
        if self.trifecta_completed {
            writeln!(f, "  TRIFECTA COMPLETED")?;
        }
        if !self.deviations.is_empty() {
            writeln!(f, "  Deviations:")?;
            for d in &self.deviations {
                writeln!(
                    f,
                    "    - {:?}: {} → {} (cost: {}, trifecta: {:?})",
                    d.operation, d.declared, d.actual, d.cost, d.trifecta_impact
                )?;
            }
        }
        Ok(())
    }
}

/// Build a deviation report from a permissive execution result.
pub fn build_deviation_report(
    identity: &str,
    result: &crate::permissive::PermissiveExecutionResult<()>,
) -> DeviationReport {
    use crate::weakening::WeakeningDimension;

    let mut capability_weakenings = 0;
    let mut obligation_removals = 0;
    let mut deviations = Vec::new();

    for w in &result.weakenings {
        match &w.dimension {
            WeakeningDimension::Capability(op) => {
                capability_weakenings += 1;
                deviations.push(DeviationDetail {
                    operation: *op,
                    declared: w.from_level.clone(),
                    actual: w.to_level.clone(),
                    cost: w.cost.total(),
                    trifecta_impact: w.trifecta_impact,
                });
            }
            WeakeningDimension::ObligationRemoval(op) => {
                obligation_removals += 1;
                deviations.push(DeviationDetail {
                    operation: *op,
                    declared: "Required".to_string(),
                    actual: "Removed".to_string(),
                    cost: w.cost.total(),
                    trifecta_impact: w.trifecta_impact,
                });
            }
            _ => {}
        }
    }

    DeviationReport {
        identity: identity.to_string(),
        declared_description: result.floor.description.clone(),
        actual_description: result.ceiling.description.clone(),
        declared_trifecta: result.floor_trifecta,
        actual_trifecta: result.ceiling_trifecta,
        total_cost: result.total_cost.total(),
        capability_weakenings,
        obligation_removals,
        trifecta_completed: result.completes_trifecta(),
        deviations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::weakening::WeakeningCost;

    #[test]
    fn test_in_memory_metrics_deviation_rate() {
        let metrics = InMemoryMetrics::new();
        let identity = "spiffe://test/agent-1";

        // 10 operations, 2 weakenings
        for _ in 0..10 {
            metrics.record(
                identity,
                MetricEvent::OperationAttempted {
                    operation: Operation::ReadFiles,
                },
            );
        }
        for _ in 0..2 {
            metrics.record(
                identity,
                MetricEvent::WeakeningRequested {
                    cost: WeakeningCost::new(rust_decimal::Decimal::new(1, 1)),
                },
            );
        }

        let rate = metrics.deviation_rate(identity);
        assert!((rate - 0.2).abs() < 0.001); // 2/10 = 0.2
    }

    #[test]
    fn test_in_memory_metrics_approval_rate() {
        let metrics = InMemoryMetrics::new();
        let identity = "spiffe://test/agent-1";

        // 4 requests, 3 granted, 1 denied
        for _ in 0..4 {
            metrics.record(identity, MetricEvent::ApprovalRequested);
        }
        for _ in 0..3 {
            metrics.record(identity, MetricEvent::ApprovalGranted);
        }
        metrics.record(identity, MetricEvent::ApprovalDenied);

        let rate = metrics.approval_rate(identity);
        assert!((rate - 0.75).abs() < 0.001); // 3/4 = 0.75
    }

    #[test]
    fn test_in_memory_metrics_trifecta_frequency() {
        let metrics = InMemoryMetrics::new();
        let identity = "spiffe://test/agent-1";

        // 4 sessions, 1 trifecta completion
        for _ in 0..4 {
            metrics.record(identity, MetricEvent::SessionStarted);
        }
        metrics.record(identity, MetricEvent::TrifectaCompleted);

        let freq = metrics.trifecta_frequency(identity);
        assert!((freq - 0.25).abs() < 0.001); // 1/4 = 0.25
    }

    #[test]
    fn test_reputation_score() {
        let metrics = InMemoryMetrics::new();
        let identity = "spiffe://test/agent-1";

        // Perfect behavior: no deviations, all approvals granted, no trifecta, no blocks
        metrics.record(identity, MetricEvent::SessionStarted);
        for _ in 0..10 {
            metrics.record(
                identity,
                MetricEvent::OperationAttempted {
                    operation: Operation::ReadFiles,
                },
            );
        }
        metrics.record(identity, MetricEvent::ApprovalRequested);
        metrics.record(identity, MetricEvent::ApprovalGranted);

        let score = metrics.reputation_score(identity);
        assert!((score - 1.0).abs() < 0.001); // Perfect score
    }

    #[test]
    fn test_reputation_score_bad_behavior() {
        let metrics = InMemoryMetrics::new();
        let identity = "spiffe://test/agent-1";

        metrics.record(identity, MetricEvent::SessionStarted);

        // All bad: many deviations, denied approvals, trifecta, blocks
        for _ in 0..10 {
            metrics.record(
                identity,
                MetricEvent::OperationAttempted {
                    operation: Operation::GitPush,
                },
            );
            metrics.record(
                identity,
                MetricEvent::WeakeningRequested {
                    cost: WeakeningCost::new(rust_decimal::Decimal::new(5, 1)),
                },
            );
            metrics.record(identity, MetricEvent::ExecutionBlocked);
        }
        metrics.record(identity, MetricEvent::ApprovalRequested);
        metrics.record(identity, MetricEvent::ApprovalDenied);
        metrics.record(identity, MetricEvent::TrifectaCompleted);

        let score = metrics.reputation_score(identity);
        // Should be low but > 0
        assert!(score < 0.5);
        assert!(score >= 0.0);
    }

    #[test]
    fn test_custom_weights() {
        let metrics = InMemoryMetrics::new();
        let identity = "spiffe://test/agent-1";

        // Only trifecta is bad
        metrics.record(identity, MetricEvent::SessionStarted);
        metrics.record(
            identity,
            MetricEvent::OperationAttempted {
                operation: Operation::ReadFiles,
            },
        );
        metrics.record(identity, MetricEvent::TrifectaCompleted);

        // Default weights
        let default_score = metrics.reputation_score(identity);

        // Custom weights emphasizing trifecta
        let weights = ReputationWeights {
            deviation_weight: 0.1,
            approval_weight: 0.1,
            trifecta_weight: 0.7,
            block_weight: 0.1,
        };
        assert!(weights.validate().is_ok());

        let custom_score = weights.score(&metrics, identity);

        // Custom score should be lower because trifecta is heavily weighted
        assert!(custom_score < default_score);
    }

    #[test]
    fn test_metrics_report() {
        let metrics = InMemoryMetrics::new();
        let identity = "spiffe://test/agent-1";

        metrics.record(identity, MetricEvent::SessionStarted);
        metrics.record(
            identity,
            MetricEvent::OperationAttempted {
                operation: Operation::ReadFiles,
            },
        );

        let report = metrics.report(identity);
        assert_eq!(report.identity, identity);
        assert_eq!(report.deviation_rate, 0.0);
        assert_eq!(report.approval_rate, 1.0);
    }

    #[test]
    fn test_reset() {
        let metrics = InMemoryMetrics::new();
        let identity = "spiffe://test/agent-1";

        metrics.record(identity, MetricEvent::SessionStarted);
        metrics.record(identity, MetricEvent::TrifectaCompleted);

        assert_eq!(metrics.trifecta_frequency(identity), 1.0);

        metrics.reset(identity);

        assert_eq!(metrics.trifecta_frequency(identity), 0.0);
    }
}
