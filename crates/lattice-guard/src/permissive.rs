//! Permissive execution with fallback tracking.
//!
//! This module provides a graded monad for tracking permission weakenings
//! when executing with max permissions but given a secure fallback floor.
//!
//! # Design
//!
//! The permissive execution model inverts the traditional nucleus pattern:
//! - **Nucleus**: Start permissive, apply deflationary restrictions
//! - **Permissive**: Start restrictive (floor), track inflationary weakenings
//!
//! # Monad Laws
//!
//! `PermissiveExecution<A>` satisfies the monad laws:
//! - **Left identity**: `pure(a).and_then(f) = f(a)`
//! - **Right identity**: `m.and_then(pure) = m`
//! - **Associativity**: `(m.and_then(f)).and_then(g) = m.and_then(|x| f(x).and_then(g))`
//!
//! # Example
//!
//! ```rust
//! use lattice_guard::permissive::{PermissiveExecution, PermissiveExecutor};
//! use lattice_guard::weakening::{WeakeningCost, WeakeningCostConfig};
//! use lattice_guard::{PermissionLattice, IsolationLattice};
//!
//! // Pure computation (no weakening)
//! let pure_result: PermissiveExecution<i32> = PermissiveExecution::pure(42);
//! assert!(pure_result.weakenings.is_empty());
//!
//! // Create executor with secure floor
//! let executor = PermissiveExecutor::new(
//!     PermissionLattice::codegen(),       // Secure floor
//!     PermissionLattice::permissive(),    // Max permissions
//!     IsolationLattice::sandboxed(),      // Isolation floor
//!     WeakeningCostConfig::default(),
//! );
//!
//! // Execute and get weakening report
//! let result = executor.compute_gap();
//! println!("Total cost: {}", result.total_cost);
//! for w in &result.requests {
//!     println!("  {}", w);
//! }
//! ```

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::capability::{IncompatibilityConstraint, Operation, TrifectaRisk};
use crate::isolation::IsolationLattice;
use crate::weakening::{WeakeningCost, WeakeningCostConfig, WeakeningGap, WeakeningRequest};
use crate::{CapabilityLevel, PermissionLattice};

/// A graded monad for tracking permission weakenings through a computation.
///
/// This is analogous to `Graded<G, A>` in `graded.rs`, but tracks
/// `Vec<WeakeningRequest>` instead of a single risk grade.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PermissiveExecution<A> {
    /// The computed value
    pub value: A,
    /// Weakenings accumulated during computation
    pub weakenings: Vec<WeakeningRequest>,
    /// Total cost of all weakenings
    pub total_cost: WeakeningCost,
}

impl<A> PermissiveExecution<A> {
    /// Pure computation with no weakenings.
    ///
    /// This is the `return` or `pure` operation of the monad.
    pub fn pure(value: A) -> Self {
        Self {
            value,
            weakenings: Vec::new(),
            total_cost: WeakeningCost::zero(),
        }
    }

    /// Create a computation with a single weakening.
    pub fn with_weakening(value: A, weakening: WeakeningRequest) -> Self {
        let total_cost = weakening.cost.clone();
        Self {
            value,
            weakenings: vec![weakening],
            total_cost,
        }
    }

    /// Create a computation with multiple weakenings.
    pub fn with_weakenings(value: A, weakenings: Vec<WeakeningRequest>) -> Self {
        let total_cost = weakenings
            .iter()
            .fold(WeakeningCost::zero(), |acc, w| acc.combine(&w.cost));
        Self {
            value,
            weakenings,
            total_cost,
        }
    }

    /// Map a function over the value, preserving weakenings.
    ///
    /// This is the `fmap` operation (functor).
    pub fn map<B, F>(self, f: F) -> PermissiveExecution<B>
    where
        F: FnOnce(A) -> B,
    {
        PermissiveExecution {
            value: f(self.value),
            weakenings: self.weakenings,
            total_cost: self.total_cost,
        }
    }

    /// Chain computations, accumulating weakenings.
    ///
    /// This is the `bind` (>>=) operation of the monad.
    pub fn and_then<B, F>(self, f: F) -> PermissiveExecution<B>
    where
        F: FnOnce(A) -> PermissiveExecution<B>,
    {
        let result = f(self.value);
        let mut weakenings = self.weakenings;
        weakenings.extend(result.weakenings);
        PermissiveExecution {
            value: result.value,
            weakenings,
            total_cost: self.total_cost.combine(&result.total_cost),
        }
    }

    /// Extract the value, discarding weakening information.
    pub fn into_value(self) -> A {
        self.value
    }

    /// Get a reference to the value.
    pub fn value(&self) -> &A {
        &self.value
    }

    /// Check if this computation required any weakenings.
    pub fn has_weakenings(&self) -> bool {
        !self.weakenings.is_empty()
    }

    /// Get weakenings that require approval.
    pub fn requiring_approval(&self) -> Vec<&WeakeningRequest> {
        self.weakenings
            .iter()
            .filter(|w| w.requires_approval())
            .collect()
    }

    /// Convert to a WeakeningGap.
    pub fn as_gap(&self) -> WeakeningGap {
        WeakeningGap {
            requests: self.weakenings.clone(),
            total_cost: self.total_cost.clone(),
        }
    }
}

impl<A: Clone> PermissiveExecution<A> {
    /// Clone the value out of the computation.
    pub fn clone_value(&self) -> A {
        self.value.clone()
    }
}

impl<A: Default> Default for PermissiveExecution<A> {
    fn default() -> Self {
        Self::pure(A::default())
    }
}

impl<A: fmt::Display> fmt::Display for PermissiveExecution<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PermissiveExecution({}, {} weakenings, cost: {})",
            self.value,
            self.weakenings.len(),
            self.total_cost
        )
    }
}

/// Result of permissive execution with full tracking information.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PermissiveExecutionResult<A> {
    /// The computed value
    pub value: A,
    /// The secure floor that was the baseline
    pub floor: PermissionLattice,
    /// The ceiling permissions used during execution
    pub ceiling: PermissionLattice,
    /// The isolation floor
    pub isolation_floor: IsolationLattice,
    /// List of weakenings needed (floor → ceiling)
    pub weakenings: Vec<WeakeningRequest>,
    /// Total cost of all weakenings
    pub total_cost: WeakeningCost,
    /// Trifecta risk at floor
    pub floor_trifecta: TrifectaRisk,
    /// Trifecta risk at ceiling
    pub ceiling_trifecta: TrifectaRisk,
}

impl<A> PermissiveExecutionResult<A> {
    /// Check if this execution required any weakenings.
    pub fn has_weakenings(&self) -> bool {
        !self.weakenings.is_empty()
    }

    /// Get weakenings that require approval.
    pub fn requiring_approval(&self) -> Vec<&WeakeningRequest> {
        self.weakenings
            .iter()
            .filter(|w| w.requires_approval())
            .collect()
    }

    /// Check if this execution completes the trifecta.
    pub fn completes_trifecta(&self) -> bool {
        self.floor_trifecta != TrifectaRisk::Complete
            && self.ceiling_trifecta == TrifectaRisk::Complete
    }

    /// Convert to a WeakeningGap.
    pub fn as_gap(&self) -> WeakeningGap {
        WeakeningGap {
            requests: self.weakenings.clone(),
            total_cost: self.total_cost.clone(),
        }
    }
}

impl<A: fmt::Display> fmt::Display for PermissiveExecutionResult<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "PermissiveExecutionResult:")?;
        writeln!(f, "  Value: {}", self.value)?;
        writeln!(f, "  Floor: {}", self.floor.description)?;
        writeln!(f, "  Ceiling: {}", self.ceiling.description)?;
        writeln!(
            f,
            "  Trifecta: {:?} → {:?}",
            self.floor_trifecta, self.ceiling_trifecta
        )?;
        writeln!(f, "  Total cost: {}", self.total_cost)?;
        writeln!(f, "  Weakenings ({}):", self.weakenings.len())?;
        for w in &self.weakenings {
            writeln!(f, "    - {}", w)?;
        }
        Ok(())
    }
}

/// Executor that runs with max permissions while tracking weakenings.
///
/// The executor computes the "gap" between a secure floor and a permissive
/// ceiling, identifying all weakenings and their costs.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PermissiveExecutor {
    /// The secure floor (fallback) - most restrictive
    floor: PermissionLattice,
    /// The ceiling - max permissions
    ceiling: PermissionLattice,
    /// Isolation floor
    isolation_floor: IsolationLattice,
    /// Cost configuration
    cost_config: WeakeningCostConfig,
}

impl PermissiveExecutor {
    /// Create a new permissive executor.
    pub fn new(
        floor: PermissionLattice,
        ceiling: PermissionLattice,
        isolation_floor: IsolationLattice,
        cost_config: WeakeningCostConfig,
    ) -> Self {
        Self {
            floor,
            ceiling,
            isolation_floor,
            cost_config,
        }
    }

    /// Create a builder for the executor.
    pub fn builder() -> PermissiveExecutorBuilder {
        PermissiveExecutorBuilder::default()
    }

    /// Get the floor permissions.
    pub fn floor(&self) -> &PermissionLattice {
        &self.floor
    }

    /// Get the ceiling permissions.
    pub fn ceiling(&self) -> &PermissionLattice {
        &self.ceiling
    }

    /// Get the isolation floor.
    pub fn isolation_floor(&self) -> &IsolationLattice {
        &self.isolation_floor
    }

    /// Compute the weakening gap from floor to ceiling.
    ///
    /// This is the core operation: identify all weakenings needed to go
    /// from the secure floor to the permissive ceiling.
    pub fn compute_gap(&self) -> WeakeningGap {
        let constraint = IncompatibilityConstraint::enforcing();
        let floor_trifecta = constraint.trifecta_risk(&self.floor.capabilities);
        let ceiling_trifecta = constraint.trifecta_risk(&self.ceiling.capabilities);
        let trifecta_multiplier = self
            .cost_config
            .trifecta_multiplier(floor_trifecta, ceiling_trifecta);

        let mut gap = WeakeningGap::empty();

        // Compute capability weakenings
        self.compute_capability_weakenings(&mut gap, trifecta_multiplier, &constraint);

        // Compute obligation weakenings (removals)
        self.compute_obligation_weakenings(&mut gap);

        gap
    }

    /// Compute capability weakenings.
    fn compute_capability_weakenings(
        &self,
        gap: &mut WeakeningGap,
        trifecta_multiplier: rust_decimal::Decimal,
        constraint: &IncompatibilityConstraint,
    ) {
        // Check each capability
        let ops = [
            (
                Operation::ReadFiles,
                self.floor.capabilities.read_files,
                self.ceiling.capabilities.read_files,
            ),
            (
                Operation::WriteFiles,
                self.floor.capabilities.write_files,
                self.ceiling.capabilities.write_files,
            ),
            (
                Operation::EditFiles,
                self.floor.capabilities.edit_files,
                self.ceiling.capabilities.edit_files,
            ),
            (
                Operation::RunBash,
                self.floor.capabilities.run_bash,
                self.ceiling.capabilities.run_bash,
            ),
            (
                Operation::GlobSearch,
                self.floor.capabilities.glob_search,
                self.ceiling.capabilities.glob_search,
            ),
            (
                Operation::GrepSearch,
                self.floor.capabilities.grep_search,
                self.ceiling.capabilities.grep_search,
            ),
            (
                Operation::WebSearch,
                self.floor.capabilities.web_search,
                self.ceiling.capabilities.web_search,
            ),
            (
                Operation::WebFetch,
                self.floor.capabilities.web_fetch,
                self.ceiling.capabilities.web_fetch,
            ),
            (
                Operation::GitCommit,
                self.floor.capabilities.git_commit,
                self.ceiling.capabilities.git_commit,
            ),
            (
                Operation::GitPush,
                self.floor.capabilities.git_push,
                self.ceiling.capabilities.git_push,
            ),
            (
                Operation::CreatePr,
                self.floor.capabilities.create_pr,
                self.ceiling.capabilities.create_pr,
            ),
            (
                Operation::ManagePods,
                self.floor.capabilities.manage_pods,
                self.ceiling.capabilities.manage_pods,
            ),
        ];

        for (op, floor_level, ceiling_level) in ops {
            if ceiling_level > floor_level {
                let mut cost = self.cost_config.capability_cost(floor_level, ceiling_level);
                cost.trifecta_multiplier = trifecta_multiplier;

                // Determine trifecta impact
                let trifecta_impact =
                    self.compute_trifecta_impact(op, floor_level, ceiling_level, constraint);

                gap.add(WeakeningRequest::capability(
                    op,
                    floor_level,
                    ceiling_level,
                    cost,
                    trifecta_impact,
                ));
            }
        }
    }

    /// Compute the trifecta impact of a capability change.
    fn compute_trifecta_impact(
        &self,
        op: Operation,
        _from: CapabilityLevel,
        to: CapabilityLevel,
        constraint: &IncompatibilityConstraint,
    ) -> TrifectaRisk {
        // Create a modified capability set to check trifecta
        let mut test_caps = self.floor.capabilities.clone();

        // Apply the change
        match op {
            Operation::ReadFiles => test_caps.read_files = to,
            Operation::WriteFiles => test_caps.write_files = to,
            Operation::EditFiles => test_caps.edit_files = to,
            Operation::RunBash => test_caps.run_bash = to,
            Operation::GlobSearch => test_caps.glob_search = to,
            Operation::GrepSearch => test_caps.grep_search = to,
            Operation::WebSearch => test_caps.web_search = to,
            Operation::WebFetch => test_caps.web_fetch = to,
            Operation::GitCommit => test_caps.git_commit = to,
            Operation::GitPush => test_caps.git_push = to,
            Operation::CreatePr => test_caps.create_pr = to,
            Operation::ManagePods => test_caps.manage_pods = to,
        }

        let before = constraint.trifecta_risk(&self.floor.capabilities);
        let after = constraint.trifecta_risk(&test_caps);

        // If this change increases trifecta risk, report the new level
        if after > before {
            after
        } else {
            TrifectaRisk::None
        }
    }

    /// Compute obligation weakenings (removals).
    fn compute_obligation_weakenings(&self, gap: &mut WeakeningGap) {
        // Check each operation that has an obligation in floor but not in ceiling
        for op in &self.floor.obligations.approvals {
            if !self.ceiling.requires_approval(*op) {
                let cost = self.cost_config.obligation_removal_cost(*op);
                gap.add(WeakeningRequest::obligation_removal(*op, cost));
            }
        }
    }

    /// Execute a function with ceiling permissions and return the result
    /// with weakening tracking.
    pub fn execute<F, A>(&self, f: F) -> PermissiveExecutionResult<A>
    where
        F: FnOnce(&PermissionLattice) -> A,
    {
        let value = f(&self.ceiling);
        let gap = self.compute_gap();

        let constraint = IncompatibilityConstraint::enforcing();
        let floor_trifecta = constraint.trifecta_risk(&self.floor.capabilities);
        let ceiling_trifecta = constraint.trifecta_risk(&self.ceiling.capabilities);

        PermissiveExecutionResult {
            value,
            floor: self.floor.clone(),
            ceiling: self.ceiling.clone(),
            isolation_floor: self.isolation_floor,
            weakenings: gap.requests,
            total_cost: gap.total_cost,
            floor_trifecta,
            ceiling_trifecta,
        }
    }

    /// Execute with a cost threshold - returns error if threshold exceeded.
    pub fn execute_with_threshold<F, A>(
        &self,
        threshold: rust_decimal::Decimal,
        f: F,
    ) -> Result<PermissiveExecutionResult<A>, ExecutionDenied>
    where
        F: FnOnce(&PermissionLattice) -> A,
    {
        let gap = self.compute_gap();
        if gap.total_cost.total() > threshold {
            return Err(ExecutionDenied {
                requested_cost: gap.total_cost,
                threshold,
                weakenings_needed: gap.requests,
            });
        }

        Ok(self.execute(f))
    }
}

/// Builder for PermissiveExecutor.
#[derive(Debug, Clone, Default)]
pub struct PermissiveExecutorBuilder {
    floor: Option<PermissionLattice>,
    ceiling: Option<PermissionLattice>,
    isolation_floor: Option<IsolationLattice>,
    cost_config: Option<WeakeningCostConfig>,
}

impl PermissiveExecutorBuilder {
    /// Set the floor permissions.
    pub fn floor(mut self, floor: PermissionLattice) -> Self {
        self.floor = Some(floor);
        self
    }

    /// Set the ceiling permissions.
    pub fn ceiling(mut self, ceiling: PermissionLattice) -> Self {
        self.ceiling = Some(ceiling);
        self
    }

    /// Set the isolation floor.
    pub fn isolation_floor(mut self, isolation: IsolationLattice) -> Self {
        self.isolation_floor = Some(isolation);
        self
    }

    /// Set the cost configuration.
    pub fn cost_config(mut self, config: WeakeningCostConfig) -> Self {
        self.cost_config = Some(config);
        self
    }

    /// Build the executor.
    pub fn build(self) -> PermissiveExecutor {
        PermissiveExecutor {
            floor: self.floor.unwrap_or_else(PermissionLattice::codegen),
            ceiling: self.ceiling.unwrap_or_else(PermissionLattice::permissive),
            isolation_floor: self.isolation_floor.unwrap_or_default(),
            cost_config: self.cost_config.unwrap_or_default(),
        }
    }
}

/// Error when execution is denied due to cost threshold.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExecutionDenied {
    /// The cost that was requested
    pub requested_cost: WeakeningCost,
    /// The threshold that was exceeded
    pub threshold: rust_decimal::Decimal,
    /// The weakenings that would have been needed
    pub weakenings_needed: Vec<WeakeningRequest>,
}

impl fmt::Display for ExecutionDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Execution denied: cost {} exceeds threshold {} ({} weakenings needed)",
            self.requested_cost.total(),
            self.threshold,
            self.weakenings_needed.len()
        )
    }
}

impl std::error::Error for ExecutionDenied {}

/// Sequence multiple permissive executions, accumulating weakenings.
pub fn sequence<A>(executions: Vec<PermissiveExecution<A>>) -> PermissiveExecution<Vec<A>> {
    let mut weakenings = Vec::new();
    let mut total_cost = WeakeningCost::zero();
    let mut values = Vec::with_capacity(executions.len());

    for exec in executions {
        values.push(exec.value);
        weakenings.extend(exec.weakenings);
        total_cost = total_cost.combine(&exec.total_cost);
    }

    PermissiveExecution {
        value: values,
        weakenings,
        total_cost,
    }
}

/// Traverse a list with a permissive function, accumulating weakenings.
pub fn traverse<A, B, F>(items: Vec<A>, f: F) -> PermissiveExecution<Vec<B>>
where
    F: Fn(A) -> PermissiveExecution<B>,
{
    let executions: Vec<_> = items.into_iter().map(f).collect();
    sequence(executions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal::Decimal;

    #[test]
    fn test_pure() {
        let exec: PermissiveExecution<i32> = PermissiveExecution::pure(42);
        assert_eq!(exec.value, 42);
        assert!(exec.weakenings.is_empty());
        assert!(exec.total_cost.is_zero());
    }

    #[test]
    fn test_map() {
        let exec = PermissiveExecution::pure(10);
        let mapped = exec.map(|x| x * 2);
        assert_eq!(mapped.value, 20);
        assert!(mapped.weakenings.is_empty());
    }

    #[test]
    fn test_and_then_accumulates_weakenings() {
        let exec1 = PermissiveExecution::with_weakening(
            10,
            WeakeningRequest::capability(
                Operation::ReadFiles,
                CapabilityLevel::Never,
                CapabilityLevel::LowRisk,
                WeakeningCost::new(Decimal::new(1, 1)),
                TrifectaRisk::Low,
            ),
        );

        let exec2 = exec1.and_then(|x| {
            PermissiveExecution::with_weakening(
                x * 2,
                WeakeningRequest::capability(
                    Operation::WriteFiles,
                    CapabilityLevel::Never,
                    CapabilityLevel::LowRisk,
                    WeakeningCost::new(Decimal::new(1, 1)),
                    TrifectaRisk::Low,
                ),
            )
        });

        assert_eq!(exec2.value, 20);
        assert_eq!(exec2.weakenings.len(), 2);
        assert_eq!(exec2.total_cost.base, Decimal::new(2, 1)); // 0.2
    }

    #[test]
    fn test_monad_left_identity() {
        // pure(a).and_then(f) = f(a)
        let a = 42;
        let f = |x: i32| {
            PermissiveExecution::with_weakening(
                x * 2,
                WeakeningRequest::capability(
                    Operation::ReadFiles,
                    CapabilityLevel::Never,
                    CapabilityLevel::LowRisk,
                    WeakeningCost::new(Decimal::new(1, 1)),
                    TrifectaRisk::None,
                ),
            )
        };

        let lhs = PermissiveExecution::pure(a).and_then(f);
        let rhs = f(a);

        assert_eq!(lhs.value, rhs.value);
        assert_eq!(lhs.weakenings.len(), rhs.weakenings.len());
        assert_eq!(lhs.total_cost.total(), rhs.total_cost.total());
    }

    #[test]
    fn test_monad_right_identity() {
        // m.and_then(pure) = m
        let m = PermissiveExecution::with_weakening(
            42,
            WeakeningRequest::capability(
                Operation::ReadFiles,
                CapabilityLevel::Never,
                CapabilityLevel::LowRisk,
                WeakeningCost::new(Decimal::new(1, 1)),
                TrifectaRisk::None,
            ),
        );

        let result = m.clone().and_then(PermissiveExecution::pure);

        assert_eq!(result.value, m.value);
        assert_eq!(result.weakenings.len(), m.weakenings.len());
        assert_eq!(result.total_cost.total(), m.total_cost.total());
    }

    #[test]
    fn test_monad_associativity() {
        // (m.and_then(f)).and_then(g) = m.and_then(|x| f(x).and_then(g))
        let m = PermissiveExecution::pure(10);
        let f = |x: i32| PermissiveExecution::pure(x * 2);
        let g = |x: i32| PermissiveExecution::pure(x + 1);

        let lhs = m.clone().and_then(f).and_then(g);
        let rhs = m.and_then(|x| f(x).and_then(g));

        assert_eq!(lhs.value, rhs.value);
        assert_eq!(lhs.total_cost.total(), rhs.total_cost.total());
    }

    #[test]
    fn test_executor_compute_gap() {
        let executor = PermissiveExecutor::new(
            PermissionLattice::codegen(),
            PermissionLattice::permissive(),
            IsolationLattice::sandboxed(),
            WeakeningCostConfig::default(),
        );

        let gap = executor.compute_gap();

        // Permissive has more capabilities than codegen, so should have weakenings
        assert!(!gap.is_empty());
        assert!(!gap.total_cost.is_zero());
    }

    #[test]
    fn test_executor_no_gap_for_same() {
        let perms = PermissionLattice::codegen();
        let executor = PermissiveExecutor::new(
            perms.clone(),
            perms,
            IsolationLattice::sandboxed(),
            WeakeningCostConfig::default(),
        );

        let gap = executor.compute_gap();

        // Same floor and ceiling should have no weakenings
        assert!(gap.is_empty());
    }

    #[test]
    fn test_executor_builder() {
        let executor = PermissiveExecutor::builder()
            .floor(PermissionLattice::read_only())
            .ceiling(PermissionLattice::permissive())
            .isolation_floor(IsolationLattice::microvm())
            .cost_config(WeakeningCostConfig::default())
            .build();

        assert_eq!(executor.floor().description, "Read-only permissions");
        assert_eq!(executor.ceiling().description, "Permissive permissions");
    }

    #[test]
    fn test_executor_execute() {
        let executor = PermissiveExecutor::new(
            PermissionLattice::codegen(),
            PermissionLattice::permissive(),
            IsolationLattice::sandboxed(),
            WeakeningCostConfig::default(),
        );

        let result = executor.execute(|_perms| "executed");

        assert_eq!(result.value, "executed");
        assert!(!result.weakenings.is_empty());
    }

    #[test]
    fn test_executor_execute_with_threshold() {
        let executor = PermissiveExecutor::new(
            PermissionLattice::codegen(),
            PermissionLattice::permissive(),
            IsolationLattice::sandboxed(),
            WeakeningCostConfig::default(),
        );

        // Very low threshold - should fail
        let result = executor.execute_with_threshold(Decimal::new(1, 2), |_| "test"); // 0.01
        assert!(result.is_err());

        // Very high threshold - should succeed
        let result = executor.execute_with_threshold(Decimal::new(100, 0), |_| "test"); // 100
        assert!(result.is_ok());
    }

    #[test]
    fn test_sequence() {
        let execs = vec![
            PermissiveExecution::pure(1),
            PermissiveExecution::pure(2),
            PermissiveExecution::pure(3),
        ];

        let result = sequence(execs);
        assert_eq!(result.value, vec![1, 2, 3]);
    }

    #[test]
    fn test_traverse() {
        let items = vec![1, 2, 3];
        let result = traverse(items, |x| PermissiveExecution::pure(x * 2));
        assert_eq!(result.value, vec![2, 4, 6]);
    }
}
