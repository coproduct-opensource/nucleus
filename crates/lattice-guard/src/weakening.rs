//! Weakening tracking for permissive execution.
//!
//! This module provides types for tracking when permissions exceed a secure
//! floor (fallback), computing the "cost" of each weakening, and generating
//! approval requests.
//!
//! # Mathematical Foundation
//!
//! A **weakening** is the dual of the nucleus pattern:
//! - Nucleus: deflationary, adds restrictions
//! - Weakening: inflationary from floor, tracks permission expansion
//!
//! The key operation is the **Heyting implication** `floor → used`:
//! ```text
//! weakening_gap(floor, used) = floor → used
//! ```
//!
//! This computes "what's needed to go from floor to used".
//!
//! # Example
//!
//! ```rust
//! use lattice_guard::weakening::{WeakeningCost, WeakeningCostConfig};
//! use lattice_guard::{CapabilityLevel, Operation};
//!
//! let config = WeakeningCostConfig::default();
//!
//! // Cost of elevating read_files from Never to Always
//! let cost = config.capability_cost(CapabilityLevel::Never, CapabilityLevel::Always);
//! assert!(cost.base > rust_decimal::Decimal::ZERO);
//! ```

use rust_decimal::Decimal;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::capability::{Operation, TrifectaRisk};
use crate::isolation::{FileIsolation, IsolationLattice, NetworkIsolation, ProcessIsolation};
use crate::CapabilityLevel;

/// Identifies which dimension of the permission lattice is being weakened.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum WeakeningDimension {
    /// Elevating a capability level (e.g., Never → LowRisk)
    Capability(Operation),
    /// Removing an approval requirement
    ObligationRemoval(Operation),
    /// Expanding path access beyond floor
    Path,
    /// Increasing budget limits
    Budget,
    /// Allowing additional commands
    Command,
    /// Extending time window
    Time,
    /// Weakening process isolation (e.g., MicroVM → Namespaced)
    ProcessIsolation,
    /// Weakening file isolation (e.g., Ephemeral → Sandboxed)
    FileIsolation,
    /// Weakening network isolation (e.g., Airgapped → Filtered)
    NetworkIsolation,
}

impl fmt::Display for WeakeningDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capability(op) => write!(f, "capability:{:?}", op),
            Self::ObligationRemoval(op) => write!(f, "obligation_removal:{:?}", op),
            Self::Path => write!(f, "path"),
            Self::Budget => write!(f, "budget"),
            Self::Command => write!(f, "command"),
            Self::Time => write!(f, "time"),
            Self::ProcessIsolation => write!(f, "process_isolation"),
            Self::FileIsolation => write!(f, "file_isolation"),
            Self::NetworkIsolation => write!(f, "network_isolation"),
        }
    }
}

/// Quantified cost of a security weakening.
///
/// The total cost is computed as: `base * trifecta_multiplier * isolation_multiplier`
///
/// # Cost Semantics
///
/// - `base`: Raw cost of the weakening (0.0 = none, 1.0 = maximum single weakening)
/// - `trifecta_multiplier`: Amplifies cost when approaching lethal trifecta
/// - `isolation_multiplier`: Amplifies cost when weakening isolation
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WeakeningCost {
    /// Base cost (0.0 = none, 1.0 = full weakening of one dimension)
    pub base: Decimal,
    /// Multiplier for trifecta proximity (1x, 3x, 10x)
    pub trifecta_multiplier: Decimal,
    /// Multiplier for isolation weakening (1x, 2x, 3x)
    pub isolation_multiplier: Decimal,
}

impl WeakeningCost {
    /// Zero cost (no weakening).
    pub fn zero() -> Self {
        Self {
            base: Decimal::ZERO,
            trifecta_multiplier: Decimal::ONE,
            isolation_multiplier: Decimal::ONE,
        }
    }

    /// Create a cost with only a base value.
    pub fn new(base: Decimal) -> Self {
        Self {
            base,
            trifecta_multiplier: Decimal::ONE,
            isolation_multiplier: Decimal::ONE,
        }
    }

    /// Create a cost with base and trifecta multiplier.
    pub fn with_trifecta(base: Decimal, trifecta_multiplier: Decimal) -> Self {
        Self {
            base,
            trifecta_multiplier,
            isolation_multiplier: Decimal::ONE,
        }
    }

    /// Create a cost with base and isolation multiplier.
    pub fn with_isolation(base: Decimal, isolation_multiplier: Decimal) -> Self {
        Self {
            base,
            trifecta_multiplier: Decimal::ONE,
            isolation_multiplier,
        }
    }

    /// Compute the total cost.
    pub fn total(&self) -> Decimal {
        self.base * self.trifecta_multiplier * self.isolation_multiplier
    }

    /// Combine two costs (sum base, max multipliers).
    ///
    /// This models that multiple weakenings accumulate additively,
    /// but the worst-case multipliers apply.
    pub fn combine(&self, other: &Self) -> Self {
        Self {
            base: self.base + other.base,
            trifecta_multiplier: self.trifecta_multiplier.max(other.trifecta_multiplier),
            isolation_multiplier: self.isolation_multiplier.max(other.isolation_multiplier),
        }
    }

    /// Check if this cost exceeds a threshold.
    pub fn exceeds(&self, threshold: Decimal) -> bool {
        self.total() > threshold
    }

    /// Check if this represents zero cost.
    pub fn is_zero(&self) -> bool {
        self.base == Decimal::ZERO
    }
}

impl PartialOrd for WeakeningCost {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WeakeningCost {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.total().cmp(&other.total())
    }
}

impl fmt::Display for WeakeningCost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:.2} (base: {:.2}, trifecta: {:.1}x, isolation: {:.1}x)",
            self.total(),
            self.base,
            self.trifecta_multiplier,
            self.isolation_multiplier
        )
    }
}

/// A request to weaken a specific dimension of the security policy.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WeakeningRequest {
    /// Which dimension is being weakened
    pub dimension: WeakeningDimension,
    /// The floor level for this dimension (as string for display)
    pub from_level: String,
    /// The requested level (as string for display)
    pub to_level: String,
    /// The computed cost of this weakening
    pub cost: WeakeningCost,
    /// Trifecta impact (does this enable a trifecta component?)
    pub trifecta_impact: TrifectaRisk,
    /// Human-readable justification (if provided)
    pub justification: Option<String>,
}

impl WeakeningRequest {
    /// Create a new weakening request.
    pub fn new(
        dimension: WeakeningDimension,
        from_level: impl Into<String>,
        to_level: impl Into<String>,
        cost: WeakeningCost,
        trifecta_impact: TrifectaRisk,
    ) -> Self {
        Self {
            dimension,
            from_level: from_level.into(),
            to_level: to_level.into(),
            cost,
            trifecta_impact,
            justification: None,
        }
    }

    /// Create a capability weakening request.
    pub fn capability(
        op: Operation,
        from: CapabilityLevel,
        to: CapabilityLevel,
        cost: WeakeningCost,
        trifecta_impact: TrifectaRisk,
    ) -> Self {
        Self::new(
            WeakeningDimension::Capability(op),
            format!("{:?}", from),
            format!("{:?}", to),
            cost,
            trifecta_impact,
        )
    }

    /// Create an obligation removal request.
    pub fn obligation_removal(op: Operation, cost: WeakeningCost) -> Self {
        Self::new(
            WeakeningDimension::ObligationRemoval(op),
            "required",
            "not_required",
            cost,
            TrifectaRisk::None,
        )
    }

    /// Create a process isolation weakening request.
    pub fn process_isolation(
        from: ProcessIsolation,
        to: ProcessIsolation,
        cost: WeakeningCost,
    ) -> Self {
        Self::new(
            WeakeningDimension::ProcessIsolation,
            from.as_str(),
            to.as_str(),
            cost,
            TrifectaRisk::None,
        )
    }

    /// Create a file isolation weakening request.
    pub fn file_isolation(from: FileIsolation, to: FileIsolation, cost: WeakeningCost) -> Self {
        Self::new(
            WeakeningDimension::FileIsolation,
            from.as_str(),
            to.as_str(),
            cost,
            TrifectaRisk::None,
        )
    }

    /// Create a network isolation weakening request.
    pub fn network_isolation(
        from: NetworkIsolation,
        to: NetworkIsolation,
        cost: WeakeningCost,
    ) -> Self {
        Self::new(
            WeakeningDimension::NetworkIsolation,
            from.as_str(),
            to.as_str(),
            cost,
            TrifectaRisk::None,
        )
    }

    /// Add a justification to this request.
    pub fn with_justification(mut self, justification: impl Into<String>) -> Self {
        self.justification = Some(justification.into());
        self
    }

    /// Check if this weakening requires human approval.
    pub fn requires_approval(&self) -> bool {
        self.trifecta_impact == TrifectaRisk::Complete || self.cost.total() > Decimal::new(5, 1)
        // > 0.5
    }
}

impl fmt::Display for WeakeningRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} → {} (cost: {}, trifecta: {:?})",
            self.dimension, self.from_level, self.to_level, self.cost, self.trifecta_impact
        )
    }
}

/// Configuration for computing weakening costs.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WeakeningCostConfig {
    // Capability costs (from → to)
    /// Cost: Never → LowRisk
    pub cap_never_to_lowrisk: Decimal,
    /// Cost: Never → Always
    pub cap_never_to_always: Decimal,
    /// Cost: LowRisk → Always
    pub cap_lowrisk_to_always: Decimal,

    // Obligation removal costs
    /// Cost: removing exfil operation obligation (git_push, create_pr, run_bash)
    pub obligation_exfil_removal: Decimal,
    /// Cost: removing other operation obligation
    pub obligation_other_removal: Decimal,

    // Trifecta multipliers
    /// Multiplier when completing trifecta
    pub trifecta_complete_multiplier: Decimal,
    /// Multiplier when approaching trifecta (None/Low → Medium)
    pub trifecta_approach_multiplier: Decimal,
    /// Multiplier when at medium trifecta
    pub trifecta_medium_multiplier: Decimal,

    // Process isolation costs
    /// Cost: MicroVM → Namespaced
    pub process_microvm_to_namespaced: Decimal,
    /// Cost: MicroVM → Shared
    pub process_microvm_to_shared: Decimal,
    /// Cost: Namespaced → Shared
    pub process_namespaced_to_shared: Decimal,

    // File isolation costs
    /// Cost: Ephemeral → ReadOnly
    pub file_ephemeral_to_readonly: Decimal,
    /// Cost: Ephemeral → Sandboxed
    pub file_ephemeral_to_sandboxed: Decimal,
    /// Cost: Ephemeral → Unrestricted
    pub file_ephemeral_to_unrestricted: Decimal,
    /// Cost: ReadOnly → Sandboxed
    pub file_readonly_to_sandboxed: Decimal,
    /// Cost: ReadOnly → Unrestricted
    pub file_readonly_to_unrestricted: Decimal,
    /// Cost: Sandboxed → Unrestricted
    pub file_sandboxed_to_unrestricted: Decimal,

    // Network isolation costs
    /// Cost: Airgapped → Filtered
    pub network_airgapped_to_filtered: Decimal,
    /// Cost: Airgapped → Namespaced
    pub network_airgapped_to_namespaced: Decimal,
    /// Cost: Airgapped → Host
    pub network_airgapped_to_host: Decimal,
    /// Cost: Filtered → Namespaced
    pub network_filtered_to_namespaced: Decimal,
    /// Cost: Filtered → Host
    pub network_filtered_to_host: Decimal,
    /// Cost: Namespaced → Host
    pub network_namespaced_to_host: Decimal,
}

impl Default for WeakeningCostConfig {
    fn default() -> Self {
        Self {
            // Capability costs
            cap_never_to_lowrisk: Decimal::new(1, 1),  // 0.1
            cap_never_to_always: Decimal::new(3, 1),   // 0.3
            cap_lowrisk_to_always: Decimal::new(2, 1), // 0.2

            // Obligation removal costs
            obligation_exfil_removal: Decimal::new(5, 1), // 0.5
            obligation_other_removal: Decimal::new(2, 1), // 0.2

            // Trifecta multipliers
            trifecta_complete_multiplier: Decimal::new(10, 0), // 10x
            trifecta_approach_multiplier: Decimal::new(3, 0),  // 3x
            trifecta_medium_multiplier: Decimal::new(2, 0),    // 2x

            // Process isolation costs
            process_microvm_to_namespaced: Decimal::new(3, 1), // 0.3
            process_microvm_to_shared: Decimal::new(8, 1),     // 0.8
            process_namespaced_to_shared: Decimal::new(5, 1),  // 0.5

            // File isolation costs
            file_ephemeral_to_readonly: Decimal::new(2, 1), // 0.2
            file_ephemeral_to_sandboxed: Decimal::new(4, 1), // 0.4
            file_ephemeral_to_unrestricted: Decimal::new(8, 1), // 0.8
            file_readonly_to_sandboxed: Decimal::new(2, 1), // 0.2
            file_readonly_to_unrestricted: Decimal::new(6, 1), // 0.6
            file_sandboxed_to_unrestricted: Decimal::new(4, 1), // 0.4

            // Network isolation costs
            network_airgapped_to_filtered: Decimal::new(3, 1), // 0.3
            network_airgapped_to_namespaced: Decimal::new(5, 1), // 0.5
            network_airgapped_to_host: Decimal::new(7, 1),     // 0.7
            network_filtered_to_namespaced: Decimal::new(2, 1), // 0.2
            network_filtered_to_host: Decimal::new(4, 1),      // 0.4
            network_namespaced_to_host: Decimal::new(2, 1),    // 0.2
        }
    }
}

impl WeakeningCostConfig {
    /// Compute the cost of elevating a capability level.
    pub fn capability_cost(&self, from: CapabilityLevel, to: CapabilityLevel) -> WeakeningCost {
        let base = match (from, to) {
            (CapabilityLevel::Never, CapabilityLevel::LowRisk) => self.cap_never_to_lowrisk,
            (CapabilityLevel::Never, CapabilityLevel::Always) => self.cap_never_to_always,
            (CapabilityLevel::LowRisk, CapabilityLevel::Always) => self.cap_lowrisk_to_always,
            _ => Decimal::ZERO, // No cost for same level or restriction
        };
        WeakeningCost::new(base)
    }

    /// Compute the cost of removing an obligation.
    pub fn obligation_removal_cost(&self, op: Operation) -> WeakeningCost {
        let base = if Self::is_exfil_operation(op) {
            self.obligation_exfil_removal
        } else {
            self.obligation_other_removal
        };
        WeakeningCost::new(base)
    }

    /// Check if an operation is an exfiltration vector.
    fn is_exfil_operation(op: Operation) -> bool {
        matches!(
            op,
            Operation::GitPush | Operation::CreatePr | Operation::RunBash
        )
    }

    /// Compute the trifecta multiplier.
    pub fn trifecta_multiplier(&self, before: TrifectaRisk, after: TrifectaRisk) -> Decimal {
        match (before, after) {
            (_, TrifectaRisk::Complete) => self.trifecta_complete_multiplier,
            (TrifectaRisk::None | TrifectaRisk::Low, TrifectaRisk::Medium) => {
                self.trifecta_approach_multiplier
            }
            (TrifectaRisk::Medium, TrifectaRisk::Medium) => self.trifecta_medium_multiplier,
            _ => Decimal::ONE,
        }
    }

    /// Compute the cost of weakening process isolation.
    pub fn process_isolation_cost(
        &self,
        from: ProcessIsolation,
        to: ProcessIsolation,
    ) -> WeakeningCost {
        // Only compute cost if actually weakening (from > to means from is stronger)
        if from <= to {
            return WeakeningCost::zero();
        }

        let base = match (from, to) {
            (ProcessIsolation::MicroVM, ProcessIsolation::Namespaced) => {
                self.process_microvm_to_namespaced
            }
            (ProcessIsolation::MicroVM, ProcessIsolation::Shared) => self.process_microvm_to_shared,
            (ProcessIsolation::Namespaced, ProcessIsolation::Shared) => {
                self.process_namespaced_to_shared
            }
            _ => Decimal::ZERO,
        };
        WeakeningCost::with_isolation(base, Decimal::new(2, 0)) // 2x isolation multiplier
    }

    /// Compute the cost of weakening file isolation.
    pub fn file_isolation_cost(&self, from: FileIsolation, to: FileIsolation) -> WeakeningCost {
        if from <= to {
            return WeakeningCost::zero();
        }

        let base = match (from, to) {
            (FileIsolation::Ephemeral, FileIsolation::ReadOnly) => self.file_ephemeral_to_readonly,
            (FileIsolation::Ephemeral, FileIsolation::Sandboxed) => {
                self.file_ephemeral_to_sandboxed
            }
            (FileIsolation::Ephemeral, FileIsolation::Unrestricted) => {
                self.file_ephemeral_to_unrestricted
            }
            (FileIsolation::ReadOnly, FileIsolation::Sandboxed) => self.file_readonly_to_sandboxed,
            (FileIsolation::ReadOnly, FileIsolation::Unrestricted) => {
                self.file_readonly_to_unrestricted
            }
            (FileIsolation::Sandboxed, FileIsolation::Unrestricted) => {
                self.file_sandboxed_to_unrestricted
            }
            _ => Decimal::ZERO,
        };
        WeakeningCost::with_isolation(base, Decimal::new(15, 1)) // 1.5x isolation multiplier
    }

    /// Compute the cost of weakening network isolation.
    pub fn network_isolation_cost(
        &self,
        from: NetworkIsolation,
        to: NetworkIsolation,
    ) -> WeakeningCost {
        if from <= to {
            return WeakeningCost::zero();
        }

        let base = match (from, to) {
            (NetworkIsolation::Airgapped, NetworkIsolation::Filtered) => {
                self.network_airgapped_to_filtered
            }
            (NetworkIsolation::Airgapped, NetworkIsolation::Namespaced) => {
                self.network_airgapped_to_namespaced
            }
            (NetworkIsolation::Airgapped, NetworkIsolation::Host) => self.network_airgapped_to_host,
            (NetworkIsolation::Filtered, NetworkIsolation::Namespaced) => {
                self.network_filtered_to_namespaced
            }
            (NetworkIsolation::Filtered, NetworkIsolation::Host) => self.network_filtered_to_host,
            (NetworkIsolation::Namespaced, NetworkIsolation::Host) => {
                self.network_namespaced_to_host
            }
            _ => Decimal::ZERO,
        };
        WeakeningCost::with_isolation(base, Decimal::new(2, 0)) // 2x isolation multiplier
    }

    /// Compute the cost of weakening isolation.
    pub fn isolation_cost(&self, from: &IsolationLattice, to: &IsolationLattice) -> WeakeningCost {
        let process_cost = self.process_isolation_cost(from.process, to.process);
        let file_cost = self.file_isolation_cost(from.file, to.file);
        let network_cost = self.network_isolation_cost(from.network, to.network);

        process_cost.combine(&file_cost).combine(&network_cost)
    }

    /// Compute the full weakening gap between a secure floor and actual permissions.
    ///
    /// Examines every dimension of the permission lattice and emits a
    /// `WeakeningRequest` for each dimension where `actual > floor`.
    pub fn compute_gap(
        &self,
        floor: &crate::PermissionLattice,
        actual: &crate::PermissionLattice,
    ) -> WeakeningGap {
        let mut gap = WeakeningGap::empty();

        // Capability weakenings
        let cap_checks: &[(Operation, CapabilityLevel, CapabilityLevel)] = &[
            (
                Operation::ReadFiles,
                floor.capabilities.read_files,
                actual.capabilities.read_files,
            ),
            (
                Operation::WriteFiles,
                floor.capabilities.write_files,
                actual.capabilities.write_files,
            ),
            (
                Operation::EditFiles,
                floor.capabilities.edit_files,
                actual.capabilities.edit_files,
            ),
            (
                Operation::RunBash,
                floor.capabilities.run_bash,
                actual.capabilities.run_bash,
            ),
            (
                Operation::WebSearch,
                floor.capabilities.web_search,
                actual.capabilities.web_search,
            ),
            (
                Operation::WebFetch,
                floor.capabilities.web_fetch,
                actual.capabilities.web_fetch,
            ),
            (
                Operation::GitPush,
                floor.capabilities.git_push,
                actual.capabilities.git_push,
            ),
            (
                Operation::CreatePr,
                floor.capabilities.create_pr,
                actual.capabilities.create_pr,
            ),
        ];

        // Compute trifecta risk before and after
        let constraint = crate::IncompatibilityConstraint::enforcing();
        let floor_trifecta = constraint.trifecta_risk(&floor.capabilities);
        let actual_trifecta = constraint.trifecta_risk(&actual.capabilities);
        let trifecta_mult = self.trifecta_multiplier(floor_trifecta, actual_trifecta);

        for &(op, floor_level, actual_level) in cap_checks {
            if actual_level > floor_level {
                let mut cost = self.capability_cost(floor_level, actual_level);
                cost.trifecta_multiplier = trifecta_mult;
                gap.add(WeakeningRequest::capability(
                    op,
                    floor_level,
                    actual_level,
                    cost,
                    actual_trifecta,
                ));
            }
        }

        // Obligation removal weakenings
        for op in &floor.obligations.approvals {
            if !actual.obligations.approvals.contains(op) {
                let cost = self.obligation_removal_cost(*op);
                gap.add(WeakeningRequest::obligation_removal(*op, cost));
            }
        }

        // Budget weakening (if actual allows more spend)
        if actual.budget.max_cost_usd > floor.budget.max_cost_usd {
            let ratio = actual.budget.max_cost_usd / floor.budget.max_cost_usd;
            // Cost scales with log of budget expansion ratio
            let base =
                Decimal::new(1, 1) * Decimal::from(ratio.to_string().parse::<i64>().unwrap_or(1));
            gap.add(WeakeningRequest::new(
                WeakeningDimension::Budget,
                format!("${}", floor.budget.max_cost_usd),
                format!("${}", actual.budget.max_cost_usd),
                WeakeningCost::new(base.min(Decimal::ONE)),
                TrifectaRisk::None,
            ));
        }

        // Path weakening (actual allows paths floor doesn't)
        let floor_allowed: std::collections::BTreeSet<_> = floor.paths.allowed.iter().collect();
        let actual_allowed: std::collections::BTreeSet<_> = actual.paths.allowed.iter().collect();
        let extra_paths: Vec<_> = actual_allowed.difference(&floor_allowed).collect();
        if !extra_paths.is_empty() {
            gap.add(WeakeningRequest::new(
                WeakeningDimension::Path,
                format!("{} allowed paths", floor.paths.allowed.len()),
                format!(
                    "{} allowed paths (+{})",
                    actual.paths.allowed.len(),
                    extra_paths.len()
                ),
                WeakeningCost::new(Decimal::new(2, 1)), // 0.2 per expansion
                TrifectaRisk::None,
            ));
        }

        // Command weakening (actual allows commands floor doesn't)
        let floor_cmds: std::collections::BTreeSet<_> = floor.commands.allowed.iter().collect();
        let actual_cmds: std::collections::BTreeSet<_> = actual.commands.allowed.iter().collect();
        let extra_cmds: Vec<_> = actual_cmds.difference(&floor_cmds).collect();
        if !extra_cmds.is_empty() {
            gap.add(WeakeningRequest::new(
                WeakeningDimension::Command,
                format!("{} allowed commands", floor.commands.allowed.len()),
                format!(
                    "{} allowed commands (+{})",
                    actual.commands.allowed.len(),
                    extra_cmds.len()
                ),
                WeakeningCost::new(Decimal::new(1, 1)), // 0.1 per expansion
                TrifectaRisk::None,
            ));
        }

        // Time weakening (actual has wider window)
        if actual.time.valid_until > floor.time.valid_until {
            let extra_secs = (actual.time.valid_until - floor.time.valid_until).num_seconds();
            gap.add(WeakeningRequest::new(
                WeakeningDimension::Time,
                format!(
                    "{}s window",
                    (floor.time.valid_until - floor.time.valid_from).num_seconds()
                ),
                format!(
                    "{}s window (+{}s)",
                    (actual.time.valid_until - actual.time.valid_from).num_seconds(),
                    extra_secs
                ),
                WeakeningCost::new(Decimal::new(1, 2)), // 0.01 per time extension
                TrifectaRisk::None,
            ));
        }

        gap
    }
}

/// A collection of weakening requests with computed total cost.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WeakeningGap {
    /// Individual weakening requests
    pub requests: Vec<WeakeningRequest>,
    /// Total cost of all weakenings
    pub total_cost: WeakeningCost,
}

impl WeakeningGap {
    /// Create an empty gap (no weakenings).
    pub fn empty() -> Self {
        Self {
            requests: Vec::new(),
            total_cost: WeakeningCost::zero(),
        }
    }

    /// Create a gap with a single weakening.
    pub fn single(request: WeakeningRequest) -> Self {
        let total_cost = request.cost.clone();
        Self {
            requests: vec![request],
            total_cost,
        }
    }

    /// Add a weakening request.
    pub fn add(&mut self, request: WeakeningRequest) {
        self.total_cost = self.total_cost.combine(&request.cost);
        self.requests.push(request);
    }

    /// Check if the gap is empty (no weakenings needed).
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Get the number of weakening requests.
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Combine two gaps.
    pub fn combine(mut self, other: Self) -> Self {
        self.total_cost = self.total_cost.combine(&other.total_cost);
        self.requests.extend(other.requests);
        self
    }

    /// Filter to weakenings that require approval.
    pub fn requiring_approval(&self) -> Vec<&WeakeningRequest> {
        self.requests
            .iter()
            .filter(|r| r.requires_approval())
            .collect()
    }

    /// Get weakenings by dimension type.
    pub fn by_dimension(&self, dimension: &WeakeningDimension) -> Vec<&WeakeningRequest> {
        self.requests
            .iter()
            .filter(|r| std::mem::discriminant(&r.dimension) == std::mem::discriminant(dimension))
            .collect()
    }

    /// Check if any weakening has the given dimension.
    pub fn has_dimension(&self, dimension: &WeakeningDimension) -> bool {
        self.requests
            .iter()
            .any(|r| std::mem::discriminant(&r.dimension) == std::mem::discriminant(dimension))
    }
}

impl fmt::Display for WeakeningGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "WeakeningGap (total: {}):", self.total_cost)?;
        for request in &self.requests {
            writeln!(f, "  - {}", request)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weakening_cost_zero() {
        let cost = WeakeningCost::zero();
        assert_eq!(cost.total(), Decimal::ZERO);
        assert!(cost.is_zero());
    }

    #[test]
    fn test_weakening_cost_combine() {
        let a = WeakeningCost::with_trifecta(Decimal::new(1, 1), Decimal::new(2, 0)); // 0.1, 2x
        let b = WeakeningCost::with_trifecta(Decimal::new(2, 1), Decimal::new(3, 0)); // 0.2, 3x

        let combined = a.combine(&b);
        assert_eq!(combined.base, Decimal::new(3, 1)); // 0.3
        assert_eq!(combined.trifecta_multiplier, Decimal::new(3, 0)); // max(2, 3) = 3
    }

    #[test]
    fn test_weakening_cost_total() {
        let cost = WeakeningCost {
            base: Decimal::new(1, 1),                 // 0.1
            trifecta_multiplier: Decimal::new(2, 0),  // 2x
            isolation_multiplier: Decimal::new(3, 0), // 3x
        };
        // 0.1 * 2 * 3 = 0.6
        assert_eq!(cost.total(), Decimal::new(6, 1));
    }

    #[test]
    fn test_config_capability_cost() {
        let config = WeakeningCostConfig::default();

        let cost = config.capability_cost(CapabilityLevel::Never, CapabilityLevel::Always);
        assert_eq!(cost.base, Decimal::new(3, 1)); // 0.3

        let cost = config.capability_cost(CapabilityLevel::Always, CapabilityLevel::Never);
        assert_eq!(cost.base, Decimal::ZERO); // No cost for restriction
    }

    #[test]
    fn test_config_obligation_removal_cost() {
        let config = WeakeningCostConfig::default();

        let exfil_cost = config.obligation_removal_cost(Operation::GitPush);
        assert_eq!(exfil_cost.base, Decimal::new(5, 1)); // 0.5

        let other_cost = config.obligation_removal_cost(Operation::ReadFiles);
        assert_eq!(other_cost.base, Decimal::new(2, 1)); // 0.2
    }

    #[test]
    fn test_config_trifecta_multiplier() {
        let config = WeakeningCostConfig::default();

        let mult = config.trifecta_multiplier(TrifectaRisk::Low, TrifectaRisk::Complete);
        assert_eq!(mult, Decimal::new(10, 0)); // 10x

        let mult = config.trifecta_multiplier(TrifectaRisk::None, TrifectaRisk::Medium);
        assert_eq!(mult, Decimal::new(3, 0)); // 3x
    }

    #[test]
    fn test_config_process_isolation_cost() {
        let config = WeakeningCostConfig::default();

        // Weakening: MicroVM → Shared
        let cost =
            config.process_isolation_cost(ProcessIsolation::MicroVM, ProcessIsolation::Shared);
        assert_eq!(cost.base, Decimal::new(8, 1)); // 0.8
        assert_eq!(cost.isolation_multiplier, Decimal::new(2, 0)); // 2x

        // Strengthening: Shared → MicroVM (should be zero)
        let cost =
            config.process_isolation_cost(ProcessIsolation::Shared, ProcessIsolation::MicroVM);
        assert!(cost.is_zero());
    }

    #[test]
    fn test_weakening_gap_combine() {
        let mut gap1 = WeakeningGap::empty();
        gap1.add(WeakeningRequest::capability(
            Operation::ReadFiles,
            CapabilityLevel::Never,
            CapabilityLevel::Always,
            WeakeningCost::new(Decimal::new(3, 1)),
            TrifectaRisk::Low,
        ));

        let mut gap2 = WeakeningGap::empty();
        gap2.add(WeakeningRequest::process_isolation(
            ProcessIsolation::MicroVM,
            ProcessIsolation::Shared,
            WeakeningCost::with_isolation(Decimal::new(8, 1), Decimal::new(2, 0)),
        ));

        let combined = gap1.combine(gap2);
        assert_eq!(combined.len(), 2);
        assert_eq!(combined.total_cost.base, Decimal::new(11, 1)); // 0.3 + 0.8 = 1.1
    }

    #[test]
    fn test_compute_gap_no_weakening() {
        let config = WeakeningCostConfig::default();
        let floor = crate::PermissionLattice::default();
        let actual = floor.clone();

        let gap = config.compute_gap(&floor, &actual);
        assert!(gap.is_empty());
        assert!(gap.total_cost.is_zero());
    }

    #[test]
    fn test_compute_gap_capability_weakening() {
        let config = WeakeningCostConfig::default();
        let floor = crate::PermissionLattice::restrictive();
        let mut actual = floor.clone();
        // read_files is already Always in restrictive, so elevate write_files instead
        actual.capabilities.write_files = CapabilityLevel::LowRisk;
        actual.capabilities.web_fetch = CapabilityLevel::LowRisk;

        let gap = config.compute_gap(&floor, &actual);
        assert_eq!(gap.len(), 2);
        assert!(gap.has_dimension(&WeakeningDimension::Capability(Operation::WriteFiles)));
        assert!(gap.has_dimension(&WeakeningDimension::Capability(Operation::WebFetch)));
        assert!(!gap.total_cost.is_zero());
    }

    #[test]
    fn test_compute_gap_path_weakening() {
        let config = WeakeningCostConfig::default();
        let floor = crate::PermissionLattice::default();
        let mut actual = floor.clone();
        actual.paths.allowed.insert("/extra/path".to_string());

        let gap = config.compute_gap(&floor, &actual);
        assert!(gap.has_dimension(&WeakeningDimension::Path));
    }

    #[test]
    fn test_compute_gap_command_weakening() {
        let config = WeakeningCostConfig::default();
        let floor = crate::PermissionLattice::default();
        let mut actual = floor.clone();
        actual.commands.allowed.insert("docker build".to_string());

        let gap = config.compute_gap(&floor, &actual);
        assert!(gap.has_dimension(&WeakeningDimension::Command));
    }

    #[test]
    fn test_compute_gap_budget_weakening() {
        let config = WeakeningCostConfig::default();
        let floor = crate::PermissionLattice::default();
        let mut actual = floor.clone();
        actual.budget.max_cost_usd = floor.budget.max_cost_usd * Decimal::new(10, 0);

        let gap = config.compute_gap(&floor, &actual);
        assert!(gap.has_dimension(&WeakeningDimension::Budget));
    }

    #[test]
    fn test_compute_gap_trifecta_multiplier_applied() {
        let config = WeakeningCostConfig::default();
        let floor = crate::PermissionLattice::restrictive();
        let mut actual = floor.clone();
        // Enable all three trifecta legs
        actual.capabilities.read_files = CapabilityLevel::Always; // private data
        actual.capabilities.web_fetch = CapabilityLevel::LowRisk; // untrusted content
        actual.capabilities.git_push = CapabilityLevel::LowRisk; // exfiltration

        let gap = config.compute_gap(&floor, &actual);
        // All capability requests should have elevated trifecta multiplier
        for req in &gap.requests {
            if let WeakeningDimension::Capability(_) = &req.dimension {
                assert!(
                    req.cost.trifecta_multiplier > Decimal::ONE,
                    "Expected trifecta multiplier > 1 for {:?}",
                    req.dimension
                );
            }
        }
    }

    #[test]
    fn test_weakening_request_requires_approval() {
        let low_cost = WeakeningRequest::capability(
            Operation::ReadFiles,
            CapabilityLevel::Never,
            CapabilityLevel::LowRisk,
            WeakeningCost::new(Decimal::new(1, 1)), // 0.1
            TrifectaRisk::Low,
        );
        assert!(!low_cost.requires_approval());

        let high_cost = WeakeningRequest::capability(
            Operation::GitPush,
            CapabilityLevel::Never,
            CapabilityLevel::Always,
            WeakeningCost::new(Decimal::new(6, 1)), // 0.6
            TrifectaRisk::Medium,
        );
        assert!(high_cost.requires_approval());

        let trifecta = WeakeningRequest::capability(
            Operation::GitPush,
            CapabilityLevel::Never,
            CapabilityLevel::Always,
            WeakeningCost::new(Decimal::new(1, 1)), // 0.1 but Complete trifecta
            TrifectaRisk::Complete,
        );
        assert!(trifecta.requires_approval());
    }
}
