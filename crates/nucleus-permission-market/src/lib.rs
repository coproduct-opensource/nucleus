//! # nucleus-permission-market
//!
//! Lagrangian permission pricing oracle for multi-dimensional capability constraints.
//!
//! ## Overview
//!
//! In constrained optimization, a Lagrange multiplier `λ` converts a hard
//! constraint into a continuous penalty. By the duality theorem, `λ` IS the
//! market price of relaxing that constraint by one unit.
//!
//! This crate generalizes the 1D budget constraint (`BudgetConstraint` in
//! workstream-kg) to N independent permission dimensions:
//!
//! ```text
//! L' = L + Σᵢ λᵢ · gᵢ(utilization)
//! ```
//!
//! Each dimension (filesystem, command exec, network, approval) has its own
//! utilization and λ. When utilization is low, λ ≈ 0 and permissions are
//! effectively free. As utilization approaches the limit, λ grows
//! exponentially, pricing out low-value operations first.
//!
//! ## Usage
//!
//! ```rust
//! use nucleus_permission_market::{PermissionMarket, PermissionBid, PermissionDimension, TrustTier};
//! use std::collections::BTreeMap;
//!
//! // Create a market with current utilization
//! let mut utilizations = BTreeMap::new();
//! utilizations.insert(PermissionDimension::Filesystem, 0.3);    // low pressure
//! utilizations.insert(PermissionDimension::CommandExec, 0.85);   // high pressure
//!
//! let market = PermissionMarket::with_utilization(utilizations);
//!
//! // Submit a bid
//! let bid = PermissionBid {
//!     skill_id: "my-plugin".into(),
//!     requested: vec![
//!         PermissionDimension::Filesystem,
//!         PermissionDimension::CommandExec,
//!     ],
//!     value_estimate: 2.0,
//!     trust_tier: TrustTier::Verified,
//! };
//!
//! let grant = market.evaluate_bid(&bid);
//! assert!(grant.granted.contains(&PermissionDimension::Filesystem)); // cheap, granted
//! // CommandExec may be denied if 2.0 < λ_exec * 0.5 (verified discount)
//! ```
//!
//! ## Integration
//!
//! The permission market sits between the plugin and the tool-proxy:
//!
//! ```text
//! Plugin → X-Nucleus-Permission-Bid header → PermissionMarket.evaluate_bid()
//!          → grant/deny with λ pricing      → tool-proxy endpoint (enforcement)
//! ```
//!
//! The _mechanism_ (λ computation, bid evaluation) is vendor-agnostic.
//! The _calibration_ (cost models, trust assignment, utilization tracking)
//! is the orchestrator's responsibility.

pub mod bid;
pub mod dimension;
pub mod market;

pub use bid::{DeniedDimension, PermissionBid, PermissionGrant};
pub use dimension::{PermissionDimension, TrustTier};
pub use market::{compute_lambda, DimensionState, PermissionConstraintState, PermissionMarket};
