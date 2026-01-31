//! # Nucleus
//!
//! OS-level enforcement of lattice-guard permissions.
//!
//! While `lattice-guard` provides the policy layer (what SHOULD be allowed),
//! `nucleus` provides the enforcement layer (what IS allowed at runtime).
//!
//! ## Key Differences from lattice-guard
//!
//! | Aspect | lattice-guard | nucleus |
//! |--------|---------------|---------|
//! | Purpose | Policy definition | Policy enforcement |
//! | File access | `PathLattice::can_access()` predicate | `Sandbox::open()` with capability handles |
//! | Commands | `CommandLattice::can_execute()` predicate | `Executor::run()` spawns real processes |
//! | Budget | `BudgetLattice::charge()` on &mut self | `AtomicBudget::charge()` thread-safe |
//! | Time | `TimeLattice::is_valid()` wall clock | `MonotonicGuard` with quanta |
//! | Bypass | All fields pub, disable functions | Private fields, no disable functions |
//!
//! ## Design Principles
//!
//! 1. **No Bypass Path**: Unlike lattice-guard where all fields are public and
//!    constraints can be disabled, nucleus enforces policy in its API design.
//!    You cannot construct a `Sandbox` without a policy. You cannot execute
//!    commands without going through `Executor`.
//!
//! 2. **Capability-Based**: File access uses `cap-std` to hold directory handles.
//!    This prevents TOCTOU races and symlink escapes at the kernel level.
//!
//! 3. **Atomic Operations**: Budget tracking uses atomic operations so concurrent
//!    agents cannot race to exhaust budgets.
//!
//! 4. **Monotonic Time**: Temporal enforcement uses `quanta` monotonic clocks,
//!    not wall time that can be manipulated.
//!
//! ## Example
//!
//! ```ignore
//! use nucleus::{Sandbox, Executor, AtomicBudget};
//! use lattice_guard::PermissionLattice;
//!
//! // Create policy
//! let policy = PermissionLattice::fix_issue();
//!
//! // Create enforcement context (cannot be constructed without policy)
//! let sandbox = Sandbox::new(&policy, "/path/to/repo")?;
//! let budget = AtomicBudget::new(&policy.budget);
//! let guard = MonotonicGuard::minutes(30);
//! let executor = Executor::new(&policy, &sandbox, &budget)
//!     .with_time_guard(&guard);
//!
//! // File access - goes through capability handle
//! let file = sandbox.open("src/main.rs")?;  // Enforces PathLattice
//!
//! // Command execution - validates before spawning
//! let output = executor.run("cargo test")?;  // Enforces CommandLattice
//!
//! // Budget charging - atomic
//! budget.charge_usd(0.50)?;  // Enforces BudgetLattice atomically
//! ```

#![deny(unsafe_code)]
#![deny(missing_docs)]

mod budget;
mod command;
mod approval;
mod error;
mod pod;
mod sandbox;
mod time;

pub use budget::AtomicBudget;
pub use approval::{ApprovalRequest, ApprovalToken, Approver, CallbackApprover};
pub use command::{BudgetModel, Executor};
pub use error::{NucleusError, Result};
pub use pod::{PodRuntime, PodSpec};
pub use sandbox::Sandbox;
pub use time::MonotonicGuard;

// Re-export lattice-guard for convenience
pub use lattice_guard;
