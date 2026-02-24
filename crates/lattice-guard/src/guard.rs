//! Type-safe permission enforcement via the PermissionGuard trait.
//!
//! This module provides compile-time guarantees that permission checks cannot
//! be bypassed or ignored by callers.
//!
//! ## Graded Guards
//!
//! The [`GradedGuard`] combines type-safe enforcement with risk tracking via
//! the graded monad. Every guard decision carries a [`TrifectaRisk`] grade
//! that accumulates through monadic composition:
//!
//! ```rust
//! use lattice_guard::guard::{GradedGuard, PermissionGuard};
//! use lattice_guard::{PermissionLattice, CapabilityLevel};
//! use lattice_guard::graded::RiskGrade;
//!
//! let perms = PermissionLattice::read_only();
//! let guard = GradedGuard::new(perms);
//!
//! let result = guard.check_path("/workspace/src/lib.rs");
//! assert!(result.value.is_ok());
//! // Risk grade reflects trifecta exposure of the permission set
//! ```

use std::marker::PhantomData;

use crate::capability::{IncompatibilityConstraint, Operation, TrifectaRisk};
use crate::graded::Graded;
use crate::heyting::permission_gap;
use crate::PermissionLattice;

/// A proof type that permission was checked and granted.
///
/// This type cannot be constructed externally (the `_private` field
/// prevents it). The only way to obtain a `GuardedAction` is through
/// a successful permission check via [`PermissionGuard::guard`].
///
/// # Example
///
/// ```ignore
/// fn execute_with_permission<A>(action: GuardedAction<A>) {
///     // We know permission was checked because GuardedAction
///     // can only be constructed by the guard system
///     action.execute();
/// }
/// ```
#[derive(Debug)]
pub struct GuardedAction<A> {
    action: A,
    /// Private field prevents external construction
    _private: (),
}

impl<A> GuardedAction<A> {
    /// Create a new guarded action (internal only).
    ///
    /// This is `pub(crate)` to allow the permission system to create
    /// guarded actions, but external code cannot construct them.
    pub(crate) fn new(action: A) -> Self {
        Self {
            action,
            _private: (),
        }
    }

    /// Get a reference to the guarded action.
    pub fn action(&self) -> &A {
        &self.action
    }

    /// Consume the guard and return the action.
    ///
    /// This should only be called when you're ready to execute the action.
    pub fn into_action(self) -> A {
        self.action
    }

    /// Map the action to a new type (functor).
    pub fn map<B, F>(self, f: F) -> GuardedAction<B>
    where
        F: FnOnce(A) -> B,
    {
        GuardedAction::new(f(self.action))
    }

    /// Chain with another fallible guard operation (monad bind).
    ///
    /// This enables composing multiple permission checks:
    /// ```ignore
    /// guard.guard(read_path)?
    ///     .and_then(|path| guard.guard(write_path))?
    ///     .and_then(|path| guard.guard(execute))?
    /// ```
    ///
    /// The monadic structure ensures:
    /// - Each check is performed only if previous checks passed
    /// - The proof chain is preserved (cannot skip intermediate checks)
    /// - Errors propagate correctly through the chain
    pub fn and_then<B, E, F>(self, f: F) -> Result<GuardedAction<B>, GuardError<E>>
    where
        F: FnOnce(A) -> Result<GuardedAction<B>, GuardError<E>>,
    {
        f(self.action)
    }

    /// Chain with another fallible operation that returns a plain result.
    ///
    /// Useful when the next operation isn't a guard check but still needs
    /// the proof that the previous operation was guarded.
    pub fn try_map<B, E, F>(self, f: F) -> Result<GuardedAction<B>, GuardError<E>>
    where
        F: FnOnce(A) -> Result<B, E>,
        E: std::fmt::Display,
    {
        match f(self.action) {
            Ok(b) => Ok(GuardedAction::new(b)),
            Err(e) => Err(GuardError::CheckFailed { error: e }),
        }
    }
}

/// Error type for permission guard failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError<E = String> {
    /// Permission was denied
    Denied {
        /// Reason for denial
        reason: String,
    },
    /// Permission check itself failed
    CheckFailed {
        /// The underlying error
        error: E,
    },
    /// The permission has expired
    Expired,
    /// Budget exhausted
    BudgetExhausted,
    /// Action is blocked by policy
    Blocked {
        /// What blocked it
        blocker: String,
    },
}

impl<E: std::fmt::Display> std::fmt::Display for GuardError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied { reason } => write!(f, "Permission denied: {}", reason),
            Self::CheckFailed { error } => write!(f, "Permission check failed: {}", error),
            Self::Expired => write!(f, "Permission has expired"),
            Self::BudgetExhausted => write!(f, "Budget exhausted"),
            Self::Blocked { blocker } => write!(f, "Blocked by policy: {}", blocker),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for GuardError<E> {}

/// Type-safe permission enforcement trait.
///
/// Implementors of this trait provide runtime permission checks that
/// return proof values (`GuardedAction`) rather than just booleans.
///
/// This pattern ensures that callers cannot:
/// - Ignore the permission check result
/// - Construct a "passed" result without actually checking
/// - Accidentally bypass the permission system
///
/// # Example
///
/// ```ignore
/// use trifecta_guard::guard::{PermissionGuard, GuardedAction, GuardError};
///
/// struct FileReadGuard {
///     allowed_paths: Vec<PathBuf>,
/// }
///
/// impl PermissionGuard for FileReadGuard {
///     type Action = PathBuf;
///     type Error = String;
///
///     fn guard(&self, path: PathBuf) -> Result<GuardedAction<PathBuf>, GuardError<String>> {
///         if self.allowed_paths.iter().any(|p| path.starts_with(p)) {
///             Ok(GuardedAction::new(path))
///         } else {
///             Err(GuardError::Denied {
///                 reason: format!("Path {:?} not in allowed list", path),
///             })
///         }
///     }
/// }
///
/// // Using the guard
/// fn read_file(guard: &FileReadGuard, path: PathBuf) -> Result<String, GuardError<String>> {
///     let guarded = guard.guard(path)?; // Must handle error
///     let path = guarded.into_action();
///     std::fs::read_to_string(path).map_err(|e| GuardError::CheckFailed { error: e.to_string() })
/// }
/// ```
pub trait PermissionGuard {
    /// The type of action being guarded.
    type Action;

    /// The error type for permission check failures.
    type Error;

    /// Check if the action is permitted and return a proof if so.
    ///
    /// Returns `Ok(GuardedAction)` if the action is allowed,
    /// or `Err(GuardError)` if denied.
    fn guard(
        &self,
        action: Self::Action,
    ) -> Result<GuardedAction<Self::Action>, GuardError<Self::Error>>;
}

/// Type alias for guard functions to reduce complexity.
pub type GuardFn<A, E> = Box<dyn Fn(&A) -> Result<(), GuardError<E>>>;

/// A composable guard that combines multiple guards.
///
/// All guards must pass for the action to be allowed.
pub struct CompositeGuard<A, E> {
    guards: Vec<GuardFn<A, E>>,
    _phantom: PhantomData<A>,
}

impl<A, E> Default for CompositeGuard<A, E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A, E> CompositeGuard<A, E> {
    /// Create a new empty composite guard.
    pub fn new() -> Self {
        Self {
            guards: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Add a guard function to the chain.
    ///
    /// The guard will be checked in order with other guards. All guards must
    /// pass for the action to be allowed.
    pub fn with_guard<F>(mut self, guard: F) -> Self
    where
        F: Fn(&A) -> Result<(), GuardError<E>> + 'static,
    {
        self.guards.push(Box::new(guard));
        self
    }
}

impl<A, E: Clone> PermissionGuard for CompositeGuard<A, E> {
    type Action = A;
    type Error = E;

    fn guard(&self, action: A) -> Result<GuardedAction<A>, GuardError<E>> {
        for guard in &self.guards {
            guard(&action)?;
        }
        Ok(GuardedAction::new(action))
    }
}

/// A permission guard that tracks trifecta risk as a grade.
///
/// Every check returns `Graded<TrifectaRisk, Result<GuardedAction<A>, GuardError>>`,
/// so callers always see both the access decision AND the risk level of the
/// permission set that produced it.
///
/// The risk grade is computed from the underlying `PermissionLattice` via
/// `IncompatibilityConstraint::enforcing()`. This means even allowed actions
/// carry their trifecta risk — enabling downstream systems to add extra
/// oversight for operations that are technically permitted but high-risk.
pub struct GradedGuard {
    perms: PermissionLattice,
    risk: TrifectaRisk,
}

impl GradedGuard {
    /// Create a new graded guard from a permission lattice.
    ///
    /// The trifecta risk is computed once at construction and carried through
    /// all subsequent checks.
    pub fn new(perms: PermissionLattice) -> Self {
        let constraint = IncompatibilityConstraint::enforcing();
        let risk = constraint.trifecta_risk(&perms.capabilities);
        Self { perms, risk }
    }

    /// Get the trifecta risk grade of this guard's permission set.
    pub fn risk(&self) -> TrifectaRisk {
        self.risk
    }

    /// Check if an operation is allowed, returning a graded result.
    ///
    /// The grade carries the trifecta risk regardless of whether the
    /// operation is allowed or denied.
    pub fn check_operation(
        &self,
        operation: Operation,
    ) -> Graded<TrifectaRisk, Result<GuardedAction<Operation>, GuardError>> {
        let requires_approval = self.perms.requires_approval(operation);

        let result = if requires_approval && self.risk == TrifectaRisk::Complete {
            Err(GuardError::Denied {
                reason: format!(
                    "{:?} denied: trifecta risk is Complete and operation requires approval",
                    operation
                ),
            })
        } else {
            Ok(GuardedAction::new(operation))
        };

        Graded::new(self.risk, result)
    }

    /// Check if a path is accessible, returning a graded result.
    ///
    /// Uses the permission lattice's path matching against the configured
    /// allowed paths.
    pub fn check_path(
        &self,
        path: &str,
    ) -> Graded<TrifectaRisk, Result<GuardedAction<String>, GuardError>> {
        let allowed = self.perms.paths.can_access(std::path::Path::new(path));

        let result = if allowed {
            Ok(GuardedAction::new(path.to_string()))
        } else {
            Err(GuardError::Denied {
                reason: format!("Path '{}' not in allowed paths", path),
            })
        };

        Graded::new(self.risk, result)
    }

    /// Compute the Heyting permission gap needed to reach a target permission set.
    ///
    /// Returns a graded gap analysis: the grade is the risk of the *target*
    /// (what the requester wants), and the value is the Heyting implication
    /// `current → target` — the logical "what's needed" to bridge.
    pub fn permission_gap_to(
        &self,
        target: &PermissionLattice,
    ) -> Graded<TrifectaRisk, crate::CapabilityLattice> {
        let constraint = IncompatibilityConstraint::enforcing();
        let target_risk = constraint.trifecta_risk(&target.capabilities);
        let gap = permission_gap(&self.perms.capabilities, &target.capabilities);
        Graded::new(target_risk, gap)
    }

    /// Get a reference to the underlying permission lattice.
    pub fn permissions(&self) -> &PermissionLattice {
        &self.perms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TestPathGuard {
        blocked: Vec<String>,
    }

    impl PermissionGuard for TestPathGuard {
        type Action = PathBuf;
        type Error = String;

        fn guard(&self, path: PathBuf) -> Result<GuardedAction<PathBuf>, GuardError<String>> {
            let path_str = path.to_string_lossy();
            for blocked in &self.blocked {
                if path_str.contains(blocked) {
                    return Err(GuardError::Blocked {
                        blocker: blocked.clone(),
                    });
                }
            }
            Ok(GuardedAction::new(path))
        }
    }

    #[test]
    fn test_guard_allows_valid_path() {
        let guard = TestPathGuard {
            blocked: vec![".env".to_string()],
        };

        let result = guard.guard(PathBuf::from("src/main.rs"));
        assert!(result.is_ok());

        let guarded = result.unwrap();
        assert_eq!(guarded.action(), &PathBuf::from("src/main.rs"));
    }

    #[test]
    fn test_guard_blocks_sensitive_path() {
        let guard = TestPathGuard {
            blocked: vec![".env".to_string()],
        };

        let result = guard.guard(PathBuf::from(".env"));
        assert!(result.is_err());

        match result {
            Err(GuardError::Blocked { blocker }) => {
                assert_eq!(blocker, ".env");
            }
            _ => panic!("Expected Blocked error"),
        }
    }

    #[test]
    fn test_guarded_action_cannot_be_constructed_externally() {
        // This test documents that GuardedAction cannot be constructed
        // outside this module due to the private field.
        //
        // If you uncomment the following line, it will fail to compile:
        // let _action = GuardedAction { action: 42, _private: () };
    }

    #[test]
    fn test_composite_guard() {
        let guard = CompositeGuard::<i32, String>::new()
            .with_guard(|n| {
                if *n < 0 {
                    Err(GuardError::Denied {
                        reason: "negative".to_string(),
                    })
                } else {
                    Ok(())
                }
            })
            .with_guard(|n| {
                if *n > 100 {
                    Err(GuardError::Denied {
                        reason: "too large".to_string(),
                    })
                } else {
                    Ok(())
                }
            });

        // Valid value passes all guards
        assert!(guard.guard(50).is_ok());

        // Negative fails first guard
        assert!(matches!(
            guard.guard(-5),
            Err(GuardError::Denied { reason }) if reason == "negative"
        ));

        // Too large fails second guard
        assert!(matches!(
            guard.guard(150),
            Err(GuardError::Denied { reason }) if reason == "too large"
        ));
    }

    #[test]
    fn test_guarded_action_map() {
        let guard = TestPathGuard { blocked: vec![] };

        let result = guard.guard(PathBuf::from("test.txt"));
        let guarded = result.unwrap();

        // Map to string
        let string_action = guarded.map(|p| p.to_string_lossy().to_string());
        assert_eq!(string_action.into_action(), "test.txt");
    }

    #[test]
    fn test_guarded_action_and_then() {
        let guard = TestPathGuard {
            blocked: vec![".env".to_string()],
        };

        // Successful chain: read src, then read lib
        let result = guard
            .guard(PathBuf::from("src/main.rs"))
            .and_then(|_| guard.guard(PathBuf::from("lib/utils.rs")));
        assert!(result.is_ok());

        // Chain fails on second guard
        let result = guard
            .guard(PathBuf::from("src/main.rs"))
            .and_then(|_| guard.guard(PathBuf::from(".env")));
        assert!(result.is_err());

        // Chain fails on first guard (second never runs)
        let result = guard
            .guard(PathBuf::from(".env"))
            .and_then(|_| guard.guard(PathBuf::from("src/main.rs")));
        assert!(result.is_err());
    }

    #[test]
    fn test_guarded_action_try_map() {
        let guard = TestPathGuard { blocked: vec![] };

        // Successful try_map
        let result: Result<GuardedAction<String>, GuardError<String>> = guard
            .guard(PathBuf::from("test.txt"))
            .unwrap()
            .try_map(|p| Ok::<_, String>(p.to_string_lossy().to_string()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().into_action(), "test.txt");

        // Failed try_map
        let result: Result<GuardedAction<String>, GuardError<String>> = guard
            .guard(PathBuf::from("test.txt"))
            .unwrap()
            .try_map(|_| Err::<String, _>("io error".to_string()));
        assert!(matches!(result, Err(GuardError::CheckFailed { .. })));
    }

    #[test]
    fn test_graded_guard_safe_profile() {
        let perms = PermissionLattice::read_only();
        let guard = GradedGuard::new(perms);

        // read_only has only private data access (read_files: Always)
        // so risk should be Low (1 trifecta component)
        assert_eq!(guard.risk(), TrifectaRisk::Low);

        // ReadFile operation should be allowed
        let result = guard.check_operation(Operation::ReadFiles);
        assert!(result.value.is_ok());
        assert_eq!(result.grade, TrifectaRisk::Low);
    }

    #[test]
    fn test_graded_guard_permissive_denies_trifecta_exfiltration() {
        let perms = PermissionLattice::permissive();
        let guard = GradedGuard::new(perms);

        // Permissive has full trifecta
        assert_eq!(guard.risk(), TrifectaRisk::Complete);

        // Exfiltration operations that require approval should be denied
        let result = guard.check_operation(Operation::GitPush);
        assert_eq!(result.grade, TrifectaRisk::Complete);
        // GitPush requires approval under trifecta, so it should be denied
        assert!(result.value.is_err());
    }

    #[test]
    fn test_graded_guard_path_check() {
        use crate::PathLattice;
        use std::collections::HashSet;

        let perms = PermissionLattice {
            paths: PathLattice {
                allowed: HashSet::from(["**/*.rs".to_string()]),
                blocked: HashSet::from([".env*".to_string()]),
                work_dir: None,
            },
            ..Default::default()
        };
        let guard = GradedGuard::new(perms);

        // .rs files should be allowed
        let result = guard.check_path("src/lib.rs");
        assert!(result.value.is_ok());

        // .env files should be denied
        let result = guard.check_path(".env");
        assert!(result.value.is_err());
    }

    #[test]
    fn test_graded_guard_permission_gap() {
        use crate::CapabilityLevel;

        let floor = PermissionLattice::read_only();
        let mut target = PermissionLattice::read_only();
        target.capabilities.git_push = CapabilityLevel::Always;
        target.capabilities.web_fetch = CapabilityLevel::LowRisk;

        let guard = GradedGuard::new(floor);
        let gap = guard.permission_gap_to(&target);

        // Target has more trifecta components, so risk is higher
        assert!(gap.grade >= TrifectaRisk::Medium);

        // The gap should show what's needed for the capabilities
        // that the floor doesn't have
        assert_eq!(gap.value.git_push, CapabilityLevel::Always);
        assert_eq!(gap.value.web_fetch, CapabilityLevel::Always);
    }

    #[test]
    fn test_graded_guard_compose_checks() {
        let perms = PermissionLattice::read_only();
        let guard = GradedGuard::new(perms);

        // Compose two graded checks using and_then
        let result = guard
            .check_path("/workspace/src/lib.rs")
            .and_then(|first_result| {
                // Only proceed if first check passed
                match first_result {
                    Ok(_) => guard.check_operation(Operation::ReadFiles),
                    Err(e) => Graded::new(guard.risk(), Err(e)),
                }
            });

        // Risk should be composed (max of both checks)
        assert_eq!(result.grade, TrifectaRisk::Low);
        assert!(result.value.is_ok());
    }
}
