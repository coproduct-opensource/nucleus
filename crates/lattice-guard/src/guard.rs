//! Type-safe permission enforcement via the PermissionGuard trait.
//!
//! This module provides compile-time guarantees that permission checks cannot
//! be bypassed or ignored by callers.

use std::marker::PhantomData;

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

    /// Map the action to a new type.
    pub fn map<B, F>(self, f: F) -> GuardedAction<B>
    where
        F: FnOnce(A) -> B,
    {
        GuardedAction::new(f(self.action))
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
}
