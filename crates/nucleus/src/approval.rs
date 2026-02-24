//! Approval types for approval-gated operations.

use std::sync::Arc;

use crate::error::{NucleusError, Result};

/// A request for human approval for a specific operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    operation: String,
}

impl ApprovalRequest {
    /// Create a new approval request for the given operation string.
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
        }
    }

    /// Get the operation string for this request.
    pub fn operation(&self) -> &str {
        &self.operation
    }
}

/// A non-forgeable approval token scoped to a specific operation.
///
/// This token can only be constructed by this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalToken {
    operation: String,
    _private: (),
}

impl ApprovalToken {
    pub(crate) fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            _private: (),
        }
    }

    /// Check whether this token matches the given operation.
    pub fn matches(&self, operation: &str) -> bool {
        self.operation == operation
    }
}

/// Trait for approval providers.
pub trait Approver: Send + Sync {
    /// Approve or deny an operation and return a scoped token if approved.
    fn approve(&self, request: &ApprovalRequest) -> Result<ApprovalToken>;
}

/// Simple callback-based approver.
#[derive(Clone)]
pub struct CallbackApprover {
    callback: Arc<dyn Fn(&ApprovalRequest) -> bool + Send + Sync>,
}

impl CallbackApprover {
    /// Create a callback approver from a predicate.
    pub fn new<F>(callback: F) -> Self
    where
        F: Fn(&ApprovalRequest) -> bool + Send + Sync + 'static,
    {
        Self {
            callback: Arc::new(callback),
        }
    }
}

impl Approver for CallbackApprover {
    fn approve(&self, request: &ApprovalRequest) -> Result<ApprovalToken> {
        if (self.callback)(request) {
            Ok(ApprovalToken::new(request.operation()))
        } else {
            Err(NucleusError::ApprovalRequired {
                operation: request.operation().to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approval_request_new() {
        let req = ApprovalRequest::new("git push origin main");
        assert_eq!(req.operation(), "git push origin main");
    }

    #[test]
    fn test_approval_request_equality() {
        let req1 = ApprovalRequest::new("deploy-prod");
        let req2 = ApprovalRequest::new("deploy-prod");
        let req3 = ApprovalRequest::new("deploy-staging");
        assert_eq!(req1, req2);
        assert_ne!(req1, req3);
    }

    #[test]
    fn test_approval_token_matches() {
        let token = ApprovalToken::new("git push origin main");
        assert!(token.matches("git push origin main"));
        assert!(!token.matches("git commit -m msg"));
        assert!(!token.matches(""));
    }

    #[test]
    fn test_approval_token_exact_match_required() {
        let token = ApprovalToken::new("git push");
        // Partial matches should not pass
        assert!(!token.matches("git push origin main"));
        assert!(!token.matches("git"));
    }

    #[test]
    fn test_callback_approver_always_approves() {
        let approver = CallbackApprover::new(|_req| true);
        let request = ApprovalRequest::new("some-operation");
        let result = approver.approve(&request);
        assert!(result.is_ok());
        let token = result.unwrap();
        assert!(token.matches("some-operation"));
    }

    #[test]
    fn test_callback_approver_always_denies() {
        let approver = CallbackApprover::new(|_req| false);
        let request = ApprovalRequest::new("some-operation");
        let result = approver.approve(&request);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NucleusError::ApprovalRequired { .. }
        ));
    }

    #[test]
    fn test_callback_approver_conditional() {
        let approver = CallbackApprover::new(|req| req.operation().starts_with("safe-"));
        let safe_request = ApprovalRequest::new("safe-read");
        let risky_request = ApprovalRequest::new("rm -rf /");

        assert!(approver.approve(&safe_request).is_ok());
        assert!(approver.approve(&risky_request).is_err());
    }

    #[test]
    fn test_callback_approver_token_is_scoped() {
        let approver = CallbackApprover::new(|_| true);
        let request = ApprovalRequest::new("operation-a");
        let token = approver.approve(&request).unwrap();

        // Token is scoped to the approved operation
        assert!(token.matches("operation-a"));
        assert!(!token.matches("operation-b"));
    }

    #[test]
    fn test_approval_token_clone() {
        let token = ApprovalToken::new("my-op");
        let token_clone = token.clone();
        assert!(token_clone.matches("my-op"));
    }

    #[test]
    fn test_approval_request_clone() {
        let req = ApprovalRequest::new("my-op");
        let req_clone = req.clone();
        assert_eq!(req_clone.operation(), "my-op");
    }

    #[test]
    fn test_approval_token_debug() {
        let token = ApprovalToken::new("debug-test");
        let debug_str = format!("{:?}", token);
        assert!(debug_str.contains("debug-test"));
    }

    #[test]
    fn test_approval_request_debug() {
        let req = ApprovalRequest::new("debug-req");
        let debug_str = format!("{:?}", req);
        assert!(debug_str.contains("debug-req"));
    }
}
