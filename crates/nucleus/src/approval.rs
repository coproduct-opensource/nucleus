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
