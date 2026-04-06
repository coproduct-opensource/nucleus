//! ActionTerm construction — delegates to the canonical `ActionTerm::from_operation`.

pub use portcullis::action_term::ActionTerm;
use portcullis::Operation;

/// Build an ActionTerm from an (Operation, subject) pair.
///
/// Thin wrapper around [`ActionTerm::from_operation`] (#1292).
pub fn build_action_term(operation: Operation, subject: &str) -> ActionTerm {
    ActionTerm::from_operation(operation, subject)
}
