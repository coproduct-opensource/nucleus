//! ActionTerm construction from legacy `(Operation, subject)` pairs (#1187).

use portcullis::action_term::{
    ActionTerm, CapabilityRequest, EffectDisposition, PrimitiveAction, ProposedEffect,
};
use portcullis::{CapabilityLevel, Operation};

/// Build an [`ActionTerm`] from an `(Operation, subject)` pair.
///
/// Shared helper for converting the legacy `(Operation, &str)` call pattern
/// to the term-first pipeline.
pub fn build_action_term(operation: Operation, subject: &str) -> ActionTerm {
    let action = match operation {
        Operation::ReadFiles => PrimitiveAction::ReadFile {
            path: subject.to_string(),
        },
        Operation::WriteFiles => PrimitiveAction::WriteFile {
            path: subject.to_string(),
        },
        Operation::EditFiles => PrimitiveAction::EditFile {
            path: subject.to_string(),
            patch: String::new(),
        },
        Operation::RunBash => PrimitiveAction::RunCommand {
            command: subject.to_string(),
        },
        Operation::GlobSearch | Operation::GrepSearch => PrimitiveAction::GlobSearch {
            pattern: subject.to_string(),
        },
        Operation::WebSearch => PrimitiveAction::WebSearch {
            query: subject.to_string(),
        },
        Operation::WebFetch => PrimitiveAction::WebFetch {
            url: subject.to_string(),
        },
        Operation::GitCommit => PrimitiveAction::GitCommit {
            message: subject.to_string(),
        },
        Operation::GitPush => PrimitiveAction::GitPush {
            remote: subject.to_string(),
            branch: String::new(),
        },
        Operation::CreatePr => PrimitiveAction::CreatePr {
            title: subject.to_string(),
        },
        Operation::ManagePods | Operation::SpawnAgent => PrimitiveAction::SpawnAgent {
            endpoint: subject.to_string(),
            payload_bytes: 0,
        },
    };

    ActionTerm {
        task: None,
        action,
        inputs: vec![],
        authority: CapabilityRequest::new(operation, CapabilityLevel::LowRisk),
        proposed_effect: ProposedEffect::CommandExecution {
            command: subject.to_string(),
            disposition: EffectDisposition::Proposed,
        },
        obligations: vec![], // derive_obligations() is authoritative
    }
}
