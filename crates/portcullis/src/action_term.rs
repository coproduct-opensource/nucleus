//! Typed action terms for proof-carrying agent actions.
//!
//! An [`ActionTerm`] is the smallest step toward a homoiconic agent model:
//! the plan, authority claim, proof obligations, and proposed effect are
//! bundled into one serializable object that can be checked before lowering
//! to the existing runtime mediation path.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{CapabilityLevel, Operation, PermissionLattice};

/// A task witness for coarse scope checking.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TaskRef {
    /// Stable task identifier for audit/replay.
    pub task_id: String,
    /// Human-readable task summary.
    pub summary: String,
    /// Operations considered in-scope for this task.
    pub allowed_operations: Vec<Operation>,
    /// Paths this task is expected to touch.
    pub allowed_paths: Vec<String>,
}

impl TaskRef {
    /// Build a new task witness.
    pub fn new(
        task_id: impl Into<String>,
        summary: impl Into<String>,
        allowed_operations: Vec<Operation>,
        allowed_paths: Vec<String>,
    ) -> Self {
        Self {
            task_id: task_id.into(),
            summary: summary.into(),
            allowed_operations,
            allowed_paths,
        }
    }
}

/// A referenced input artifact used to justify the action.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ActionInput {
    /// Human-readable input label.
    pub name: String,
    /// Stable content hash for replay and audit.
    pub source_hash: String,
    /// Coarse derivation class of the input.
    pub derivation: portcullis_core::DerivationClass,
}

impl ActionInput {
    /// Create a new input reference.
    pub fn new(
        name: impl Into<String>,
        source_hash: impl Into<String>,
        derivation: portcullis_core::DerivationClass,
    ) -> Self {
        Self {
            name: name.into(),
            source_hash: source_hash.into(),
            derivation,
        }
    }
}

/// The primitive action the runtime would lower to an existing kernel operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
pub enum PrimitiveAction {
    /// Edit a file using a unified diff.
    EditFile {
        /// Path being edited.
        path: String,
        /// Proposed unified diff.
        patch: String,
    },
    /// Run a command string via the existing `RunBash` mediation path.
    RunCommand {
        /// Command string to execute.
        command: String,
    },
}

/// Intended handling lane for the action's effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum EffectDisposition {
    /// Draft/proposed effect — reviewable and non-verified.
    Proposed,
    /// Verified effect — stricter compatibility checks apply.
    Verified,
}

/// The claimed effect of the action.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
pub enum ProposedEffect {
    /// A file patch effect.
    FilePatch {
        /// Path affected by the patch.
        path: String,
        /// Claimed output lane for the patch.
        disposition: EffectDisposition,
    },
    /// A command execution effect.
    CommandExecution {
        /// Command that would execute.
        command: String,
        /// Claimed output lane for command output.
        disposition: EffectDisposition,
    },
}

impl ProposedEffect {
    fn disposition(&self) -> EffectDisposition {
        match self {
            Self::FilePatch { disposition, .. } | Self::CommandExecution { disposition, .. } => {
                *disposition
            }
        }
    }
}

/// Authority claim attached to the term.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CapabilityRequest {
    /// Operation the term expects to exercise.
    pub operation: Operation,
    /// Capability level the term assumes is available.
    pub requested_level: CapabilityLevel,
}

impl CapabilityRequest {
    /// Create a new capability request.
    pub fn new(operation: Operation, requested_level: CapabilityLevel) -> Self {
        Self {
            operation,
            requested_level,
        }
    }
}

/// Proof obligations that must be discharged before the term may reduce.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ProofObligation {
    /// Action is in scope for the declared task.
    InScopeWithTask,
    /// Inputs are explicitly named and content-addressed.
    InputsAuthorized,
    /// Inputs have no AI-derived, mixed, or opaque ancestry.
    NoAdversarialAncestry,
    /// Requested authority stays within the session ceiling.
    WithinDelegationCeiling,
    /// Target path is allowed by the path lattice.
    PathAllowed,
    /// Verified outputs must not depend on AI-derived or opaque inputs.
    VerifiedSinkCompatible,
}

/// A typed action term: plan + authority + obligations + proposed effect.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ActionTerm {
    /// Optional task witness for coarse relevance checks.
    pub task: Option<TaskRef>,
    /// Primitive action to lower if preflight passes.
    pub action: PrimitiveAction,
    /// Input artifacts the action depends on.
    pub inputs: Vec<ActionInput>,
    /// Claimed authority for the action.
    pub authority: CapabilityRequest,
    /// Claimed effect.
    pub proposed_effect: ProposedEffect,
    /// Obligations to check before reduction.
    pub obligations: Vec<ProofObligation>,
}

impl ActionTerm {
    /// Derive the required proof obligations mechanically from the term's structure.
    ///
    /// This is the **authoritative source** of required obligations.
    /// [`preflight_action`] evaluates the *derived* set, not the caller-supplied
    /// `obligations` field, closing the self-attestation gap (#1188): a caller
    /// cannot skip `NoAdversarialAncestry` by omitting it from the field.
    ///
    /// Derivation rules:
    /// - `WithinDelegationCeiling` — always required.
    /// - `InScopeWithTask` — when a task witness is attached.
    /// - `NoAdversarialAncestry` — when any input has non-deterministic provenance
    ///   (`AIDerived`, `Mixed`, or `OpaqueExternal`).
    /// - `InputsAuthorized` — when the claimed capability exceeds `LowRisk`
    ///   (high-risk operations require explicit content-addressing of all inputs).
    /// - `PathAllowed` — when the action writes to the filesystem (`EditFile`).
    /// - `VerifiedSinkCompatible` — when the proposed effect targets a verified sink.
    pub fn derive_obligations(&self) -> Vec<ProofObligation> {
        let mut obs: Vec<ProofObligation> = Vec::new();

        // Always required: authority must not exceed the session ceiling.
        obs.push(ProofObligation::WithinDelegationCeiling);

        // Task scoping: required whenever a task witness is present.
        if self.task.is_some() {
            obs.push(ProofObligation::InScopeWithTask);
        }

        // Adversarial ancestry: required when any input has non-deterministic provenance.
        let has_tainted_input = self.inputs.iter().any(|i| {
            matches!(
                i.derivation,
                portcullis_core::DerivationClass::AIDerived
                    | portcullis_core::DerivationClass::Mixed
                    | portcullis_core::DerivationClass::OpaqueExternal
            )
        });
        if has_tainted_input {
            obs.push(ProofObligation::NoAdversarialAncestry);
        }

        // Input authorization: required when the claimed capability exceeds LowRisk.
        if self.authority.requested_level > CapabilityLevel::LowRisk {
            obs.push(ProofObligation::InputsAuthorized);
        }

        // Path access: required for any filesystem write (EditFile).
        if matches!(self.action, PrimitiveAction::EditFile { .. }) {
            obs.push(ProofObligation::PathAllowed);
        }

        // Verified sink compatibility: required when the effect targets a verified sink.
        if self.proposed_effect.disposition() == EffectDisposition::Verified {
            obs.push(ProofObligation::VerifiedSinkCompatible);
        }

        obs
    }

    /// Convenience constructor for an edit-file term.
    pub fn edit_file(
        task: Option<TaskRef>,
        path: impl Into<String>,
        patch: impl Into<String>,
        inputs: Vec<ActionInput>,
        disposition: EffectDisposition,
    ) -> Self {
        let path = path.into();
        Self {
            task,
            action: PrimitiveAction::EditFile {
                path: path.clone(),
                patch: patch.into(),
            },
            inputs,
            authority: CapabilityRequest::new(Operation::EditFiles, CapabilityLevel::LowRisk),
            proposed_effect: ProposedEffect::FilePatch { path, disposition },
            obligations: vec![
                ProofObligation::InScopeWithTask,
                ProofObligation::InputsAuthorized,
                ProofObligation::NoAdversarialAncestry,
                ProofObligation::WithinDelegationCeiling,
                ProofObligation::PathAllowed,
            ],
        }
    }

    /// Convenience constructor for a run-command term.
    pub fn run_command(
        task: Option<TaskRef>,
        command: impl Into<String>,
        inputs: Vec<ActionInput>,
        disposition: EffectDisposition,
    ) -> Self {
        let command = command.into();
        Self {
            task,
            action: PrimitiveAction::RunCommand {
                command: command.clone(),
            },
            inputs,
            authority: CapabilityRequest::new(Operation::RunBash, CapabilityLevel::LowRisk),
            proposed_effect: ProposedEffect::CommandExecution {
                command,
                disposition,
            },
            obligations: vec![
                ProofObligation::InScopeWithTask,
                ProofObligation::InputsAuthorized,
                ProofObligation::NoAdversarialAncestry,
                ProofObligation::WithinDelegationCeiling,
            ],
        }
    }

    /// The runtime operation this term lowers to.
    pub fn operation(&self) -> Operation {
        match self.action {
            PrimitiveAction::EditFile { .. } => Operation::EditFiles,
            PrimitiveAction::RunCommand { .. } => Operation::RunBash,
        }
    }

    /// Subject string used by the existing kernel API.
    pub fn subject(&self) -> &str {
        match &self.action {
            PrimitiveAction::EditFile { path, .. } => path,
            PrimitiveAction::RunCommand { command } => command,
        }
    }

    fn action_path(&self) -> Option<&str> {
        match &self.action {
            PrimitiveAction::EditFile { path, .. } => Some(path),
            PrimitiveAction::RunCommand { .. } => None,
        }
    }
}

/// Pure preflight context used to validate an [`ActionTerm`].
pub struct PreflightContext<'a> {
    /// The current effective permissions.
    pub permissions: &'a PermissionLattice,
}

impl<'a> PreflightContext<'a> {
    /// Create a new preflight context.
    pub fn new(permissions: &'a PermissionLattice) -> Self {
        Self { permissions }
    }
}

/// Preflight verdict for an action term.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum PreflightVerdict {
    /// All obligations passed.
    Pass,
    /// The term is structurally plausible but needs human intervention.
    RequiresApproval,
    /// The term is invalid under the current policy context.
    Deny,
}

/// A single failed proof obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ObligationFailure {
    /// The obligation that failed.
    pub obligation: ProofObligation,
    /// Human-readable failure detail.
    pub detail: String,
    /// Severity of the failure.
    pub verdict: PreflightVerdict,
}

/// Result of preflighting an action term.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PreflightResult {
    /// Aggregate verdict.
    pub verdict: PreflightVerdict,
    /// Obligations that were satisfied.
    pub satisfied_obligations: Vec<ProofObligation>,
    /// Obligations that failed.
    pub failures: Vec<ObligationFailure>,
}

impl PreflightResult {
    fn pass() -> Self {
        Self {
            verdict: PreflightVerdict::Pass,
            satisfied_obligations: Vec::new(),
            failures: Vec::new(),
        }
    }
}

/// Check an [`ActionTerm`] before lowering it to runtime execution.
///
/// Evaluates the *derived* obligation set (via [`ActionTerm::derive_obligations`])
/// rather than the caller-supplied `obligations` field. This closes the
/// self-attestation gap: a caller cannot skip a required obligation by omitting
/// it from the term (#1188).
///
/// In debug builds, a mismatch between derived and declared obligations is
/// reported to stderr to help callers keep their constructors aligned.
pub fn preflight_action(term: &ActionTerm, ctx: &PreflightContext<'_>) -> PreflightResult {
    let mut result = PreflightResult::pass();

    // Derive obligations from term structure — ignore caller-supplied field.
    let obligations = term.derive_obligations();

    #[cfg(debug_assertions)]
    {
        let mut declared: Vec<_> = term.obligations.iter().map(|o| format!("{o:?}")).collect();
        declared.sort();
        let mut derived: Vec<_> = obligations.iter().map(|o| format!("{o:?}")).collect();
        derived.sort();
        if declared != derived {
            eprintln!(
                "portcullis: ActionTerm obligation mismatch for {:?}\n  declared: {declared:?}\n  derived:  {derived:?}",
                term.operation(),
            );
        }
    }

    for obligation in &obligations {
        match obligation {
            ProofObligation::InScopeWithTask => {
                if let Some(task) = &term.task {
                    if !task.allowed_operations.is_empty()
                        && !task.allowed_operations.contains(&term.operation())
                    {
                        push_failure(
                            &mut result,
                            obligation.clone(),
                            format!(
                                "operation {:?} is outside task '{}' allowed ops",
                                term.operation(),
                                task.task_id
                            ),
                            PreflightVerdict::RequiresApproval,
                        );
                        continue;
                    }

                    if let Some(path) = term.action_path() {
                        if !task.allowed_paths.is_empty()
                            && !task.allowed_paths.iter().any(|allowed| {
                                path.starts_with(allowed) || crate::path::glob_match(allowed, path)
                            })
                        {
                            push_failure(
                                &mut result,
                                obligation.clone(),
                                format!(
                                    "path '{}' is outside task scope {:?}",
                                    path, task.allowed_paths
                                ),
                                PreflightVerdict::RequiresApproval,
                            );
                            continue;
                        }
                    }
                }
                result.satisfied_obligations.push(obligation.clone());
            }
            ProofObligation::InputsAuthorized => {
                if term.inputs.iter().any(|i| i.source_hash.trim().is_empty()) {
                    push_failure(
                        &mut result,
                        obligation.clone(),
                        "all inputs must be content-addressed".to_string(),
                        PreflightVerdict::Deny,
                    );
                } else {
                    result.satisfied_obligations.push(obligation.clone());
                }
            }
            ProofObligation::NoAdversarialAncestry => {
                let tainted = term.inputs.iter().find(|i| {
                    matches!(
                        i.derivation,
                        portcullis_core::DerivationClass::AIDerived
                            | portcullis_core::DerivationClass::Mixed
                            | portcullis_core::DerivationClass::OpaqueExternal
                    )
                });
                if let Some(input) = tainted {
                    push_failure(
                        &mut result,
                        obligation.clone(),
                        format!(
                            "input '{}' has {:?} derivation",
                            input.name, input.derivation
                        ),
                        PreflightVerdict::RequiresApproval,
                    );
                } else {
                    result.satisfied_obligations.push(obligation.clone());
                }
            }
            ProofObligation::WithinDelegationCeiling => {
                let available = ctx.permissions.capabilities.level_for(term.operation());
                if term.authority.operation != term.operation()
                    || term.authority.requested_level > available
                {
                    push_failure(
                        &mut result,
                        obligation.clone(),
                        format!(
                            "requested {:?}@{:?} exceeds available {:?}",
                            term.authority.operation, term.authority.requested_level, available
                        ),
                        PreflightVerdict::Deny,
                    );
                } else {
                    result.satisfied_obligations.push(obligation.clone());
                }
            }
            ProofObligation::PathAllowed => {
                if let Some(path) = term.action_path() {
                    if !ctx.permissions.paths.can_access(std::path::Path::new(path)) {
                        push_failure(
                            &mut result,
                            obligation.clone(),
                            format!("path '{}' is blocked by path lattice", path),
                            PreflightVerdict::Deny,
                        );
                    } else {
                        result.satisfied_obligations.push(obligation.clone());
                    }
                } else {
                    result.satisfied_obligations.push(obligation.clone());
                }
            }
            ProofObligation::VerifiedSinkCompatible => {
                let verified_effect =
                    term.proposed_effect.disposition() == EffectDisposition::Verified;
                let incompatible = term.inputs.iter().find(|i| {
                    !matches!(
                        i.derivation,
                        portcullis_core::DerivationClass::Deterministic
                            | portcullis_core::DerivationClass::HumanPromoted
                    )
                });
                if verified_effect {
                    if let Some(input) = incompatible {
                        push_failure(
                            &mut result,
                            obligation.clone(),
                            format!(
                                "verified effect cannot depend on {:?} input '{}'",
                                input.derivation, input.name
                            ),
                            PreflightVerdict::RequiresApproval,
                        );
                    } else {
                        result.satisfied_obligations.push(obligation.clone());
                    }
                } else {
                    result.satisfied_obligations.push(obligation.clone());
                }
            }
        }
    }

    result
}

fn push_failure(
    result: &mut PreflightResult,
    obligation: ProofObligation,
    detail: String,
    verdict: PreflightVerdict,
) {
    if verdict == PreflightVerdict::Deny {
        result.verdict = PreflightVerdict::Deny;
    } else if result.verdict == PreflightVerdict::Pass {
        result.verdict = PreflightVerdict::RequiresApproval;
    }

    result.failures.push(ObligationFailure {
        obligation,
        detail,
        verdict,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PermissionLattice;

    fn trusted_input(name: &str) -> ActionInput {
        ActionInput::new(
            name,
            "sha256:abc123",
            portcullis_core::DerivationClass::Deterministic,
        )
    }

    #[test]
    fn edit_term_constructor_sets_defaults() {
        let term = ActionTerm::edit_file(
            None,
            "src/lib.rs",
            "@@ -1 +1 @@",
            vec![trusted_input("src/lib.rs")],
            EffectDisposition::Proposed,
        );

        assert_eq!(term.operation(), Operation::EditFiles);
        assert_eq!(term.subject(), "src/lib.rs");
        assert!(term
            .obligations
            .contains(&ProofObligation::WithinDelegationCeiling));
    }

    #[test]
    fn preflight_passes_for_scoped_edit() {
        let perms = PermissionLattice::safe_pr_fixer();
        let ctx = PreflightContext::new(&perms);
        let task = TaskRef::new(
            "task-1",
            "fix auth test",
            vec![Operation::EditFiles],
            vec!["src/auth/".to_string()],
        );
        let term = ActionTerm::edit_file(
            Some(task),
            "src/auth/session.rs",
            "@@ -1 +1 @@",
            vec![trusted_input("session")],
            EffectDisposition::Proposed,
        );

        let result = preflight_action(&term, &ctx);
        assert_eq!(result.verdict, PreflightVerdict::Pass);
        assert!(result.failures.is_empty());
    }

    #[test]
    fn preflight_requires_approval_for_out_of_scope_path() {
        let perms = PermissionLattice::safe_pr_fixer();
        let ctx = PreflightContext::new(&perms);
        let task = TaskRef::new(
            "task-1",
            "docs edit",
            vec![Operation::EditFiles],
            vec!["docs/".to_string()],
        );
        let term = ActionTerm::edit_file(
            Some(task),
            "src/main.rs",
            "@@ -1 +1 @@",
            vec![trusted_input("main")],
            EffectDisposition::Proposed,
        );

        let result = preflight_action(&term, &ctx);
        assert_eq!(result.verdict, PreflightVerdict::RequiresApproval);
        assert_eq!(result.failures.len(), 1);
        assert_eq!(
            result.failures[0].obligation,
            ProofObligation::InScopeWithTask
        );
    }

    #[test]
    fn preflight_denies_when_authority_exceeds_ceiling() {
        let perms = PermissionLattice::read_only();
        let ctx = PreflightContext::new(&perms);
        let mut term = ActionTerm::run_command(
            None,
            "cargo test",
            vec![trusted_input("test")],
            EffectDisposition::Proposed,
        );
        term.authority.requested_level = CapabilityLevel::Always;

        let result = preflight_action(&term, &ctx);
        assert_eq!(result.verdict, PreflightVerdict::Deny);
        assert!(result
            .failures
            .iter()
            .any(|f| f.obligation == ProofObligation::WithinDelegationCeiling));
    }

    #[test]
    fn verified_effect_requires_clean_derivation() {
        let perms = PermissionLattice::safe_pr_fixer();
        let ctx = PreflightContext::new(&perms);
        // Note: VerifiedSinkCompatible is now auto-derived — no manual push needed (#1188).
        let term = ActionTerm::edit_file(
            None,
            "src/lib.rs",
            "@@ -1 +1 @@",
            vec![ActionInput::new(
                "web-note",
                "sha256:def456",
                portcullis_core::DerivationClass::AIDerived,
            )],
            EffectDisposition::Verified,
        );

        let result = preflight_action(&term, &ctx);
        assert_eq!(result.verdict, PreflightVerdict::RequiresApproval);
        assert!(result
            .failures
            .iter()
            .any(|f| f.obligation == ProofObligation::VerifiedSinkCompatible));
    }

    // ── Self-attestation gap closed (#1188) ──────────────────────────────────

    #[test]
    fn adversarial_input_triggers_obligation_even_without_explicit_declaration() {
        // The self-attestation gap: caller omits NoAdversarialAncestry from
        // obligations field. Before #1188, preflight would skip the check.
        // After #1188, derive_obligations adds it mechanically.
        let perms = PermissionLattice::safe_pr_fixer();
        let ctx = PreflightContext::new(&perms);
        let mut term = ActionTerm::edit_file(
            None,
            "src/lib.rs",
            "@@ -1 +1 @@",
            vec![ActionInput::new(
                "web-scrape",
                "sha256:feed1234",
                portcullis_core::DerivationClass::OpaqueExternal,
            )],
            EffectDisposition::Proposed,
        );
        // Attacker strips the obligation they don't want checked.
        term.obligations
            .retain(|o| o != &ProofObligation::NoAdversarialAncestry);

        let result = preflight_action(&term, &ctx);
        // Must still be denied/approved — derivation catches the tainted input.
        assert_ne!(
            result.verdict,
            PreflightVerdict::Pass,
            "tainted input must not pass even when NoAdversarialAncestry omitted from field"
        );
        assert!(
            result
                .failures
                .iter()
                .any(|f| f.obligation == ProofObligation::NoAdversarialAncestry),
            "NoAdversarialAncestry failure must be present in result"
        );
    }

    #[test]
    fn derive_obligations_always_includes_delegation_ceiling() {
        let term = ActionTerm::run_command(None, "echo hi", vec![], EffectDisposition::Proposed);
        assert!(term
            .derive_obligations()
            .contains(&ProofObligation::WithinDelegationCeiling));
    }

    #[test]
    fn derive_obligations_includes_scope_check_when_task_present() {
        let task = TaskRef::new("t1", "test task", vec![], vec![]);
        let term = ActionTerm::run_command(Some(task), "ls", vec![], EffectDisposition::Proposed);
        assert!(term
            .derive_obligations()
            .contains(&ProofObligation::InScopeWithTask));
    }

    #[test]
    fn derive_obligations_no_scope_check_without_task() {
        let term = ActionTerm::run_command(None, "ls", vec![], EffectDisposition::Proposed);
        assert!(!term
            .derive_obligations()
            .contains(&ProofObligation::InScopeWithTask));
    }

    #[test]
    fn derive_obligations_path_allowed_for_edit_not_run() {
        let edit = ActionTerm::edit_file(
            None,
            "src/x.rs",
            "@@ @@",
            vec![],
            EffectDisposition::Proposed,
        );
        assert!(edit
            .derive_obligations()
            .contains(&ProofObligation::PathAllowed));

        let run = ActionTerm::run_command(None, "ls", vec![], EffectDisposition::Proposed);
        assert!(!run
            .derive_obligations()
            .contains(&ProofObligation::PathAllowed));
    }

    #[test]
    fn derive_obligations_verified_sink_only_for_verified_disposition() {
        let proposed =
            ActionTerm::edit_file(None, "f.rs", "@@ @@", vec![], EffectDisposition::Proposed);
        assert!(!proposed
            .derive_obligations()
            .contains(&ProofObligation::VerifiedSinkCompatible));

        let verified =
            ActionTerm::edit_file(None, "f.rs", "@@ @@", vec![], EffectDisposition::Verified);
        assert!(verified
            .derive_obligations()
            .contains(&ProofObligation::VerifiedSinkCompatible));
    }

    #[test]
    fn derive_obligations_inputs_authorized_only_above_lowrisk() {
        // LowRisk authority → no InputsAuthorized required.
        let low = ActionTerm::edit_file(None, "f.rs", "@@ @@", vec![], EffectDisposition::Proposed);
        assert!(!low
            .derive_obligations()
            .contains(&ProofObligation::InputsAuthorized));

        // Always authority → InputsAuthorized required.
        let mut high = low.clone();
        high.authority.requested_level = CapabilityLevel::Always;
        assert!(high
            .derive_obligations()
            .contains(&ProofObligation::InputsAuthorized));
    }
}
