//! Exposure detector + the pure capability decision (`decide_pure`) and the
//! IFCLabel→ExposureSet quotient map (`ifc_to_exposure`). Part of the
//! Aeneas-verified surface (aeneas-decide-pure extraction roots), moved into the
//! kernel crate (MVK M3 whole-core) to keep proof extraction single-crate.
//! Re-exported at portcullis-core's root for backward compat.

use crate::{CapabilityLevel, ConfLevel, IFCLabel, IntegLevel, Operation, is_exfil_operation};

/// Exposure classification for the uninhabitable state detector.
///
/// Each operation contributes at most one exposure label. When all three
/// labels are present in a session, the uninhabitable state is reached
/// and exfiltration operations are dynamically gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ExposureLabel {
    /// Agent has accessed private/sensitive data (read_files, glob_search, grep_search)
    PrivateData = 0,
    /// Agent has accessed untrusted external content (web_fetch, web_search)
    UntrustedContent = 1,
    /// Agent has access to an exfiltration vector (run_bash, git_push, create_pr)
    ExfilVector = 2,
}

// Compile-time invariant: discriminants match declaration order for Aeneas.
const _: () = {
    assert!(ExposureLabel::PrivateData as u8 == 0);
    assert!(ExposureLabel::UntrustedContent as u8 == 1);
    assert!(ExposureLabel::ExfilVector as u8 == 2);
};

/// 3-bit exposure accumulator for uninhabitable state detection.
///
/// Tracks which exposure legs have been touched during a session.
/// Once a leg is set, it never resets (monotonicity invariant).
/// When all 3 legs are set, the uninhabitable state is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExposureSet {
    private_data: bool,
    untrusted_content: bool,
    exfil_vector: bool,
}

impl ExposureSet {
    /// Empty exposure set (no exposure legs touched).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create an exposure set from a single label.
    pub fn singleton(label: ExposureLabel) -> Self {
        let mut s = Self::empty();
        s.set(label);
        s
    }

    /// Set a specific exposure label.
    pub fn set(&mut self, label: ExposureLabel) {
        match label {
            ExposureLabel::PrivateData => self.private_data = true,
            ExposureLabel::UntrustedContent => self.untrusted_content = true,
            ExposureLabel::ExfilVector => self.exfil_vector = true,
        }
    }

    /// Check if a specific exposure label is present.
    pub fn contains(&self, label: ExposureLabel) -> bool {
        match label {
            ExposureLabel::PrivateData => self.private_data,
            ExposureLabel::UntrustedContent => self.untrusted_content,
            ExposureLabel::ExfilVector => self.exfil_vector,
        }
    }

    /// Union of two exposure sets (the monoid operation).
    pub fn union(&self, other: &Self) -> Self {
        Self {
            private_data: self.private_data || other.private_data,
            untrusted_content: self.untrusted_content || other.untrusted_content,
            exfil_vector: self.exfil_vector || other.exfil_vector,
        }
    }

    /// Check if the uninhabitable state is present (all 3 legs active).
    pub fn is_uninhabitable(&self) -> bool {
        self.private_data && self.untrusted_content && self.exfil_vector
    }

    /// Number of active exposure legs (0..=3).
    pub fn count(&self) -> u8 {
        self.private_data as u8 + self.untrusted_content as u8 + self.exfil_vector as u8
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Exposure classification functions (Aeneas-translatable)
// ═══════════════════════════════════════════════════════════════════════════

/// Classify an operation's exposure contribution.
///
/// Returns the exposure label that this operation contributes to the session's
/// accumulated exposure. Every operation contributes a leg (most-paranoid #4):
/// local sinks (WriteFiles/EditFiles/GitCommit/ManagePods) are exfiltration
/// vectors too, since a tainted secret written or committed locally is an
/// exfiltration channel.
pub fn classify_operation(op: Operation) -> Option<ExposureLabel> {
    match op {
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => {
            Some(ExposureLabel::PrivateData)
        }
        Operation::WebFetch | Operation::WebSearch => Some(ExposureLabel::UntrustedContent),
        Operation::RunBash
        | Operation::GitPush
        | Operation::CreatePr
        | Operation::SpawnAgent
        | Operation::WriteFiles
        | Operation::EditFiles
        | Operation::GitCommit
        | Operation::ManagePods => Some(ExposureLabel::ExfilVector),
    }
}

/// Project what the exposure set WOULD be if this operation is allowed.
pub fn project_exposure(current: &ExposureSet, op: Operation) -> ExposureSet {
    match classify_operation(op) {
        Some(label) => {
            let mut projected = *current;
            projected.set(label);
            projected
        }
        None => *current,
    }
}

/// Record an allowed operation's exposure contribution.
pub fn apply_record(current: &ExposureSet, op: Operation) -> ExposureSet {
    project_exposure(current, op)
}

// `is_exfil_operation` now lives in the `ifc_ops` kernel module (MVK M1b),
// re-exported at the crate root. The classifier-parity test
// `is_exfil_operation_matches_classifier` pins the moved direct-match definition
// to the `classify_operation`-based one that lived here.

/// The dynamic exposure gate: should this operation be gated?
///
/// Returns true if the operation should require approval because:
/// 1. The exposure set is already uninhabitable OR would become uninhabitable, AND
/// 2. The operation is an exfiltration vector
pub fn should_gate(current: &ExposureSet, op: Operation) -> bool {
    let projected = project_exposure(current, op);
    (current.is_uninhabitable() || projected.is_uninhabitable()) && is_exfil_operation(op)
}

/// Map an IFCLabel to the legacy ExposureSet (monotone homomorphism).
///
/// This is the quotient map φ that proves backward compatibility:
/// the existing 3-bit exposure tracker is a sound abstraction of the
/// full IFC label lattice.
pub fn ifc_to_exposure(label: &IFCLabel, op: Operation) -> ExposureSet {
    let mut s = ExposureSet::empty();
    if label.confidentiality >= ConfLevel::Internal {
        s.set(ExposureLabel::PrivateData);
    }
    if label.integrity <= IntegLevel::Untrusted {
        s.set(ExposureLabel::UntrustedContent);
    }
    if is_exfil_operation(op) {
        s.set(ExposureLabel::ExfilVector);
    }
    s
}

// ═══════════════════════════════════════════════════════════════════════════
// Pure decision logic — the Lean 4 verification target (Phase 2)
//
// This function captures the security-critical lattice-based decisions
// without runtime dependencies (no chrono, no Path, no Decimal). It is
// the kernel that will be translated to Lean via Aeneas and proved correct.
// ═══════════════════════════════════════════════════════════════════════════

/// Pure verdict from the lattice decision logic.
///
/// Does NOT include runtime checks (time, budget, path, command, isolation).
/// Those are checked in the full `Kernel::decide()` before calling this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PureVerdict {
    /// The capability lattice allows this operation.
    Allow,
    /// The capability level is Never — operation is denied.
    DenyCapability,
    /// Static approval required (capability level is LowRisk).
    RequiresApproval,
    /// Dynamic exposure gate triggered — exfil blocked by uninhabitable state.
    GateExfil,
}

/// Pure lattice-based decision logic.
///
/// Given the effective capability level for an operation and the current
/// exposure state, determine the verdict. This is the function we prove
/// correct in Lean 4.
///
/// The decision chain:
/// 1. If capability level is Never → DenyCapability
/// 2. If capability level is LowRisk → RequiresApproval
/// 3. If exposure gate triggers → GateExfil
/// 4. Otherwise → Allow
pub fn decide_pure(level: CapabilityLevel, exposure: &ExposureSet, op: Operation) -> PureVerdict {
    // Step 1: Capability level check
    if level == CapabilityLevel::Never {
        return PureVerdict::DenyCapability;
    }

    // Step 2: Static approval (LowRisk requires human approval)
    if level == CapabilityLevel::LowRisk {
        return PureVerdict::RequiresApproval;
    }

    // Step 3: Dynamic exposure gate
    if should_gate(exposure, op) {
        return PureVerdict::GateExfil;
    }

    PureVerdict::Allow
}
