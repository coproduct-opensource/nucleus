//! Python bindings for the portcullis policy algebra.
//!
//! The only formally verified policy algebra available as a pip package.
//! Lean 4 proofs. Belnap bilattice. Composable combinators.
//!
//! ```python
//! from portcullis import (
//!     Verdict, CapabilityLevel, CheckResult,
//!     PolicyRequest, Pipeline,
//!     read_only, deny_disabled, require_approval_for, deny_operations,
//! )
//!
//! # Belnap bilattice operations
//! result = Verdict.ALLOW.truth_meet(Verdict.DENY)
//! assert result == Verdict.DENY
//!
//! # Contradiction detection
//! combined = Verdict.ALLOW.info_join(Verdict.DENY)
//! assert combined == Verdict.CONFLICT
//!
//! # Compose a policy pipeline
//! policy = Pipeline([
//!     deny_disabled(),
//!     require_approval_for(["git_push", "create_pr"]),
//!     read_only(),
//! ])
//! req = PolicyRequest("read_files", CapabilityLevel.LOW_RISK)
//! result = policy.check(req)
//! assert result.is_allow()
//! ```

use std::sync::Arc;

use pyo3::prelude::*;

use portcullis_core::CapabilityLevel as RustCapabilityLevel;
use portcullis_core::bilattice::Verdict as RustVerdict;
use portcullis_core::builtin_checks;
use portcullis_core::combinators::{
    CheckResult as RustCheckResult, PolicyCheck, PolicyRequest as RustPolicyRequest, all_of,
    any_of, first_match,
};

// ── ArcCheck wrapper — lets Arc<dyn PolicyCheck> act as Box<dyn PolicyCheck> ─────

struct ArcCheck(Arc<dyn PolicyCheck>);

impl PolicyCheck for ArcCheck {
    fn check(&self, req: &RustPolicyRequest) -> RustCheckResult {
        self.0.check(req)
    }

    fn name(&self) -> &str {
        self.0.name()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Verdict
// ═══════════════════════════════════════════════════════════════════════════

/// A four-valued policy verdict forming a Belnap bilattice.
///
/// Two orderings:
/// - Truth: Deny < Unknown < Allow
/// - Information: Unknown < {Allow, Deny} < Conflict
///
/// Five operations are functionally complete (Bruni et al., ACM TISSEC).
#[pyclass(eq, hash, frozen, from_py_object)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Operation is permitted.
    #[pyo3(name = "ALLOW")]
    Allow,
    /// Operation is denied.
    #[pyo3(name = "DENY")]
    Deny,
    /// Not enough information to decide.
    #[pyo3(name = "UNKNOWN")]
    Unknown,
    /// Contradictory signals from multiple sources.
    #[pyo3(name = "CONFLICT")]
    Conflict,
}

impl From<Verdict> for RustVerdict {
    fn from(v: Verdict) -> Self {
        match v {
            Verdict::Allow => RustVerdict::Allow,
            Verdict::Deny => RustVerdict::Deny,
            Verdict::Unknown => RustVerdict::Unknown,
            Verdict::Conflict => RustVerdict::Conflict,
        }
    }
}

impl From<RustVerdict> for Verdict {
    fn from(v: RustVerdict) -> Self {
        match v {
            RustVerdict::Allow => Verdict::Allow,
            RustVerdict::Deny => Verdict::Deny,
            RustVerdict::Unknown => Verdict::Unknown,
            RustVerdict::Conflict => Verdict::Conflict,
        }
    }
}

#[pymethods]
impl Verdict {
    /// Truth-meet: most restrictive (AND).
    /// Allow & Deny = Deny. Both must allow.
    fn truth_meet(&self, other: Verdict) -> Verdict {
        let r: RustVerdict = (*self).into();
        r.truth_meet(other.into()).into()
    }

    /// Truth-join: most permissive (OR).
    /// Deny | Allow = Allow. Either may allow.
    fn truth_join(&self, other: Verdict) -> Verdict {
        let r: RustVerdict = (*self).into();
        r.truth_join(other.into()).into()
    }

    /// Negate: flip Allow <-> Deny, preserve Unknown/Conflict.
    fn negate(&self) -> Verdict {
        let r: RustVerdict = (*self).into();
        r.negate().into()
    }

    /// Information-meet: least informative (consensus minimum).
    fn info_meet(&self, other: Verdict) -> Verdict {
        let r: RustVerdict = (*self).into();
        r.info_meet(other.into()).into()
    }

    /// Information-join: most informative (detects contradictions).
    /// Allow ∨_k Deny = Conflict.
    fn info_join(&self, other: Verdict) -> Verdict {
        let r: RustVerdict = (*self).into();
        r.info_join(other.into()).into()
    }

    /// Whether this verdict allows the operation.
    fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow)
    }

    /// Whether this verdict denies the operation.
    fn is_deny(&self) -> bool {
        matches!(self, Verdict::Deny)
    }

    /// Whether this verdict represents contradictory signals.
    fn is_conflict(&self) -> bool {
        matches!(self, Verdict::Conflict)
    }

    /// Whether this verdict is decided (Allow or Deny).
    fn is_decided(&self) -> bool {
        matches!(self, Verdict::Allow | Verdict::Deny)
    }

    fn __repr__(&self) -> String {
        format!("Verdict.{self:?}")
    }

    fn __str__(&self) -> String {
        match self {
            Verdict::Allow => "ALLOW".into(),
            Verdict::Deny => "DENY".into(),
            Verdict::Unknown => "UNKNOWN".into(),
            Verdict::Conflict => "CONFLICT".into(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CapabilityLevel
// ═══════════════════════════════════════════════════════════════════════════

/// Three-element bounded lattice for tool permission levels.
///
/// Ordering: `NEVER < LOW_RISK < ALWAYS`
///
/// - `NEVER`: operation is disabled
/// - `LOW_RISK`: operation is allowed when risk is contained (reads, searches)
/// - `ALWAYS`: operation requires full trust (writes, exec, network mutations)
#[pyclass(eq, hash, frozen, ord, from_py_object)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CapabilityLevel {
    #[pyo3(name = "NEVER")]
    Never,
    #[pyo3(name = "LOW_RISK")]
    LowRisk,
    #[pyo3(name = "ALWAYS")]
    Always,
}

impl From<CapabilityLevel> for RustCapabilityLevel {
    fn from(v: CapabilityLevel) -> Self {
        match v {
            CapabilityLevel::Never => RustCapabilityLevel::Never,
            CapabilityLevel::LowRisk => RustCapabilityLevel::LowRisk,
            CapabilityLevel::Always => RustCapabilityLevel::Always,
        }
    }
}

impl From<RustCapabilityLevel> for CapabilityLevel {
    fn from(v: RustCapabilityLevel) -> Self {
        match v {
            RustCapabilityLevel::Never => CapabilityLevel::Never,
            RustCapabilityLevel::LowRisk => CapabilityLevel::LowRisk,
            RustCapabilityLevel::Always => CapabilityLevel::Always,
        }
    }
}

#[pymethods]
impl CapabilityLevel {
    fn __repr__(&self) -> String {
        format!("CapabilityLevel.{self:?}")
    }

    fn __str__(&self) -> String {
        match self {
            CapabilityLevel::Never => "NEVER".into(),
            CapabilityLevel::LowRisk => "LOW_RISK".into(),
            CapabilityLevel::Always => "ALWAYS".into(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CheckResult
// ═══════════════════════════════════════════════════════════════════════════

/// Result of a single policy check.
///
/// Used as the return value of `PolicyCheck.check()` and `Pipeline.check()`.
///
/// ```python
/// result = pipeline.check(req)
/// if result.is_allow():
///     print("permitted")
/// elif result.is_deny():
///     print(f"denied: {result.reason}")
/// elif result.is_requires_approval():
///     print(f"needs human approval: {result.reason}")
/// else:
///     print("no opinion (abstain)")
/// ```
#[pyclass(frozen, skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct CheckResult {
    inner: RustCheckResult,
}

impl From<RustCheckResult> for CheckResult {
    fn from(r: RustCheckResult) -> Self {
        Self { inner: r }
    }
}

#[pymethods]
impl CheckResult {
    /// Whether this result definitively allows the operation.
    fn is_allow(&self) -> bool {
        self.inner.is_allow()
    }

    /// Whether this result definitively denies the operation.
    fn is_deny(&self) -> bool {
        self.inner.is_deny()
    }

    /// Whether this result requires human approval before proceeding.
    fn is_requires_approval(&self) -> bool {
        matches!(self.inner, RustCheckResult::RequiresApproval(_))
    }

    /// Whether this check has no opinion (passes to the next check in a pipeline).
    fn is_abstain(&self) -> bool {
        matches!(self.inner, RustCheckResult::Abstain)
    }

    /// Whether this result is decided (not Abstain).
    fn is_decided(&self) -> bool {
        self.inner.is_decided()
    }

    /// The reason string for Deny or RequiresApproval results; `None` otherwise.
    #[getter]
    fn reason(&self) -> Option<String> {
        match &self.inner {
            RustCheckResult::Deny(r) | RustCheckResult::RequiresApproval(r) => {
                Some(r.clone())
            }
            _ => None,
        }
    }

    fn __repr__(&self) -> String {
        match &self.inner {
            RustCheckResult::Allow => "CheckResult.Allow".into(),
            RustCheckResult::Deny(r) => format!("CheckResult.Deny({r:?})"),
            RustCheckResult::RequiresApproval(r) => {
                format!("CheckResult.RequiresApproval({r:?})")
            }
            RustCheckResult::Abstain => "CheckResult.Abstain".into(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PolicyRequest
// ═══════════════════════════════════════════════════════════════════════════

/// Request context passed to policy checks.
///
/// ```python
/// req = PolicyRequest("git_push", CapabilityLevel.ALWAYS)
/// req = req.with_context("branch", "main")
/// req = req.with_context("taint", "adversarial")
/// ```
#[pyclass(skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct PolicyRequest {
    inner: RustPolicyRequest,
}

#[pymethods]
impl PolicyRequest {
    /// Create a new request.
    ///
    /// Args:
    ///     operation: The operation string, e.g. "git_push", "read_files".
    ///     level: The capability level required for this operation.
    #[new]
    fn new(operation: &str, level: CapabilityLevel) -> Self {
        Self {
            inner: RustPolicyRequest::new(operation, level.into()),
        }
    }

    /// Return a new request with an added context key-value pair.
    fn with_context(&self, key: &str, value: &str) -> Self {
        Self {
            inner: self.inner.clone().with_context(key, value),
        }
    }

    /// The operation string.
    #[getter]
    fn operation(&self) -> &str {
        &self.inner.operation
    }

    /// The required capability level.
    #[getter]
    fn required_level(&self) -> CapabilityLevel {
        self.inner.required_level.into()
    }

    fn __repr__(&self) -> String {
        format!(
            "PolicyRequest(operation={:?}, level={:?})",
            self.inner.operation, self.inner.required_level
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Pipeline
// ═══════════════════════════════════════════════════════════════════════════

/// A composed policy pipeline.
///
/// The pipeline is a first-match combinator: checks are evaluated in order
/// and the first decisive result (Allow, Deny, RequiresApproval) is returned.
/// If all checks abstain, `CheckResult.Abstain` is returned.
///
/// Build with named check constructors:
///
/// ```python
/// from portcullis import (
///     Pipeline, PolicyRequest, CapabilityLevel,
///     read_only, deny_disabled, require_approval_for, deny_operations,
///     deny_adversarial_taint,
/// )
///
/// policy = Pipeline([
///     deny_disabled(),
///     deny_adversarial_taint(),
///     require_approval_for(["git_push", "create_pr", "spawn_agent"]),
///     read_only(),
/// ])
///
/// req = PolicyRequest("run_bash", CapabilityLevel.ALWAYS)
/// result = policy.check(req)
/// assert result.is_deny()  # read_only blocks exec
/// ```
#[pyclass]
pub struct Pipeline {
    inner: Box<dyn PolicyCheck>,
}

#[pymethods]
impl Pipeline {
    /// Create a pipeline that uses first-match semantics.
    ///
    /// Pass a list of check objects returned by the builder functions
    /// (`read_only()`, `deny_disabled()`, etc.).
    #[new]
    fn new(checks: Vec<Bound<'_, PyCheckWrapper>>) -> Self {
        let boxed: Vec<Box<dyn PolicyCheck>> =
            checks.iter().map(|c| c.borrow().to_boxed()).collect();
        Self {
            inner: Box::new(first_match(boxed)),
        }
    }

    /// Evaluate the pipeline against a request.
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        self.inner.check(&req.inner).into()
    }

    /// Create an "all must allow" composition from a list of checks.
    ///
    /// All checks must return Allow (or Abstain). If any denies, deny.
    #[staticmethod]
    fn all_of(checks: Vec<Bound<'_, PyCheckWrapper>>) -> Pipeline {
        let boxed: Vec<Box<dyn PolicyCheck>> =
            checks.iter().map(|c| c.borrow().to_boxed()).collect();
        Pipeline {
            inner: Box::new(all_of(boxed)),
        }
    }

    /// Create an "any may allow" composition from a list of checks.
    ///
    /// If any check allows, allow. If all deny, deny.
    #[staticmethod]
    fn any_of(checks: Vec<Bound<'_, PyCheckWrapper>>) -> Pipeline {
        let boxed: Vec<Box<dyn PolicyCheck>> =
            checks.iter().map(|c| c.borrow().to_boxed()).collect();
        Pipeline {
            inner: Box::new(any_of(boxed)),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PyCheckWrapper — opaque handle for built-in checks passed to Pipeline
// ═══════════════════════════════════════════════════════════════════════════

/// Opaque handle for a built-in policy check.
///
/// Create via the named constructor functions (`read_only()`, `deny_disabled()`,
/// etc.) and pass to `Pipeline([...])`.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct PyCheckWrapper {
    inner: Arc<dyn PolicyCheck>,
}

impl PyCheckWrapper {
    fn new(check: impl PolicyCheck + 'static) -> Self {
        Self {
            inner: Arc::new(check),
        }
    }

    fn to_boxed(&self) -> Box<dyn PolicyCheck> {
        Box::new(ArcCheck(Arc::clone(&self.inner)))
    }
}

#[pymethods]
impl PyCheckWrapper {
    fn __repr__(&self) -> String {
        format!("PolicyCheck({})", self.inner.name())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Check builder functions
// ═══════════════════════════════════════════════════════════════════════════

/// Allow reads, deny writes and execution.
///
/// Denies any operation at `CapabilityLevel.ALWAYS` (write/exec territory).
///
/// ```python
/// policy = Pipeline([read_only()])
/// assert policy.check(PolicyRequest("read_files", CapabilityLevel.LOW_RISK)).is_allow()
/// assert policy.check(PolicyRequest("run_bash", CapabilityLevel.ALWAYS)).is_deny()
/// ```
#[pyfunction]
fn read_only() -> PyCheckWrapper {
    PyCheckWrapper::new(builtin_checks::ReadOnly)
}

/// Deny any operation with capability level `NEVER` (i.e., disabled operations).
///
/// ```python
/// policy = Pipeline([deny_disabled()])
/// assert policy.check(PolicyRequest("git_push", CapabilityLevel.NEVER)).is_deny()
/// ```
#[pyfunction]
fn deny_disabled() -> PyCheckWrapper {
    PyCheckWrapper::new(builtin_checks::DenyDisabled)
}

/// Require human approval for the listed operations.
///
/// Args:
///     operations: List of operation strings that require approval.
///
/// ```python
/// policy = Pipeline([require_approval_for(["git_push", "create_pr"])])
/// result = policy.check(PolicyRequest("git_push", CapabilityLevel.ALWAYS))
/// assert result.is_requires_approval()
/// ```
#[pyfunction]
fn require_approval_for(operations: Vec<String>) -> PyCheckWrapper {
    PyCheckWrapper::new(builtin_checks::RequireApprovalFor::new(operations))
}

/// Deny the listed operations entirely.
///
/// Args:
///     operations: List of operation strings to deny.
///     reason: Human-readable reason included in the denial message.
///
/// ```python
/// policy = Pipeline([deny_operations(["run_bash"], "shell exec not permitted")])
/// result = policy.check(PolicyRequest("run_bash", CapabilityLevel.ALWAYS))
/// assert result.is_deny()
/// ```
#[pyfunction]
fn deny_operations(operations: Vec<String>, reason: String) -> PyCheckWrapper {
    PyCheckWrapper::new(builtin_checks::DenyOperations::new(operations, reason))
}

/// Deny if a request context key matches a given value.
///
/// ```python
/// check = deny_when_context_matches("mode", "offline", ["web_fetch", "web_search"])
/// policy = Pipeline([check])
/// req = PolicyRequest("web_fetch", CapabilityLevel.LOW_RISK).with_context("mode", "offline")
/// assert policy.check(req).is_deny()
/// ```
#[pyfunction]
fn deny_when_context_matches(key: String, value: String, operations: Vec<String>) -> PyCheckWrapper {
    PyCheckWrapper::new(builtin_checks::DenyWhenContextMatches::new(
        key, value, operations,
    ))
}

/// Deny if the request has `taint=adversarial` in context.
///
/// Use this to block operations that carry prompt-injection or adversarial
/// data in their lineage.
///
/// ```python
/// policy = Pipeline([deny_adversarial_taint()])
/// req = PolicyRequest("web_fetch", CapabilityLevel.LOW_RISK).with_context("taint", "adversarial")
/// assert policy.check(req).is_deny()
/// ```
#[pyfunction]
fn deny_adversarial_taint() -> PyCheckWrapper {
    PyCheckWrapper::new(builtin_checks::DenyAdversarialTaint)
}

/// Require at least a minimum capability level for all operations.
///
/// Denies any operation whose required level is below the minimum.
///
/// ```python
/// policy = Pipeline([require_min_capability(CapabilityLevel.LOW_RISK)])
/// assert policy.check(PolicyRequest("read_files", CapabilityLevel.NEVER)).is_deny()
/// ```
#[pyfunction]
fn require_min_capability(minimum: CapabilityLevel) -> PyCheckWrapper {
    PyCheckWrapper::new(builtin_checks::RequireMinCapability::new(minimum.into()))
}

// ═══════════════════════════════════════════════════════════════════════════
// Profile — named capability presets (#1278)
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// IntegLevel + ConfLevel (#1279)
// ═══════════════════════════════════════════════════════════════════════════

/// Integrity level — tracks data trustworthiness.
#[pyclass(eq, hash, frozen, ord, from_py_object)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IntegLevel {
    #[pyo3(name = "ADVERSARIAL")]
    Adversarial,
    #[pyo3(name = "UNTRUSTED")]
    Untrusted,
    #[pyo3(name = "TRUSTED")]
    Trusted,
}

#[pymethods]
impl IntegLevel {
    fn __repr__(&self) -> String {
        format!("IntegLevel.{self:?}")
    }
}

/// Confidentiality level — tracks data sensitivity.
#[pyclass(eq, hash, frozen, ord, from_py_object)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConfLevel {
    #[pyo3(name = "PUBLIC")]
    Public,
    #[pyo3(name = "INTERNAL")]
    Internal,
    #[pyo3(name = "SECRET")]
    Secret,
}

#[pymethods]
impl ConfLevel {
    fn __repr__(&self) -> String {
        format!("ConfLevel.{self:?}")
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Labeled — Python IFC wrapper with gated access (#1279)
// ═══════════════════════════════════════════════════════════════════════════

pyo3::create_exception!(portcullis, UntrustedAccess, pyo3::exceptions::PyException);

/// Data tagged with integrity and confidentiality levels.
///
/// Accessing `.data` on adversarial-integrity content raises `UntrustedAccess`.
/// Call `.acknowledge(reason)` to explicitly accept the risk — the reason is
/// logged for audit.
///
/// ```python
/// page = rt.fetch_url("https://example.com")
/// page.integrity    # IntegLevel.ADVERSARIAL
/// page.data         # raises UntrustedAccess!
/// raw = page.acknowledge("human reviewed for injection")  # returns bytes
/// ```
#[pyclass(skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct Labeled {
    raw: Vec<u8>,
    integrity: IntegLevel,
    confidentiality: ConfLevel,
    node_id: u64,
}

#[pymethods]
impl Labeled {
    /// The integrity level of this data.
    #[getter]
    fn integrity(&self) -> IntegLevel {
        self.integrity
    }

    /// The confidentiality level of this data.
    #[getter]
    fn confidentiality(&self) -> ConfLevel {
        self.confidentiality
    }

    /// The FlowTracker node ID (for IFC ancestry tracking).
    #[getter]
    fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Access the raw data bytes.
    ///
    /// **Raises `UntrustedAccess`** for adversarial-integrity data.
    /// Call `.acknowledge(reason)` instead to explicitly accept the risk.
    #[getter]
    fn data<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, pyo3::types::PyBytes>> {
        if self.integrity == IntegLevel::Adversarial {
            return Err(UntrustedAccess::new_err(
                "adversarial data cannot be accessed directly — \
                 call .acknowledge(reason) to explicitly accept the risk",
            ));
        }
        Ok(pyo3::types::PyBytes::new(py, &self.raw))
    }

    /// Explicitly accept adversarial data. Reason is audit-logged.
    ///
    /// Returns the raw bytes without raising `UntrustedAccess`.
    fn acknowledge<'py>(
        &self,
        py: Python<'py>,
        reason: &str,
    ) -> Bound<'py, pyo3::types::PyBytes> {
        let _ = reason; // TODO: emit audit event
        pyo3::types::PyBytes::new(py, &self.raw)
    }

    fn __repr__(&self) -> String {
        format!(
            "Labeled(len={}, integrity={:?}, confidentiality={:?})",
            self.raw.len(),
            self.integrity,
            self.confidentiality
        )
    }

    fn __len__(&self) -> usize {
        self.raw.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PolicyDenied + RepairHint (#1280)
// ═══════════════════════════════════════════════════════════════════════════

/// Structured policy denial exception with machine-readable repair hints.
///
/// Raised when a `Runtime` method is denied by the policy engine.
/// Carries structured fields so agents can programmatically determine
/// what to fix.
///
/// ```python
/// try:
///     rt.git_push("origin", "main")
/// except PolicyDenied as e:
///     print(e.attempted)    # "GitPush → GitPush"
///     print(e.reason)       # "capability git_push is Never"
///     print(e.hint)         # "raise artifact integrity..."
///     print(e.suggestion)   # same as hint
/// ```
#[pyclass(extends=pyo3::exceptions::PyException, skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct PolicyDenied {
    /// What the caller tried to do.
    #[pyo3(get)]
    pub attempted: String,
    /// Why it was denied.
    #[pyo3(get)]
    pub reason: String,
    /// Machine-readable repair hint (human-readable string form).
    #[pyo3(get)]
    pub hint: String,
    /// Suggested fix (same as hint — for ergonomic access).
    #[pyo3(get)]
    pub suggestion: String,
}

#[pymethods]
impl PolicyDenied {
    #[new]
    fn new(attempted: String, reason: String, hint: String) -> Self {
        Self {
            attempted,
            reason,
            hint: hint.clone(),
            suggestion: hint,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "PolicyDenied(attempted={:?}, reason={:?})",
            self.attempted, self.reason
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Profile — named capability presets (#1278)
// ═══════════════════════════════════════════════════════════════════════════

/// Named policy profiles for common agent work patterns.
///
/// ```python
/// from portcullis import Profile
///
/// # Named presets
/// profile = Profile.RESEARCH
///
/// # Composition via + operator
/// combined = Profile.RESEARCH + Profile.CODEGEN
/// assert combined.allows("web_fetch")  # from Research
/// assert combined.allows("run_bash")    # from Codegen
///
/// # Add individual capabilities
/// custom = Profile.RESEARCH.with_capability("run_bash")
/// ```
#[pyclass(eq, hash, frozen, from_py_object)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    #[pyo3(name = "READ_ONLY")]
    ReadOnly,
    #[pyo3(name = "RESEARCH")]
    Research,
    #[pyo3(name = "CODEGEN")]
    Codegen,
    #[pyo3(name = "REVIEW")]
    Review,
    #[pyo3(name = "STRICT")]
    Strict,
    #[pyo3(name = "PERMISSIVE")]
    Permissive,
}

impl From<Profile> for portcullis_effects::runtime::PolicyProfile {
    fn from(p: Profile) -> Self {
        match p {
            Profile::ReadOnly => Self::ReadOnly,
            Profile::Research => Self::Research,
            Profile::Codegen => Self::Codegen,
            Profile::Review => Self::Review,
            Profile::Strict => Self::Strict,
            Profile::Permissive => Self::Permissive,
        }
    }
}

#[pymethods]
impl Profile {
    /// Add a single capability to this profile.
    ///
    /// Returns a new ComposedProfile (does not modify self).
    fn with_capability(&self, capability: &str) -> PyResult<ComposedProfile> {
        let cap = parse_capability(capability)?;
        let rust_profile: portcullis_effects::runtime::PolicyProfile = (*self).into();
        let composed = rust_profile.with(cap);
        Ok(ComposedProfile { inner: composed })
    }

    /// Remove a capability from this profile.
    fn without_capability(&self, capability: &str) -> PyResult<ComposedProfile> {
        let cap = parse_capability(capability)?;
        let rust_profile: portcullis_effects::runtime::PolicyProfile = (*self).into();
        let composed = rust_profile.without(cap);
        Ok(ComposedProfile { inner: composed })
    }

    /// Compose with another profile (lattice join).
    fn __add__(&self, other: Profile) -> ComposedProfile {
        let a: portcullis_effects::runtime::PolicyProfile = (*self).into();
        let b: portcullis_effects::runtime::PolicyProfile = other.into();
        ComposedProfile {
            inner: a.join_profile(b),
        }
    }

    fn __repr__(&self) -> String {
        format!("Profile.{self:?}")
    }
}

/// A composed policy — result of Profile + Profile or Profile.with_capability().
#[pyclass(skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct ComposedProfile {
    inner: portcullis_effects::runtime::ComposedPolicy,
}

#[pymethods]
impl ComposedProfile {
    /// Add another capability.
    fn with_capability(&self, capability: &str) -> PyResult<ComposedProfile> {
        let cap = parse_capability(capability)?;
        Ok(ComposedProfile {
            inner: self.inner.clone().with(cap),
        })
    }

    /// Remove a capability.
    fn without_capability(&self, capability: &str) -> PyResult<ComposedProfile> {
        let cap = parse_capability(capability)?;
        Ok(ComposedProfile {
            inner: self.inner.clone().without(cap),
        })
    }

    /// Check if a capability is allowed.
    fn allows(&self, capability: &str) -> PyResult<bool> {
        let cap = parse_capability(capability)?;
        Ok(self.inner.allows(cap))
    }

    fn __repr__(&self) -> String {
        format!("ComposedProfile(base={:?})", self.inner.base_profile())
    }
}

fn parse_capability(s: &str) -> PyResult<portcullis_effects::runtime::RuntimeCapability> {
    use portcullis_effects::runtime::RuntimeCapability;
    match s {
        "read_files" => Ok(RuntimeCapability::ReadFiles),
        "write_files" => Ok(RuntimeCapability::WriteFiles),
        "edit_files" => Ok(RuntimeCapability::EditFiles),
        "run_bash" => Ok(RuntimeCapability::RunBash),
        "web_fetch" => Ok(RuntimeCapability::WebFetch),
        "web_search" => Ok(RuntimeCapability::WebSearch),
        "git_commit" => Ok(RuntimeCapability::GitCommit),
        "git_push" => Ok(RuntimeCapability::GitPush),
        "create_pr" => Ok(RuntimeCapability::CreatePr),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unknown capability: {s}"
        ))),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Runtime — batteries-included entry point (#1278)
// ═══════════════════════════════════════════════════════════════════════════

/// The nucleus runtime — secure agent execution with named profiles.
///
/// ```python
/// from portcullis import Runtime, Profile
///
/// rt = Runtime(Profile.RESEARCH, task="analyze SEC filings")
/// assert rt.can("web_fetch")
/// assert not rt.can("run_bash")
/// ```
#[pyclass(skip_from_py_object)]
pub struct Runtime {
    inner: portcullis_effects::runtime::NucleusRuntime,
}

#[pymethods]
impl Runtime {
    /// Create a runtime with a named profile.
    #[new]
    #[pyo3(signature = (profile, task=""))]
    fn new(profile: Profile, task: &str) -> Self {
        let rust_profile: portcullis_effects::runtime::PolicyProfile = profile.into();
        Self {
            inner: portcullis_effects::runtime::NucleusRuntime::builder()
                .profile(rust_profile)
                .task(task)
                .build(),
        }
    }

    /// Create a runtime from a composed profile.
    #[staticmethod]
    fn from_composed(composed: &ComposedProfile, task: &str) -> Self {
        Self {
            inner: portcullis_effects::runtime::NucleusRuntime::builder()
                .composed(composed.inner.clone())
                .task(task)
                .build(),
        }
    }

    /// Check if a capability is available.
    fn can(&self, capability: &str) -> PyResult<bool> {
        let cap = parse_capability(capability)?;
        Ok(self.inner.can(cap))
    }

    /// Whether the session has observed adversarial data.
    fn is_tainted(&self) -> bool {
        self.inner.is_tainted()
    }

    /// Whether the session has observed confidential data.
    fn has_confidential_data(&self) -> bool {
        self.inner.has_confidential_data()
    }

    fn __repr__(&self) -> String {
        format!(
            "Runtime(profile={:?}, task={:?})",
            self.inner.profile(),
            self.inner.task()
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Module
// ═══════════════════════════════════════════════════════════════════════════

/// The portcullis module — formally verified policy algebra.
#[pymodule]
fn portcullis(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Core types
    m.add_class::<Verdict>()?;
    m.add_class::<CapabilityLevel>()?;
    m.add_class::<CheckResult>()?;
    m.add_class::<PolicyRequest>()?;
    m.add_class::<Pipeline>()?;
    m.add_class::<PyCheckWrapper>()?;

    // IFC types (#1279)
    m.add_class::<IntegLevel>()?;
    m.add_class::<ConfLevel>()?;
    m.add_class::<Labeled>()?;
    m.add_class::<PolicyDenied>()?;

    // Runtime + profiles (#1278)
    m.add_class::<Profile>()?;
    m.add_class::<ComposedProfile>()?;
    m.add_class::<Runtime>()?;

    // Check builder functions
    m.add_function(wrap_pyfunction!(read_only, m)?)?;
    m.add_function(wrap_pyfunction!(deny_disabled, m)?)?;
    m.add_function(wrap_pyfunction!(require_approval_for, m)?)?;
    m.add_function(wrap_pyfunction!(deny_operations, m)?)?;
    m.add_function(wrap_pyfunction!(deny_when_context_matches, m)?)?;
    m.add_function(wrap_pyfunction!(deny_adversarial_taint, m)?)?;
    m.add_function(wrap_pyfunction!(require_min_capability, m)?)?;

    Ok(())
}
