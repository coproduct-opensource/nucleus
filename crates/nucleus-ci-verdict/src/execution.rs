//! Host-observed execution in the existing signed receipt envelope.
//!
//! This versioned CI body is deliberately distinct from a complete build
//! verdict: source materialization, resolved environment and output artifacts
//! still need their own bindings before a publisher can report a build green.

use nucleus_receipt::{Projection, RECEIPT_VERSION, Receipt};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionSchema {
    #[serde(rename = "nucleus.execution.v1")]
    V1,
}

/// Taken from the host's spawned driver, never from pod labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Local,
    Container,
    Firecracker,
}

/// What the protected supervisor actually observed. There is no caller-supplied
/// conclusion: normal exit zero is distinct from nonzero, signals and no result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionClaim {
    pub schema: ExecutionSchema,
    pub pod_id: String,
    /// Declared program identity, matched between host and supervisor.
    pub program_digest: String,
    pub architecture: String,
    pub backend: Backend,
    pub uid_isolated: bool,
    pub exit_code: Option<i32>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    /// Authority inventory, not a command or environment digest.
    pub launch_hash: String,
}

impl ExecutionClaim {
    pub fn to_projection(&self) -> Result<Projection, serde_json::Error> {
        serde_json::to_value(self).map(Projection::Ci)
    }
}

/// Expectations come from the controller's attempt record and pinned signer.
pub struct ExpectedExecution<'a> {
    pub pod_id: &'a str,
    pub program_digest: &'a str,
    pub architecture: &'a str,
    pub session_id: &'a str,
    pub issuer_kid: &'a str,
    pub verifying_key: &'a [u8; 32],
    pub issued_not_before_micros: u64,
    pub issued_not_after_micros: u64,
}

/// Authenticated microVM execution, not yet a verified build or cache hit.
///
/// ```compile_fail
/// use nucleus_ci_verdict::execution::{ExecutionClaim, VerifiedExecution};
/// fn forge(claim: ExecutionClaim) -> VerifiedExecution {
///     VerifiedExecution { claim }
/// }
/// ```
#[derive(Debug)]
#[must_use]
pub struct VerifiedExecution {
    claim: ExecutionClaim,
    valid_until: u64,
}

impl VerifiedExecution {
    pub fn claim(&self) -> &ExecutionClaim {
        &self.claim
    }

    /// Recheck the controller's deadline when consuming the evidence. A value
    /// verified before a queue delay cannot authorize publication indefinitely.
    pub fn into_claim(self, now_micros: u64) -> Result<ExecutionClaim, ExecutionError> {
        if now_micros > self.valid_until {
            return Err(ExecutionError::OutsideWindow);
        }
        Ok(self.claim)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExecutionError {
    Authentication(String),
    Binding(&'static str),
    Body(String),
    InvalidWindow,
    OutsideWindow,
    NotProtectedMicroVm,
    InvalidDigest(&'static str),
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "execution receipt refused: {self:?}")
    }
}

impl std::error::Error for ExecutionError {}

/// Authenticate first, then require exact run and actual protected microVM
/// execution. This does not turn an observed exit into a complete build verdict.
pub fn verify_execution(
    receipt: &Receipt,
    expected: &ExpectedExecution<'_>,
) -> Result<VerifiedExecution, ExecutionError> {
    let ExpectedExecution {
        pod_id,
        program_digest,
        architecture,
        session_id,
        issuer_kid,
        verifying_key,
        issued_not_before_micros,
        issued_not_after_micros,
    } = expected;
    if issued_not_before_micros > issued_not_after_micros {
        return Err(ExecutionError::InvalidWindow);
    }
    if receipt.version != RECEIPT_VERSION {
        return Err(ExecutionError::Authentication("envelope version".into()));
    }
    receipt
        .verify_strict(verifying_key)
        .map_err(|e| ExecutionError::Authentication(e.to_string()))?;
    for (field, actual, wanted) in [
        (
            "session_id",
            receipt.session.session_id.as_str(),
            *session_id,
        ),
        (
            "issuer_kid",
            receipt.session.issuer_kid.as_str(),
            *issuer_kid,
        ),
    ] {
        if actual != wanted {
            return Err(ExecutionError::Binding(field));
        }
    }
    if !(*issued_not_before_micros..=*issued_not_after_micros)
        .contains(&receipt.session.issued_at_micros)
    {
        return Err(ExecutionError::OutsideWindow);
    }
    let mut bodies = receipt.projections.iter().filter_map(|p| match p {
        Projection::Ci(body) => Some(body),
        _ => None,
    });
    let body = bodies
        .next()
        .ok_or_else(|| ExecutionError::Body("missing CI body".into()))?;
    if bodies.next().is_some() {
        return Err(ExecutionError::Body("multiple CI bodies".into()));
    }
    let claim: ExecutionClaim =
        serde_json::from_value(body.clone()).map_err(|e| ExecutionError::Body(e.to_string()))?;
    // Every field must be considered here when the wire body grows. Exit is
    // observed data, deliberately not a condition for authenticating a failure.
    let ExecutionClaim {
        schema: ExecutionSchema::V1,
        pod_id: actual_pod,
        program_digest: actual_program,
        architecture: actual_arch,
        backend,
        uid_isolated,
        exit_code: _,
        stdout_sha256,
        stderr_sha256,
        launch_hash,
    } = &claim;
    for (field, actual, wanted) in [
        ("pod_id", actual_pod.as_str(), *pod_id),
        ("program_digest", actual_program.as_str(), *program_digest),
        ("architecture", actual_arch.as_str(), *architecture),
    ] {
        if actual != wanted {
            return Err(ExecutionError::Binding(field));
        }
    }
    if *backend != Backend::Firecracker || !uid_isolated {
        return Err(ExecutionError::NotProtectedMicroVm);
    }
    for (field, digest) in [
        ("program_digest", actual_program),
        ("stdout_sha256", stdout_sha256),
        ("stderr_sha256", stderr_sha256),
        ("launch_hash", launch_hash),
    ] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ExecutionError::InvalidDigest(field));
        }
    }
    Ok(VerifiedExecution {
        claim,
        valid_until: *issued_not_after_micros,
    })
}
