//! Host-observed execution in the existing signed receipt envelope.
//!
//! This versioned CI body is deliberately distinct from a complete build
//! verdict: source materialization, resolved environment and output artifacts
//! still need their own bindings before a publisher can report a build green.

use nucleus_receipt::{Projection, RECEIPT_VERSION, Receipt};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

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
    pub source_commit: String,
    pub source_tree: String,
    pub gate: String,
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
    /// Every resolved env input except the two mediator-injected bindings.
    pub environment_inputs_sha256: String,
    /// Complete per-attempt env, including mediator URL and authentication.
    pub environment_complete_sha256: String,
    #[serde(default)]
    pub artifacts: BTreeMap<String, ArtifactIdentity>,
}

impl ExecutionClaim {
    pub fn to_projection(&self) -> Result<Projection, serde_json::Error> {
        serde_json::to_value(self).map(Projection::Ci)
    }
}

/// Expectations come from the controller's attempt record and pinned signer.
#[derive(Serialize)]
pub struct ExpectedExecution<'a> {
    pub pod_id: &'a str,
    pub source_commit: &'a str,
    pub source_tree: &'a str,
    pub gate: &'a str,
    pub program_digest: &'a str,
    pub architecture: &'a str,
    pub environment_inputs_sha256: &'a str,
    pub artifacts: &'a BTreeMap<String, String>,
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
    Artifact(&'static str),
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
        source_commit,
        source_tree,
        gate,
        program_digest,
        architecture,
        environment_inputs_sha256,
        artifacts: expected_artifacts,
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
        source_commit: actual_source_commit,
        source_tree: actual_source_tree,
        gate: actual_gate,
        program_digest: actual_program,
        architecture: actual_arch,
        backend,
        uid_isolated,
        exit_code: _,
        stdout_sha256,
        stderr_sha256,
        launch_hash,
        environment_inputs_sha256: actual_environment,
        environment_complete_sha256,
        artifacts,
    } = &claim;
    for (field, actual, wanted) in [
        ("pod_id", actual_pod.as_str(), *pod_id),
        ("program_digest", actual_program.as_str(), *program_digest),
        ("architecture", actual_arch.as_str(), *architecture),
        (
            "source_commit",
            actual_source_commit.as_str(),
            *source_commit,
        ),
        ("source_tree", actual_source_tree.as_str(), *source_tree),
        ("gate", actual_gate.as_str(), *gate),
        (
            "environment_inputs_sha256",
            actual_environment.as_str(),
            *environment_inputs_sha256,
        ),
    ] {
        if actual != wanted {
            return Err(ExecutionError::Binding(field));
        }
    }
    if *backend != Backend::Firecracker || !uid_isolated {
        return Err(ExecutionError::NotProtectedMicroVm);
    }
    if artifacts.len() != expected_artifacts.len()
        || !expected_artifacts.iter().all(|(name, path)| {
            artifacts
                .get(name)
                .is_some_and(|artifact| artifact.path == *path)
        })
    {
        return Err(ExecutionError::Artifact(
            "manifest differs from controller request",
        ));
    }
    for (field, digest) in [
        ("program_digest", actual_program),
        ("stdout_sha256", stdout_sha256),
        ("stderr_sha256", stderr_sha256),
        ("launch_hash", launch_hash),
        ("environment_inputs_sha256", actual_environment),
        ("environment_complete_sha256", environment_complete_sha256),
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

/// Verified execution plus the exact output bytes. Private construction keeps
/// checking only a receipt from being mistaken for checking its artifacts.
///
/// ```compile_fail
/// use nucleus_ci_verdict::execution::{ExecutionClaim, VerifiedArtifacts};
/// fn forge(claim: ExecutionClaim) -> VerifiedArtifacts {
///     VerifiedArtifacts { claim, bytes: Default::default(), valid_until: u64::MAX }
/// }
/// ```
#[derive(Debug)]
#[must_use]
pub struct VerifiedArtifacts {
    claim: ExecutionClaim,
    bytes: BTreeMap<String, Vec<u8>>,
    valid_until: u64,
}

impl VerifiedArtifacts {
    pub fn into_parts(
        self,
        now_micros: u64,
    ) -> Result<(ExecutionClaim, BTreeMap<String, Vec<u8>>), ExecutionError> {
        if now_micros > self.valid_until {
            return Err(ExecutionError::OutsideWindow);
        }
        Ok((self.claim, self.bytes))
    }
}

pub fn verify_artifacts(
    receipt: &Receipt,
    expected: &ExpectedExecution<'_>,
    bytes: BTreeMap<String, Vec<u8>>,
) -> Result<VerifiedArtifacts, ExecutionError> {
    use sha2::{Digest, Sha256};
    let verified = verify_execution(receipt, expected)?;
    if expected.artifacts.is_empty() || bytes.len() != verified.claim.artifacts.len() {
        return Err(ExecutionError::Artifact("missing artifact bytes"));
    }
    for (name, artifact) in &verified.claim.artifacts {
        let ArtifactIdentity {
            path: _,
            sha256,
            size,
        } = artifact;
        let data = bytes
            .get(name)
            .ok_or(ExecutionError::Artifact("missing artifact bytes"))?;
        if data.len() as u64 != *size || hex::encode(Sha256::digest(data)) != *sha256 {
            return Err(ExecutionError::Artifact(
                "artifact bytes differ from signed identity",
            ));
        }
    }
    Ok(VerifiedArtifacts {
        claim: verified.claim,
        bytes,
        valid_until: verified.valid_until,
    })
}
