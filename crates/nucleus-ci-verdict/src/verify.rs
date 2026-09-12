//! Authentication and exact-run binding for CI consumers.
//!
//! A store lookup returns untrusted bytes. Only this module can construct the
//! witness a publisher consumes (ADR 0007 C-1). Expectations are supplied by
//! the controller, never inferred from the receipt being checked.

use crate::{CiVerdict, Conclusion};
use nucleus_receipt::{RECEIPT_VERSION, Receipt};

/// Independently selected run and signer. The inclusive issuance window is
/// bounded by the controller's attempt and trusted clock.
pub struct ExpectedRun<'a> {
    pub action_key: &'a str,
    pub context: &'a str,
    pub tree: &'a str,
    pub pod_id: &'a str,
    pub session_id: &'a str,
    pub issuer_kid: &'a str,
    pub verifying_key: &'a [u8; 32],
    pub issued_not_before_micros: u64,
    pub issued_not_after_micros: u64,
}

/// An authenticated verdict bound to the controller's exact run.
///
/// No `Deserialize`, public constructor, or mutable access: verification
/// cannot be bypassed by parsing a purported witness or editing it afterwards.
///
/// ```compile_fail
/// use nucleus_ci_verdict::{CiVerdict, verify::VerifiedCiVerdict};
/// fn forge(verdict: CiVerdict) -> VerifiedCiVerdict {
///     VerifiedCiVerdict { verdict }
/// }
/// ```
#[derive(Debug)]
#[must_use]
pub struct VerifiedCiVerdict {
    verdict: CiVerdict,
    valid_until: u64,
}

impl VerifiedCiVerdict {
    /// Inspect the authenticated claim without changing it.
    pub fn verdict(&self) -> &CiVerdict {
        &self.verdict
    }

    /// Consume the verified verdict at the publication boundary (ADR C-4).
    pub fn into_verdict(self, now_micros: u64) -> Result<CiVerdict, VerificationError> {
        if now_micros > self.valid_until {
            return Err(VerificationError::OutsideWindow);
        }
        Ok(self.verdict)
    }
}

/// Failure to authenticate or bind a claim is never a passing CI result.
#[derive(Debug, PartialEq, Eq)]
pub enum VerificationError {
    InvalidWindow,
    Version(u32),
    Signature(String),
    Binding(&'static str),
    OutsideWindow,
    Body(String),
    InconsistentOutcome,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CI receipt refused: {self:?}")
    }
}

impl std::error::Error for VerificationError {}

/// Verify before parsing a CI body or consulting its conclusion. A signature
/// from an arbitrary key embedded in the receipt is not a trust anchor.
pub fn verify(
    receipt: &Receipt,
    expected: &ExpectedRun<'_>,
) -> Result<VerifiedCiVerdict, VerificationError> {
    let ExpectedRun {
        action_key,
        context,
        tree,
        pod_id,
        session_id,
        issuer_kid,
        verifying_key,
        issued_not_before_micros,
        issued_not_after_micros,
    } = expected;
    if issued_not_before_micros > issued_not_after_micros {
        return Err(VerificationError::InvalidWindow);
    }
    if receipt.version != RECEIPT_VERSION {
        return Err(VerificationError::Version(receipt.version));
    }
    receipt
        .verify_strict(verifying_key)
        .map_err(|e| VerificationError::Signature(e.to_string()))?;
    for (field, actual, wanted) in [
        (
            "issuer_kid",
            receipt.session.issuer_kid.as_str(),
            *issuer_kid,
        ),
        (
            "session_id",
            receipt.session.session_id.as_str(),
            *session_id,
        ),
    ] {
        if actual != wanted {
            return Err(VerificationError::Binding(field));
        }
    }
    if !(*issued_not_before_micros..=*issued_not_after_micros)
        .contains(&receipt.session.issued_at_micros)
    {
        return Err(VerificationError::OutsideWindow);
    }
    let verdict =
        CiVerdict::from_receipt(receipt).map_err(|e| VerificationError::Body(e.to_string()))?;
    for (field, actual, wanted) in [
        ("action_key", verdict.action_key.as_str(), *action_key),
        ("context", verdict.context.as_str(), *context),
        ("tree", verdict.tree.as_str(), *tree),
        ("pod_id", verdict.pod_id.as_str(), *pod_id),
    ] {
        if actual != wanted {
            return Err(VerificationError::Binding(field));
        }
    }
    match (verdict.conclusion, verdict.exit_status) {
        (Conclusion::Success, 0) | (Conclusion::CouldNotLook, _) => {}
        (Conclusion::Failure, status) if status != 0 => {}
        (Conclusion::Success | Conclusion::Failure, _) => {
            return Err(VerificationError::InconsistentOutcome);
        }
    }
    Ok(VerifiedCiVerdict {
        verdict,
        valid_until: *issued_not_after_micros,
    })
}
