//! An exit report the host can tell apart from one the workload wrote.
//!
//! # The gap this closes
//!
//! The exit report lives at `/work/.nucleus-exit-report.json`, and on a
//! Firecracker pod `/work` is a scratch image whose root the WORKLOAD owns. So
//! a workload can write that path itself, or delete and replace the file the
//! supervisor wrote, and the node reads it back out of the image and signs a
//! receipt over it. `scratch_readback.rs` said so plainly: the host quotes the
//! image and does not know whether the words are true. Measured on a live node
//! (`nucleus-perf guest-transcript --forge-spec`), the only thing that stopped a
//! forged report from becoming a signed receipt was that no receipt could be
//! produced for a Firecracker pod at all.
//!
//! # The fix is a key the workload never holds
//!
//! The supervisor signs the report with the pod's mediation key. The node mints
//! that key for this pod, records its public half in the pod directory, and
//! serves the seed exactly once over vsock, before any workload exists (see
//! `workload_api_vsock`'s one-shots). The workload runs under a distinct uid and
//! cannot read the supervisor's environment. So a report the node can verify
//! against ITS OWN record of the key came from the supervisor, wherever the
//! bytes sat in between — which is why the location stays guest-writable and no
//! longer matters.
//!
//! The signature says who wrote the report, not that its contents are true: a
//! compromised supervisor signs whatever it likes. What it removes is the
//! workload's word standing in for the supervisor's.
//!
//! # Preimage
//!
//! A domain separator, then the report as RFC 8785 canonical JSON — the same
//! canonicalizer `identity::program_digest` uses, so key order and whitespace
//! cannot make one report two preimages. Versioned by the separator: a later
//! change of shape cannot be confused with this one.

use serde::{Deserialize, Serialize};

use crate::ExitReport;

/// Where the supervisor writes the report, relative to the pod's work dir.
pub const EXIT_REPORT_FILE: &str = ".nucleus-exit-report.json";

const DOMAIN: &[u8] = b"nucleus.exit-report.v1\n";

/// An exit report and the supervisor's signature over it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedExitReport {
    pub report: ExitReport,
    /// Hex Ed25519 public key the supervisor signed with. A verifier compares
    /// it with its own record of the pod's key; this copy is a claim.
    pub signer_pubkey: String,
    /// Hex Ed25519 signature over [`signing_bytes`] of `report`.
    pub signature: String,
}

/// The bytes the supervisor signs and the node verifies.
///
/// # Errors
///
/// Only if the report cannot be serialized, which plain data cannot fail; it is
/// returned rather than unwrapped because this sits on a verification path.
pub fn signing_bytes(report: &ExitReport) -> Result<Vec<u8>, serde_json::Error> {
    let canonical = serde_json_canonicalizer::to_vec(report)?;
    let mut out = Vec::with_capacity(DOMAIN.len().saturating_add(canonical.len()));
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&canonical);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(hash: &str) -> ExitReport {
        serde_json::from_str(&format!(
            r#"{{"workspace_hash":"{hash}","audit_tail_hash":"t","audit_entry_count":2,"timestamp_unix":9}}"#
        ))
        .expect("a minimal report parses")
    }

    #[test]
    fn the_preimage_is_domain_separated_and_covers_the_content() {
        let a = signing_bytes(&report("a")).unwrap();
        assert!(a.starts_with(DOMAIN));
        assert_ne!(a, signing_bytes(&report("b")).unwrap());
        assert_eq!(a, signing_bytes(&report("a")).unwrap(), "deterministic");
    }

    /// Two spellings of one report are one preimage: the verifier re-derives it
    /// from the parsed value, never from the file's bytes.
    #[test]
    fn key_order_in_the_file_does_not_change_the_preimage() {
        let spelled_differently: ExitReport = serde_json::from_str(
            r#"{"timestamp_unix":9,"audit_entry_count":2,"audit_tail_hash":"t","workspace_hash":"a"}"#,
        )
        .unwrap();
        assert_eq!(
            signing_bytes(&report("a")).unwrap(),
            signing_bytes(&spelled_differently).unwrap()
        );
    }

    #[test]
    fn an_unknown_field_is_refused_so_nothing_rides_unsigned() {
        let r = serde_json::to_value(report("a")).unwrap();
        let bad =
            serde_json::json!({"report": r, "signer_pubkey": "", "signature": "", "note": "x"});
        assert!(serde_json::from_value::<SignedExitReport>(bad).is_err());
    }
}
