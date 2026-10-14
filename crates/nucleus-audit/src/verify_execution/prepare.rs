//! Prepare controller expectations without accepting any execution evidence.
use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use nucleus_ci_verdict::execution::RecordedExecution;
use nucleus_spec::workload_admission::WorkloadAdmission;
use nucleus_spec::workload_result::EnvironmentIdentity;

#[derive(clap::Args, Debug)]
pub(crate) struct Args {
    /// Admission JSON saved separately through the authenticated node API
    #[arg(long)]
    admission: PathBuf,
    /// Independently enrolled node public Ed25519 key (64 hexadecimal characters)
    #[arg(long)]
    signer_key_hex: String,
    /// JSON name/value map of the intended environment inputs, including
    /// defaults. Omit what the runtime injects (`NUCLEUS_EGRESS_<NAME>_URL`):
    /// it is derived from the admission record, and restating it is refused.
    #[arg(long)]
    environment_inputs: PathBuf,
    /// Unix microsecond deadline for receipt issuance AND verification consumption
    #[arg(long)]
    valid_until_micros: u64,
    /// Selected declared artifact name/path map; omit for receipt-only verification
    #[arg(long)]
    artifacts: Option<PathBuf>,
}

impl Args {
    pub(super) fn prepare(self, now: u64) -> Result<RecordedExecution> {
        let mut admission: WorkloadAdmission = super::read(&self.admission)?;
        let selected: BTreeMap<String, String> = self
            .artifacts
            .as_deref()
            .map(super::read)
            .transpose()?
            .unwrap_or_default();
        for (name, path) in &selected {
            if admission.artifacts.get(name) != Some(path) {
                bail!("selected artifact {name:?} does not match admission");
            }
        }
        admission.artifacts = selected;
        let inputs = super::read(&self.environment_inputs)?;
        let key = hex::decode(&self.signer_key_hex).context("invalid signer public key hex")?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| anyhow::anyhow!("signer public key must be exactly 32 bytes"))?;
        prepare(admission, &inputs, key, self.valid_until_micros, now)
    }
}

fn prepare(
    admission: WorkloadAdmission,
    declared: &BTreeMap<String, String>,
    signer: [u8; 32],
    valid_until: u64,
    now: u64,
) -> Result<RecordedExecution> {
    // Declared inputs plus what the runtime injected, read from the admission
    // record rather than restated (#3219). Mediator bindings and restated
    // runtime names are refused by name.
    let inputs = admission.environment_inputs(declared)?;
    let WorkloadAdmission {
        pod_id,
        created_at_unix,
        source_commit,
        source_tree,
        gate,
        program_digest,
        architecture,
        artifacts,
        session_id,
        issuer_kid,
        verifying_key,
        runtime_environment_inputs: _,
    } = admission;
    if verifying_key != signer {
        bail!("admission signer does not match the independently enrolled public key");
    }
    if pod_id.is_empty() || pod_id != session_id {
        bail!("admission pod and session must identify the same nonempty attempt");
    }
    let issued_not_before_micros = created_at_unix
        .checked_mul(1_000_000)
        .context("admission timestamp exceeds microsecond range")?;
    if valid_until <= now || valid_until < issued_not_before_micros {
        bail!("validity deadline must be after now and no earlier than admission");
    }
    Ok(RecordedExecution {
        pod_id,
        source_commit,
        source_tree,
        gate,
        program_digest,
        architecture,
        environment_inputs_sha256: EnvironmentIdentity::of(&inputs).inputs_sha256,
        artifacts,
        session_id,
        issuer_kid,
        verifying_key: signer,
        issued_not_before_micros,
        issued_not_after_micros: valid_until,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admission() -> WorkloadAdmission {
        WorkloadAdmission {
            pod_id: "attempt-1".into(),
            session_id: "attempt-1".into(),
            created_at_unix: 10,
            source_commit: "commit".into(),
            source_tree: "tree".into(),
            gate: "tests".into(),
            program_digest: "program".into(),
            architecture: "aarch64".into(),
            artifacts: BTreeMap::from([("patch".into(), "changes.patch".into())]),
            issuer_kid: "enrolled-node".into(),
            verifying_key: [7; 32],
            runtime_environment_inputs: BTreeMap::new(),
        }
    }

    #[test]
    fn preserves_admission_and_commits_only_intended_environment() {
        let inputs = BTreeMap::from([
            ("HOME".into(), "/work/.home".into()),
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("LANG".into(), "C".into()),
            ("TZ".into(), "UTC".into()),
        ]);
        let expected = prepare(admission(), &inputs, [7; 32], 30_000_000, 20_000_000).unwrap();
        // Independently computed for the live packaged workload, not read from
        // its receipt. This also exercises the exact CLI input representation.
        assert_eq!(
            expected.environment_inputs_sha256,
            "84d64364661d3efe6456dd418e0cf83f48c893efd387ba6d8384bed2c68c29ee"
        );
        assert_eq!(expected.issued_not_before_micros, 10_000_000);
        assert_eq!(expected.issued_not_after_micros, 30_000_000);
        let mut actual = serde_json::to_value(expected).unwrap();
        actual
            .as_object_mut()
            .unwrap()
            .remove("environment_inputs_sha256");
        actual
            .as_object_mut()
            .unwrap()
            .remove("issued_not_before_micros");
        actual
            .as_object_mut()
            .unwrap()
            .remove("issued_not_after_micros");
        let mut original = serde_json::to_value(admission()).unwrap();
        original.as_object_mut().unwrap().remove("created_at_unix");
        original
            .as_object_mut()
            .unwrap()
            .remove("runtime_environment_inputs");
        assert_eq!(actual, original);
    }

    #[test]
    fn mismatched_signer_and_expired_deadline_explain_configuration_errors() {
        let inputs = BTreeMap::new();
        assert!(
            prepare(admission(), &inputs, [8; 32], 30_000_000, 20_000_000)
                .err()
                .unwrap()
                .to_string()
                .contains("signer")
        );
        assert!(
            prepare(admission(), &inputs, [7; 32], 20_000_000, 20_000_000)
                .err()
                .unwrap()
                .to_string()
                .contains("deadline")
        );
    }

    #[test]
    fn file_inputs_select_receipt_only_or_declared_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let admission_path = dir.path().join("admission.json");
        let environment = dir.path().join("environment.json");
        let artifacts = dir.path().join("artifacts.json");
        std::fs::write(&admission_path, serde_json::to_vec(&admission()).unwrap()).unwrap();
        std::fs::write(&environment, b"{}").unwrap();
        std::fs::write(&artifacts, br#"{"patch":"changes.patch"}"#).unwrap();
        let args = |selection| Args {
            admission: admission_path.clone(),
            signer_key_hex: hex::encode([7; 32]),
            environment_inputs: environment.clone(),
            valid_until_micros: 30_000_000,
            artifacts: selection,
        };
        assert!(args(None).prepare(20_000_000).unwrap().artifacts.is_empty());
        assert_eq!(
            args(Some(artifacts.clone()))
                .prepare(20_000_000)
                .unwrap()
                .artifacts,
            admission().artifacts
        );
        std::fs::write(&artifacts, br#"{"patch":"other.patch"}"#).unwrap();
        assert!(args(Some(artifacts)).prepare(20_000_000).is_err());
        let retained: WorkloadAdmission = super::super::read(&admission_path).unwrap();
        assert_eq!(retained, admission());
    }
}
