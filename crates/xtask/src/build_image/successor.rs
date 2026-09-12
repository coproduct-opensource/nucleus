//! Consume a verified stage-one executor in a subsequent disposable build.
//! The operator pins the approved source and predecessor key independently;
//! evidence files must come from the protected controller attempt directory.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use nucleus_ci_verdict::execution::{RecordedExecution, verify_artifacts};
use nucleus_receipt::Receipt;

use super::*;

#[derive(clap::Args)]
pub struct Args {
    /// Protected stage-one experiment directory, not an arbitrary artifact bundle.
    #[arg(long)]
    pub(super) predecessor: PathBuf,
    /// Independently approved exact commit for both builds.
    #[arg(long)]
    pub(super) source_commit: String,
    /// Operator-pinned predecessor key. Never inferred from a receipt.
    #[arg(long)]
    pub(super) executor_public_key: String,
    /// New, short directory for the successor node and its evidence.
    #[arg(long)]
    pub(super) output: PathBuf,
}

/// Only prepare() can mint the bytes that this command launches as an executor.
struct VerifiedExecutor {
    bytes: Vec<u8>,
    provenance: serde_json::Value,
    valid_until: u64,
}

pub fn run(args: Args) -> Result<()> {
    let Args {
        predecessor,
        source_commit,
        executor_public_key,
        output,
    } = args;
    let key: [u8; 32] = hex::decode(executor_public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("executor public key must contain 32 bytes"))?;
    let predecessor = predecessor.canonicalize()?;
    let verified = prepare(&predecessor, &source_commit, &key, now()?)?;
    // Copy the verified bytes into an owner-only directory. Do not execute the
    // original artifact path, whose contents could change after verification.
    let executable = tempfile::tempdir()?;
    let node_binary = executable.path().join("nucleus-node");
    fs::write(&node_binary, verified.bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&node_binary, fs::Permissions::from_mode(0o700))?;
    }
    execute::bootstrap(execute::BootstrapArgs {
        inputs: predecessor.join("build/inputs.json"),
        source_commit,
        node_binary,
        output,
        successor_output: None,
        successor_provenance: Some((verified.provenance, verified.valid_until)),
    })
}

fn prepare(
    predecessor: &Path,
    approved_commit: &str,
    key: &[u8; 32],
    now: u64,
) -> Result<VerifiedExecutor> {
    ensure!(
        is_hex(approved_commit, 40),
        "approved source must be a full commit ID"
    );
    let cold = predecessor.join("build/cold");
    let record: RecordedExecution = serde_json::from_slice(&read_bounded(
        &cold.join("expected-execution.json"),
        128 * 1024,
    )?)?;
    ensure!(
        record.source_commit == approved_commit,
        "predecessor source differs from approved commit"
    );
    ensure!(
        &record.verifying_key == key,
        "predecessor record differs from pinned executor key"
    );
    ensure!(
        record.gate == "cargo-build-nucleus-node-v1",
        "predecessor did not run the nucleus build gate"
    );
    let receipt: Receipt = serde_json::from_slice(&read_bounded(
        &cold.join("artifact-receipt.json"),
        2 * 1024 * 1024,
    )?)?;
    ensure!(
        receipt.session.issued_at_micros <= now,
        "predecessor receipt is issued in the future"
    );
    let bytes = read_bounded(&cold.join("nucleus-node"), 256 * 1024 * 1024)?;
    let verified = verify_artifacts(
        &receipt,
        &record.as_expected(),
        BTreeMap::from([("nucleus-node".into(), bytes)]),
    )?;
    let (claim, mut outputs) = verified.into_parts(now)?;
    ensure!(
        claim.exit_code == Some(0),
        "predecessor build did not succeed"
    );
    let bytes = outputs
        .remove("nucleus-node")
        .context("verified executor artifact is missing")?;
    Ok(VerifiedExecutor {
        provenance: serde_json::json!({
            "schema": "nucleus.successor.v1", "source_commit": approved_commit,
            "source_tree": claim.source_tree, "predecessor_pod_id": claim.pod_id,
            "predecessor_receipt_root": receipt.root_hash_hex,
            "predecessor_executor_public_key": hex::encode(key),
            "predecessor_issuer": receipt.session.issuer_kid,
            "executor_sha256": hex::encode(Sha256::digest(&bytes)),
            "trust": "verified predecessor output; new disposable executor keys; no production promotion"
        }),
        bytes,
        valid_until: record.issued_not_after_micros,
    })
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? <= limit,
        "{} exceeds its size limit",
        path.display()
    );
    Ok(bytes)
}

fn now() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use nucleus_ci_verdict::execution::{
        ArtifactIdentity, Backend, ExecutionClaim, ExecutionSchema,
    };
    use nucleus_receipt::Session;

    fn fixture(root: &Path, exit: i32, signer: &SigningKey) -> Result<[u8; 32]> {
        let cold = root.join("build/cold");
        fs::create_dir_all(&cold)?;
        let trusted = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        let data = b"verified stage-one bytes";
        let record = RecordedExecution {
            pod_id: "pod-1".into(),
            source_commit: "a".repeat(40),
            source_tree: "b".repeat(40),
            gate: "cargo-build-nucleus-node-v1".into(),
            program_digest: "c".repeat(64),
            architecture: "x86_64".into(),
            environment_inputs_sha256: "d".repeat(64),
            artifacts: BTreeMap::from([(
                "nucleus-node".into(),
                "target/debug/nucleus-node".into(),
            )]),
            session_id: "pod-1".into(),
            issuer_kid: "bootstrap-node".into(),
            verifying_key: trusted,
            issued_not_before_micros: 100,
            issued_not_after_micros: 200,
        };
        let claim = ExecutionClaim {
            schema: ExecutionSchema::V1,
            pod_id: record.pod_id.clone(),
            source_commit: record.source_commit.clone(),
            source_tree: record.source_tree.clone(),
            gate: record.gate.clone(),
            program_digest: record.program_digest.clone(),
            architecture: record.architecture.clone(),
            backend: Backend::Firecracker,
            uid_isolated: true,
            exit_code: Some(exit),
            stdout_sha256: "e".repeat(64),
            stderr_sha256: "e".repeat(64),
            launch_hash: "f".repeat(64),
            environment_inputs_sha256: record.environment_inputs_sha256.clone(),
            environment_complete_sha256: "f".repeat(64),
            artifacts: BTreeMap::from([(
                "nucleus-node".into(),
                ArtifactIdentity {
                    path: "target/debug/nucleus-node".into(),
                    sha256: hex::encode(Sha256::digest(data)),
                    size: data.len() as u64,
                },
            )]),
        };
        let receipt = Receipt::sign(
            Session {
                session_id: record.session_id.clone(),
                issuer_kid: record.issuer_kid.clone(),
                issued_at_micros: 150,
                parent_chain: vec![],
            },
            vec![claim.to_projection()?],
            signer,
        );
        fs::write(cold.join("nucleus-node"), data)?;
        fs::write(
            cold.join("expected-execution.json"),
            serde_json::to_vec(&record)?,
        )?;
        fs::write(
            cold.join("artifact-receipt.json"),
            serde_json::to_vec(&receipt)?,
        )?;
        Ok(trusted)
    }

    #[test]
    fn successor_uses_verified_bytes_and_refuses_wrong_inputs() -> Result<()> {
        let root = tempfile::tempdir()?;
        let signer = SigningKey::from_bytes(&[7; 32]);
        let key = fixture(root.path(), 0, &signer)?;
        let approved = "a".repeat(40);
        let verified = prepare(root.path(), &approved, &key, 160)?;
        fs::write(
            root.path().join("build/cold/nucleus-node"),
            b"swapped after verification",
        )?;
        assert_eq!(verified.bytes, b"verified stage-one bytes");
        assert!(prepare(root.path(), &approved, &key, 160).is_err());
        fixture(root.path(), 0, &signer)?;
        for clock in [149, 201] {
            assert!(prepare(root.path(), &approved, &key, clock).is_err());
        }
        assert!(prepare(root.path(), &"b".repeat(40), &key, 160).is_err());
        assert!(prepare(root.path(), &approved, &[8; 32], 160).is_err());
        fixture(root.path(), 0, &SigningKey::from_bytes(&[8; 32]))?;
        assert!(prepare(root.path(), &approved, &key, 160).is_err());
        // An old binary in a signed failed build is not a successor executor.
        fixture(root.path(), 1, &signer)?;
        assert!(prepare(root.path(), &approved, &key, 160).is_err());
        Ok(())
    }
}
