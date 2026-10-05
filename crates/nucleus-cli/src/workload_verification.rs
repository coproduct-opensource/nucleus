//! Portable supervised-workload check using authenticated admission and the shared verifier.
use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use nucleus_ci_verdict::execution::{RecordedExecution, verify_execution};
use nucleus_receipt::Receipt;
use nucleus_spec::workload_admission::WorkloadAdmission;
use nucleus_spec::workload_result::{EnvironmentIdentity, WorkloadResult};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Deserialize)]
pub(crate) struct Manifest {
    schema: String,
    architecture: String,
    files: BTreeMap<String, Input>,
}

#[derive(Deserialize)]
struct Input {
    sha256: String,
    bytes: u64,
}

impl Manifest {
    pub(crate) fn is_aarch64(&self) -> bool {
        self.architecture == "aarch64"
    }

    /// Enroll installed input bytes before requesting a workload. These hashes
    /// come from the operator's files, never from the resulting receipt.
    pub(crate) fn installed() -> Result<Self> {
        let mut files = BTreeMap::new();
        for name in ["vmlinux", "rootfs.ext4"] {
            let path = std::path::Path::new(crate::provision::HOST_ARTIFACTS_DIR).join(name);
            let bytes = path
                .metadata()
                .with_context(|| format!("stat {}", path.display()))?
                .len();
            let sha256 = crate::provision::sha256_file(&path)
                .with_context(|| format!("hash {}", path.display()))?;
            files.insert(name.into(), Input { sha256, bytes });
        }
        Ok(Self {
            schema: "nucleus.microvm-host-inputs.v1".into(),
            architecture: std::env::consts::ARCH.into(),
            files,
        })
    }
}

fn spec(manifest: &Manifest, nonce: Uuid) -> Result<nucleus_spec::PodSpec> {
    ensure!(
        manifest.schema == "nucleus.microvm-host-inputs.v1",
        "unsupported host input manifest"
    );
    ensure!(
        matches!(manifest.architecture.as_str(), "aarch64" | "x86_64"),
        "unsupported guest architecture"
    );
    let digest = |name: &str| -> Result<String> {
        let input = manifest
            .files
            .get(name)
            .with_context(|| format!("host manifest has no {name}"))?;
        ensure!(
            input.bytes > 0
                && input.sha256.len() == 64
                && input.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid host manifest digest for {name}"
        );
        Ok(format!("sha-256:{}", input.sha256.to_ascii_lowercase()))
    };
    let mut spec: nucleus_spec::PodSpec = serde_json::from_value(json!({
        "apiVersion":"nucleus/v1", "kind":"Pod",
        "metadata":{"name":format!("setup-{nonce}")},
        "spec": {
            "work_dir":"/tmp", "timeout_seconds":600,
            "policy":{"type":"profile", "name":"codegen"},
            "workload": {
                "command":"/bin/sh", "args":["-c",format!("printf 'nucleus-setup-{nonce}\\n'; uname -s")],
                "uid":1000,
                "env":environment(),
            },
            "image": {
                "kernel_path":nucleus_spec::microvm_host::guest_kernel_path(),
                "rootfs_path":nucleus_spec::microvm_host::guest_rootfs_path(),
                "kernel_digest":digest("vmlinux")?, "rootfs_digest":digest("rootfs.ext4")?,
                "read_only":true,
            },
            "vsock":{"guest_cid":3,"port":5005},
        }
    })).context("constructing setup workload")?;
    // Predict the same host admission labels using the shared decider. The
    // signed execution verifier separately checks the actual microVM backend.
    let policy = spec.spec.resolve_policy()?;
    let isolation = portcullis::enforcement::require_isolation(
        policy.effective_minimum_isolation(),
        &portcullis::enforcement::BackendCapability::FIRECRACKER,
    )?;
    spec.record_isolation(isolation);
    // Authority admission replaces a named profile with its effective inline
    // lattice. Request that resolved lattice so the identity has the same form.
    spec.spec.policy = nucleus_spec::PolicySpec::Inline {
        lattice: Box::new(policy),
    };
    Ok(spec)
}

fn environment() -> BTreeMap<String, String> {
    [
        ("HOME", "/work/.home"),
        ("PATH", "/usr/bin:/bin"),
        ("LANG", "C"),
        ("TZ", "UTC"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect()
}

fn now() -> Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?)
}

/// Enroll the signer through authenticated admission, independently of the
/// receipt. Setup trusts its locally provisioned CA and operator-selected image;
/// this enrollment does not establish external platform attestation.
fn expectations(
    admission: WorkloadAdmission,
    pod: Uuid,
    program: String,
    architecture: &str,
) -> Result<RecordedExecution> {
    ensure!(
        admission.pod_id == pod.to_string() && admission.session_id == pod.to_string(),
        "setup admission identifies another pod"
    );
    ensure!(
        admission.program_digest == program,
        "setup admission changed the requested program"
    );
    ensure!(
        admission.architecture == architecture,
        "setup admission architecture differs from host inputs"
    );
    Ok(RecordedExecution {
        pod_id: pod.to_string(),
        session_id: pod.to_string(),
        source_commit: String::new(),
        source_tree: String::new(),
        gate: String::new(),
        program_digest: program,
        architecture: architecture.into(),
        environment_inputs_sha256: EnvironmentIdentity::of(&environment()).inputs_sha256,
        artifacts: BTreeMap::new(),
        issuer_kid: admission.issuer_kid,
        verifying_key: admission.verifying_key,
        issued_not_before_micros: admission
            .created_at_unix
            .checked_mul(1_000_000)
            .context("admission timestamp overflow")?,
        issued_not_after_micros: now()?
            .checked_add(180_000_000)
            .context("verification deadline overflow")?,
    })
}

async fn get<T: serde::de::DeserializeOwned>(client: &reqwest::Client, url: &str) -> Result<T> {
    serde_json::from_slice(&reply(client.get(url).send().await?).await?)
        .context("reading setup response")
}

async fn reply(response: reqwest::Response) -> Result<Vec<u8>> {
    let status = response.status().as_u16();
    let bytes = response.bytes().await?.to_vec();
    crate::node::ensure_ok(status, &bytes, "workload verification node request")?;
    Ok(bytes)
}

async fn observe(client: &reqwest::Client, base: &str) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            match get::<WorkloadResult>(client, &format!("{base}/workload-result")).await? {
                WorkloadResult::Exited { .. } => return Ok(()),
                WorkloadResult::Running => tokio::time::sleep(Duration::from_secs(1)).await,
                WorkloadResult::NotConfigured => bail!("setup workload was not configured"),
                WorkloadResult::Unavailable { reason } => {
                    bail!("setup workload unavailable: {reason}")
                }
            }
        }
    })
    .await
    .context("timed out waiting for the setup workload")?
}

async fn completed(
    client: &reqwest::Client,
    base: &str,
    expected: &RecordedExecution,
    nonce: Uuid,
) -> Result<Value> {
    observe(client, base).await?;
    let receipt: Receipt = get(client, &format!("{base}/execution-receipt")).await?;
    let verified = verify_execution(&receipt, &expected.as_expected())?;
    let stdout = reply(
        client
            .get(format!("{base}/workload-logs/stdout"))
            .send()
            .await?,
    )
    .await?;
    let stderr = reply(
        client
            .get(format!("{base}/workload-logs/stderr"))
            .send()
            .await?,
    )
    .await?;
    let logs = verified.verify_logs(stdout, stderr)?;
    let (stdout, stderr) = logs.into_parts(now()?)?;
    let claim = verified.into_claim(now()?)?;
    ensure!(
        claim.exit_code == Some(0),
        "setup workload did not exit successfully: {:?}",
        claim.exit_code
    );
    ensure!(
        stdout == format!("nucleus-setup-{nonce}\nLinux\n").as_bytes() && stderr.is_empty(),
        "setup workload output differed from the requested ordinary command"
    );
    Ok(
        json!({"execution_verified":true,"claim":claim,"stdout_bytes":stdout.len(),"stderr_bytes":stderr.len()}),
    )
}

/// Verify a host-requested workload on an authenticated node. The node must
/// require its own PodSpec in the guest; a legacy baked workload cannot satisfy
/// the fresh-output and program-identity checks.
pub(crate) async fn verify(
    client: reqwest::Client,
    node_url: &str,
    manifest: Manifest,
) -> Result<Value> {
    let nonce = Uuid::new_v4();
    let requested = spec(&manifest, nonce)?;
    let program = nucleus_spec::identity::program_digest(&requested)
        .map_err(|error| anyhow::anyhow!("setup program identity: {error}"))?;
    #[derive(Deserialize)]
    struct Created {
        id: Uuid,
    }
    let created: Created = serde_json::from_slice(
        &reply(
            client
                .post(format!("{}/v1/pods", node_url))
                .timeout(nucleus_spec::boot_budget::POD_CREATE_CLIENT_TIMEOUT)
                .json(&requested)
                .send()
                .await?,
        )
        .await?,
    )?;
    let base = format!("{}/v1/pods/{}", node_url, created.id);
    // Once create returns an ID, every ordinary exit (including Ctrl-C) reaches
    // cancellation. Cancellation is not hidden when verification also failed.
    let verification = async {
        let admission = get(&client, &format!("{base}/workload-admission")).await?;
        let expected = expectations(admission, created.id, program, &manifest.architecture)?;
        completed(&client, &base, &expected, nonce).await
    };
    let result = tokio::select! {
        result = verification => result,
        signal = tokio::signal::ctrl_c() => {
            match signal {
                Ok(()) => Err(anyhow::anyhow!("setup verification interrupted")),
                Err(error) => Err(anyhow::Error::new(error).context("installing setup interrupt handler")),
            }
        }
    };
    let cleanup = async { reply(client.post(format!("{base}/cancel")).send().await?).await }.await;
    match (result, cleanup) {
        (Ok(mut report), Ok(_)) => {
            report["pod_cancelled"] = true.into();
            Ok(report)
        }
        (Err(error), Ok(_)) => {
            Err(error.context(format!("setup pod {} was cancelled", created.id)))
        }
        (result, Err(error)) => bail!(
            "setup pod {} cancellation failed: {error}; verification: {}",
            created.id,
            match result {
                Ok(_) => "passed".into(),
                Err(e) => format!("{e:#}"),
            }
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_program_pins_inputs_and_predicts_the_hosts_isolation_labels() {
        for architecture in ["aarch64", "x86_64"] {
            check_program(architecture);
        }
    }

    fn check_program(architecture: &str) {
        let manifest = Manifest {
            schema: "nucleus.microvm-host-inputs.v1".into(),
            architecture: architecture.into(),
            files: BTreeMap::from([
                (
                    "vmlinux".into(),
                    Input {
                        sha256: "1".repeat(64),
                        bytes: 1024,
                    },
                ),
                (
                    "rootfs.ext4".into(),
                    Input {
                        sha256: "2".repeat(64),
                        bytes: 2048,
                    },
                ),
            ]),
        };
        let nonce = Uuid::new_v4();
        let mut requested = spec(&manifest, nonce).unwrap();
        let before = nucleus_spec::identity::program_digest(&requested).unwrap();
        let policy = requested.spec.resolve_policy().unwrap();
        requested.record_isolation(
            portcullis::enforcement::require_isolation(
                policy.effective_minimum_isolation(),
                &portcullis::enforcement::BackendCapability::FIRECRACKER,
            )
            .unwrap(),
        );
        assert_eq!(
            nucleus_spec::identity::program_digest(&requested).unwrap(),
            before
        );
        let image = requested.spec.image.as_ref().unwrap();
        assert_eq!(
            image
                .kernel_digest
                .as_ref()
                .map(nucleus_spec::ArtifactDigest::as_str),
            Some(format!("sha-256:{}", "1".repeat(64)).as_str())
        );
        let workload = requested.spec.workload.as_ref().unwrap();
        assert_eq!(workload.uid, Some(1000));
        assert_eq!(workload.env, environment());
        assert!(workload.args[1].contains(&nonce.to_string()));
    }
}
