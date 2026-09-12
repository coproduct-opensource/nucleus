//! Controller for an exact-tree build on a separately started, trusted node.
//! Local input preparation and the executor public key are controller inputs;
//! neither expectations nor publication authority come from a returned receipt.

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use nucleus_ci_verdict::execution::{ExpectedExecution, verify_artifacts, verify_execution};
use nucleus_receipt::Receipt;
use nucleus_spec::workload_result::{EnvironmentIdentity, WorkloadResult};
use reqwest::blocking::Client;
use serde::Deserialize;

use super::*;

// Release asset digest resolved from the official Firecracker release API on
// 2026-09-12. Coupled to the public runtime version pin below, never floating.
const FIRECRACKER_TGZ_SHA256: &str =
    "382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6";

#[derive(clap::Args)]
pub struct BootstrapArgs {
    #[arg(long)]
    pub(super) inputs: PathBuf,
    #[arg(long)]
    pub(super) source_commit: String,
    #[arg(long)]
    pub(super) node_binary: PathBuf,
    /// New directory for the disposable node, keys and verified build output.
    #[arg(long)]
    pub(super) output: PathBuf,
    /// Set only by the verified successor path, never by command-line input.
    #[arg(skip)]
    pub(super) successor_provenance: Option<(serde_json::Value, u64)>,
}

pub fn bootstrap(args: BootstrapArgs) -> Result<()> {
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
    let BootstrapArgs {
        inputs,
        source_commit,
        node_binary,
        output,
        successor_provenance,
    } = args;
    ensure!(
        Path::new("/dev/kvm").exists() && Path::new("/dev/vhost-vsock").exists(),
        "the experiment needs real KVM and vhost-vsock devices"
    );
    ensure!(
        capture(Command::new("id").arg("-u"))?.trim() == "0",
        "bootstrap must run as root to configure the jailed VM"
    );
    ensure!(
        nucleus_spec::vmm_version::PINNED_STR == "1.16.1",
        "update the Firecracker asset pin with the version"
    );
    let node_binary = node_binary.canonicalize()?;
    let inputs = inputs.canonicalize()?;
    fs::create_dir(&output).context("bootstrap output must be a new directory")?;
    let output = output.canonicalize()?;
    check_bootstrap_socket_paths(&output)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
    }
    let archive = output.join("firecracker.tgz");
    let successor_deadline = successor_provenance.as_ref().map(|(_, deadline)| *deadline);
    if let Some((provenance, _)) = successor_provenance {
        fs::write(
            output.join("successor-provenance.json"),
            serde_json::to_vec_pretty(&provenance)?,
        )?;
    }
    checked(Command::new("curl").args(["--fail", "--location", "--retry", "2", "--output"])
        .arg(&archive).arg("https://github.com/firecracker-microvm/firecracker/releases/download/v1.16.1/firecracker-v1.16.1-x86_64.tgz"))?;
    ensure!(
        sha256(&archive)? == FIRECRACKER_TGZ_SHA256,
        "Firecracker archive differs from pinned release"
    );
    checked(
        Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&output),
    )?;
    let release = output.join("release-v1.16.1-x86_64");
    // The jailer includes the executable basename in every Unix socket path.
    // The versioned release name overflowed sun_path with this output layout.
    let firecracker = output.join("firecracker");
    copy_executable(&release.join("firecracker-v1.16.1-x86_64"), &firecracker)?;
    let jailer = release.join("jailer-v1.16.1-x86_64");
    let state = output.join("state");
    let log = fs::File::create(output.join("node.log"))?;
    let auth = capture(Command::new("openssl").args(["rand", "-hex", "32"]))?;
    let approval = capture(Command::new("openssl").args(["rand", "-hex", "32"]))?;
    if let Some(deadline) = successor_deadline {
        ensure!(
            now()? <= deadline,
            "predecessor evidence expired before successor launch"
        );
    }
    let mut node = Command::new(&node_binary)
        .arg("--state-dir")
        .arg(&state)
        .args([
            "--listen",
            "127.0.0.1:18443",
            "--proxy-auth-secret",
            auth.trim(),
            "--proxy-approval-secret",
            approval.trim(),
        ])
        .arg("--firecracker-path")
        .arg(&firecracker)
        .arg("--jailer-path")
        .arg(&jailer)
        .arg("--jailer-chroot-base")
        .arg(output.join("jailer"))
        .env("TRUST_EXECUTOR_ID", "nucleus-self-build/bootstrap")
        .env("RUST_LOG", "info")
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()
        .context("start disposable bootstrap node")?;
    // Keep every fallible operation after spawn inside the closure so normal
    // failure always kills and reaps the disposable node before returning.
    let result = (|| -> Result<()> {
        let start = Instant::now();
        while !state.join("ca/ca-cert.pem").exists()
            || !state.join("executor_signing_key.der").exists()
        {
            ensure!(
                node.try_wait()?.is_none(),
                "bootstrap node exited; see node.log"
            );
            ensure!(
                start.elapsed() < Duration::from_secs(60),
                "bootstrap node did not initialize"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        mint_client(&output, &state)?;
        let signing = ed25519_dalek::SigningKey::from_pkcs8_der(&fs::read(
            state.join("executor_signing_key.der"),
        )?)?;
        let public = hex::encode(signing.verifying_key().to_bytes());
        fs::write(
            output.join("bootstrap-runtime.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "node_sha256": sha256(&node_binary)?, "firecracker_sha256": sha256(&firecracker)?,
                "jailer_sha256": sha256(&jailer)?, "firecracker_archive_sha256": FIRECRACKER_TGZ_SHA256,
                "executor_id": "nucleus-self-build/bootstrap", "executor_public_key": public,
                "trust": "disposable experiment, not production executor promotion"
            }))?,
        )?;
        let cert = output.join("cli-cert.pem");
        let key = output.join("cli-key.pem");
        let trust = state.join("ca/ca-cert.pem");
        let http = client(&cert, &key, &trust)?;
        loop {
            ensure!(
                node.try_wait()?.is_none(),
                "bootstrap node exited; see node.log"
            );
            if let Ok(response) = http.get("https://127.0.0.1:18443/v1/health").send()
                && response.status().is_success()
            {
                break;
            }
            ensure!(
                start.elapsed() < Duration::from_secs(90),
                "bootstrap mTLS health check timed out"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        run(Args {
            inputs,
            source_commit,
            node_url: "https://127.0.0.1:18443".into(),
            tls_cert: cert,
            tls_key: key,
            trust_bundle: trust,
            executor_public_key: public,
            executor_id: "nucleus-self-build/bootstrap".into(),
            output: output.join("build"),
        })
    })();
    let stopped = node.kill();
    let reaped = node.wait();
    // Both cleanup operations have already run. Preserve the build failure if
    // the node also exited before kill; cleanup must not hide that diagnosis.
    result?;
    stopped.context("stop bootstrap node")?;
    reaped.context("reap bootstrap node")?;
    Ok(())
}

fn check_bootstrap_socket_paths(output: &Path) -> Result<()> {
    let longest = output
        .join("jailer/firecracker")
        .join("00000000-0000-0000-0000-000000000000")
        .join("root/vsock.sock_4294967295");
    ensure!(
        longest.as_os_str().as_encoded_bytes().len() < 108,
        "bootstrap output path is too long for Linux Unix sockets: {}",
        output.display()
    );
    Ok(())
}

fn mint_client(output: &Path, state: &Path) -> Result<()> {
    let config = output.join("client.cnf");
    fs::write(
        &config,
        "[req]\ndistinguished_name=dn\nreq_extensions=v3\nprompt=no\n[dn]\nCN=nucleus-cli\n[v3]\nsubjectAltName=URI:spiffe://nucleus.local/ns/system/sa/cli\nextendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n",
    )?;
    let key = output.join("cli-key.pem");
    let csr = output.join("cli.csr");
    checked(
        Command::new("openssl")
            .args([
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
            ])
            .arg(&key),
    )?;
    checked(
        Command::new("openssl")
            .args(["req", "-new", "-key"])
            .arg(&key)
            .arg("-out")
            .arg(&csr)
            .arg("-config")
            .arg(&config),
    )?;
    checked(
        Command::new("openssl")
            .args(["x509", "-req", "-in"])
            .arg(csr)
            .arg("-CA")
            .arg(state.join("ca/ca-cert.pem"))
            .arg("-CAkey")
            .arg(state.join("ca/ca-key.pem"))
            .args(["-CAcreateserial", "-out"])
            .arg(output.join("cli-cert.pem"))
            .args(["-days", "1", "-extfile"])
            .arg(config)
            .args(["-extensions", "v3"]),
    )
}

#[derive(clap::Args)]
pub struct EvidenceArgs {
    #[arg(long)]
    experiment: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

pub fn evidence(args: EvidenceArgs) -> Result<()> {
    let EvidenceArgs { experiment, output } = args;
    ensure!(experiment.is_dir(), "experiment directory is absent");
    fs::create_dir(&output).context("evidence output must be a new directory")?;
    for name in [
        "bootstrap-runtime.json",
        "successor-provenance.json",
        "node.log",
        "build/inputs.json",
    ] {
        copy_evidence(&experiment, &output, Path::new(name))?;
    }
    for phase in ["cold", "warm"] {
        for name in [
            "spec.json",
            "expected-execution.json",
            "execution-receipt.json",
            "artifact-receipt.json",
            "timing.json",
            "nucleus-node",
        ] {
            copy_evidence(
                &experiment,
                &output,
                &Path::new("build").join(phase).join(name),
            )?;
        }
    }
    // Host-owned console logs only; never recursively export state (which also
    // contains the CA, executor key, certificate holders and broker secrets).
    let pods = experiment.join("state/pods");
    if pods.try_exists()? {
        for entry in fs::read_dir(pods)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                copy_evidence(
                    &experiment,
                    &output,
                    &Path::new("state/pods")
                        .join(entry.file_name())
                        .join("firecracker.log"),
                )?;
            }
        }
    }
    Ok(())
}

fn copy_evidence(source: &Path, output: &Path, relative: &Path) -> Result<()> {
    let path = source.join(relative);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    ensure!(
        metadata.is_file(),
        "evidence is not a regular file: {}",
        path.display()
    );
    let destination = output.join(relative);
    fs::create_dir_all(destination.parent().context("evidence parent missing")?)?;
    fs::copy(path, &destination)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

#[derive(clap::Args)]
pub struct Args {
    /// Controller-owned inputs.json emitted by build-image on this node host.
    #[arg(long)]
    inputs: PathBuf,
    /// Independent exact source commit expected by the controller.
    #[arg(long)]
    source_commit: String,
    #[arg(long)]
    node_url: String,
    #[arg(long)]
    tls_cert: PathBuf,
    #[arg(long)]
    tls_key: PathBuf,
    #[arg(long)]
    trust_bundle: PathBuf,
    /// Hex public key obtained from the node operator, never the receipt.
    #[arg(long)]
    executor_public_key: String,
    #[arg(long)]
    executor_id: String,
    /// New output directory, on the same host as the node.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Deserialize)]
struct Created {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    receipt: Receipt,
    artifacts: BTreeMap<String, String>,
}

pub fn run(args: Args) -> Result<()> {
    let Args {
        inputs,
        source_commit,
        node_url,
        tls_cert,
        tls_key,
        trust_bundle,
        executor_public_key,
        executor_id,
        output,
    } = args;
    ensure!(
        node_url.starts_with("https://"),
        "the node URL must use mTLS HTTPS"
    );
    let input_bytes = fs::read(&inputs)?;
    let inputs: BuildInputs = serde_json::from_slice(&input_bytes)?;
    ensure!(
        inputs.schema == "nucleus.build-inputs.v1"
            && inputs.architecture == "x86_64"
            && inputs.toolchain == TOOLCHAIN
            && inputs.base_image == RUST_IMAGE,
        "unexpected build input recipe"
    );
    ensure!(
        inputs.source_commit == source_commit,
        "prepared source differs from controller commit"
    );
    ensure!(
        inputs.source_tree == resolve_source(&std::env::current_dir()?, &source_commit)?,
        "prepared tree differs from controller Git object"
    );
    for file in [&inputs.kernel, &inputs.rootfs] {
        ensure!(
            sha256(&file.path)? == file.sha256,
            "prepared image differs from controller manifest: {}",
            file.path.display()
        );
    }
    let key: [u8; 32] = hex::decode(executor_public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("executor key must contain 32 bytes"))?;
    let client = client(&tls_cert, &tls_key, &trust_bundle)?;
    fs::create_dir(&output).context("build output must be a new directory")?;
    let output = output.canonicalize()?;
    fs::write(output.join("inputs.json"), &input_bytes)?;
    let scratch = output.join("scratch.ext4");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&scratch)?
        .set_len(8 * 1024 * 1024 * 1024)?;
    checked(
        Command::new("mke2fs")
            .args(["-q", "-t", "ext4", "-m", "0", "-F"])
            .arg(&scratch),
    )?;
    // Warm means a second real build with the first run's compiler cache, on
    // a new VM. It does not mean a receipt cache hit or cross-tree reuse.
    for phase in ["cold", "warm"] {
        let directory = output.join(phase);
        fs::create_dir(&directory)?;
        let spec = build_spec(&inputs, &scratch, &sha256(&scratch)?)?;
        fs::write(
            directory.join("spec.json"),
            serde_json::to_vec_pretty(&spec)?,
        )?;
        let program = nucleus_spec::identity::program_digest(&spec)
            .map_err(|e| anyhow::anyhow!("build program identity: {e}"))?;
        let workload = spec
            .spec
            .workload
            .as_ref()
            .context("build workload missing")?;
        let env = EnvironmentIdentity::of(&workload.env);
        let started = now()?;
        let deadline = started
            .checked_add(3600 * 1_000_000)
            .context("build deadline overflow")?;
        let timer = Instant::now();
        let create_response = client
            .post(format!("{}/v1/pods", node_url.trim_end_matches('/')))
            .json(&serde_json::json!({ "spec": spec }))
            .send()?;
        let created: Created = response_json_checked(create_response, 16 * 1024)?;
        // The ID is used as a URL segment and session binding, never as a path.
        ensure!(
            created.id.len() == 36
                && created
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || b == b'-'),
            "invalid pod ID"
        );
        let pod_url = format!("{}/v1/pods/{}", node_url.trim_end_matches('/'), created.id);
        let expected = ExpectedExecution {
            pod_id: &created.id,
            source_commit: &inputs.source_commit,
            source_tree: &inputs.source_tree,
            gate: "cargo-build-nucleus-node-v1",
            session_id: &created.id,
            program_digest: &program,
            architecture: &inputs.architecture,
            environment_inputs_sha256: &env.inputs_sha256,
            artifacts: &workload.artifacts,
            issuer_kid: &executor_id,
            verifying_key: &key,
            issued_not_before_micros: started,
            issued_not_after_micros: deadline,
        };
        // Persist the controller's values before collecting any returned claim.
        // An offline verifier must not reconstruct these from the receipt.
        let result = (|| -> Result<()> {
            fs::write(
                directory.join("expected-execution.json"),
                serde_json::to_vec_pretty(&expected)?,
            )?;
            collect(&client, &pod_url, &expected, &directory)
        })();
        // Cancellation is attempted on both success and failure. A failure to
        // stop the VM prevents a warm run from sharing its writable disk.
        let cancelled = client
            .post(format!("{pod_url}/cancel"))
            .send()
            .and_then(reqwest::blocking::Response::error_for_status);
        result?;
        cancelled.context("could not stop build VM; refusing shared scratch reuse")?;
        fs::write(
            directory.join("timing.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "phase": phase, "wall_seconds": timer.elapsed().as_secs_f64(),
                "scope": "launch through verified artifact retrieval and cancellation",
                "pod_id": created.id, "source_commit": inputs.source_commit,
                "source_tree": inputs.source_tree, "program_digest": program,
            }))?,
        )?;
        println!(
            "{phase}: verified nucleus-node artifact in {:.3}s",
            timer.elapsed().as_secs_f64()
        );
    }
    Ok(())
}

fn client(cert: &Path, key: &Path, bundle: &Path) -> Result<Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut identity = fs::read(cert)?;
    identity.extend_from_slice(&fs::read(key)?);
    Ok(Client::builder()
        .identity(reqwest::Identity::from_pem(&identity)?)
        .tls_certs_only(reqwest::Certificate::from_pem_bundle(&fs::read(bundle)?)?)
        // Node SVIDs have a SPIFFE URI SAN, not a DNS SAN. Chain validation is
        // retained against ONLY the explicitly supplied node trust bundle.
        .danger_accept_invalid_hostnames(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(120))
        .build()?)
}

fn collect(
    client: &Client,
    pod_url: &str,
    expected: &ExpectedExecution<'_>,
    directory: &Path,
) -> Result<()> {
    loop {
        ensure!(
            now()? <= expected.issued_not_after_micros,
            "build timed out"
        );
        let response = client.get(format!("{pod_url}/workload-result")).send()?;
        // The node may not have a proxy address while the VM boots. Do not
        // reinterpret that transient absence as success, or retry auth errors.
        if response.status().is_server_error() {
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }
        let result: WorkloadResult = response_json(response.error_for_status()?, 16 * 1024)?;
        match result {
            WorkloadResult::Running => std::thread::sleep(Duration::from_secs(2)),
            WorkloadResult::Exited {
                exit_code: _,
                stdout_sha256: _,
                stderr_sha256: _,
                launch_hash: _,
                environment: _,
                program: _,
                isolation: _,
            } => break,
            other => bail!("workload cannot produce a build observation: {other:?}"),
        }
    }
    let receipt: Receipt = response_json(
        client
            .get(format!("{pod_url}/execution-receipt"))
            .send()?
            .error_for_status()?,
        128 * 1024,
    )?;
    fs::write(
        directory.join("execution-receipt.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    // Authenticate a failure too. A missing output must not obscure the signed
    // exit or allow a stale binary in the warm cache to turn failure green.
    let none = BTreeMap::new();
    let ExpectedExecution {
        pod_id,
        source_commit,
        source_tree,
        gate,
        program_digest,
        architecture,
        environment_inputs_sha256,
        artifacts: _,
        session_id,
        issuer_kid,
        verifying_key,
        issued_not_before_micros,
        issued_not_after_micros,
    } = expected;
    let empty_expected = ExpectedExecution {
        pod_id,
        source_commit,
        source_tree,
        gate,
        program_digest,
        architecture,
        environment_inputs_sha256,
        artifacts: &none,
        session_id,
        issuer_kid,
        verifying_key,
        issued_not_before_micros: *issued_not_before_micros,
        issued_not_after_micros: *issued_not_after_micros,
    };
    let claim = verify_execution(&receipt, &empty_expected)?.into_claim(now()?)?;
    ensure!(
        claim.exit_code == Some(0),
        "supervisor observed build failure: {:?}",
        claim.exit_code
    );
    let bundle: Bundle = response_json(
        client
            .post(format!("{pod_url}/execution-receipt"))
            .json(&serde_json::json!({"artifacts": expected.artifacts}))
            .send()?
            .error_for_status()?,
        360 * 1024 * 1024,
    )?;
    let mut bytes = BTreeMap::new();
    for (name, value) in bundle.artifacts {
        bytes.insert(
            name,
            base64::engine::general_purpose::STANDARD.decode(value)?,
        );
    }
    let verified = verify_artifacts(&bundle.receipt, expected, bytes)?;
    let (claim, mut bytes) = verified.into_parts(now()?)?;
    ensure!(
        claim.exit_code == Some(0),
        "artifact receipt does not attest a successful build"
    );
    let binary = bytes
        .remove("nucleus-node")
        .context("verified node artifact missing")?;
    fs::write(directory.join("nucleus-node"), binary)?;
    fs::write(
        directory.join("artifact-receipt.json"),
        serde_json::to_vec_pretty(&bundle.receipt)?,
    )?;
    Ok(())
}

fn response_json<T: serde::de::DeserializeOwned>(
    response: reqwest::blocking::Response,
    limit: u64,
) -> Result<T> {
    let mut bytes = Vec::new();
    response
        .take(limit.checked_add(1).context("response limit overflow")?)
        .read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? <= limit,
        "node response exceeds size limit"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn response_json_checked<T: serde::de::DeserializeOwned>(
    response: reqwest::blocking::Response,
    limit: u64,
) -> Result<T> {
    let status = response.status();
    let mut bytes = Vec::new();
    response
        .take(limit.checked_add(1).context("response limit overflow")?)
        .read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? <= limit,
        "node response exceeds size limit"
    );
    if !status.is_success() {
        bail!(
            "node refused pod creation ({status}): {}",
            String::from_utf8_lossy(&bytes)
        );
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn now() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros(),
    )?)
}

fn build_spec(
    inputs: &BuildInputs,
    scratch: &Path,
    scratch_sha256: &str,
) -> Result<nucleus_spec::PodSpec> {
    let compiler_bin =
        format!("/usr/local/rustup/toolchains/{TOOLCHAIN}-x86_64-unknown-linux-gnu/bin");
    let env = BTreeMap::from([
        (
            "PATH",
            format!("{compiler_bin}:/usr/local/bin:/usr/bin:/bin"),
        ),
        ("HOME", "/work".into()),
        ("LANG", "C.UTF-8".into()),
        ("TZ", "UTC".into()),
        ("CARGO_HOME", "/work/cargo-home".into()),
        ("RUSTC", format!("{compiler_bin}/rustc")),
        ("CARGO_INCREMENTAL", "0".into()),
        ("CARGO_PROFILE_DEV_DEBUG", "0".into()),
        ("CARGO_PROFILE_TEST_DEBUG", "0".into()),
        ("CARGO_BUILD_JOBS", "2".into()),
    ]);
    let mut spec: nucleus_spec::PodSpec = serde_json::from_value(serde_json::json!({
        "apiVersion": "nucleus/v1", "kind": "Pod",
        "metadata": { "name": "nucleus-self-build", "labels": {
            "build.source.commit": inputs.source_commit, "build.source.tree": inputs.source_tree,
            "build.source.archive": inputs.source_archive_sha256, "build.gate": "cargo-build-nucleus-node-v1"
        }},
        "spec": { "work_dir": "/work", "timeout_seconds": 3600,
            "resources": {"cpu_cores": 2, "memory_mib": 6144},
            "policy": {"type": "profile", "name": "demo"},
            "network": {"allow": [], "deny": []},
            "vsock": {"guest_cid": 3, "port": 5005},
            "image": {"kernel_path": inputs.kernel.path, "kernel_digest": format!("sha-256:{}", inputs.kernel.sha256),
                "rootfs_path": inputs.rootfs.path, "rootfs_digest": format!("sha-256:{}", inputs.rootfs.sha256),
                "read_only": true, "scratch_path": scratch, "scratch_digest": format!("sha-256:{scratch_sha256}")},
            "workload": {"command": format!("{compiler_bin}/cargo"),
                "args": ["build", "--offline", "--locked", "-p", "nucleus-node", "--manifest-path",
                    "/opt/nucleus-build/source/Cargo.toml", "--target-dir", "/work/target",
                    "--config", "/opt/nucleus-build/cargo-config.toml"],
                "env": env, "uid": 65534, "artifacts": {"nucleus-node": "target/debug/nucleus-node"}}
        }
    }))?;
    // The node issues an inline effective lattice. Submit that same explicit
    // lattice, so the independently computed program identity does not depend
    // on a profile name becoming inline during admission. Attenuation beyond
    // this request is still a mismatch and must be refused by verification.
    let lattice = spec.spec.resolve_policy()?;
    let isolation = portcullis::enforcement::require_isolation(
        lattice.effective_minimum_isolation(),
        &portcullis::enforcement::BackendCapability::FIRECRACKER,
    )?;
    spec.record_isolation(isolation);
    spec.spec.policy = nucleus_spec::PolicySpec::Inline {
        lattice: Box::new(if isolation.was_strengthened() {
            lattice.with_minimum_isolation(isolation.enforced)
        } else {
            lattice
        }),
    };
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> BuildInputs {
        BuildInputs {
            schema: "nucleus.build-inputs.v1".into(),
            architecture: "x86_64".into(),
            source_commit: "a".repeat(40),
            source_tree: "b".repeat(40),
            source_archive_sha256: "c".repeat(64),
            toolchain: TOOLCHAIN.into(),
            base_image: RUST_IMAGE.into(),
            bootstrap: BTreeMap::new(),
            kernel: InputFile {
                path: "/images/kernel".into(),
                sha256: "d".repeat(64),
            },
            rootfs: InputFile {
                path: "/images/rootfs".into(),
                sha256: "e".repeat(64),
            },
        }
    }

    #[test]
    fn bootstrap_layout_fits_linux_socket_paths() {
        assert!(check_bootstrap_socket_paths(Path::new("/tmp/nucleus-self-run")).is_ok());
        assert!(
            check_bootstrap_socket_paths(Path::new(&format!("/tmp/{}", "x".repeat(50)))).is_err()
        );
        // This was the real failed experiment's host-side vsock address.
        let old = "/tmp/nucleus-self-run/jailer/firecracker-v1.16.1-x86_64/00000000-0000-0000-0000-000000000000/root/vsock.sock_15012";
        assert!(old.len() >= 108);
    }

    #[test]
    fn build_request_binds_source_images_environment_and_declared_binary() -> Result<()> {
        let mut inputs = inputs();
        let scratch = Path::new("/images/scratch");
        let spec = build_spec(&inputs, scratch, &"f".repeat(64))?;
        let digest = nucleus_spec::identity::program_digest(&spec).unwrap();
        assert!(matches!(
            spec.spec.policy,
            nucleus_spec::PolicySpec::Inline { .. }
        ));
        let workload = spec.spec.workload.as_ref().unwrap();
        assert_eq!(
            workload.artifacts.get("nucleus-node").map(String::as_str),
            Some("target/debug/nucleus-node")
        );
        assert!(workload.args.iter().any(|a| a == "--offline"));
        inputs.source_commit = "0".repeat(40);
        let changed = build_spec(&inputs, scratch, &"f".repeat(64))?;
        assert_ne!(
            digest,
            nucleus_spec::identity::program_digest(&changed).unwrap()
        );
        let mut changed = spec.clone();
        changed
            .spec
            .workload
            .as_mut()
            .unwrap()
            .env
            .insert("CARGO_BUILD_JOBS".into(), "3".into());
        assert_ne!(
            digest,
            nucleus_spec::identity::program_digest(&changed).unwrap()
        );
        assert_ne!(
            EnvironmentIdentity::of(&workload.env),
            EnvironmentIdentity::of(&changed.spec.workload.as_ref().unwrap().env)
        );
        let mut changed = spec.clone();
        changed.spec.image.as_mut().unwrap().rootfs_digest = Some(
            nucleus_spec::ArtifactDigest::parse(&format!("sha-256:{}", "0".repeat(64))).unwrap(),
        );
        assert_ne!(
            digest,
            nucleus_spec::identity::program_digest(&changed).unwrap()
        );
        Ok(())
    }

    #[test]
    fn exporting_failure_evidence_does_not_export_private_state() -> Result<()> {
        let root = tempfile::tempdir()?;
        let experiment = root.path().join("experiment");
        fs::create_dir_all(experiment.join("state/ca"))?;
        fs::write(experiment.join("state/ca/ca-key.pem"), "private canary")?;
        fs::write(
            experiment.join("state/executor_signing_key.der"),
            "private canary",
        )?;
        fs::write(experiment.join("cli-key.pem"), "private canary")?;
        fs::write(experiment.join("node.log"), "public failure")?;
        let output = root.path().join("public");
        evidence(EvidenceArgs {
            experiment,
            output: output.clone(),
        })?;
        assert_eq!(
            fs::read_to_string(output.join("node.log"))?,
            "public failure"
        );
        assert!(!output.join("state/ca/ca-key.pem").exists());
        assert!(!output.join("state/executor_signing_key.der").exists());
        assert!(!output.join("cli-key.pem").exists());
        Ok(())
    }
}
