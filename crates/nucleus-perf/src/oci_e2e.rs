//! OCI-H: a user's OCI image boots as a healthy nucleus Firecracker pod, end to end.
//!
//! Run from the Mac, with the Lima VM `nucleus` up:
//!
//! ```text
//! NUCLEUS_OCI_E2E=1 cargo test -p nucleus-perf oci_e2e -- --ignored --nocapture
//! ```
//!
//! # What it drives, in order
//!
//! 1. `cargo xtask guest-layer --arch aarch64` — the guest layer from THIS tree.
//! 2. Apple `container build` of a placeholder agent image (debian, `USER 1000:1000`), saved
//!    with `container image save` as an oci-archive.
//! 3. `nucleus image import --oci-archive … --guest-layer …` on the Mac (stage one), then
//!    `nucleus-hostctl image build` twice in a `debian:trixie` container (stage two: the
//!    deterministic ext4 needs e2fsprogs >= 1.47.1, which the VM does not have).
//! 4. A SCRATCH `nucleus-node` built from this tree, started on the VM as a transient
//!    systemd unit with its own state dir, port, image root and jailer base. The installed
//!    node service is not touched.
//! 5. One pod: `rootfs_oci` + `rootfs_digest` from the store, every image digest pinned, the
//!    workload taken from the image's own config (entrypoint, cmd, env, user) as the import
//!    record states it, and one allowlisted egress destination.
//!
//! # What it asserts, and against what
//!
//! Every claim is read from the node or the pod, never from the harness's own intent:
//!
//! - **healthy, attested** — the pod's tool-proxy `/v1/health` says `attested`;
//! - **uid** — the workload's stdout, served by the node (`workload-logs/stdout`), prints
//!   `id` as the image's user;
//! - **/work writable** — the file the workload wrote is collected by the node's mediated
//!   artifact reader and signed into an execution receipt;
//! - **egress** — the allowlisted destination connected, the other one did not, the VM
//!   itself reaches that other one (so the block is the pod's fence, not the internet), and
//!   the guest's own probe printed `NUCLEUS_EGRESS_PROBE: PASS`;
//! - **attestation** — the SVID the node serves the pod over its workload-API socket is
//!   verified by `nucleus verify-attestation` against the imported rootfs digest, and
//!   refused against a different one (so the check has teeth);
//! - **provenance** — the signed pod receipt carries the image reference, manifest digest
//!   and guest-layer digest;
//! - **determinism** — two stage-two builds of the same inputs give one ext4 digest, and
//!   the Mac's own sha256 of the copied bytes is that digest.
//!
//! # What it leaves behind
//!
//! Nothing it created: the pod, the scratch node unit, its VM directory, the stage-two
//! container and the image are removed on every exit, pass or fail. `NUCLEUS_OCI_E2E_KEEP=1`
//! keeps the Mac work dir (`target/oci-e2e`) for inspection.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use nucleus_oci_rootfs::ImportRecord;
use nucleus_spec::ArtifactDigest;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::node_mtls::{Node, NodeTls};

/// The image tag. `nucleus-dev-*` so a stray one is recognisably this harness's.
const IMAGE_TAG: &str = "nucleus-dev-oci-e2e:e2e";
/// The stage-two container.
const STAGE_TWO: &str = "nucleus-dev-oci-e2e-stage2";
/// The scratch node's transient systemd unit on the VM.
const NODE_UNIT: &str = "nucleus-oci-e2e-node";
/// The scratch node's directory under the VM user's home.
const VM_DIR: &str = "oci-e2e";
/// The file the workload writes under `/work`, and the name it is collected by.
const OUTPUT_FILE: &str = "agent-output.txt";
const OUTPUT_ARTIFACT: &str = "agent_output";

/// The placeholder agent: prints who it runs as, writes under `/work`, then attempts a TCP
/// connect to every `host:port` argument. It knows nothing about nucleus.
const AGENT_SCRIPT: &str = r#"#!/bin/bash
echo "AGENT_ID: $(id)"
if echo "written by the agent as uid $(id -u)" > /work/agent-output.txt; then
  echo "AGENT_WORK: wrote /work/agent-output.txt"
else
  echo "AGENT_WORK: FAILED"
fi
for target in "$@"; do
  host=${target%:*}
  port=${target##*:}
  if timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
    echo "AGENT_CONNECT: $target CONNECTED"
  else
    echo "AGENT_CONNECT: $target BLOCKED"
  fi
done
sync
"#;

/// Everything the run needs from its environment, with the defaults the Lima VM has.
struct Config {
    repo: PathBuf,
    work: PathBuf,
    vm: String,
    port: u16,
    kernel: String,
    allowed: String,
    denied: String,
    keep_work: bool,
}

impl Config {
    fn from_env() -> Result<Self> {
        let var = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .context("repository root")?;
        Ok(Self {
            work: repo.join("target").join("oci-e2e"),
            repo,
            vm: var("NUCLEUS_OCI_E2E_VM", "nucleus"),
            port: var("NUCLEUS_OCI_E2E_PORT", "18480")
                .parse()
                .context("NUCLEUS_OCI_E2E_PORT")?,
            kernel: var(
                "NUCLEUS_OCI_E2E_KERNEL",
                "/var/lib/nucleus/artifacts/vmlinux",
            ),
            // Two public resolvers' TLS ports: stable, and neither is one of the egress
            // probe's own deny targets, so the probe and the agent observe different edges.
            allowed: var("NUCLEUS_OCI_E2E_ALLOWED", "9.9.9.9:443"),
            denied: var("NUCLEUS_OCI_E2E_DENIED", "208.67.222.222:443"),
            keep_work: std::env::var("NUCLEUS_OCI_E2E_KEEP").as_deref() == Ok("1"),
        })
    }

    fn containerfile(&self) -> String {
        format!(
            "FROM docker.io/library/debian:bookworm-slim\n\
             RUN groupadd -g 1000 agent && useradd -u 1000 -g 1000 -M -d /work/.home -s /bin/bash agent\n\
             COPY agent /usr/local/bin/agent\n\
             RUN chmod 0755 /usr/local/bin/agent\n\
             USER 1000:1000\n\
             ENTRYPOINT [\"/usr/local/bin/agent\"]\n\
             CMD [\"{}\", \"{}\"]\n",
            self.allowed, self.denied
        )
    }
}

/// What the run observed. Printed at the end; each field is the evidence for one assertion.
struct Evidence {
    guest_layer: ArtifactDigest,
    image_index: String,
    manifest: String,
    rootfs: ArtifactDigest,
    observed: Observed,
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

fn run(what: &str, cmd: &mut Command) -> Result<String> {
    run_with_stdin(what, cmd, None)
}

/// Run to completion; stdout on success, and on failure an error carrying stderr's tail.
fn run_with_stdin(what: &str, cmd: &mut Command, stdin: Option<&[u8]>) -> Result<String> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = cmd
        .spawn()
        .with_context(|| format!("{what}: could not start {:?}", cmd.get_program()))?;
    if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(bytes)
            .with_context(|| format!("{what}: writing stdin"))?;
    }
    let out = child
        .wait_with_output()
        .with_context(|| format!("{what}: waiting"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        let tail: Vec<&str> = stderr.lines().rev().take(15).collect();
        bail!(
            "{what}: {} ({})\n{}",
            out.status,
            cmd.get_args()
                .map(|a| a.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" "),
            tail.into_iter().rev().collect::<Vec<_>>().join("\n")
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A command inside the VM.
fn vm(cfg: &Config) -> Command {
    let mut c = Command::new("limactl");
    c.args(["shell", &cfg.vm, "--"]);
    c
}

fn cargo(cfg: &Config) -> Command {
    let mut c = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    c.current_dir(&cfg.repo);
    c
}

fn target_dir(cfg: &Config) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| cfg.repo.join("target"))
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// The one line of `text` starting with `prefix`, with the prefix removed and trimmed.
fn field<'a>(text: &'a str, prefix: &str) -> Result<&'a str> {
    let mut hits = text.lines().filter_map(|l| l.strip_prefix(prefix));
    let first = hits
        .next()
        .with_context(|| format!("no `{prefix}` line in:\n{text}"))?;
    ensure!(
        hits.next().is_none(),
        "more than one `{prefix}` line in:\n{text}"
    );
    Ok(first.trim())
}

fn random_hex() -> Result<String> {
    use ring::rand::SecureRandom as _;
    let mut b = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| anyhow::anyhow!("system RNG failed"))?;
    Ok(hex::encode(b))
}

fn poll<T>(what: &str, within: Duration, mut f: impl FnMut() -> Result<Option<T>>) -> Result<T> {
    let start = Instant::now();
    let mut last = String::from("never answered");
    while start.elapsed() < within {
        match f() {
            Ok(Some(v)) => return Ok(v),
            Ok(None) => {}
            Err(e) => last = format!("{e:#}"),
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    bail!("{what}: not within {within:?} ({last})")
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

/// What the run created, undone in reverse on drop — on a pass, a failed assertion, or a
/// panic alike. Each undo is best effort and reports its own failure.
#[derive(Default)]
struct Cleanup {
    undo: Vec<(String, Command)>,
    work: Option<PathBuf>,
}

impl Cleanup {
    fn push(&mut self, what: &str, cmd: Command) {
        self.undo.push((what.to_string(), cmd));
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        while let Some((what, mut cmd)) = self.undo.pop() {
            match run(&what, &mut cmd) {
                Ok(_) => eprintln!("cleanup: {what}"),
                Err(e) => eprintln!("cleanup FAILED: {e:#}"),
            }
        }
        if let Some(work) = self.work.take()
            && let Err(e) = std::fs::remove_dir_all(&work)
        {
            eprintln!("cleanup FAILED: removing {}: {e}", work.display());
        }
    }
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/// Step 1: the guest layer from this tree.
fn guest_layer(cfg: &Config) -> Result<(PathBuf, ArtifactDigest)> {
    let out = cfg.work.join("guest.tar");
    let stdout = run(
        "cargo xtask guest-layer",
        cargo(cfg)
            .args(["xtask", "guest-layer", "--arch", "aarch64", "--out"])
            .arg(&out),
    )?;
    let line = stdout
        .lines()
        .rev()
        .find(|l| l.starts_with("sha-256:"))
        .with_context(|| format!("guest-layer printed no digest:\n{stdout}"))?;
    let digest = ArtifactDigest::parse(line.trim()).map_err(anyhow::Error::msg)?;
    ensure!(
        sha256_file(&out)? == digest.hex(),
        "the guest layer's printed digest is not its file's"
    );
    Ok((out, digest))
}

/// Step 1b: the static binaries the VM and the stage-two container run, and the Mac's CLI.
fn binaries(cfg: &Config) -> Result<(PathBuf, PathBuf)> {
    let triple = "aarch64-unknown-linux-musl";
    run(
        "cargo zigbuild (linux binaries)",
        cargo(cfg).args([
            "zigbuild",
            "--release",
            "--target",
            triple,
            "-p",
            "nucleus-node",
            "--bin",
            "nucleus-node",
            "-p",
            "nucleus-microvm-host",
            "--bin",
            "nucleus-hostctl",
        ]),
    )?;
    let bin = cfg.work.join("bin");
    std::fs::create_dir_all(&bin)?;
    for name in ["nucleus-node", "nucleus-hostctl"] {
        let from = target_dir(cfg).join(triple).join("release").join(name);
        std::fs::copy(&from, bin.join(name)).with_context(|| format!("{}", from.display()))?;
    }
    run(
        "cargo build (the Mac's nucleus CLI)",
        cargo(cfg).args(["build", "-p", "nucleus-cli", "--bin", "nucleus"]),
    )?;
    Ok((bin, target_dir(cfg).join("debug").join("nucleus")))
}

/// Step 2: build and save the user image; its index digest.
fn user_image(cfg: &Config, cleanup: &mut Cleanup) -> Result<(PathBuf, String)> {
    let ctx = cfg.work.join("image");
    std::fs::create_dir_all(&ctx)?;
    std::fs::write(ctx.join("agent"), AGENT_SCRIPT)?;
    std::fs::write(ctx.join("Containerfile"), cfg.containerfile())?;
    let builder_existed = run(
        "container list",
        Command::new("container").args(["list", "--all"]),
    )?
    .lines()
    .any(|l| l.starts_with("buildkit "));
    run(
        "container build",
        Command::new("container")
            .args([
                "build",
                "--progress",
                "plain",
                "--platform",
                "linux/arm64",
                "-t",
                IMAGE_TAG,
            ])
            .arg(&ctx),
    )?;
    if !builder_existed {
        // Undone in reverse: stopped, then deleted.
        let mut delete = Command::new("container");
        delete.args(["builder", "delete"]);
        cleanup.push("delete the image builder this run created", delete);
        let mut stop = Command::new("container");
        stop.args(["builder", "stop"]);
        cleanup.push("stop the image builder this run started", stop);
    }
    let mut rm = Command::new("container");
    rm.args(["image", "delete", IMAGE_TAG]);
    cleanup.push("delete the user image", rm);

    let archive = cfg.work.join("agent.oci.tar");
    run(
        "container image save",
        Command::new("container")
            .args(["image", "save", "-o"])
            .arg(&archive)
            .arg(IMAGE_TAG),
    )?;
    let index = read_archive_member(&archive, "index.json")?;
    let index: Value = serde_json::from_slice(&index).context("index.json")?;
    let manifests = index["manifests"]
        .as_array()
        .context("index.json has no manifests")?;
    ensure!(
        manifests.len() == 1,
        "one image saved, {} manifests",
        manifests.len()
    );
    let digest = manifests[0]["digest"]
        .as_str()
        .context("manifest digest")?
        .to_string();
    Ok((archive, digest))
}

fn read_archive_member(archive: &Path, name: &str) -> Result<Vec<u8>> {
    let file = std::fs::File::open(archive)?;
    let mut tar = tar::Archive::new(file);
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().into_owned();
        if path.trim_start_matches("./") == name {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut bytes)?;
            return Ok(bytes);
        }
    }
    bail!("{} has no {name}", archive.display())
}

/// Step 3a: stage one on the Mac. The flattened tar's directory and its import record.
fn stage_one(
    cfg: &Config,
    cli: &Path,
    archive: &Path,
    index: &str,
    guest: &Path,
) -> Result<(String, ImportRecord)> {
    let stdout = run(
        "nucleus image import (stage one)",
        Command::new(cli)
            .args(["image", "import", "--oci-archive"])
            .arg(archive)
            .arg(index)
            .args(["--arch", "arm64", "--cache-dir"])
            .arg(cfg.work.join("cache"))
            .arg("--guest-layer")
            .arg(guest)
            .arg("--image-root")
            .arg(cfg.work.join("images-unused")),
    )?;
    // `rootfs     sha256:<hex> (<n> bytes)`
    let tar_hex = field(&stdout, "rootfs")?
        .strip_prefix("sha256:")
        .and_then(|r| r.split_whitespace().next())
        .context("rootfs line")?
        .to_string();
    let record_path = cfg
        .work
        .join("cache/rootfs/sha256")
        .join(&tar_hex)
        .join("import.json");
    let record: ImportRecord = serde_json::from_slice(&std::fs::read(&record_path)?)
        .with_context(|| record_path.display().to_string())?;
    ensure!(
        record.pinned.to_string() == index,
        "the import record pins {}, not {index}",
        record.pinned
    );
    Ok((tar_hex, record))
}

/// Step 3b: stage two, twice, in a trixie container; the ext4 digest both builds agree on.
fn stage_two(
    cfg: &Config,
    tar_hex: &str,
    guest: &ArtifactDigest,
    record: &ImportRecord,
    cleanup: &mut Cleanup,
) -> Result<ArtifactDigest> {
    // A stale one from an interrupted run would hold the name.
    let _ = run(
        "remove a stale stage-two container",
        Command::new("container").args(["delete", "--force", STAGE_TWO]),
    );
    run(
        "container run (stage two)",
        Command::new("container")
            .args([
                "run", "-d", "--name", STAGE_TWO, "-c", "4", "-m", "4G", "-v",
            ])
            .arg(format!("{}:/w", cfg.work.display()))
            .args(["docker.io/library/debian:trixie", "sleep", "infinity"]),
    )?;
    let mut rm = Command::new("container");
    rm.args(["delete", "--force", STAGE_TWO]);
    cleanup.push("delete the stage-two container", rm);
    let exec = || {
        let mut c = Command::new("container");
        c.args(["exec", STAGE_TWO]);
        c
    };
    run("apt-get update", exec().args(["apt-get", "update", "-qq"]))?;
    run(
        "install e2fsprogs",
        exec().args([
            "apt-get",
            "install",
            "-y",
            "-qq",
            "--no-install-recommends",
            "e2fsprogs",
            "libarchive13t64",
        ]),
    )?;
    let entry = format!("/w/cache/rootfs/sha256/{tar_hex}");
    let mut digests = Vec::new();
    for store in ["/root/store-a", "/root/store-b"] {
        let json = run(
            "nucleus-hostctl image build",
            exec()
                .arg("/w/bin/nucleus-hostctl")
                .args(["image", "build"])
                .arg(format!("{entry}/rootfs.tar"))
                .arg("--import-record")
                .arg(format!("{entry}/import.json"))
                .args(["--guest-layer", "/w/guest.tar", "--image-root", store]),
        )?;
        let v: Value = serde_json::from_str(&json).context("hostctl output")?;
        ensure!(
            v["reused"] == json!(false),
            "{store}: not a fresh build: {v}"
        );
        ensure!(
            v["guest_layer_digest"] == json!(guest.as_str()),
            "stage two used another guest layer: {v}"
        );
        ensure!(
            v["manifest_digest"] == json!(record.manifest_digest.to_string()),
            "stage two built another manifest: {v}"
        );
        let d = v["rootfs_digest"].as_str().context("rootfs_digest")?;
        digests.push(ArtifactDigest::parse(d).map_err(anyhow::Error::msg)?);
    }
    ensure!(
        digests[0] == digests[1],
        "stage two is not deterministic: {} vs {}",
        digests[0].as_str(),
        digests[1].as_str()
    );
    let rootfs = digests.swap_remove(0);
    run(
        "copy the store entry out",
        exec()
            .args(["cp", "-a"])
            .arg(format!("/root/store-a/sha256/{}", rootfs.hex()))
            .arg("/w/store-entry"),
    )?;
    // A third opinion on the bytes, from the machine that did not build them.
    ensure!(
        sha256_file(&cfg.work.join("store-entry/rootfs.ext4"))? == rootfs.hex(),
        "the copied rootfs.ext4 does not hash to its store digest"
    );
    Ok(rootfs)
}

/// The scratch node on the VM, reached over mTLS.
struct ScratchNode {
    node: Node,
    dir: String,
}

/// Step 4: start the scratch node and mint a client identity against its CA.
fn scratch_node(
    cfg: &Config,
    bin: &Path,
    rootfs: &ArtifactDigest,
    cleanup: &mut Cleanup,
) -> Result<ScratchNode> {
    let home = run("VM home", vm(cfg).args(["printenv", "HOME"]))?
        .trim()
        .to_string();
    let user = run("VM user", vm(cfg).args(["id", "-un"]))?
        .trim()
        .to_string();
    let dir = format!("{home}/{VM_DIR}");
    let _ = run(
        "stop a stale scratch node",
        vm(cfg).args(["sudo", "systemctl", "stop", NODE_UNIT]),
    );
    run(
        "clear the scratch dir",
        vm(cfg).args(["sudo", "rm", "-rf", &dir]),
    )?;
    let mut rm = vm(cfg);
    rm.args(["sudo", "rm", "-rf", &dir]);
    cleanup.push("remove the scratch node's VM directory", rm);
    for sub in ["images/sha256", "jailer", "client"] {
        run(
            "mkdir",
            vm(cfg).args(["mkdir", "-p", &format!("{dir}/{sub}")]),
        )?;
    }
    let copy = |from: &Path, to: &str, recursive: bool| -> Result<String> {
        let mut c = Command::new("limactl");
        c.arg("copy");
        if recursive {
            c.arg("-r");
        }
        c.arg(from).arg(format!("{}:{to}", cfg.vm));
        run("limactl copy", &mut c)
    };
    copy(
        &bin.join("nucleus-node"),
        &format!("{dir}/nucleus-node"),
        false,
    )?;
    copy(
        &cfg.work.join("store-entry"),
        &format!("{dir}/images/sha256/{}", rootfs.hex()),
        true,
    )?;

    let artifacts = Path::new(&cfg.kernel)
        .parent()
        .context("kernel path has no directory")?
        .display()
        .to_string();
    run(
        "start the scratch node",
        vm(cfg)
            .args([
                "sudo",
                "systemd-run",
                "--collect",
                &format!("--unit={NODE_UNIT}"),
            ])
            .arg(format!(
                "--setenv=NUCLEUS_NODE_PROXY_AUTH_SECRET={}",
                random_hex()?
            ))
            .arg(format!(
                "--setenv=NUCLEUS_NODE_PROXY_APPROVAL_SECRET={}",
                random_hex()?
            ))
            .arg("--setenv=RUST_LOG=info")
            .arg(format!("{dir}/nucleus-node"))
            .args(["--listen", &format!("127.0.0.1:{}", cfg.port)])
            .args(["--state-dir", &format!("{dir}/state")])
            .args(["--artifacts-root", &artifacts])
            .args(["--image-root", &format!("{dir}/images")])
            .args([
                "--identity-workload-api-socket",
                &format!("{dir}/wapi.sock"),
            ])
            .args(["--firecracker-path", "/usr/local/bin/firecracker"])
            .args(["--jailer-path", "/usr/local/bin/jailer"])
            .args(["--jailer-chroot-base", &format!("{dir}/jailer")]),
    )?;
    let mut stop = vm(cfg);
    stop.args(["sudo", "systemctl", "stop", NODE_UNIT]);
    cleanup.push("stop the scratch node", stop);

    let ca = format!("{dir}/state/ca");
    poll("the scratch node's CA", Duration::from_secs(30), || {
        Ok(run(
            "CA",
            vm(cfg).args(["sudo", "test", "-f", &format!("{ca}/ca-cert.pem")]),
        )
        .ok())
    })?;
    // The client identity: signed in place by the node's CA, whose key never leaves the VM.
    let client = format!("{dir}/client");
    std::fs::write(
        cfg.work.join("client.ext"),
        "subjectAltName=URI:spiffe://nucleus.local/ns/system/sa/cli\nextendedKeyUsage=clientAuth\n",
    )?;
    copy(
        &cfg.work.join("client.ext"),
        &format!("{client}/ext"),
        false,
    )?;
    run(
        "client key",
        vm(cfg).args([
            "openssl",
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            &format!("{client}/cli.key"),
            "-subj",
            "/CN=cli",
            "-out",
            &format!("{client}/cli.csr"),
        ]),
    )?;
    run(
        "client cert",
        vm(cfg).args([
            "sudo",
            "openssl",
            "x509",
            "-req",
            "-in",
            &format!("{client}/cli.csr"),
            "-CA",
            &format!("{ca}/ca-cert.pem"),
            "-CAkey",
            &format!("{ca}/ca-key.pem"),
            "-CAcreateserial",
            "-CAserial",
            &format!("{client}/ca.srl"),
            "-days",
            "1",
            "-out",
            &format!("{client}/cli.crt"),
            "-extfile",
            &format!("{client}/ext"),
        ]),
    )?;
    run(
        "copy the CA cert",
        vm(cfg).args(["cp", &format!("{ca}/ca-cert.pem"), &client]),
    )?;
    run(
        "own the client files",
        vm(cfg).args(["sudo", "chown", "-R", &user, &client]),
    )?;
    let local = cfg.work.join("client");
    std::fs::create_dir_all(&local)?;
    for f in ["cli.crt", "cli.key", "ca-cert.pem"] {
        let mut c = Command::new("limactl");
        c.arg("copy")
            .arg(format!("{}:{client}/{f}", cfg.vm))
            .arg(local.join(f));
        run("limactl copy (client)", &mut c)?;
    }
    let node = Node::connect(
        &format!("https://127.0.0.1:{}", cfg.port),
        &NodeTls {
            tls_cert: Some(local.join("cli.crt")),
            tls_key: Some(local.join("cli.key")),
            trust_bundle: Some(local.join("ca-cert.pem")),
        },
    )?;
    // Lima forwards the VM's loopback listener to the Mac once it notices it.
    poll("the scratch node's API", Duration::from_secs(60), || {
        node.list_pods().map(Some)
    })?;
    Ok(ScratchNode { node, dir })
}

fn vm_sha256(cfg: &Config, path: &str) -> Result<ArtifactDigest> {
    let out = run("sha256sum", vm(cfg).args(["sudo", "sha256sum", path]))?;
    let hex = out.split_whitespace().next().context("sha256sum output")?;
    ArtifactDigest::parse(&format!("sha-256:{hex}")).map_err(anyhow::Error::msg)
}

/// Step 5: the pod spec. The workload is the image's own process, as the import record
/// states it — not restated here.
fn pod_spec(cfg: &Config, sn: &ScratchNode, built: &Built) -> Result<Value> {
    let Built {
        index,
        guest,
        rootfs,
        record,
        ..
    } = built;
    let run_as = record
        .workload
        .for_workload()
        .map_err(|e| anyhow::anyhow!("the image's user cannot run as the workload: {e}"))?;
    // WorkloadSpec carries one id, and the proxy sets the gid equal to it.
    ensure!(
        run_as.gid() == run_as.uid(),
        "the image runs as {}:{}, which a WorkloadSpec (uid only; gid = uid) cannot express",
        run_as.uid(),
        run_as.gid()
    );
    let mut argv = record
        .workload
        .entrypoint
        .iter()
        .chain(&record.workload.cmd)
        .cloned();
    let command = argv.next().context("the image names no process")?;
    let args: Vec<String> = argv.collect();
    let env: BTreeMap<&str, &str> = record
        .workload
        .env
        .iter()
        .filter_map(|kv| kv.split_once('='))
        .collect();

    let scratch = format!("{}/state/scratch/agent.ext4", sn.dir);
    run(
        "scratch disk",
        vm(cfg).args(["sudo", "truncate", "-s", "64M", &scratch]),
    )?;
    run(
        "scratch mkfs",
        vm(cfg).args(["sudo", "mkfs.ext4", "-q", "-F", &scratch]),
    )?;
    Ok(json!({
        "apiVersion": "nucleus/v1",
        "kind": "Pod",
        "metadata": {"name": "oci-e2e"},
        "spec": {
            "work_dir": "/work",
            "timeout_seconds": 300,
            "policy": {"type": "profile", "name": "restrictive"},
            "network": {"allow": [cfg.allowed]},
            "image": {
                "kernel_path": cfg.kernel,
                "kernel_digest": vm_sha256(cfg, &cfg.kernel)?.as_str(),
                "rootfs_oci": {
                    "reference": format!("localhost/{IMAGE_TAG}@{index}"),
                    "manifest_digest": record.manifest_digest.to_string(),
                    "guest_layer_digest": guest.as_str(),
                },
                "rootfs_digest": rootfs.as_str(),
                "scratch_path": scratch,
                "scratch_digest": vm_sha256(cfg, &scratch)?.as_str(),
                "read_only": true,
            },
            "vsock": {"guest_cid": 7, "port": 5000},
            "workload": {
                "command": command,
                "args": args,
                "env": env,
                "uid": run_as.uid(),
                "artifacts": {OUTPUT_ARTIFACT: OUTPUT_FILE},
            },
        },
    }))
}

/// The SVID the node serves this pod, fetched from the host end of the pod's workload-API
/// vsock socket — the bytes the guest itself is handed.
fn served_svid(cfg: &Config, sn: &ScratchNode, pod: &str) -> Result<String> {
    let root = format!("{}/jailer/firecracker/{pod}/root", sn.dir);
    let listing = run("jail listing", vm(cfg).args(["sudo", "ls", &root]))?;
    let mut sockets: Vec<&str> = listing
        .lines()
        .filter(|l| l.starts_with("vsock.sock_"))
        .collect();
    sockets.sort_unstable();
    ensure!(!sockets.is_empty(), "no workload-API socket in {root}");
    let mut refusals = Vec::new();
    for sock in sockets {
        let reply = run_with_stdin(
            "FETCH_SVID",
            vm(cfg).args(["sudo", "nc", "-U", "-q", "2", &format!("{root}/{sock}")]),
            Some(b"FETCH_SVID\n"),
        );
        match reply.map(|r| serde_json::from_str::<Value>(r.lines().next().unwrap_or(""))) {
            Ok(Ok(v)) if v["certificate_chain"].is_string() => {
                return Ok(v["certificate_chain"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string());
            }
            other => refusals.push(format!("{sock}: {other:?}")),
        }
    }
    bail!("no socket served an SVID: {refusals:?}")
}

/// What was built before the boot: the inputs every assertion is checked against.
struct Built {
    cli: PathBuf,
    guest: ArtifactDigest,
    index: String,
    record: ImportRecord,
    rootfs: ArtifactDigest,
    uid: u32,
}

/// What the pod itself was observed to do.
struct Observed {
    pod: String,
    health: Value,
    stdout: String,
    harvested: String,
    probe_line: String,
    attestation: String,
    provenance: Value,
}

/// Steps 5-6: boot, then read every claim back from the node and the pod.
fn boot_and_assert(
    cfg: &Config,
    built: &Built,
    sn: &ScratchNode,
    spec: &Value,
    cleanup: &mut Cleanup,
) -> Result<Observed> {
    let Built {
        cli,
        guest,
        rootfs,
        uid,
        ..
    } = built;
    let uid = *uid;
    let (pod, proxy) = sn.node.create_pod_with_proxy(&spec.to_string())?;
    let mut cancel = vm(cfg);
    // Cancel through the node, as the operator would; best effort on the way out.
    cancel.args([
        "curl",
        "-sS",
        "-X",
        "POST",
        "--cacert",
        &format!("{}/client/ca-cert.pem", sn.dir),
        "--cert",
        &format!("{}/client/cli.crt", sn.dir),
        "--key",
        &format!("{}/client/cli.key", sn.dir),
        "--resolve",
        &format!("node:{}:127.0.0.1", cfg.port),
        &format!("https://node:{}/v1/pods/{pod}/cancel", cfg.port),
    ]);
    cleanup.push("cancel the pod", cancel);

    // Healthy and attested: the pod's own tool-proxy says so.
    let health: Value = serde_json::from_str(&run(
        "proxy health",
        vm(cfg).args([
            "curl",
            "-sS",
            "--max-time",
            "10",
            &format!("{proxy}/v1/health"),
        ]),
    )?)?;
    ensure!(health["status"] == json!("ok"), "unhealthy: {health}");
    ensure!(
        health["sandbox_proof"]["label"] == json!("attested"),
        "not attested: {health}"
    );

    let result = poll("the workload to exit", Duration::from_secs(90), || {
        let v = sn
            .node
            .get_json(&format!("/v1/pods/{pod}/workload-result"))
            .map_err(anyhow::Error::msg)?;
        Ok((v["state"] == json!("exited")).then_some(v))
    })?;
    ensure!(result["exit_code"] == json!(0), "workload failed: {result}");
    ensure!(
        result["program"]["state"] == json!("bound"),
        "every image digest is pinned, so the program must be bound: {result}"
    );

    // uid, /work and the agent's own egress attempts, from the node's copy of its stdout.
    let stdout = sn
        .node
        .get_text(&format!("/v1/pods/{pod}/workload-logs/stdout"))
        .map_err(anyhow::Error::msg)?;
    let id_line = field(&stdout, "AGENT_ID:")?;
    ensure!(
        id_line.starts_with(&format!("uid={uid}(")),
        "the workload ran as `{id_line}`, not uid {uid}"
    );
    ensure!(
        field(&stdout, "AGENT_WORK:")? == "wrote /work/agent-output.txt",
        "/work was not writable:\n{stdout}"
    );
    ensure!(
        field(&stdout, &format!("AGENT_CONNECT: {}", cfg.allowed))? == "CONNECTED",
        "the allowlisted destination was not reached — the deny below would prove nothing:\n{stdout}"
    );
    ensure!(
        field(&stdout, &format!("AGENT_CONNECT: {}", cfg.denied))? == "BLOCKED",
        "a destination off the allowlist was reached:\n{stdout}"
    );
    // The block is the pod's fence only if the destination is reachable without it.
    let (host, port) = cfg.denied.rsplit_once(':').context("denied host:port")?;
    run(
        "the VM itself reaches the denied destination",
        vm(cfg).args([
            "timeout",
            "5",
            "bash",
            "-c",
            &format!("exec 3<>/dev/tcp/{host}/{port}"),
        ]),
    )?;

    // The guest's own confinement probe, from the console the node captured.
    let console = sn
        .node
        .get_text(&format!("/v1/pods/{pod}/logs"))
        .map_err(anyhow::Error::msg)?;
    ensure!(
        !console.contains("NUCLEUS_EGRESS_PROBE: FAIL"),
        "the egress probe failed:\n{console}"
    );
    let probe_line = console
        .lines()
        .find(|l| l.contains("NUCLEUS_EGRESS_PROBE: PASS"))
        .context("no NUCLEUS_EGRESS_PROBE: PASS on the console")?
        .trim()
        .to_string();

    // /work, harvested by the node's mediated reader and signed, not the agent's say-so.
    let bundle = sn.node.post_json(
        &format!("/v1/pods/{pod}/execution-receipt"),
        &json!({"artifacts": {OUTPUT_ARTIFACT: OUTPUT_FILE}}),
        "collect the workload's artifact",
    )?;
    let harvested = base64::engine::general_purpose::STANDARD
        .decode(
            bundle["artifacts"][OUTPUT_ARTIFACT]
                .as_str()
                .context("no artifact in the bundle")?,
        )
        .context("artifact base64")?;
    let harvested = String::from_utf8(harvested).context("artifact utf-8")?;
    ensure!(
        harvested.trim() == format!("written by the agent as uid {uid}"),
        "harvested {harvested:?}"
    );

    // The attestation the pod is served, checked by the relying-party verifier.
    let pem = served_svid(cfg, sn, &pod)?;
    let pem_path = cfg.work.join("svid.pem");
    std::fs::write(&pem_path, &pem)?;
    let verify = |expect: &str| {
        run(
            "nucleus verify-attestation",
            Command::new(cli)
                .args(["verify-attestation", "--cert"])
                .arg(&pem_path)
                .args(["--expect-rootfs", expect]),
        )
    };
    let attestation = verify(rootfs.hex())?;
    ensure!(
        verify(guest.hex()).is_err(),
        "verify-attestation accepted a rootfs digest the pod did not boot — the check is vacuous"
    );

    // The receipt is built once the pod has exited; cancel is how a Firecracker pod exits.
    sn.node.cancel_pod(&pod)?;
    let receipt = poll("the pod receipt", Duration::from_secs(30), || {
        Ok(sn.node.get_json(&format!("/v1/pods/{pod}/receipt")).ok())
    })?;
    ensure!(
        receipt["signature"].as_str().is_some_and(|s| !s.is_empty()),
        "unsigned receipt: {receipt}"
    );
    Ok(Observed {
        pod,
        health,
        stdout,
        harvested,
        probe_line,
        attestation: attestation.lines().next().unwrap_or_default().to_string(),
        provenance: receipt["rootfs_provenance"].clone(),
    })
}

fn prove(cfg: &Config, cleanup: &mut Cleanup) -> Result<Evidence> {
    std::fs::create_dir_all(&cfg.work)?;
    let (guest_path, guest) = guest_layer(cfg)?;
    let (bin, cli) = binaries(cfg)?;
    let (archive, index) = user_image(cfg, cleanup)?;
    let (tar_hex, record) = stage_one(cfg, &cli, &archive, &index, &guest_path)?;
    let rootfs = stage_two(cfg, &tar_hex, &guest, &record, cleanup)?;
    let uid = record
        .workload
        .for_workload()
        .map_err(|e| anyhow::anyhow!("the image's user cannot run as the workload: {e}"))?
        .uid();
    let built = Built {
        cli,
        guest,
        index,
        record,
        rootfs,
        uid,
    };
    let sn = scratch_node(cfg, &bin, &built.rootfs, cleanup)?;
    let spec = pod_spec(cfg, &sn, &built)?;
    let observed = boot_and_assert(cfg, &built, &sn, &spec, cleanup)?;

    let reference = format!("localhost/{IMAGE_TAG}@{}", built.index);
    let provenance = &observed.provenance;
    ensure!(
        provenance["reference"] == json!(reference)
            && provenance["manifest_digest"] == json!(built.record.manifest_digest.to_string())
            && provenance["guest_layer_digest"] == json!(built.guest.as_str())
            && provenance["e2fsprogs_version"].is_string(),
        "the receipt's rootfs provenance is not this image's: {provenance}"
    );
    Ok(Evidence {
        manifest: built.record.manifest_digest.to_string(),
        guest_layer: built.guest,
        image_index: built.index,
        rootfs: built.rootfs,
        observed,
    })
}

#[test]
#[ignore = "boots a real pod: needs Apple `container`, the Lima VM and cargo-zigbuild; \
            run with NUCLEUS_OCI_E2E=1"]
fn an_oci_image_boots_as_a_healthy_attested_pod() {
    // Refuse rather than pass: an ignored test asked to run without its environment has
    // looked at nothing, and "looked at nothing" must not read as green.
    assert_eq!(
        std::env::var("NUCLEUS_OCI_E2E").as_deref(),
        Ok("1"),
        "set NUCLEUS_OCI_E2E=1 to run the OCI end-to-end proof"
    );
    let cfg = Config::from_env().expect("config");
    let mut cleanup = Cleanup::default();
    if !cfg.keep_work {
        cleanup.work = Some(cfg.work.clone());
    }
    let evidence = prove(&cfg, &mut cleanup);
    drop(cleanup);
    let evidence = evidence.unwrap_or_else(|e| panic!("OCI end-to-end proof failed: {e:#}"));
    evidence.report();
}

impl Evidence {
    /// The run's evidence, one assertion per line.
    fn report(&self) {
        let o = &self.observed;
        eprintln!("OCI end-to-end proof: PASS");
        eprintln!("  guest layer      {}", self.guest_layer.as_str());
        eprintln!("  image (index)    {}", self.image_index);
        eprintln!("  image (manifest) {}", self.manifest);
        eprintln!(
            "  rootfs (ext4)    {} (two stage-two builds agree)",
            self.rootfs.as_str()
        );
        eprintln!("  pod              {}", o.pod);
        eprintln!("  proxy health     {}", o.health);
        eprintln!("  egress probe     {}", o.probe_line);
        eprintln!("  attestation      {}", o.attestation);
        eprintln!("  /work harvested  {:?}", o.harvested.trim());
        eprintln!("  receipt rootfs   {}", o.provenance);
        eprintln!("  workload stdout:");
        for line in o.stdout.lines() {
            eprintln!("    {line}");
        }
    }
}
