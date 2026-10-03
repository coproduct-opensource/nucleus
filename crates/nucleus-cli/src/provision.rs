//! Installing the things a Tier 2 host needs, from the pins that name them.
//!
//! # Why this exists
//!
//! `nucleus setup` used to provision a VM that could not run nucleus. Measured
//! on a clean Apple M5 / macOS 26.6 on 2026-07-29: setup exited **0** and its
//! smoke test reported "Tier 2 works on this host", `doctor` exited **0** with
//! "All checks passed", and `nucleus start` exited **1** with "nucleus-node
//! binary not found in Lima VM" — because nothing ever installed it. The VM had
//! Firecracker and a kernel and nothing else: no rootfs, no node, and a systemd
//! unit naming environment variables the node does not read
//! (`NUCLEUS_NODE_LISTEN_ADDR` for `NUCLEUS_NODE_LISTEN`) and none of the three
//! secrets it requires at startup — which `keychain` had already generated.
//!
//! This module is the missing step. Everything it installs is named by
//! [`nucleus_spec::tier2_artifacts`] or [`nucleus_spec::vmm_version`], never by
//! a literal here, so there is one answer to "which kernel" rather than three.
//!
//! # Why the guest secrets are hex
//!
//! `run.rs` and `node.rs` both sign with `hex::encode(secret)`, so the node must
//! be started with the same encoding. Writing the raw bytes instead would
//! produce authentication failures that read like clock skew, on a path where
//! the actual cause is an encoding mismatch two crates away.

use anyhow::{Context, Result, anyhow, bail};
use nucleus_spec::tier2_artifacts::{self, Tier2Artifact};
use nucleus_spec::vmm_version;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where nucleus's artifacts live inside a Tier 2 host. Defined in
/// `nucleus-spec`, which the Apple `container` host reads too, and which is
/// also the node's default `--artifacts-root`.
pub use nucleus_spec::tier2_artifacts::HOST_ARTIFACTS_DIR;

/// Where the node keeps per-pod state inside the Tier 2 host.
pub const HOST_STATE_DIR: &str = "/var/lib/nucleus/state";

/// The only directory a caller-supplied `image.scratch_path` may name a file in
/// (`--scratch-root`). Seeded workspace images are staged here; the node refuses a
/// writable guest disk from anywhere else, its own CA under `HOST_STATE_DIR/ca`
/// included.
pub const HOST_SCRATCH_ROOT: &str = "/var/lib/nucleus/state/scratch";

/// The environment file the node's systemd unit reads.
pub const NODE_ENV_PATH: &str = "/etc/nucleus/node.env";

/// The workload API socket the node serves SVIDs on.
pub const WORKLOAD_API_SOCKET: &str = "/var/lib/nucleus/wapi.sock";

/// A machine that can run Firecracker: either a Lima VM or this host.
#[derive(Debug, Clone)]
pub enum Tier2Host {
    /// Reached through `limactl`, which is how macOS reaches Linux.
    Lima(String),
    /// This machine, which is how a Linux host reaches itself.
    Local,
}

impl Tier2Host {
    /// Run a shell script as root on the host, returning stdout.
    ///
    /// Errors carry stderr, because the failures worth debugging here
    /// (a missing package, a full disk, a refused sudo) only say so there.
    pub fn sh(&self, script: &str) -> Result<String> {
        let stdout = self.sh_bytes(script)?;
        Ok(String::from_utf8_lossy(&stdout).trim().to_string())
    }

    /// [`Self::sh`] without the trim: stdout exactly as the script wrote it.
    ///
    /// For reading a file's bytes back. `sh` trims, which is right for a
    /// one-line answer and wrong for file content: a PEM read through it loses
    /// its trailing newline, and that stripped PEM, written back out beside
    /// another, glued the two together (#3158).
    pub fn sh_bytes(&self, script: &str) -> Result<Vec<u8>> {
        let output = match self {
            Self::Lima(vm) => Command::new("limactl")
                .args(["shell", vm, "--", "sudo", "sh", "-c", script])
                .output()
                .with_context(|| format!("failed to run limactl shell {vm}"))?,
            Self::Local => Command::new("sudo")
                .args(["sh", "-c", script])
                .output()
                .context("failed to run sudo sh")?,
        };
        if !output.status.success() {
            bail!(
                "command failed on {}: {}\n{}",
                self.describe(),
                script.lines().next().unwrap_or(script),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(output.stdout)
    }

    /// Whether a shell test succeeds, without treating failure as an error.
    pub fn test(&self, script: &str) -> bool {
        self.sh(script).is_ok()
    }

    /// Place a local file at an absolute path on the host, with `mode`.
    ///
    /// # Why this lands via a sibling temp file and `mv`
    ///
    /// Writing **into** the destination fails when the destination is a running
    /// binary: `cp` gets `ETXTBSY` ("Text file busy"). That is not a corner case
    /// here — on a Linux Tier 2 host, `nucleus setup` installs the `nucleus` CLI
    /// to `/usr/local/bin/nucleus`, which is very often the binary executing the
    /// install. It failed exactly that way in CI.
    ///
    /// `mv` within the same directory is a `rename(2)`: it swaps the directory
    /// entry rather than writing through it, so it succeeds against a running
    /// binary (existing processes keep the old inode) and is atomic — no window
    /// where the path holds a half-written file. Staging in the destination
    /// directory rather than `/tmp` is what makes it a rename instead of a
    /// cross-filesystem copy, which would reintroduce the problem.
    ///
    /// `chmod` happens on the temp file, before the rename, so the binary is
    /// never visible at its real path with the wrong mode.
    pub fn put(&self, local: &Path, remote: &str, mode: &str) -> Result<()> {
        let file_name = local
            .file_name()
            .ok_or_else(|| anyhow!("not a file: {}", local.display()))?
            .to_string_lossy()
            .to_string();
        // A sibling of the destination, so the final step is a rename.
        let staged = format!("{remote}.nucleus-new");
        match self {
            Self::Lima(vm) => {
                // `limactl copy` cannot write into a root-owned directory, so
                // land in /tmp first and move into place as root.
                let tmp = format!("/tmp/{file_name}");
                let status = Command::new("limactl")
                    .arg("copy")
                    .arg(local)
                    .arg(format!("{vm}:{tmp}"))
                    .status()
                    .context("failed to run limactl copy")?;
                if !status.success() {
                    bail!("limactl copy of {} into {vm} failed", local.display());
                }
                self.sh(&put_script(remote, &staged, &tmp, mode))?;
            }
            Self::Local => {
                self.sh(&put_script(
                    remote,
                    &staged,
                    &local.display().to_string(),
                    mode,
                ))?;
            }
        }
        Ok(())
    }

    fn describe(&self) -> String {
        match self {
            Self::Lima(vm) => format!("Lima VM '{vm}'"),
            Self::Local => "this host".to_string(),
        }
    }
}

/// The root shell that lands a staged file at its destination.
///
/// Pure, so the one case that bit can be tested without a VM: when `remote` is
/// itself under `/tmp`, the path `limactl copy` writes to and the destination are
/// **the same file**, and an unconditional `rm -f {source}` cleanup deletes what
/// was just installed. That is exactly what happened installing the node tarball,
/// whose destination is `/tmp/<asset>.tar.gz` — provenance verified, file copied,
/// then removed, and `tar` reported a missing archive three layers later.
///
/// The staged copy is created under `umask 077`, into a path cleared first, so a
/// file whose final mode is `0600` (a private key) is never briefly readable at
/// the root umask's `0644` between `cp` and `chmod`. The umask is scoped to the
/// `cp` so directories `mkdir -p` creates keep their ordinary mode.
fn put_script(remote: &str, staged: &str, source: &str, mode: &str) -> String {
    // Only clean up a source that is not the destination.
    let cleanup = if source == remote {
        String::new()
    } else {
        format!("\n                     rm -f {source}")
    };
    format!(
        "set -e
                     mkdir -p \"$(dirname {remote})\"
                     rm -f {staged}
                     (umask 077 && cp {source} {staged})
                     chmod {mode} {staged}
                     mv {staged} {remote}{cleanup}"
    )
}

/// Download `url` to `dest`, returning the SHA-256 of what arrived.
///
/// Hashes the bytes as they are written rather than re-reading the file, so the
/// digest describes what was received and not what is on disk a moment later.
fn download_hashing(url: &str, dest: &Path) -> Result<String> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let response = ureq::get(url)
        .call()
        .map_err(|e| anyhow!("download failed: {url}: {e}"))?;
    let mut reader = response.into_parts().1.into_reader();
    let mut file =
        std::fs::File::create(dest).with_context(|| format!("cannot create {}", dest.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = std::io::Read::read(&mut reader, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        std::io::Write::write_all(&mut file, &buf[..n])?;
    }
    Ok(hex::encode(hasher.finalize()))
}

/// SHA-256 of a file already on disk.
pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Fetch `url` into `dest` and refuse anything whose digest is not `expected`.
///
/// The mismatched file is **removed**, not left in place: a cached artifact that
/// failed verification is exactly the thing a later run must not silently pick
/// up because it "already exists".
fn download_verified(url: &str, dest: &Path, expected: &str) -> Result<()> {
    if dest.exists() {
        if sha256_file(dest)? == expected {
            println!("    cached, digest verified: {}", dest.display());
            return Ok(());
        }
        std::fs::remove_file(dest)?;
    }
    let got = download_hashing(url, dest)?;
    if got != expected {
        let _ = std::fs::remove_file(dest);
        bail!(
            "digest mismatch for {url}\n  expected {expected}\n  got      {got}\n\
             The pinned artifact is not what was served. Refusing to install it."
        );
    }
    Ok(())
}

/// Install the pinned Firecracker and jailer onto `host`.
///
/// Verifies by asking the installed binary its version and judging it with
/// [`vmm_version::judge`] — the same check the node makes before launching a
/// pod, so setup cannot leave behind a VMM the node will later refuse.
pub fn install_firecracker(host: &Tier2Host, arch: &str) -> Result<()> {
    let v = vmm_version::PINNED_STR;
    println!("  Firecracker v{v} + jailer...");
    let url = format!(
        "https://github.com/firecracker-microvm/firecracker/releases/download/v{v}/firecracker-v{v}-{arch}.tgz"
    );
    host.sh(&format!(
        "set -e
         tmp=$(mktemp -d)
         curl -fsSL '{url}' | tar -xz -C \"$tmp\"
         mv \"$tmp/release-v{v}-{arch}/firecracker-v{v}-{arch}\" /usr/local/bin/firecracker
         mv \"$tmp/release-v{v}-{arch}/jailer-v{v}-{arch}\" /usr/local/bin/jailer
         chmod 0755 /usr/local/bin/firecracker /usr/local/bin/jailer
         rm -rf \"$tmp\""
    ))?;

    let reported = host.sh("/usr/local/bin/firecracker --version")?;
    let verdict = vmm_version::judge(&reported);
    if !verdict.is_acceptable() {
        bail!("installed Firecracker is not acceptable to the node: {verdict}");
    }
    println!(
        "    {} (accepted by the node's own check)",
        reported.lines().next().unwrap_or(&reported)
    );
    Ok(())
}

/// Install the pinned guest kernel onto `host`.
pub fn install_kernel(host: &Tier2Host, arch: &str, cache_dir: &Path) -> Result<()> {
    let kernel = tier2_artifacts::kernel_for(arch)
        .ok_or_else(|| anyhow!("no pinned kernel for architecture '{arch}'"))?;
    println!("  Guest kernel...");
    let local = cache_dir.join(format!("vmlinux-{arch}"));
    download_verified(kernel.url, &local, kernel.sha256)?;
    host.put(&local, &format!("{HOST_ARTIFACTS_DIR}/vmlinux"), "0644")?;
    println!("    installed, sha256 {}", &kernel.sha256[..16]);
    Ok(())
}

/// Where the guest rootfs and node binary come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactSource {
    /// Whatever this working tree has built, if anything; otherwise the release.
    Auto,
    /// Only this working tree's build output. Fails if it is not there.
    Local,
    /// Only the pinned release.
    Release,
}

/// One release asset, with the digest the release API reports for it.
struct ReleaseAsset {
    url: String,
    name: String,
    digest: String,
}

/// Ask the release API for the assets of `version`.
///
/// The digest returned here is an **integrity** check, not a provenance one —
/// it travels from the same place the bytes do. `gh attestation verify` is the
/// check that binds an asset to the workflow that built it, and
/// [`verify_attestation`] runs it when `gh` is available.
fn release_assets(version: &str) -> Result<Vec<ReleaseAsset>> {
    let url = format!(
        "https://api.github.com/repos/{}/releases/tags/v{version}",
        tier2_artifacts::RELEASE_REPO
    );
    let body: serde_json::Value = ureq::get(&url)
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "nucleus-cli")
        .call()
        .map_err(|e| {
            anyhow!(
                "cannot read release v{version} of {}: {e}\n\
                 If that release does not exist yet, build artifacts locally instead:\n\
                   nucleus setup --artifacts local",
                tier2_artifacts::RELEASE_REPO
            )
        })?
        .into_body()
        .read_json()
        .context("release API returned something that is not JSON")?;

    let assets = body
        .get("assets")
        .and_then(|a| a.as_array())
        .ok_or_else(|| anyhow!("release v{version} has no assets"))?;

    Ok(assets
        .iter()
        .filter_map(|a| {
            Some(ReleaseAsset {
                url: a.get("browser_download_url")?.as_str()?.to_string(),
                name: a.get("name")?.as_str()?.to_string(),
                // Reported as "sha256:<hex>"; keep only the hex.
                digest: a
                    .get("digest")
                    .and_then(|d| d.as_str())
                    .unwrap_or_default()
                    .trim_start_matches("sha256:")
                    .to_string(),
            })
        })
        .collect())
}

/// Run `gh attestation verify` on a downloaded asset, if `gh` is available.
///
/// Returns whether the check *ran and passed*. A missing `gh` is not a failure —
/// requiring it would make a supply-chain nicety a hard dependency of the
/// quickstart — but the difference is printed, because "verified" and "not
/// checked" must not look the same in the output.
fn verify_attestation(path: &Path) -> bool {
    let ran = Command::new("gh")
        .args(["attestation", "verify"])
        .arg(path)
        .args(["--repo", tier2_artifacts::RELEASE_REPO])
        .output();
    match ran {
        Ok(o) if o.status.success() => true,
        Ok(_) | Err(_) => false,
    }
}

/// Candidate paths for a locally built artifact in this working tree.
fn local_build_candidates(artifact: Tier2Artifact, arch: &str) -> Vec<PathBuf> {
    // The working directory first, and `CARGO_MANIFEST_DIR` only as a fallback.
    //
    // `CARGO_MANIFEST_DIR` is resolved at COMPILE time, so a released binary
    // carries whichever machine built it — a path that does not exist on the
    // user's disk, which would make `--artifacts local` fail with a message
    // naming a directory they have never seen. "The checkout I am standing in"
    // is both what someone means by *local* and independent of where the binary
    // came from.
    let mut roots = vec![std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))];
    if let Some(manifest_root) = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        && manifest_root.is_dir()
        && !roots.contains(&manifest_root.to_path_buf())
    {
        roots.push(manifest_root.to_path_buf());
    }
    // `find(is_file)` at the call sites picks the first that exists, so listing
    // several roots is how a candidate list earns its plural.
    let paths =
        |suffix: String| -> Vec<PathBuf> { roots.iter().map(|r| r.join(&suffix)).collect() };
    match artifact {
        // Matches what release.yml packages, so a local build and a release
        // build are the same file in two places rather than two conventions.
        Tier2Artifact::Rootfs => paths(format!("build/firecracker/{arch}/rootfs.ext4")),
        Tier2Artifact::Node => paths(format!(
            "target/{arch}-unknown-linux-musl/release/nucleus-node"
        )),
        Tier2Artifact::Cli => paths(format!("target/{arch}-unknown-linux-musl/release/nucleus")),
    }
}

/// Install the rootfs and the node binary onto `host`.
///
/// Refuses a release that lacks any [`tier2_artifacts::GuestCapability`] rather
/// than installing it: a guest this build's node cannot boot would look like
/// nucleus being broken, which — with that artifact — it is. Today that is the
/// pinned release itself, so only `--artifacts local` installs.
pub fn install_tier2_artifacts(
    host: &Tier2Host,
    arch: &str,
    cache_dir: &Path,
    source: ArtifactSource,
) -> Result<()> {
    // Prefer a local build when asked to, or when Auto finds one: a working tree
    // that has built the guest is almost certainly ahead of the last release,
    // and silently installing older artifacts over it is the surprising choice.
    let use_local = match source {
        ArtifactSource::Local => true,
        ArtifactSource::Release => false,
        ArtifactSource::Auto => Tier2Artifact::all()
            .iter()
            .all(|a| local_build_candidates(*a, arch).iter().any(|p| p.is_file())),
    };

    if use_local {
        println!("  Guest artifacts from this working tree:");
        for artifact in Tier2Artifact::all() {
            let found = local_build_candidates(*artifact, arch)
                .into_iter()
                .find(|p| p.is_file())
                .ok_or_else(|| {
                    anyhow!(
                        "--artifacts local, but no local build of {artifact:?} for {arch}.\n\
                         Expected one of: {:?}\n\
                         Build it, or use --artifacts release.",
                        local_build_candidates(*artifact, arch)
                    )
                })?;
            install_one_local(host, *artifact, &found)?;
        }
        return Ok(());
    }

    let version = tier2_artifacts::GUEST_RELEASE;
    // Before any download: a guest this build cannot serve is refused here, by
    // name, rather than installed and left to die mid-boot with a diagnosis
    // pointing somewhere else.
    if let Err(skew) = tier2_artifacts::guest_skew(version) {
        bail!("{skew}");
    }
    println!("  Guest artifacts from release v{version}:");
    let assets = release_assets(version)?;

    for artifact in Tier2Artifact::all() {
        let name = artifact.asset_name(version, arch);
        let asset = assets
            .iter()
            .find(|a| a.name == name)
            .ok_or_else(|| anyhow!("release v{version} has no asset named {name}"))?;
        if asset.digest.len() != 64 {
            bail!("release API reported no usable digest for {name}");
        }
        let local = cache_dir.join(&name);
        println!("    {name}");
        download_verified(&asset.url, &local, &asset.digest)?;
        if verify_attestation(&local) {
            println!("      build provenance verified (gh attestation verify)");
        } else {
            println!("      digest matches the release API; build provenance NOT checked");
            println!(
                "      (install the gh CLI for a provenance check that the release API cannot fake)"
            );
        }
        install_one_local(host, *artifact, &local)?;
    }
    Ok(())
}

/// Place one artifact, decompressing if the filename says it is compressed.
fn install_one_local(host: &Tier2Host, artifact: Tier2Artifact, local: &Path) -> Result<()> {
    let name = local.file_name().unwrap_or_default().to_string_lossy();
    match artifact {
        Tier2Artifact::Rootfs => {
            let staged = format!("{HOST_ARTIFACTS_DIR}/{name}");
            host.put(local, &staged, "0644")?;
            if name.ends_with(".gz") {
                host.sh(&format!(
                    "gunzip -f -c {staged} > {HOST_ARTIFACTS_DIR}/rootfs.ext4 && rm -f {staged}"
                ))?;
            } else if staged != format!("{HOST_ARTIFACTS_DIR}/rootfs.ext4") {
                host.sh(&format!("mv {staged} {HOST_ARTIFACTS_DIR}/rootfs.ext4"))?;
            }
            host.sh(&format!("chmod 0644 {HOST_ARTIFACTS_DIR}/rootfs.ext4"))?;
        }
        Tier2Artifact::Node => install_binary(host, local, &name, "nucleus-node")?,
        Tier2Artifact::Cli => install_binary(host, local, &name, "nucleus")?,
    }
    Ok(())
}

/// Place a binary at `/usr/local/bin/<bin>`, unpacking it first if it is a tarball.
fn install_binary(host: &Tier2Host, local: &Path, name: &str, bin: &str) -> Result<()> {
    if name.ends_with(".tar.gz") {
        let staged = format!("/tmp/{name}");
        host.put(local, &staged, "0644")?;
        // Unpack beside the destination and rename into place, for the same
        // reason `put` does: `mv` out of a `mktemp -d` under /tmp is very likely
        // cross-filesystem, which degrades to copy+unlink and fails with
        // ETXTBSY against a running binary.
        host.sh(&format!(
            "set -e
             tmp=$(mktemp -d)
             tar -xzf {staged} -C \"$tmp\"
             cp \"$tmp/{bin}\" /usr/local/bin/{bin}.nucleus-new
             chmod 0755 /usr/local/bin/{bin}.nucleus-new
             mv /usr/local/bin/{bin}.nucleus-new /usr/local/bin/{bin}
             rm -rf \"$tmp\" {staged}"
        ))?;
    } else {
        host.put(local, &format!("/usr/local/bin/{bin}"), "0755")?;
    }
    Ok(())
}

/// The environment a working `nucleus-node` needs, as an env-file body.
///
/// Split out and pure so the variable **names** are testable without a VM.
/// They were wrong for as long as they were only ever written into a VM nobody
/// asserted against: the previous unit set `NUCLEUS_NODE_LISTEN_ADDR` (the node
/// reads `NUCLEUS_NODE_LISTEN`), `NUCLEUS_NODE_GRPC_ADDR` (it reads
/// `NUCLEUS_NODE_GRPC_LISTEN`), and `NUCLEUS_NODE_ARTIFACTS_DIR`, which nothing
/// reads at all.
/// `canary_hex` is a throwaway value planted so `verify --tier2` has a real
/// node-held secret to hunt for in the guest. Without one the leak sweep has
/// nothing to look for and refuses to run — which is correct, but made the check
/// reachable only from CI, since CI was the only thing that planted a canary.
/// See #2372.
pub fn node_env_body(
    auth_hex: &str,
    proxy_hex: &str,
    approval_hex: &str,
    canary_hex: &str,
) -> String {
    format!(
        "# Written by `nucleus setup`. Contains HMAC secrets - keep mode 0600.\n\
         NUCLEUS_NODE_LISTEN=0.0.0.0:8080\n\
         NUCLEUS_NODE_GRPC_LISTEN=0.0.0.0:9180\n\
         NUCLEUS_NODE_STATE_DIR={HOST_STATE_DIR}\n\
         NUCLEUS_NODE_SCRATCH_ROOT={HOST_SCRATCH_ROOT}\n\
         NUCLEUS_NODE_ARTIFACTS_ROOT={HOST_ARTIFACTS_DIR}\n\
         NUCLEUS_NODE_AUTH_SECRET={auth_hex}\n\
         NUCLEUS_NODE_PROXY_AUTH_SECRET={proxy_hex}\n\
         NUCLEUS_NODE_PROXY_APPROVAL_SECRET={approval_hex}\n\
         NUCLEUS_IDENTITY_WORKLOAD_API_SOCKET={WORKLOAD_API_SOCKET}\n\
         NUCLEUS_FIRECRACKER_PATH=/usr/local/bin/firecracker\n\
         NUCLEUS_JAILER_PATH=/usr/local/bin/jailer\n\
         NUCLEUS_E2E_CANARY=nucleus-e2e-canary-{canary_hex}\n\
         RUST_LOG=info\n"
    )
}

/// The systemd unit, which reads [`node_env_path`](NODE_ENV_PATH) rather than
/// inlining secrets into a world-readable unit file.
pub fn node_unit_body() -> String {
    format!(
        "[Unit]\n\
         Description=nucleus-node (Firecracker orchestrator)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         EnvironmentFile={NODE_ENV_PATH}\n\
         ExecStart=/usr/local/bin/nucleus-node\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// Where the node persists its CA root (`SelfSignedCa::load_or_create`,
/// `IdentityManager::new_with_persistent_ca`) — `{HOST_STATE_DIR}/ca`, since
/// `node_env_body` points `NUCLEUS_NODE_STATE_DIR` at `HOST_STATE_DIR`.
const HOST_CA_DIR: &str = "/var/lib/nucleus/state/ca";

/// This CLI's own mTLS identity, and the trust bundle that verifies the
/// node's self-issued certificate — the paths `--tls-cert`/`--tls-key`/
/// `--trust-bundle` on `nucleus node` want.
pub struct MtlsIdentityPaths {
    pub cli_cert: PathBuf,
    pub cli_key: PathBuf,
    pub trust_bundle: PathBuf,
}

impl MtlsIdentityPaths {
    /// The three files under `dir`, named by [`IdentityFile::name`].
    fn in_dir(dir: &Path) -> Self {
        Self {
            cli_cert: dir.join(IdentityFile::CertChain.name()),
            cli_key: dir.join(IdentityFile::Key.name()),
            trust_bundle: dir.join(IdentityFile::TrustBundle.name()),
        }
    }

    fn path(&self, file: IdentityFile) -> &Path {
        match file {
            IdentityFile::CertChain => &self.cli_cert,
            IdentityFile::Key => &self.cli_key,
            IdentityFile::TrustBundle => &self.trust_bundle,
        }
    }
}

/// One file of the CLI identity: its name, its mode, and what it must hold.
///
/// One decider for all three facts (ADR 0007 G-1): minting, installing into the
/// Tier 2 host, and deciding whether an existing identity can be reused all
/// read them from here rather than each restating a filename or a mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityFile {
    /// The CLI's certificate chain, leaf first. Public.
    CertChain,
    /// The CLI's private key. Owner-only.
    Key,
    /// The CA root(s) the node's certificate is verified against. Public.
    TrustBundle,
}

impl IdentityFile {
    const ALL: [Self; 3] = [Self::CertChain, Self::Key, Self::TrustBundle];

    fn name(self) -> &'static str {
        match self {
            Self::CertChain => "cli-cert.pem",
            Self::Key => "cli-key.pem",
            Self::TrustBundle => "trust-bundle.pem",
        }
    }

    fn mode(self) -> &'static str {
        match self {
            Self::Key => "0600",
            Self::CertChain | Self::TrustBundle => "0644",
        }
    }

    /// Refuse, by file name, content this file must not hold.
    ///
    /// A certificate file holds certificates and nothing else — in particular
    /// no private key, because tools and people treat a file named as a
    /// certificate as public, and #3158 put the key in exactly that file. A key
    /// file holds exactly one private key. Text outside a PEM block is refused
    /// too, since that is what a mis-terminated heredoc leaves behind and a PEM
    /// parser skips silently.
    fn check(self, bytes: &[u8]) -> Result<()> {
        let name = self.name();
        let text =
            std::str::from_utf8(bytes).map_err(|e| anyhow!("{name} is not UTF-8 text: {e}"))?;
        let mut inside = false;
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            let framed = line.ends_with("-----");
            if inside {
                if line.starts_with("-----END ") {
                    if !framed {
                        bail!("{name} has a malformed PEM END line: {line:?}");
                    }
                    inside = false;
                }
            } else if line.starts_with("-----BEGIN ") && framed {
                inside = true;
            } else if !line.trim().is_empty() {
                bail!("{name} holds text outside a PEM block: {line:?}");
            }
        }
        let blocks = pem::parse_many(bytes).map_err(|e| anyhow!("{name} is not valid PEM: {e}"))?;
        let (mut certs, mut keys) = (0usize, 0usize);
        for block in &blocks {
            match block.tag() {
                "CERTIFICATE" => certs += 1,
                tag if tag.ends_with("PRIVATE KEY") => keys += 1,
                tag => bail!("{name} holds an unexpected PEM block: {tag}"),
            }
        }
        match self {
            Self::CertChain | Self::TrustBundle => {
                if keys != 0 {
                    bail!(
                        "{name} holds {keys} private key(s): it is a certificate file, which \
                         is treated as public — refusing it"
                    );
                }
                if certs == 0 {
                    bail!("{name} holds no certificate");
                }
            }
            Self::Key => {
                if certs != 0 {
                    bail!("{name} holds {certs} certificate(s); it must hold only the key");
                }
                if keys != 1 {
                    bail!("{name} must hold exactly one private key, found {keys}");
                }
            }
        }
        Ok(())
    }
}

/// The three identity files' bytes, each checked by [`IdentityFile::check`],
/// and refused by name when one fails,
/// and checked together: the key is the leaf's key, and the leaf chains to the
/// bundle. The certificate is a CHAIN (leaf, then the CA root — what
/// `WorkloadCertificate::chain_pem` writes), so "only certificates" rather than
/// "one certificate" is the per-file rule.
fn check_identity(cert: &[u8], key: &[u8], bundle: &[u8]) -> Result<()> {
    IdentityFile::CertChain.check(cert)?;
    IdentityFile::Key.check(key)?;
    IdentityFile::TrustBundle.check(bundle)?;
    // `check` has already refused non-UTF-8 text, so these cannot fail.
    let utf8 = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let workload = nucleus_identity::WorkloadCertificate::from_pem(&utf8(cert), &utf8(key))
        .map_err(|e| {
            anyhow!(
                "{} does not parse as an SVID chain: {e}",
                IdentityFile::CertChain.name()
            )
        })?;
    workload
        .to_rustls_certified_key()
        .map_err(|e| anyhow!("{} is not a usable key: {e}", IdentityFile::Key.name()))?
        .keys_match()
        .map_err(|e| {
            anyhow!(
                "{} is not the key of the leaf in {}: {e}",
                IdentityFile::Key.name(),
                IdentityFile::CertChain.name()
            )
        })?;
    let bundle = nucleus_identity::TrustBundle::from_pem(&utf8(bundle))
        .map_err(|e| anyhow!("{} does not parse: {e}", IdentityFile::TrustBundle.name()))?;
    nucleus_identity::verify_svid_chain(workload.leaf(), &bundle).map_err(|e| {
        anyhow!(
            "the leaf in {} does not verify against {}: {e}",
            IdentityFile::CertChain.name(),
            IdentityFile::TrustBundle.name()
        )
    })?;
    Ok(())
}

/// Builds an mTLS client presenting the identity provisioned at
/// `~/.config/nucleus/identity/` (`Config::identity_dir()`,
/// `mint_cli_identity`'s output). Shared by every in-process caller that
/// talks to a LOCAL node over HTTP now that Move B made the node's listener
/// mTLS-only with no HMAC fallback: `nucleus verify --tier2` and the
/// 2-safety experiment (`twosafety_boot.rs`) both used to sign requests with
/// `NUCLEUS_NODE_AUTH_SECRET` read out of `/etc/nucleus/node.env`; neither
/// secret means anything to the node any more.
///
/// `nucleus node`'s own client (`node.rs::create_client`) does NOT use this:
/// it also accepts explicit `--tls-cert`/`--tls-key`/`--trust-bundle` flags
/// (for a remote node whose identity isn't the local provisioned one) and
/// only falls back to these same provisioned defaults when none are given —
/// see `node.rs::apply_provisioned_identity_defaults`. The callers here
/// always run "here" relative to the node they're checking, so there is no
/// analogous remote case to support.
/// `(identity_pem, bundle_pem)` read from the provisioned identity — the
/// half shared by both the async and blocking client builders below.
fn read_provisioned_identity_pems() -> Result<(Vec<u8>, Vec<u8>)> {
    let dir = crate::config::Config::identity_dir()
        .context("could not resolve the identity directory")?;
    let cert_path = dir.join("cli-cert.pem");
    let key_path = dir.join("cli-key.pem");
    let bundle_path = dir.join("trust-bundle.pem");

    let mut identity_pem = std::fs::read(&cert_path).with_context(|| {
        format!(
            "no CLI identity at {} — run: nucleus setup",
            cert_path.display()
        )
    })?;
    let key_pem = std::fs::read(&key_path)
        .with_context(|| format!("failed to read {}", key_path.display()))?;
    identity_pem.push(b'\n');
    identity_pem.extend_from_slice(&key_pem);
    let bundle_pem = std::fs::read(&bundle_path)
        .with_context(|| format!("failed to read {}", bundle_path.display()))?;

    Ok((identity_pem, bundle_pem))
}

/// `Some` client when an identity is actually provisioned, `None` (not an
/// error) when it isn't — for a caller that has another way to authenticate
/// to fall back to (`run.rs`'s `resolve_config`, still supporting an
/// explicit `--node-auth-secret` for a not-yet-migrated node). Contrast
/// [`mtls_client_from_provisioned_identity`], which errors when the
/// identity is missing because its callers have no fallback to offer.
pub fn mtls_client_if_provisioned() -> Result<Option<reqwest::Client>> {
    let Ok(dir) = crate::config::Config::identity_dir() else {
        return Ok(None);
    };
    if !(dir.join("cli-cert.pem").is_file()
        && dir.join("cli-key.pem").is_file()
        && dir.join("trust-bundle.pem").is_file())
    {
        return Ok(None);
    }
    mtls_client_from_provisioned_identity().map(Some)
}

pub fn mtls_client_from_provisioned_identity() -> Result<reqwest::Client> {
    let tls = provisioned_node_tls()?;
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .tls_backend_preconfigured(tls)
        .build()
        .context("failed to build mTLS client")
}

/// The TLS configuration both provisioned clients use: the provisioned CLI
/// identity, the provisioned trust bundle, and — because the node's
/// certificate names it by SPIFFE ID rather than hostname — acceptance of
/// exactly the node in the trust domain that identity belongs to. See
/// `nucleus_identity::node_tls`.
fn provisioned_node_tls() -> Result<rustls::ClientConfig> {
    let (identity_pem, bundle_pem) = read_provisioned_identity_pems()?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    nucleus_identity::node_tls::node_client_config(&identity_pem, &bundle_pem)
        .context("failed to build the node TLS configuration from the provisioned identity")
}

/// The `reqwest::blocking` twin of [`mtls_client_from_provisioned_identity`],
/// for a caller with a sync call chain it cannot make async (see
/// `twosafety_boot.rs::PodBoot`'s doc comment on its `mtls_client` field).
/// `reqwest::blocking::Client` builds its own internal runtime and PANICS if
/// constructed directly on an async task's worker thread — callers must
/// wrap the call (and every use of the returned client) in
/// `tokio::task::block_in_place`, as `twosafety_boot::execute` does.
pub fn mtls_blocking_client_from_provisioned_identity() -> Result<reqwest::blocking::Client> {
    let tls = provisioned_node_tls()?;
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .tls_backend_preconfigured(tls)
        .build()
        .context("failed to build mTLS client")
}

/// Seeds the node's CA root on `host` and mints this CLI's own client
/// identity from it — the material Move A step 5's `--tls-cert`/`--tls-key`/
/// `--trust-bundle` flags need, which nothing produced before this function
/// existed.
///
/// # Why the CA is seeded here rather than left to the node's own first boot
///
/// `IdentityManager::new_with_persistent_ca` already persists a CA root on
/// first boot via `SelfSignedCa::load_or_create` — so a provisioned node
/// gets ONE eventually either way. But this CLI's own certificate must be
/// signed by that SAME root, and minting it requires the CA to already
/// exist. Waiting for the node's first boot to create it would mean either
/// running `setup` twice (once to let the node create the CA, again to mint
/// a matching client cert) or an operator's first `nucleus node` invocation
/// racing the node's own startup. Generating it HERE, before
/// `install_node_service` starts the unit, means the node's very first boot
/// finds a root already in place (`load_or_create`'s load path, not its
/// create path) and this CLI's cert is valid from that first boot onward.
///
/// # Idempotent re-runs
///
/// If `{HOST_CA_DIR}` already holds a root — a previous `setup` run, or a
/// node that has already booted at least once — that EXACT root is loaded
/// and reused, never regenerated. Minting a fresh CA on a re-run would
/// silently invalidate every certificate (the node's own, and any
/// previously-provisioned CLI identity) issued under the old one, the same
/// failure mode `SelfSignedCa::load_or_create`'s own doc comment describes
/// for the node itself.
///
/// The CLI identity is kept the same way: an identity already on disk that
/// [`reusable_cli_identity`] accepts is installed again as-is rather than
/// re-minted, so a second `setup` leaves byte-identical files on both machines
/// (#3158).
pub async fn provision_mtls_identity(
    host: &Tier2Host,
    trust_domain: &str,
) -> Result<MtlsIdentityPaths> {
    let ca = load_or_seed_host_ca(host, trust_domain)?;
    let dir = crate::config::Config::identity_dir()?;
    let paths = match reusable_cli_identity(&ca, trust_domain, &dir) {
        Ok(paths) => {
            println!("  CLI identity at {} is current; keeping it", dir.display());
            paths
        }
        Err(why) => {
            println!("  minting a CLI identity ({why:#})");
            mint_cli_identity(&ca, trust_domain, &dir).await?
        }
    };
    install_identity_on_tier2_host(host, &paths)?;
    Ok(paths)
}

/// Renew the CLI identity on a `setup` run when it has less than this left.
/// It is minted for 90 days (`mint_cli_identity`).
const CLI_IDENTITY_RENEW_WITHIN_DAYS: i64 = 30;

/// The identity under `dir`, when it can be kept: all three files pass
/// [`check_identity`], the leaf is this CLI's SPIFFE ID, the bundle is exactly
/// `ca`'s root, and the leaf has more than [`CLI_IDENTITY_RENEW_WITHIN_DAYS`]
/// left. `Err` says why not, and the caller mints — the only thing a wrong
/// answer here costs is a fresh identity.
fn reusable_cli_identity(
    ca: &nucleus_identity::SelfSignedCa,
    trust_domain: &str,
    dir: &Path,
) -> Result<MtlsIdentityPaths> {
    use nucleus_identity::CaClient as _;

    let paths = MtlsIdentityPaths::in_dir(dir);
    let [cert, key, bundle] = read_identity(&paths)?;
    check_identity(&cert, &key, &bundle)?;

    let workload = nucleus_identity::WorkloadCertificate::from_pem(
        &String::from_utf8_lossy(&cert),
        &String::from_utf8_lossy(&key),
    )
    .map_err(|e| anyhow!("{} does not parse: {e}", IdentityFile::CertChain.name()))?;
    let want = nucleus_identity::Identity::new(trust_domain, "system", "cli");
    if workload.identity() != &want {
        bail!(
            "{} names {}, not {}",
            IdentityFile::CertChain.name(),
            workload.identity().to_spiffe_uri(),
            want.to_spiffe_uri()
        );
    }
    let bundle = nucleus_identity::TrustBundle::from_pem(&String::from_utf8_lossy(&bundle))
        .map_err(|e| anyhow!("{} does not parse: {e}", IdentityFile::TrustBundle.name()))?;
    let ders = |b: &nucleus_identity::TrustBundle| {
        b.roots()
            .iter()
            .map(|c| c.der().to_vec())
            .collect::<Vec<_>>()
    };
    if ders(&bundle) != ders(ca.trust_bundle()) {
        bail!(
            "{} is not this host's CA root",
            IdentityFile::TrustBundle.name()
        );
    }
    if workload.expires_within(chrono::Duration::days(CLI_IDENTITY_RENEW_WITHIN_DAYS)) {
        bail!(
            "it expires {}, within {CLI_IDENTITY_RENEW_WITHIN_DAYS} days",
            workload.expiry()
        );
    }
    Ok(paths)
}

/// Where `verify --tier2` looks for the CLI identity on the Tier 2 host.
///
/// `verify --tier2` re-invokes the Linux CLI as root on that host
/// (`limactl shell <vm> -- sudo /usr/local/bin/nucleus verify --tier2 --here`),
/// and `Config::identity_dir()` evaluated as root is this path. It is written
/// out rather than computed because the process that computes it runs on the
/// other machine — on macOS, `Config::identity_dir()` here resolves under the
/// operator's own home, which is what #2715 was.
const TIER2_IDENTITY_DIR: &str = "/root/.config/nucleus/identity";

/// Put the identity just minted where the Tier 2 host will look for it.
///
/// # Why this is a second write and not a different destination
///
/// `mint_cli_identity` writes into `Config::identity_dir()`, which resolves on
/// the machine running `setup`. On macOS that is the operator's Mac, while
/// `verify --tier2` runs the CLI inside the Lima VM as root — so setup minted
/// an identity, verification looked somewhere else, and the error it printed
/// was `run: nucleus setup`, the command that had just run (#2715). The CA root
/// was already seeded in the VM by `load_or_seed_host_ca`, so the identity was
/// the only missing piece; both are needed and both belong on that host.
///
/// The operator's own copy stays where it is: `nucleus node` on the Mac reads
/// it, so this adds a destination rather than moving one. On a Linux host where
/// `setup` already runs as root the two paths coincide and the write is an
/// idempotent rewrite of identical bytes.
///
/// # Why the key goes into the VM at all
///
/// It is the operator's own credential and the VM is the operator's own
/// machine, already holding the CA **private key** that can mint more of them
/// (`{HOST_CA_DIR}/ca-key.pem`). Writing a leaf key beside a root key it is
/// derived from adds no reachable authority. It lands owner-only: staged at
/// `0600` here, copied under `umask 077` there (`put_script`).
///
/// # Why files, not a script (#3158)
///
/// This used to splice the three PEMs into heredocs. A terminator only counts
/// on a line of its own, so a cert without a trailing newline glued the
/// terminator to `-----END CERTIFICATE-----`, the heredoc ran on, and the
/// private key was written into `cli-cert.pem`. The bytes now travel as files
/// through [`Tier2Host::put`], the path every other artifact takes; no secret
/// is ever part of a shell command, and the content cannot change the shape of
/// the command that lands it.
///
/// # What is checked
///
/// Before: [`check_identity`] — each file holds what its name says, and the
/// three belong together. After: each installed file's SHA-256, taken on the
/// host, equals the digest of those checked bytes, so what `verify --tier2`
/// reads is exactly what was checked.
fn install_identity_on_tier2_host(host: &Tier2Host, paths: &MtlsIdentityPaths) -> Result<()> {
    let staging = tempfile::tempdir().context("failed to create a staging directory")?;
    let staged = stage_identity(paths, staging.path(), TIER2_IDENTITY_DIR)?;
    land_staged(host, &staged).with_context(|| {
        format!(
            "failed to install the CLI identity into {TIER2_IDENTITY_DIR} on {} — \
             `nucleus verify --tier2` reads it from there",
            host.describe()
        )
    })
}

/// A file staged locally for [`Tier2Host::put`], with the digest it must have
/// when it arrives.
#[derive(Debug)]
struct StagedFile {
    local: PathBuf,
    remote: String,
    mode: &'static str,
    sha256: String,
}

/// Read the identity under `paths`, refuse it by name unless it passes
/// [`check_identity`], and stage those exact bytes under `staging` for landing
/// in `remote_dir`.
///
/// The pure half of [`install_identity_on_tier2_host`]: no `Tier2Host`, so a
/// test can land the result with `put_script` into a temporary directory.
fn stage_identity(
    paths: &MtlsIdentityPaths,
    staging: &Path,
    remote_dir: &str,
) -> Result<Vec<StagedFile>> {
    let bytes = read_identity(paths)?;
    let [cert, key, bundle] = &bytes;
    check_identity(cert, key, bundle).context("refusing to install the CLI identity")?;
    let files: Vec<_> = IdentityFile::ALL
        .iter()
        .zip(&bytes)
        .map(|(file, b)| (file.name(), b.as_slice(), file.mode()))
        .collect();
    stage_files(staging, remote_dir, &files)
}

/// The bytes of the three identity files under `paths`, in
/// [`IdentityFile::ALL`] order: certificate chain, key, trust bundle.
fn read_identity(paths: &MtlsIdentityPaths) -> Result<[Vec<u8>; 3]> {
    let read = |f: IdentityFile| {
        let p = paths.path(f);
        std::fs::read(p).with_context(|| format!("failed to read {}", p.display()))
    };
    let [cert, key, bundle] = IdentityFile::ALL;
    Ok([read(cert)?, read(key)?, read(bundle)?])
}

/// Write each `(name, bytes, mode)` to `staging/name`, owner-only, and pair it
/// with `remote_dir/name` and the digest of `bytes`.
///
/// Staged rather than handed to `put` from where it lies: `put` removes its
/// source after landing (the `/tmp` copy, on a Lima host), which on a Linux host
/// would be the operator's own identity file.
fn stage_files(
    staging: &Path,
    remote_dir: &str,
    files: &[(&str, &[u8], &'static str)],
) -> Result<Vec<StagedFile>> {
    let mut staged = Vec::with_capacity(files.len());
    for &(name, bytes, mode) in files {
        let local = staging.join(name);
        let mut open = std::fs::OpenOptions::new();
        open.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600);
        }
        let mut file = open
            .open(&local)
            .with_context(|| format!("failed to stage {}", local.display()))?;
        std::io::Write::write_all(&mut file, bytes)
            .with_context(|| format!("failed to stage {}", local.display()))?;
        staged.push(StagedFile {
            local,
            remote: format!("{remote_dir}/{name}"),
            mode,
            sha256: hex::encode(Sha256::digest(bytes)),
        });
    }
    Ok(staged)
}

/// Land each staged file with [`Tier2Host::put`], then confirm on the host
/// that every one arrived byte-for-byte: its SHA-256 there must equal the
/// digest of what was staged. Refuses by path otherwise.
fn land_staged(host: &Tier2Host, staged: &[StagedFile]) -> Result<()> {
    for file in staged {
        host.put(&file.local, &file.remote, file.mode)?;
    }
    for file in staged {
        let out = host.sh(&format!("sha256sum {}", file.remote))?;
        let arrived = sha256sum_digest(&out)
            .ok_or_else(|| anyhow!("sha256sum printed no digest for {}: {out:?}", file.remote))?;
        if arrived != file.sha256 {
            bail!(
                "{} on {} is not the file that was checked: sha256 {arrived}, expected {}",
                file.remote,
                host.describe(),
                file.sha256
            );
        }
    }
    Ok(())
}

/// The digest from one line of `sha256sum` output (`<hex>  <path>`).
fn sha256sum_digest(line: &str) -> Option<&str> {
    let digest = line.split_whitespace().next()?;
    (digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())).then_some(digest)
}

/// The `Tier2Host`-touching half: load the CA root already at `HOST_CA_DIR`
/// on `host`, or generate one and land it there through [`stage_files`] and
/// [`land_staged`] — the same file path the CLI identity takes, never a PEM
/// spliced into a shell command. Exercised by review and the live `setup`;
/// see [`mint_cli_identity`] for the half that IS unit-tested.
///
/// The existing root is read with [`Tier2Host::sh_bytes`], not `sh`: `sh`
/// trims, and the root read through it lost its trailing newline, which is how
/// a re-run of `setup` came to mint a chain whose last line had none (#3158).
fn load_or_seed_host_ca(
    host: &Tier2Host,
    trust_domain: &str,
) -> Result<nucleus_identity::SelfSignedCa> {
    use nucleus_identity::SelfSignedCa;

    let cert_path = format!("{HOST_CA_DIR}/ca-cert.pem");
    let key_path = format!("{HOST_CA_DIR}/ca-key.pem");
    if host.test(&format!("test -f {cert_path} -a -f {key_path}")) {
        let read = |path: &str| -> Result<String> {
            String::from_utf8(host.sh_bytes(&format!("cat {path}"))?)
                .map_err(|e| anyhow!("{path} on {} is not UTF-8: {e}", host.describe()))
        };
        let cert_pem = read(&cert_path)?;
        let key_pem = read(&key_path)?;
        SelfSignedCa::from_pem(trust_domain, &cert_pem, &key_pem).map_err(|e| {
            anyhow!(
                "CA root at {HOST_CA_DIR} on {} is unreadable: {e}",
                host.describe()
            )
        })
    } else {
        let ca = SelfSignedCa::new(trust_domain)
            .map_err(|e| anyhow!("failed to generate a new CA root: {e}"))?;
        let staging = tempfile::tempdir().context("failed to create a staging directory")?;
        let staged = stage_files(
            staging.path(),
            HOST_CA_DIR,
            &[
                ("ca-cert.pem", ca.root_cert_pem().as_bytes(), "0644"),
                ("ca-key.pem", ca.root_key_pem().as_bytes(), "0600"),
            ],
        )?;
        land_staged(host, &staged).with_context(|| {
            format!(
                "failed to seed the CA root into {HOST_CA_DIR} on {}",
                host.describe()
            )
        })?;
        Ok(ca)
    }
}

/// The pure half: mint this CLI's identity from an already-materialized CA
/// and write it under `identity_dir`. No `Tier2Host` involved — takes
/// `identity_dir` as a parameter rather than reading
/// `Config::identity_dir()` itself specifically so a test can point it at a
/// tempdir instead of `~/.config/nucleus/identity`.
async fn mint_cli_identity(
    ca: &nucleus_identity::SelfSignedCa,
    trust_domain: &str,
    identity_dir: &Path,
) -> Result<MtlsIdentityPaths> {
    use nucleus_identity::{CaClient, CsrOptions, Identity};

    // The CLI's own identity: distinct from any pod's (`ns/<pod-namespace>`)
    // and from the node's own self-issued one (`ns/system/sa/node`, see
    // `IdentityManager::node_identity`) — `ns/system/sa/cli` names this
    // operator's own long-lived credential.
    let identity = Identity::new(trust_domain, "system", "cli");
    let csr = CsrOptions::new(identity.to_spiffe_uri())
        .generate()
        .map_err(|e| anyhow!("failed to generate a CSR for the CLI's identity: {e}"))?;
    // 90 days, not a pod's 1-hour default: this is an operator's own
    // credential, not re-minted per session, and 90 days matches the
    // existing secret-rotation reminder convention (`keychain::ROTATION_DAYS`).
    let cert = ca
        .sign_csr(
            csr.csr(),
            csr.private_key(),
            &identity,
            std::time::Duration::from_secs(90 * 24 * 3600),
        )
        .await
        .map_err(|e| anyhow!("failed to sign the CLI's identity: {e}"))?;

    std::fs::create_dir_all(identity_dir)
        .with_context(|| format!("failed to create {}", identity_dir.display()))?;
    let MtlsIdentityPaths {
        cli_cert,
        cli_key,
        trust_bundle: trust_bundle_path,
    } = MtlsIdentityPaths::in_dir(identity_dir);

    std::fs::write(&cli_cert, cert.chain_pem())
        .with_context(|| format!("failed to write {}", cli_cert.display()))?;
    std::fs::write(&cli_key, cert.private_key_pem())
        .with_context(|| format!("failed to write {}", cli_key.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cli_key, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to restrict permissions on {}", cli_key.display()))?;
    }

    // The trust bundle IS the CA's own root cert — a single-entry bundle
    // today, written as one because `--trust-bundle` accepts a concatenated
    // PEM bundle in general (matching tool-proxy/node's own `--trust-bundle`
    // convention), not because this CA ever issues more than one root.
    std::fs::write(&trust_bundle_path, ca.root_cert_pem())
        .with_context(|| format!("failed to write {}", trust_bundle_path.display()))?;

    Ok(MtlsIdentityPaths {
        cli_cert,
        cli_key,
        trust_bundle: trust_bundle_path,
    })
}

/// Write the node's environment file and unit onto `host`.
///
/// The env file is written through a `0600` temp file created by the same
/// command, so the secrets are never briefly world-readable — the window a
/// `write then chmod` would open is small but entirely avoidable.
pub fn install_node_service(host: &Tier2Host, env_body: &str) -> Result<()> {
    println!("  nucleus-node service...");
    host.sh(&format!(
        "set -e
         mkdir -p /etc/nucleus {HOST_STATE_DIR} {HOST_ARTIFACTS_DIR}
         umask 077
         cat > {NODE_ENV_PATH} <<'NUCLEUS_ENV_EOF'
{env_body}NUCLEUS_ENV_EOF
         chmod 0600 {NODE_ENV_PATH}"
    ))?;
    host.sh(&format!(
        "cat > /etc/systemd/system/nucleus-node.service <<'NUCLEUS_UNIT_EOF'
{}NUCLEUS_UNIT_EOF
         systemctl daemon-reload",
        node_unit_body()
    ))?;
    println!("    {NODE_ENV_PATH} (0600) and nucleus-node.service written");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variable the node actually reads, spelled the way it reads it.
    ///
    /// This is the test the previous unit needed and did not have: it was wrong
    /// in three places for as long as nothing compared it to the node's `#[arg]`
    /// attributes.
    #[test]
    fn node_env_uses_the_names_the_node_reads() {
        let body = node_env_body("aa", "bb", "cc", "dd");
        for required in [
            "NUCLEUS_NODE_LISTEN=",
            "NUCLEUS_NODE_GRPC_LISTEN=",
            "NUCLEUS_NODE_AUTH_SECRET=",
            "NUCLEUS_NODE_PROXY_AUTH_SECRET=",
            "NUCLEUS_NODE_PROXY_APPROVAL_SECRET=",
            "NUCLEUS_IDENTITY_WORKLOAD_API_SOCKET=",
        ] {
            assert!(body.contains(required), "node.env is missing {required}");
        }
    }

    /// The three names that were wrong, pinned as wrong. A regression that
    /// reintroduced any of them would otherwise produce a node that exits at
    /// startup with a message about a missing secret.
    #[test]
    fn node_env_does_not_use_the_names_that_never_worked() {
        let body = node_env_body("aa", "bb", "cc", "dd");
        for wrong in [
            "NUCLEUS_NODE_LISTEN_ADDR",
            "NUCLEUS_NODE_GRPC_ADDR",
            "NUCLEUS_NODE_ARTIFACTS_DIR",
        ] {
            assert!(
                !body.contains(wrong),
                "{wrong} is not read by nucleus-node; setting it does nothing"
            );
        }
    }

    /// All three secrets must appear with the values given. The node refuses to
    /// start without any one of them (`nucleus-node/src/main.rs:552,557,562`),
    /// so a partial env file is a node that never comes up.
    #[test]
    fn every_required_secret_reaches_the_env_file() {
        let body = node_env_body("1111", "2222", "3333", "4444");
        assert!(body.contains("NUCLEUS_NODE_AUTH_SECRET=1111"));
        assert!(body.contains("NUCLEUS_NODE_PROXY_AUTH_SECRET=2222"));
        assert!(body.contains("NUCLEUS_NODE_PROXY_APPROVAL_SECRET=3333"));
    }

    /// A secret must never be pasted into the unit file: units are 0644 by
    /// convention and readable by every user on the box.
    #[test]
    fn the_unit_carries_no_secret_and_defers_to_the_env_file() {
        let unit = node_unit_body();
        assert!(unit.contains(&format!("EnvironmentFile={NODE_ENV_PATH}")));
        assert!(!unit.contains("SECRET="), "unit must not inline secrets");
    }

    #[test]
    fn artifact_paths_are_guest_absolute_not_host_relative() {
        assert!(HOST_ARTIFACTS_DIR.starts_with('/'));
        assert!(node_env_body("a", "b", "c", "d").contains(HOST_STATE_DIR));
    }

    /// A provisioned node confines caller-supplied scratch disks to a directory
    /// that is inside its state dir but is NOT the state dir, which holds the CA.
    #[test]
    fn a_provisioned_node_confines_scratch_away_from_its_ca() {
        let body = node_env_body("a", "b", "c", "d");
        assert!(body.contains(&format!("NUCLEUS_NODE_SCRATCH_ROOT={HOST_SCRATCH_ROOT}\n")));
        assert!(HOST_SCRATCH_ROOT.starts_with(&format!("{HOST_STATE_DIR}/")));
        assert!(!HOST_SCRATCH_ROOT.starts_with(HOST_CA_DIR));
    }

    /// A provisioned node admits a pod's kernel and rootfs only from the
    /// directory `setup` installs them into (`--artifacts-root`), which is
    /// outside the state dir and so nowhere near the CA. `nucleus-node`'s
    /// `--data-root` and `--workspace-root` default under the state dir
    /// (`<state>/data`, `<state>/workspaces`), which is already `HOST_STATE_DIR`
    /// here, so they need no line of their own.
    #[test]
    fn a_provisioned_node_admits_kernels_only_from_its_artifacts_dir() {
        let body = node_env_body("a", "b", "c", "d");
        assert!(body.contains(&format!(
            "NUCLEUS_NODE_ARTIFACTS_ROOT={HOST_ARTIFACTS_DIR}\n"
        )));
        assert!(!HOST_ARTIFACTS_DIR.starts_with(&format!("{HOST_STATE_DIR}/")));
        assert!(!HOST_CA_DIR.starts_with(&format!("{HOST_ARTIFACTS_DIR}/")));
    }

    /// The node env file is WRITTEN here and READ back by
    /// `verify::resolve_canary` with `grep -m1 '^NUCLEUS_E2E_CANARY=' | cut -d= -f2-`.
    /// Those are two different languages in two different files, so this pins
    /// the contract: parse the generated body exactly the way the shell does and
    /// require the planted value to come back out.
    #[test]
    fn the_canary_line_round_trips_through_the_shell_parse() {
        let body = node_env_body("aa", "bb", "cc", "deadbeef");

        let parsed = body
            .lines()
            .find(|l| l.starts_with("NUCLEUS_E2E_CANARY="))
            .and_then(|l| l.split_once('=').map(|(_, v)| v))
            .unwrap_or_default();

        assert!(
            parsed.contains("deadbeef"),
            "the canary must survive the grep/cut the verifier uses; got {parsed:?}"
        );
        // One `=` only. A value containing '=' would be truncated by `cut -d=
        // -f2` without `-f2-`, and would fail here first.
        assert_eq!(parsed.matches('=').count(), 0);
    }

    /// A canary equal to a real secret would make a genuine credential leak
    /// indistinguishable from the decoy, and vice versa.
    #[test]
    fn the_canary_is_not_any_of_the_real_secrets() {
        let body = node_env_body("aaaa", "bbbb", "cccc", "dddd");
        let canary = body
            .lines()
            .find(|l| l.starts_with("NUCLEUS_E2E_CANARY="))
            .unwrap();
        for secret in ["aaaa", "bbbb", "cccc"] {
            assert!(
                !canary.contains(secret),
                "canary line must not carry a real secret value"
            );
        }
    }

    /// The bug this pins: `install_binary` stages a release tarball at
    /// `/tmp/<asset>` and asks `put` to land it there, so `put`'s staging source
    /// and its destination are the same file. An unconditional cleanup deleted
    /// the installed archive, and `tar` then failed on a missing file — with
    /// "build provenance verified" printed two lines above, which made it look
    /// like a download problem.
    #[test]
    fn the_cleanup_never_deletes_the_destination() {
        let same = put_script(
            "/tmp/a.tar.gz",
            "/tmp/a.tar.gz.new",
            "/tmp/a.tar.gz",
            "0644",
        );
        // The staged path is cleared before the copy; the source never is.
        assert!(
            !same.lines().any(|l| l.trim() == "rm -f /tmp/a.tar.gz"),
            "source == destination, so there is nothing to clean up:\n{same}"
        );
        assert!(same.contains("mv /tmp/a.tar.gz.new /tmp/a.tar.gz"));
    }

    /// And the ordinary case still cleans up, so the guard above is not a licence
    /// to leave staged copies behind.
    #[test]
    fn a_distinct_source_is_still_cleaned_up() {
        let differ = put_script(
            "/usr/local/bin/nucleus",
            "/usr/local/bin/nucleus.new",
            "/tmp/n",
            "0755",
        );
        assert!(differ.contains("rm -f /tmp/n"), "must clean up:\n{differ}");
    }

    /// The rename must be the last thing that touches the destination.
    #[test]
    fn the_destination_is_written_by_rename_not_by_copy() {
        let s = put_script(
            "/usr/local/bin/nucleus",
            "/usr/local/bin/nucleus.new",
            "/tmp/n",
            "0755",
        );
        assert!(
            !s.contains("cp /tmp/n /usr/local/bin/nucleus\n"),
            "must not copy onto the destination:\n{s}"
        );
        assert!(s.contains("mv /usr/local/bin/nucleus.new /usr/local/bin/nucleus"));
    }

    /// The staged path must be a SIBLING of the destination.
    ///
    /// `mv` within one directory is a `rename(2)` — it swaps the directory entry
    /// instead of writing through it, so it succeeds against a running binary
    /// (ETXTBSY) and is atomic. Staging under `/tmp` instead would very likely be
    /// a cross-filesystem move, which degrades to copy+unlink and brings the
    /// problem back. That derivation lives in `put`, so it is checked at the
    /// source; everything downstream of it is checked against `put_script`.
    #[test]
    fn the_staged_path_is_a_sibling_of_the_destination() {
        let source = include_str!("provision.rs");
        let put = source
            .split("pub fn put(")
            .nth(1)
            .expect("put() must exist");
        let body = &put[..put.find("\n    fn describe").unwrap_or(put.len())];
        assert!(
            body.contains("{remote}.nucleus-new"),
            "the staged path must be derived from the DESTINATION, not from /tmp"
        );
        assert!(
            body.contains("put_script("),
            "landing must go through put_script, which is where the cleanup guard lives"
        );
    }

    /// The first place looked at must be the working directory, not the
    /// directory this binary was compiled in. `CARGO_MANIFEST_DIR` is resolved
    /// at compile time, so a released binary would otherwise search a path that
    /// exists only on the machine that built it.
    #[test]
    fn local_candidates_start_from_the_working_directory() {
        let cwd = std::env::current_dir().expect("cwd");
        for artifact in Tier2Artifact::all() {
            let first = &local_build_candidates(*artifact, "aarch64")[0];
            assert!(
                first.starts_with(&cwd),
                "{artifact:?} looks in {} before the working directory {}",
                first.display(),
                cwd.display()
            );
        }
    }

    /// `Auto` must not claim a local build when only half of one exists — a
    /// rootfs with no matching node (or the reverse) is the mixed state that
    /// would otherwise install silently.
    #[test]
    fn every_guest_artifact_has_a_local_candidate_path() {
        for artifact in Tier2Artifact::all() {
            let candidates = local_build_candidates(*artifact, "aarch64");
            assert!(
                !candidates.is_empty(),
                "{artifact:?} has no local build path, so Auto can never find it"
            );
        }
    }

    /// `setup --artifacts release` must refuse the pinned 2.2.0 guest before it
    /// downloads or touches anything, and say why. It used to pass a floor of
    /// 2.2.0 and install a guest this tree's node cannot boot. Hermetic: the
    /// refusal comes before the release API and before the host, so a VM name
    /// that does not exist is never reached.
    #[test]
    fn a_release_install_refuses_a_guest_this_build_cannot_serve() {
        let cache = tempfile::tempdir().expect("tempdir");
        let err = install_tier2_artifacts(
            &Tier2Host::Lima("nucleus-test-never-reached".into()),
            "aarch64",
            cache.path(),
            ArtifactSource::Release,
        )
        .expect_err("the pinned guest predates #2365 and #2379");
        let msg = format!("{err:#}");
        assert!(msg.contains("#2365") && msg.contains("#2379"), "{msg}");
        assert!(msg.contains("--artifacts local"), "{msg}");
        assert!(
            std::fs::read_dir(cache.path())
                .expect("cache")
                .next()
                .is_none(),
            "nothing may be downloaded before the refusal"
        );
    }

    // ── mTLS identity provisioning (Move A step 6) ──────────────────────────

    #[tokio::test]
    async fn mint_cli_identity_writes_all_three_files_with_the_right_identity() {
        use nucleus_identity::SelfSignedCa;

        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let dir = tempfile::tempdir().unwrap();

        let paths = mint_cli_identity(&ca, "nucleus.local", dir.path())
            .await
            .unwrap();

        assert!(paths.cli_cert.exists());
        assert!(paths.cli_key.exists());
        assert!(paths.trust_bundle.exists());

        // A PEM cert is base64-encoded DER, so the SPIFFE URI never appears
        // as literal text in the file — must parse the SAN out properly,
        // the same way any real relying party would.
        let cert_pem = std::fs::read_to_string(&paths.cli_cert).unwrap();
        let der = nucleus_identity::certificate::Certificate::from_pem(&cert_pem)
            .unwrap()
            .der()
            .to_vec();
        let spiffe_id = nucleus_identity::spiffe_uri_from_svid(&der).unwrap();
        assert_eq!(
            spiffe_id, "spiffe://nucleus.local/ns/system/sa/cli",
            "minted cert should carry the CLI's own identity, not a pod's or the node's"
        );
        assert_eq!(
            std::fs::read_to_string(&paths.trust_bundle).unwrap(),
            ca.root_cert_pem(),
            "the trust bundle IS the CA's own root, unmodified"
        );
    }

    #[cfg(unix)]
    #[test]
    fn mint_cli_identity_key_file_is_owner_only() {
        use nucleus_identity::SelfSignedCa;
        use std::os::unix::fs::PermissionsExt;

        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let paths = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(mint_cli_identity(&ca, "nucleus.local", dir.path()))
            .unwrap();

        let mode = std::fs::metadata(&paths.cli_key)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "key file mode was {mode:o}");
    }

    /// The property step 6 exists for, proven with a REAL mTLS handshake
    /// rather than by inspecting the minted files: the exact PEM files
    /// `mint_cli_identity` writes to disk are read back and used to build a
    /// reqwest client (the same construction `node::create_client`'s mTLS
    /// branch does — kept self-contained here rather than reaching into
    /// that module's private test internals) against a real
    /// `nucleus_identity::TlsServerConfig` server signed by the SAME CA —
    /// the shape a provisioned node's own self-issued listener has.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provisioned_identity_completes_a_real_handshake_against_the_node() {
        use nucleus_identity::{CaClient, CsrOptions, Identity, SelfSignedCa, TlsServerConfig};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let trust_domain = "provision-e2e-test.nucleus.local";
        let ca = SelfSignedCa::new(trust_domain).unwrap();
        let dir = tempfile::tempdir().unwrap();

        // Exactly what `provision_mtls_identity` produces, minus the
        // Tier2Host round trip -- the CA itself is already in hand here,
        // same as `load_or_seed_host_ca` would return.
        let paths = mint_cli_identity(&ca, trust_domain, dir.path())
            .await
            .unwrap();

        // The node's own self-issued server cert, from the SAME CA --
        // mirrors `IdentityManager::node_certificate`.
        let server_identity = Identity::new(trust_domain, "system", "node");
        let server_csr = CsrOptions::new(server_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let server_cert = ca
            .sign_csr(
                server_csr.csr(),
                server_csr.private_key(),
                &server_identity,
                std::time::Duration::from_secs(3600),
            )
            .await
            .unwrap();
        let trust_bundle = ca.trust_bundle().clone();

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();
        let server_handle = tokio::spawn(async move {
            let (stream, _peer) = tcp_listener.accept().await.unwrap();
            let acceptor = TlsServerConfig::new(server_cert, trust_bundle)
                .build_acceptor()
                .unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            let mut buf = [0u8; 1024];
            let n = tls.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).starts_with("GET /v1/health"));
            tls.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}",
            )
            .await
            .unwrap();
        });

        // Read back exactly what was written to disk -- proving the FILES
        // are usable, not just the in-memory `WorkloadCertificate`.
        let mut identity_pem = std::fs::read(&paths.cli_cert).unwrap();
        identity_pem.push(b'\n');
        identity_pem.extend(std::fs::read(&paths.cli_key).unwrap());
        let bundle_pem = std::fs::read(&paths.trust_bundle).unwrap();

        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls =
            nucleus_identity::node_tls::node_client_config(&identity_pem, &bundle_pem).unwrap();
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .build()
            .unwrap();

        let resp = client
            .get(format!("https://{addr}/v1/health"))
            .send()
            .await
            .expect(
                "provisioned identity must complete a real handshake with a node cert \
                 from the same CA",
            );
        assert_eq!(resp.status(), 200);

        server_handle.await.unwrap();
    }

    /// The whole of #2715 in one assertion: the directory setup writes into
    /// must be the directory the root CLI on the Tier 2 host reads from.
    /// Computed here from `Config::identity_dir()`'s own shape rather than
    /// restated, so changing `nucleus_dir()` moves both or fails loudly — the
    /// two drifting apart is exactly the bug.
    #[test]
    fn the_tier2_identity_dir_is_where_the_root_cli_will_look() {
        let home = dirs::home_dir().expect("home directory");
        let local = crate::config::Config::identity_dir().expect("identity dir");
        let under_home = local
            .strip_prefix(&home)
            .expect("the identity dir is under the home directory");
        assert_eq!(
            std::path::Path::new(TIER2_IDENTITY_DIR),
            std::path::Path::new("/root").join(under_home),
            "setup would write the identity somewhere `verify --tier2` does not read"
        );
    }

    // ── #3158: the identity travels as files, and is checked ────────────────

    /// The CA `load_or_seed_host_ca` returned on a re-run before #3158: its
    /// root read back through the trimming `Tier2Host::sh`, so the root PEM —
    /// and therefore the minted chain, whose last certificate it is — ends
    /// without a newline.
    fn reloaded_through_a_trim(
        ca: &nucleus_identity::SelfSignedCa,
    ) -> nucleus_identity::SelfSignedCa {
        nucleus_identity::SelfSignedCa::from_pem(
            "nucleus.local",
            ca.root_cert_pem().trim_end(),
            &ca.root_key_pem(),
        )
        .unwrap()
    }

    /// Land `staged` exactly as `Tier2Host::put` does on a Linux host — through
    /// `put_script`, run by `sh` — except as this user, into `dest`'s tree.
    fn land_locally(staged: &[StagedFile]) {
        for file in staged {
            let script = put_script(
                &file.remote,
                &format!("{}.nucleus-new", file.remote),
                &file.local.display().to_string(),
                file.mode,
            );
            let out = std::process::Command::new("sh")
                .args(["-c", &script])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "landing {} failed: {}",
                file.remote,
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    /// #3158, red on main: a cert chain without a trailing newline — what every
    /// re-run of `setup` minted — is installed byte-for-byte, the key stays out
    /// of the cert file, and the installed identity passes `check_identity`.
    #[tokio::test]
    async fn a_cert_without_a_trailing_newline_is_installed_correctly() {
        let ca =
            reloaded_through_a_trim(&nucleus_identity::SelfSignedCa::new("nucleus.local").unwrap());
        let src = tempfile::tempdir().unwrap();
        let paths = mint_cli_identity(&ca, "nucleus.local", src.path())
            .await
            .unwrap();
        let cert = std::fs::read(&paths.cli_cert).unwrap();
        assert!(!cert.ends_with(b"\n"), "precondition: the re-run shape");

        let staging = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let dest_dir = dest.path().join("identity").display().to_string();
        let staged = stage_identity(&paths, staging.path(), &dest_dir).unwrap();
        land_locally(&staged);

        let installed = MtlsIdentityPaths::in_dir(Path::new(&dest_dir));
        for file in IdentityFile::ALL {
            assert_eq!(
                std::fs::read(installed.path(file)).unwrap(),
                std::fs::read(paths.path(file)).unwrap(),
                "{} did not arrive byte-for-byte",
                file.name()
            );
        }
        let installed_cert = std::fs::read_to_string(&installed.cli_cert).unwrap();
        assert!(
            !installed_cert.contains("PRIVATE KEY"),
            "cli-cert.pem holds a private key:\n{installed_cert}"
        );
        check_identity(
            &std::fs::read(&installed.cli_cert).unwrap(),
            &std::fs::read(&installed.cli_key).unwrap(),
            &std::fs::read(&installed.trust_bundle).unwrap(),
        )
        .expect("the installed identity is valid");
        for file in &staged {
            assert_eq!(
                sha256_file(Path::new(&file.remote)).unwrap(),
                file.sha256,
                "the post-install digest check would refuse {}",
                file.remote
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&installed.cli_key)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "installed key mode was {mode:o}");
        }
    }

    /// The exact file #3158 produced — the private key appended to the
    /// certificate chain — is refused, and by the name of the file at fault.
    #[tokio::test]
    async fn a_cert_file_holding_the_key_is_refused_by_name() {
        let ca = nucleus_identity::SelfSignedCa::new("nucleus.local").unwrap();
        let src = tempfile::tempdir().unwrap();
        let paths = mint_cli_identity(&ca, "nucleus.local", src.path())
            .await
            .unwrap();
        let cert = std::fs::read(&paths.cli_cert).unwrap();
        let key = std::fs::read(&paths.cli_key).unwrap();
        let bundle = std::fs::read(&paths.trust_bundle).unwrap();

        let mut glued = cert.clone();
        glued.extend_from_slice(&key);
        let err = check_identity(&glued, &key, &bundle).unwrap_err();
        assert!(
            format!("{err:#}").contains("cli-cert.pem holds 1 private key"),
            "{err:#}"
        );

        // And the heredoc's leftovers, if a key were not also there.
        let mut trailing = cert.clone();
        trailing.extend_from_slice(b"NUCLEUS_CLI_CERT_EOF\n");
        let err = IdentityFile::CertChain.check(&trailing).unwrap_err();
        assert!(format!("{err:#}").contains("cli-cert.pem"), "{err:#}");

        let mut two_keys = key.clone();
        two_keys.extend_from_slice(&key);
        let err = check_identity(&cert, &two_keys, &bundle).unwrap_err();
        assert!(
            format!("{err:#}").contains("cli-key.pem must hold exactly one private key, found 2"),
            "{err:#}"
        );

        let err = check_identity(&cert, &key, &key).unwrap_err();
        assert!(format!("{err:#}").contains("trust-bundle.pem"), "{err:#}");

        // A key that is not the leaf's.
        let other = tempfile::tempdir().unwrap();
        let other = mint_cli_identity(&ca, "nucleus.local", other.path())
            .await
            .unwrap();
        let err =
            check_identity(&cert, &std::fs::read(&other.cli_key).unwrap(), &bundle).unwrap_err();
        assert!(
            format!("{err:#}").contains("cli-key.pem is not the key"),
            "{err:#}"
        );

        // And `stage_identity` refuses rather than staging any of it.
        std::fs::write(&paths.cli_cert, &glued).unwrap();
        let staging = tempfile::tempdir().unwrap();
        assert!(stage_identity(&paths, staging.path(), "/nowhere").is_err());
        assert_eq!(std::fs::read_dir(staging.path()).unwrap().count(), 0);
    }

    /// Idempotence: a second `setup` keeps the identity it finds instead of
    /// re-minting, so the files on both machines are byte-identical across
    /// runs — including when the CA is reloaded from the host, as it is on
    /// every run after the first.
    #[tokio::test]
    async fn a_second_run_keeps_the_identity_byte_for_byte() {
        let ca = nucleus_identity::SelfSignedCa::new("nucleus.local").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let first = mint_cli_identity(&ca, "nucleus.local", dir.path())
            .await
            .unwrap();
        let before: Vec<_> = IdentityFile::ALL
            .iter()
            .map(|f| std::fs::read(first.path(*f)).unwrap())
            .collect();

        // The second run's CA: the same root, read back raw.
        let reloaded = nucleus_identity::SelfSignedCa::from_pem(
            "nucleus.local",
            &ca.root_cert_pem(),
            &ca.root_key_pem(),
        )
        .unwrap();
        let kept = reusable_cli_identity(&reloaded, "nucleus.local", dir.path())
            .expect("a current identity under the same CA is kept");
        let after: Vec<_> = IdentityFile::ALL
            .iter()
            .map(|f| std::fs::read(kept.path(*f)).unwrap())
            .collect();
        assert_eq!(before, after);

        // A different CA (the host's root was replaced) is not kept.
        let other = nucleus_identity::SelfSignedCa::new("nucleus.local").unwrap();
        assert!(reusable_cli_identity(&other, "nucleus.local", dir.path()).is_err());
        // Nor an identity from another trust domain.
        assert!(reusable_cli_identity(&reloaded, "other.local", dir.path()).is_err());
        // Nor nothing.
        let empty = tempfile::tempdir().unwrap();
        assert!(reusable_cli_identity(&reloaded, "nucleus.local", empty.path()).is_err());
    }

    /// The three filenames are not free: `node.rs::provisioned_identity_paths_in`
    /// requires all three to be present before it will default the node client's
    /// flags, and treats a partial set as none.
    #[tokio::test]
    async fn the_install_lands_all_three_files_the_node_client_requires() {
        let ca = nucleus_identity::SelfSignedCa::new("nucleus.local").unwrap();
        let src = tempfile::tempdir().unwrap();
        let paths = mint_cli_identity(&ca, "nucleus.local", src.path())
            .await
            .unwrap();
        let staging = tempfile::tempdir().unwrap();
        let staged = stage_identity(&paths, staging.path(), TIER2_IDENTITY_DIR).unwrap();
        let landed: Vec<_> = staged.iter().map(|f| (f.remote.as_str(), f.mode)).collect();
        assert_eq!(
            landed,
            [
                (&*format!("{TIER2_IDENTITY_DIR}/cli-cert.pem"), "0644"),
                (&*format!("{TIER2_IDENTITY_DIR}/cli-key.pem"), "0600"),
                (&*format!("{TIER2_IDENTITY_DIR}/trust-bundle.pem"), "0644"),
            ]
        );
    }

    /// No secret is part of a shell command: what lands a file names it by
    /// path, and the PEM bytes never appear in the script. This is the
    /// property that makes #3158 unwritable rather than fixed.
    #[tokio::test]
    async fn no_landing_script_carries_pem_content() {
        let ca = nucleus_identity::SelfSignedCa::new("nucleus.local").unwrap();
        let src = tempfile::tempdir().unwrap();
        let paths = mint_cli_identity(&ca, "nucleus.local", src.path())
            .await
            .unwrap();
        let staging = tempfile::tempdir().unwrap();
        for file in stage_identity(&paths, staging.path(), TIER2_IDENTITY_DIR).unwrap() {
            let script = put_script(
                &file.remote,
                &format!("{}.nucleus-new", file.remote),
                "/tmp/staged",
                file.mode,
            );
            assert!(!script.contains("-----"), "PEM in the script:\n{script}");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&file.local).unwrap().permissions().mode();
                assert_eq!(
                    mode & 0o777,
                    0o600,
                    "{} staged at {mode:o}",
                    file.local.display()
                );
            }
        }
    }

    /// The staged copy is created owner-only, before the `chmod` that gives a
    /// public file its mode, so a key is never briefly world-readable.
    #[test]
    fn the_staged_copy_is_created_owner_only() {
        let s = put_script(
            "/root/k.pem",
            "/root/k.pem.nucleus-new",
            "/tmp/k.pem",
            "0600",
        );
        let cp = s
            .find("(umask 077 && cp ")
            .expect("the copy is umask-scoped");
        let chmod = s.find("chmod 0600").expect("the mode is set");
        assert!(cp < chmod, "{s}");
        assert!(
            s.starts_with("set -e"),
            "a failed step must stop the script"
        );
    }

    #[test]
    fn sha256sum_digest_takes_only_a_digest() {
        let d = "a".repeat(64);
        assert_eq!(sha256sum_digest(&format!("{d}  /x/y")), Some(d.as_str()));
        assert_eq!(sha256sum_digest(""), None);
        assert_eq!(sha256sum_digest("sha256sum: /x: No such file"), None);
    }
}
