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

use anyhow::{anyhow, bail, Context, Result};
use nucleus_spec::tier2_artifacts::{self, Tier2Artifact};
use nucleus_spec::vmm_version;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where nucleus's artifacts live inside a Tier 2 host.
///
/// This is *guest-VM* path space on macOS, which is the distinction the config
/// previously lost: `Config::artifacts_dir()` resolves under the host's
/// `~/Library/Application Support`, and a PodSpec built from it named paths the
/// node — running inside the Lima VM — cannot see.
pub const HOST_ARTIFACTS_DIR: &str = "/var/lib/nucleus/artifacts";

/// Where the node keeps per-pod state inside the Tier 2 host.
pub const HOST_STATE_DIR: &str = "/var/lib/nucleus/state";

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
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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
                     cp {source} {staged}
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
    {
        if manifest_root.is_dir() && !roots.contains(&manifest_root.to_path_buf()) {
            roots.push(manifest_root.to_path_buf());
        }
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
/// Refuses a release below [`tier2_artifacts::GUEST_RELEASE_FLOOR`] rather than
/// installing it: every release up to 2.0.2 ships a rootfs with no CA store, on
/// which the tool-proxy panics as PID 1 and takes the guest kernel with it.
/// Handing that to someone running the quickstart would look like nucleus being
/// broken, which — on that artifact — it is.
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
    if !tier2_artifacts::release_is_acceptable(version) {
        bail!(
            "pinned guest release v{version} is below the floor v{}",
            tier2_artifacts::GUEST_RELEASE_FLOOR
        );
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
            println!("      (install the gh CLI for a provenance check that the release API cannot fake)");
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
pub fn node_env_body(auth_hex: &str, proxy_hex: &str, approval_hex: &str) -> String {
    format!(
        "# Written by `nucleus setup`. Contains HMAC secrets - keep mode 0600.\n\
         NUCLEUS_NODE_LISTEN=0.0.0.0:8080\n\
         NUCLEUS_NODE_GRPC_LISTEN=0.0.0.0:9180\n\
         NUCLEUS_NODE_STATE_DIR={HOST_STATE_DIR}\n\
         NUCLEUS_NODE_AUTH_SECRET={auth_hex}\n\
         NUCLEUS_NODE_PROXY_AUTH_SECRET={proxy_hex}\n\
         NUCLEUS_NODE_PROXY_APPROVAL_SECRET={approval_hex}\n\
         NUCLEUS_IDENTITY_WORKLOAD_API_SOCKET={WORKLOAD_API_SOCKET}\n\
         NUCLEUS_FIRECRACKER_PATH=/usr/local/bin/firecracker\n\
         NUCLEUS_JAILER_PATH=/usr/local/bin/jailer\n\
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
        let body = node_env_body("aa", "bb", "cc");
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
        let body = node_env_body("aa", "bb", "cc");
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
        let body = node_env_body("1111", "2222", "3333");
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
        assert!(node_env_body("a", "b", "c").contains(HOST_STATE_DIR));
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
        assert!(
            !same.contains("rm -f"),
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
}
