//! Build inputs for the first nucleus-on-nucleus run. No source build scripts
//! execute on the host: only Git export and Cargo vendoring run here. The build
//! itself belongs to the supervised, unprivileged workload in the microVM.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

// linux/amd64 manifest resolved from the official 1.96.1-bookworm index on
// 2026-09-12. Docker verifies fetched layers against this immutable manifest.
const RUST_IMAGE: &str =
    "rust@sha256:d99f7b31f49909348dc59b51f3c95d1efded1701ffb222f095aaab7de3c4abd8";
const TOOLCHAIN: &str = "1.96.1";
const GUEST_INPUTS: &str = "/opt/nucleus-build";

#[derive(clap::Args)]
pub struct Args {
    /// Exact commit object ID. Branch names and abbreviated IDs are refused.
    #[arg(long)]
    source_commit: String,
    /// New output directory; an existing directory is never overwritten.
    #[arg(long)]
    output: PathBuf,
    /// Trusted bootstrap musl binaries, built separately from the build subject.
    #[arg(long)]
    guest_bin_dir: PathBuf,
    /// Independently obtained kernel and its expected SHA-256.
    #[arg(long, requires = "kernel_sha256")]
    kernel: Option<PathBuf>,
    #[arg(long, requires = "kernel")]
    kernel_sha256: Option<String>,
}

#[derive(Serialize)]
struct InputFile {
    path: PathBuf,
    sha256: String,
}

#[derive(Serialize)]
struct BuildInputs {
    schema: &'static str,
    architecture: &'static str,
    source_commit: String,
    source_tree: String,
    source_archive_sha256: String,
    toolchain: &'static str,
    base_image: &'static str,
    bootstrap: std::collections::BTreeMap<String, String>,
    kernel: InputFile,
    rootfs: InputFile,
}

pub fn run(args: Args) -> Result<()> {
    let Args {
        source_commit,
        output,
        guest_bin_dir,
        kernel,
        kernel_sha256,
    } = args;
    ensure!(
        std::env::consts::OS == "linux" && std::env::consts::ARCH == "x86_64",
        "build-image requires a Linux x86_64 host with Docker and e2fsprogs"
    );
    if let (Some(path), Some(pin)) = (&kernel, &kernel_sha256) {
        ensure!(is_hex(pin, 64), "kernel SHA-256 must be lowercase hex");
        ensure!(
            sha256(path)? == *pin,
            "kernel digest differs from controller pin"
        );
    }
    let repo = std::env::current_dir()?;
    let source_tree = resolve_source(&repo, &source_commit)?;
    // Check all bootstrap inputs before allocating the image. These hashes are
    // provenance, not permission to promote an arbitrary PR-built executor.
    let mut bootstrap = std::collections::BTreeMap::new();
    for name in [
        "nucleus-guest-init",
        "nucleus-tool-proxy",
        "nucleus-net-probe",
    ] {
        bootstrap.insert(name.to_owned(), sha256(&guest_bin_dir.join(name))?);
    }
    fs::create_dir(&output).context("output must be a new directory")?;
    let output = output.canonicalize()?;
    let kernel_path = output.join("vmlinux");
    let kernel_sha256 = match (kernel, kernel_sha256) {
        (Some(path), Some(pin)) => {
            fs::copy(path, &kernel_path)?;
            pin
        }
        (None, None) => {
            let pin = nucleus_spec::tier2_artifacts::KERNEL_X86_64;
            checked(
                Command::new("curl")
                    .args(["--fail", "--location", "--retry", "2", "--output"])
                    .arg(&kernel_path)
                    .arg(pin.url),
            )?;
            pin.sha256.to_owned()
        }
        _ => bail!("kernel path and digest must be supplied together"),
    };
    ensure!(
        sha256(&kernel_path)? == kernel_sha256,
        "placed kernel differs from controller pin"
    );
    let root = output.join("rootfs");
    fs::create_dir(&root)?;
    export_base(&output, &root)?;
    // Refuse a baked workload: the host-fetched spec must be the only command
    // source. A base image changing this convention must stop preparation.
    for name in ["etc/nucleus/pod.yaml", "pod.yaml"] {
        ensure!(
            !root.join(name).try_exists()?,
            "base image contains a baked pod spec"
        );
    }
    let inputs = root.join("opt/nucleus-build");
    fs::create_dir_all(&inputs)?;
    let archive = output.join("source.tar");
    materialize(&repo, &source_commit, &archive, &inputs.join("source"))?;
    let toolchain: toml::Value = toml::from_str(&fs::read_to_string(
        inputs.join("source/rust-toolchain.toml"),
    )?)?;
    ensure!(
        toolchain
            .get("toolchain")
            .and_then(|v| v.get("channel"))
            .and_then(toml::Value::as_str)
            == Some(TOOLCHAIN),
        "source toolchain differs from pinned build image"
    );
    let vendor_cwd = output.join("vendor-cwd");
    fs::create_dir(&vendor_cwd)?;
    let vendor = inputs.join("vendor");
    // Run outside the source tree so its .cargo/config cannot nominate a host
    // rustc wrapper or credential process. Explicit toolchain avoids rustup's
    // directory override. Cargo vendor fetches source; it does not compile it.
    let config = capture(
        Command::new("rustup")
            .current_dir(&vendor_cwd)
            .args([
                "run",
                TOOLCHAIN,
                "cargo",
                "vendor",
                "--locked",
                "--versioned-dirs",
                "--manifest-path",
            ])
            .arg(inputs.join("source/Cargo.toml"))
            .arg(&vendor),
    )?;
    fs::write(
        inputs.join("cargo-config.toml"),
        guest_vendor_config(&config, &vendor)?,
    )?;
    fs::create_dir_all(root.join("usr/local/bin"))?;
    fs::create_dir_all(root.join("etc/nucleus"))?;
    fs::create_dir_all(root.join("work"))?;
    copy_executable(
        &guest_bin_dir.join("nucleus-guest-init"),
        &root.join("init"),
    )?;
    for name in ["nucleus-tool-proxy", "nucleus-net-probe"] {
        copy_executable(
            &guest_bin_dir.join(name),
            &root.join("usr/local/bin").join(name),
        )?;
    }
    for (name, digest) in &bootstrap {
        let placed = if name == "nucleus-guest-init" {
            root.join("init")
        } else {
            root.join("usr/local/bin").join(name)
        };
        ensure!(
            sha256(&placed)? == *digest,
            "bootstrap binary changed during preparation: {name}"
        );
    }
    let rootfs_path = output.join("rootfs.ext4");
    // A fixed ceiling makes disk demand reviewable. Sparse ext4; free space is
    // not writable by the workload because the node mounts this image read-only.
    checked(
        Command::new("mke2fs")
            .args(["-q", "-t", "ext4", "-m", "0", "-F", "-d"])
            .arg(&root)
            .arg(&rootfs_path)
            .arg("8192M"),
    )?;
    let manifest = BuildInputs {
        schema: "nucleus.build-inputs.v1",
        architecture: "x86_64",
        source_commit,
        source_tree,
        source_archive_sha256: sha256(&archive)?,
        toolchain: TOOLCHAIN,
        base_image: RUST_IMAGE,
        bootstrap,
        kernel: InputFile {
            path: kernel_path,
            sha256: kernel_sha256,
        },
        rootfs: InputFile {
            sha256: sha256(&rootfs_path)?,
            path: rootfs_path,
        },
    };
    fs::write(
        output.join("inputs.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    println!(
        "prepared {} (inputs only; no build has run)",
        output.join("inputs.json").display()
    );
    Ok(())
}

fn resolve_source(repo: &Path, commit: &str) -> Result<String> {
    ensure!(
        is_hex(commit, 40) || is_hex(commit, 64),
        "source must be a full lowercase commit object ID"
    );
    let actual = capture(Command::new("git").current_dir(repo).args([
        "rev-parse",
        "--verify",
        "--end-of-options",
        &format!("{commit}^{{commit}}"),
    ]))?;
    ensure!(
        actual.trim() == commit,
        "source must name a commit, not a tag object"
    );
    let entries = capture(
        Command::new("git")
            .current_dir(repo)
            .args(["ls-tree", "-r", commit]),
    )?;
    ensure!(
        !entries.lines().any(|l| l.starts_with("160000 ")),
        "submodules require explicit materialization; refusing an incomplete source tree"
    );
    Ok(capture(Command::new("git").current_dir(repo).args([
        "rev-parse",
        "--verify",
        &format!("{commit}^{{tree}}"),
    ]))?
    .trim()
    .to_owned())
}

fn materialize(repo: &Path, commit: &str, archive: &Path, destination: &Path) -> Result<()> {
    // Revalidate here too: callers cannot accidentally feed a branch name into
    // archive after having resolved a different commit for the manifest.
    resolve_source(repo, commit)?;
    fs::create_dir(destination)?;
    checked(
        Command::new("git")
            .current_dir(repo)
            .args(["archive", "--format=tar", "--output"])
            .arg(archive)
            .arg(commit),
    )?;
    checked(
        Command::new("tar")
            .arg("-xf")
            .arg(archive)
            .arg("-C")
            .arg(destination),
    )
}

fn export_base(output: &Path, root: &Path) -> Result<()> {
    let id = capture(Command::new("docker").args([
        "create",
        "--platform",
        "linux/amd64",
        RUST_IMAGE,
        "/bin/true",
    ]))?;
    let id = id.trim();
    ensure!(is_hex(id, 64), "Docker returned an invalid container ID");
    let archive = output.join("base.tar");
    let exported = checked(
        Command::new("docker")
            .arg("export")
            .arg(id)
            .arg("--output")
            .arg(&archive),
    );
    let removed = checked(Command::new("docker").args(["rm", id]));
    exported?;
    removed?;
    checked(
        Command::new("tar")
            .arg("-xf")
            .arg(&archive)
            .arg("-C")
            .arg(root),
    )?;
    fs::remove_file(archive)?;
    Ok(())
}

fn guest_vendor_config(config: &str, vendor: &Path) -> Result<String> {
    let mut config: toml::Value = toml::from_str(config).context("Cargo vendor configuration")?;
    let sources = config
        .get_mut("source")
        .and_then(toml::Value::as_table_mut)
        .context("Cargo vendor returned no sources")?;
    let mut directories = 0u32;
    for (_, source) in sources.iter_mut() {
        if let Some(directory) = source.get_mut("directory") {
            ensure!(
                directory.as_str() == vendor.to_str(),
                "unexpected vendor directory"
            );
            *directory = toml::Value::String(format!("{GUEST_INPUTS}/vendor"));
            directories = directories.saturating_add(1);
        }
    }
    ensure!(
        directories == 1,
        "expected exactly one vendored source directory"
    );
    Ok(toml::to_string(&config)?)
}

fn copy_executable(source: &Path, target: &Path) -> Result<()> {
    fs::copy(source, target)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(target, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn sha256(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hash.update(buf.get(..read).context("file read exceeded buffer")?);
    }
    Ok(hex::encode(hash.finalize()))
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn checked(command: &mut Command) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("spawn {command:?}"))?;
    ensure!(status.success(), "{command:?} failed: {status}");
    Ok(())
}

fn capture(command: &mut Command) -> Result<String> {
    let output = command
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("spawn {command:?}"))?;
    if !output.status.success() {
        bail!("{command:?} failed: {}", output.status);
    }
    String::from_utf8(output.stdout).context("command emitted non-UTF-8 output")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn materialization_uses_commit_objects_not_dirty_or_untracked_files() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo)?;
        checked(Command::new("git").current_dir(&repo).args(["init", "-q"]))?;
        fs::write(repo.join("input"), "committed")?;
        checked(
            Command::new("git")
                .current_dir(&repo)
                .args(["add", "input"]),
        )?;
        checked(Command::new("git").current_dir(&repo).args([
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        ]))?;
        let commit = capture(
            Command::new("git")
                .current_dir(&repo)
                .args(["rev-parse", "HEAD"]),
        )?;
        fs::write(repo.join("input"), "dirty")?;
        fs::write(repo.join("untracked"), "must not enter image")?;
        let dest = tmp.path().join("export");
        materialize(&repo, commit.trim(), &tmp.path().join("source.tar"), &dest)?;
        assert_eq!(fs::read_to_string(dest.join("input"))?, "committed");
        assert!(!dest.join("untracked").exists());
        assert!(resolve_source(&repo, "HEAD").is_err());
        assert!(resolve_source(&repo, "--help").is_err());
        Ok(())
    }

    #[test]
    fn vendor_configuration_is_relocated_and_unexpected_paths_refused() -> Result<()> {
        let config = "[source.crates-io]\nreplace-with = 'vendored-sources'\n[source.vendored-sources]\ndirectory = '/host/vendor'\n";
        let relocated = guest_vendor_config(config, Path::new("/host/vendor"))?;
        assert!(relocated.contains("/opt/nucleus-build/vendor"));
        assert!(!relocated.contains("/host/vendor"));
        assert!(guest_vendor_config(config, Path::new("/another/vendor")).is_err());
        assert!(guest_vendor_config("[source.crates-io]\n", Path::new("/host/vendor")).is_err());
        Ok(())
    }
}
