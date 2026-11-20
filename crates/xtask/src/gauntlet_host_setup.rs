//! `cargo xtask gauntlet-host-setup`: prepare a fresh Linux KVM host for
//! `cargo xtask links-live` (ADR 0017 §10), as one Rust command rather than a
//! recipe of shell lines.
//!
//! It follows `quickstart-boot.yml` and `podlist-probe.yml`: check KVM and
//! vsock, build the static binaries (plus `nucleus-egress-proxy`, the link
//! relay, and `nucleus-link-probe`, the workload), build the rootfs with the
//! probe laid in by `OVERLAY_DIR` (the existing `build-rootfs.sh`, invoked, not
//! rewritten), stage copies before `nucleus setup --artifacts local` moves the
//! originals, and stage the kernel setup installed. It prints the
//! `links-live` command to run next.
use anyhow::{Context, Result, bail, ensure};
use std::path::{Path, PathBuf};
use std::process::Command;

const TARGET: &str = "x86_64-unknown-linux-musl";

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Skip the cargo build (binaries already in target/<musl>/release).
    #[arg(long)]
    pub skip_build: bool,
    /// Skip `nucleus setup` (Firecracker, jailer and kernel already installed).
    #[arg(long)]
    pub skip_setup: bool,
}

fn run(mut c: Command, what: &str) -> Result<()> {
    let status = c.status().with_context(|| format!("starting {what}"))?;
    ensure!(status.success(), "{what} failed: {status}");
    Ok(())
}

fn sudo(args: &[&str]) -> Command {
    let mut c = Command::new("sudo");
    c.args(args);
    c
}

fn find_named(dir: &Path, prefix: &str) -> Option<PathBuf> {
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(p) = find_named(&path, prefix) {
                return Some(p);
            }
        } else if path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with(prefix))
        {
            return Some(path);
        }
    }
    None
}

pub fn run_setup(root: &Path, args: &Args) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "gauntlet-host-setup is for a Linux KVM host"
    );
    ensure!(
        Path::new("/dev/kvm").exists(),
        "no /dev/kvm: is nested virtualization on?"
    );
    run(sudo(&["chmod", "666", "/dev/kvm"]), "chmod /dev/kvm")?;
    run(sudo(&["modprobe", "vhost_vsock"]), "modprobe vhost_vsock")?;
    run(sudo(&["modprobe", "br_netfilter"]), "modprobe br_netfilter")?;
    ensure!(
        Path::new("/dev/vhost-vsock").exists(),
        "no /dev/vhost-vsock"
    );

    let release = root.join("target").join(TARGET).join("release");
    if !args.skip_build {
        let mut rustup = Command::new("rustup");
        rustup.current_dir(root).args(["target", "add", TARGET]);
        run(rustup, "rustup target add")?;
        let listed = Command::new("bash")
            .current_dir(root)
            .args(["scripts/cross-build.sh", "--list-packages"])
            .output()?;
        ensure!(
            listed.status.success(),
            "cross-build.sh --list-packages failed"
        );
        let mut cargo = Command::new("cargo");
        cargo
            .current_dir(root)
            .args(["build", "--release", "--target", TARGET]);
        for p in [
            "nucleus-cli",
            "nucleus-node",
            "nucleus-microvm-host",
            "nucleus-egress-proxy",
            "nucleus-link-probe",
        ] {
            cargo.args(["-p", p]);
        }
        for p in String::from_utf8(listed.stdout)?.split_whitespace() {
            cargo.args(["-p", p]);
        }
        run(cargo, "cargo build (musl release)")?;
    }

    let stage = root.join("target").join("gauntlet");
    let bin = stage.join("bin");
    let overlay = stage.join("overlay").join("usr/local/bin");
    std::fs::create_dir_all(&bin)?;
    std::fs::create_dir_all(&overlay)?;
    std::fs::copy(
        release.join("nucleus-link-probe"),
        overlay.join("nucleus-link-probe"),
    )
    .context("nucleus-link-probe was not built")?;
    for b in ["nucleus-node", "nucleus-egress-proxy", "nucleus-hostctl"] {
        std::fs::copy(release.join(b), bin.join(b))
            .with_context(|| format!("{b} was not built"))?;
    }

    let mut rootfs = Command::new("bash");
    rootfs
        .current_dir(root)
        .env(
            "POD_SPEC",
            root.join("examples/openclaw-demo/probe-pod.yaml"),
        )
        .env("OVERLAY_DIR", stage.join("overlay"))
        .env("ARCH", "x86_64")
        .arg("scripts/firecracker/build-rootfs.sh");
    run(rootfs, "build-rootfs.sh")?;
    let built = root.join("build/firecracker/x86_64/rootfs.ext4");
    let staged_rootfs = stage.join("links-rootfs.ext4");
    std::fs::copy(&built, &staged_rootfs).context("the rootfs was not built")?;

    if !args.skip_setup {
        run(
            sudo(&[
                "cp",
                &release.join("nucleus").to_string_lossy(),
                "/usr/local/bin/nucleus",
            ]),
            "install nucleus",
        )?;
        let mut setup = Command::new("nucleus");
        setup
            .current_dir(root)
            .args(["setup", "--skip-verify", "--artifacts", "local"]);
        run(setup, "nucleus setup")?;
        // The gauntlet starts its own node; the installed service is not needed.
        let _ = sudo(&["systemctl", "stop", "nucleus-node"]).status();
    }
    let kernel = find_named(Path::new("/var/lib/nucleus/artifacts"), "vmlinux")
        .or_else(|| find_named(Path::new("/var/lib/nucleus"), "vmlinux"));
    let Some(kernel) = kernel else {
        bail!("no vmlinux under /var/lib/nucleus: did `nucleus setup` install the kernel?");
    };
    let staged_kernel = stage.join("vmlinux");
    std::fs::copy(&kernel, &staged_kernel)?;

    println!("gauntlet-host-setup: ready. Run:");
    println!(
        "  cargo xtask links-live --bin-dir {} --kernel {} --rootfs {} --sudo",
        bin.display(),
        staged_kernel.display(),
        staged_rootfs.display()
    );
    Ok(())
}
