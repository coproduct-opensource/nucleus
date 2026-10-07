//! `cargo xtask guest-kernel-mirror` — publish the pinned guest kernel's bytes
//! as a release asset (#2696 P3, S4).
//!
//! The guest kernel is a Firecracker CI build under a DATED bucket prefix, the
//! first upstream line with Landlock compiled in. A dated prefix is CI output:
//! nothing promises it stays. So each release mirrors the exact pinned bytes as
//! an asset, signed and attested like every other asset in `release.yml`.
//! v2.6.0 was the first to publish it, and the pin
//! (`nucleus_spec::tier2_artifacts::KERNEL_*`) now names v2.6.0's mirror with
//! the SAME digest it had on the upstream URL. A later release therefore fetches
//! from that mirror and republishes the same bytes under its own version.
//!
//! Two steps, the shape `release-reference-manifest` already has: this command
//! writes a `curl --config` for the pinned URL (the workflow runs curl), then
//! `stage` refuses any bytes whose SHA-256 is not the pin's and only then
//! places them under the asset name [`Kernel::mirror_asset_name`] gives. A
//! mirror of the wrong bytes would be worse than no mirror: it would carry the
//! release's signature.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use nucleus_spec::tier2_artifacts::{Kernel, kernel_for};
use sha2::{Digest, Sha256};

use crate::release_reference::Arch;

/// Arguments.
#[derive(clap::Subcommand, Debug)]
pub enum Args {
    /// Write a `curl --config` file that downloads the pinned guest kernel for
    /// ARCH to OUTPUT (the release workflow runs it).
    FetchConfig {
        #[arg(long, value_enum)]
        arch: Arch,
        /// Where curl writes the kernel.
        #[arg(long)]
        output: PathBuf,
        /// Where this command writes the curl configuration.
        #[arg(long)]
        out: PathBuf,
    },
    /// Check FILE against ARCH's pinned digest and copy it into DIST under the
    /// release asset name. Refuses, and writes nothing, on any other bytes.
    Stage {
        #[arg(long, value_enum)]
        arch: Arch,
        /// The downloaded kernel.
        #[arg(long)]
        file: PathBuf,
        /// The release version, as in the asset names.
        #[arg(long)]
        version: String,
        /// The directory the release collects assets from.
        #[arg(long)]
        dist: PathBuf,
    },
}

fn pin(arch: Arch) -> Kernel {
    // Both architectures a release ships are pinned; `kernel_for` answering
    // `None` for one of them would be a broken spec, not a missing kernel.
    kernel_for(arch.name()).expect("every release architecture has a pinned guest kernel")
}

/// Copy `file` to `dist/<asset name>` only if its digest is `pinned`. Returns
/// the path written.
fn stage(file: &Path, pinned: &str, version: &str, arch: Arch, dist: &Path) -> Result<PathBuf> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let got = hex::encode(Sha256::digest(&bytes));
    if got != pinned {
        bail!(
            "{} has sha256 {got}, not the pinned guest kernel's {pinned}; refusing to mirror it",
            file.display()
        );
    }
    std::fs::create_dir_all(dist).with_context(|| format!("creating {}", dist.display()))?;
    let out = dist.join(Kernel::mirror_asset_name(version, arch.name()));
    std::fs::write(&out, &bytes).with_context(|| format!("writing {}", out.display()))?;
    Ok(out)
}

/// Run.
pub fn run(a: &Args) -> Result<()> {
    match a {
        Args::FetchConfig { arch, output, out } => {
            let config = format!(
                "url = \"{}\"\noutput = \"{}\"\n",
                pin(*arch).url,
                output.display()
            );
            std::fs::write(out, config).with_context(|| format!("writing {}", out.display()))
        }
        Args::Stage {
            arch,
            file,
            version,
            dist,
        } => {
            let out = stage(file, pin(*arch).sha256, version, *arch, dist)?;
            println!("staged {}", out.display());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal (A-19 for this command): bytes that are not the pin's are
    /// never placed in the release directory. Red if `stage` copied first and
    /// checked after, or skipped the check.
    #[test]
    fn bytes_off_the_pin_are_refused_and_nothing_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("vmlinux");
        std::fs::write(&file, b"not the pinned kernel").unwrap();
        let dist = dir.path().join("dist");
        let err = stage(
            &file,
            pin(Arch::Aarch64).sha256,
            "2.6.0",
            Arch::Aarch64,
            &dist,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("refusing to mirror"), "{err}");
        assert!(
            !dist.exists(),
            "nothing may be staged for bytes off the pin"
        );
    }

    /// The bytes whose digest is the pin are staged under the one asset name.
    #[test]
    fn bytes_on_the_pin_are_staged_under_the_asset_name() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("vmlinux");
        std::fs::write(&file, b"a kernel").unwrap();
        let digest = hex::encode(Sha256::digest(b"a kernel"));
        let dist = dir.path().join("dist");
        let out = stage(&file, &digest, "2.6.0", Arch::X86_64, &dist).unwrap();
        assert_eq!(
            out.file_name().unwrap().to_str().unwrap(),
            "nucleus-guest-kernel-2.6.0-x86_64.vmlinux"
        );
        assert_eq!(std::fs::read(out).unwrap(), b"a kernel");
    }

    /// The fetch config names exactly the pinned URL for each architecture.
    #[test]
    fn the_fetch_config_names_the_pinned_url() {
        let dir = tempfile::tempdir().unwrap();
        for arch in [Arch::Aarch64, Arch::X86_64] {
            let out = dir.path().join("k.curl");
            run(&Args::FetchConfig {
                arch,
                output: "k".into(),
                out: out.clone(),
            })
            .unwrap();
            let config = std::fs::read_to_string(&out).unwrap();
            assert!(config.contains(&format!("url = \"{}\"", pin(arch).url)));
        }
    }
}
