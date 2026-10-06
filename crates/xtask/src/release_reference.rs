//! `cargo xtask release-reference-manifest` — the node reference manifest a
//! release publishes (`nucleus-node-reference/v1`, ADR 0011).
//!
//! A relying party appraising a node's TPM evidence needs reference values it
//! did not get from the node. For the node's own files, the release is the
//! right source: the IMA allowlist digests here are computed from the bytes
//! the release ships — `nucleus-node` from the musl tarball `nucleus setup`
//! installs, `firecracker` and `jailer` from the upstream release archive at
//! the version the node pins ([`nucleus_spec::vmm_version::PINNED_STR`]) — and
//! never from an event log.
//!
//! What a release does NOT determine is written out as `not_checked` with the
//! reason, never omitted and never guessed (ADR 0007 A-2, B-2): the release
//! publishes no host image, so Secure Boot state, EFI applications, boot
//! files, the kernel command line and PCR pins are the operator's to supply
//! (`cargo xtask node-reference-manifest --ima-from-manifest <this>` folds
//! this manifest's allowlist into an operator's boot pins).
//!
//! Firecracker and jailer are *allowed*, not *required*: IMA measures a binary
//! when it is executed, and a node quoted before its first pod has not executed
//! either. A replaced binary that did run is still measured with a digest that
//! is not allowed, which contests the evidence. `nucleus-node` is required —
//! the evidence exists only because it ran.
//!
//! The IMA reference is scoped to the install directory
//! (`scope: {path_prefixes: [<install-dir>]}`, #3276). A host whose Secure
//! Boot IMA policy measures kernel modules logs files the release cannot
//! vouch for; out of scope they are listed beside the verdict, not contested.
//! Inside the scope nothing is forgiven: an unlisted or replaced binary there
//! contests. The scope is in the signed manifest, so the evidence never sets
//! or widens it.
//!
//! The manifest is published as a release asset and signed like every other
//! asset (`cosign sign-blob`), which records its digest in the public Sigstore
//! transparency log — the "publish measurements to a log" pattern of arXiv
//! 2409.03720 (Confidential Computing Transparency). The guide is
//! `docs/stranger-verification.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use nucleus_node_evidence::{
    Expect, ImaReference, ImaScope, REFERENCE_PROFILE, ReferenceManifest, ReferenceValues,
};
use nucleus_spec::tier2_artifacts::Tier2Artifact;
use nucleus_spec::vmm_version::PINNED_STR as FIRECRACKER_VERSION;
use sha2::{Digest, Sha256};

/// Why the boot checks are not in a release manifest.
pub(crate) const NO_HOST_IMAGE: &str = "the release publishes no host image: boot measurements \
     (Secure Boot, EFI applications, boot files, kernel command line, PCR pins) are the \
     operator's to supply";

/// Where `nucleus setup` installs the node binaries. IMA records the path a
/// file was executed from after symlinks resolve, so a node that keeps its
/// binaries on a dedicated filesystem regenerates with `--install-dir`.
const DEFAULT_INSTALL_DIR: &str = "/usr/local/bin";

/// A Linux architecture a release ships a node for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Arch {
    /// `aarch64-unknown-linux-musl`.
    Aarch64,
    /// `x86_64-unknown-linux-musl`.
    #[value(name = "x86_64")]
    X86_64,
}

impl Arch {
    /// The name in the upstream Firecracker archive and in release asset names.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Aarch64 => "aarch64",
            Self::X86_64 => "x86_64",
        }
    }
}

/// Arguments.
#[derive(clap::Subcommand, Debug)]
pub enum Args {
    /// Write a `curl --config` file that downloads the pinned upstream
    /// Firecracker archive for ARCH to OUTPUT (the release workflow runs it).
    FetchConfig {
        #[arg(long, value_enum)]
        arch: Arch,
        /// Where curl writes the archive.
        #[arg(long)]
        output: PathBuf,
        /// Where this command writes the curl configuration.
        #[arg(long)]
        out: PathBuf,
    },
    /// Write the manifest from a release's build outputs.
    Emit(Box<EmitArgs>),
}

/// `emit`.
#[derive(clap::Args, Debug)]
pub struct EmitArgs {
    /// A directory holding the release's `nucleus-node-<version>-<target>.tar.gz`
    /// (searched recursively: the release job downloads one directory per artifact).
    #[arg(long)]
    dist: PathBuf,
    /// The release version, as in the asset names.
    #[arg(long)]
    version: String,
    #[arg(long, value_enum)]
    arch: Arch,
    /// The upstream Firecracker release archive for ARCH at the pinned version.
    #[arg(long)]
    firecracker_tgz: PathBuf,
    /// The directory the binaries are executed from on the node.
    #[arg(long, default_value = DEFAULT_INSTALL_DIR)]
    install_dir: String,
    /// The manifest file to write.
    #[arg(long)]
    out: PathBuf,
}

fn firecracker_url(arch: Arch) -> String {
    let (v, a) = (FIRECRACKER_VERSION, arch.name());
    format!(
        "https://github.com/firecracker-microvm/firecracker/releases/download/v{v}/firecracker-v{v}-{a}.tgz"
    )
}

/// Every file under `dir` named `name`.
fn find_named(dir: &Path, name: &str, found: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            find_named(&path, name, found)?;
        } else if entry.file_name() == name {
            found.push(path);
        }
    }
    Ok(())
}

/// The SHA-256 of the one regular file at `member` inside a gzip tarball.
/// Absent or present twice is an error: a manifest that allowed "whichever
/// one" would pin nothing.
fn member_digest(tgz: &Path, member: &str) -> Result<String> {
    let file = std::fs::File::open(tgz).with_context(|| format!("opening {}", tgz.display()))?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let mut digest = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        // Upstream archives may spell members `./release-…`; compare without
        // the `.` components.
        let path: PathBuf = entry
            .path()?
            .components()
            .filter(|c| !matches!(c, std::path::Component::CurDir))
            .collect();
        if path != Path::new(member) {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            bail!("{member} in {} is not a regular file", tgz.display());
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        if digest
            .replace(hex::encode(Sha256::digest(&bytes)))
            .is_some()
        {
            bail!("{member} appears twice in {}", tgz.display());
        }
    }
    digest.ok_or_else(|| anyhow!("{} has no {member}", tgz.display()))
}

/// Build the manifest.
pub fn manifest(a: &EmitArgs) -> Result<ReferenceManifest> {
    if !a.install_dir.starts_with('/') {
        bail!(
            "--install-dir must be absolute (IMA records absolute paths), got {:?}",
            a.install_dir
        );
    }
    // The asset `nucleus setup` downloads, named by the one function that names
    // it there (ADR 0007 G-1).
    let tarball = Tier2Artifact::Node.asset_name(&a.version, a.arch.name());
    let mut found = Vec::new();
    find_named(&a.dist, &tarball, &mut found)?;
    let node_tgz = match found.as_slice() {
        [one] => one,
        [] => bail!("{} holds no {tarball}", a.dist.display()),
        many => bail!("{tarball} is ambiguous: {many:?}"),
    };

    let (v, arch) = (FIRECRACKER_VERSION, a.arch.name());
    let upstream = format!("release-v{v}-{arch}");
    let dir = a.install_dir.trim_end_matches('/');
    let at = |bin: &str| format!("{dir}/{bin}");
    let node = at("nucleus-node");

    let mut allowlist: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut allow = |path: String, digest: String| {
        allowlist.entry(path).or_default().insert(digest);
    };
    allow(node.clone(), member_digest(node_tgz, "nucleus-node")?);
    for bin in ["firecracker", "jailer"] {
        let member = format!("{upstream}/{bin}-v{v}-{arch}");
        allow(at(bin), member_digest(&a.firecracker_tgz, &member)?);
    }

    // The release vouches for its own binaries and nothing else the host's IMA
    // policy measures (a Secure Boot policy adds every kernel module loaded),
    // so its IMA reference governs the install directory only. Files measured
    // elsewhere are reported as not in scope, never as allowed or divergent.
    let ima = ImaReference {
        scope: ImaScope::PathPrefixes([dir.to_string()].into_iter().collect()),
        allowlist,
        required: [node].into_iter().collect(),
    };
    if let Some(why) = ima.incoherence() {
        bail!("--install-dir {:?}: {why}", a.install_dir);
    }

    let not_checked = || NO_HOST_IMAGE.to_string();
    Ok(ReferenceManifest {
        profile: REFERENCE_PROFILE.into(),
        tag_id: format!("nucleus-{}-{arch}", a.version),
        reference_values: ReferenceValues {
            pcrs: BTreeMap::new(),
            secure_boot: Expect::NotChecked(not_checked()),
            efi_applications: Expect::NotChecked(not_checked()),
            boot_files: Expect::NotChecked(not_checked()),
            kernel_cmdline: Expect::NotChecked(not_checked()),
            ima: Expect::Required(ima),
        },
    })
}

/// Run.
pub fn run(a: &Args) -> Result<()> {
    match a {
        Args::FetchConfig { arch, output, out } => {
            let config = format!(
                "url = \"{}\"\noutput = \"{}\"\n",
                firecracker_url(*arch),
                output.display()
            );
            std::fs::write(out, config).with_context(|| format!("writing {}", out.display()))
        }
        Args::Emit(e) => {
            let m = manifest(e)?;
            let json = serde_json::to_string_pretty(&m)? + "\n";
            std::fs::write(&e.out, json).with_context(|| format!("writing {}", e.out.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tgz(path: &Path, members: &[(&str, &[u8])]) {
        let gz = flate2::write::GzEncoder::new(
            std::fs::File::create(path).unwrap(),
            flate2::Compression::fast(),
        );
        let mut b = tar::Builder::new(gz);
        for (name, bytes) in members {
            let mut h = tar::Header::new_gnu();
            h.set_size(bytes.len() as u64);
            h.set_mode(0o755);
            h.set_cksum();
            b.append_data(&mut h, name, *bytes).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap();
    }

    fn sha(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    /// A dist tree as the release job downloads it, and an upstream archive.
    fn fixture(dir: &Path) -> EmitArgs {
        let artifact = dir.join("dist/nucleus-binaries-x86_64-unknown-linux-musl");
        std::fs::create_dir_all(&artifact).unwrap();
        tgz(
            &artifact.join("nucleus-node-9.9.9-x86_64-unknown-linux-musl.tar.gz"),
            &[("nucleus-node", b"node")],
        );
        // The same version's aarch64 tarball must not be picked up for x86_64.
        tgz(
            &artifact.join("nucleus-node-9.9.9-aarch64-unknown-linux-musl.tar.gz"),
            &[("nucleus-node", b"other arch")],
        );
        let v = FIRECRACKER_VERSION;
        let fc = dir.join("fc.tgz");
        tgz(
            &fc,
            &[
                (
                    &format!("release-v{v}-x86_64/firecracker-v{v}-x86_64"),
                    b"fc",
                ),
                (
                    &format!("release-v{v}-x86_64/jailer-v{v}-x86_64"),
                    b"jailer",
                ),
            ],
        );
        EmitArgs {
            dist: dir.join("dist"),
            version: "9.9.9".into(),
            arch: Arch::X86_64,
            firecracker_tgz: fc,
            install_dir: DEFAULT_INSTALL_DIR.into(),
            out: dir.join("out.json"),
        }
    }

    #[test]
    fn a_release_manifest_pins_the_shipped_bytes_and_names_what_it_cannot_check() {
        let dir = tempfile::tempdir().unwrap();
        let m = manifest(&fixture(dir.path())).unwrap();
        // It is the verifier's own type, so it round-trips through the
        // verifier's parser (one schema, ADR 0007 G-1).
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(serde_json::from_str::<ReferenceManifest>(&json).unwrap(), m);
        assert_eq!(m.tag_id, "nucleus-9.9.9-x86_64");
        let rv = m.reference_values;
        assert!(rv.pcrs.is_empty());
        for (what, unchecked) in [
            (
                "secure_boot",
                matches!(&rv.secure_boot, Expect::NotChecked(r) if r == NO_HOST_IMAGE),
            ),
            (
                "efi",
                matches!(&rv.efi_applications, Expect::NotChecked(r) if r == NO_HOST_IMAGE),
            ),
            (
                "boot",
                matches!(&rv.boot_files, Expect::NotChecked(r) if r == NO_HOST_IMAGE),
            ),
            (
                "cmdline",
                matches!(&rv.kernel_cmdline, Expect::NotChecked(r) if r == NO_HOST_IMAGE),
            ),
        ] {
            assert!(unchecked, "{what} must be not_checked with the reason");
        }
        let Expect::Required(ima) = rv.ima else {
            panic!("the release's own files are checked")
        };
        let one = |s: &str| [s.to_string()].into_iter().collect::<BTreeSet<_>>();
        assert_eq!(
            ima.allowlist,
            [
                (
                    "/usr/local/bin/nucleus-node".to_string(),
                    one(&sha(b"node"))
                ),
                ("/usr/local/bin/firecracker".to_string(), one(&sha(b"fc"))),
                ("/usr/local/bin/jailer".to_string(), one(&sha(b"jailer"))),
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(ima.required, one("/usr/local/bin/nucleus-node"));
        assert_eq!(
            ima.scope,
            ImaScope::PathPrefixes(one("/usr/local/bin")),
            "the release governs its install directory, not the host's modules"
        );
    }

    #[test]
    fn a_missing_binary_is_an_error_never_a_smaller_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = fixture(dir.path());
        // No jailer in the upstream archive.
        let v = FIRECRACKER_VERSION;
        tgz(
            &a.firecracker_tgz,
            &[(
                &format!("release-v{v}-x86_64/firecracker-v{v}-x86_64"),
                b"fc",
            )],
        );
        let err = manifest(&a).unwrap_err().to_string();
        assert!(err.contains("jailer"), "{err}");
        // No node tarball for this version.
        a.version = "0.0.1".into();
        let err = manifest(&a).unwrap_err().to_string();
        assert!(err.contains("holds no nucleus-node-0.0.1"), "{err}");
    }

    #[test]
    fn a_node_tarball_without_the_node_or_twice_published_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let a = fixture(dir.path());
        let name = "nucleus-node-9.9.9-x86_64-unknown-linux-musl.tar.gz";
        let second = a.dist.join("elsewhere");
        std::fs::create_dir_all(&second).unwrap();
        tgz(&second.join(name), &[("nucleus-node", b"node")]);
        assert!(manifest(&a).unwrap_err().to_string().contains("ambiguous"));
        std::fs::remove_dir_all(&second).unwrap();
        let tarball = a
            .dist
            .join("nucleus-binaries-x86_64-unknown-linux-musl")
            .join(name);
        tgz(&tarball, &[("README", b"no binary")]);
        assert!(
            manifest(&a)
                .unwrap_err()
                .to_string()
                .contains("has no nucleus-node")
        );
        tgz(&tarball, &[("nucleus-node", b"a"), ("nucleus-node", b"b")]);
        assert!(manifest(&a).unwrap_err().to_string().contains("twice"));
    }

    #[test]
    fn install_dir_moves_every_path_and_must_be_absolute() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = fixture(dir.path());
        a.install_dir = "/opt/nucleus/bin/".into();
        let Expect::Required(ima) = manifest(&a).unwrap().reference_values.ima else {
            panic!()
        };
        assert!(
            ima.allowlist
                .keys()
                .all(|p| p.starts_with("/opt/nucleus/bin/"))
        );
        assert!(ima.required.contains("/opt/nucleus/bin/nucleus-node"));
        assert_eq!(
            ima.scope,
            ImaScope::PathPrefixes(["/opt/nucleus/bin".to_string()].into_iter().collect())
        );
        a.install_dir = "bin".into();
        assert!(manifest(&a).is_err());
        // `/` would scope nothing out; `..` would name another directory.
        for bad in ["/", "/opt/../usr"] {
            a.install_dir = bad.into();
            assert!(manifest(&a).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_fetch_config_names_the_pinned_upstream_archive() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("fc.curl");
        run(&Args::FetchConfig {
            arch: Arch::Aarch64,
            output: PathBuf::from("fc.tgz"),
            out: out.clone(),
        })
        .unwrap();
        let v = FIRECRACKER_VERSION;
        assert_eq!(
            std::fs::read_to_string(out).unwrap(),
            format!(
                "url = \"https://github.com/firecracker-microvm/firecracker/releases/download/v{v}/firecracker-v{v}-aarch64.tgz\"\noutput = \"fc.tgz\"\n"
            )
        );
    }
}
