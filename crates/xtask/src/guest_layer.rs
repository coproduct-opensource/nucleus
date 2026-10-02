//! `cargo xtask guest-layer` — the nucleus guest as one deterministic tar.
//!
//! An imported OCI image supplies the workload; the guest layer supplies the
//! runtime that mediates it: `/init`, the `nucleus-*` binaries, and the CA
//! bundle the runtime's TLS stack reads. This command writes exactly that and
//! nothing else, as a tar whose bytes depend only on its inputs, and prints its
//! digest as `sha-256:<hex>` (the [`nucleus_spec::ArtifactDigest`] spelling).
//!
//! # What decides the contents
//!
//! - **Which binaries**: [`GuestBinary::ALL`], the table in
//!   `nucleus_spec::guest_layout` that also names every path the runtime
//!   trusts. Nothing here lists a binary (ADR 0007 G-1).
//! - **How each is built**: [`features`], an exhaustive match, checked against
//!   `release.yml` by [`release_coverage`] so the layer and the release build
//!   the same binary the same way.
//! - **The CA bundle**: the Mozilla roots in `webpki-root-certs`, pinned
//!   exactly in `Cargo.toml` (and so by its `Cargo.lock` checksum), rendered to
//!   PEM, and checked against [`CA_BUNDLE_SHA256`]. `build-rootfs.sh` copies
//!   the build host's store instead, which makes the image depend on which
//!   machine built it; a layer that is meant to have one digest cannot.
//! - **No `/etc/nucleus/pod.yaml`**, and no `/pod.yaml`: a baked spec outranks
//!   the one the node fetches, and an imported image must boot the node's.
//!
//! # Determinism
//!
//! The tar is written by `nucleus_oci_rootfs::AuthoredTree`, the same writer
//! that emits an imported image: sorted paths, mtime 0, owner `0:0`, explicit
//! modes, no user names, no pax records. The binaries themselves are as
//! reproducible as the toolchain makes them — the same checkout, toolchain and
//! target directory give the same bytes; a different checkout path can move
//! embedded source paths, which this command does not hide.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use nucleus_oci_rootfs::AuthoredTree;
use nucleus_spec::ArtifactDigest;
use nucleus_spec::guest_layout::{self, GuestBinary};
use sha2::{Digest, Sha256};

/// SHA-256 of the PEM bundle rendered from `webpki-root-certs` at the version
/// `crates/xtask/Cargo.toml` pins. Bumping that crate moves this; the build
/// refuses until it is updated, so a trust-store change is a reviewed diff.
pub const CA_BUNDLE_SHA256: &str =
    "5c4539be266bd5c71e427d385c3087f73000a7f00dfe434e953519f255a4341a";

/// A guest architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Arch {
    /// 64-bit Arm.
    Aarch64,
    /// 64-bit x86.
    #[value(name = "x86_64")]
    X86_64,
}

impl Arch {
    /// The musl target the guest binaries are built for: static, so they run
    /// on an image with no libc at all.
    pub fn triple(self) -> &'static str {
        match self {
            Self::Aarch64 => "aarch64-unknown-linux-musl",
            Self::X86_64 => "x86_64-unknown-linux-musl",
        }
    }

    /// ELF `e_machine` for this architecture.
    fn elf_machine(self) -> u16 {
        match self {
            Self::Aarch64 => 183,
            Self::X86_64 => 62,
        }
    }
}

/// How the musl binaries are cross-built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Builder {
    /// `cargo zigbuild` — needs no container runtime; what a Mac has.
    Zigbuild,
    /// `cross build` — what `release.yml` runs.
    Cross,
    /// Plain `cargo build` — a host whose linker already targets musl.
    Cargo,
}

impl Builder {
    fn command(self) -> Command {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        match self {
            Self::Zigbuild => {
                let mut c = Command::new(cargo);
                c.arg("zigbuild");
                c
            }
            Self::Cross => {
                let mut c = Command::new("cross");
                c.arg("build");
                c
            }
            Self::Cargo => {
                let mut c = Command::new(cargo);
                c.arg("build");
                c
            }
        }
    }
}

/// The cargo features a guest binary is built with. Exhaustive, so a new
/// binary is a compile error here until someone decides; checked against
/// `release.yml` by [`release_coverage`].
pub fn features(binary: GuestBinary) -> &'static [&'static str] {
    match binary {
        GuestBinary::ToolProxy => &["remote-audit"],
        GuestBinary::Init
        | GuestBinary::EgressProbe
        | GuestBinary::NetProbe
        | GuestBinary::WorkloadProbe
        | GuestBinary::PodlistProbe
        | GuestBinary::AdversaryProbe
        | GuestBinary::Mcp => &[],
    }
}

/// The CA bundle as PEM, rendered from the pinned root set.
pub fn render_ca_bundle() -> Vec<u8> {
    let mut pem = String::new();
    for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        let b64 = base64::engine::general_purpose::STANDARD.encode(cert.as_ref());
        pem.push_str("-----BEGIN CERTIFICATE-----\n");
        for line in b64.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(line));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
    }
    pem.into_bytes()
}

/// The CA bundle, refused unless it is the pinned one.
pub fn ca_bundle() -> Result<Vec<u8>> {
    let pem = render_ca_bundle();
    let got = hex::encode(Sha256::digest(&pem));
    ensure!(
        got == CA_BUNDLE_SHA256,
        "the CA bundle rendered from webpki-root-certs is sha256 {got}, pinned {CA_BUNDLE_SHA256}; \
         a root-store change must update CA_BUNDLE_SHA256 in crates/xtask/src/guest_layer.rs"
    );
    Ok(pem)
}

/// Every binary the layer carries, read and checked, in [`GuestBinary::ALL`] order.
pub struct GuestBinaries(Vec<(GuestBinary, Vec<u8>)>);

impl GuestBinaries {
    /// Read every [`GuestBinary`] from `dir` (a `target/<triple>/release`), each
    /// a static ELF for `arch`. A missing binary is an error naming it.
    pub fn read(dir: &Path, arch: Arch) -> Result<Self> {
        let mut out = Vec::new();
        for b in GuestBinary::ALL {
            let path = dir.join(b.package());
            let bytes = std::fs::read(&path)
                .with_context(|| format!("reading {} for {}", path.display(), b.path()))?;
            check_static_elf(&bytes, arch)
                .with_context(|| format!("{} ({})", path.display(), b.path()))?;
            out.push((b, bytes));
        }
        Ok(Self(out))
    }
}

/// `bytes` is a little-endian ELF64 for `arch` with no program interpreter —
/// a dynamically linked `/init` would not start on an image without its libc.
fn check_static_elf(bytes: &[u8], arch: Arch) -> Result<()> {
    let u16_at = |o: usize| -> Option<u16> {
        Some(u16::from_le_bytes(bytes.get(o..o + 2)?.try_into().ok()?))
    };
    let u32_at = |o: usize| -> Option<u32> {
        Some(u32::from_le_bytes(bytes.get(o..o + 4)?.try_into().ok()?))
    };
    let u64_at = |o: usize| -> Option<u64> {
        Some(u64::from_le_bytes(bytes.get(o..o + 8)?.try_into().ok()?))
    };
    ensure!(
        bytes.get(..6) == Some(b"\x7fELF\x02\x01".as_slice()),
        "not a little-endian ELF64"
    );
    let machine = u16_at(0x12).context("truncated ELF header")?;
    ensure!(
        machine == arch.elf_machine(),
        "ELF machine {machine}, expected {} for {arch:?}",
        arch.elf_machine()
    );
    let phoff = usize::try_from(u64_at(0x20).context("truncated ELF header")?)?;
    let phentsize = usize::from(u16_at(0x36).context("truncated ELF header")?);
    let phnum = usize::from(u16_at(0x38).context("truncated ELF header")?);
    const PT_INTERP: u32 = 3;
    for i in 0..phnum {
        let at = phoff + i * phentsize;
        let p_type = u32_at(at).context("truncated program header table")?;
        ensure!(
            p_type != PT_INTERP,
            "dynamically linked (has PT_INTERP); the guest binaries must be static"
        );
    }
    Ok(())
}

/// Every file the layer holds, as `(guest path, mode, content)`.
fn files(binaries: GuestBinaries, ca: Vec<u8>) -> Vec<(&'static str, u32, Vec<u8>)> {
    let mut files: Vec<_> = binaries
        .0
        .into_iter()
        .map(|(b, bytes)| (b.path(), 0o755, bytes))
        .collect();
    files.push((guest_layout::CA_BUNDLE, 0o644, ca));
    files
}

/// The layer as a tree: every file, and exactly the directories they need.
pub fn layer_tree(binaries: GuestBinaries, ca: Vec<u8>) -> Result<AuthoredTree> {
    let files = files(binaries, ca);
    let dirs: BTreeSet<&str> = files
        .iter()
        .flat_map(|(path, _, _)| Path::new(path).ancestors().skip(1))
        .filter_map(Path::to_str)
        .filter(|d| *d != "/")
        .collect();
    let mut tree = AuthoredTree::new();
    // BTreeSet order puts a parent before its children.
    for dir in dirs {
        tree.dir(dir, 0o755)?;
    }
    for (path, mode, content) in files {
        tree.file(path, mode, content)?;
    }
    Ok(tree)
}

/// Write the layer to `out`; return its digest.
pub fn write_layer(binaries: GuestBinaries, ca: Vec<u8>, out: &Path) -> Result<ArtifactDigest> {
    let tree = layer_tree(binaries, ca)?;
    let file = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let mut writer = std::io::BufWriter::new(file);
    let record = tree.emit(&mut writer)?;
    writer.flush()?;
    ArtifactDigest::parse(&format!("sha-256:{}", record.digest.hex())).map_err(anyhow::Error::msg)
}

/// Build every guest binary for `arch`, the way `release.yml` does: one
/// invocation per package, so features do not unify across them.
fn build(root: &Path, arch: Arch, builder: Builder) -> Result<()> {
    for b in GuestBinary::ALL {
        let mut cmd = builder.command();
        cmd.current_dir(root)
            .args(["-p", b.package(), "--release", "--target", arch.triple()]);
        let feats = features(b);
        if !feats.is_empty() {
            cmd.args(["--features", &feats.join(",")]);
        }
        eprintln!("guest-layer: building {} ({:?})", b.package(), builder);
        let status = cmd
            .status()
            .with_context(|| format!("running {builder:?} for {}", b.package()))?;
        ensure!(
            status.success(),
            "{builder:?} build of {} failed: {status}",
            b.package()
        );
    }
    Ok(())
}

/// `cargo xtask guest-layer`.
pub fn run(
    root: &Path,
    arch: Arch,
    out: &Path,
    builder: Builder,
    prebuilt: Option<PathBuf>,
) -> Result<()> {
    // A layer the release would not build the same way is a layer nobody can
    // reproduce from a release, so refuse it before spending the build.
    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).with_context(|| format!("reading {rel}"))
    };
    let findings = release_coverage(
        &GuestBinary::ALL,
        &read("scripts/firecracker/build-rootfs.sh")?,
        &read(".github/workflows/release.yml")?,
    );
    ensure!(
        findings.is_empty(),
        "the release does not build this guest layer:\n  {}",
        findings.join("\n  ")
    );
    let ca = ca_bundle()?;
    let dir = match prebuilt {
        Some(dir) => dir,
        None => {
            build(root, arch, builder)?;
            let target = std::env::var_os("CARGO_TARGET_DIR")
                .map_or_else(|| root.join("target"), PathBuf::from);
            target.join(arch.triple()).join("release")
        }
    };
    let binaries = GuestBinaries::read(&dir, arch)?;
    let digest = write_layer(binaries, ca, out)?;
    eprintln!("guest-layer: wrote {}", out.display());
    println!("{}", digest.as_str());
    Ok(())
}

/// Everything the release fails to build or upload of what the layer needs.
///
/// `ci/release-builds-rootfs-inputs.sh` asks the same questions of the list it
/// parses from `build-rootfs.sh`; the first finding here keeps that list equal
/// to [`GuestBinary::ALL`], so the shell gate and this check decide one set.
pub fn release_coverage(needed: &[GuestBinary], rootfs_sh: &str, release_yml: &str) -> Vec<String> {
    let mut findings = Vec::new();
    let ours: BTreeSet<&str> = needed.iter().map(|b| b.package()).collect();
    let theirs: BTreeSet<&str> = rootfs_sh
        .split("release/")
        .skip(1)
        .filter_map(|rest| {
            let end = rest
                .find(|c: char| !(c.is_ascii_lowercase() || c == '-'))
                .unwrap_or(rest.len());
            rest.get(..end).filter(|name| name.starts_with("nucleus-"))
        })
        .collect();
    if ours != theirs {
        findings.push(format!(
            "the guest layer ships {ours:?} but build-rootfs.sh builds {theirs:?}; \
             the two guests must carry the same binaries"
        ));
    }
    // Comments are not steps. release.yml has a comment quoting the error
    // `Missing target/<triple>/release/nucleus-workload-probe`, which a
    // line-end match would take for that binary's upload.
    let steps: Vec<&str> = release_yml
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect();
    for b in needed {
        let pkg = b.package();
        let build = format!("cross build -p {pkg} ");
        match steps.iter().find(|l| l.contains(&build)) {
            None => findings.push(format!("release.yml never BUILDS {pkg}")),
            Some(line) => {
                let declared: BTreeSet<&str> = line
                    .split_whitespace()
                    .skip_while(|w| *w != "--features")
                    .nth(1)
                    .map(|f| f.split(',').collect())
                    .unwrap_or_default();
                let want: BTreeSet<&str> = features(*b).iter().copied().collect();
                if declared != want {
                    findings.push(format!(
                        "release.yml builds {pkg} with features {declared:?}, the layer with {want:?}"
                    ));
                }
            }
        }
        let upload = format!("release/{pkg}");
        if !steps.iter().any(|l| l.trim_end().ends_with(&upload)) {
            findings.push(format!(
                "release.yml never UPLOADS {pkg}; the rootfs job runs on another runner"
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_file(rel: &str) -> String {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    /// A minimal static ELF64 header for `machine`, then `payload`.
    fn fake_elf(machine: u16, payload: &[u8]) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[..6].copy_from_slice(b"\x7fELF\x02\x01");
        h[0x12..0x14].copy_from_slice(&machine.to_le_bytes());
        h.extend_from_slice(payload);
        h
    }

    fn fake_bins(dir: &Path, arch: Arch, skip: Option<GuestBinary>) {
        for b in GuestBinary::ALL {
            if Some(b) != skip {
                let bytes = fake_elf(arch.elf_machine(), b.package().as_bytes());
                std::fs::write(dir.join(b.package()), bytes).unwrap();
            }
        }
    }

    fn build_in(tmp: &tempfile::TempDir) -> (ArtifactDigest, Vec<u8>) {
        let bin = tmp.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        fake_bins(&bin, Arch::Aarch64, None);
        let out = tmp.path().join("layer.tar");
        let bins = GuestBinaries::read(&bin, Arch::Aarch64).unwrap();
        let d = write_layer(bins, render_ca_bundle(), &out).unwrap();
        (d, std::fs::read(out).unwrap())
    }

    #[test]
    fn two_builds_in_different_directories_are_byte_identical() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        assert_ne!(a.path(), b.path());
        let (da, ta) = build_in(&a);
        let (db, tb) = build_in(&b);
        assert_eq!(da, db);
        assert_eq!(ta, tb);
        assert_eq!(
            da.hex(),
            hex::encode(Sha256::digest(&ta)),
            "printed digest is the file's"
        );
    }

    /// Exactly the guest: every [`GuestBinary`], the CA bundle, the directories
    /// they need — and no pod spec, which would outrank the node's.
    #[test]
    fn the_layer_holds_exactly_the_guest_and_no_pod_spec() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, tar_bytes) = build_in(&tmp);
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let mut files = BTreeSet::new();
        let mut dirs = BTreeSet::new();
        for e in archive.entries().unwrap() {
            let e = e.unwrap();
            let path = format!("/{}", String::from_utf8_lossy(&e.path_bytes()));
            let h = e.header();
            assert_eq!((h.uid().unwrap(), h.gid().unwrap()), (0, 0), "{path}");
            assert_eq!(h.mtime().unwrap(), 0, "{path}");
            if h.entry_type().is_dir() {
                dirs.insert(path.trim_end_matches('/').to_owned());
            } else {
                assert!(h.entry_type().is_file(), "{path}");
                // Every file is a path the runtime owns, so an image cannot
                // replace it — and nothing here is merely image furniture.
                assert!(guest_layout::reserved_by(&path).is_some(), "{path}");
                files.insert(path);
            }
        }
        let mut want: BTreeSet<String> = GuestBinary::ALL
            .iter()
            .map(|b| b.path().to_owned())
            .collect();
        want.insert(guest_layout::CA_BUNDLE.to_owned());
        assert_eq!(files, want);
        let want_dirs: BTreeSet<String> = [
            "/etc",
            "/etc/nucleus",
            "/usr",
            "/usr/local",
            "/usr/local/bin",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(dirs, want_dirs);
        for spec in [guest_layout::POD_SPEC_PATH, guest_layout::FALLBACK_POD_SPEC] {
            assert!(!files.contains(spec), "{spec} must not be baked");
        }
    }

    #[test]
    fn a_missing_binary_is_named() {
        let tmp = tempfile::tempdir().unwrap();
        fake_bins(tmp.path(), Arch::X86_64, Some(GuestBinary::EgressProbe));
        let err = GuestBinaries::read(tmp.path(), Arch::X86_64).err().unwrap();
        assert!(
            format!("{err:#}").contains("nucleus-egress-probe"),
            "{err:#}"
        );
    }

    #[test]
    fn a_wrong_arch_or_dynamic_binary_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        fake_bins(tmp.path(), Arch::X86_64, None);
        assert!(GuestBinaries::read(tmp.path(), Arch::Aarch64).is_err());

        // One PT_INTERP program header.
        let mut dynamic = fake_elf(62, &[]);
        dynamic[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        dynamic[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        dynamic[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
        let mut ph = vec![0u8; 56];
        ph[..4].copy_from_slice(&3u32.to_le_bytes());
        dynamic.extend_from_slice(&ph);
        assert!(check_static_elf(&dynamic, Arch::X86_64).is_err());
        assert!(check_static_elf(&fake_elf(62, &[]), Arch::X86_64).is_ok());
    }

    /// The trust store is pinned: a `webpki-root-certs` bump reds here, and
    /// the layer build refuses, until [`CA_BUNDLE_SHA256`] is updated.
    #[test]
    fn the_ca_bundle_is_the_pinned_one_and_is_pem() {
        let pem = ca_bundle().unwrap();
        let text = String::from_utf8(pem).unwrap();
        let n = text.matches("-----BEGIN CERTIFICATE-----").count();
        assert!(n > 100, "only {n} roots");
    }

    /// `ci/release-builds-rootfs-inputs.sh` proves the release builds and uploads
    /// what `build-rootfs.sh` needs. This covers the guest layer's manifest the
    /// same way, and ties that manifest to the shell gate's list.
    #[test]
    fn the_release_builds_every_binary_the_guest_layer_needs() {
        let findings = release_coverage(
            &GuestBinary::ALL,
            &repo_file("scripts/firecracker/build-rootfs.sh"),
            &repo_file(".github/workflows/release.yml"),
        );
        assert!(GuestBinary::ALL.len() >= 5, "vacuous manifest");
        assert!(findings.is_empty(), "{findings:#?}");
    }

    // A-19: each finding driven red on the real files.

    #[test]
    fn a_binary_dropped_from_the_layer_is_red() {
        let fewer: Vec<GuestBinary> = GuestBinary::ALL
            .into_iter()
            .filter(|b| *b != GuestBinary::AdversaryProbe)
            .collect();
        let findings = release_coverage(
            &fewer,
            &repo_file("scripts/firecracker/build-rootfs.sh"),
            &repo_file(".github/workflows/release.yml"),
        );
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert!(findings[0].contains("build-rootfs.sh"), "{findings:#?}");
    }

    #[test]
    fn a_release_that_stops_building_or_uploading_is_red() {
        let rootfs = repo_file("scripts/firecracker/build-rootfs.sh");
        let release = repo_file(".github/workflows/release.yml");
        let unbuilt: String = release
            .lines()
            .filter(|l| !l.contains("cross build -p nucleus-egress-probe "))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_ne!(unbuilt, release, "perturbation matched nothing");
        let f = release_coverage(&GuestBinary::ALL, &rootfs, &unbuilt);
        assert_eq!(f, vec!["release.yml never BUILDS nucleus-egress-probe"]);

        let unuploaded: String = release
            .lines()
            .filter(|l| !l.trim_end().ends_with("release/nucleus-podlist-probe"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_ne!(unuploaded, release, "perturbation matched nothing");
        let f = release_coverage(&GuestBinary::ALL, &rootfs, &unuploaded);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(f[0].contains("UPLOADS nucleus-podlist-probe"), "{f:#?}");
    }

    /// release.yml quotes `Missing target/<triple>/release/nucleus-workload-probe`
    /// in a comment. A comment is not an upload.
    #[test]
    fn a_comment_does_not_count_as_an_upload() {
        let rootfs = repo_file("scripts/firecracker/build-rootfs.sh");
        let release = repo_file(".github/workflows/release.yml");
        let commented = release
            .lines()
            .filter(|l| l.trim_start().starts_with('#'))
            .any(|l| l.trim_end().ends_with("release/nucleus-workload-probe"));
        assert!(commented, "the comment this test is about is gone");
        let unuploaded: String = release
            .lines()
            .filter(|l| {
                l.trim_start().starts_with('#')
                    || !l.trim_end().ends_with("release/nucleus-workload-probe")
            })
            .map(|l| format!("{l}\n"))
            .collect();
        assert_ne!(unuploaded, release, "perturbation matched nothing");
        let f = release_coverage(&GuestBinary::ALL, &rootfs, &unuploaded);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(f[0].contains("UPLOADS nucleus-workload-probe"), "{f:#?}");
    }

    /// The MCP bridge is a guest binary like the probes: a release that builds
    /// it for the CLI tarball but never hands it to the rootfs job is red.
    #[test]
    fn a_release_that_does_not_upload_the_mcp_bridge_is_red() {
        assert!(GuestBinary::ALL.contains(&GuestBinary::Mcp));
        let rootfs = repo_file("scripts/firecracker/build-rootfs.sh");
        let release = repo_file(".github/workflows/release.yml");
        let unuploaded: String = release
            .lines()
            .filter(|l| !l.trim_end().ends_with("release/nucleus-mcp"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_ne!(unuploaded, release, "perturbation matched nothing");
        let f = release_coverage(&GuestBinary::ALL, &rootfs, &unuploaded);
        assert_eq!(
            f,
            vec!["release.yml never UPLOADS nucleus-mcp; the rootfs job runs on another runner"]
        );

        let unbuilt: String = release
            .lines()
            .filter(|l| !l.contains("cross build -p nucleus-mcp "))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_ne!(unbuilt, release, "perturbation matched nothing");
        let f = release_coverage(&GuestBinary::ALL, &rootfs, &unbuilt);
        assert_eq!(f, vec!["release.yml never BUILDS nucleus-mcp"]);
    }

    #[test]
    fn a_release_built_with_other_features_is_red() {
        let rootfs = repo_file("scripts/firecracker/build-rootfs.sh");
        let release = repo_file(".github/workflows/release.yml");
        let changed = release.replace("--features remote-audit ", "");
        assert_ne!(changed, release, "perturbation matched nothing");
        let f = release_coverage(&GuestBinary::ALL, &rootfs, &changed);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(f[0].contains("nucleus-tool-proxy with features"), "{f:#?}");
    }
}
