//! Which guest artifacts a Tier 2 host installs, and where they come from.
//!
//! # Why this exists
//!
//! Three separate places used to answer "which kernel, which Firecracker, which
//! rootfs": the published Lima templates (`scripts/lima/nucleus-<arch>.yaml`),
//! `scripts/install.sh`, and the config `nucleus-cli::setup` generated inline.
//! They disagreed. Measured on 2026-07-29: the published aarch64 template pinned
//! Firecracker **1.14.0** and a kernel URL that returns **HTTP 404**, while
//! [`vmm_version::PINNED`](crate::vmm_version::PINNED) was 1.16.1 and `setup`
//! used a third URL again. Nothing noticed, because nothing in CI boots a
//! microVM.
//!
//! Keeping three copies in sync is the problem, not the fix. So the templates no
//! longer name any artifact at all — they describe the *shape* of the VM and
//! nothing else — and every URL, version and digest lives here, in one module
//! that `setup`, `doctor` and CI all read. A divergence is now a compile error
//! rather than a 404 discovered by a user.
//!
//! # What the digests do and do not buy
//!
//! The kernels are immutable objects in the Firecracker CI bucket, so
//! [`Kernel::sha256`] is a genuine pin: a substituted kernel fails the check
//! offline, against a constant compiled into the binary.
//!
//! The guest artifacts are GitHub release assets, and their digests cannot be
//! baked in here — the constant would have to be written before the release it
//! describes exists. They are instead checked against the digest the release API
//! reports for that asset, which detects truncation and corruption and **does
//! not** detect a compromised release: the digest and the bytes come from the
//! same trust root. The check that does bind them is Sigstore build provenance
//! (`actions/attest-build-provenance` in `release.yml`), verified with
//! `gh attestation verify` when `gh` is on PATH. Stated rather than implied,
//! because "sha256 verified" reads like a supply-chain guarantee and this half
//! of it is not one.

/// A kernel image pinned by URL and content digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kernel {
    /// Where to fetch it.
    pub url: &'static str,
    /// Lowercase hex SHA-256 of the fetched bytes.
    pub sha256: &'static str,
}

/// The guest kernel for aarch64 hosts.
///
/// The `firecracker-ci/v1.13` prefix, not a later one: `v1.14` has no aarch64
/// `vmlinux-6.1` object (probed — 404), which is exactly the pin the published
/// Lima template carried. Bucket layout is not a version ladder, so "use the
/// newest path" is not a rule that holds here; list it with
/// `?list-type=2&prefix=firecracker-ci/` before changing this.
pub const KERNEL_AARCH64: Kernel = Kernel {
    url: "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/aarch64/vmlinux-6.1.141",
    sha256: "69aa3308219ec1a070bc9a8e7f80c3b34056fed8ae05efb44e55f73b31adde44",
};

/// The guest kernel for x86_64 hosts. Same bucket prefix as [`KERNEL_AARCH64`].
pub const KERNEL_X86_64: Kernel = Kernel {
    url: "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/x86_64/vmlinux-6.1.141",
    sha256: "b36a4a1b10f33b9cfdcde3d1a787d9c090556a3edb211cd06d1f3f9a6c7e8724",
};

/// The kernel for a Linux architecture name as `uname -m` reports it.
pub fn kernel_for(arch: &str) -> Option<Kernel> {
    match arch {
        "aarch64" | "arm64" => Some(KERNEL_AARCH64),
        "x86_64" | "amd64" => Some(KERNEL_X86_64),
        _ => None,
    }
}

/// The repository guest artifacts are published from.
pub const RELEASE_REPO: &str = "coproduct-opensource/nucleus";

/// The oldest release whose rootfs can actually boot a nucleus pod.
///
/// This is a **floor on the artifact, not a preference**. Every published
/// release up to and including 2.0.2 ships a rootfs with no CA bundle anywhere
/// in it — verified by mounting `nucleus-rootfs-2.0.2-aarch64.ext4`, and by
/// `git show v2.0.2:scripts/firecracker/build-rootfs.sh | grep -c ca-cert` → 0.
/// On such a rootfs `DrandClient::new` used to `.expect()` on the missing store
/// and the tool-proxy panicked **as PID 1**, taking the guest kernel with it:
/// "the tool-proxy panicked as PID 1 on every pod this repo can build" (#2110).
/// Both halves of that fix — the fallible constructor and `build-rootfs.sh`
/// installing a bundle — landed after 2.0.2.
///
/// So a quickstart pinned below this floor would hand a new user a pod that
/// cannot boot. `setup` refuses rather than installing one, and says why.
pub const GUEST_RELEASE_FLOOR: &str = "2.1.0";

/// The release `setup` installs guest artifacts from.
///
/// `2.1.0` is the first release containing everything a pod needs to boot: the CA
/// bundle in the rootfs (#2110), the `ip netns exec` separator fix without which
/// no pod launches on a default install, and the workload-API socket chown
/// without which the guest cannot fetch its SVID.
///
/// Bumped from `2.1.0-rc.1` in the same change that is released as `2.1.0`, and
/// deliberately BEFORE the tag is cut: a stable CLI must not pin prerelease guest
/// images, which is what shipping 2.1.0 with the RC still pinned would do.
///
/// `pinned_release_is_at_or_above_the_floor` fails if this ever drops below the
/// floor; `parse_release` explains why an RC compares equal to its own version.
pub const GUEST_RELEASE: &str = "2.1.0";

/// Something a Tier 2 host needs, published as a release asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier2Artifact {
    /// The bootable root filesystem for the microVM guest, gzipped.
    Rootfs,
    /// The `nucleus-node` binary that launches microVMs, statically linked.
    Node,
    /// The `nucleus` CLI, statically linked for Linux.
    ///
    /// Needed **on the Tier 2 host**, not just on the workstation, because the
    /// per-pod tool-proxy binds `127.0.0.1:0` inside that host. From macOS there
    /// is no route to an ephemeral loopback port inside a Lima VM, so the
    /// verification that drives the proxy has to run where the proxy is. Same
    /// binary, same code path a Linux user runs directly.
    Cli,
}

impl Tier2Artifact {
    /// The release asset filename for this artifact at `version`.
    ///
    /// `arch` is a Linux architecture name (`aarch64`, `x86_64`).
    pub fn asset_name(&self, version: &str, arch: &str) -> String {
        match self {
            Self::Rootfs => format!("nucleus-rootfs-{version}-{arch}.ext4.gz"),
            Self::Node => format!("nucleus-node-{version}-{arch}-unknown-linux-musl.tar.gz"),
            Self::Cli => format!("nucleus-cli-{version}-{arch}-unknown-linux-musl.tar.gz"),
        }
    }

    /// The download URL for this artifact at `version`.
    pub fn asset_url(&self, version: &str, arch: &str) -> String {
        format!(
            "https://github.com/{RELEASE_REPO}/releases/download/v{version}/{}",
            self.asset_name(version, arch)
        )
    }

    /// Every artifact, so a caller cannot install a partial set by forgetting one.
    pub fn all() -> &'static [Tier2Artifact] {
        &[
            Tier2Artifact::Rootfs,
            Tier2Artifact::Node,
            Tier2Artifact::Cli,
        ]
    }
}

/// Parse a release string into its comparable numeric core.
///
/// Accepts a `v` prefix and a prerelease or build suffix, so `v2.1.0-rc.1` and
/// `2.1.0` both yield `(2, 1, 0)`. Returns `None` for anything whose core is not
/// three numeric components, so a malformed pin fails the comparison rather than
/// silently ordering as zero.
///
/// # Why the suffix is dropped rather than ordered
///
/// Semver sorts `2.1.0-rc.1` **before** `2.1.0`, so a strict semver comparison
/// would reject an RC against a floor of `2.1.0`. That is the wrong answer for
/// what this floor is *for*: it exists to exclude releases whose rootfs has no CA
/// bundle and therefore panics as PID 1, and a release candidate **of** an
/// acceptable version contains those fixes. Comparing the numeric core is the
/// deliberate choice, not an oversight.
///
/// It is still a floor: `2.0.2-rc.1` has core `(2, 0, 2)` and is refused, because
/// a prerelease of a broken version is still broken.
pub fn parse_release(raw: &str) -> Option<(u32, u32, u32)> {
    let core = raw.trim_start_matches('v');
    // `-` starts a prerelease, `+` starts build metadata; either ends the core.
    let core = core.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Whether `version` is new enough to contain a bootable rootfs.
///
/// An unparseable version is **not** acceptable: a pin nobody can order is a pin
/// nobody is checking.
pub fn release_is_acceptable(version: &str) -> bool {
    match (parse_release(version), parse_release(GUEST_RELEASE_FLOOR)) {
        (Some(found), Some(floor)) => found >= floor,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_lookup_covers_both_uname_spellings() {
        assert_eq!(kernel_for("aarch64"), Some(KERNEL_AARCH64));
        assert_eq!(kernel_for("arm64"), Some(KERNEL_AARCH64));
        assert_eq!(kernel_for("x86_64"), Some(KERNEL_X86_64));
        assert_eq!(kernel_for("amd64"), Some(KERNEL_X86_64));
        assert_eq!(kernel_for("riscv64"), None);
    }

    #[test]
    fn kernel_digests_are_lowercase_hex_sha256() {
        for k in [KERNEL_AARCH64, KERNEL_X86_64] {
            assert_eq!(k.sha256.len(), 64, "not a sha256: {}", k.sha256);
            assert!(
                k.sha256
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "not lowercase hex: {}",
                k.sha256
            );
        }
    }

    /// The two kernels must not share a digest — a copy-paste of one constant
    /// over the other would otherwise install the wrong-architecture kernel and
    /// pass its own integrity check.
    #[test]
    fn the_two_kernels_are_different_objects() {
        assert_ne!(KERNEL_AARCH64.url, KERNEL_X86_64.url);
        assert_ne!(KERNEL_AARCH64.sha256, KERNEL_X86_64.sha256);
    }

    #[test]
    fn pinned_release_is_at_or_above_the_floor() {
        assert!(
            release_is_acceptable(GUEST_RELEASE),
            "GUEST_RELEASE {GUEST_RELEASE} is below the floor {GUEST_RELEASE_FLOOR}"
        );
    }

    /// The floor exists because 2.0.2 and everything before it ships a rootfs
    /// with no CA store, on which the tool-proxy panics as PID 1. If this ever
    /// starts passing, the floor has been lowered past the fix.
    #[test]
    fn the_known_broken_releases_are_refused() {
        for broken in ["2.0.2", "2.0.0", "1.1.0", "1.0.9"] {
            assert!(
                !release_is_acceptable(broken),
                "{broken} predates the PID-1 CA-store fix and must be refused"
            );
        }
    }

    /// A release CANDIDATE of an acceptable version must be acceptable: it
    /// contains the fixes the floor exists to require. Strict semver would sort
    /// it below `2.1.0` and refuse it — which is why the parser compares the
    /// numeric core.
    #[test]
    fn a_prerelease_of_an_acceptable_version_is_accepted() {
        for rc in ["2.1.0-rc.1", "v2.1.0-rc.1", "2.1.0-rc1", "2.1.0+build.7"] {
            assert_eq!(parse_release(rc), Some((2, 1, 0)), "{rc} core");
            assert!(release_is_acceptable(rc), "{rc} should be accepted");
        }
    }

    /// The other half, and the one that keeps the above from being a hole: a
    /// prerelease of a BROKEN version is still broken. Without this the suffix
    /// handling would be a way to smuggle a pre-CA-bundle rootfs past the floor.
    #[test]
    fn a_prerelease_of_a_refused_version_is_still_refused() {
        for rc in ["2.0.2-rc.1", "1.1.0-rc.1", "v2.0.0-beta"] {
            assert!(
                !release_is_acceptable(rc),
                "{rc} predates the PID-1 CA-store fix and must stay refused"
            );
        }
    }

    #[test]
    fn an_unparseable_release_is_refused_rather_than_ordered_as_zero() {
        for bad in ["", "2.1", "2.1.0.1", "latest", "v2.x.0"] {
            assert!(!release_is_acceptable(bad), "{bad:?} should be refused");
        }
    }

    /// A `v` prefix is what a git tag looks like, and it must order the same as
    /// the bare version rather than failing to parse.
    #[test]
    fn a_tag_style_version_parses() {
        assert_eq!(parse_release("v2.1.0"), parse_release("2.1.0"));
        assert!(release_is_acceptable("v2.1.0"));
    }

    #[test]
    fn asset_names_match_what_release_yml_publishes() {
        // Verified against the real asset list of v2.0.2.
        assert_eq!(
            Tier2Artifact::Rootfs.asset_name("2.0.2", "aarch64"),
            "nucleus-rootfs-2.0.2-aarch64.ext4.gz"
        );
        assert_eq!(
            Tier2Artifact::Node.asset_name("2.0.2", "aarch64"),
            "nucleus-node-2.0.2-aarch64-unknown-linux-musl.tar.gz"
        );
        assert_eq!(
            Tier2Artifact::Node.asset_name("2.0.2", "x86_64"),
            "nucleus-node-2.0.2-x86_64-unknown-linux-musl.tar.gz"
        );
    }

    #[test]
    fn asset_urls_point_at_the_tagged_release() {
        assert_eq!(
            Tier2Artifact::Rootfs.asset_url("2.1.0", "aarch64"),
            "https://github.com/coproduct-opensource/nucleus/releases/download/v2.1.0/nucleus-rootfs-2.1.0-aarch64.ext4.gz"
        );
    }

    /// `all()` is what callers iterate to install a complete set; a new variant
    /// that is not listed there would be silently never installed.
    #[test]
    fn every_artifact_variant_is_in_all() {
        let all = Tier2Artifact::all();
        for v in [
            Tier2Artifact::Rootfs,
            Tier2Artifact::Node,
            Tier2Artifact::Cli,
        ] {
            assert!(all.contains(&v), "{v:?} missing from all()");
        }
        assert_eq!(all.len(), 3, "a new variant needs adding to all()");
    }

    /// Two artifacts must never resolve to the same asset, or installing one
    /// would silently overwrite the other.
    #[test]
    fn artifact_asset_names_are_distinct() {
        let names: Vec<String> = Tier2Artifact::all()
            .iter()
            .map(|a| a.asset_name("2.1.0", "aarch64"))
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            names.len(),
            "duplicate asset names: {names:?}"
        );
    }
}
