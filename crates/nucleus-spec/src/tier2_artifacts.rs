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

/// Where nucleus's artifacts live inside a Tier 2 host.
///
/// This is *guest-VM* path space on macOS, which is the distinction the config
/// previously lost: `Config::artifacts_dir()` resolves under the host's
/// `~/Library/Application Support`, and a PodSpec built from it named paths the
/// node — running inside the Lima VM — cannot see.
///
/// Lives here rather than in `nucleus-cli::provision` because two hosts now
/// install into it: the Lima VM `provision` builds, and the Apple `container`
/// image described by [`crate::microvm_host`]. One constant for both, so a
/// PodSpec written for one names paths the other has (ADR 0007 G-1).
///
/// The node reads it too: it is the default of `nucleus-node --artifacts-root`,
/// the only directory a pod's `kernel_path` and `rootfs_path` may name
/// (2026-09-29). One constant, so the directory `setup` installs into and the one
/// the node admits from cannot drift apart.
pub const HOST_ARTIFACTS_DIR: &str = "/var/lib/nucleus/artifacts";

/// The guest kernel's file name under [`HOST_ARTIFACTS_DIR`].
pub const GUEST_KERNEL_FILE: &str = "vmlinux";

/// The guest root filesystem's file name under [`HOST_ARTIFACTS_DIR`].
pub const GUEST_ROOTFS_FILE: &str = "rootfs.ext4";

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

/// Where a host gets the guest layer an imported image is booted with: the tar
/// `cargo xtask guest-layer` writes (`/init`, the `nucleus-*` binaries, the CA
/// bundle — see [`crate::guest_layout`]).
///
/// Two cases, not an `Option`: "no pin" is a decision (build it here), and it
/// is spelled as one rather than as the absence of a digest (ADR 0007 B-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestLayerSource {
    /// No published layer: the host builds one from this checkout. Its digest
    /// is whatever that build prints, and nothing here vouches for it.
    LocalBuild,
    /// A published layer, checked against this digest (`sha-256:<hex>`, the
    /// [`ArtifactDigest`](crate::ArtifactDigest) spelling) before it is used.
    Pinned {
        /// The layer tar's digest.
        digest: &'static str,
    },
}

/// The guest layer for aarch64 hosts. `LocalBuild` until a release publishes one.
pub const GUEST_LAYER_AARCH64: GuestLayerSource = GuestLayerSource::LocalBuild;

/// The guest layer for x86_64 hosts. `LocalBuild` until a release publishes one.
pub const GUEST_LAYER_X86_64: GuestLayerSource = GuestLayerSource::LocalBuild;

/// The guest layer for a Linux architecture name as `uname -m` reports it.
pub fn guest_layer_for(arch: &str) -> Option<GuestLayerSource> {
    match arch {
        "aarch64" | "arm64" => Some(GUEST_LAYER_AARCH64),
        "x86_64" | "amd64" => Some(GUEST_LAYER_X86_64),
        _ => None,
    }
}

/// The repository guest artifacts are published from.
pub const RELEASE_REPO: &str = "coproduct-opensource/nucleus";

/// Something this tree's node or CLI requires the guest rootfs to do.
///
/// # Why a table and not a floor
///
/// This used to be one constant, `GUEST_RELEASE_FLOOR`, a version with the
/// reasons for it in a comment. It was right twice and then wrong for four
/// weeks. #2110 (the CA bundle) and #2214 (approval by public key) each raised
/// it. Then #2365 made the node require the guest's egress attestation and
/// #2379 moved the SVID to tmpfs, the day after 2.2.0 was tagged, and the floor
/// stayed at 2.2.0 because nothing forced anyone to ask whether it still held.
/// It did not: a node built from `main` refuses every confined pod on the 2.2.0
/// rootfs (no `NUCLEUS_EGRESS_PROBE:` line), and a read-only 2.2.0 rootfs dies
/// creating `/etc/nucleus/identity`. `verify --tier2` has asked for a read-only
/// rootfs since #2786, so on the pinned release it cannot pass either.
///
/// A requirement is now a variant, and whether a release meets it is derived
/// from when each one first shipped ([`GuestCapability::first_shipped`]). The
/// floor is no longer something to keep up to date; it is what the table says.
/// Adding a guest-side requirement means adding a variant, and the match in
/// `first_shipped` will not compile until someone states which release has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GuestCapability {
    /// The rootfs carries a CA bundle (#2110). Without it the tool-proxy's
    /// drand client failed and, as PID 1, took the guest kernel with it. Every
    /// release through 2.0.2 lacks it — verified by mounting
    /// `nucleus-rootfs-2.0.2-aarch64.ext4`.
    CaBundle,
    /// guest-init verifies approvals against the node's Ed25519 public key
    /// (#2214). The node sends `nucleus.approval_pubkeys` and no longer sends
    /// `nucleus.approval_secret`, which the 2.1.0 guest-init requires, so it
    /// exits as PID 1.
    ApprovalByPublicKey,
    /// guest-init runs `nucleus-egress-probe` and prints its
    /// `NUCLEUS_EGRESS_PROBE:` verdict (#2365). The node refuses a confined pod
    /// whose console has no verdict, and it must: the probe is the only evidence
    /// that the netns/iptables fence drops traffic rather than just applied
    /// cleanly. A guest that predates it is refused, never waved through.
    EgressAttestation,
    /// The SVID is written to `/run/nucleus/identity` on tmpfs (#2379). Before
    /// that it went to `/etc/nucleus/identity` on the rootfs, so a pod with
    /// `image.read_only: true` — the configured default, and what
    /// `verify --tier2` sends — dies creating the directory.
    SvidOnTmpfs,
    /// The tool-proxy serves the workload on its own Unix socket, the workload
    /// door at `guest_layout::WORKLOAD_DOOR`, and the workload's environment
    /// carries no proxy credential (#3031 option B, #2696 P1). An older guest
    /// points the workload at the proxy's vsock listener, which a process inside
    /// the guest cannot connect to, so an agent run in the pod (P5) reaches no
    /// tool and no egress at all.
    WorkloadDoor,
    /// The guest carries the MCP bridge at `guest_layout::MCP_BIN`, which an
    /// agent run in the pod speaks MCP to and which reaches the tool-proxy
    /// through the workload door with no secret (#2696 P2). An older guest has
    /// no bridge, so an agent started in the pod (P5) has no tools at all.
    McpBridge,
}

/// Which published release first carried a [`GuestCapability`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstShipped {
    /// This release and every later one carry it.
    Release(&'static str),
    /// It is in this tree and in no published release. No pin can satisfy it
    /// until one is cut, and the change that bumps [`GUEST_RELEASE`] to that
    /// release is the one that turns this into [`FirstShipped::Release`].
    NotYet,
}

impl GuestCapability {
    /// Every capability, for the callers that check all of them.
    pub const ALL: [GuestCapability; 6] = [
        GuestCapability::CaBundle,
        GuestCapability::ApprovalByPublicKey,
        GuestCapability::EgressAttestation,
        GuestCapability::SvidOnTmpfs,
        GuestCapability::WorkloadDoor,
        GuestCapability::McpBridge,
    ];

    /// The first release whose rootfs has this.
    pub const fn first_shipped(self) -> FirstShipped {
        match self {
            GuestCapability::CaBundle => FirstShipped::Release("2.1.0"),
            GuestCapability::ApprovalByPublicKey => FirstShipped::Release("2.2.0"),
            // Both merged on 2026-09-02, after `v2.2.0` (8a452030b) was tagged.
            GuestCapability::EgressAttestation => FirstShipped::NotYet,
            GuestCapability::SvidOnTmpfs => FirstShipped::NotYet,
            GuestCapability::WorkloadDoor => FirstShipped::NotYet,
            GuestCapability::McpBridge => FirstShipped::NotYet,
        }
    }

    /// The change that introduced it and what a guest without it does, in one
    /// sentence an operator can look up.
    pub const fn change(self) -> &'static str {
        match self {
            GuestCapability::CaBundle => {
                "#2110 put a CA bundle in the rootfs; without one the tool-proxy panics as PID 1"
            }
            GuestCapability::ApprovalByPublicKey => {
                "#2214 (2026-08-08) replaced the guest's shared approval secret with Ed25519 \
                 verification against the node's public key, so this node sends \
                 `nucleus.approval_pubkeys` and no longer sends `nucleus.approval_secret`, \
                 which an older guest-init still requires"
            }
            GuestCapability::EgressAttestation => {
                "#2365 made the node require the guest's `NUCLEUS_EGRESS_PROBE:` verdict \
                 before it calls a confined pod up; an older guest-init never runs the probe, \
                 so every confined pod is refused"
            }
            GuestCapability::SvidOnTmpfs => {
                "#2379 moved the guest's SVID to tmpfs; an older guest-init writes it to \
                 /etc/nucleus/identity, which a read-only rootfs cannot create"
            }
            GuestCapability::WorkloadDoor => {
                "#3031 gave the workload its own door, a Unix socket the tool-proxy \
                 serves to the workload's uid alone; an older guest points the workload at \
                 the proxy's vsock listener, which nothing inside the guest can connect to"
            }
            GuestCapability::McpBridge => {
                "#2696 (P2) put the MCP bridge in the guest at /usr/local/bin/nucleus-mcp; \
                 an older guest has none, so an agent run in the pod has no way to call its tools"
            }
        }
    }
}

/// What to do about a guest that lacks a capability. The same for every one of
/// them, which is why it is not per-variant.
pub const REBUILD_THE_GUEST: &str = "Build the guest from this checkout: \
     `bash scripts/firecracker/build-rootfs.sh` (or `just guest-rootfs`), which \
     preflights its tooling and, on macOS, prints how to run it in the Linux VM; \
     then install it with `nucleus setup --artifacts local`";

/// Why a guest release cannot serve this tree's node and CLI.
///
/// Two cases, not one: "we could not order the version" is not "we ordered it
/// and it was too old" (ADR 0007 A-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestSkew {
    /// The version string has no three-part numeric core. A pin nobody can
    /// order is a pin nobody is checking, so it is refused.
    Unorderable {
        /// The string as given.
        release: String,
    },
    /// The release predates at least one capability. Never empty: it is only
    /// built by [`guest_skew`] after finding one.
    Lacks {
        /// The release as given.
        release: String,
        /// What it lacks, in declaration order.
        missing: Vec<GuestCapability>,
    },
}

impl std::fmt::Display for GuestSkew {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuestSkew::Unorderable { release } => write!(
                f,
                "guest release {release:?} is not a version this build can order, so it \
                 cannot tell what the guest supports"
            ),
            GuestSkew::Lacks { release, missing } => {
                writeln!(
                    f,
                    "guest release v{} cannot serve this build of nucleus. It predates:",
                    release.trim_start_matches('v')
                )?;
                for cap in missing {
                    let when = match cap.first_shipped() {
                        FirstShipped::Release(v) => format!("first released in v{v}"),
                        FirstShipped::NotYet => "in no published release yet".to_string(),
                    };
                    writeln!(f, "  - {} ({when})", cap.change())?;
                }
                write!(f, "{REBUILD_THE_GUEST}.")
            }
        }
    }
}

/// Whether the guest artifacts of `version` meet every [`GuestCapability`].
pub fn guest_skew(version: &str) -> Result<(), GuestSkew> {
    skew_against(version, GuestCapability::first_shipped)
}

/// [`guest_skew`] with the table as a parameter, so the ordering rules can be
/// tested on releases the real table does not (yet) contain.
fn skew_against(
    version: &str,
    first_shipped: impl Fn(GuestCapability) -> FirstShipped,
) -> Result<(), GuestSkew> {
    let Some(found) = parse_release(version) else {
        return Err(GuestSkew::Unorderable {
            release: version.to_string(),
        });
    };
    let mut missing = Vec::new();
    for cap in GuestCapability::ALL {
        let has = match first_shipped(cap) {
            // An unparseable table entry is a table nobody can check against:
            // it counts as missing, never as present.
            FirstShipped::Release(v) => parse_release(v).is_some_and(|since| found >= since),
            FirstShipped::NotYet => false,
        };
        if !has {
            missing.push(cap);
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(GuestSkew::Lacks {
            release: version.to_string(),
            missing,
        })
    }
}

/// The release `setup` installs guest artifacts from.
///
/// `2.2.0` is the first release whose rootfs matches a post-#2214 node. 2.1.0
/// was the first release containing everything a pod needed to boot at the time
/// — the CA bundle in the rootfs (#2110), the `ip netns exec` separator fix
/// without which no pod launches on a default install, and the workload-API
/// socket chown without which the guest cannot fetch its SVID — and it stayed
/// pinned for five weeks after the node moved past it.
///
/// Bumped BEFORE the tag is cut, matching how `2.1.0` was bumped from its RC in
/// the change that was released as `2.1.0`. The ordering is deliberate and it
/// has a cost worth naming: between this landing and the `v2.2.0` assets being
/// built, `setup` points at a release that does not exist yet. That window is
/// inherent to pinning your own next version, and the alternative — tag first,
/// bump after — ships a release whose CLI pins the *previous* release's guest,
/// which is precisely the skew being closed.
///
/// **2.2.0 does not serve this tree.** It predates
/// [`GuestCapability::EgressAttestation`], [`GuestCapability::SvidOnTmpfs`],
/// [`GuestCapability::WorkloadDoor`] and [`GuestCapability::McpBridge`], so
/// `setup` refuses to install it (see
/// [`guest_skew`]) and says to build the guest locally instead. The change that
/// bumps this constant to the next release must also turn those entries into
/// [`FirstShipped::Release`];
/// `no_capability_claims_a_release_after_the_pin` stops it naming a release
/// the pin has not reached.
///
/// `parse_release` explains why an RC compares equal to its own version.
pub const GUEST_RELEASE: &str = "2.2.0";

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
/// would reject an RC of the very release a [`GuestCapability`] first shipped
/// in. That is the wrong answer for what the comparison is *for*: a release
/// candidate **of** an acceptable version contains the fixes. Comparing the
/// numeric core is the deliberate choice, not an oversight.
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

    /// A pinned guest layer must be a digest the spec parser accepts, or the
    /// check against it could never pass (or, worse, compare against garbage).
    #[test]
    fn guest_layer_pins_are_artifact_digests() {
        for arch in ["aarch64", "x86_64"] {
            match guest_layer_for(arch) {
                Some(GuestLayerSource::LocalBuild) => {}
                Some(GuestLayerSource::Pinned { digest }) => {
                    assert!(
                        crate::ArtifactDigest::parse(digest).is_ok(),
                        "{arch}: {digest}"
                    );
                }
                None => panic!("{arch} has no guest layer slot"),
            }
        }
        assert_eq!(guest_layer_for("riscv64"), None);
    }

    /// THE FINDING, as a refusal. A node built from this tree cannot boot the
    /// pinned 2.2.0 guest: it never prints `NUCLEUS_EGRESS_PROBE:`, and read-only
    /// it dies creating `/etc/nucleus/identity`. Before this table the floor said
    /// 2.2.0 was fine, `setup` installed it, and the failure surfaced mid-boot.
    #[test]
    fn the_pinned_release_is_refused_and_the_refusal_names_why() {
        let skew = guest_skew(GUEST_RELEASE)
            .expect_err("2.2.0 predates #2365 and #2379; a node from this tree cannot boot it");
        let GuestSkew::Lacks { missing, .. } = &skew else {
            panic!("2.2.0 is orderable: {skew:?}");
        };
        assert_eq!(
            missing,
            &[
                GuestCapability::EgressAttestation,
                GuestCapability::SvidOnTmpfs,
                GuestCapability::WorkloadDoor,
                GuestCapability::McpBridge,
            ]
        );
        let msg = skew.to_string();
        for needle in [
            "v2.2.0",
            "#2365",
            "#2379",
            "#3031",
            "#2696",
            "no published release yet",
            "build-rootfs.sh",
            "--artifacts local",
        ] {
            assert!(msg.contains(needle), "missing {needle:?} in: {msg}");
        }
    }

    /// A table entry naming a release the pin has not reached would be a claim
    /// about an artifact nobody has checked. The change that cuts the next
    /// release moves the pin, then the entries.
    #[test]
    fn no_capability_claims_a_release_after_the_pin() {
        let pin = parse_release(GUEST_RELEASE).expect("the pin parses");
        for cap in GuestCapability::ALL {
            if let FirstShipped::Release(v) = cap.first_shipped() {
                let since = parse_release(v).unwrap_or_else(|| panic!("{cap:?}: {v:?}"));
                assert!(since <= pin, "{cap:?} claims v{v}, past the pin");
            }
        }
    }

    /// `ALL` is what `guest_skew` iterates. A variant left out of it would be a
    /// requirement nobody checks; this match stops compiling when one is added,
    /// and the assertion proves it was listed.
    #[test]
    fn every_capability_is_in_all() {
        for c in GuestCapability::ALL {
            let next = match c {
                GuestCapability::CaBundle => GuestCapability::ApprovalByPublicKey,
                GuestCapability::ApprovalByPublicKey => GuestCapability::EgressAttestation,
                GuestCapability::EgressAttestation => GuestCapability::SvidOnTmpfs,
                GuestCapability::SvidOnTmpfs => GuestCapability::WorkloadDoor,
                GuestCapability::WorkloadDoor => GuestCapability::McpBridge,
                GuestCapability::McpBridge => GuestCapability::CaBundle,
            };
            assert!(GuestCapability::ALL.contains(&next), "{next:?} missing");
        }
    }

    /// 2.0.2 and everything before it ship a rootfs with no CA store, on which
    /// the tool-proxy panics as PID 1; 2.1.0 predates #2214. If either starts
    /// passing, an entry has been moved back past its fix.
    #[test]
    fn the_known_broken_releases_are_refused() {
        for (broken, lacks) in [
            ("2.0.2", GuestCapability::CaBundle),
            ("2.0.0", GuestCapability::CaBundle),
            ("1.0.9", GuestCapability::CaBundle),
            ("2.1.0", GuestCapability::ApprovalByPublicKey),
        ] {
            match guest_skew(broken) {
                Err(GuestSkew::Lacks { missing, .. }) => {
                    assert!(missing.contains(&lacks), "{broken}: {missing:?}")
                }
                other => panic!("{broken} must be refused for {lacks:?}: {other:?}"),
            }
        }
    }

    /// A table in which everything shipped by 2.2.0, to test the ordering rules
    /// on a release that satisfies it — the real table has none today.
    fn all_by_2_2_0(_: GuestCapability) -> FirstShipped {
        FirstShipped::Release("2.2.0")
    }

    /// A release CANDIDATE of an acceptable version must be acceptable: it
    /// contains the fixes. Strict semver would sort it below `2.2.0` and refuse
    /// it — which is why the parser compares the numeric core.
    #[test]
    fn a_prerelease_of_an_acceptable_version_is_accepted() {
        for rc in ["2.2.0-rc.1", "v2.2.0-rc.1", "2.2.0-rc1", "2.2.0+build.7"] {
            assert_eq!(parse_release(rc), Some((2, 2, 0)), "{rc} core");
            assert_eq!(skew_against(rc, all_by_2_2_0), Ok(()), "{rc}");
        }
    }

    /// The other half, and the one that keeps the above from being a hole: a
    /// prerelease of a BROKEN version is still broken.
    #[test]
    fn a_prerelease_of_a_refused_version_is_still_refused() {
        for rc in ["2.1.0-rc.1", "2.0.2-rc.1", "1.1.0-rc.1", "v2.0.0-beta"] {
            assert!(skew_against(rc, all_by_2_2_0).is_err(), "{rc}");
            assert!(guest_skew(rc).is_err(), "{rc}");
        }
    }

    /// "Could not order it" is its own answer, not a refusal for being old.
    #[test]
    fn an_unparseable_release_is_refused_rather_than_ordered_as_zero() {
        for bad in ["", "2.1", "2.1.0.1", "latest", "v2.x.0"] {
            assert_eq!(
                skew_against(bad, all_by_2_2_0),
                Err(GuestSkew::Unorderable {
                    release: bad.to_string()
                }),
                "{bad:?}"
            );
        }
    }

    /// An entry nobody can parse counts as missing, never as present.
    #[test]
    fn an_unparseable_table_entry_is_missing_not_present() {
        let unparseable = |_: GuestCapability| FirstShipped::Release("2.x");
        assert!(skew_against("9.9.9", unparseable).is_err());
    }

    /// A `v` prefix is what a git tag looks like, and it must order the same as
    /// the bare version rather than failing to parse.
    #[test]
    fn a_tag_style_version_parses() {
        assert_eq!(parse_release("v2.2.0"), parse_release("2.2.0"));
        assert_eq!(skew_against("v2.2.0", all_by_2_2_0), Ok(()));
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
