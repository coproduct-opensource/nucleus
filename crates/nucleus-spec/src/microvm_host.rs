//! The pins for hosting Firecracker microVMs inside an Apple `container`.
//!
//! # Why this exists
//!
//! On macOS the host tier runs `nucleus-node --driver firecracker` inside a
//! Linux VM that the `container` runtime starts with nested virtualization
//! (measured in `docs/findings/microvm-host-apple-container.md`). Three things
//! describe that VM: the recipes under `docker/`, the CLI code that starts it,
//! and the PodSpecs that name paths inside it. Each used to be free to say its
//! own thing, which is how `tier2_artifacts` found three provisioners pinning
//! three Firecracker builds. So every name, version, path and capability the
//! three share is written here once, and the tests at the bottom read the
//! committed recipes back and fail if they say anything else.
//!
//! # What is pinned and what is not yet
//!
//! Nothing has been published. The image and the L1 kernel are therefore
//! [`ArtifactSource::LocalBuild`] from their `docker/` recipes until a release
//! pins a digest, and the type makes that visible rather than carrying a
//! placeholder digest that reads like a pin (ADR 0007 A-1).

use std::fmt;

use crate::tier2_artifacts::{GUEST_KERNEL_FILE, GUEST_ROOTFS_FILE, HOST_ARTIFACTS_DIR};
use crate::vmm_version::{self, VmmVersion};

// ── names ────────────────────────────────────────────────────────────

/// The label every container nucleus creates for this tier carries.
///
/// The CLI only ever stops, starts or deletes a container that carries this
/// label with its own name as the value, so a container someone else created
/// under a colliding name is refused rather than clobbered.
pub const OWNER_LABEL: &str = "org.nucleus.microvm-host";

/// The `container` names one host tier installation uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostNames {
    /// The long-lived container that runs the node.
    pub container: &'static str,
    /// The block volume mounted at [`SRV_MOUNT`]. One running container at a
    /// time can attach it (findings, point 5).
    pub state_volume: &'static str,
    /// The tag a [`ArtifactSource::LocalBuild`] image is built under.
    pub image_tag: &'static str,
}

impl HostNames {
    /// What a user's installation is called.
    pub const INSTALL: HostNames = HostNames {
        container: "nucleus-microvm-host",
        state_volume: "nucleus-microvm-host-srv",
        image_tag: "nucleus-microvm-host:local",
    };

    /// What development and live tests use, so they can never touch a user's
    /// installation or anything else on the machine.
    pub const DEV: HostNames = HostNames {
        container: "nucleus-dev-microvm-host",
        state_volume: "nucleus-dev-microvm-host-srv",
        image_tag: "nucleus-dev-microvm-host:local",
    };
}

// ── the container CLI ────────────────────────────────────────────────

/// The `container` CLI's version, compared the obvious way.
///
/// The same dotted triple, and the same parser, as the VMM's: one reader for
/// "the first `X.Y.Z` in a tool's version output" (ADR 0007 G-1).
pub type CliVersion = VmmVersion;

/// The oldest `container` CLI the host tier runs on.
///
/// 1.4.1 is the build the spike measured, and it has both flags the tier
/// cannot do without: `run --virtualization` and a per-container `--kernel`.
/// Nothing older was measured, so nothing older is accepted.
pub const MIN_CLI_VERSION: CliVersion = VmmVersion::new(1, 4, 1);

/// Read the version from `container --version`, which prints
/// `container CLI version 1.4.1 (build: release, commit: …)`.
///
/// `None` means no version could be read, and a caller must treat that as
/// unmet, never as new enough.
pub fn parse_cli_version(raw: &str) -> Option<CliVersion> {
    vmm_version::parse_version(raw)
}

// ── the Mac ──────────────────────────────────────────────────────────

/// The oldest Apple silicon generation (the `N` in `Apple MN`) whose
/// hypervisor offers nested virtualization. M1 and M2 do not.
pub const MIN_APPLE_CHIP_GENERATION: u32 = 3;

/// The oldest macOS major version the tier runs on.
///
/// Nested virtualization arrived in macOS 15, but the spike measured 26 and
/// nothing else, so 26 is the floor until something older is measured.
pub const MIN_MACOS_MAJOR: u32 = 26;

/// The chip generation in a `machdep.cpu.brand_string` such as `Apple M5 Pro`.
///
/// `None` for anything that is not `Apple M<digits>`, which includes Intel.
pub fn parse_apple_chip_generation(brand: &str) -> Option<u32> {
    let rest = brand.trim().strip_prefix("Apple M")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// The major version in `sw_vers -productVersion` output such as `26.6.2`.
pub fn parse_macos_major(raw: &str) -> Option<u32> {
    raw.trim().split('.').next()?.parse().ok()
}

// ── the L1 kernel ────────────────────────────────────────────────────

/// A Kconfig value the L1 fragment sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kconfig {
    /// `CONFIG_X=y`.
    BuiltIn,
    /// `# CONFIG_X is not set`.
    NotSet,
}

/// Why the fragment sets a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentPurpose {
    /// Without it the kernel cannot host a microVM: a preflight that reads the
    /// kernel's config must find it.
    HostsMicroVms,
    /// Only makes the build cheaper. The kernel works either way.
    BuildEconomy,
}

/// One line of `docker/l1-kernel.fragment`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KconfigSetting {
    /// The symbol, including its `CONFIG_` prefix.
    pub symbol: &'static str,
    /// What it is set to.
    pub value: Kconfig,
    /// Why.
    pub purpose: FragmentPurpose,
}

impl KconfigSetting {
    const fn host(symbol: &'static str) -> Self {
        Self {
            symbol,
            value: Kconfig::BuiltIn,
            purpose: FragmentPurpose::HostsMicroVms,
        }
    }
}

impl fmt::Display for KconfigSetting {
    /// The line as a `.config` or fragment spells it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.value {
            Kconfig::BuiltIn => write!(f, "{}=y", self.symbol),
            Kconfig::NotSet => write!(f, "# {} is not set", self.symbol),
        }
    }
}

/// The L1 kernel: the runtime's own default kernel version, rebuilt with KVM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L1Kernel {
    /// The kernel.org version, which is also the default kernel's.
    pub linux_version: &'static str,
    /// The source tarball.
    pub source_url: &'static str,
    /// Its SHA-256, against kernel.org's signed `sha256sums.asc`.
    pub source_sha256: &'static str,
    /// SHA-256 of the default kernel whose embedded config is inherited
    /// (`vmlinux-6.18.35-197-debug` from the runtime's kata-static 3.32.0).
    pub base_kernel_sha256: &'static str,
    /// The delta over that config, in the order the fragment file lists it.
    pub fragment: &'static [KconfigSetting],
    /// Where the kernel comes from.
    pub source: ArtifactSource,
}

/// The L1 kernel the host tier attaches with `container run --kernel`, and
/// never as the system default.
pub const L1_KERNEL: L1Kernel = L1Kernel {
    linux_version: "6.18.35",
    source_url: "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.35.tar.xz",
    source_sha256: "f78602932219125e211c5f5bfd84edcfd4ec5ce88fc944f8248413f665bef236",
    base_kernel_sha256: "fb2cfb79eb1ae19447a85d75682d7fa5cfec97e24beb2609a492b806e8072c8d",
    fragment: &[
        KconfigSetting::host("CONFIG_VIRTUALIZATION"),
        KconfigSetting::host("CONFIG_KVM"),
        KconfigSetting::host("CONFIG_VHOST_MENU"),
        KconfigSetting::host("CONFIG_VHOST"),
        KconfigSetting::host("CONFIG_VHOST_VSOCK"),
        KconfigSetting {
            symbol: "CONFIG_DEBUG_INFO_NONE",
            value: Kconfig::BuiltIn,
            purpose: FragmentPurpose::BuildEconomy,
        },
        KconfigSetting {
            symbol: "CONFIG_DEBUG_INFO_BTF",
            value: Kconfig::NotSet,
            purpose: FragmentPurpose::BuildEconomy,
        },
    ],
    source: ArtifactSource::LocalBuild {
        containerfile: "docker/Containerfile.l1-kernel",
    },
};

/// Where `container build -o type=local` leaves the kernel, relative to the
/// output directory: one directory per platform.
pub const L1_KERNEL_IMAGE_IN_OUTPUT: &str = "linux_arm64/Image";

/// Where the same build leaves the kernel's final `.config`.
pub const L1_KERNEL_CONFIG_IN_OUTPUT: &str = "linux_arm64/config";

/// The fragment settings a kernel's `.config` must contain for it to host
/// microVMs. Derived from [`L1Kernel::fragment`], never listed twice.
pub fn required_kernel_config() -> impl Iterator<Item = &'static KconfigSetting> {
    L1_KERNEL
        .fragment
        .iter()
        .filter(|s| s.purpose == FragmentPurpose::HostsMicroVms)
}

/// The required settings a kernel `.config` lacks. Empty means it can host
/// microVMs, as far as its config says.
pub fn missing_kernel_config(config: &str) -> Vec<&'static KconfigSetting> {
    let lines: Vec<&str> = config.lines().map(str::trim).collect();
    required_kernel_config()
        .filter(|s| !lines.contains(&s.to_string().as_str()))
        .collect()
}

// ── the image ────────────────────────────────────────────────────────

/// Where an artifact of this tier comes from.
///
/// There is deliberately no default digest. Until a release publishes one, the
/// artifact is built locally from its recipe, and a caller can see that it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactSource {
    /// A published artifact, pinned by content digest.
    Pinned {
        /// `sha256:<64 lowercase hex>`.
        digest: &'static str,
    },
    /// Built on this machine from a recipe in this repository.
    LocalBuild {
        /// The recipe, relative to the repository root.
        containerfile: &'static str,
    },
}

/// The microVM host image.
pub const IMAGE_SOURCE: ArtifactSource = ArtifactSource::LocalBuild {
    containerfile: "docker/Containerfile.microvm-host",
};

/// The environment variable a developer sets to run a different image.
pub const IMAGE_OVERRIDE_ENV: &str = "NUCLEUS_MICROVM_HOST_IMAGE";

/// A developer's replacement for [`IMAGE_SOURCE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageOverride {
    /// An image already in the local store, by reference.
    Reference(String),
}

/// Why an override was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageOverrideError {
    /// The value was empty or only whitespace.
    Empty,
    /// The value had whitespace or a control character in it, so it would be
    /// split or mangled on the way to the CLI.
    NotAReference(String),
}

impl fmt::Display for ImageOverrideError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "{IMAGE_OVERRIDE_ENV} is set but empty"),
            Self::NotAReference(v) => {
                write!(f, "{IMAGE_OVERRIDE_ENV}={v:?} is not an image reference")
            }
        }
    }
}

impl std::error::Error for ImageOverrideError {}

/// Read a developer override. Refuses rather than ignoring a malformed value,
/// because silently falling back to the default image would run something the
/// developer did not ask for.
pub fn parse_image_override(raw: &str) -> Result<ImageOverride, ImageOverrideError> {
    let v = raw.trim();
    if v.is_empty() {
        return Err(ImageOverrideError::Empty);
    }
    if v.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ImageOverrideError::NotAReference(raw.to_string()));
    }
    Ok(ImageOverride::Reference(v.to_string()))
}

// ── what the container is started with ───────────────────────────────

/// A Linux capability the host container is started with, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    /// The name `container run --cap-add` takes.
    pub name: &'static str,
    /// What fails without it (findings, P2 leave-one-out).
    pub without_it: &'static str,
}

/// The capabilities added to the runtime's default set. Each was found
/// necessary by leave-one-out, even for a pod with no `network` block, because
/// the node always builds a default-deny netns. `CAP_SYS_RESOURCE` was tried
/// and is not needed.
pub const REQUIRED_CAPS: &[Capability] = &[
    Capability {
        name: "CAP_NET_ADMIN",
        without_it: "iptables in the pod netns: Permission denied",
    },
    Capability {
        name: "CAP_SYS_ADMIN",
        without_it: "the node cannot create the pod netns",
    },
    Capability {
        name: "CAP_SYS_PTRACE",
        without_it: "nsenter cannot open the jailed Firecracker's netns",
    },
];

// ── paths and ports inside the container ─────────────────────────────

/// Where the state volume is mounted. It holds the jail and the scratch
/// images (the jailer hard-links writable drives, so they must share a
/// filesystem) and the node's state, so all of it survives a restart.
pub const SRV_MOUNT: &str = "/srv";

/// The node's state directory (CA, pod records).
pub const NODE_STATE_DIR: &str = "/srv/state";

/// The jailer's chroot base.
pub const JAILER_CHROOT_BASE: &str = "/srv/jailer";

/// The workload API socket the node serves SVIDs on.
pub const WORKLOAD_API_SOCKET: &str = "/srv/state/wapi.sock";

/// The port the node listens on inside the container.
pub const NODE_PORT: u16 = 8080;

/// Where the image installs its binaries.
pub const BIN_DIR: &str = "/usr/local/bin";

/// The guest kernel inside the container, as a PodSpec's `image.kernel_path`
/// names it. The same path a Lima Tier 2 host uses.
pub fn guest_kernel_path() -> String {
    format!("{HOST_ARTIFACTS_DIR}/{GUEST_KERNEL_FILE}")
}

/// The guest root filesystem inside the container, as a PodSpec's
/// `image.rootfs_path` names it.
pub fn guest_rootfs_path() -> String {
    format!("{HOST_ARTIFACTS_DIR}/{GUEST_ROOTFS_FILE}")
}

/// A binary installed in the image.
pub fn in_container_bin(name: &str) -> String {
    format!("{BIN_DIR}/{name}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier2_artifacts::{GUEST_RELEASE, KERNEL_AARCH64};
    use std::path::PathBuf;

    fn repo_file(rel: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
    }

    fn recipe(source: ArtifactSource) -> String {
        match source {
            ArtifactSource::LocalBuild { containerfile } => repo_file(containerfile),
            ArtifactSource::Pinned { digest } => panic!("no recipe for pinned {digest}"),
        }
    }

    /// `ENV` values in a Containerfile, `KEY=value` pairs on continuation lines.
    fn env_value(containerfile: &str, key: &str) -> String {
        let prefix = format!("{key}=");
        containerfile
            .lines()
            .map(|l| {
                l.trim()
                    .trim_start_matches("ENV ")
                    .trim_end_matches('\\')
                    .trim()
            })
            .find_map(|l| l.strip_prefix(&prefix).map(str::to_string))
            .unwrap_or_else(|| panic!("the recipe sets no {key}"))
    }

    // ── the fragment cannot drift from the list ──

    /// The settings a fragment file states, comments and blanks skipped.
    fn parse_fragment(text: &str) -> Vec<String> {
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .filter(|l| !l.starts_with('#') || l.ends_with(" is not set"))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn the_committed_fragment_is_exactly_the_list() {
        let committed = parse_fragment(&repo_file("docker/l1-kernel.fragment"));
        let listed: Vec<String> = L1_KERNEL.fragment.iter().map(|s| s.to_string()).collect();
        assert!(!committed.is_empty(), "the fragment parsed to nothing");
        assert_eq!(
            committed, listed,
            "docker/l1-kernel.fragment and microvm_host::L1_KERNEL.fragment disagree"
        );
    }

    #[test]
    fn a_dropped_fragment_line_is_seen() {
        let text = repo_file("docker/l1-kernel.fragment").replace("CONFIG_VHOST_VSOCK=y", "");
        let listed: Vec<String> = L1_KERNEL.fragment.iter().map(|s| s.to_string()).collect();
        assert_ne!(parse_fragment(&text), listed);
    }

    #[test]
    fn the_kernel_recipe_builds_the_pinned_source_over_the_pinned_base() {
        let r = recipe(L1_KERNEL.source);
        assert!(r.contains(&format!("--checksum=sha256:{}", L1_KERNEL.source_sha256)));
        assert!(r.contains(L1_KERNEL.source_url));
        assert!(r.contains(&format!(
            "{}  /src/base-kernel",
            L1_KERNEL.base_kernel_sha256
        )));
        assert!(r.contains(&format!("linux-{}", L1_KERNEL.linux_version)));
        assert!(
            L1_KERNEL
                .source_url
                .ends_with(&format!("linux-{}.tar.xz", L1_KERNEL.linux_version))
        );
        assert!(r.contains("l1-kernel.fragment"));
        assert!(r.contains("COPY --from=build /src/linux-6.18.35/arch/arm64/boot/Image /Image"));
    }

    // ── the kernel config check ──

    #[test]
    fn a_config_with_every_required_symbol_is_complete() {
        let config: String = L1_KERNEL
            .fragment
            .iter()
            .map(|s| format!("{s}\n"))
            .collect();
        assert!(missing_kernel_config(&config).is_empty());
    }

    #[test]
    fn the_default_kernel_config_is_missing_kvm() {
        // What the runtime's default kernel says (findings, P7).
        let default = "# CONFIG_VIRTUALIZATION is not set\nCONFIG_BRIDGE_NETFILTER=y\n";
        let missing: Vec<&str> = missing_kernel_config(default)
            .iter()
            .map(|s| s.symbol)
            .collect();
        assert!(missing.contains(&"CONFIG_VIRTUALIZATION"));
        assert!(missing.contains(&"CONFIG_KVM"));
        assert!(missing.contains(&"CONFIG_VHOST_VSOCK"));
    }

    #[test]
    fn build_economy_settings_are_not_required() {
        assert!(required_kernel_config().all(|s| s.purpose == FragmentPurpose::HostsMicroVms));
        assert_eq!(required_kernel_config().count(), 5);
    }

    // ── the image recipe cannot drift from the paths ──

    #[test]
    fn the_image_installs_guest_artifacts_where_podspecs_look() {
        let r = recipe(IMAGE_SOURCE);
        assert!(
            r.contains(&format!("/out/artifacts/ {HOST_ARTIFACTS_DIR}/")),
            "the image must install guest artifacts under HOST_ARTIFACTS_DIR"
        );
        assert!(r.contains(&format!("/out/artifacts/{GUEST_KERNEL_FILE}")));
        assert!(r.contains(&format!("/out/artifacts/{GUEST_ROOTFS_FILE}")));
        assert_eq!(guest_kernel_path(), "/var/lib/nucleus/artifacts/vmlinux");
        assert_eq!(
            guest_rootfs_path(),
            "/var/lib/nucleus/artifacts/rootfs.ext4"
        );
    }

    #[test]
    fn the_image_node_environment_matches_the_pins() {
        let r = recipe(IMAGE_SOURCE);
        assert_eq!(env_value(&r, "NUCLEUS_NODE_STATE_DIR"), NODE_STATE_DIR);
        assert_eq!(
            env_value(&r, "NUCLEUS_JAILER_CHROOT_BASE"),
            JAILER_CHROOT_BASE
        );
        assert_eq!(
            env_value(&r, "NUCLEUS_IDENTITY_WORKLOAD_API_SOCKET"),
            WORKLOAD_API_SOCKET
        );
        assert_eq!(
            env_value(&r, "NUCLEUS_NODE_LISTEN"),
            format!("0.0.0.0:{NODE_PORT}")
        );
        assert_eq!(
            env_value(&r, "NUCLEUS_FIRECRACKER_PATH"),
            in_container_bin("firecracker")
        );
        assert_eq!(
            env_value(&r, "NUCLEUS_JAILER_PATH"),
            in_container_bin("jailer")
        );
        for p in [NODE_STATE_DIR, JAILER_CHROOT_BASE, WORKLOAD_API_SOCKET] {
            assert!(
                p.starts_with(&format!("{SRV_MOUNT}/")),
                "{p} is off the volume"
            );
        }
    }

    #[test]
    fn the_image_pins_the_same_vmm_guest_kernel_and_release() {
        let r = recipe(IMAGE_SOURCE);
        let fc = vmm_version::PINNED_STR;
        assert!(r.contains(&format!("/v{fc}/firecracker-v{fc}-aarch64.tgz")));
        assert!(r.contains(&format!("--checksum=sha256:{}", KERNEL_AARCH64.sha256)));
        assert!(r.contains(KERNEL_AARCH64.url));
        assert!(r.contains(&format!("releases/download/v{GUEST_RELEASE}/")));
    }

    // ── versions and the Mac ──

    #[test]
    fn the_cli_version_is_read_from_real_output() {
        let out = "container CLI version 1.4.1 (build: release, commit: unspeci)\n";
        assert_eq!(parse_cli_version(out), Some(VmmVersion::new(1, 4, 1)));
        assert!(parse_cli_version(out).is_some_and(|v| v >= MIN_CLI_VERSION));
        assert!(
            parse_cli_version("container CLI version 1.4.0").is_some_and(|v| v < MIN_CLI_VERSION)
        );
        assert_eq!(parse_cli_version("container: command not found"), None);
    }

    #[test]
    fn chip_and_macos_are_read_from_real_output() {
        assert_eq!(parse_apple_chip_generation("Apple M5 Pro"), Some(5));
        assert_eq!(parse_apple_chip_generation("Apple M10 Max\n"), Some(10));
        assert_eq!(parse_apple_chip_generation("Apple M2"), Some(2));
        assert_eq!(parse_apple_chip_generation("Intel(R) Core(TM) i9"), None);
        assert_eq!(parse_apple_chip_generation("Apple M"), None);
        assert_eq!(parse_macos_major("26.6.2\n"), Some(26));
        assert_eq!(parse_macos_major("15.4"), Some(15));
        assert_eq!(parse_macos_major(""), None);
    }

    // ── names, caps, image source ──

    #[test]
    fn dev_names_are_disjoint_from_install_names_and_prefixed() {
        let (i, d) = (HostNames::INSTALL, HostNames::DEV);
        for (a, b) in [
            (i.container, d.container),
            (i.state_volume, d.state_volume),
            (i.image_tag, d.image_tag),
        ] {
            assert_ne!(a, b);
            assert!(b.starts_with("nucleus-dev-"), "{b}");
            assert!(a.starts_with("nucleus-"), "{a}");
        }
    }

    #[test]
    fn the_caps_are_the_measured_three() {
        let names: Vec<&str> = REQUIRED_CAPS.iter().map(|c| c.name).collect();
        assert_eq!(names, ["CAP_NET_ADMIN", "CAP_SYS_ADMIN", "CAP_SYS_PTRACE"]);
    }

    #[test]
    fn nothing_is_pinned_before_a_release() {
        assert!(matches!(IMAGE_SOURCE, ArtifactSource::LocalBuild { .. }));
        assert!(matches!(
            L1_KERNEL.source,
            ArtifactSource::LocalBuild { .. }
        ));
    }

    #[test]
    fn an_override_is_refused_rather_than_ignored_when_malformed() {
        assert_eq!(parse_image_override("  "), Err(ImageOverrideError::Empty));
        assert!(matches!(
            parse_image_override("a b"),
            Err(ImageOverrideError::NotAReference(_))
        ));
        assert_eq!(
            parse_image_override(" nucleus-dev-microvm-host:other \n"),
            Ok(ImageOverride::Reference(
                "nucleus-dev-microvm-host:other".into()
            ))
        );
    }
}
