//! The paths the guest runtime owns inside a pod's root filesystem.
//!
//! # Why one table
//!
//! A pod's rootfs has two authors. The **image** supplies the workload: a
//! language runtime, a CLI, whatever the pod exists to run, and nucleus does not
//! know or care what it is. The **guest layer** supplies the runtime that
//! mediates it: `/init`, the tool-proxy, the probes, the baked policy. The
//! guarantee rests on the second author winning every path it trusts.
//!
//! Those paths used to be string literals in each consumer — `nucleus-guest-init`
//! had `PROXY_BIN`, `EGRESS_PROBE_BIN` and `POD_SPEC_PATH` as private consts,
//! `nucleus-workload-probe` re-typed the spec path, and `build-rootfs.sh`
//! restated the overlay-guard list by hand. An importer that refuses image
//! layers writing a trusted path would have been a fourth copy, and the first
//! trusted path added to one copy and not the other would be a path an image
//! could replace unnoticed (ADR 0007 G-1: one decider per fact).
//!
//! So every path the runtime trusts is built from [`RESERVED`]'s own prefixes by
//! the private macros below: `PROXY_BIN` is `nucleus_bin!("tool-proxy")`, which
//! is under the `/usr/local/bin/nucleus-` prefix *by construction*, not because
//! somebody kept two lists in step. The refusal list and the trusted paths
//! cannot drift, because there is only one list.
//!
//! # What this module does not do
//!
//! It decides nothing about an image's contents. An importer consults
//! [`reserved_by`] per layer entry; the runtime reads the path constants. Paths
//! the guest *mounts over* are listed too ([`ReservedKind::MustBeEmptyDir`]),
//! because a mount that fails leaves the image's contents visible, and a
//! mount-only-if-it-works directory is only safe if what shows through is
//! nothing.

/// `/etc/nucleus/<file>` — the guest layer's configuration directory.
macro_rules! etc_nucleus {
    ($file:literal) => {
        concat!("/etc/nucleus/", $file)
    };
}

/// `/usr/local/bin/nucleus-<name>` — the guest layer's binaries.
macro_rules! nucleus_bin {
    ($name:literal) => {
        concat!("/usr/local/bin/nucleus-", $name)
    };
}

/// How a [`Reserved`] entry claims the paths it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservedKind {
    /// Exactly this path.
    Exact,
    /// This path and everything whose path starts with it. A prefix ending in
    /// `/` also claims the directory itself, so an image cannot replace
    /// `/etc/nucleus` with a symlink.
    Prefix,
    /// A directory the guest mounts over or populates at boot. The directory
    /// itself may exist in an image; nothing may be *inside* it.
    MustBeEmptyDir,
}

/// One path (or family of paths) owned by the guest layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reserved {
    /// Absolute path inside the guest.
    pub path: &'static str,
    /// How the path is claimed.
    pub kind: ReservedKind,
    /// Why an image may not supply it — shown to whoever is refused.
    pub why: &'static str,
    /// What a confined workload may do there (#2696 P3c). Stated on every
    /// entry, beside the reason it is reserved, so the Landlock ruleset and the
    /// list of trusted paths are one table (ADR 0007 G-1).
    pub workload: WorkloadFs,
}

/// What a confined workload may do beneath a guest path: the input the
/// workload's Landlock ruleset is compiled from (`nucleus::ChildConfinement`,
/// #2696 P3c).
///
/// A path [`RESERVED`] does not name is [`WorkloadFs::Read`]: the image's own
/// files are the workload's to read and run, and nothing more.
///
/// No `Default` (ADR 0007 B-1): each reserved entry states its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadFs {
    /// No access at all, not even listing: runtime-owned state (the pod spec,
    /// the SVID, legacy secrets). Connecting to a socket beneath it is not an
    /// access Landlock governs, which is why the workload door under `/run`
    /// still answers.
    Hidden,
    /// Read files, list directories and execute. Never write, create or remove.
    Read,
    /// Everything the kernel's Landlock ABI can govern: the workload's own
    /// scratch and temporary space.
    ReadWrite,
    /// The directory itself is not granted; only the [`WORKLOAD_DEVICES`]
    /// beneath it, each read-write.
    Devices,
}

/// The device nodes under `/dev` a confined workload may open, read-write.
/// Nothing else under `/dev` is granted (the block devices, `vsock`, `kmsg`).
/// Symlinks such as `/dev/stdout` resolve into `/proc`, which is
/// [`WorkloadFs::Read`].
///
/// Minimal on purpose: the data sinks and sources every program assumes.
/// No `tty`: the workload has no controlling terminal, so it gains nothing
/// (and on the x86_64 guest even an `O_PATH` open of it answers `ENXIO`).
/// No `ptmx`/`pts`: the guest mounts no devpts, so a pseudo-terminal cannot
/// be allocated there whatever the grant says.
pub const WORKLOAD_DEVICES: &[&str] = &["null", "zero", "full", "random", "urandom"];

/// The kernel command-line token by which the NODE waives Landlock for the
/// workloads of a pod whose kernel cannot enforce it (#2696 P3c). Without it, a
/// guest whose kernel lacks Landlock at the minimum ABI refuses to start a
/// confined child. Not a secret: the command line is world-readable, and the
/// token grants the workload nothing it could use.
pub const WORKLOAD_LANDLOCK_WAIVED_ARG: &str = "nucleus.workload_landlock=waived";

/// The prefix of the console line the tool-proxy prints once at startup,
/// stating whether its children's filesystem is confined by Landlock. The node
/// reads it into the pod's reported posture (#2696 P3c).
pub const WORKLOAD_LANDLOCK_VERDICT: &str = "NUCLEUS_WORKLOAD_LANDLOCK:";

/// What the tool-proxy reports about its children's filesystem confinement,
/// as one [`WORKLOAD_LANDLOCK_VERDICT`] line on the console. The guest renders
/// it and the node parses it with the same type, so the two cannot spell it
/// differently (ADR 0007 G-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadLandlockVerdict {
    /// Every confined child is held to the guest layout's ruleset at this ABI.
    Enforced {
        /// The kernel's Landlock ABI.
        abi: u32,
    },
    /// The kernel cannot enforce Landlock and the node waived it: children
    /// run filesystem-unconfined.
    Waived {
        /// What the kernel offered instead.
        kernel: String,
    },
    /// The kernel cannot enforce Landlock and nothing waived it: every
    /// confined child is refused, so the workload never starts.
    Refused {
        /// What the kernel offered instead.
        kernel: String,
    },
    /// This containment does not hold the filesystem with Landlock.
    NotApplied,
}

impl WorkloadLandlockVerdict {
    /// The console line.
    #[must_use]
    pub fn line(&self) -> String {
        let body = match self {
            Self::Enforced { abi } => format!("enforced abi={abi}"),
            Self::Waived { kernel } => format!("waived {kernel}"),
            Self::Refused { kernel } => format!("refused {kernel}"),
            Self::NotApplied => "not_applied".to_string(),
        };
        format!("{WORKLOAD_LANDLOCK_VERDICT} {body}")
    }

    /// The verdict on a captured console, if the guest printed one. A line
    /// that carries the prefix but no verdict this type can read is `None`,
    /// the same as no line: an unreadable claim is no claim.
    #[must_use]
    pub fn parse(console: &str) -> Option<Self> {
        let rest = console.lines().find_map(|l| {
            l.find(WORKLOAD_LANDLOCK_VERDICT)
                .map(|at| l[at + WORKLOAD_LANDLOCK_VERDICT.len()..].trim())
        })?;
        let (word, detail) = rest.split_once(' ').unwrap_or((rest, ""));
        match word {
            "enforced" => detail
                .strip_prefix("abi=")
                .and_then(|n| n.trim().parse().ok())
                .map(|abi| Self::Enforced { abi }),
            "waived" => Some(Self::Waived {
                kernel: detail.to_string(),
            }),
            "refused" => Some(Self::Refused {
                kernel: detail.to_string(),
            }),
            "not_applied" if detail.is_empty() => Some(Self::NotApplied),
            _ => None,
        }
    }
}

/// The guest's PID 1.
pub const INIT: &str = "/init";

/// The guest layer's configuration directory, as a prefix.
pub const ETC_NUCLEUS: &str = etc_nucleus!("");

/// The guest layer's binaries, as a name prefix.
pub const NUCLEUS_BIN_PREFIX: &str = nucleus_bin!("");

/// The baked pod spec. Wins only in legacy mode; enforced guests require the host spec.
pub const POD_SPEC_PATH: &str = etc_nucleus!("pod.yaml");

/// Node-owned boot configuration: a sanitized host spec must replace baked specs.
pub const HOST_SPEC_REQUIRED_ARG: &str = "nucleus.host_spec=required";
/// Guest compatibility acknowledgment, not host-authoritative execution evidence.
pub const HOST_SPEC_READY: &str = "NUCLEUS_HOST_SPEC: READY";

/// The legacy location of the baked pod spec, copied to [`POD_SPEC_PATH`] when
/// that is absent. Reserved because it outranks the host-fetched spec: an image
/// that shipped `/pod.yaml` would otherwise choose the command the pod runs.
pub const FALLBACK_POD_SPEC: &str = "/pod.yaml";

/// Guest-side egress allowlist (defence in depth; the host netns is primary).
pub const NET_ALLOW: &str = etc_nucleus!("net.allow");
/// Guest-side egress denylist.
pub const NET_DENY: &str = etc_nucleus!("net.deny");
/// Legacy baked HMAC secret (deprecated `--legacy-secrets`).
pub const AUTH_SECRET: &str = etc_nucleus!("auth.secret");
/// Legacy baked approval secret (deprecated `--legacy-secrets`).
pub const APPROVAL_SECRET: &str = etc_nucleus!("approval.secret");
/// Legacy baked sandbox token.
pub const SANDBOX_TOKEN: &str = etc_nucleus!("sandbox.token");
/// Where the audit log goes, when the image builder chose.
pub const AUDIT_PATH_FILE: &str = etc_nucleus!("audit.path");

/// The CA bundle the guest layer ships. The runtime's TLS stack reads this,
/// never the image's store: a workload image is free to have no CA store, or
/// one that trusts whatever its author likes.
pub const CA_BUNDLE: &str = etc_nucleus!("ca-bundle.pem");

/// Where 2.x rootfs images carried the bundle. **Image-owned**, deliberately
/// not reserved: it is only a fallback for a guest layer that predates
/// [`CA_BUNDLE`], and a Debian-derived workload image legitimately ships it.
pub const LEGACY_CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

/// The mediating runtime.
pub const PROXY_BIN: &str = GuestBinary::ToolProxy.path();
/// The in-guest egress confinement probe; its verdict line is required by the node.
pub const EGRESS_PROBE_BIN: &str = GuestBinary::EgressProbe.path();
/// The network reachability probe.
pub const NET_PROBE_BIN: &str = GuestBinary::NetProbe.path();
/// The workload-mediation probe.
pub const WORKLOAD_PROBE_BIN: &str = GuestBinary::WorkloadProbe.path();
/// The pod-list probe (C2 boot lane).
pub const PODLIST_PROBE_BIN: &str = GuestBinary::PodlistProbe.path();
/// The adversary probe (probe-pod boot lane).
pub const ADVERSARY_PROBE_BIN: &str = GuestBinary::AdversaryProbe.path();
/// The MCP bridge an agent in the pod speaks to (#2696 P2): stdio MCP in, the
/// tool-proxy's workload door out. It needs no flags there: the runtime gives
/// the workload `NUCLEUS_TOOL_PROXY_URL`, the door's `unix://` URL.
pub const MCP_BIN: &str = GuestBinary::Mcp.path();

/// A binary the guest layer ships, and the one place its guest path and the
/// cargo package that builds it are written.
///
/// The guest layer (`cargo xtask guest-layer`) is built from
/// [`GuestBinary::ALL`], and the release workflow is checked against the same
/// list, so a probe added here is a probe the layer carries and the release
/// must build — nothing else has to be remembered (ADR 0007 G-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GuestBinary {
    /// `/init`, the guest's PID 1.
    Init,
    /// The mediating runtime.
    ToolProxy,
    /// The in-guest egress confinement probe.
    EgressProbe,
    /// The network reachability probe.
    NetProbe,
    /// The workload-mediation probe.
    WorkloadProbe,
    /// The pod-list probe.
    PodlistProbe,
    /// The adversary probe.
    AdversaryProbe,
    /// The MCP bridge (`nucleus-mcp`), which an agent run in the pod uses to
    /// reach its tools through the workload door (#2696 P2).
    Mcp,
    /// Local HTTP compatibility adapter for the credentialed workload door.
    EgressHttp,
}

/// `(guest path, binary target)` for a binary installed under
/// [`NUCLEUS_BIN_PREFIX`]: both halves from one name, so they cannot disagree.
macro_rules! guest_bin {
    ($name:literal) => {
        (nucleus_bin!($name), concat!("nucleus-", $name))
    };
}

impl GuestBinary {
    /// Every binary the guest layer ships.
    pub const ALL: [Self; 9] = [
        Self::Init,
        Self::ToolProxy,
        Self::EgressProbe,
        Self::NetProbe,
        Self::WorkloadProbe,
        Self::PodlistProbe,
        Self::AdversaryProbe,
        Self::Mcp,
        Self::EgressHttp,
    ];

    /// `(guest path, binary target)`.
    const fn parts(self) -> (&'static str, &'static str) {
        match self {
            Self::Init => (INIT, "nucleus-guest-init"),
            Self::ToolProxy => guest_bin!("tool-proxy"),
            Self::EgressProbe => guest_bin!("egress-probe"),
            Self::NetProbe => guest_bin!("net-probe"),
            Self::WorkloadProbe => guest_bin!("workload-probe"),
            Self::PodlistProbe => guest_bin!("podlist-probe"),
            Self::AdversaryProbe => guest_bin!("adversary-probe"),
            Self::Mcp => guest_bin!("mcp"),
            Self::EgressHttp => guest_bin!("egress-http"),
        }
    }

    /// Absolute path inside the guest.
    #[must_use]
    pub const fn path(self) -> &'static str {
        self.parts().0
    }

    /// The executable name; a package may produce more than one.
    #[must_use]
    pub const fn binary(self) -> &'static str {
        self.parts().1
    }

    /// The cargo package that builds the executable.
    #[must_use]
    pub const fn package(self) -> &'static str {
        match self {
            Self::Init
            | Self::ToolProxy
            | Self::EgressHttp
            | Self::EgressProbe
            | Self::NetProbe
            | Self::WorkloadProbe
            | Self::PodlistProbe
            | Self::AdversaryProbe
            | Self::Mcp => self.binary(),
        }
    }
}

/// The per-pod scratch mount.
pub const WORK_DIR: &str = "/work";

/// The workload door: the Unix socket on which the tool-proxy serves the
/// workload, and only the workload (#3031 option B, #2696 P1).
///
/// The one declaration of where it is. The proxy binds it, and the workload
/// learns it from `NUCLEUS_TOOL_PROXY_URL` (`unix://` + this path), which the
/// proxy derives from the socket it actually bound, never from this constant
/// re-typed.
///
/// Under `/run`, the boot tmpfs, so an image cannot pre-place anything there.
/// In a directory of its own, and not under `/run/nucleus`, because that
/// directory is mode 0700 and the workload's uid could not traverse it to
/// connect. The workload's own scratch (`/work`) is the wrong home too: the
/// workload owns it, so it could unlink the socket and bind its own.
pub const WORKLOAD_DOOR: &str = "/run/nucleus-door/workload.sock";

/// The name of the workload's home directory under its work dir.
///
/// A name, not a path, because the tool-proxy also runs outside a guest with a
/// different work dir; inside the guest it resolves to `/work/.home`. On the
/// scratch rather than the rootfs because the rootfs is read-only by the time
/// the workload runs, and a `HOME` that cannot be written makes ordinary tools
/// fail in ways that look like the workload's own bugs.
pub const WORKLOAD_HOME_NAME: &str = ".home";

/// Every path the guest layer owns. See the module docs for why this is the
/// only list.
pub const RESERVED: &[Reserved] = &[
    Reserved {
        path: INIT,
        kind: ReservedKind::Exact,
        why: "the guest's PID 1; an image-supplied /init would replace the runtime",
        workload: WorkloadFs::Read,
    },
    Reserved {
        path: ETC_NUCLEUS,
        kind: ReservedKind::Prefix,
        why: "the baked pod spec, egress policy and CA bundle the runtime trusts",
        workload: WorkloadFs::Hidden,
    },
    Reserved {
        path: NUCLEUS_BIN_PREFIX,
        kind: ReservedKind::Prefix,
        why: "the mediating runtime and its probes",
        workload: WorkloadFs::Read,
    },
    Reserved {
        path: FALLBACK_POD_SPEC,
        kind: ReservedKind::Exact,
        why: "outranks the host-fetched pod spec, so it would choose the pod's command",
        workload: WorkloadFs::Hidden,
    },
    Reserved {
        path: "/run/",
        kind: ReservedKind::MustBeEmptyDir,
        why: "tmpfs mounted at boot; holds the fetched spec and identity",
        workload: WorkloadFs::Hidden,
    },
    Reserved {
        path: "/tmp/",
        kind: ReservedKind::MustBeEmptyDir,
        why: "tmpfs mounted at boot",
        workload: WorkloadFs::ReadWrite,
    },
    Reserved {
        path: "/work/",
        kind: ReservedKind::MustBeEmptyDir,
        why: "the pod scratch is mounted here; without a scratch drive the image's contents would show through",
        workload: WorkloadFs::ReadWrite,
    },
    Reserved {
        path: "/cache/",
        kind: ReservedKind::MustBeEmptyDir,
        why: "the pinned compiler cache is mounted here; stale image contents would poison it",
        workload: WorkloadFs::ReadWrite,
    },
    Reserved {
        path: "/cache-seed/",
        kind: ReservedKind::MustBeEmptyDir,
        why: "the pinned cache seed is mounted here",
        workload: WorkloadFs::Read,
    },
    Reserved {
        path: "/proc/",
        kind: ReservedKind::MustBeEmptyDir,
        why: "procfs is mounted at boot",
        workload: WorkloadFs::Read,
    },
    Reserved {
        path: "/sys/",
        kind: ReservedKind::MustBeEmptyDir,
        why: "sysfs is mounted at boot",
        workload: WorkloadFs::Read,
    },
    Reserved {
        path: "/dev/",
        kind: ReservedKind::MustBeEmptyDir,
        why: "devtmpfs is mounted at boot; an image-supplied device node is a privilege primitive",
        workload: WorkloadFs::Devices,
    },
];

/// The [`RESERVED`] entry that claims `path`, if any.
///
/// Accepts an absolute guest path (`/etc/nucleus/pod.yaml`) or an image-layer
/// path (`etc/nucleus/pod.yaml`, `./etc/nucleus/pod.yaml`). A
/// [`ReservedKind::MustBeEmptyDir`] directory itself is *not* claimed — an image
/// may create `/work` — only what is inside it.
#[must_use]
pub fn reserved_by(path: &str) -> Option<&'static Reserved> {
    let rel = path.trim_start_matches("./").trim_start_matches('/');
    let rel = rel.strip_suffix('/').unwrap_or(rel);
    RESERVED.iter().find(|r| {
        let claimed = r.path.trim_start_matches('/');
        match r.kind {
            ReservedKind::Exact => rel == claimed,
            ReservedKind::Prefix => {
                rel.starts_with(claimed) || claimed.strip_suffix('/').is_some_and(|dir| rel == dir)
            }
            ReservedKind::MustBeEmptyDir => rel.starts_with(claimed),
        }
    })
}

/// The [`RESERVED`] entry rooted exactly at `path` (an absolute guest path with
/// no trailing slash), as the workload's Landlock ruleset sees it: a
/// directory entry (`/tmp/`) or an exact one (`/init`) is rooted at its own
/// path, and a name prefix (`/usr/local/bin/nucleus-`) roots every path that
/// starts with it. `None`: no entry is rooted here, so `path` is the image's.
///
/// Unlike [`reserved_by`], a [`ReservedKind::MustBeEmptyDir`] directory IS
/// matched by its own path: what the workload may do in `/work` is a fact
/// about `/work`.
#[must_use]
pub fn reserved_at(path: &str) -> Option<&'static Reserved> {
    RESERVED.iter().find(|r| match r.path.strip_suffix('/') {
        Some(dir) => path == dir,
        None => match r.kind {
            ReservedKind::Prefix => path.starts_with(r.path),
            ReservedKind::Exact | ReservedKind::MustBeEmptyDir => path == r.path,
        },
    })
}

/// Whether a reserved entry that the workload may NOT simply read lies strictly
/// beneath `path`. A Landlock rule grants a whole subtree and cannot carve a
/// hole in it, so such a directory is not granted whole: its children are
/// granted one by one instead, and the hole is the child left out.
#[must_use]
pub fn workload_must_descend(path: &str) -> bool {
    let beneath = if path == "/" {
        "/".to_string()
    } else {
        format!("{path}/")
    };
    RESERVED.iter().any(|r| {
        r.workload != WorkloadFs::Read && r.path.starts_with(&beneath) && r.path != beneath
    })
}

/// Which CA bundle the runtime's TLS stack should read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaBundle {
    /// The guest layer's own bundle at [`CA_BUNDLE`].
    GuestLayer,
    /// A 2.x rootfs that predates [`CA_BUNDLE`]: the bundle at
    /// [`LEGACY_CA_BUNDLE`].
    LegacyRootfs,
    /// Neither exists. A proxy with drand enabled will refuse to start, naming
    /// the missing store; this is not silently turned into "no TLS".
    Absent,
}

impl CaBundle {
    /// The one decider: the guest layer's bundle, else the 2.x location.
    #[must_use]
    pub fn resolve(exists: impl Fn(&str) -> bool) -> Self {
        if exists(CA_BUNDLE) {
            Self::GuestLayer
        } else if exists(LEGACY_CA_BUNDLE) {
            Self::LegacyRootfs
        } else {
            Self::Absent
        }
    }

    /// The file to hand the TLS stack, if there is one.
    #[must_use]
    pub fn path(self) -> Option<&'static str> {
        match self {
            Self::GuestLayer => Some(CA_BUNDLE),
            Self::LegacyRootfs => Some(LEGACY_CA_BUNDLE),
            Self::Absent => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every path the runtime trusts is claimed by the table. Built from the
    /// table's prefixes by construction; this is the check that the
    /// construction still holds (a const typed as a bare literal would fail).
    #[test]
    fn every_trusted_path_is_reserved() {
        for path in [
            INIT,
            POD_SPEC_PATH,
            FALLBACK_POD_SPEC,
            NET_ALLOW,
            NET_DENY,
            AUTH_SECRET,
            APPROVAL_SECRET,
            SANDBOX_TOKEN,
            AUDIT_PATH_FILE,
            CA_BUNDLE,
            PROXY_BIN,
            EGRESS_PROBE_BIN,
            NET_PROBE_BIN,
            WORKLOAD_PROBE_BIN,
            PODLIST_PROBE_BIN,
            ADVERSARY_PROBE_BIN,
            MCP_BIN,
            WORKLOAD_DOOR,
        ] {
            assert!(
                reserved_by(path).is_some(),
                "{path} is trusted but not reserved"
            );
        }
    }

    /// `ALL` is what the guest layer is built from, so a variant missing from it
    /// is a binary no layer carries. The match is exhaustive: a new variant does
    /// not compile until it is given a slot here, beside `ALL`.
    #[test]
    fn every_guest_binary_is_in_all_once() {
        let slot = |b: GuestBinary| match b {
            GuestBinary::Init => 0,
            GuestBinary::ToolProxy => 1,
            GuestBinary::EgressProbe => 2,
            GuestBinary::NetProbe => 3,
            GuestBinary::WorkloadProbe => 4,
            GuestBinary::PodlistProbe => 5,
            GuestBinary::AdversaryProbe => 6,
            GuestBinary::Mcp => 7,
            GuestBinary::EgressHttp => 8,
        };
        for (i, b) in GuestBinary::ALL.iter().enumerate() {
            assert_eq!(slot(*b), i, "{b:?} out of place in ALL");
        }
    }

    /// An agent in the pod reaches its tools through the MCP bridge, so the
    /// guest layer must carry it at the path the runtime and the CLI expect.
    /// Asked by package name, so it reads the same before `GuestBinary::Mcp`
    /// existed (red) and after (green).
    #[test]
    fn the_guest_layer_ships_the_mcp_bridge() {
        let mcp = GuestBinary::ALL
            .into_iter()
            .find(|b| b.package() == "nucleus-mcp")
            .expect("the guest layer carries no nucleus-mcp");
        assert_eq!(mcp.path(), "/usr/local/bin/nucleus-mcp");
        assert!(reserved_by(mcp.path()).is_some());
    }

    /// Every guest binary is reserved, and every one but `/init` sits under the
    /// binary prefix with its binary target's name.
    #[test]
    fn guest_binaries_are_reserved_and_named_by_their_binary_target() {
        for b in GuestBinary::ALL {
            assert!(reserved_by(b.path()).is_some(), "{b:?} not reserved");
            if b != GuestBinary::Init {
                assert_eq!(
                    b.path().strip_prefix("/usr/local/bin/"),
                    Some(b.binary()),
                    "{b:?}"
                );
            }
        }
    }

    /// The legacy bundle location is the image's. Reserving it would refuse
    /// every Debian-derived workload image.
    #[test]
    fn the_legacy_ca_bundle_is_image_owned() {
        assert_eq!(reserved_by(LEGACY_CA_BUNDLE), None);
    }

    #[test]
    fn layer_paths_and_absolute_paths_resolve_alike() {
        for p in [
            "etc/nucleus/pod.yaml",
            "./etc/nucleus/pod.yaml",
            "/etc/nucleus/pod.yaml",
        ] {
            assert_eq!(reserved_by(p).map(|r| r.path), Some(ETC_NUCLEUS), "{p}");
        }
        assert_eq!(reserved_by("init").map(|r| r.path), Some(INIT));
        assert_eq!(
            reserved_by("usr/local/bin/nucleus-anything").map(|r| r.path),
            Some(NUCLEUS_BIN_PREFIX)
        );
    }

    /// A prefix directory is claimed itself, so it cannot become a symlink.
    #[test]
    fn a_prefix_directory_is_claimed_itself() {
        assert!(reserved_by("etc/nucleus").is_some());
        assert!(reserved_by("etc/nucleus/").is_some());
    }

    /// A must-be-empty directory may exist; only its contents are claimed.
    #[test]
    fn a_must_be_empty_dir_may_exist_but_not_hold_anything() {
        assert_eq!(reserved_by("work"), None);
        assert_eq!(reserved_by("work/"), None);
        assert!(reserved_by("work/.home/.profile").is_some());
        assert!(reserved_by("dev/mem").is_some());
    }

    /// Near misses are not claimed: the table is not a substring match.
    #[test]
    fn near_misses_are_image_owned() {
        for p in [
            "usr/local/bin/tool-proxy",
            "etc/nucleus-extra/x",
            "initrd.img",
            "workspace/file",
            "usr/local/bin/guest-net.sh",
        ] {
            assert_eq!(reserved_by(p), None, "{p}");
        }
    }

    #[test]
    fn the_ca_bundle_prefers_the_guest_layer_then_the_2x_location() {
        assert_eq!(CaBundle::resolve(|_| true), CaBundle::GuestLayer);
        assert_eq!(
            CaBundle::resolve(|p| p == LEGACY_CA_BUNDLE),
            CaBundle::LegacyRootfs
        );
        assert_eq!(CaBundle::resolve(|_| false), CaBundle::Absent);
        assert_eq!(CaBundle::Absent.path(), None);
        assert_eq!(CaBundle::GuestLayer.path(), Some(CA_BUNDLE));
    }

    /// #2696 P3c: every file that holds a runtime secret or the pod's spec is
    /// hidden from the workload by the table, and the workload's scratch is
    /// writable. Asked of the paths, not of the entries, so moving a secret
    /// under a readable prefix reds here.
    #[test]
    fn runtime_secrets_are_hidden_from_the_workload_and_its_scratch_is_writable() {
        let hidden = |p: &str| {
            // The entry that roots the path, or the nearest ancestor that does.
            let mut at = p.to_string();
            loop {
                if let Some(r) = reserved_at(&at) {
                    return r.workload == WorkloadFs::Hidden;
                }
                match at.rsplit_once('/') {
                    Some(("", _)) | None => return false,
                    Some((parent, _)) => at = parent.to_string(),
                }
            }
        };
        for p in [
            POD_SPEC_PATH,
            FALLBACK_POD_SPEC,
            NET_ALLOW,
            NET_DENY,
            AUTH_SECRET,
            APPROVAL_SECRET,
            SANDBOX_TOKEN,
            AUDIT_PATH_FILE,
            "/run/nucleus/identity/svid.pem",
        ] {
            assert!(hidden(p), "{p} must be hidden from the workload");
        }
        for p in [WORK_DIR, "/tmp", "/cache"] {
            assert_eq!(
                reserved_at(p).map(|r| r.workload),
                Some(WorkloadFs::ReadWrite),
                "{p}"
            );
        }
        // The binaries the workload itself runs (the MCP bridge, the egress
        // adapter) stay readable and executable.
        assert_eq!(
            reserved_at(MCP_BIN).map(|r| r.workload),
            Some(WorkloadFs::Read)
        );
    }

    /// Descent is needed exactly where a hole must be cut: `/` (for `/run`,
    /// `/etc/nucleus`, `/pod.yaml`) and `/etc`, but not `/usr`, whose only
    /// reserved entry (the guest binaries) is readable anyway.
    #[test]
    fn the_ruleset_descends_only_where_a_hole_is_cut() {
        assert!(workload_must_descend("/"));
        assert!(workload_must_descend("/etc"));
        assert!(!workload_must_descend("/etc/nucleus"));
        assert!(!workload_must_descend("/usr"));
        assert!(!workload_must_descend("/usr/local/bin"));
        assert!(!workload_must_descend("/home"));
    }

    /// The guest renders and the node parses with one type: every verdict
    /// survives the round trip, behind a kernel log prefix too.
    #[test]
    fn the_landlock_verdict_round_trips_through_the_console() {
        for v in [
            WorkloadLandlockVerdict::Enforced { abi: 2 },
            WorkloadLandlockVerdict::Waived {
                kernel:
                    "no Landlock (landlock_create_ruleset: Function not implemented (os error 38))"
                        .to_string(),
            },
            WorkloadLandlockVerdict::Refused {
                kernel: "Landlock ABI 1".to_string(),
            },
            WorkloadLandlockVerdict::NotApplied,
        ] {
            let console = format!("[    1.2] Run /init\n[proxy] {}\nother\n", v.line());
            assert_eq!(WorkloadLandlockVerdict::parse(&console), Some(v));
        }
        assert_eq!(WorkloadLandlockVerdict::parse("no verdict here"), None);
        assert_eq!(
            WorkloadLandlockVerdict::parse("NUCLEUS_WORKLOAD_LANDLOCK: enforced abi=two"),
            None
        );
    }

    #[test]
    fn reserved_at_roots_directories_at_their_own_path() {
        assert_eq!(reserved_at("/work").map(|r| r.path), Some("/work/"));
        assert_eq!(
            reserved_at("/etc/nucleus").map(|r| r.path),
            Some(ETC_NUCLEUS)
        );
        assert_eq!(reserved_at("/init").map(|r| r.path), Some(INIT));
        assert_eq!(
            reserved_at("/usr/local/bin/nucleus-mcp").map(|r| r.path),
            Some(NUCLEUS_BIN_PREFIX)
        );
        assert_eq!(reserved_at("/work/x"), None);
        assert_eq!(reserved_at("/etc"), None);
        assert_eq!(reserved_at("/initrd.img"), None);
    }

    #[test]
    fn the_workload_home_is_inside_the_scratch() {
        let home = std::path::Path::new(WORK_DIR).join(WORKLOAD_HOME_NAME);
        assert_eq!(home, std::path::Path::new("/work/.home"));
        assert!(reserved_by(home.to_str().unwrap_or_default()).is_some());
    }
}
