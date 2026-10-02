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
}

/// The guest's PID 1.
pub const INIT: &str = "/init";

/// The guest layer's configuration directory, as a prefix.
pub const ETC_NUCLEUS: &str = etc_nucleus!("");

/// The guest layer's binaries, as a name prefix.
pub const NUCLEUS_BIN_PREFIX: &str = nucleus_bin!("");

/// The baked pod spec. Wins over the one fetched from the host when present.
pub const POD_SPEC_PATH: &str = etc_nucleus!("pod.yaml");

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
}

/// `(guest path, cargo package)` for a binary installed under
/// [`NUCLEUS_BIN_PREFIX`]: both halves from one name, so they cannot disagree.
macro_rules! guest_bin {
    ($name:literal) => {
        (nucleus_bin!($name), concat!("nucleus-", $name))
    };
}

impl GuestBinary {
    /// Every binary the guest layer ships.
    pub const ALL: [Self; 7] = [
        Self::Init,
        Self::ToolProxy,
        Self::EgressProbe,
        Self::NetProbe,
        Self::WorkloadProbe,
        Self::PodlistProbe,
        Self::AdversaryProbe,
    ];

    /// `(guest path, cargo package)`. Each package's binary target carries the
    /// package's own name.
    const fn parts(self) -> (&'static str, &'static str) {
        match self {
            Self::Init => (INIT, "nucleus-guest-init"),
            Self::ToolProxy => guest_bin!("tool-proxy"),
            Self::EgressProbe => guest_bin!("egress-probe"),
            Self::NetProbe => guest_bin!("net-probe"),
            Self::WorkloadProbe => guest_bin!("workload-probe"),
            Self::PodlistProbe => guest_bin!("podlist-probe"),
            Self::AdversaryProbe => guest_bin!("adversary-probe"),
        }
    }

    /// Absolute path inside the guest.
    #[must_use]
    pub const fn path(self) -> &'static str {
        self.parts().0
    }

    /// The cargo package (and binary target) that builds it.
    #[must_use]
    pub const fn package(self) -> &'static str {
        self.parts().1
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
    },
    Reserved {
        path: ETC_NUCLEUS,
        kind: ReservedKind::Prefix,
        why: "the baked pod spec, egress policy and CA bundle the runtime trusts",
    },
    Reserved {
        path: NUCLEUS_BIN_PREFIX,
        kind: ReservedKind::Prefix,
        why: "the mediating runtime and its probes",
    },
    Reserved {
        path: FALLBACK_POD_SPEC,
        kind: ReservedKind::Exact,
        why: "outranks the host-fetched pod spec, so it would choose the pod's command",
    },
    Reserved {
        path: "/run/",
        kind: ReservedKind::MustBeEmptyDir,
        why: "tmpfs mounted at boot; holds the fetched spec and identity",
    },
    Reserved {
        path: "/tmp/",
        kind: ReservedKind::MustBeEmptyDir,
        why: "tmpfs mounted at boot",
    },
    Reserved {
        path: "/work/",
        kind: ReservedKind::MustBeEmptyDir,
        why: "the pod scratch is mounted here; without a scratch drive the image's contents would show through",
    },
    Reserved {
        path: "/cache/",
        kind: ReservedKind::MustBeEmptyDir,
        why: "the pinned compiler cache is mounted here; stale image contents would poison it",
    },
    Reserved {
        path: "/cache-seed/",
        kind: ReservedKind::MustBeEmptyDir,
        why: "the pinned cache seed is mounted here",
    },
    Reserved {
        path: "/proc/",
        kind: ReservedKind::MustBeEmptyDir,
        why: "procfs is mounted at boot",
    },
    Reserved {
        path: "/sys/",
        kind: ReservedKind::MustBeEmptyDir,
        why: "sysfs is mounted at boot",
    },
    Reserved {
        path: "/dev/",
        kind: ReservedKind::MustBeEmptyDir,
        why: "devtmpfs is mounted at boot; an image-supplied device node is a privilege primitive",
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
    /// binary prefix with its package's name.
    #[test]
    fn guest_binaries_are_reserved_and_named_by_their_package() {
        for b in GuestBinary::ALL {
            assert!(reserved_by(b.path()).is_some(), "{b:?} not reserved");
            if b != GuestBinary::Init {
                assert_eq!(
                    b.path().strip_prefix("/usr/local/bin/"),
                    Some(b.package()),
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

    #[test]
    fn the_workload_home_is_inside_the_scratch() {
        let home = std::path::Path::new(WORK_DIR).join(WORKLOAD_HOME_NAME);
        assert_eq!(home, std::path::Path::new("/work/.home"));
        assert!(reserved_by(home.to_str().unwrap_or_default()).is_some());
    }
}
