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

/// The guest kernel for aarch64 hosts: Firecracker CI `6.1.186`, built with
/// Landlock (`CONFIG_SECURITY_LANDLOCK=y`, `landlock` first in `CONFIG_LSM`).
///
/// # Why this build (#2696 P3, S4)
///
/// The previous pin, `firecracker-ci/v1.13/<arch>/vmlinux-6.1.141`, had
/// Landlock compiled out: booted, `landlock_create_ruleset` answered `ENOSYS`
/// (`docs/findings/p3-workload-confinement-spike.md`). So did every versioned
/// prefix after it (`v1.14`, `v1.15`). Upstream turned Landlock on in its 6.1
/// guest config on 2026-09-01, and those configs ship only under the bucket's
/// DATED prefixes, `firecracker-ci/YYYYMMDD-<sha>-0/`. This is the newest one
/// on the 6.1 line, the same line as the old pin with a near-superset config:
/// the x_tables options `fence.rs` speaks, vsock, virtio, ext4 and seccomp
/// are all still `y`. Booted, it reports Landlock ABI 2.
///
/// Bucket layout is not a version ladder, so "use the newest path" is not a
/// rule that holds here; list it with `?list-type=2&prefix=firecracker-ci/`
/// and read the `.config` beside the image before changing this.
///
/// # Why the upstream URL and not a nucleus mirror
///
/// A dated prefix is CI output, and nothing promises it stays. So every
/// release from this one on also publishes these exact bytes as a signed
/// asset (`cargo xtask guest-kernel-mirror`, [`Kernel::mirror_asset_name`]).
/// The pin cannot NAME that asset yet: it exists only once a tag has built
/// it, and this pin has to work before then. The digest, not the URL, is the
/// binding, so moving `url` to the mirror after the next release changes
/// where the bytes come from and not which bytes are accepted.
pub const KERNEL_AARCH64: Kernel = Kernel {
    url: "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260930-0dd90d4c672d-0/aarch64/vmlinux-6.1.186",
    sha256: "5699d939bd168c1fcc4aa8c217344f00b8cf2b7dffbf973af3d9440ce766a6bd",
};

/// The guest kernel for x86_64 hosts. Same dated prefix and kernel version as
/// [`KERNEL_AARCH64`], with the same Landlock configuration.
pub const KERNEL_X86_64: Kernel = Kernel {
    url: "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260930-0dd90d4c672d-0/x86_64/vmlinux-6.1.186",
    sha256: "21c1b167482f3c10428b8fd5e08bbeea14258ce74479730712dc11a4f34d2029",
};

impl Kernel {
    /// The name of the release asset that mirrors this kernel's bytes for
    /// release `version` on `arch` (`uname -m` spelling). One function, used by
    /// the release workflow that publishes it and by whatever later fetches
    /// it (ADR 0007 G-1).
    pub fn mirror_asset_name(version: &str, arch: &str) -> String {
        format!("nucleus-guest-kernel-{version}-{arch}.vmlinux")
    }
}

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
    /// guest-init fetches the pod's DLC-D admission provisioning over the
    /// workload API (`FETCH_DLC_ADMISSION`) and hands it to the tool-proxy as
    /// `NUCLEUS_DLC_*`, and the proxy reports `dlc_admission` in its health
    /// (#2124). `verify --tier2` provisions its pod this way and checks that
    /// field; a guest without it answers health with no `dlc_admission` at all,
    /// which is what #2903 reported as `dlc_admission=None`. Verified present in
    /// `nucleus-rootfs-2.2.0-aarch64.ext4` (`/init` sends `FETCH_DLC_ADMISSION`,
    /// the proxy carries the health field); absent from v2.1.0's source.
    DlcAdmission,
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
    /// The tool-proxy puts every decision its kernel takes to the host's shadow
    /// decision service as well, on `nucleus_decision_protocol::DECISION_VSOCK_PORT`
    /// (#2702, P8). [`Demand::Optional`]: the guest still enforces its own
    /// decisions, so a guest without the client loses only the host's
    /// measurement — the node serves the port and simply hears nothing. P9,
    /// which makes the host's verdict the enforced one, turns this into
    /// [`Demand::Required`].
    HostDecideShadow,
    /// The tool-proxy relays a workload's credentialed egress to the host as a
    /// STREAM: the body goes up in bounded chunks, each charged to the pod's
    /// egress ceiling, and the reply comes back as the upstream sends it
    /// (#2696 P4). An older proxy sends the whole call in one perform frame,
    /// which the host refuses above 256 KiB and which cannot carry a streamed
    /// (server-sent-event) reply, so a model call from the pod fails or stalls.
    StreamingEgress,
    /// The guest's egress adapter (`nucleus-egress-http`) takes `--upstream`
    /// repeatedly, plus `--export VAR=NAME` and `--placeholder VAR`, and gives
    /// each declared upstream its own loopback origin (#3211).
    /// `nucleus run --agent … --egress` starts the agent under the adapter with
    /// exactly those flags (#3212). An older adapter accepts one `--upstream`
    /// and neither of the others, so the agent never starts.
    /// [`Demand::When`]`(`[`GuestUse::AgentEgress`]`)`: only a run that
    /// declares an upstream depends on it.
    EgressAdapterUpstreams,
    /// The tool-proxy's stream open names the call's method (GET or POST), may
    /// carry a query and proposes protocol headers (#3210). The node requires
    /// the method: an older proxy's open has none, so the node refuses it as
    /// malformed and every credentialed call from the pod (a model call
    /// included) fails. A breaking change by the owner's decision, with no
    /// compatibility arm: a 2.3.x guest cannot serve this node.
    EgressMethodAndQuery,
    /// The tool-proxy reads an upstream's operator-declared effect table from
    /// the pod spec and labels a call by it (#3229): a forge's pull-request
    /// route as `CreatePr`, an unclassified forge write refused. An older
    /// proxy's spec type refuses the unknown `effects` field, and even past
    /// that would label the call `WebFetch`, which the host refuses as
    /// mislabelled. Fails closed either way. Required only by a run that
    /// declares an upstream whose registry entry carries an effect table
    /// ([`GuestUse::EffectTableEgress`]); ordinary egress does not need it.
    EgressEffectTable,
    /// The tool-proxy decides a credentialed push (and pull request) with the
    /// effect decider, so a push from a session its own flow graph has tainted
    /// is submitted to the host to be held for the operator's action-bound
    /// approval instead of being refused in the guest (#3255).
    /// [`Demand::Optional`]: the host holds and declassifies regardless, and a
    /// push after only model calls (taint the host observed, not the guest)
    /// completes with an older guest; that guest still refuses, in the guest,
    /// a push after content its own tools read, which is stricter, never wider.
    TaintedPushHeld,
    /// The tool-proxy labels a push's ref advertisement
    /// (`GET …/info/refs?service=git-receive-pack`, no body) a `WebFetch`,
    /// as the shared classifier now decides it, so only the pack's POST is
    /// held for the operator and one approval completes a `git push` (#3266).
    /// [`Demand::Optional`]: the node accepts a stricter label and decides
    /// it, so an older guest's advertisement labelled `GitPush` is still held
    /// for its own approval, as before. Stricter, never wider.
    PushAdvertisementIsRead,
}

/// A use of the guest that depends on capabilities the node does not need for
/// every pod. A capability whose demand is [`Demand::When`] is checked only
/// for a caller that names the use (see [`guest_skew_for`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestUse {
    /// `nucleus run --agent … --egress`: the agent in the pod is started under
    /// the guest's egress adapter with the upstreams the run declares.
    AgentEgress,
    /// `--egress` naming an upstream whose registry entry declares an effect
    /// table (`kind`/`effects`, #3229): the guest must read the table from the
    /// pod spec and label calls by it.
    EffectTableEgress,
}

/// Whether the node refuses a guest that lacks a [`GuestCapability`].
///
/// Two answers, as a type rather than a `bool`, because "the node cannot work
/// without it" and "the node works without it and learns less" have different
/// consequences for an operator holding an older guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Demand {
    /// The node's behaviour depends on it; a guest without it is refused.
    Required,
    /// The node uses it when present and runs without it. Never refuses a guest.
    Optional,
    /// Required for this use only. Every other caller treats it as
    /// [`Demand::Optional`], so a guest without it still serves every pod that
    /// does not make this use.
    When(GuestUse),
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
    pub const ALL: [GuestCapability; 14] = [
        GuestCapability::CaBundle,
        GuestCapability::ApprovalByPublicKey,
        GuestCapability::DlcAdmission,
        GuestCapability::EgressAttestation,
        GuestCapability::SvidOnTmpfs,
        GuestCapability::WorkloadDoor,
        GuestCapability::McpBridge,
        GuestCapability::HostDecideShadow,
        GuestCapability::StreamingEgress,
        GuestCapability::EgressAdapterUpstreams,
        GuestCapability::EgressMethodAndQuery,
        GuestCapability::EgressEffectTable,
        GuestCapability::TaintedPushHeld,
        GuestCapability::PushAdvertisementIsRead,
    ];

    /// Whether a guest without it is refused. Exhaustive, so a new capability
    /// states its demand when it is added.
    pub const fn demand(self) -> Demand {
        match self {
            GuestCapability::CaBundle
            | GuestCapability::ApprovalByPublicKey
            | GuestCapability::DlcAdmission
            | GuestCapability::EgressAttestation
            | GuestCapability::SvidOnTmpfs
            | GuestCapability::WorkloadDoor
            | GuestCapability::McpBridge
            | GuestCapability::StreamingEgress
            | GuestCapability::EgressMethodAndQuery => Demand::Required,
            // Shadow mode: nothing the node does depends on the guest asking.
            GuestCapability::HostDecideShadow => Demand::Optional,
            // The host holds the push either way; an older guest only refuses
            // more (a push after its own tainting read), never less.
            GuestCapability::TaintedPushHeld => Demand::Optional,
            // The node decides a stricter label too: an older guest only asks
            // for one more approval (the advertisement's), never for less.
            GuestCapability::PushAdvertisementIsRead => Demand::Optional,
            // Only the run that starts its agent under the adapter needs it.
            GuestCapability::EgressAdapterUpstreams => Demand::When(GuestUse::AgentEgress),
            // Only a pod holding an upstream WITH an effect table reads one.
            GuestCapability::EgressEffectTable => Demand::When(GuestUse::EffectTableEgress),
        }
    }

    /// The first release whose rootfs has this.
    pub const fn first_shipped(self) -> FirstShipped {
        match self {
            GuestCapability::CaBundle => FirstShipped::Release("2.1.0"),
            GuestCapability::ApprovalByPublicKey => FirstShipped::Release("2.2.0"),
            GuestCapability::DlcAdmission => FirstShipped::Release("2.2.0"),
            // #2365 and #2379 merged on 2026-09-02, after `v2.2.0` (8a452030b)
            // was tagged; #3122 (the door) and #3135 (the bridge) on
            // 2026-10-02. 2.3.0 is the first release cut from a tree carrying
            // all four; #3178 added streaming egress before the tag as well.
            GuestCapability::EgressAttestation => FirstShipped::Release("2.3.0"),
            GuestCapability::SvidOnTmpfs => FirstShipped::Release("2.3.0"),
            GuestCapability::WorkloadDoor => FirstShipped::Release("2.3.0"),
            GuestCapability::McpBridge => FirstShipped::Release("2.3.0"),
            GuestCapability::StreamingEgress => FirstShipped::Release("2.3.0"),
            // #3177 (P8) merged on 2026-10-04, before `v2.3.0` (450e47854) was
            // tagged: the published `nucleus-rootfs-2.3.0-aarch64.ext4` carries
            // the tool-proxy's shadow client (its "host-decide shadow" log
            // string is in the image).
            GuestCapability::HostDecideShadow => FirstShipped::Release("2.3.0"),
            // #3211 (75e2f18c2) and #3226 (0d3a72fa0, the protocol half of
            // #3210) are ancestors of `v2.4.0` (f3e700763) and not of `v2.3.0`
            // (the 2.3.0 adapter takes one `--upstream`, and its tool-proxy's
            // stream open names no method).
            GuestCapability::EgressAdapterUpstreams => FirstShipped::Release("2.4.0"),
            GuestCapability::EgressMethodAndQuery => FirstShipped::Release("2.4.0"),
            // #3246 (936e24606, #3229's effect table) and #3257 (587c3524f,
            // #3255's held push) are ancestors of `v2.5.0` (0f2471d52) and not
            // of `v2.4.0` (f3e700763): the published 2.4.0 tool-proxy reads no
            // effect table and refuses a tainted push in the guest.
            GuestCapability::EgressEffectTable => FirstShipped::Release("2.5.0"),
            GuestCapability::TaintedPushHeld => FirstShipped::Release("2.5.0"),
            // #3266 landed after `v2.5.0` (0f2471d52): the published 2.5.0
            // tool-proxy labels the advertisement `GitPush`.
            GuestCapability::PushAdvertisementIsRead => FirstShipped::NotYet,
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
            GuestCapability::DlcAdmission => {
                "#2124 delivers a pod's DLC-D admission provisioning to the guest over the \
                 workload API (FETCH_DLC_ADMISSION) and has the tool-proxy report \
                 `dlc_admission` in its health; an older guest never fetches it, so the \
                 admission gate stays unarmed whatever the pod's dlc_* labels say"
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
            GuestCapability::HostDecideShadow => {
                "#2702 (P8) has the tool-proxy shadow every decision to the host's decision \
                 service; an older guest never asks, so the host records no comparisons for it \
                 (shadow mode: the node does not require it)"
            }
            GuestCapability::StreamingEgress => {
                "#2696 (P4) made the tool-proxy stream a workload's credentialed egress to the \
                 host in bounded, metered chunks; an older proxy sends the whole call in one \
                 perform frame, which the host refuses above 256 KiB and which cannot carry a \
                 streamed reply"
            }
            GuestCapability::EgressAdapterUpstreams => {
                "#3211 lets the guest's egress adapter (nucleus-egress-http) serve several \
                 upstreams and take --export and --placeholder, which `nucleus run --egress` \
                 starts the agent with; an older adapter refuses those flags, so the agent \
                 never starts"
            }
            GuestCapability::EgressMethodAndQuery => {
                "#3210 made the tool-proxy's stream open name its method (GET or POST) and \
                 carry a query and protocol headers, and the node requires the method; an \
                 older proxy's open has none, so the node refuses every credentialed call \
                 from the pod as malformed"
            }
            GuestCapability::EgressEffectTable => {
                "#3229 put the operator's effect table for an upstream in the pod spec, and \
                 the tool-proxy labels a forge write by it; an older proxy cannot read a spec \
                 that carries one, and would label a pull request as a fetch, which the node \
                 refuses"
            }
            GuestCapability::TaintedPushHeld => {
                "#3255 has the tool-proxy submit a push from a session it saw untrusted content \
                 in for the host to hold for the operator's approval of that push; an older \
                 proxy refuses that push in the guest (the node does not require it: the host \
                 holds a push after model calls with either guest)"
            }
            GuestCapability::PushAdvertisementIsRead => {
                "#3266 decides a push's bodiless ref advertisement as a read, so one operator \
                 approval of the pack completes a git push; an older proxy labels the \
                 advertisement a push, which the node decides as asked, so that push needs a \
                 second approval (the node does not require it)"
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

/// Whether the guest artifacts of `version` meet every [`GuestCapability`] the
/// node [requires](Demand::Required). An [optional](Demand::Optional) one is
/// never a reason to refuse a guest, and neither is one demanded only
/// [`When`](Demand::When) a use this caller does not make.
pub fn guest_skew(version: &str) -> Result<(), GuestSkew> {
    guest_skew_for(version, &[])
}

/// [`guest_skew`] for a caller that makes `uses` of the guest: a capability
/// demanded [`When`](Demand::When) one of them is required as well. The same
/// decider, so a refusal for a use names its cause the way every other skew
/// refusal does.
pub fn guest_skew_for(version: &str, uses: &[GuestUse]) -> Result<(), GuestSkew> {
    skew_against(version, uses, GuestCapability::first_shipped)
}

/// [`guest_skew_for`] with the table as a parameter, so the ordering rules can
/// be tested on releases the real table does not (yet) contain.
fn skew_against(
    version: &str,
    uses: &[GuestUse],
    first_shipped: impl Fn(GuestCapability) -> FirstShipped,
) -> Result<(), GuestSkew> {
    let Some(found) = parse_release(version) else {
        return Err(GuestSkew::Unorderable {
            release: version.to_string(),
        });
    };
    let mut missing = Vec::new();
    for cap in GuestCapability::ALL {
        match cap.demand() {
            Demand::Required => {}
            Demand::When(used) if uses.contains(&used) => {}
            Demand::Optional | Demand::When(_) => continue,
        }
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
/// `2.5.0` is the first release whose tool-proxy reads an upstream's effect
/// table from the pod spec (#3229) and submits a tainted push to the host to
/// be held for approval (#3255). Neither is required of every pod, so the
/// node still serves a 2.4.0 guest; only a run declaring an upstream with an
/// effect table refuses one. `2.4.0` is the first release whose tool-proxy names the method of each
/// stream open and may carry a query and protocol headers (#3210), which this
/// node requires: a breaking change, owner-approved, with no compatibility arm
/// for 2.3.x opens. `2.3.0` was the first release whose rootfs runs the egress
/// probe (#2365), keeps its SVID on tmpfs (#2379), serves the workload its own
/// door (#3122), carries the MCP bridge (#3135), and streams credentialed
/// egress (#3178); it also carries the optional shadow decision client
/// (#3177). 2.2.0
/// was the first release matching a post-#2214 node, and it stopped serving
/// `main` the day after it was tagged. 2.1.0 was the first release containing
/// everything a pod needed to boot at the time
/// — the CA bundle in the rootfs (#2110), the `ip netns exec` separator fix
/// without which no pod launches on a default install, and the workload-API
/// socket chown without which the guest cannot fetch its SVID — and it stayed
/// pinned for five weeks after the node moved past it.
///
/// Bumped BEFORE the tag is cut, matching how `2.1.0` was bumped from its RC in
/// the change that was released as `2.1.0`. The ordering is deliberate and it
/// has a cost worth naming: between this landing and the tag's assets being
/// built, `setup` points at a release that does not exist yet. That window is
/// inherent to pinning your own next version, and the alternative — tag first,
/// bump after — ships a release whose CLI pins the *previous* release's guest,
/// which is precisely the skew being closed.
///
/// The change that bumps this constant must also turn every
/// [`FirstShipped::NotYet`] entry whose behaviour is in the tagged tree into
/// [`FirstShipped::Release`]: `the_pinned_release_serves_this_tree` fails until
/// it does, and `no_capability_claims_a_release_after_the_pin` stops an entry
/// naming a release the pin has not reached.
///
/// `parse_release` explains why an RC compares equal to its own version.
pub const GUEST_RELEASE: &str = "2.5.0";

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

    /// Each pin fetches its own architecture's image, and both are the same
    /// kernel build: a re-pin that moves one architecture and forgets the other
    /// would boot two different kernels (one without Landlock) under one tree.
    #[test]
    fn both_kernels_are_the_same_build_for_their_own_architecture() {
        for (arch, k) in [("aarch64", KERNEL_AARCH64), ("x86_64", KERNEL_X86_64)] {
            assert!(k.url.contains(&format!("/{arch}/")), "{arch}: {}", k.url);
        }
        let build = |k: Kernel| {
            let (prefix, file) = k.url.rsplit_once('/').expect("a path");
            let (prefix, _arch) = prefix.rsplit_once('/').expect("an arch segment");
            (prefix.to_string(), file.to_string())
        };
        assert_eq!(build(KERNEL_AARCH64), build(KERNEL_X86_64));
        assert_ne!(
            Kernel::mirror_asset_name("2.6.0", "aarch64"),
            Kernel::mirror_asset_name("2.6.0", "x86_64")
        );
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

    /// The pin must serve the tree that pins it. From 2.2.0's tag until 2.3.0 it
    /// did not, and `setup --artifacts release` refused the pinned guest.
    ///
    /// Every USE as well, not just the uses every pod makes: a
    /// [`Demand::When`] row left at [`FirstShipped::NotYet`] when the pin moves
    /// to the release that ships it would refuse that use on a guest that
    /// serves it. `GuestUse` has two variants, so the list is exhaustive.
    #[test]
    fn the_pinned_release_serves_this_tree() {
        let every_use = [GuestUse::AgentEgress, GuestUse::EffectTableEgress];
        assert_eq!(guest_skew(GUEST_RELEASE), Ok(()));
        assert_eq!(guest_skew_for(GUEST_RELEASE, &every_use), Ok(()));
        // No row is left unreleased once the pin moves: every capability this
        // tree's node and CLI know of is in the pinned release, except the
        // ones that landed after it, named here. The change that moves the
        // pin empties this list, and the assertion fails until it does.
        let after_the_pin = [GuestCapability::PushAdvertisementIsRead];
        for cap in GuestCapability::ALL {
            assert_eq!(
                cap.first_shipped() == FirstShipped::NotYet,
                after_the_pin.contains(&cap),
                "{cap:?}"
            );
        }
        for cap in after_the_pin {
            assert_eq!(cap.demand(), Demand::Optional, "{cap:?}");
        }
        // The release before the pin (2.4.0) serves every pod and every
        // adapter run, and is refused only for an upstream with an effect
        // table (#3229), by name: no 2.5.0 row is Required, so the floor
        // stays at 2.4.0.
        assert_eq!(guest_skew("2.4.0"), Ok(()));
        assert_eq!(guest_skew_for("2.4.0", &[GuestUse::AgentEgress]), Ok(()));
        assert_eq!(
            guest_skew_for("2.4.0", &every_use),
            Err(GuestSkew::Lacks {
                release: "2.4.0".to_string(),
                missing: vec![GuestCapability::EgressEffectTable],
            })
        );
    }

    /// THE FINDING, as a refusal. A node built from this tree cannot boot the
    /// 2.2.0 guest: it never prints `NUCLEUS_EGRESS_PROBE:`, and read-only it
    /// dies creating `/etc/nucleus/identity`. Before this table the floor said
    /// 2.2.0 was fine, `setup` installed it, and the failure surfaced mid-boot.
    #[test]
    fn the_previous_release_is_refused_and_the_refusal_names_why() {
        let skew = guest_skew("2.2.0")
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
                GuestCapability::StreamingEgress,
                GuestCapability::EgressMethodAndQuery,
            ]
        );
        // The release before the pin now, refused for exactly the open format
        // #3210 changed, and told so by name.
        let previous = guest_skew("2.3.0").expect_err("2.3.0 writes opens without a method");
        assert_eq!(
            previous,
            GuestSkew::Lacks {
                release: "2.3.0".to_string(),
                missing: vec![GuestCapability::EgressMethodAndQuery],
            }
        );
        assert!(previous.to_string().contains("#3210"), "{previous}");
        assert!(
            previous.to_string().contains("first released in v2.4.0"),
            "{previous}"
        );
        let msg = skew.to_string();
        for needle in [
            "v2.2.0",
            "#2365",
            "#2379",
            "#3031",
            "#2696",
            "first released in v2.3.0",
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
                GuestCapability::ApprovalByPublicKey => GuestCapability::DlcAdmission,
                GuestCapability::DlcAdmission => GuestCapability::EgressAttestation,
                GuestCapability::EgressAttestation => GuestCapability::SvidOnTmpfs,
                GuestCapability::SvidOnTmpfs => GuestCapability::WorkloadDoor,
                GuestCapability::WorkloadDoor => GuestCapability::McpBridge,
                GuestCapability::McpBridge => GuestCapability::StreamingEgress,
                GuestCapability::StreamingEgress => GuestCapability::HostDecideShadow,
                GuestCapability::HostDecideShadow => GuestCapability::EgressAdapterUpstreams,
                GuestCapability::EgressAdapterUpstreams => GuestCapability::EgressMethodAndQuery,
                GuestCapability::EgressMethodAndQuery => GuestCapability::EgressEffectTable,
                GuestCapability::EgressEffectTable => GuestCapability::TaintedPushHeld,
                GuestCapability::TaintedPushHeld => GuestCapability::PushAdvertisementIsRead,
                GuestCapability::PushAdvertisementIsRead => GuestCapability::CaBundle,
            };
            assert!(GuestCapability::ALL.contains(&next), "{next:?} missing");
        }
    }

    /// 2.0.2 and everything before it ship a rootfs with no CA store, on which
    /// the tool-proxy panics as PID 1; 2.1.0 predates #2214; 2.2.0 predates
    /// #2365, #2379, #3031 and #2696 P2. If any starts passing, an entry has
    /// been moved back past its fix.
    #[test]
    fn the_known_broken_releases_are_refused() {
        for (broken, lacks) in [
            ("2.0.2", GuestCapability::CaBundle),
            ("2.0.0", GuestCapability::CaBundle),
            ("1.0.9", GuestCapability::CaBundle),
            ("2.1.0", GuestCapability::ApprovalByPublicKey),
            ("2.1.0", GuestCapability::DlcAdmission),
            ("2.2.0", GuestCapability::EgressAttestation),
            ("2.2.0", GuestCapability::SvidOnTmpfs),
            ("2.2.0", GuestCapability::WorkloadDoor),
            ("2.2.0", GuestCapability::McpBridge),
            ("2.2.0", GuestCapability::StreamingEgress),
            ("2.3.0", GuestCapability::EgressMethodAndQuery),
        ] {
            match guest_skew(broken) {
                Err(GuestSkew::Lacks { missing, .. }) => {
                    assert!(missing.contains(&lacks), "{broken}: {missing:?}")
                }
                other => panic!("{broken} must be refused for {lacks:?}: {other:?}"),
            }
        }
    }

    /// The node does not require the shadow client (P8 is not enforcing), so a
    /// release that has every REQUIRED capability is accepted without it — and
    /// the same release missing one required capability is still refused.
    #[test]
    fn an_optional_capability_never_refuses_a_guest() {
        let all_but_shadow = |c: GuestCapability| match c.demand() {
            Demand::Required => FirstShipped::Release("2.2.0"),
            Demand::Optional | Demand::When(_) => FirstShipped::NotYet,
        };
        assert_eq!(GuestCapability::HostDecideShadow.demand(), Demand::Optional);
        assert_eq!(skew_against("2.2.0", &[], all_but_shadow), Ok(()));
        let all_but_door = |c: GuestCapability| match c {
            GuestCapability::WorkloadDoor => FirstShipped::NotYet,
            _ => FirstShipped::Release("2.2.0"),
        };
        assert_eq!(
            skew_against("2.2.0", &[], all_but_door),
            Err(GuestSkew::Lacks {
                release: "2.2.0".to_string(),
                missing: vec![GuestCapability::WorkloadDoor],
            })
        );
        // And the refusal of the pinned release never names it.
        if let Err(GuestSkew::Lacks { missing, .. }) = guest_skew(GUEST_RELEASE) {
            assert!(!missing.contains(&GuestCapability::HostDecideShadow));
        }
    }

    /// A capability demanded `When` a use is required by the caller that makes
    /// the use and by no other. 2.3.0's adapter takes one `--upstream` (#3211
    /// is not in it): a run that starts its agent under the adapter (#3212) is
    /// refused for it by name, while a plain pod is refused for #3210 alone.
    /// 2.4.0, the release before the pin, ships both.
    #[test]
    fn a_capability_for_one_use_refuses_only_that_use() {
        assert_eq!(
            GuestCapability::EgressAdapterUpstreams.demand(),
            Demand::When(GuestUse::AgentEgress)
        );
        assert_eq!(
            guest_skew_for(GUEST_RELEASE, &[GuestUse::AgentEgress]),
            Ok(())
        );
        let skew = guest_skew_for("2.3.0", &[GuestUse::AgentEgress])
            .expect_err("the 2.3.0 adapter takes one --upstream and no --export");
        assert_eq!(
            skew,
            GuestSkew::Lacks {
                release: "2.3.0".to_string(),
                missing: vec![
                    GuestCapability::EgressAdapterUpstreams,
                    GuestCapability::EgressMethodAndQuery,
                ],
            }
        );
        let msg = skew.to_string();
        for needle in ["#3211", "first released in v2.4.0", "build-rootfs.sh"] {
            assert!(msg.contains(needle), "missing {needle:?} in: {msg}");
        }
        // The same release, for a caller that makes no such use, never names it.
        let Err(GuestSkew::Lacks { missing, .. }) = guest_skew("2.3.0") else {
            panic!("2.3.0 lacks #3210");
        };
        assert!(!missing.contains(&GuestCapability::EgressAdapterUpstreams));
        // A `When` row still unreleased is refused for its use, and only for it.
        let not_yet = |c: GuestCapability| match c {
            GuestCapability::EgressAdapterUpstreams => FirstShipped::NotYet,
            _ => FirstShipped::Release("2.2.0"),
        };
        assert_eq!(
            skew_against("2.4.0", &[GuestUse::AgentEgress], not_yet),
            Err(GuestSkew::Lacks {
                release: "2.4.0".to_string(),
                missing: vec![GuestCapability::EgressAdapterUpstreams],
            })
        );
        assert_eq!(skew_against("2.4.0", &[], not_yet), Ok(()));
        // Once a release carries it, the use is served by that release.
        let shipped = |c: GuestCapability| match c {
            GuestCapability::EgressAdapterUpstreams => FirstShipped::Release("2.4.0"),
            _ => FirstShipped::Release("2.2.0"),
        };
        assert!(skew_against("2.3.0", &[GuestUse::AgentEgress], shipped).is_err());
        assert_eq!(
            skew_against("2.4.0", &[GuestUse::AgentEgress], shipped),
            Ok(())
        );
        assert_eq!(skew_against("2.3.0", &[], shipped), Ok(()));
    }

    /// A table in which everything shipped by 2.2.0, to test the ordering rules
    /// independently of where the real table's entries sit.
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
            assert_eq!(skew_against(rc, &[], all_by_2_2_0), Ok(()), "{rc}");
        }
    }

    /// The other half, and the one that keeps the above from being a hole: a
    /// prerelease of a BROKEN version is still broken.
    #[test]
    fn a_prerelease_of_a_refused_version_is_still_refused() {
        for rc in ["2.1.0-rc.1", "2.0.2-rc.1", "1.1.0-rc.1", "v2.0.0-beta"] {
            assert!(skew_against(rc, &[], all_by_2_2_0).is_err(), "{rc}");
            assert!(guest_skew(rc).is_err(), "{rc}");
        }
        // 2.3.0 raised the floor past 2.2.0, and 2.4.0 past 2.3.0 (#3210: the
        // node requires the stream open's method): a prerelease of either is
        // refused by the real table, while one of 2.4.0 itself is accepted.
        for rc in [
            "2.2.0-rc.1",
            "v2.2.0-rc.2",
            "2.2.0+build.7",
            "2.3.0",
            "2.3.0-rc.1",
            "v2.3.1",
        ] {
            assert!(guest_skew(rc).is_err(), "{rc}");
        }
        assert_eq!(guest_skew("2.4.0-rc.1"), Ok(()));
    }

    /// "Could not order it" is its own answer, not a refusal for being old.
    #[test]
    fn an_unparseable_release_is_refused_rather_than_ordered_as_zero() {
        for bad in ["", "2.1", "2.1.0.1", "latest", "v2.x.0"] {
            assert_eq!(
                skew_against(bad, &[], all_by_2_2_0),
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
        assert!(skew_against("9.9.9", &[], unparseable).is_err());
    }

    /// A `v` prefix is what a git tag looks like, and it must order the same as
    /// the bare version rather than failing to parse.
    #[test]
    fn a_tag_style_version_parses() {
        assert_eq!(parse_release("v2.2.0"), parse_release("2.2.0"));
        assert_eq!(skew_against("v2.2.0", &[], all_by_2_2_0), Ok(()));
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
