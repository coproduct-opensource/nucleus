//! Admission for the eval-cell isolation profile (ADR 0013).
//!
//! An eval cell runs an agent that is assumed hostile and assumed to hold root
//! inside its guest. Everything the guest enforces is therefore defence in
//! depth; what the cell may rely on is the host's: Firecracker under the jailer,
//! the VMM's own seccomp filter verified active, the netns default-deny fence,
//! and credentials the guest never receives. This module refuses, at create and
//! by name, every pod that asks for the eval-cell profile on a node or with a
//! spec that cannot hold those.
//!
//! The profile only adds requirements. [`admit`] returns before checking
//! anything for a standard pod, so a standard pod is admitted exactly as it was
//! before this module existed.
//!
//! [`admit`] is the one decider for the profile at create, and
//! [`require_confined_children`] the one at boot, where the guest's Landlock
//! verdict first exists.

use nucleus_federation::ClaimedTier;
use nucleus_spec::PodSpec;
use nucleus_spec::isolation_profile::{IsolationProfile, UnknownProfile};
use portcullis::CapabilityLevel;
use uuid::Uuid;

use crate::ApiError;
use crate::broker_rollout::HostSpecEnforcement;
use crate::driver::{DriverKind, isolation_backend};
use crate::federated_credential::PlatformAttestation;

/// What this node is configured to enforce, as far as an eval cell depends on it.
///
/// A snapshot of [`crate::NodeState`] so the decision is a pure function and is
/// tested without a node (`NodePosture::of` is the only production constructor).
pub(crate) struct NodePosture<'a> {
    pub(crate) driver: &'a DriverKind,
    /// `--firecracker-seccomp-verify`: the VMM's seccomp filter is confirmed active.
    pub(crate) seccomp_verify: bool,
    /// `--firecracker-jailer`: the VMM is launched under the jailer.
    pub(crate) jailer: bool,
    /// `--allow-workload-without-landlock`.
    pub(crate) landlock: nucleus::LandlockWaiver,
    /// Enforcing credential delivery (`cred_split`): the guest runs the admitted
    /// spec with every credential value withheld.
    pub(crate) host_spec: HostSpecEnforcement,
    /// The node's platform evidence: asked, at admission, for its appraisal now.
    /// The same decider every federation assertion's tier comes from (ADR 0012
    /// A3), so the node never states one tier to a relying party and admits on
    /// another (ADR 0007 G-1).
    pub(crate) platform: &'a dyn PlatformAttestation,
}

impl<'a> NodePosture<'a> {
    pub(crate) fn of(state: &'a crate::NodeState) -> Self {
        Self {
            driver: &state.driver,
            seccomp_verify: state.firecracker_seccomp_verify,
            jailer: state.firecracker_jailer,
            landlock: state.workload_landlock,
            host_spec: state.broker_enforcing,
            platform: state.node_platform.as_ref(),
        }
    }
}

/// Why an eval-cell pod was refused. Every variant names what to change.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum EvalCellRefused {
    /// The profile label names no profile this build knows.
    #[error(transparent)]
    UnknownProfile(#[from] UnknownProfile),
    /// The node's isolation tier is not Firecracker.
    #[error(
        "the eval-cell profile is refused on the `{tier}` tier: {why}. An eval cell runs only on \
         a Firecracker node (ADR 0013)"
    )]
    Tier {
        /// The backend name (`portcullis::enforcement::BackendCapability::name`).
        tier: &'static str,
        why: &'static str,
    },
    /// The node does not verify the VMM's seccomp filter.
    #[error(
        "the eval-cell profile is refused: this node runs with --firecracker-seccomp-verify=false, \
         so a VMM whose seccomp filter is not active would still be launched (ADR 0013)"
    )]
    SeccompVerifyOff,
    /// The node launches the VMM without the jailer.
    #[error(
        "the eval-cell profile is refused: this node runs with --firecracker-jailer=false, so the \
         VMM is not chrooted, cgroup-placed and privilege-dropped before exec (ADR 0013)"
    )]
    JailerOff,
    /// The operator waived the guest's workload Landlock.
    #[error(
        "the eval-cell profile is refused: this node runs with --allow-workload-without-landlock, \
         and an eval cell requires its guest to confine every child with Landlock (ADR 0013)"
    )]
    LandlockWaived,
    /// Credentials would be delivered into the guest.
    #[error(
        "the eval-cell profile is refused: this node does not enforce host-spec credential \
         delivery, so credential values would be written into a guest whose root is assumed \
         hostile. Run the node with broker enforcement on (ADR 0013)"
    )]
    CredentialDelivery,
    /// The spec asks for a VMM seccomp filter other than the default.
    #[error(
        "the eval-cell profile is refused: seccomp `{mode}` is not the default VMM filter. An eval \
         cell runs the VMM under the default filter, whatever this build's driver features \
         (ADR 0013)"
    )]
    SpecSeccomp { mode: &'static str },
    /// A `network.allow` entry that does not name exactly one host.
    #[error(
        "the eval-cell profile is refused: network.allow `{entry}` does not name exactly one \
         host. An eval cell reaches only destinations listed one by one (a bare address, /32 or \
         /128), private ranges included: a reachable range is how an agent finds a supporting \
         service it was never meant to reach (ADR 0013)"
    )]
    UnlistedRange { entry: String },
    /// The policy grants a network capability while the spec lists no destination.
    #[error(
        "the eval-cell profile is refused: the policy grants {capability} but the spec lists no \
         destination (network.allow, network.dns_allow or credentialed_egress). An eval cell's \
         egress is what it lists; name the hosts, or use a policy with {capability}: never \
         (ADR 0013)"
    )]
    UnlistedEgress { capability: &'static str },
    /// The spec names an audit sink, whose uploader credential the guest would hold.
    #[error(
        "the eval-cell profile is refused: audit_sink.sink `{sink}` is shipped by the tool-proxy \
         in the guest, so the cloud credential it writes with would be served to a guest whose \
         root is assumed hostile, and it signs from anywhere until it expires. An eval cell's \
         receipts reach the host over SHIP_RECEIPT instead; remove audit_sink (ADR 0013)"
    )]
    GuestHeldAuditCredential { sink: String },
    /// The policy could not be resolved, so its network capabilities could not be read.
    #[error("the eval-cell profile is refused: the policy does not resolve ({0})")]
    Policy(String),
    /// A child of an eval-cell pod that does not ask for the eval-cell profile.
    #[error(
        "the pod is refused: its parent {parent} is an eval cell, and a pod an eval cell creates \
         is an eval cell too. Label the child isolation.coproduct.one/profile: eval-cell \
         (ADR 0013)"
    )]
    ShedByChild { parent: Uuid },
    /// The node's own evidence does not appraise Attested (ADR 0016 D3).
    #[error(
        "the eval-cell profile is refused: this node's platform evidence appraises `{tier}` \
         ({note}), and an eval cell runs only on a node whose current TPM evidence appraises \
         attested against the operator's reference (--node-evidence-tpm, \
         --node-evidence-reference, an anchored AK) (ADR 0016)"
    )]
    NodeNotAttested { tier: &'static str, note: String },
    /// The SVID the node would serve the cell does not verify (ADR 0016 D3).
    #[error(
        "the eval-cell pod was not started: its launch does not verify ({0}). An eval cell is \
         served only an SVID that chains to this node's CA and carries the measurement the node \
         took of its kernel, rootfs and config (ADR 0016)"
    )]
    LaunchUnverified(String),
}

impl From<EvalCellRefused> for ApiError {
    fn from(e: EvalCellRefused) -> Self {
        ApiError::InvalidSpec(e.to_string())
    }
}

/// The refusal for a tier that is not Firecracker, or `None` for Firecracker.
///
/// Exhaustive over [`DriverKind`] with no `_` arm (ADR 0007 B-3, E-2): a new
/// driver does not compile until someone decides whether it may host an eval
/// cell. The tier is named by [`isolation_backend`], the same name the isolation
/// clamp writes into the pod's labels (G-1).
fn refuse_tier(driver: &DriverKind) -> Option<EvalCellRefused> {
    let why = match driver {
        DriverKind::Firecracker => return None,
        DriverKind::Container => {
            "a container shares the host kernel, so guest root is one kernel bug from host root"
        }
        DriverKind::AppleVz => {
            "its isolation has not been reviewed for a hostile guest, and the host has no egress \
             allowlist or VMM seccomp to verify"
        }
        #[cfg(feature = "local-driver")]
        DriverKind::Local => "there is no VM: the agent runs on the host as a process",
    };
    Some(EvalCellRefused::Tier {
        tier: isolation_backend(driver).name,
        why,
    })
}

/// Admit `spec` under its isolation profile on a node with `node`'s posture, as
/// a child of a pod under `parent` (when it has one).
///
/// # Errors
///
/// [`EvalCellRefused`] naming the first requirement the pod or node fails.
pub(crate) fn admit(
    spec: &PodSpec,
    node: &NodePosture<'_>,
    parent: Option<(Uuid, IsolationProfile)>,
) -> Result<IsolationProfile, EvalCellRefused> {
    let profile = IsolationProfile::of(spec)?;
    // The profile a parent holds binds its children: a child may ask for more,
    // never shed it by omitting the label (the absent-label case of ADR 0007 B).
    // Exhaustive over both profiles, no `_` arm (E-2).
    if let Some((parent, parent_profile)) = parent {
        match (parent_profile, profile) {
            (IsolationProfile::EvalCell, IsolationProfile::Standard) => {
                return Err(EvalCellRefused::ShedByChild { parent });
            }
            (IsolationProfile::EvalCell, IsolationProfile::EvalCell)
            | (IsolationProfile::Standard, IsolationProfile::Standard)
            | (IsolationProfile::Standard, IsolationProfile::EvalCell) => {}
        }
    }
    match profile {
        IsolationProfile::Standard => Ok(profile),
        IsolationProfile::EvalCell => {
            admit_eval_cell(spec, node)?;
            Ok(profile)
        }
    }
}

fn admit_eval_cell(spec: &PodSpec, node: &NodePosture<'_>) -> Result<(), EvalCellRefused> {
    // The tier first: on any other tier nothing below means what it says.
    if let Some(refused) = refuse_tier(node.driver) {
        return Err(refused);
    }
    // Destructured whole, so a new field of the node's posture is a compile error
    // here until someone says what an eval cell needs of it (ADR 0007 E-1).
    let NodePosture {
        driver: _,
        seccomp_verify,
        jailer,
        landlock,
        host_spec,
        platform,
    } = node;
    require_attested(*platform)?;
    if !seccomp_verify {
        return Err(EvalCellRefused::SeccompVerifyOff);
    }
    if !jailer {
        return Err(EvalCellRefused::JailerOff);
    }
    match landlock {
        nucleus::LandlockWaiver::Absent => {}
        nucleus::LandlockWaiver::Explicit => return Err(EvalCellRefused::LandlockWaived),
    }
    if !host_spec.is_required() {
        return Err(EvalCellRefused::CredentialDelivery);
    }
    // The one third-party credential the workload API serves a guest: the audit uploader's cloud
    // key (`FETCH_AUDIT_CREDENTIALS`). Served once, it is still served, and guest root holds what
    // the guest holds. The rest of what that API serves is public, or the pod's own identity, or
    // a capability spent only at this pod's host-side broker, which decides and holds the
    // credential (ADR 0013's credential-theft row lists each). Refused here, in the one decider,
    // before anything is minted (ADR 0007 G-1), rather than withheld at the socket after the
    // pod has booted expecting it.
    if let Some(audit) = &spec.spec.audit_sink {
        return Err(EvalCellRefused::GuestHeldAuditCredential {
            sink: audit.sink.clone(),
        });
    }
    match &spec.spec.seccomp {
        None | Some(nucleus_spec::SeccompSpec::Default) => {}
        Some(nucleus_spec::SeccompSpec::Disabled) => {
            return Err(EvalCellRefused::SpecSeccomp { mode: "disabled" });
        }
        Some(nucleus_spec::SeccompSpec::Custom { .. }) => {
            return Err(EvalCellRefused::SpecSeccomp { mode: "custom" });
        }
    }
    admit_egress(spec)
}

/// The node's current evidence appraises Attested, now (ADR 0016 D3).
///
/// Only `Attested` admits. Exhaustive, no `_` arm (E-2): a tier added to the
/// verifier does not compile here until someone says whether it admits a cell.
/// The appraisal reads the evidence in force from the store, so this runs only
/// for an eval cell, never on a standard pod's create.
fn require_attested(platform: &dyn PlatformAttestation) -> Result<(), EvalCellRefused> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let attestation = platform.attestation_now(now);
    match attestation.tier() {
        ClaimedTier::Attested => Ok(()),
        tier @ (ClaimedTier::Contested | ClaimedTier::Expired | ClaimedTier::Unattested) => {
            Err(EvalCellRefused::NodeNotAttested {
                tier: tier.as_str(),
                note: attestation.note().to_string(),
            })
        }
    }
}

/// What the node holds of a pod's launch identity just before it serves it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum LaunchIdentity<'a> {
    /// The node issues this pod no workload identity.
    NoIdentity,
    /// Measuring the pod's kernel, rootfs and config failed.
    NotMeasured(String),
    /// Issuing the attested SVID failed.
    NotIssued(String),
    /// The SVID the node will serve, the measurement it took, and its CA's roots.
    Issued {
        measured: &'a nucleus_identity::LaunchAttestation,
        leaf_der: &'a [u8],
        trust_bundle: &'a nucleus_identity::TrustBundle,
    },
}

/// At boot, before the VMM starts: an eval cell is served only an SVID that
/// verifies (ADR 0016 D3). A standard pod is not checked, and keeps today's
/// fallback to a plain SVID.
///
/// The check is `nucleus_identity::VerifiedLaunch::verify`, the one decider every
/// relying party calls (G-1): the leaf chains to the node's CA, and carries a
/// launch claim. Then the claim must be exactly the measurement the node took:
/// a cached certificate from another launch is not this one.
///
/// # Errors
///
/// [`EvalCellRefused::LaunchUnverified`], naming the failure.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn require_verified_launch(
    profile: IsolationProfile,
    launch: LaunchIdentity<'_>,
) -> Result<(), EvalCellRefused> {
    match profile {
        IsolationProfile::Standard => return Ok(()),
        IsolationProfile::EvalCell => {}
    }
    match launch {
        LaunchIdentity::NoIdentity => Err(EvalCellRefused::LaunchUnverified(
            "this node issues the pod no workload identity".into(),
        )),
        LaunchIdentity::NotMeasured(e) => Err(EvalCellRefused::LaunchUnverified(format!(
            "the launch could not be measured: {e}"
        ))),
        LaunchIdentity::NotIssued(e) => Err(EvalCellRefused::LaunchUnverified(format!(
            "the attested SVID could not be issued: {e}"
        ))),
        LaunchIdentity::Issued {
            measured,
            leaf_der,
            trust_bundle,
        } => {
            let verified = nucleus_identity::VerifiedLaunch::verify(leaf_der, trust_bundle)
                .map_err(|e| EvalCellRefused::LaunchUnverified(e.to_string()))?;
            // The three measurements, compared by the relying party's own rule. Not `==`
            // on the whole value: the certificate keeps the time to the second, the
            // measurement to the nanosecond, so equality would refuse every launch.
            nucleus_identity::AttestationRequirements::exact(
                *measured.kernel_hash(),
                *measured.rootfs_hash(),
                *measured.config_hash(),
            )
            .verify(verified.launch())
            .map_err(|e| {
                EvalCellRefused::LaunchUnverified(format!(
                    "the SVID carries {}, but the node measured {}: {e}",
                    verified.launch().to_hex_summary(),
                    measured.to_hex_summary()
                ))
            })
        }
    }
}

/// An eval cell's egress is exactly what it lists, host by host.
fn admit_egress(spec: &PodSpec) -> Result<(), EvalCellRefused> {
    let network = spec.spec.network.as_ref();
    for entry in network.map_or(&[][..], |n| n.allow.as_slice()) {
        // An entry that does not parse is refused here too, not skipped: an
        // entry nobody can read is not one anybody listed (ADR 0007 A-2).
        match crate::net::names_one_host(entry) {
            Ok(true) => {}
            Ok(false) | Err(_) => {
                return Err(EvalCellRefused::UnlistedRange {
                    entry: entry.clone(),
                });
            }
        }
    }
    let listed = network.is_some_and(|n| !n.allow.is_empty() || !n.dns_allow.is_empty())
        || !spec.spec.credentialed_egress.is_empty();
    if listed {
        return Ok(());
    }
    let lattice = spec
        .spec
        .resolve_policy()
        .map_err(|e| EvalCellRefused::Policy(e.to_string()))?;
    let caps = &lattice.capabilities;
    for (capability, level) in [
        ("web_fetch", caps.web_fetch),
        ("web_search", caps.web_search),
    ] {
        match level {
            CapabilityLevel::Never => {}
            CapabilityLevel::LowRisk | CapabilityLevel::Always => {
                return Err(EvalCellRefused::UnlistedEgress { capability });
            }
        }
    }
    Ok(())
}

/// The eval cells this node has admitted, recorded at admission (before the
/// guest boots), so a child's parent profile is read from what the node itself
/// decided and never from a spec, and so a guest that asks for a child before
/// its own pod is registered is still known to be an eval cell.
///
/// A pod is recorded for the node process's lifetime and never removed: an id
/// left behind by a pod that failed to boot or exited only makes its (impossible)
/// children stricter. Pod tokens do not outlive the process (`caller_secret` is
/// fresh per process), so a parent from a previous process cannot call here.
///
/// No `Default` (ADR 0007 B-1): the one constructor is [`Admitted::none`], named
/// for what it holds, called once per node process.
#[derive(Debug, Clone)]
pub(crate) struct Admitted(std::sync::Arc<std::sync::Mutex<std::collections::HashSet<Uuid>>>);

impl Admitted {
    /// A node process that has admitted no eval cell yet.
    pub(crate) fn none() -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashSet::new(),
        )))
    }

    fn record(&self, id: Uuid) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id);
    }

    /// The profile the node admitted `id` under. Absence is standard: every
    /// eval cell is recorded before its guest exists to ask for a child.
    fn profile_of(&self, id: Uuid) -> IsolationProfile {
        if self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&id)
        {
            IsolationProfile::EvalCell
        } else {
            IsolationProfile::Standard
        }
    }
}

/// [`admit`] against the live node: its posture, and the profile the node
/// itself admitted the parent under. An admitted eval cell is recorded as `id`.
pub(crate) fn admit_on(
    state: &crate::NodeState,
    spec: &PodSpec,
    parent: Option<Uuid>,
    id: Uuid,
) -> Result<IsolationProfile, ApiError> {
    let parent = parent.map(|p| (p, state.eval_cells.profile_of(p)));
    let profile = admit(spec, &NodePosture::of(state), parent)?;
    match profile {
        IsolationProfile::Standard => {}
        IsolationProfile::EvalCell => state.eval_cells.record(id),
    }
    Ok(profile)
}

/// At boot: an eval cell's guest must report its children confined by Landlock.
///
/// The release table already requires a guest that carries Landlock for an eval
/// cell (`tier2_artifacts::GuestUse::EvalCell`), but the node does not know which
/// release a Firecracker rootfs came from. The verdict on the console is what the
/// node can see, so a guest that is silent, refused or waived fails the boot.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn require_confined_children(
    spec: &PodSpec,
    filesystem: &crate::net::confinement::WorkloadFilesystem,
) -> Result<(), ApiError> {
    match IsolationProfile::of(spec).map_err(EvalCellRefused::from)? {
        IsolationProfile::Standard => Ok(()),
        IsolationProfile::EvalCell if filesystem.enforced() => Ok(()),
        IsolationProfile::EvalCell => Err(ApiError::Driver(format!(
            "the eval-cell pod was not started: its guest must confine every child with \
             Landlock, and it reported {} (ADR 0013)",
            filesystem.posture()
        ))),
    }
}

#[cfg(test)]
#[path = "eval_cell_tests.rs"]
mod tests;
