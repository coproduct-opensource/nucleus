//! Owner-decision material: what the operator configures, how each pod receives it, and which
//! pods the node refuses for it (`docs/permissions.md`, "Decisions").
//!
//! # What the node holds
//!
//! `--decision-trust-roots <file>` (the keys whose signatures make a decision an owner's),
//! `--decision-tenant` (the tenant every decision must name) and `--decision-bundles <dir>` (where
//! the tenant's decision bundles arrive, one `<decision id>.json` each). All three or none, and
//! every one is checked at startup: a node that cannot parse its roots refuses to start, by
//! the flag's name, rather than hand its pods a verifier that refuses everything.
//!
//! The roots are operator configuration. The bundles are untrusted bytes: the node checks their
//! names and sizes so they are safe to hand on, and nothing else. The tool-proxy in the pod is
//! the only verifier (`nucleus-signed-decision`), as it is the only enforcer.
//!
//! # How a pod receives it
//!
//! | driver | roots and bundles | variables |
//! |---|---|---|
//! | local | the node's own files | naming the node's files |
//! | container | bind-mounted read-only at `decision_gate::GUEST_DIR` | naming those paths |
//! | Firecracker | in the `FETCH_POD_SPEC` reply, written by guest-init under `GUEST_DIR` | set by guest-init |
//!
//! A Firecracker or local pod gets the bundles present when it was created; a container sees the
//! directory as it changes. A pod that predates a decision does not hold it.
//!
//! # Which pods are refused
//!
//! A spec that lists `requires_decision` is refused at create, by name, when the node has no
//! decision material, when a requirement names an upstream the spec does not declare (a gate that
//! could never fire), on an unmediated container (nothing would enforce it), and on a guest known
//! to predate [`GuestCapability::DecisionGatedSinks`]. A Firecracker guest whose release the node
//! cannot tell must print the tool-proxy's armed line before the pod is handed out.

use std::path::{Path, PathBuf};

use nucleus_spec::PodSpec;
use nucleus_spec::decision_gate::{
    self, BUNDLES_ENV, DecisionBundleFile, DecisionMaterial, MAX_BUNDLE_BYTES, MAX_BUNDLES,
    MAX_ROOTS_BYTES, TENANT_ENV, TRUST_ROOTS_ENV,
};
use nucleus_spec::guest_release::{GuestOrigin, NodeGuestReport};
use nucleus_spec::tier2_artifacts::{self, FirstShipped, GuestCapability, GuestSkew};

use crate::ApiError;
use crate::container_mediation::ContainerMediation;
use crate::driver::DriverKind;

/// The guest capability a decision-requiring pod depends on.
const CAPABILITY: GuestCapability = GuestCapability::DecisionGatedSinks;

/// The operator's decision material. All three or none.
#[derive(clap::Args, Debug)]
pub(crate) struct DecisionArgs {
    /// Trust roots for owner decisions: a JSON array of `{kid, public_key, who}`. Unset means
    /// this node's pods have no decision tools, and a pod that requires a decision is refused.
    #[arg(
        long,
        env = "NUCLEUS_NODE_DECISION_TRUST_ROOTS",
        requires_all = ["decision_tenant", "decision_bundles"]
    )]
    decision_trust_roots: Option<PathBuf>,
    /// The tenant every decision must name (`github~owner~name`).
    #[arg(
        long,
        env = "NUCLEUS_NODE_DECISION_TENANT",
        requires = "decision_trust_roots"
    )]
    decision_tenant: Option<String>,
    /// The directory the tenant's decision bundles arrive in, one `<decision id>.json` each.
    #[arg(
        long,
        env = "NUCLEUS_NODE_DECISION_BUNDLES",
        requires = "decision_trust_roots"
    )]
    decision_bundles: Option<PathBuf>,
}

/// Decision material the node checked at startup.
#[derive(Debug)]
pub(crate) struct NodeDecisions {
    roots_path: PathBuf,
    roots_text: String,
    tenant: String,
    bundles: PathBuf,
}

/// A refusal at startup, named by the flag it concerns.
fn startup(flag: &str, why: impl std::fmt::Display) -> ApiError {
    ApiError::Driver(format!("--{flag}: {why}"))
}

/// Read an operator file of at most `cap` bytes: a regular file, size checked before and after.
fn read_capped(path: &Path, cap: u64) -> std::io::Result<Vec<u8>> {
    let too_big = || std::io::Error::new(std::io::ErrorKind::InvalidData, "over the size cap");
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if meta.len() > cap {
        return Err(too_big());
    }
    let bytes = std::fs::read(path)?;
    if !u64::try_from(bytes.len()).is_ok_and(|n| n <= cap) {
        return Err(too_big());
    }
    Ok(bytes)
}

impl DecisionArgs {
    /// Whether any decision material is configured, for the insecure-mode
    /// refusal (`insecure_mode`, Program C C0). Any one of the three counts:
    /// partial material is a refusal of its own in [`Self::load`].
    pub(crate) fn configured(&self) -> bool {
        let Self {
            decision_trust_roots,
            decision_tenant,
            decision_bundles,
        } = self;
        decision_trust_roots.is_some() || decision_tenant.is_some() || decision_bundles.is_some()
    }

    /// Check the material, or `Ok(None)` when none is configured. Any partial or malformed
    /// configuration refuses the node's start.
    pub(crate) fn load(&self, workspace_root: &Path) -> Result<Option<NodeDecisions>, ApiError> {
        let (roots, tenant, bundles) = match (
            &self.decision_trust_roots,
            &self.decision_tenant,
            &self.decision_bundles,
        ) {
            (None, None, None) => return Ok(None),
            (Some(r), Some(t), Some(b)) => (r, t, b),
            _ => {
                return Err(startup(
                    "decision-trust-roots",
                    "--decision-trust-roots, --decision-tenant and --decision-bundles are \
                     configured together",
                ));
            }
        };
        if tenant.is_empty() {
            return Err(startup("decision-tenant", "is empty"));
        }
        let workspace = workspace_root.canonicalize().map_err(ApiError::from)?;
        let outside = |flag: &str, p: &Path| -> Result<PathBuf, ApiError> {
            let p = p
                .canonicalize()
                .map_err(|e| startup(flag, format!("{}: {e}", p.display())))?;
            if p.starts_with(&workspace) {
                return Err(startup(flag, "must be outside the workspace root"));
            }
            Ok(p)
        };
        let roots_path = outside("decision-trust-roots", roots)?;
        let bundles = outside("decision-bundles", bundles)?;
        if !bundles.is_dir() {
            return Err(startup("decision-bundles", "is not a directory"));
        }
        let bytes = read_capped(&roots_path, MAX_ROOTS_BYTES)
            .map_err(|e| startup("decision-trust-roots", e))?;
        let roots_text = String::from_utf8(bytes)
            .map_err(|_| startup("decision-trust-roots", "is not UTF-8"))?;
        let parsed = nucleus_signed_decision::TrustRoots::from_json(&roots_text)
            .map_err(|e| startup("decision-trust-roots", e))?;
        tracing::info!(
            roots = parsed.len(),
            tenant = %tenant,
            bundles = %bundles.display(),
            "owner decisions: trust roots pinned"
        );
        Ok(Some(NodeDecisions {
            roots_path,
            roots_text,
            tenant: tenant.clone(),
            bundles,
        }))
    }
}

impl NodeDecisions {
    /// The material a Firecracker guest is served: the roots, the tenant, and every bundle file
    /// now in the directory that is named `<decision id>.json` and within the size cap. Nothing
    /// is verified here.
    ///
    /// # Errors
    /// The directory cannot be read, or holds more than the material may carry. The pod is
    /// refused rather than handed a chosen subset.
    pub(crate) fn material(&self) -> Result<DecisionMaterial, ApiError> {
        let refuse = |why: String| {
            ApiError::Driver(format!(
                "owner decisions in {}: {why}",
                self.bundles.display()
            ))
        };
        let mut bundles = Vec::new();
        let entries = std::fs::read_dir(&self.bundles).map_err(|e| refuse(e.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|e| refuse(e.to_string()))?;
            let Some(id) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.strip_suffix(".json"))
                .filter(|id| decision_gate::is_decision_id(id))
                .map(str::to_string)
            else {
                continue;
            };
            let Ok(bytes) = read_capped(&entry.path(), MAX_BUNDLE_BYTES) else {
                tracing::debug!(%id, "decision bundle skipped: not a regular file within the cap");
                continue;
            };
            let Ok(json) = String::from_utf8(bytes) else {
                continue;
            };
            if bundles.len() >= MAX_BUNDLES {
                return Err(refuse(format!("more than {MAX_BUNDLES} bundles")));
            }
            bundles.push(DecisionBundleFile { id, json });
        }
        bundles.sort_by(|a, b| a.id.cmp(&b.id));
        let material = DecisionMaterial {
            trust_roots: self.roots_text.clone(),
            tenant: self.tenant.clone(),
            bundles,
        };
        material.check().map_err(|e| refuse(e.to_string()))?;
        Ok(material)
    }

    /// A local pod's tool-proxy reads the node's own files.
    #[cfg(feature = "local-driver")]
    pub(crate) fn local_env(&self) -> [(&'static str, String); 3] {
        [
            (TRUST_ROOTS_ENV, self.roots_path.display().to_string()),
            (BUNDLES_ENV, self.bundles.display().to_string()),
            (TENANT_ENV, self.tenant.clone()),
        ]
    }

    /// A container pod's tool-proxy reads read-only binds of the node's files at the guest paths.
    pub(crate) fn container_env(&self) -> impl Iterator<Item = String> + '_ {
        [
            (
                TRUST_ROOTS_ENV,
                decision_gate::GUEST_TRUST_ROOTS.to_string(),
            ),
            (BUNDLES_ENV, decision_gate::GUEST_BUNDLES.to_string()),
            (TENANT_ENV, self.tenant.clone()),
        ]
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
    }

    /// The read-only binds behind [`Self::container_env`].
    pub(crate) fn container_binds(&self) -> [String; 2] {
        [
            format!(
                "{}:{}:ro",
                self.roots_path.display(),
                decision_gate::GUEST_TRUST_ROOTS
            ),
            format!(
                "{}:{}:ro",
                self.bundles.display(),
                decision_gate::GUEST_BUNDLES
            ),
        ]
    }
}

/// The node's own verifier, for the one thing the node itself decides on an owner decision: a
/// memory binding policy (`memory_space`). The tool-proxy stays the verifier of everything a pod
/// does; this answers only whether a standing decision covers `memory.bind:<space>` or
/// `memory.publish:<space>` now.
///
/// Every bundle in the directory is verified and held, so a decision that a present one
/// supersedes is refused as superseded. A bundle filed under another decision's id is not that
/// decision, and one that does not verify is not held.
impl crate::memory_space::DecisionCiter for NodeDecisions {
    fn cite(&self, decision: &str, capability: &str, now: u64) -> Result<u64, String> {
        use nucleus_signed_decision::{
            Action, DecisionBundle, DecisionLedger, LedgerError, OwnerDecisionId, TrustRoots,
            WriteSet,
        };
        let id = OwnerDecisionId::from_hex(decision).map_err(|e| e.to_string())?;
        let roots = TrustRoots::from_json(&self.roots_text).map_err(|e| e.to_string())?;
        let material = self.material().map_err(|e| e.to_string())?;
        let mut ledger = DecisionLedger::empty();
        for file in &material.bundles {
            let Ok(bundle) = DecisionBundle::from_slice(file.json.as_bytes()) else {
                continue;
            };
            let Ok(verified) = nucleus_signed_decision::verify(&bundle, &roots, now, &self.tenant)
            else {
                continue;
            };
            if verified.id().to_hex() != file.id {
                continue;
            }
            match ledger.hold(verified) {
                Ok(_) => {}
                Err(LedgerError::Full) => return Err(LedgerError::Full.to_string()),
                // Retired (superseded by one already held) or malformed: not held.
                Err(_) => {}
            }
        }
        let action = Action {
            capability,
            writes: WriteSet::Known(&[]),
        };
        let cited = ledger.cite(id, &action, now).map_err(|e| e.to_string())?;
        Ok(cited.record().not_after)
    }
}

/// `DecisionGatedSinks (in no published release yet: <change>)`, from the table.
fn capability_name() -> String {
    let when = match CAPABILITY.first_shipped() {
        FirstShipped::Release(v) => format!("first released in v{v}"),
        FirstShipped::NotYet => "in no published release yet".to_string(),
    };
    format!("{CAPABILITY:?} ({when}: {})", CAPABILITY.change())
}

fn required_names(spec: &PodSpec) -> String {
    spec.spec
        .requires_decision
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Refuse at create a pod whose decision requirements this node could not enforce. Pure over
/// what it is handed, so a test drives every arm without a node.
pub(crate) fn admit_with(
    decisions: Option<&NodeDecisions>,
    spec: &PodSpec,
    driver: &DriverKind,
    mediation: ContainerMediation,
    guest: &NodeGuestReport,
) -> Result<(), ApiError> {
    let required = &spec.spec.requires_decision;
    if required.is_empty() {
        return Ok(());
    }
    let refuse = |why: String| {
        ApiError::InvalidSpec(format!(
            "the pod requires an owner decision for {}, and {why}",
            required_names(spec)
        ))
    };
    if decisions.is_none() {
        return Err(refuse(
            "this node has no --decision-trust-roots, so no decision could be verified".into(),
        ));
    }
    for cap in required {
        if !spec
            .spec
            .credentialed_egress
            .iter()
            .any(|u| u.name == cap.upstream())
        {
            return Err(refuse(format!(
                "{cap} names upstream {:?}, which the spec does not declare in \
                 credentialed_egress, so the requirement could never apply",
                cap.upstream()
            )));
        }
    }
    match driver {
        // The same tree's tool-proxy.
        #[cfg(feature = "local-driver")]
        DriverKind::Local => Ok(()),
        DriverKind::Container if mediation.runs_tool_proxy() => Ok(()),
        DriverKind::Container => Err(refuse(
            "this node runs containers unmediated, so nothing in the pod would enforce it".into(),
        )),
        DriverKind::Firecracker => firecracker_guest(spec, guest).map_err(refuse),
        // The VZ spawn refuses every pod (`driver::spawn_vz_pod`).
        DriverKind::AppleVz => Ok(()),
    }
}

/// [`admit_with`] against the live node.
pub(crate) fn admit(state: &crate::NodeState, spec: &PodSpec) -> Result<(), ApiError> {
    admit_with(
        state.decisions.as_deref(),
        spec,
        &state.driver,
        state.container_mediation,
        &state.guest_report.current(),
    )
}

/// The default rootfs's recorded release, when the pod boots it: a release known to predate the
/// capability is refused. Anything the node cannot tell is decided at boot ([`require_armed`]).
fn firecracker_guest(spec: &PodSpec, guest: &NodeGuestReport) -> Result<(), String> {
    let NodeGuestReport::Known {
        origin: GuestOrigin::Release { version },
        rootfs_path,
        ..
    } = guest
    else {
        return Ok(());
    };
    let same = |a: &Path, b: &Path| {
        a == b || matches!((a.canonicalize(), b.canonicalize()), (Ok(x), Ok(y)) if x == y)
    };
    let boots_default = spec
        .spec
        .image
        .as_ref()
        .is_some_and(|image| match &image.rootfs {
            nucleus_spec::RootfsSource::Path(p) => same(p, rootfs_path),
            nucleus_spec::RootfsSource::Oci(_) => false,
        });
    if !boots_default {
        return Ok(());
    }
    match tier2_artifacts::capability_skew(version, CAPABILITY) {
        Ok(()) | Err(GuestSkew::Unorderable { .. }) => Ok(()),
        Err(GuestSkew::Lacks { .. }) => Err(format!(
            "its guest rootfs {} is release v{version}, which lacks {}. {}",
            rootfs_path.display(),
            capability_name(),
            tier2_artifacts::REBUILD_THE_GUEST
        )),
    }
}

/// Refuse, before anything is created, a decision-requiring pod on a container image whose
/// tool-proxy is known to lack the capability. An image whose release cannot be read is launched:
/// an older tool-proxy refuses the spec's `requires_decision` and the pod never comes up.
pub(crate) fn admit_image(
    image: &str,
    version: Option<&str>,
    spec: &PodSpec,
) -> Result<(), ApiError> {
    if spec.spec.requires_decision.is_empty() {
        return Ok(());
    }
    let Some(version) = version else {
        return Ok(());
    };
    match tier2_artifacts::capability_skew(version, CAPABILITY) {
        Ok(()) | Err(GuestSkew::Unorderable { .. }) => Ok(()),
        Err(GuestSkew::Lacks { .. }) => Err(ApiError::Driver(format!(
            "refusing to launch a container pod that requires an owner decision for {}: image \
             {image} is tool-proxy release {version}, which lacks {}",
            required_names(spec),
            capability_name()
        ))),
    }
}

/// At boot: a Firecracker pod that requires a decision is handed out only once its tool-proxy
/// has printed that it armed every requirement. Pure over the console.
pub(crate) fn require_armed_in(spec: &PodSpec, console: &str) -> Result<(), ApiError> {
    let required = &spec.spec.requires_decision;
    if required.is_empty() || decision_gate::armed_in(console, required) {
        return Ok(());
    }
    Err(ApiError::Driver(format!(
        "the pod requires an owner decision for {}, and its tool-proxy never reported the \
         requirement armed (`{}`). If the guest predates it: {}. {}",
        required_names(spec),
        decision_gate::ARMED_PREFIX,
        capability_name(),
        tier2_artifacts::REBUILD_THE_GUEST
    )))
}

/// [`require_armed_in`] over the pod's console file.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) async fn require_armed(spec: &PodSpec, pod_dir: &Path) -> Result<(), ApiError> {
    if spec.spec.requires_decision.is_empty() {
        return Ok(());
    }
    let console = tokio::fs::read_to_string(pod_dir.join("firecracker.log"))
        .await
        .map_err(|e| ApiError::Driver(format!("decision gate acknowledgment unavailable: {e}")))?;
    require_armed_in(spec, &console)
}

/// A boot failure of a decision-requiring pod, with the likely cause named: an older guest's
/// tool-proxy refuses the spec, so the pod dies before it can say why.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn name_skew(spec: &PodSpec, cause: ApiError) -> ApiError {
    if spec.spec.requires_decision.is_empty() {
        return cause;
    }
    ApiError::Driver(format!(
        "{cause}. The pod requires an owner decision; a guest that predates {} refuses its spec",
        capability_name()
    ))
}

#[cfg(test)]
#[path = "decision_provisioning_tests.rs"]
mod tests;
