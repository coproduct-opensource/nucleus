//! The spec a pod's guest receives, and the one manifest hash every party binds to it.
//!
//! **The canonical spec is the delivered one.** Two parties hash a pod's spec: the node, into the
//! receipt's `manifest_hash` (`pod_receipt`), and the pod's tool-proxy, which binds an approval
//! bundle to `PodSpec::manifest_hash` of the spec file it reads (#3395). They are one fact, so
//! they must be one computation (ADR 0007 G-1). They were not. The receipt hashed the node's
//! admitted host spec, while the guest hashed the copy delivered to it, and the two differ by the
//! driver's delivery transform:
//!
//! - **Firecracker, enforcing** (`cred_split`): every `credentials.env` value is withheld from the
//!   guest's copy.
//! - **Container**: `work_dir` is rewritten to the container's mount. On the HTTP create path the
//!   file was also the caller's raw request, not the admitted spec, so it carried the requested
//!   policy, the requested upstreams, and none of the labels admission stamps.
//!
//! An approval minted for the receipt's hash therefore never verified in those guests. A hash
//! computed from what the guest reads would never match a receipt.
//!
//! [`DeliveredSpec::of`] is now the only decider. It produces the bytes a driver hands the guest,
//! then hashes them by parsing those bytes as a [`PodSpec`]. That is the computation the guest's
//! approval check performs on the same file. The receipt carries this hash and no other.
//!
//! What the canonical spec is, per delivery:
//!
//! | delivery | the guest's spec | hashed |
//! |---|---|---|
//! | local | the admitted spec | the file |
//! | Firecracker | the admitted spec, credential values withheld when enforcing | the served spec |
//! | container, mediated | the admitted spec, `work_dir` = the container mount | the file |
//! | container, unmediated | the caller's YAML with that `work_dir` (extension fields kept) | the admitted spec with that `work_dir` |
//!
//! A Firecracker node with host-spec enforcement off lets the guest fall back to its image's own
//! `pod.yaml`. That guest hashes the image's spec, so an approval minted for the receipt fails
//! closed there, as it should: the guest is not running the spec the receipt names.
//!
//! An unmediated container runs no tool-proxy, so nothing inside it binds an approval to its spec.
//! Its file keeps the caller's extension fields, such as `task`, for the orchestrator's runner.
//! Those fields are not in [`PodSpec`] and have no hash. The receipt hashes the typed admitted
//! spec under the same mount translation.
//!
//! A spec with no canonical form (a non-finite float) is refused here at creation. It used to
//! launch and then fail to produce a receipt.

use crate::ApiError;
use crate::container_mediation::ContainerMediation;
use crate::cred_split::Withheld;
use nucleus_spec::{ManifestHash, PodSpec};

/// How a driver hands a pod its spec. Chosen once per pod by [`Delivery::for_driver`].
#[derive(Debug, Clone, Copy)]
pub(crate) enum Delivery<'a> {
    /// Written to the pod directory as admitted (the local driver).
    AsAdmitted,
    /// Served over the workload API. `withhold`: enforcing credential delivery.
    Firecracker { withhold: bool },
    /// Written to the container's `/data/pod/pod.yaml`, under the container's workspace mount.
    Container {
        mediation: ContainerMediation,
        /// The caller's request, as sent: kept only for an unmediated container's extension fields.
        raw: Option<&'a str>,
    },
}

impl<'a> Delivery<'a> {
    /// The delivery a node with this driver uses. Exhaustive, so a new driver is a compile error
    /// here before its guest is handed a spec nobody hashed (E-1).
    pub(crate) fn for_driver(
        driver: &crate::DriverKind,
        broker_enforcing: crate::broker_rollout::HostSpecEnforcement,
        container_mediation: ContainerMediation,
        raw: Option<&'a str>,
    ) -> Self {
        match driver {
            #[cfg(feature = "local-driver")]
            crate::DriverKind::Local => Self::AsAdmitted,
            crate::DriverKind::Firecracker => Self::Firecracker {
                withhold: broker_enforcing.is_required(),
            },
            crate::DriverKind::Container => Self::Container {
                mediation: container_mediation,
                raw,
            },
            // The VZ spawn refuses every pod (`driver::spawn_vz_pod`); nothing is delivered.
            crate::DriverKind::AppleVz => Self::AsAdmitted,
        }
    }
}

/// The spec bytes one pod's guest is handed, and their manifest hash: a pair minted together, so
/// the hash cannot describe other bytes (C-1). Not `Clone`: one delivery per admitted pod.
pub(crate) struct DeliveredSpec {
    yaml: String,
    manifest_hash: ManifestHash,
    withheld: Option<Withheld>,
}

impl std::fmt::Debug for DeliveredSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the YAML: in a non-withholding delivery it carries credential values.
        f.debug_struct("DeliveredSpec")
            .field("manifest_hash", &self.manifest_hash)
            .field("withheld", &self.withheld.is_some())
            .finish_non_exhaustive()
    }
}

impl DeliveredSpec {
    /// The delivered form of the admitted `spec`. See the [module docs](self).
    ///
    /// # Errors
    ///
    /// The spec does not serialize, or its delivered form has no canonical hash. Never a
    /// delivery whose hash is missing.
    pub(crate) fn of(spec: &PodSpec, delivery: Delivery<'_>) -> Result<Self, ApiError> {
        let (yaml, hashed, withheld) = match delivery {
            Delivery::AsAdmitted => {
                let yaml = nucleus_yaml::to_string(spec)?;
                (yaml.clone(), yaml, None)
            }
            Delivery::Firecracker { withhold } => {
                let (yaml, withheld) = crate::cred_split::guest_spec_yaml(spec, withhold)?;
                (yaml.clone(), yaml, withheld)
            }
            Delivery::Container { mediation, raw } => {
                let typed = crate::container_mediation::pod_yaml(spec, None)?;
                let yaml = match (mediation, raw) {
                    // The proxy reads this file and enforces and hashes what it parses, so it
                    // gets the admitted spec. It does not get the request.
                    (ContainerMediation::ToolProxy, _) | (ContainerMediation::Unmediated, None) => {
                        typed.clone()
                    }
                    (ContainerMediation::Unmediated, Some(raw)) => {
                        crate::container_mediation::pod_yaml(spec, Some(raw))?
                    }
                };
                (yaml, typed, None)
            }
        };
        let manifest_hash = Self::guest_hash(&hashed)?;
        Ok(Self {
            yaml,
            manifest_hash,
            withheld,
        })
    }

    /// The hash a reader of `yaml` computes: parse it as a pod spec, then take its v3 manifest
    /// hash. This is what the tool-proxy's approval check does with its `--spec` file.
    fn guest_hash(yaml: &str) -> Result<ManifestHash, ApiError> {
        let parsed: PodSpec = nucleus_yaml::from_str(yaml).map_err(|e| {
            ApiError::Driver(format!("the delivered pod spec does not parse back: {e}"))
        })?;
        parsed
            .manifest_hash()
            .map_err(|e| ApiError::InvalidSpec(format!("pod spec has no manifest hash: {e}")))
    }

    /// The bytes the guest is handed.
    pub(crate) fn yaml(&self) -> &str {
        &self.yaml
    }

    /// The pod's manifest hash: what its receipt carries and what an approval binds.
    pub(crate) fn manifest_hash(&self) -> &ManifestHash {
        &self.manifest_hash
    }

    /// The evidence that credential values were withheld from [`Self::yaml`], minted only by
    /// `cred_split` while preparing it (Firecracker, enforcing).
    pub(crate) fn withheld(&self) -> Option<&Withheld> {
        self.withheld.as_ref()
    }
}

/// The manifest hash a fixture's `PodHandle` carries: its spec, delivered as admitted.
#[cfg(test)]
pub(crate) fn fixture_hash(spec: &PodSpec) -> ManifestHash {
    DeliveredSpec::of(spec, Delivery::AsAdmitted)
        .expect("a fixture spec is delivered")
        .manifest_hash
}

#[cfg(test)]
#[path = "delivered_spec_tests.rs"]
mod tests;
