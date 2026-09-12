//! Prepare the host identity service before the VMM can boot.
//!
//! Run 34717924790 booted an 8 GiB build image before computing its launch
//! attestation and opening the workload API. PID 1 immediately asked for its
//! spec, received a reset, and exited. Readiness before the proxy health check
//! was too late: readiness must precede the guest's first instruction.
//! The guard keeps registration and listeners owned across every launch error.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use super::*;

pub(crate) struct IdentityParts {
    pub identity: Option<nucleus_identity::Identity>,
    pub manager: Option<identity::IdentityManager>,
    pub registry_key: Option<String>,
    pub bridge: Option<workload_api_vsock::WorkloadApiVsockBridge>,
}

#[must_use]
pub(crate) struct PreparedIdentity(Option<IdentityParts>);

impl PreparedIdentity {
    pub(crate) fn identity(&self) -> Option<&nucleus_identity::Identity> {
        self.0.as_ref().and_then(|parts| parts.identity.as_ref())
    }

    /// The caller holds prepared services through spawn and confinement checks.
    pub(crate) fn spawn(
        &self,
        command: &mut tokio::process::Command,
    ) -> std::io::Result<tokio::process::Child> {
        boot_trace::time_sync("firecracker.spawn", || command.spawn())
    }

    /// Transfer cleanup responsibility to the running pod, by value (C-4).
    pub(crate) fn into_parts(mut self) -> IdentityParts {
        self.0.take().expect("prepared identity is consumed once")
    }
}

impl Drop for PreparedIdentity {
    fn drop(&mut self) {
        if let Some(IdentityParts {
            identity,
            manager,
            registry_key,
            bridge,
        }) = self.0.take()
        {
            tokio::spawn(async move {
                if let Some(bridge) = bridge {
                    bridge.shutdown().await;
                }
                if let (Some(identity), Some(manager)) = (identity, manager) {
                    manager
                        .release_pod(registry_key.as_deref(), &identity)
                        .await;
                    if let Some(key) = registry_key {
                        manager.forget_attestation(&key).await;
                    }
                }
            });
        }
    }
}

pub(crate) struct Inputs<'a> {
    pub state: &'a NodeState,
    pub pod_dir: &'a Path,
    pub spec: &'a PodSpec,
    pub image: &'a nucleus_spec::ImageSpec,
    pub id: Uuid,
    pub grant: &'a net::IdentityGrant,
    pub vsock_path: &'a Path,
    pub jail_owner: Option<(u32, u32)>,
    pub task_token: Option<session_mint::MintedTaskToken>,
    pub pod_certificate: Option<pod_authority::BootCertificate>,
    pub broker_serve: broker_launch::ServeToken,
}

pub(crate) async fn prepare(inputs: Inputs<'_>) -> Result<PreparedIdentity, ApiError> {
    let Inputs {
        state,
        pod_dir,
        spec,
        image,
        id,
        grant,
        vsock_path,
        jail_owner,
        task_token,
        pod_certificate,
        broker_serve,
    } = inputs;
    let identity_source = net::identity_registration(state.identity_manager.as_ref(), grant);
    let mut ready = PreparedIdentity(Some(IdentityParts {
        identity: None,
        manager: None,
        registry_key: None,
        bridge: None,
    }));
    if let Some(manager) = identity_source {
        let identity = manager.pod_identity(id);
        let registry_key = id.to_string();
        manager
            .register_pod(registry_key.clone(), identity.clone())
            .await;
        // Own registration before any further await can fail or be cancelled.
        ready.0 = Some(IdentityParts {
            identity: Some(identity.clone()),
            manager: Some(manager.clone()),
            registry_key: Some(registry_key),
            bridge: None,
        });
        // Compute launch attestation for this pod
        // This captures integrity measurements of kernel, rootfs, and config
        let pod_id_str = id.to_string();
        let config_bytes = serde_json::to_vec(spec)
            .map_err(|e| ApiError::Driver(format!("attestation config: {e}")))?;
        match manager
            .compute_attestation(
                &pod_id_str,
                &image.kernel_path,
                &image.rootfs_path,
                &config_bytes,
            )
            .await
        {
            Ok(attestation) => {
                info!(
                    "computed launch attestation for pod {}: {}",
                    id,
                    attestation.to_hex_summary()
                );
                // Cache the attested cert so the served FETCH_SVID carries the measurement;
                // else the pod serves a plain SVID an attesting relying party refuses.
                if let Err(e) = manager
                    .fetch_attested_certificate(&identity, &pod_id_str)
                    .await
                {
                    tracing::warn!(
                        "pod {id} serves a PLAIN (unattested) SVID; attesting relying parties refuse it: {e}"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    "failed to compute attestation for pod {}, using standard certificate: {}",
                    id,
                    e
                );
                // Fall back to standard certificate without attestation
                if let Err(e) = manager.prefetch_certificate(&identity).await {
                    tracing::warn!("failed to prefetch certificate for pod {}: {}", id, e);
                }
            }
        }

        let bridge = workload_api_vsock::WorkloadApiVsockBridge::start(
            vsock_path,
            state.identity_vsock_port,
            id,
            manager.clone(),
            workload_api_vsock::PodMaterial {
                pod_spec_yaml: serde_yaml::to_string(spec).ok(),
                // The same token that rides the kernel command line today.
                // Serving it here is what lets the cmdline copy go: a value
                // fetched after boot is not baked into a snapshot base.
                task_token,
                pod_certificate,
                // This pod's caller identity for the management API, derived
                // from a NODE-ONLY secret. Deliberately not `auth_secret`:
                // every proxy already holds that one, so deriving from it
                // would let any pod compute any other pod's token and the
                // mechanism would prove nothing.
                caller_token: Some(pod_caller_identity::derive_token(
                    state.caller_secret.as_ref(),
                    id,
                )),
                // Pod-scoped DLC-D admission provisioning (PodSpec labels).
                dlc_admission: workload_api_vsock::DlcAdmissionMaterial::from_labels(
                    &spec.metadata.labels,
                ),
                // The broker capability, minted per pod and served ONCE. See
                // `handle_fetch_broker_secret`: this is what lets the host
                // tell the mediating proxy from every other guest process.
                broker_secret: Some(broker_serve.into_served(id)?),
                // Served WITH the capability, not separately — the proxy
                // needs both to reach the broker and neither is useful alone.
                broker_port: state.broker_vsock_port,
                broker_secret_served: std::sync::Arc::default(),
                // Set the first time this pod is handed anything that names it; a snapshot
                // of a VM past that point would give every clone this pod's identity.
                personalized: std::sync::Arc::default(),
                at_snapshot_barrier: std::sync::Arc::default(),
                // The S3 audit-sink credentials, served once over this
                // socket instead of riding the world-readable kernel
                // command line (the C1 exposure).
                audit_creds: workload_api_vsock::AuditCredentials::from_node_env(
                    spec.spec.audit_sink.is_some(),
                ),
                audit_creds_served: std::sync::Arc::default(),
                // A per-pod ed25519 seed the guest proxy signs receipts with,
                // served ONCE before the workload exists. See `mediation`.
                mediation_signing_key: mediation::new_seed_hex(pod_dir),
                mediation_spiffe_id: Some(mediation::spiffe_id(manager.trust_domain(), id)),
                mediation_key_served: std::sync::Arc::default(),
                // Where the host durably collects SHIP_RECEIPT receipts.
                receipt_dir: Some(pod_dir.to_path_buf()),
                pod_registry: state.pods.clone(),
            },
            jail_owner,
        )
        .await
        .map_err(|e| {
            ApiError::Driver(format!("workload API must be ready before VMM spawn: {e}"))
        })?;
        info!(socket = %bridge.socket_path().display(), "workload API ready before VMM spawn");
        ready.0.as_mut().expect("guard owns registration").bridge = Some(bridge);
    }
    Ok(ready)
}
