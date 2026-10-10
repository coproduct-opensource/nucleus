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
pub(crate) struct PreparedIdentity {
    parts: Option<IdentityParts>,
    withholding: Option<crate::cred_split::Withheld>,
}

impl PreparedIdentity {
    pub(crate) fn identity(&self) -> Option<&nucleus_identity::Identity> {
        self.parts
            .as_ref()
            .and_then(|parts| parts.identity.as_ref())
    }

    /// Broker admission and binding must finish before a VMM can be spawned.
    /// A refusal consumes and drops the identity preparation (D-1, C-4).
    pub(crate) async fn with_broker(
        self,
        state: &NodeState,
        spec: &PodSpec,
        vsock_path: &Path,
        id: Uuid,
        capability: broker_launch::VerifyToken,
        jail_owner: Option<(u32, u32)>,
    ) -> Result<PreparedBroker, ApiError> {
        let egress = crate::egress_meter::EgressMeter::for_pod(
            spec,
            crate::lifecycle::pod_dir(&state.state_dir, id),
            id,
        );
        let broker = broker_launch::start_broker_for_pod(broker_launch::BrokerInputs {
            state,
            spec,
            vsock_path,
            registered: self.identity(),
            id,
            capability,
            jail_owner,
            withheld: self.withholding.as_ref(),
            egress: Arc::clone(&egress),
        })
        .await?;
        Ok(PreparedBroker {
            identity: self,
            broker,
            egress,
        })
    }

    /// Transfer cleanup responsibility to the running pod, by value (C-4).
    pub(crate) fn into_parts(mut self) -> IdentityParts {
        self.parts
            .take()
            .expect("prepared identity is consumed once")
    }
}

/// Broker readiness precedes explicit network-accounting preparation (D-1).
#[must_use]
pub(crate) struct PreparedBroker {
    identity: PreparedIdentity,
    broker: Option<broker_transport::BrokerListener>,
    egress: Arc<crate::egress_meter::EgressMeter>,
}

impl PreparedBroker {
    pub(crate) async fn with_network_meter(
        self,
        plan: Option<&net::NetPlan>,
    ) -> Result<PreparedPod, ApiError> {
        let link = match plan {
            Some(plan) => Some(crate::egress_link::LinkMonitor::start(plan, self.egress).await?),
            None => None,
        };
        Ok(PreparedPod {
            identity: self.identity,
            broker: self.broker,
            link,
        })
    }
}

/// Only completed broker and network preparation can expose VMM spawn.
#[must_use]
pub(crate) struct PreparedPod {
    identity: PreparedIdentity,
    broker: Option<broker_transport::BrokerListener>,
    link: Option<crate::egress_link::LinkMonitor>,
}

impl PreparedPod {
    pub(crate) fn spawn(
        &self,
        command: &mut tokio::process::Command,
    ) -> std::io::Result<tokio::process::Child> {
        // Any later launch error must drop a killing child, not detach a VMM.
        command.kill_on_drop(true);
        boot_trace::time_sync("firecracker.spawn", || command.spawn())
    }

    pub(crate) async fn gate(
        &self,
        addr: SocketAddr,
        pod_dir: &Path,
        spec: &PodSpec,
        id: Uuid,
        child: &mut crate::vmm_process::VmmProcess,
    ) -> Result<net::confinement::WorkloadFilesystem, ApiError> {
        let filesystem = net::confinement::gate(addr, pod_dir, spec, id, child).await?;
        if self.identity.withholding.is_some() {
            let console = tokio::fs::read_to_string(pod_dir.join("firecracker.log"))
                .await
                .map_err(|e| {
                    ApiError::Driver(format!("host spec acknowledgment unavailable: {e}"))
                })?;
            crate::cred_split::verify_guest_ack(&console)?;
        }
        Ok(filesystem)
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        IdentityParts,
        Option<broker_transport::BrokerListener>,
        Option<crate::egress_link::LinkMonitor>,
    ) {
        (self.identity.into_parts(), self.broker, self.link)
    }
}

impl Drop for PreparedIdentity {
    fn drop(&mut self) {
        if let Some(IdentityParts {
            identity,
            manager,
            registry_key,
            bridge,
        }) = self.parts.take()
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
    pub image: &'a crate::rootfs_source::HostImage,
    pub id: Uuid,
    pub grant: &'a net::IdentityGrant,
    pub vsock_path: &'a Path,
    pub jail_owner: Option<(u32, u32)>,
    pub task_token: Option<session_mint::MintedTaskToken>,
    pub pod_certificate: Option<pod_authority::BootCertificate>,
    pub broker_serve: broker_launch::ServeToken,
    /// The audit uploader's credential, minted for this pod's resolved sink (#3160). `None` when
    /// the pod has no audit sink.
    pub audit_creds: Option<workload_api_vsock::AuditCredentials>,
    /// What `image_identity::verify` read for this pod, so the attestation reports the bytes
    /// that were held to the pin rather than a second read of the same file.
    pub measured: crate::image_identity::Measured,
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
        audit_creds,
        measured,
    } = inputs;
    // An eval cell is served only a launch that verifies; each fallback below is a refusal for
    // it, never the plain SVID a standard pod keeps (ADR 0016 D3, `Demand::When(EvalCell)`).
    let profile = nucleus_spec::isolation_profile::IsolationProfile::of(spec)
        .map_err(crate::eval_cell::EvalCellRefused::from)?;
    let identity_source = net::identity_registration(state.identity_manager.as_ref(), grant);
    if identity_source.is_none() {
        crate::eval_cell::require_verified_launch(
            profile,
            crate::eval_cell::LaunchIdentity::NoIdentity,
        )?;
    }
    let mut ready = PreparedIdentity {
        parts: Some(IdentityParts {
            identity: None,
            manager: None,
            registry_key: None,
            bridge: None,
        }),
        withholding: None,
    };
    if let Some(manager) = identity_source {
        let identity = manager.pod_identity(id);
        let registry_key = id.to_string();
        manager
            .register_pod(registry_key.clone(), identity.clone())
            .await;
        // Own registration before any further await can fail or be cancelled.
        ready.parts = Some(IdentityParts {
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
                image.rootfs_path(),
                &config_bytes,
                measured,
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
                match manager
                    .fetch_attested_certificate(&identity, &pod_id_str)
                    .await
                {
                    Ok(cert) => crate::eval_cell::require_verified_launch(
                        profile,
                        crate::eval_cell::LaunchIdentity::Issued {
                            measured: &attestation,
                            leaf_der: cert.leaf().der(),
                            trust_bundle: manager.trust_bundle(),
                        },
                    )?,
                    Err(e) => {
                        crate::eval_cell::require_verified_launch(
                            profile,
                            crate::eval_cell::LaunchIdentity::NotIssued(e.clone()),
                        )?;
                        tracing::warn!(
                            "pod {id} serves a PLAIN (unattested) SVID; attesting relying parties refuse it: {e}"
                        );
                    }
                }
            }
            Err(e) => {
                crate::eval_cell::require_verified_launch(
                    profile,
                    crate::eval_cell::LaunchIdentity::NotMeasured(e.to_string()),
                )?;
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

        let (guest_spec, withheld) =
            crate::cred_split::guest_spec_yaml(spec, state.broker_enforcing.is_required())
                .map_err(|e| ApiError::Driver(format!("guest spec serialization failed: {e}")))?;
        let bridge = workload_api_vsock::WorkloadApiVsockBridge::start(
            vsock_path,
            id,
            manager.clone(),
            workload_api_vsock::PodMaterial {
                pod_spec_yaml: Some(guest_spec),
                // The same token that rides the kernel command line today.
                // Serving it here is what lets the cmdline copy go: a value
                // fetched after boot is not baked into a snapshot base.
                task_token,
                pod_certificate,
                // No caller token: a Firecracker guest cannot reach the HTTP
                // listener that reads one (see `handle_fetch_pod_caller_token`).
                // Pod-scoped DLC-D admission provisioning (PodSpec labels).
                dlc_admission: nucleus_spec::dlc_admission::DlcProvisioning::from_labels(
                    &spec.metadata.labels,
                ),
                // The broker capability, minted per pod and served ONCE. See
                // `handle_fetch_broker_secret`: this is what lets the host
                // tell the mediating proxy from every other guest process.
                broker_secret: Some(broker_serve.into_served(id)?),
                // Served WITH the capability, not separately — the proxy
                // needs both to reach the broker and neither is useful alone.
                broker_port: nucleus_ifc_kernel::VsockListener::CredentialBroker.port(),
                // Nothing served yet. Every per-pod value above that names or
                // empowers this pod goes out ONCE, to guest-init, before the
                // workload exists (#2724) — the SVID key included.
                served: workload_api_vsock::ServedLedger::new(),
                // Set the first time this pod is handed anything that names it; a snapshot
                // of a VM past that point would give every clone this pod's identity.
                personalized: std::sync::Arc::default(),
                at_snapshot_barrier: std::sync::Arc::default(),
                // The audit uploader's credential, served once over this
                // socket instead of riding the world-readable kernel
                // command line (the C1 exposure). Minted for this pod's
                // resolved sink; the node's own key is never served (#3160).
                audit_creds,
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
        ready
            .parts
            .as_mut()
            .expect("guard owns registration")
            .bridge = Some(bridge);
        ready.withholding = withheld;
    }
    Ok(ready)
}

impl FirecrackerPod {
    /// Cleans up identity resources (unregister from VM registry, forget certificate).
    pub(super) async fn cleanup_identity(&self) {
        // Revoke effects before waiting for any other identity service to drain.
        if let Some(listener) = self.broker.lock().await.as_ref() {
            listener.revoke();
        }
        // Shut down workload API bridge
        if let Some(bridge) = self.workload_api_bridge.lock().await.take() {
            bridge.shutdown().await;
        }

        // Stop the credential broker and unlink its socket. Both halves matter:
        // see `BrokerListener::shutdown`.
        if let Some(listener) = self.broker.lock().await.take() {
            let path = listener.socket_path().to_path_buf();
            if listener.shutdown().await == broker_transport::ShutdownOutcome::Aborted {
                tracing::warn!(
                    socket = %path.display(),
                    "credential broker had to be aborted at teardown — a connection outlived the \
                     shutdown signal"
                );
            }
        }

        if let Some(listener) = self.decide.lock().await.take() {
            crate::host_decide::log_teardown(&self.pod_dir, listener.shutdown().await);
        }

        // A let-chain (edition 2024) rather than a tuple of Options: it says the
        // same thing without building a throwaway tuple, and the explicit `ref`
        // bindings the tuple form needed are gone.
        if let Some(identity) = &self.identity
            && let Some(manager) = &self.identity_manager
        {
            manager
                .release_pod(self.identity_registry_key.as_deref(), identity)
                .await;
        }
    }
}
