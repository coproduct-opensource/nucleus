//! Identity management integration for nucleus-node.
//!
//! This module integrates the nucleus-identity crate to provide SPIFFE-based
//! workload identity for Firecracker VMs.
//!
//! # Launch Attestation
//!
//! When a Firecracker VM is launched, the identity manager can compute
//! launch attestation based on the kernel, rootfs, and config hashes.
//! This attestation is embedded in the SPIFFE certificate as an X.509
//! extension, enabling verifiers to ensure the workload is running in
//! an attested environment.

use nucleus_identity::{
    CaClient, Identity, LaunchAttestation, SecretManager, SelfSignedCa, VmRegistry,
    WorkloadApiClient,
};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Identity manager for the node daemon.
///
/// Wraps the SecretManager and WorkloadApiServer to provide SPIFFE identities
/// to Firecracker VMs over Unix sockets (which bridge to vsock).
#[derive(Clone)]
pub struct IdentityManager {
    /// The secret manager for certificate operations.
    secret_manager: Arc<SecretManager<Arc<dyn CaClient>>>,
    /// The CA client (needed for trust bundle access). Held as `dyn` so the node is
    /// not monomorphized to one CA type — a future hardware-rooted or SPIRE-issued
    /// root can be injected via [`IdentityManager::with_ca`].
    ca: Arc<dyn CaClient>,
    /// Registry mapping pod IDs to their SPIFFE identities.
    vm_registry: Arc<VmRegistry>,
    /// Trust domain for this node.
    trust_domain: String,
    /// Registry mapping pod IDs to their launch attestations.
    attestation_registry: Arc<RwLock<HashMap<String, LaunchAttestation>>>,
    /// Default certificate TTL.
    // Reached only from the Firecracker spawn path, which is `cfg(target_os = "linux")`.
    // On other hosts it is genuinely dead, and CI builds release binaries with
    // `RUSTFLAGS=-D warnings` (setup-rust-toolchain's default), so the warning is an
    // error that fails the macOS release job.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    cert_ttl: Duration,
    /// Base directory holding each pod's node-side state (`<dir>/<pod_id>/…`),
    /// where the node records `mediator-pubkey.hex` when it mints the pod's
    /// mediation key. When set, an attested SVID also carries a mediator-key
    /// binding extension (OID .1.4) bound to that key, so a relying party can
    /// require the pod's forensic receipts to be signed by exactly it. `None`
    /// leaves SVIDs unbound (attestation only) — a graceful default, not a
    /// failure.
    mediation_binding_dir: Option<std::path::PathBuf>,
}

impl IdentityManager {
    /// Creates a new identity manager with a self-signed CA.
    ///
    /// **The CA root this mints is EPHEMERAL** — a fresh key generated in
    /// memory, gone on process exit. Every SVID this CA issues stops
    /// verifying the moment the process restarts, because a new root is not
    /// the same trust anchor as the old one. Fine for a short-lived process
    /// (a test, a one-shot CLI invocation); wrong for a node daemon, which is
    /// why [`Self::new_with_persistent_ca`] exists. For production, this
    /// should eventually be replaced with a SPIRE CA client.
    ///
    /// The node binary itself now calls only `new_with_persistent_ca`, so
    /// this is unreachable outside `#[cfg(test)]` — where the ~20 call sites
    /// in this file and `workload_api_vsock.rs` are. Kept as the ergonomic
    /// constructor for test setup that does not want a tempdir per case.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(trust_domain: impl Into<String>, cert_ttl: Duration) -> Result<Self, String> {
        let trust_domain = trust_domain.into();
        let ca: Arc<dyn CaClient> = Arc::new(
            SelfSignedCa::new(&trust_domain)
                .map_err(|e| format!("failed to create self-signed CA: {e}"))?,
        );
        Ok(Self::with_ca(trust_domain, cert_ttl, ca))
    }

    /// Creates an identity manager whose CA root survives a process restart.
    ///
    /// Loads the root from `ca_dir` (`ca-cert.pem` + `ca-key.pem`), or mints
    /// and persists a fresh one on first run — see
    /// [`SelfSignedCa::load_or_create`] for the persistence contract,
    /// including why a corrupt or partial pair is a hard error rather than a
    /// silent regeneration.
    ///
    /// This is the constructor the node daemon uses. [`Self::new`] remains
    /// for short-lived callers (tests, one-shot CLI invocations) that do not
    /// need the root to outlive the process.
    pub fn new_with_persistent_ca(
        trust_domain: impl Into<String>,
        cert_ttl: Duration,
        ca_dir: &std::path::Path,
    ) -> Result<Self, String> {
        let trust_domain = trust_domain.into();
        let ca: Arc<dyn CaClient> = Arc::new(
            SelfSignedCa::load_or_create(&trust_domain, ca_dir)
                .map_err(|e| format!("failed to load or create persistent CA: {e}"))?,
        );
        Ok(Self::with_ca(trust_domain, cert_ttl, ca))
    }

    /// Creates an identity manager backed by an arbitrary attestation root.
    ///
    /// [`Self::new`] uses a self-signed CA; this constructor lets a host inject any
    /// [`CaClient`] — a future hardware-rooted backend (TPM DevID, cloud KMS), a
    /// SPIRE-issued root, etc. — without the node being monomorphized to one CA type.
    /// The injected CA must override `sign_attested_csr` for attested SVIDs to carry
    /// a measurement; a CA that only signs plainly yields plain SVIDs (which an
    /// attesting relying party then refuses, fail-closed).
    pub fn with_ca(
        trust_domain: impl Into<String>,
        cert_ttl: Duration,
        ca: Arc<dyn CaClient>,
    ) -> Self {
        let trust_domain = trust_domain.into();
        let secret_manager = SecretManager::new(Arc::new(ca.clone()), cert_ttl);
        let vm_registry = Arc::new(RwLock::new(HashMap::new()));

        Self {
            secret_manager,
            ca,
            vm_registry,
            trust_domain,
            attestation_registry: Arc::new(RwLock::new(HashMap::new())),
            cert_ttl,
            mediation_binding_dir: None,
        }
    }

    /// Sets the base directory (`<dir>/<pod_id>/mediator-pubkey.hex`) from which an
    /// attested SVID's mediator-key binding is read at issuance. Chainable so the
    /// node can wire it at construction; absent, SVIDs are attestation-only.
    #[must_use]
    pub fn with_mediation_binding_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.mediation_binding_dir = Some(dir);
        self
    }

    /// The mediator-key binding for a pod: `SHA-256` of the Ed25519 public key the
    /// node minted for it, read from `mediator-pubkey.hex`. `None` when no binding
    /// dir is configured or the file is absent/malformed — issuance then falls back
    /// to an attestation-only SVID rather than failing.
    // Reached only from the Firecracker spawn path, which is `cfg(target_os = "linux")`.
    // On other hosts it is genuinely dead, and CI builds release binaries with
    // `RUSTFLAGS=-D warnings` (setup-rust-toolchain's default), so the warning is an
    // error that fails the macOS release job. Same pattern as `boot_trace`/`cgroup`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn mediation_binding_for(&self, pod_id: &str) -> Option<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let dir = self.mediation_binding_dir.as_ref()?;
        let hex = std::fs::read_to_string(dir.join(pod_id).join("mediator-pubkey.hex")).ok()?;
        let pubkey = hex::decode(hex.trim()).ok()?;
        if pubkey.len() != 32 {
            return None;
        }
        Some(Sha256::digest(&pubkey).into())
    }

    /// Returns the trust domain.
    #[allow(dead_code)]
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// Returns a reference to the CA client.
    pub fn ca(&self) -> &dyn CaClient {
        self.ca.as_ref()
    }

    /// Creates a SPIFFE identity for a pod.
    #[allow(dead_code)]
    pub fn identity_for_pod(
        &self,
        pod_id: Uuid,
        namespace: &str,
        service_account: &str,
    ) -> Identity {
        // Use the service account if provided, otherwise use pod ID
        let sa = if service_account.is_empty() {
            pod_id.to_string()
        } else {
            service_account.to_string()
        };
        Identity::new(&self.trust_domain, namespace, sa)
    }

    /// The node's own SPIFFE identity: `spiffe://<trust_domain>/ns/system/sa/node`.
    ///
    /// Stable across restarts by construction (it is a pure function of
    /// `trust_domain`, not of any generated material), so a certificate
    /// minted under it is reusable across a restart as long as the CA root
    /// is also persisted — see [`Self::new_with_persistent_ca`]. Namespace
    /// `system` / service account `node` deliberately does not collide with
    /// any pod identity (`identity_for_pod` uses the pod's own namespace) or
    /// with `AuthorizationPolicy`'s orchestrator/CI-CD prefixes in `auth.rs`,
    /// which describe CLIENTS this node accepts, not the node's own identity.
    pub fn node_identity(&self) -> Identity {
        Identity::new(&self.trust_domain, "system", "node")
    }

    /// Fetches (minting and caching on first call) the node's own workload
    /// certificate, signed by this manager's CA. Reuses `SecretManager`'s
    /// existing cache and refresh machinery — same path pod certificates
    /// take, just for [`Self::node_identity`] instead of a pod's.
    ///
    /// This is what makes the node's own SVID as durable as the CA root
    /// itself: the identity is fixed, the CA persists (see
    /// [`Self::new_with_persistent_ca`]), so a certificate minted under it
    /// verifies across a restart for any peer that cached the CA's trust
    /// bundle — not just for the process that happened to mint it.
    pub async fn node_certificate(
        &self,
    ) -> Result<std::sync::Arc<nucleus_identity::WorkloadCertificate>, String> {
        self.fetch_certificate(&self.node_identity()).await
    }

    /// Builds a self-issued mTLS config for the node's HTTP API: the node's
    /// own certificate as server identity, and this CA's trust bundle as the
    /// root a client certificate must chain to.
    ///
    /// Unlike [`crate::grpc_tls::GrpcTlsConfig::from_node_identity`]
    /// (server-only), this is full mTLS: `nucleus_identity::mtls::MtlsListener`
    /// always requires a client certificate (`TlsServerConfig::build_acceptor`
    /// builds its verifier without `allow_unauthenticated`) — so a caller with
    /// no SVID cannot connect at all. Correct once the CLI has one (Move A
    /// step 5); until then, `--http-mtls-self-issued` is an opt-in mode an
    /// operator enables knowing that. Using THIS manager's own CA as the
    /// trust root (rather than requiring separately-provisioned trust-bundle
    /// files, as the tool-proxy's `--trust-bundle` does) is deliberate: once
    /// step 5 lands, the CLI's SVID is issued by this same CA, so no further
    /// wiring is needed here for the trust relationship to already be correct.
    pub async fn self_issued_http_mtls_config(
        &self,
    ) -> Result<nucleus_identity::mtls::MtlsConfig, String> {
        let cert = self.node_certificate().await?;
        let trust_bundle = self.ca().trust_bundle().clone();
        Ok(nucleus_identity::mtls::MtlsConfig::new(
            (*cert).clone(),
            trust_bundle,
        ))
    }

    /// Wraps `tcp_listener` in a self-issued mTLS listener built from
    /// [`Self::self_issued_http_mtls_config`]. What `--http-mtls-self-issued`
    /// uses to build the transport before `axum::serve` runs — kept here
    /// rather than inline in `main.rs`'s already-large boot sequence, since
    /// "how do I present myself over TLS" is this type's own responsibility,
    /// the same reasoning as [`Self::node_certificate`].
    pub async fn self_issued_http_mtls_listener(
        &self,
        tcp_listener: tokio::net::TcpListener,
    ) -> Result<nucleus_identity::mtls::MtlsListener, String> {
        let mtls_config = self.self_issued_http_mtls_config().await?;
        nucleus_identity::mtls::MtlsListener::new(tcp_listener, &mtls_config)
            .map_err(|e| format!("failed to create HTTP mTLS listener: {e}"))
    }

    /// Rebuild the VM registry from the pods already on disk.
    ///
    /// # Why derive instead of journalling
    ///
    /// A node restart used to orphan every running pod from the identity
    /// registry: `VmRegistry` is an in-memory `HashMap` and nothing repopulated
    /// it (#1641). The issue proposed appending each registration to a JSONL and
    /// replaying it, with deriving from pod state as the alternative.
    ///
    /// Derivation wins here, and not only for having fewer moving parts. A
    /// journal is a SECOND record of which pods exist, next to `state_dir/pods/`,
    /// which is already the first. Two records that must agree is the shape that
    /// drifts: a pod that dies leaves a stale line, a pod created between the
    /// append and the crash leaves none, and the journal is then confidently
    /// wrong in both directions. Deriving cannot disagree with the directory it
    /// reads. It is also what kubelet does — re-discover running pods from the
    /// runtime on restart rather than replay a log.
    ///
    /// Nothing new is written: `pod.yaml` is already persisted per pod, and the
    /// identity is a pure function of it plus the node's trust domain.
    ///
    /// # It restores identity RESOLUTION, not liveness
    ///
    /// A pod directory can outlive its microVM, so this may register an identity
    /// for a pod that is gone. That is deliberate, and the asymmetry is the
    /// argument: a stale entry is inert, because the key is the pod's UUID and
    /// nothing will ever present it again. A MISSING entry for a live pod is the
    /// actual defect — the pod cannot resolve its own identity. Erring toward
    /// registering is the fail-safe direction.
    ///
    /// Returns how many pods were restored.
    pub async fn rebuild_registry_from_disk(&self, state_dir: &std::path::Path) -> usize {
        let pods_dir = state_dir.join("pods");
        let Ok(mut entries) = tokio::fs::read_dir(&pods_dir).await else {
            return 0;
        };

        let mut restored = 0usize;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let dir = entry.path();
            let Some(pod_id) = dir.file_name().and_then(|n| n.to_str()).map(str::to_owned) else {
                continue;
            };
            // A directory with no spec is not a pod this node launched.
            let Ok(yaml) = tokio::fs::read_to_string(dir.join("pod.yaml")).await else {
                continue;
            };
            let Some(identity) = self.identity_from_spec_yaml(&pod_id, &yaml) else {
                continue;
            };
            self.register_pod(pod_id, identity).await;
            restored += 1;
        }
        restored
    }

    /// The identity a pod spec yields, derived exactly as the launch path does.
    ///
    /// Split out and kept pure so the restored identity can be tested against
    /// the one `identity_for_pod` mints live. If these two ever disagree, a pod
    /// would come back after a restart under a DIFFERENT SPIFFE ID than it had
    /// before, which is worse than not coming back at all.
    fn identity_from_spec_yaml(&self, pod_id: &str, yaml: &str) -> Option<Identity> {
        let spec: serde_yaml::Value = serde_yaml::from_str(yaml).ok()?;
        let meta = spec.get("metadata");
        let namespace = meta
            .and_then(|m| m.get("namespace"))
            .and_then(|v| v.as_str())
            .unwrap_or("default");
        let name = meta
            .and_then(|m| m.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        // Mirrors identity_for_pod: an empty service account falls back to the
        // pod id.
        let sa = if name.is_empty() { pod_id } else { name };
        Some(Identity::new(&self.trust_domain, namespace, sa))
    }

    /// Registers a pod's identity in the VM registry.
    #[allow(dead_code)]
    pub async fn register_pod(&self, connection_id: impl Into<String>, identity: Identity) {
        let mut registry = self.vm_registry.write().await;
        registry.insert(connection_id.into(), identity);
    }

    /// Unregisters a pod from the VM registry.
    ///
    /// Returns whether an entry was actually removed. `HashMap::remove` reports
    /// this and the result used to be discarded, which is precisely how the
    /// registry came to never drain: teardown removed by the pod's SPIFFE URI
    /// while registration inserted under the pod's UUID, the two never matched,
    /// and the no-op was invisible at every call site.
    ///
    /// `#[must_use]` so a caller cannot reintroduce that silence without saying
    /// so in the code. A wrong key is a bug either way; the difference is whether
    /// anyone finds out.
    #[must_use = "a false return means NOTHING was removed -- usually a wrong key"]
    #[allow(dead_code)]
    pub async fn unregister_pod(&self, connection_id: &str) -> bool {
        let mut registry = self.vm_registry.write().await;
        registry.remove(connection_id).is_some()
    }

    /// Release everything this pod held in the identity subsystem.
    ///
    /// Takes the key registration actually USED rather than re-deriving one, and
    /// keeps the "did anything get removed?" check beside the registry it
    /// concerns. Both call sites of that check now live in this module, so a
    /// future key change has one place to be wrong instead of two.
    pub async fn release_pod(&self, registry_key: Option<&str>, identity: &Identity) {
        if let Some(key) = registry_key
            && !self.unregister_pod(key).await
        {
            // Reachable only if the key drifted again. Worth a warning
            // rather than a silent no-op: a registry that does not drain is
            // what makes the Workload API's "exactly one identity is
            // registered" precondition permanently false.
            tracing::warn!(
                registry_key = %key,
                "pod teardown removed no identity registry entry -- the \
                 registration and removal keys have drifted apart"
            );
        }
        self.forget_certificate(identity).await;
    }

    // `start_workload_api_server` was removed here, not merely left uncalled.
    //
    // It was the only thing that invoked `WorkloadApiServer::serve`, the
    // deprecated registry-lookup path that handed an arbitrary pod's SVID to any
    // local connector (#2197). Deleting it means the node cannot open that socket
    // by anyone re-adding a call site, which a commented-out invocation or an
    // unused function would still allow.

    /// Starts the certificate refresh loop in the background.
    #[allow(dead_code)]
    pub fn start_refresh_loop(&self) {
        let manager = self.secret_manager.clone();
        tokio::spawn(async move {
            manager.run_refresh_loop().await;
        });
    }

    /// Pre-fetches a certificate for the given identity.
    ///
    /// This is useful to warm the cache before the VM starts requesting certificates.
    #[allow(dead_code)]
    pub async fn prefetch_certificate(&self, identity: &Identity) -> Result<(), String> {
        self.secret_manager
            .fetch_certificate(identity)
            .await
            .map(|_| ())
            .map_err(|e| format!("failed to prefetch certificate: {e}"))
    }

    /// Fetches a certificate for the given identity, returning the certificate.
    ///
    /// Uses the cache if available, otherwise generates a new certificate.
    /// Live path: `--grpc-tls-self-issued` reaches this via
    /// [`Self::node_certificate`].
    pub async fn fetch_certificate(
        &self,
        identity: &Identity,
    ) -> Result<std::sync::Arc<nucleus_identity::WorkloadCertificate>, String> {
        self.secret_manager
            .fetch_certificate(identity)
            .await
            .map_err(|e| format!("failed to fetch certificate: {e}"))
    }

    /// Forgets a certificate for the given identity.
    ///
    /// Called when a pod is terminated to clean up cached certificates.
    #[allow(dead_code)]
    pub async fn forget_certificate(&self, identity: &Identity) {
        self.secret_manager.forget_certificate(identity).await;
    }

    /// Returns the trust bundle (root CA certificates).
    #[allow(dead_code)]
    /// The underlying certificate manager.
    ///
    /// Exposed so the SPIFFE Workload API service can source SVIDs from the
    /// SAME issuance and cache path as the JSON protocol, rather than opening a
    /// second one. Two issuance paths would be two things to keep conformant.
    pub fn secret_manager(&self) -> Arc<SecretManager<Arc<dyn CaClient>>> {
        self.secret_manager.clone()
    }

    pub fn trust_bundle(&self) -> &nucleus_identity::TrustBundle {
        self.ca.trust_bundle()
    }

    /// Computes and stores launch attestation for a pod.
    ///
    /// This should be called before launching a Firecracker VM to capture
    /// the integrity measurements of the kernel, rootfs, and configuration.
    ///
    /// # Arguments
    ///
    /// * `pod_id` - Unique identifier for the pod
    /// * `kernel_path` - Path to the kernel image
    /// * `rootfs_path` - Path to the root filesystem
    /// * `config` - Serialized pod configuration (PodSpec + policy)
    ///
    /// # Returns
    ///
    /// The computed attestation, or an error if hashing fails.
    #[allow(dead_code)]
    #[tracing::instrument(skip_all, fields(boot.stage = "attestation.hash"))]
    pub async fn compute_attestation(
        &self,
        pod_id: &str,
        kernel_path: &Path,
        rootfs_path: &Path,
        config: &[u8],
    ) -> Result<LaunchAttestation, String> {
        info!(
            "computing launch attestation for pod {} (kernel={}, rootfs={})",
            pod_id,
            kernel_path.display(),
            rootfs_path.display()
        );

        let attestation = LaunchAttestation::compute(kernel_path, rootfs_path, config)
            .await
            .map_err(|e| format!("failed to compute attestation: {e}"))?;

        debug!(
            "attestation computed for pod {}: {}",
            pod_id,
            attestation.to_hex_summary()
        );

        // Store in registry
        let mut registry = self.attestation_registry.write().await;
        registry.insert(pod_id.to_string(), attestation.clone());

        Ok(attestation)
    }

    /// Retrieves stored attestation for a pod.
    #[allow(dead_code)]
    pub async fn get_attestation(&self, pod_id: &str) -> Option<LaunchAttestation> {
        let registry = self.attestation_registry.read().await;
        registry.get(pod_id).cloned()
    }

    /// Removes stored attestation for a pod.
    #[allow(dead_code)]
    pub async fn forget_attestation(&self, pod_id: &str) {
        let mut registry = self.attestation_registry.write().await;
        if registry.remove(pod_id).is_some() {
            debug!("forgot attestation for pod {}", pod_id);
        }
    }

    /// Fetches an attested certificate for the given identity and pod.
    ///
    /// If attestation exists for the pod, it will be embedded in the certificate as
    /// an X.509 extension, and the result is written into the shared certificate
    /// cache so the served `FETCH_SVID` path returns the *attested* cert rather than
    /// a plain one. If no attestation is registered, falls back to a standard cert.
    #[tracing::instrument(skip_all, fields(boot.stage = "cert.issue"))]
    // Reached only from the Firecracker spawn path, which is `cfg(target_os = "linux")`.
    // On other hosts it is genuinely dead, and CI builds release binaries with
    // `RUSTFLAGS=-D warnings` (setup-rust-toolchain's default), so the warning is an
    // error that fails the macOS release job.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub async fn fetch_attested_certificate(
        &self,
        identity: &Identity,
        pod_id: &str,
    ) -> Result<std::sync::Arc<nucleus_identity::WorkloadCertificate>, String> {
        // Check if we have attestation for this pod
        let attestation = {
            let registry = self.attestation_registry.read().await;
            registry.get(pod_id).cloned()
        };

        match attestation {
            Some(att) => {
                info!(
                    "fetching attested certificate for {} (pod {})",
                    identity, pod_id
                );

                // Generate CSR
                let csr_options = nucleus_identity::CsrOptions::new(identity.to_spiffe_uri());
                let cert_sign = csr_options
                    .generate()
                    .map_err(|e| format!("CSR generation failed: {e}"))?;

                // Sign with attestation using configured TTL. When the pod has a
                // minted mediation key, ALSO bind it into the SVID (OID .1.4) so a
                // relying party can require the pod's receipts to be signed by that
                // exact key; otherwise a plain attested SVID.
                let cert = match self.mediation_binding_for(pod_id) {
                    Some(binding) => {
                        info!("binding mediation key into attested SVID for pod {pod_id}");
                        self.ca
                            .sign_attested_and_bound_csr(
                                cert_sign.csr(),
                                cert_sign.private_key(),
                                identity,
                                self.cert_ttl,
                                &att,
                                &binding,
                            )
                            .await
                    }
                    None => {
                        self.ca
                            .sign_attested_csr(
                                cert_sign.csr(),
                                cert_sign.private_key(),
                                identity,
                                self.cert_ttl,
                                &att,
                            )
                            .await
                    }
                }
                .map_err(|e| format!("attested signing failed: {e}"))?;

                // Warm the cache so the served FETCH_SVID fast-path returns THIS
                // attested cert (carrying the measurement), not the plain one.
                let cert = std::sync::Arc::new(cert);
                self.secret_manager
                    .cache_certificate(identity, cert.clone())
                    .await;
                Ok(cert)
            }
            None => {
                warn!(
                    "no attestation found for pod {}, using standard certificate",
                    pod_id
                );
                self.fetch_certificate(identity).await
            }
        }
    }

    /// Creates a Workload API client for the given socket path.
    #[allow(dead_code)]
    pub fn client(socket_path: impl Into<std::path::PathBuf>) -> WorkloadApiClient {
        WorkloadApiClient::new(socket_path)
    }
}

impl std::fmt::Debug for IdentityManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityManager")
            .field("trust_domain", &self.trust_domain)
            .finish()
    }
}

#[cfg(test)]
mod tests {

    // ── registry survives a node restart (#1641) ─────────────────────────────

    fn write_pod(state_dir: &std::path::Path, pod_id: &str, yaml: &str) {
        let d = state_dir.join("pods").join(pod_id);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("pod.yaml"), yaml).unwrap();
    }

    /// The property that matters: a restored identity must be the SAME one the
    /// launch path minted. If they differed, a pod would come back after a
    /// restart under a different SPIFFE ID than it had before — worse than not
    /// coming back at all, because the mismatch is silent.
    #[tokio::test]
    async fn a_restored_identity_equals_the_one_the_launch_path_mints() {
        let tmp = tempfile::tempdir().unwrap();
        let pod_id = uuid::Uuid::new_v4();
        write_pod(
            tmp.path(),
            &pod_id.to_string(),
            "apiVersion: nucleus/v1\nkind: Pod\nmetadata:\n  name: web\n  namespace: prod\n",
        );

        let m = IdentityManager::new("nucleus.local", Duration::from_secs(3600)).unwrap();
        let live = m.identity_for_pod(pod_id, "prod", "web");

        assert_eq!(m.rebuild_registry_from_disk(tmp.path()).await, 1);
        let restored = m
            .vm_registry
            .read()
            .await
            .get(&pod_id.to_string())
            .cloned()
            .expect("pod must be in the registry after a rebuild");

        assert_eq!(
            restored, live,
            "a restored identity must match what the launch path mints for the same spec"
        );
    }

    /// The launch path falls back to the pod id when the spec has no name. The
    /// rebuild has to make the same choice or the SPIFFE ID changes.
    #[tokio::test]
    async fn a_spec_with_no_name_falls_back_to_the_pod_id_on_both_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let pod_id = uuid::Uuid::new_v4();
        write_pod(
            tmp.path(),
            &pod_id.to_string(),
            "apiVersion: nucleus/v1\nkind: Pod\n",
        );

        let m = IdentityManager::new("nucleus.local", Duration::from_secs(3600)).unwrap();
        assert_eq!(m.rebuild_registry_from_disk(tmp.path()).await, 1);

        let restored = m
            .vm_registry
            .read()
            .await
            .get(&pod_id.to_string())
            .cloned()
            .unwrap();
        assert_eq!(restored, m.identity_for_pod(pod_id, "default", ""));
    }

    /// Non-vacuity. Without these, `rebuild` returning 0 on everything would
    /// satisfy the tests above only by accident of them writing a pod first.
    #[tokio::test]
    async fn a_directory_with_no_pods_restores_nothing_and_does_not_fail() {
        let tmp = tempfile::tempdir().unwrap();
        let m = IdentityManager::new("nucleus.local", Duration::from_secs(3600)).unwrap();
        // No pods/ dir at all — a fresh node.
        assert_eq!(m.rebuild_registry_from_disk(tmp.path()).await, 0);

        // A directory that is not a pod: present, but no spec to derive from.
        std::fs::create_dir_all(tmp.path().join("pods").join("not-a-pod")).unwrap();
        assert_eq!(
            m.rebuild_registry_from_disk(tmp.path()).await,
            0,
            "a directory with no pod.yaml is not a pod this node launched"
        );
    }

    /// Several pods, so the count is not passing on a single-entry special case.
    #[tokio::test]
    async fn every_pod_on_disk_comes_back() {
        let tmp = tempfile::tempdir().unwrap();
        let ids: Vec<uuid::Uuid> = (0..3).map(|_| uuid::Uuid::new_v4()).collect();
        for (n, id) in ids.iter().enumerate() {
            write_pod(
                tmp.path(),
                &id.to_string(),
                &format!("metadata:\n  name: pod{n}\n  namespace: ns{n}\n"),
            );
        }

        let m = IdentityManager::new("nucleus.local", Duration::from_secs(3600)).unwrap();
        assert_eq!(m.rebuild_registry_from_disk(tmp.path()).await, 3);

        let reg = m.vm_registry.read().await;
        for (n, id) in ids.iter().enumerate() {
            let got = reg.get(&id.to_string()).expect("every pod must come back");
            assert_eq!(
                got,
                &m.identity_for_pod(*id, &format!("ns{n}"), &format!("pod{n}"))
            );
        }
    }

    use super::*;

    #[tokio::test]
    async fn test_identity_manager_creation() {
        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        assert_eq!(manager.trust_domain(), "test.local");
    }

    /// `new_with_persistent_ca` is what the node binary actually calls now.
    /// The property that matters: a second manager built against the SAME
    /// directory issues SVIDs a client trusting the FIRST manager's root
    /// still accepts -- i.e. it is the same trust anchor, not merely a
    /// second CA that happens to look similar. Covers the wiring in
    /// `main.rs`; `SelfSignedCa`'s own persistence contract is covered in
    /// `nucleus-identity`'s `ca::self_signed::tests::persistence`.
    #[tokio::test]
    async fn a_node_restart_keeps_issuing_under_the_same_root() {
        use nucleus_identity::certificate::Certificate;
        use nucleus_identity::{TrustBundle, verify_svid_chain};

        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");

        let first = IdentityManager::new_with_persistent_ca(
            "nucleus.local",
            Duration::from_secs(3600),
            &ca_dir,
        )
        .unwrap();
        let first_root_pem = first.ca.trust_bundle().roots()[0].to_pem().to_string();
        let first_bundle = TrustBundle::new(vec![Certificate::from_pem(&first_root_pem).unwrap()]);

        // Simulates a restart: a fresh `IdentityManager` built from scratch
        // against the same directory, as `main.rs` does on every boot.
        let second = IdentityManager::new_with_persistent_ca(
            "nucleus.local",
            Duration::from_secs(3600),
            &ca_dir,
        )
        .unwrap();

        let identity = second.identity_for_pod(Uuid::new_v4(), "default", "post-restart-service");
        let cert = second.fetch_certificate(&identity).await.unwrap();

        verify_svid_chain(cert.leaf(), &first_bundle).expect(
            "an SVID issued after a simulated restart must verify against the pre-restart root",
        );
    }

    /// The node's own identity is stable (a pure function of trust domain,
    /// not of generated material) and `node_certificate` mints under it.
    /// This is what `--grpc-tls-self-issued` relies on in `main.rs`.
    #[tokio::test]
    async fn node_certificate_is_minted_under_the_stable_node_identity() {
        let manager = IdentityManager::new("nucleus.local", Duration::from_secs(3600)).unwrap();

        let identity = manager.node_identity();
        assert_eq!(
            identity.to_spiffe_uri(),
            "spiffe://nucleus.local/ns/system/sa/node"
        );

        let cert = manager.node_certificate().await.unwrap();
        assert_eq!(cert.identity(), &identity);
    }

    /// Combines the node-identity and CA-persistence properties: a
    /// self-issued cert minted AFTER a simulated restart verifies against a
    /// trust bundle built from the PRE-restart root, because both the
    /// identity (pure function of trust domain) and the CA root (persisted,
    /// see `a_node_restart_keeps_issuing_under_the_same_root`) survive it.
    #[tokio::test]
    async fn a_self_issued_node_certificate_survives_a_restart() {
        use nucleus_identity::certificate::Certificate;
        use nucleus_identity::{TrustBundle, verify_svid_chain};

        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");

        let first = IdentityManager::new_with_persistent_ca(
            "nucleus.local",
            Duration::from_secs(3600),
            &ca_dir,
        )
        .unwrap();
        let first_root_pem = first.ca().trust_bundle().roots()[0].to_pem().to_string();
        let first_bundle = TrustBundle::new(vec![Certificate::from_pem(&first_root_pem).unwrap()]);

        let second = IdentityManager::new_with_persistent_ca(
            "nucleus.local",
            Duration::from_secs(3600),
            &ca_dir,
        )
        .unwrap();
        let cert = second.node_certificate().await.unwrap();

        verify_svid_chain(cert.leaf(), &first_bundle).expect(
            "a self-issued node cert minted after a simulated restart must verify against \
             the pre-restart root",
        );
    }

    /// The property `--http-mtls-self-issued` depends on, proven with a REAL
    /// TLS handshake rather than inspecting the config's fields: a peer whose
    /// certificate was minted by this SAME CA (a pod, say) completes a full
    /// mTLS handshake against the config `self_issued_http_mtls_config`
    /// builds; a peer from an unrelated CA is refused. Satisfy-before-refute:
    /// the positive case is checked first, so a config that accepts nothing
    /// could not pass this by accident.
    #[tokio::test]
    async fn self_issued_http_mtls_config_accepts_same_ca_and_refuses_a_stranger() {
        use nucleus_identity::{
            CaClient, CsrOptions, SelfSignedCa, TlsClientConfig, TlsServerConfig,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let dir = tempfile::tempdir().unwrap();
        let manager = IdentityManager::new_with_persistent_ca(
            "nucleus.local",
            Duration::from_secs(3600),
            &dir.path().join("ca"),
        )
        .unwrap();
        let mtls_config = manager.self_issued_http_mtls_config().await.unwrap();

        // A peer minted by the SAME CA -- the shape a real pod SVID has.
        let same_ca_identity = manager.identity_for_pod(Uuid::new_v4(), "default", "same-ca-peer");
        let same_ca_cert = manager.fetch_certificate(&same_ca_identity).await.unwrap();

        // --- positive: same-CA peer completes a real handshake ---
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server_cert = mtls_config.server_cert.clone();
            let server_trust_bundle = mtls_config.trust_bundle.clone();
            let server_handle = tokio::spawn(async move {
                let (stream, _peer) = listener.accept().await.unwrap();
                let acceptor = TlsServerConfig::new(server_cert, server_trust_bundle)
                    .build_acceptor()
                    .unwrap();
                let mut tls = acceptor.accept(stream).await.unwrap();
                let mut buf = [0u8; 5];
                tls.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"hello");
                tls.write_all(b"ok").await.unwrap();
            });

            let client_trust_bundle = mtls_config.trust_bundle.clone();
            let stream = TcpStream::connect(addr).await.unwrap();
            let connector = TlsClientConfig::new((*same_ca_cert).clone(), client_trust_bundle)
                .with_spiffe_trust_domain("nucleus.local")
                .build_connector()
                .unwrap();
            let server_name =
                rustls::pki_types::ServerName::try_from("nucleus.local".to_string()).unwrap();
            let mut tls = connector
                .connect(server_name, stream)
                .await
                .expect("a peer certified by the SAME CA must complete the handshake");
            tls.write_all(b"hello").await.unwrap();
            let mut buf = [0u8; 2];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ok");

            server_handle.await.unwrap();
        }

        // --- negative: a stranger from an unrelated CA is refused ---
        {
            let stranger_ca = SelfSignedCa::new("nucleus.local").unwrap();
            let stranger_identity = Identity::new("nucleus.local", "default", "stranger");
            let stranger_csr = CsrOptions::new(stranger_identity.to_spiffe_uri())
                .generate()
                .unwrap();
            let stranger_cert = stranger_ca
                .sign_csr(
                    stranger_csr.csr(),
                    stranger_csr.private_key(),
                    &stranger_identity,
                    Duration::from_secs(3600),
                )
                .await
                .unwrap();
            let stranger_trust_bundle = stranger_ca.trust_bundle().clone();

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server_cert = mtls_config.server_cert.clone();
            let server_trust_bundle = mtls_config.trust_bundle.clone();
            let server_handle = tokio::spawn(async move {
                let (stream, _peer) = listener.accept().await.unwrap();
                let acceptor = TlsServerConfig::new(server_cert, server_trust_bundle)
                    .build_acceptor()
                    .unwrap();
                let result = acceptor.accept(stream).await;
                assert!(result.is_err(), "a stranger's certificate must be refused");
            });

            let stream = TcpStream::connect(addr).await.unwrap();
            let connector = TlsClientConfig::new(stranger_cert, stranger_trust_bundle)
                .with_spiffe_trust_domain("nucleus.local")
                .build_connector()
                .unwrap();
            let server_name =
                rustls::pki_types::ServerName::try_from("nucleus.local".to_string()).unwrap();
            // Either side may be the one that observes the failure first
            // (the stranger's trust bundle doesn't contain the real server's
            // CA either) -- both outcomes are the property under test.
            let _ = connector.connect(server_name, stream).await;

            server_handle.await.unwrap();
        }
    }

    /// C9 Phase 0: a CA injected via `with_ca` (as `Arc<dyn CaClient>`) flows through
    /// the `dyn` seam AND still embeds launch attestation — proving the blanket
    /// `impl CaClient for Arc<dyn CaClient>` forwards `sign_attested_csr` to the
    /// concrete override rather than the extension-dropping trait default.
    #[tokio::test]
    async fn with_ca_injects_a_root_that_still_attests_through_the_dyn_seam() {
        use nucleus_identity::{AttestationRequirements, SelfSignedCa, verify_attested_svid};
        use std::io::Write;

        let injected: Arc<dyn CaClient> = Arc::new(SelfSignedCa::new("injected.local").unwrap());
        let manager =
            IdentityManager::with_ca("injected.local", Duration::from_secs(3600), injected);
        assert_eq!(manager.trust_domain(), "injected.local");

        let mut kernel = tempfile::NamedTempFile::new().unwrap();
        kernel.write_all(b"k").unwrap();
        let mut rootfs = tempfile::NamedTempFile::new().unwrap();
        rootfs.write_all(b"r").unwrap();

        let pod = Uuid::new_v4();
        let id = manager.identity_for_pod(pod, "default", "svc");
        let att = manager
            .compute_attestation(&pod.to_string(), kernel.path(), rootfs.path(), b"cfg")
            .await
            .expect("attest");
        manager
            .fetch_attested_certificate(&id, &pod.to_string())
            .await
            .expect("issue attested cert via injected dyn CA");

        // The served cert (from the cache the injected CA wrote through) must carry
        // the measurement — i.e. the dyn seam did NOT drop the attestation.
        let chain = manager
            .fetch_certificate(&id)
            .await
            .expect("served")
            .chain_pem();
        let req = AttestationRequirements::exact(
            *att.kernel_hash(),
            *att.rootfs_hash(),
            *att.config_hash(),
        );
        assert!(
            verify_attested_svid(&chain, &req, true)
                .expect("verify ok")
                .is_some(),
            "injected dyn CA must still embed the launch attestation"
        );
    }

    /// North Star C9 (Inc 1): an attested SVID is served over the real cache path a
    /// pod's `FETCH_SVID` reads, and a shipped relying-party verifier reds on
    /// measurement drift and on an absent extension (fail-closed) — while passing
    /// the correct measurement (non-vacuous). KVM-free: exercises the same
    /// `fetch_certificate` fast-path the workload API serves, minus the UDS
    /// transport and a real Firecracker rootfs (named gaps in the ledger).
    #[tokio::test]
    async fn attested_svid_is_served_and_verifier_reds_on_drift_and_absent() {
        use nucleus_identity::{AttestationRequirements, verify_attested_svid};
        use std::io::Write;

        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();

        // Two temp "images" the node measures, plus a config blob.
        let mut kernel = tempfile::NamedTempFile::new().unwrap();
        kernel.write_all(b"kernel-image-bytes").unwrap();
        let mut rootfs = tempfile::NamedTempFile::new().unwrap();
        rootfs.write_all(b"rootfs-image-bytes").unwrap();
        let config = b"pod-config-blob";

        // Attested pod: measure, then issue+cache the attested cert.
        let attested_pod = Uuid::new_v4();
        let attested_id = manager.identity_for_pod(attested_pod, "default", "attested");
        let att = manager
            .compute_attestation(
                &attested_pod.to_string(),
                kernel.path(),
                rootfs.path(),
                config,
            )
            .await
            .expect("attestation computes");
        manager
            .fetch_attested_certificate(&attested_id, &attested_pod.to_string())
            .await
            .expect("attested cert issues");

        // The SERVED path: fetch_certificate is exactly what FETCH_SVID calls. After
        // caching it must return the ATTESTED cert (carrying the measurement).
        let chain = manager
            .fetch_certificate(&attested_id)
            .await
            .expect("served cert")
            .chain_pem();

        let expected = AttestationRequirements::exact(
            *att.kernel_hash(),
            *att.rootfs_hash(),
            *att.config_hash(),
        );

        // (i) POSITIVE CONTROL — correct expectation verifies (proves it is not
        //     always-red: teeth (ii)/(iii) below then mean something).
        assert!(
            verify_attested_svid(&chain, &expected, true)
                .expect("correct measurement verifies")
                .is_some(),
            "served SVID must carry the launch attestation"
        );

        // (ii) TEETH — one byte of drift in the expected artifact reds the verifier.
        let mut wrong_kernel = *att.kernel_hash();
        wrong_kernel[0] ^= 0x01;
        let drifted =
            AttestationRequirements::exact(wrong_kernel, *att.rootfs_hash(), *att.config_hash());
        assert!(
            verify_attested_svid(&chain, &drifted, true).is_err(),
            "one byte of measurement drift must red the verifier"
        );

        // (iii) TEETH — a plain (unattested) pod's SVID fails closed when required,
        //       and yields no attestation (not a spurious one) when not required.
        let plain_pod = Uuid::new_v4();
        let plain_id = manager.identity_for_pod(plain_pod, "default", "plain");
        let plain_chain = manager
            .fetch_certificate(&plain_id)
            .await
            .expect("plain cert")
            .chain_pem();
        assert!(
            verify_attested_svid(&plain_chain, &AttestationRequirements::any(), true).is_err(),
            "absent extension + require_attestation must fail closed"
        );
        assert!(
            verify_attested_svid(&plain_chain, &AttestationRequirements::any(), false)
                .expect("absent-not-required is ok")
                .is_none(),
            "absent extension without requirement yields no attestation"
        );
    }

    #[tokio::test]
    async fn test_identity_for_pod() {
        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let pod_id = Uuid::new_v4();

        let identity = manager.identity_for_pod(pod_id, "default", "my-service");
        assert_eq!(identity.trust_domain(), "test.local");
        assert_eq!(identity.namespace(), "default");
        assert_eq!(identity.service_account(), "my-service");
    }

    #[tokio::test]
    async fn test_identity_for_pod_no_service_account() {
        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let pod_id = Uuid::new_v4();

        let identity = manager.identity_for_pod(pod_id, "default", "");
        assert_eq!(identity.service_account(), pod_id.to_string());
    }

    #[tokio::test]
    async fn test_pod_registration() {
        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let pod_id = Uuid::new_v4();
        let identity = manager.identity_for_pod(pod_id, "default", "my-service");

        manager
            .register_pod(pod_id.to_string(), identity.clone())
            .await;

        // Verify registration
        let registry = manager.vm_registry.read().await;
        assert!(registry.contains_key(&pod_id.to_string()));
        assert_eq!(registry.get(&pod_id.to_string()), Some(&identity));
        drop(registry);

        // Unregister
        assert!(
            manager.unregister_pod(&pod_id.to_string()).await,
            "the pod was registered under this key, so removal must report a hit"
        );
        let registry = manager.vm_registry.read().await;
        assert!(!registry.contains_key(&pod_id.to_string()));
    }

    #[tokio::test]
    async fn test_prefetch_certificate() {
        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let identity = Identity::new("test.local", "default", "my-service");

        // Should succeed - CA will sign the certificate
        manager.prefetch_certificate(&identity).await.unwrap();
    }

    #[tokio::test]
    async fn test_compute_attestation() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();

        // Create temp files for kernel and rootfs
        let mut kernel = NamedTempFile::new().unwrap();
        kernel.write_all(b"fake kernel image").unwrap();

        let mut rootfs = NamedTempFile::new().unwrap();
        rootfs.write_all(b"fake rootfs image").unwrap();

        let config = b"pod spec yaml content";
        let pod_id = "test-pod-123";

        // Compute attestation
        let attestation = manager
            .compute_attestation(pod_id, kernel.path(), rootfs.path(), config)
            .await
            .unwrap();

        // Verify attestation is non-trivial
        assert_ne!(attestation.kernel_hash(), &[0u8; 32]);
        assert_ne!(attestation.rootfs_hash(), &[0u8; 32]);
        assert_ne!(attestation.config_hash(), &[0u8; 32]);

        // Verify it's stored in registry
        let stored = manager.get_attestation(pod_id).await;
        assert!(stored.is_some());
        assert_eq!(stored.unwrap().kernel_hash(), attestation.kernel_hash());
    }

    #[tokio::test]
    async fn test_forget_attestation() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();

        let mut kernel = NamedTempFile::new().unwrap();
        kernel.write_all(b"kernel").unwrap();

        let mut rootfs = NamedTempFile::new().unwrap();
        rootfs.write_all(b"rootfs").unwrap();

        let pod_id = "pod-to-forget";

        // Compute and store
        manager
            .compute_attestation(pod_id, kernel.path(), rootfs.path(), b"config")
            .await
            .unwrap();
        assert!(manager.get_attestation(pod_id).await.is_some());

        // Forget
        manager.forget_attestation(pod_id).await;
        assert!(manager.get_attestation(pod_id).await.is_none());
    }

    #[tokio::test]
    async fn test_fetch_attested_certificate() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();

        let mut kernel = NamedTempFile::new().unwrap();
        kernel.write_all(b"kernel").unwrap();

        let mut rootfs = NamedTempFile::new().unwrap();
        rootfs.write_all(b"rootfs").unwrap();

        let pod_id = "attested-pod";
        let identity = Identity::new("test.local", "default", "attested-service");

        // Compute attestation first
        manager
            .compute_attestation(pod_id, kernel.path(), rootfs.path(), b"config")
            .await
            .unwrap();

        // Fetch attested certificate
        let cert = manager
            .fetch_attested_certificate(&identity, pod_id)
            .await
            .unwrap();

        assert_eq!(cert.identity(), &identity);
        assert!(!cert.is_expired());
    }

    #[tokio::test]
    async fn test_fetch_attested_certificate_no_attestation() {
        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let identity = Identity::new("test.local", "default", "non-attested-service");
        let pod_id = "no-attestation-pod";

        // Should still work, just without attestation extension
        let cert = manager
            .fetch_attested_certificate(&identity, pod_id)
            .await
            .unwrap();

        assert_eq!(cert.identity(), &identity);
    }

    /// **Track-1 live-embed.** When the pod has a minted mediation key (recorded
    /// as `mediator-pubkey.hex`), its attested SVID carries the mediator-key
    /// binding (OID .1.4) = SHA-256 of that pubkey — the value a relying party
    /// then requires the pod's forensic receipts to be signed under.
    #[tokio::test]
    async fn an_attested_svid_binds_the_pods_minted_mediation_key() {
        use nucleus_identity::attestation::extract_mediation_key_binding;
        use sha2::{Digest, Sha256};
        use std::io::Write;
        use tempfile::NamedTempFile;

        let dir = tempfile::tempdir().unwrap();
        let manager = IdentityManager::new("test.local", Duration::from_secs(3600))
            .unwrap()
            .with_mediation_binding_dir(dir.path().to_path_buf());

        let pod_id = "bound-pod";
        // The node's minted mediator key: record its pubkey where the mint would.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let pubkey = sk.verifying_key().to_bytes();
        std::fs::create_dir_all(dir.path().join(pod_id)).unwrap();
        std::fs::write(
            dir.path().join(pod_id).join("mediator-pubkey.hex"),
            format!("{}\n", hex::encode(pubkey)),
        )
        .unwrap();

        let mut kernel = NamedTempFile::new().unwrap();
        kernel.write_all(b"kernel").unwrap();
        let mut rootfs = NamedTempFile::new().unwrap();
        rootfs.write_all(b"rootfs").unwrap();
        manager
            .compute_attestation(pod_id, kernel.path(), rootfs.path(), b"config")
            .await
            .unwrap();

        let identity = Identity::new("test.local", "default", "bound-service");
        let cert = manager
            .fetch_attested_certificate(&identity, pod_id)
            .await
            .unwrap();

        let expect: [u8; 32] = Sha256::digest(pubkey).into();
        assert_eq!(
            extract_mediation_key_binding(cert.leaf().der()),
            Some(expect),
            "the attested SVID must bind the pod's minted mediation key"
        );
    }

    /// The control: with a binding dir configured but no `mediator-pubkey.hex` for
    /// the pod, the attested SVID carries NO binding (attestation only) — a missing
    /// key degrades gracefully, it does not fail issuance or fabricate a binding.
    #[tokio::test]
    async fn an_attested_svid_without_a_minted_key_carries_no_binding() {
        use nucleus_identity::attestation::extract_mediation_key_binding;
        use std::io::Write;
        use tempfile::NamedTempFile;

        let dir = tempfile::tempdir().unwrap();
        let manager = IdentityManager::new("test.local", Duration::from_secs(3600))
            .unwrap()
            .with_mediation_binding_dir(dir.path().to_path_buf());

        let pod_id = "unbound-pod";
        let mut kernel = NamedTempFile::new().unwrap();
        kernel.write_all(b"kernel").unwrap();
        let mut rootfs = NamedTempFile::new().unwrap();
        rootfs.write_all(b"rootfs").unwrap();
        manager
            .compute_attestation(pod_id, kernel.path(), rootfs.path(), b"config")
            .await
            .unwrap();

        let identity = Identity::new("test.local", "default", "unbound-service");
        let cert = manager
            .fetch_attested_certificate(&identity, pod_id)
            .await
            .unwrap();
        assert_eq!(extract_mediation_key_binding(cert.leaf().der()), None);
    }
}

#[cfg(test)]
mod registry_key_tests {
    use super::*;

    fn manager() -> IdentityManager {
        IdentityManager::new("example.org", std::time::Duration::from_secs(3600))
            .expect("identity manager should construct")
    }

    /// The regression. A pod registered under its UUID is NOT removed by its
    /// SPIFFE URI: the two key spaces are disjoint, so the mismatched teardown
    /// silently removed nothing and the registry grew without bound.
    ///
    /// This matters beyond the leak. The Workload API's registry-lookup path
    /// serves `registry.values().next()` -- an arbitrary entry -- and warns that
    /// this is only safe while exactly one identity is registered. A registry
    /// that never drains guarantees that precondition is false forever after the
    /// second pod.
    #[tokio::test]
    async fn a_spiffe_uri_does_not_remove_a_uuid_keyed_entry() {
        let m = manager();
        let pod_id = uuid::Uuid::new_v4();
        let identity = m.identity_for_pod(pod_id, "default", "agent");

        m.register_pod(pod_id.to_string(), identity.clone()).await;

        // The old teardown key.
        assert!(
            !m.unregister_pod(&identity.to_spiffe_uri()).await,
            "a SPIFFE URI must not match a UUID-keyed entry -- if this ever \
             passes, the two key spaces have merged and this test is no longer \
             pinning anything"
        );
        assert_eq!(
            m.vm_registry.read().await.len(),
            1,
            "the entry must still be there: that is the defect being pinned"
        );

        // The key registration actually used.
        assert!(
            m.unregister_pod(&pod_id.to_string()).await,
            "removing by the registered key must actually remove"
        );
        assert!(
            m.vm_registry.read().await.is_empty(),
            "the registry must drain"
        );
    }
}

#[cfg(test)]
mod retired_surface_tests {
    /// **The retirement is structural, and this keeps it that way.**
    ///
    /// `WorkloadApiServer::serve` returns an arbitrary registry entry — including
    /// the private key — to any local connector (#2197). The node no longer calls
    /// it, and this reads the source to make sure a future change does not
    /// quietly restore the call. A comment saying "do not call this" is not a
    /// gate; a test that fails when someone does is.
    ///
    /// Deliberately a source check rather than a behavioural one: the defect is
    /// the *existence* of a call site, and there is no runtime observation that
    /// distinguishes "never opened the socket" from "opened it and nobody
    /// connected".
    #[test]
    fn the_node_does_not_start_the_unix_workload_api_server() {
        // Match CODE forms -- a definition or a call -- not any mention. The
        // first draft of this test matched the bare name and went red on the
        // comment above explaining the removal, which is a gate failing for the
        // wrong reason: prose about a retired function is exactly what should
        // survive, and only a live call site is the defect.
        let src = include_str!("identity.rs");
        let body = src.split("mod retired_surface_tests").next().unwrap();
        assert!(
            !body.contains("fn start_workload_api_server")
                && !body.contains(".start_workload_api_server("),
            "identity.rs defines or calls start_workload_api_server again -- that \
             function was the only route to WorkloadApiServer::serve, the \
             deprecated registry-lookup path that hands an arbitrary pod's SVID \
             to any local connector (#2197)"
        );
        let main_src = include_str!("main.rs");
        assert!(
            !main_src.contains(".start_workload_api_server("),
            "main.rs calls start_workload_api_server again -- see #2197"
        );
    }
}
