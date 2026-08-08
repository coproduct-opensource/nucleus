//! Vsock bridge for the Workload API.
//!
//! This module provides a vsock server that accepts incoming connections from
//! Firecracker guests for the SPIFFE Workload API.
//!
//! # Firecracker Vsock Protocol
//!
//! For guest-to-host connections, Firecracker uses a socket naming convention:
//! - Host listens on: `{uds_path}_{port}` (e.g., `vsock.sock_15012`)
//! - Guest connects to CID 2 (host) on the specified port via AF_VSOCK
//! - Firecracker routes the connection to the host's Unix socket
//!
//! Reference: https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md
//!
//! # Workload API Protocol
//!
//! Once connected, the guest sends commands:
//! - `FETCH_SVID\n` - Request the X.509 SVID (certificate + key)
//! - `FETCH_BUNDLE\n` - Request the trust bundle (root CA certificates)
//! - `PING\n` - Health check
//!
//! Responses are newline-delimited JSON.

use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

use crate::identity::IdentityManager;
use crate::workload_api_protocol::{parse_command, WorkloadApiCommand, MAX_COMMAND_LEN};

/// Default port for the Workload API vsock server.
#[allow(dead_code)]
pub const DEFAULT_WORKLOAD_API_PORT: u32 = 15012;

/// Vsock bridge for the Workload API.
///
/// This server listens on a Unix socket following Firecracker's naming convention
/// (`{vsock_uds_path}_{port}`) and handles Workload API requests from guests.
///
/// Each bridge is associated with a specific pod and provides that pod's unique
/// SPIFFE identity.
pub struct WorkloadApiVsockBridge {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
    socket_path: PathBuf,
    /// The pod ID this bridge serves (used for unique identity per pod).
    #[allow(dead_code)]
    pod_id: uuid::Uuid,
}

/// The pod-scoped DLC-D admission provisioning served over `FETCH_DLC_ADMISSION`
/// (values verbatim from the PodSpec labels; the in-VM tool-proxy's parser owns
/// validation and fails closed).
#[derive(Debug, Clone)]
pub struct DlcAdmissionMaterial {
    /// Comma-separated hex Ed25519 trusted issuer public keys.
    pub trusted_keys: String,
    /// Hex public key of the issuer whose credentials this pod presents.
    pub issuer: String,
    /// Comma-separated `operation=hex_signature` credentials.
    pub credentials: String,
}

impl DlcAdmissionMaterial {
    /// Pod-scoped DLC-D admission provisioning from the PodSpec labels.
    ///
    /// Partial labels still provision — the proxy's parser fails CLOSED, so
    /// misconfiguration narrows rather than widens.
    // The only caller is inside spawn_firecracker_pod's target_os = "linux"
    // block; on Linux the dead-code detector stays live for it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn from_labels(labels: &std::collections::BTreeMap<String, String>) -> Option<Self> {
        labels.get("dlc_trusted_keys").map(|keys| Self {
            trusted_keys: keys.clone(),
            issuer: labels.get("dlc_issuer").cloned().unwrap_or_default(),
            credentials: labels.get("dlc_credentials").cloned().unwrap_or_default(),
        })
    }
}

/// Cloud credentials for the pod's S3 audit sink, served over
/// `FETCH_AUDIT_CREDENTIALS` exactly once per pod.
///
/// Deliberately NO `Debug` derive: these are long-lived cloud credentials, and
/// a derived `Debug` would put them one `{material:?}` away from a log line.
#[derive(Clone)]
pub struct AuditCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Present only for temporary (STS) credentials.
    pub session_token: Option<String>,
}

impl AuditCredentials {
    /// The credentials for a pod's audit sink, from the node's ambient AWS
    /// environment — the same source the kernel-cmdline emission used to read.
    ///
    /// `None` unless the pod has an audit sink, and only ever a PAIR: an access
    /// key id without its secret (or the reverse) is not a credential, so
    /// `None` beats half of one. The session token alone is optional (absent
    /// for long-lived keys).
    // The only caller is inside spawn_firecracker_pod's target_os = "linux"
    // block; on Linux the dead-code detector stays live for it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn from_node_env(pod_has_audit_sink: bool) -> Option<Self> {
        if !pod_has_audit_sink {
            return None;
        }
        let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").ok()?;
        let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY").ok()?;
        Some(Self {
            access_key_id,
            secret_access_key,
            session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
        })
    }
}

impl std::fmt::Debug for WorkloadApiVsockBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadApiVsockBridge")
            .field("socket_path", &self.socket_path)
            .finish()
    }
}
/// The per-pod material a workload-API bridge serves.
///
/// Bundled rather than passed as six positional arguments: clippy's
/// `too_many_arguments` fired when the broker capability was added, and it was
/// right to. These four are one thing — everything the host holds ON BEHALF of
/// one pod — and a struct makes a new item a named field at every construction
/// site rather than another `None` in a row of them.
#[derive(Default)]
pub struct PodMaterial {
    /// The pod's live-path session capability token.
    pub task_token: Option<crate::session_mint::MintedTaskToken>,
    /// This pod's caller-identity token for the node's management API.
    ///
    /// Derived host-side from a node-only secret and THIS pod's id, and served
    /// only down this pod's own socket — so holding it proves which pod's
    /// authority the caller is exercising. See `pod_caller_identity`.
    pub caller_token: Option<String>,
    /// DLC-D verified-admission provisioning.
    pub dlc_admission: Option<DlcAdmissionMaterial>,
    /// The credential-broker capability, served exactly once.
    pub broker_secret: Option<String>,
    /// The vsock port the broker listens on, served WITH the capability.
    ///
    /// Together and not separately, deliberately: knowing where to connect and
    /// being able to sign are one capability, and delivering them through two
    /// mechanisms would let a proxy end up holding one without the other — able
    /// to sign but not to find the socket, or the reverse. Both arrive in the
    /// same one-shot reply or neither does.
    pub broker_port: u32,
    /// Whether the capability has been served. SHARED across every connection
    /// this listener accepts — a per-connection flag would make "once" mean
    /// "once per connection", which is not a restriction.
    pub broker_secret_served: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The S3 audit-sink credentials, off the kernel command line at last.
    /// `None` when the pod has no audit sink or the node holds no credentials.
    pub audit_creds: Option<AuditCredentials>,
    /// Whether the audit credentials have been served — one flag across every
    /// connection, for the same reason as `broker_secret_served`.
    pub audit_creds_served: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl WorkloadApiVsockBridge {
    /// Starts the Workload API vsock bridge for a specific pod.
    ///
    /// Creates a Unix socket at `{vsock_uds_path}_{port}` following Firecracker's
    /// naming convention for guest-to-host connections.
    ///
    /// # Arguments
    ///
    /// * `vsock_uds_path` - The base vsock UDS path configured in Firecracker
    /// * `port` - The port number guests will connect to (e.g., 15012)
    /// * `pod_id` - The unique identifier for the pod this bridge serves
    /// * `identity_manager` - The identity manager for fetching certificates
    ///
    /// # Example
    ///
    /// If `vsock_uds_path` is `/tmp/pod/vsock.sock` and `port` is 15012,
    /// the bridge will listen on `/tmp/pod/vsock.sock_15012`.
    ///
    /// Each pod gets its own bridge with a unique SPIFFE identity based on `pod_id`.
    #[allow(dead_code)]
    pub async fn start(
        vsock_uds_path: impl AsRef<Path>,
        port: u32,
        pod_id: uuid::Uuid,
        identity_manager: IdentityManager,
        material: PodMaterial,
        jail_owner: Option<(u32, u32)>,
    ) -> std::io::Result<Self> {
        // One Arc over the whole bundle rather than a per-field clone into
        // `handle_connection`: the parameter list crossed clippy's
        // `too_many_arguments` line when the audit credentials arrived, and the
        // fields are read-only anyway — the one-shot flags inside are already
        // their own `Arc<AtomicBool>`s, so sharing the bundle shares them.
        let material = std::sync::Arc::new(material);
        // Firecracker naming convention: {uds_path}_{port}
        let socket_path = PathBuf::from(format!("{}_{}", vsock_uds_path.as_ref().display(), port));

        // Remove existing socket if present
        if socket_path.exists() {
            tokio::fs::remove_file(&socket_path).await?;
        }

        // Create parent directory if needed
        if let Some(parent) = socket_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let listener = UnixListener::bind(&socket_path)?;

        // Hand the socket to the jailed uid, or the guest cannot reach it.
        //
        // `prepare_jail` chowns everything it places, and its comment says the
        // vsock socket is "deliberately absent" because Firecracker creates it.
        // That is true of `vsock.sock` — and NOT of this one. `vsock.sock_<port>`
        // is created HERE, by the node, running as root, so it lands
        // `srwxr-xr-x root root` while Firecracker runs as the jailer uid.
        // Connecting to a Unix socket requires WRITE permission on it, so
        // Firecracker's connect() gets EACCES and the guest sees
        // "Connection reset by peer" from a socket that is demonstrably
        // listening. Measured on a booted pod, 2026-07-29:
        //
        //   srwxr-xr-x 1  123 users  vsock.sock          <- Firecracker made this
        //   srwxr-xr-x 1 root root   vsock.sock_15012    <- the node made this
        //
        // Downstream, the guest fetched no SVID and no task token, all three
        // sandbox-proof tiers failed, and the tool-proxy exited as PID 1 —
        // a kernel panic whose visible cause was four layers from the file mode.
        //
        // chown, not chmod: only the jailed Firecracker should be able to
        // connect. Widening the mode would open the workload API — which serves
        // SVIDs and task tokens — to every user on the host.
        crate::guest_socket::give_socket_to_jail(&socket_path, jail_owner)?;
        #[cfg(not(target_os = "linux"))]
        let _ = jail_owner;
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let socket_path_clone = socket_path.clone();
        let task = tokio::spawn(async move {
            info!(
                "workload API vsock bridge listening on {} (port {}) for pod {}",
                socket_path_clone.display(),
                port,
                pod_id
            );

            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        info!("workload API vsock bridge shutting down for pod {}", pod_id);
                        break;
                    }
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((stream, _)) => {
                                let manager = identity_manager.clone();
                                // The SAME Arc for every connection, so the
                                // one-shot flags inside stay one flag each. A
                                // per-connection flag would make "once" mean
                                // "once per connection", which is not a
                                // restriction at all.
                                let material = std::sync::Arc::clone(&material);
                                tokio::spawn(async move {
                                    if let Err(err) =
                                        handle_connection(stream, manager, pod_id, material).await
                                    {
                                        debug!("workload API connection closed: {err}");
                                    }
                                });
                            }
                            Err(err) => {
                                error!("workload API vsock bridge accept error: {err}");
                                // Don't break on accept errors - could be transient
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            shutdown: Some(shutdown_tx),
            task,
            socket_path,
            pod_id,
        })
    }

    /// Returns the pod ID this bridge serves.
    #[allow(dead_code)]
    pub fn pod_id(&self) -> uuid::Uuid {
        self.pod_id
    }

    /// Returns the socket path.
    #[allow(dead_code)]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Shuts down the bridge.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
        // Clean up socket file
        let _ = tokio::fs::remove_file(&self.socket_path).await;
    }
}

/// Handles a single Workload API connection from a guest.
#[allow(dead_code)]
/// Serve this pod's session capability token.
///
/// `None` — the pod was launched without one — is answered with an explicit
/// refusal rather than an empty token. A guest handed `{"token":""}` could not
/// distinguish "none was minted" from "the token is empty", and the tool-proxy's
/// verify half treats a missing token and an invalid one differently.
/// Serve the pod's DLC admission provisioning, or a JSON error when the pod
/// was not provisioned (the ordinary case — the guest treats it as "inert").
/// Serve the broker capability EXACTLY ONCE.
///
/// # The one-shot is the whole mechanism
///
/// This secret's job is to distinguish the mediating tool-proxy from every other
/// process in the guest. Any guest process can open `AF_VSOCK` — that is not
/// preventable by permissions on `/dev/vsock`, which does not gate the socket
/// family — so a workload can reach this API too. What it cannot do is arrive
/// FIRST: `nucleus-guest-init` fetches before `exec_proxy`, i.e. before any
/// workload exists.
///
/// So a second request is not a retry to be tolerated, it is either a bug or an
/// attempt, and either way the answer is no. Serving it twice would hand the
/// capability to whoever asked second and silently reduce the broker to
/// unauthenticated.
///
/// `Acquire`/`AcqRel` via `swap` rather than a load-then-store: two concurrent
/// connections must not both observe "not yet served".
fn handle_fetch_broker_secret(
    secret: Option<&str>,
    port: u32,
    already_served: &std::sync::atomic::AtomicBool,
) -> String {
    use std::sync::atomic::Ordering;
    let Some(secret) = secret else {
        return r#"{"error":"no broker secret provisioned for this pod"}"#.to_string();
    };
    if already_served.swap(true, Ordering::AcqRel) {
        tracing::warn!(
            "refused a repeat FETCH_BROKER_SECRET — the capability is served once, before the \
             workload exists; a second request is a bug or an attempt to obtain it"
        );
        return r#"{"error":"broker secret already served"}"#.to_string();
    }
    serde_json::json!({ "secret": secret, "port": port }).to_string()
}

fn handle_fetch_dlc_admission(material: Option<&DlcAdmissionMaterial>) -> String {
    match material {
        Some(m) => serde_json::json!({
            "trusted_keys": m.trusted_keys,
            "issuer": m.issuer,
            "credentials": m.credentials,
        })
        .to_string(),
        None => r#"{"error":"no dlc admission provisioned for this pod"}"#.to_string(),
    }
}

/// Serve the S3 audit-sink credentials EXACTLY ONCE.
///
/// Same mechanism and same reasoning as [`handle_fetch_broker_secret`]: any
/// guest process can open `AF_VSOCK`, so the only thing distinguishing the
/// mediating tool-proxy from the workload it audits is that `nucleus-guest-init`
/// asks FIRST, before `exec_proxy`. These credentials write the audit trail; a
/// workload holding them could erase or forge its own record, which is exactly
/// the C1 exposure that existed while they rode the world-readable kernel
/// command line. A refusal for an absent credential set must not consume the
/// one-shot (a pod with no audit sink asks and is told no, harmlessly).
fn handle_fetch_audit_credentials(
    creds: Option<&AuditCredentials>,
    already_served: &std::sync::atomic::AtomicBool,
) -> String {
    use std::sync::atomic::Ordering;
    let Some(creds) = creds else {
        return r#"{"error":"no audit credentials provisioned for this pod"}"#.to_string();
    };
    if already_served.swap(true, Ordering::AcqRel) {
        tracing::warn!(
            "refused a repeat FETCH_AUDIT_CREDENTIALS — the credentials are served once, before \
             the workload exists; a second request is a bug or an attempt to obtain them"
        );
        return r#"{"error":"audit credentials already served"}"#.to_string();
    }
    serde_json::json!({
        "access_key_id": creds.access_key_id,
        "secret_access_key": creds.secret_access_key,
        "session_token": creds.session_token,
    })
    .to_string()
}

fn handle_fetch_task_token(token: Option<&crate::session_mint::MintedTaskToken>) -> String {
    match token {
        Some(t) => serde_json::json!({
            "token": t.token_json,
            "nonce": t.nonce_hex,
            "issuer": t.issuer_hex,
        })
        .to_string(),
        None => r#"{"error":"no task token was minted for this pod"}"#.to_string(),
    }
}

async fn handle_connection(
    stream: tokio::net::UnixStream,
    manager: IdentityManager,
    pod_id: uuid::Uuid,
    material: std::sync::Arc<PodMaterial>,
) -> std::io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    loop {
        let frame = match read_command_frame(&mut reader).await? {
            Some(frame) => frame,
            // Clean EOF: the guest closed the connection.
            None => break,
        };

        // ALL interpretation of guest-supplied bytes happens in the pure,
        // fuzz- and property-tested `parse_command`. The host never branches on
        // raw guest input directly.
        let response = match parse_command(&frame) {
            Ok(WorkloadApiCommand::FetchSvid) => {
                debug!("workload API FETCH_SVID for pod {}", pod_id);
                handle_fetch_svid(&manager, pod_id).await
            }
            Ok(WorkloadApiCommand::FetchBundle) => {
                debug!("workload API FETCH_BUNDLE for pod {}", pod_id);
                handle_fetch_bundle(&manager)
            }
            Ok(WorkloadApiCommand::Ping) => r#"{"status":"ok"}"#.to_string(),
            Ok(WorkloadApiCommand::FetchPodCallerToken) => {
                debug!("workload API FETCH_POD_CALLER_TOKEN for pod {}", pod_id);
                // Served for the pod bound to THIS socket. The request carries no
                // pod id and could not be believed if it did.
                match &material.caller_token {
                    Some(t) => format!(r#"{{"caller_token":"{t}"}}"#),
                    None => r#"{"error":"no caller token minted for this pod"}"#.to_string(),
                }
            }
            Ok(WorkloadApiCommand::FetchTaskToken) => {
                debug!("workload API FETCH_TASK_TOKEN for pod {}", pod_id);
                handle_fetch_task_token(material.task_token.as_ref())
            }
            Ok(WorkloadApiCommand::FetchDlcAdmission) => {
                debug!("workload API FETCH_DLC_ADMISSION for pod {}", pod_id);
                handle_fetch_dlc_admission(material.dlc_admission.as_ref())
            }
            Ok(WorkloadApiCommand::FetchBrokerSecret) => {
                // Value never logged, at any level: this is the one workload-API
                // payload whose possession IS the capability.
                debug!("workload API FETCH_BROKER_SECRET for pod {}", pod_id);
                handle_fetch_broker_secret(
                    material.broker_secret.as_deref(),
                    material.broker_port,
                    &material.broker_secret_served,
                )
            }
            Ok(WorkloadApiCommand::FetchAuditCredentials) => {
                // Like the broker secret: never log the value, at any level.
                debug!("workload API FETCH_AUDIT_CREDENTIALS for pod {}", pod_id);
                handle_fetch_audit_credentials(
                    material.audit_creds.as_ref(),
                    &material.audit_creds_served,
                )
            }
            Err(err) => {
                debug!("workload API rejected command for pod {}: {err}", pod_id);
                // Build the error response via serde so the (attacker-controlled)
                // error text — e.g. an unknown-command token echoed back — is
                // JSON-escaped and cannot inject into the response framing.
                serde_json::json!({ "error": err.to_string() }).to_string()
            }
        };

        writer.write_all(response.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}

/// Reads one newline-delimited command frame from the guest, bounding the
/// buffered bytes to [`MAX_COMMAND_LEN`].
///
/// Unlike `read_line`/`read_until` (which buffer without limit), this refuses to
/// grow past the cap, so a malicious guest that never sends a newline cannot
/// drive unbounded host allocation (OOM). Returns:
/// * `Ok(None)` on a clean EOF with no buffered bytes,
/// * `Ok(Some(frame))` with the bytes up to and including the newline (or up to
///   EOF) — interpretation is left to [`parse_command`],
/// * `Err(InvalidData)` if the frame exceeds [`MAX_COMMAND_LEN`] without a
///   newline (the over-long / DoS case).
///
/// `reader` is a [`BufReader`], so the byte-at-a-time reads hit its in-memory
/// buffer rather than issuing a syscall per byte.
async fn read_command_frame<R>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>>
where
    R: AsyncReadExt + Unpin,
{
    let mut frame: Vec<u8> = Vec::with_capacity(16);
    loop {
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            // EOF. Surface any partial frame so the parser can reject it; an
            // empty buffer means the connection simply closed.
            return Ok(if frame.is_empty() { None } else { Some(frame) });
        }
        frame.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(Some(frame));
        }
        if frame.len() > MAX_COMMAND_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "workload API command exceeds maximum length",
            ));
        }
    }
}

/// Handles FETCH_SVID command - returns the workload certificate and key.
///
/// Each pod gets a unique SPIFFE identity based on its pod_id:
/// `spiffe://{trust_domain}/ns/pods/sa/{pod_id}`
#[allow(dead_code)]
async fn handle_fetch_svid(manager: &IdentityManager, pod_id: uuid::Uuid) -> String {
    // Create a unique identity for this specific pod
    // The identity is based on the pod's UUID, ensuring isolation between pods
    let identity =
        nucleus_identity::Identity::new(manager.trust_domain(), "pods", pod_id.to_string());

    // Fetch the certificate with the actual certificate data
    match manager.fetch_certificate(&identity).await {
        Ok(cert) => {
            #[derive(serde::Serialize)]
            struct SvidResponse {
                spiffe_id: String,
                certificate_chain: String,
                private_key: String,
                expires_at: i64,
            }

            let response = SvidResponse {
                spiffe_id: identity.to_spiffe_uri(),
                certificate_chain: cert.chain_pem(),
                private_key: cert.private_key_pem().to_string(),
                expires_at: cert.expiry().timestamp(),
            };

            serde_json::to_string(&response)
                .unwrap_or_else(|e| format!(r#"{{"error":"serialization failed: {}"}}"#, e))
        }
        Err(e) => {
            error!("failed to fetch certificate for pod {}: {}", pod_id, e);
            format!(r#"{{"error":"{}"}}"#, e)
        }
    }
}

/// Handles FETCH_BUNDLE command - returns the trust bundle (CA certificates).
#[allow(dead_code)]
fn handle_fetch_bundle(manager: &IdentityManager) -> String {
    #[derive(serde::Serialize)]
    struct BundleResponse {
        trust_domain: String,
        bundle_pem: String,
    }

    let bundle = manager.trust_bundle();
    let pem: String = bundle
        .roots()
        .iter()
        .map(|c| c.to_pem().to_string())
        .collect();

    let response = BundleResponse {
        trust_domain: manager.trust_domain().to_string(),
        bundle_pem: pem,
    };

    serde_json::to_string(&response)
        .unwrap_or_else(|e| format!(r#"{{"error":"serialization failed: {}"}}"#, e))
}

#[cfg(test)]
mod task_token_serving_tests {
    use super::*;
    use crate::session_mint::MintedTaskToken;

    fn minted() -> MintedTaskToken {
        MintedTaskToken {
            token_json: r#"{"task":"demo"}"#.to_string(),
            nonce_hex: "0011223344556677".to_string(),
            issuer_hex: "aabbccdd".to_string(),
        }
    }

    /// The served shape is exactly the three values the guest sets as
    /// `NUCLEUS_TASK_TOKEN{,_NONCE,_ISSUER}` — the same trio the kernel command
    /// line carries today. If these drift apart the guest gets a token the
    /// tool-proxy cannot verify, which fails at startup rather than at use.
    #[test]
    fn the_served_token_carries_the_three_values_the_guest_needs() {
        let body = handle_fetch_task_token(Some(&minted()));
        let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(v["token"], r#"{"task":"demo"}"#);
        assert_eq!(v["nonce"], "0011223344556677");
        assert_eq!(v["issuer"], "aabbccdd");
    }

    /// **A pod with no token gets a refusal, not an empty one.** A guest handed
    /// `{"token":""}` could not tell "none was minted" from "the token is
    /// empty", and the tool-proxy's verify half treats missing and invalid
    /// differently — so collapsing them would turn a launch-time
    /// misconfiguration into a confusing runtime denial.
    #[test]
    fn a_pod_without_a_token_is_refused_rather_than_given_an_empty_one() {
        let body = handle_fetch_task_token(None);
        let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert!(
            v.get("token").is_none(),
            "must not offer an empty token: {body}"
        );
        assert!(v["error"].is_string(), "must say why: {body}");
    }

    /// The command must round-trip through the wire spelling the guest sends.
    #[test]
    fn the_guest_spelling_parses_to_the_command() {
        use crate::workload_api_protocol::{parse_command, WorkloadApiCommand};
        assert_eq!(
            parse_command(b"FETCH_TASK_TOKEN").unwrap(),
            WorkloadApiCommand::FetchTaskToken
        );
        assert_eq!(
            WorkloadApiCommand::FetchTaskToken.as_wire(),
            "FETCH_TASK_TOKEN"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

    #[tokio::test]
    async fn test_workload_api_vsock_bridge_ping() {
        let temp_dir = tempdir().unwrap();
        // Simulate Firecracker's vsock UDS path
        let vsock_uds_path = temp_dir.path().join("vsock.sock");
        let pod_id = uuid::Uuid::new_v4();

        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let bridge = WorkloadApiVsockBridge::start(
            &vsock_uds_path,
            15012,
            pod_id,
            manager,
            PodMaterial::default(),
            None,
        )
        .await
        .unwrap();

        // Verify socket path follows Firecracker convention
        assert_eq!(
            bridge.socket_path(),
            temp_dir.path().join("vsock.sock_15012")
        );
        // Verify pod_id is stored
        assert_eq!(bridge.pod_id(), pod_id);

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect to the socket (simulating Firecracker routing a guest connection)
        let stream = tokio::net::UnixStream::connect(bridge.socket_path())
            .await
            .unwrap();
        let (reader, mut writer): (OwnedReadHalf, OwnedWriteHalf) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);

        writer.write_all(b"PING\n").await.unwrap();
        writer.flush().await.unwrap();

        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();
        assert!(response.contains("ok"));

        bridge.shutdown().await;
    }

    #[tokio::test]
    async fn test_workload_api_vsock_bridge_fetch_bundle() {
        let temp_dir = tempdir().unwrap();
        let vsock_uds_path = temp_dir.path().join("vsock.sock");
        let pod_id = uuid::Uuid::new_v4();

        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let bridge = WorkloadApiVsockBridge::start(
            &vsock_uds_path,
            15012,
            pod_id,
            manager,
            PodMaterial::default(),
            None,
        )
        .await
        .unwrap();

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect and send FETCH_BUNDLE
        let stream = tokio::net::UnixStream::connect(bridge.socket_path())
            .await
            .unwrap();
        let (reader, mut writer): (OwnedReadHalf, OwnedWriteHalf) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);

        writer.write_all(b"FETCH_BUNDLE\n").await.unwrap();
        writer.flush().await.unwrap();

        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();
        assert!(response.contains("trust_domain"));
        assert!(response.contains("test.local"));
        assert!(response.contains("bundle_pem"));

        bridge.shutdown().await;
    }

    #[tokio::test]
    async fn test_socket_naming_convention() {
        let temp_dir = tempdir().unwrap();
        let vsock_uds_path = temp_dir.path().join("pod-123").join("vsock.sock");
        let pod_id = uuid::Uuid::new_v4();

        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let bridge = WorkloadApiVsockBridge::start(
            &vsock_uds_path,
            8080,
            pod_id,
            manager,
            PodMaterial::default(),
            None,
        )
        .await
        .unwrap();

        // Verify Firecracker naming convention: {uds_path}_{port}
        let expected_path = temp_dir.path().join("pod-123").join("vsock.sock_8080");
        assert_eq!(bridge.socket_path(), expected_path);

        bridge.shutdown().await;
    }

    #[tokio::test]
    async fn test_fetch_svid_returns_real_certificate() {
        let temp_dir = tempdir().unwrap();
        let vsock_uds_path = temp_dir.path().join("vsock.sock");
        let pod_id = uuid::Uuid::new_v4();

        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let bridge = WorkloadApiVsockBridge::start(
            &vsock_uds_path,
            15012,
            pod_id,
            manager,
            PodMaterial::default(),
            None,
        )
        .await
        .unwrap();

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect and send FETCH_SVID
        let stream = tokio::net::UnixStream::connect(bridge.socket_path())
            .await
            .unwrap();
        let (reader, mut writer): (OwnedReadHalf, OwnedWriteHalf) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);

        writer.write_all(b"FETCH_SVID\n").await.unwrap();
        writer.flush().await.unwrap();

        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();

        // Verify the response contains real certificate data
        assert!(
            response.contains("spiffe_id"),
            "response should contain spiffe_id"
        );
        assert!(
            response.contains(&pod_id.to_string()),
            "spiffe_id should contain pod_id"
        );
        assert!(
            response.contains("BEGIN CERTIFICATE"),
            "should contain real certificate"
        );
        assert!(
            response.contains("BEGIN PRIVATE KEY"),
            "should contain real private key"
        );
        assert!(response.contains("expires_at"), "should contain expiry");

        // Parse the response to verify structure
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert!(
            parsed["expires_at"].as_i64().unwrap() > 0,
            "expires_at should be set"
        );

        bridge.shutdown().await;
    }

    #[tokio::test]
    async fn test_different_pods_get_different_identities() {
        let temp_dir = tempdir().unwrap();
        let pod1_id = uuid::Uuid::new_v4();
        let pod2_id = uuid::Uuid::new_v4();

        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();

        // Create bridges for two different pods
        let vsock1_path = temp_dir.path().join("pod1").join("vsock.sock");
        let vsock2_path = temp_dir.path().join("pod2").join("vsock.sock");

        let bridge1 = WorkloadApiVsockBridge::start(
            &vsock1_path,
            15012,
            pod1_id,
            manager.clone(),
            PodMaterial::default(),
            None,
        )
        .await
        .unwrap();
        let bridge2 = WorkloadApiVsockBridge::start(
            &vsock2_path,
            15012,
            pod2_id,
            manager.clone(),
            PodMaterial::default(),
            None,
        )
        .await
        .unwrap();

        // Wait for servers to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Fetch SVID from both bridges
        let svid1 = fetch_svid_from_socket(bridge1.socket_path()).await;
        let svid2 = fetch_svid_from_socket(bridge2.socket_path()).await;

        // Verify they have different identities
        assert!(
            svid1.contains(&pod1_id.to_string()),
            "svid1 should contain pod1_id"
        );
        assert!(
            svid2.contains(&pod2_id.to_string()),
            "svid2 should contain pod2_id"
        );
        assert!(
            !svid1.contains(&pod2_id.to_string()),
            "svid1 should NOT contain pod2_id"
        );
        assert!(
            !svid2.contains(&pod1_id.to_string()),
            "svid2 should NOT contain pod1_id"
        );

        bridge1.shutdown().await;
        bridge2.shutdown().await;
    }

    /// Helper to fetch SVID from a socket path
    async fn fetch_svid_from_socket(socket_path: &Path) -> String {
        let stream = tokio::net::UnixStream::connect(socket_path).await.unwrap();
        let (reader, mut writer): (OwnedReadHalf, OwnedWriteHalf) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);

        writer.write_all(b"FETCH_SVID\n").await.unwrap();
        writer.flush().await.unwrap();

        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();
        response
    }

    use std::sync::atomic::AtomicBool;

    /// **The one-shot IS the mechanism.** This secret distinguishes the
    /// mediating tool-proxy from every other process in the guest. Any guest
    /// process can open AF_VSOCK, so what the proxy has that a workload does not
    /// is only that it asked FIRST — before `exec_proxy`, before a workload
    /// exists. Serving twice hands the capability to whoever asks second.
    #[test]
    fn the_broker_secret_is_served_exactly_once() {
        let served = AtomicBool::new(false);
        let first = handle_fetch_broker_secret(Some("cap"), 1027, &served);
        let v: serde_json::Value = serde_json::from_str(&first).unwrap();
        assert_eq!(v["secret"], "cap", "the first request must be served");

        let second = handle_fetch_broker_secret(Some("cap"), 1027, &served);
        assert!(
            second.contains("already served"),
            "a second request must be refused: {second}"
        );
        assert!(
            !second.contains("cap"),
            "and must not leak the secret in the refusal: {second}"
        );
    }

    /// **The port travels with the secret.** A proxy given one and not the other
    /// can sign but not connect, or connect but not sign — a capability that
    /// looks held and is not, which is the shape of the defect
    /// `BrokerCapability` was introduced to remove one file over.
    #[test]
    fn the_reply_carries_the_port_as_well_as_the_secret() {
        let served = AtomicBool::new(false);
        let reply = handle_fetch_broker_secret(Some("cap"), 4242, &served);
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["secret"], "cap");
        assert_eq!(
            v["port"], 4242,
            "the guest cannot reach the broker without being told where it is: {reply}"
        );
    }

    /// The port is the CONFIGURED one, not a constant re-derived guest-side. An
    /// operator who moves the broker port must not have to move it twice.
    #[test]
    fn the_served_port_is_whatever_the_node_was_configured_with() {
        let served = AtomicBool::new(false);
        let reply = handle_fetch_broker_secret(Some("cap"), 9999, &served);
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["port"], 9999);
    }

    /// A pod with no broker secret gets an explicit error, and — the part that
    /// matters — the refusal must not consume the one-shot. Otherwise a
    /// misconfigured pod could be made to burn its own capability before the
    /// proxy ever asks.
    #[test]
    fn an_absent_secret_does_not_consume_the_one_shot() {
        let served = AtomicBool::new(false);
        let r = handle_fetch_broker_secret(None, 1027, &served);
        assert!(r.contains("error"), "got: {r}");
        assert!(
            !served.load(std::sync::atomic::Ordering::Acquire),
            "a refusal for an absent secret must not mark the capability as served"
        );
    }

    /// `FETCH_BROKER_SECRET` must be a command the parser knows, or the guest
    /// client would fail closed — correctly, but silently and far from the cause.
    #[test]
    fn the_broker_secret_command_round_trips_through_the_parser() {
        use crate::workload_api_protocol::{parse_command, WorkloadApiCommand};
        assert_eq!(
            parse_command(b"FETCH_BROKER_SECRET\n").unwrap(),
            WorkloadApiCommand::FetchBrokerSecret
        );
    }

    fn audit_creds() -> AuditCredentials {
        AuditCredentials {
            access_key_id: "AKIAEXAMPLE".to_string(),
            secret_access_key: "hunter2secret".to_string(),
            session_token: Some("ststoken".to_string()),
        }
    }

    /// **The audit credentials get the broker secret's discipline.** They write
    /// the audit trail; a workload holding them can erase its own record. Only
    /// "asked first" distinguishes the proxy from the workload, so serving
    /// twice hands the trail's keys to whoever asks second.
    #[test]
    fn the_audit_credentials_are_served_exactly_once() {
        let served = AtomicBool::new(false);
        let first = handle_fetch_audit_credentials(Some(&audit_creds()), &served);
        let v: serde_json::Value = serde_json::from_str(&first).unwrap();
        assert_eq!(v["access_key_id"], "AKIAEXAMPLE");
        assert_eq!(v["secret_access_key"], "hunter2secret");
        assert_eq!(v["session_token"], "ststoken");

        let second = handle_fetch_audit_credentials(Some(&audit_creds()), &served);
        assert!(
            second.contains("already served"),
            "a second request must be refused: {second}"
        );
        assert!(
            !second.contains("hunter2secret"),
            "and must not leak the credentials in the refusal: {second}"
        );
    }

    /// Long-lived keys without an STS session token are the common static-cred
    /// case; the reply must carry an explicit null, not omit the field, so the
    /// guest client can tell "no session token" from "truncated reply".
    #[test]
    fn static_credentials_serve_a_null_session_token() {
        let served = AtomicBool::new(false);
        let reply = handle_fetch_audit_credentials(
            Some(&AuditCredentials {
                session_token: None,
                ..audit_creds()
            }),
            &served,
        );
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert!(v["session_token"].is_null(), "got: {reply}");
        assert_eq!(v["access_key_id"], "AKIAEXAMPLE");
    }

    /// A pod with no audit sink asks (guest-init always asks) and must be told
    /// no WITHOUT burning the one-shot — otherwise a misprovisioned pod could
    /// consume its own capability before the proxy exists to want it.
    #[test]
    fn an_absent_credential_set_does_not_consume_the_one_shot() {
        let served = AtomicBool::new(false);
        let r = handle_fetch_audit_credentials(None, &served);
        assert!(r.contains("error"), "got: {r}");
        assert!(
            !served.load(std::sync::atomic::Ordering::Acquire),
            "a refusal for an absent credential set must not mark it served"
        );
    }

    /// `FETCH_AUDIT_CREDENTIALS` must be a command the parser knows, or the
    /// guest client fails closed far from the cause.
    #[test]
    fn the_audit_credentials_command_round_trips_through_the_parser() {
        use crate::workload_api_protocol::{parse_command, WorkloadApiCommand};
        assert_eq!(
            parse_command(b"FETCH_AUDIT_CREDENTIALS\n").unwrap(),
            WorkloadApiCommand::FetchAuditCredentials
        );
    }
}
